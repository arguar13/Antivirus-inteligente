//! `AegisResilience`: el guardian de detencion. La pieza en vivo de la
//! autodefensa que convierte una senal de parada del sistema operativo en una
//! decision: se permite solo si viene con la autorizacion del dueno.
//!
//! # Que hace, exactamente
//!
//! El sistema operativo pide parar un proceso de muchas formas: una senal POSIX
//! (`SIGTERM`, `SIGINT`, `SIGQUIT`...), un control del SCM de Windows
//! (`SERVICE_CONTROL_STOP`, `...SHUTDOWN`), o una peticion explicita de
//! desinstalar. El guardian toma esa senal cruda, la traduce a la
//! [`OperacionProtegida`] que representa, y aplica la MISMA regla de la
//! [`crate::tamper`]: si es un recurso protegido y no hay un OTP valido del
//! Control Plane, se deniega; con OTP (o si quien lo pide es el propio kernel, el
//! agente o un componente de AegisCore), se permite.
//!
//! Asi, un atacante con privilegios de administrador que haga `kill -TERM` o
//! `sc stop AegisCore` para cegar al EDR se topa con una negativa; el dueno de la
//! flota, que tiene la llave (el OTP firmado con la firma hibrida de la FASE 59),
//! desinstala cuando quiere. Es la linea que separa un EDR de un rootkit,
//! aplicada a nivel de senal.
//!
//! # La honestidad que NO se cruza: `SIGKILL` y `SIGSTOP`
//!
//! Dos senales POSIX —`SIGKILL` (9) y `SIGSTOP` (19)— **no se pueden interceptar
//! desde el espacio de usuario**: el kernel no deja instalar un manejador para
//! ellas, por diseno. Ningun guardian en Rust puede "rechazar" un `SIGKILL`; el
//! que diga lo contrario miente. Por eso este guardian **declara la verdad** en
//! cada resultado ([`ResultadoDetencion::interceptable_en_usuario`]): calcula la
//! decision correcta (un `SIGKILL` de un atacante DEBERIA denegarse) pero avisa
//! de que su cumplimiento no es cosa del espacio de usuario, sino del kernel —y
//! ese es justo el trabajo de PPL-Antimalware ([`crate::ppl`]) y del minifilter,
//! que el kernel SI respalda—. La logica de decision se prueba aqui, entera y con
//! firmas reales; el cumplimiento de las senales no interceptables es el muro, y
//! se declara.

use crate::abi;
use crate::otp::{OperacionProtegida, Otp, HOST_ID_LEN};
use crate::tamper::{decidir, ContextoTamper, Solicitante, Veredicto};
use crate::{RegistroOtp, TamperError};
use aegis_pqc::firma_hibrida::ClaveVerificacionHibrida;

/// Numero de la senal POSIX `SIGINT` (interrupcion de teclado).
pub const SIGINT: i32 = 2;
/// Numero de la senal POSIX `SIGQUIT`.
pub const SIGQUIT: i32 = 3;
/// Numero de la senal POSIX `SIGKILL` (NO interceptable desde el usuario).
pub const SIGKILL: i32 = 9;
/// Numero de la senal POSIX `SIGTERM` (peticion educada de terminar).
pub const SIGTERM: i32 = 15;
/// Numero de la senal POSIX `SIGSTOP` (NO interceptable desde el usuario).
pub const SIGSTOP: i32 = 19;

/// La senal cruda de detencion que llega del sistema operativo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SenalDetencion {
    /// Una senal POSIX, por su numero (p. ej. [`SIGTERM`]).
    SenalPosix(i32),
    /// Un codigo de control del SCM de Windows (p. ej.
    /// [`abi::SERVICE_CONTROL_STOP`]).
    ControlServicio(u32),
    /// Una peticion explicita de desinstalar el agente (del instalador o del
    /// gestor de flota).
    PeticionDesinstalar,
    /// Una peticion explicita de bajar la proteccion del proceso (para una
    /// actualizacion o depuracion autorizada).
    PeticionDesproteger,
}

impl SenalDetencion {
    /// La [`OperacionProtegida`] que esta senal representa, o `None` si la senal
    /// no es una parada de un recurso protegido (p. ej. una consulta de estado o
    /// una recarga de configuracion): en ese caso el guardian no se mete.
    #[must_use]
    pub fn operacion_protegida(self) -> Option<OperacionProtegida> {
        match self {
            // Todas las senales de "termina" mapean a detener el servicio.
            SenalDetencion::SenalPosix(SIGINT | SIGQUIT | SIGTERM | SIGKILL | SIGSTOP) => {
                Some(OperacionProtegida::DetenerServicio)
            }
            // Otras senales POSIX (SIGHUP recargar, SIGUSR..., etc.) no son
            // paradas: no aplican.
            SenalDetencion::SenalPosix(_) => None,
            SenalDetencion::ControlServicio(
                abi::SERVICE_CONTROL_STOP
                | abi::SERVICE_CONTROL_SHUTDOWN
                | abi::SERVICE_CONTROL_PRESHUTDOWN,
            ) => Some(OperacionProtegida::DetenerServicio),
            // Pausar/reanudar/consultar no destruyen: no aplican.
            SenalDetencion::ControlServicio(_) => None,
            SenalDetencion::PeticionDesinstalar => Some(OperacionProtegida::Desinstalar),
            SenalDetencion::PeticionDesproteger => Some(OperacionProtegida::DesprotegerProceso),
        }
    }

    /// `true` si esta senal se puede interceptar y decidir desde el espacio de
    /// usuario. `SIGKILL`/`SIGSTOP` devuelven `false`: su cumplimiento solo lo
    /// puede imponer el kernel (PPL). Ver el aviso del modulo.
    #[must_use]
    pub fn es_interceptable_en_usuario(self) -> bool {
        !matches!(self, SenalDetencion::SenalPosix(SIGKILL | SIGSTOP))
    }
}

/// Por que el guardian decidio lo que decidio. Es material de auditoria: el dueno
/// tiene derecho a saber por que una parada se permitio o se nego.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MotivoDetencion {
    /// La senal no es una parada de un recurso protegido; no se interviene.
    NoAplica,
    /// Quien pide la parada es de confianza (el kernel, el propio agente o un
    /// componente de AegisCore). No necesita OTP.
    SolicitanteDeConfianza,
    /// Habia un OTP valido del Control Plane y se consumio: el dueno autoriza.
    AutorizadaPorOtp,
    /// Recurso protegido, sin autorizacion: sabotaje. Se deniega.
    DenegadaSinAutorizacion,
    /// Se presento un OTP pero se rechazo; se conserva el motivo exacto.
    OtpRechazado(TamperError),
}

/// El resultado completo de evaluar una senal de detencion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultadoDetencion {
    /// Permitir o denegar la parada.
    pub veredicto: Veredicto,
    /// La operacion protegida en juego, si la senal representaba una.
    pub operacion: Option<OperacionProtegida>,
    /// Si esta senal se puede hacer cumplir desde el espacio de usuario. Cuando
    /// es `false` (SIGKILL/SIGSTOP), el veredicto sigue siendo correcto pero
    /// quien lo impone es el kernel (PPL), no este guardian. NO se finge.
    pub interceptable_en_usuario: bool,
    /// El motivo, para la auditoria.
    pub motivo: MotivoDetencion,
}

impl ResultadoDetencion {
    /// Atajo: `true` si la parada se permite.
    #[must_use]
    pub fn permitida(&self) -> bool {
        self.veredicto == Veredicto::Permitir
    }
}

/// El guardian de detencion de AegisCore. Guarda lo que necesita para verificar
/// una autorizacion del dueno: la identidad de este host, la clave publica del
/// Control Plane con la que se comprueban los OTP, y el registro anti-replay de
/// nonces ya gastados.
///
/// Es la parte que puede estar MAL de forma peligrosa (de menos: un atacante para
/// el EDR; de mas: el dueno no puede desinstalarlo), asi que su decision se
/// prueba entera y con firmas hibridas reales en cada `make ci`.
pub struct AegisResilience {
    host_id: [u8; HOST_ID_LEN],
    clave_control: ClaveVerificacionHibrida,
    registro: RegistroOtp,
}

impl core::fmt::Debug for AegisResilience {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Se resume la clave del Control Plane: ni siquiera la publica se vuelca
        // en un log por costumbre, y `ClaveVerificacionHibrida` no es `Debug`.
        f.debug_struct("AegisResilience")
            .field("host_id", &self.host_id)
            .field(
                "clave_control",
                &"<clave de verificacion del Control Plane>",
            )
            .field("nonces_recordados", &self.registro.len())
            .finish()
    }
}

impl AegisResilience {
    /// Crea el guardian para este host, con la clave de verificacion del Control
    /// Plane (la mitad publica de la clave con la que el plano de control firma
    /// los OTP).
    #[must_use]
    pub fn nuevo(host_id: [u8; HOST_ID_LEN], clave_control: ClaveVerificacionHibrida) -> Self {
        Self {
            host_id,
            clave_control,
            registro: RegistroOtp::nuevo(),
        }
    }

    /// Evalua una senal de detencion y decide si se permite.
    ///
    /// `solicitante` describe quien la pide (el kernel, el propio agente, un
    /// componente de AegisCore, o un tercero); `otp` son los bytes de un OTP del
    /// Control Plane, si vienen con la peticion; `ahora_unix` es el instante para
    /// comprobar la ventana de validez.
    ///
    /// Un OTP solo se verifica —y se CONSUME— si de verdad hace falta (es decir,
    /// si el solicitante no es de confianza): asi una parada legitima del
    /// watchdog no gasta un token de un solo uso del dueno.
    pub fn evaluar_detencion(
        &mut self,
        senal: SenalDetencion,
        solicitante: Solicitante,
        otp: Option<&[u8]>,
        ahora_unix: u64,
    ) -> ResultadoDetencion {
        let interceptable = senal.es_interceptable_en_usuario();

        // 0. Traducir la senal a una operacion protegida. Si no es una parada de
        //    un recurso nuestro, no nos metemos.
        let Some(operacion) = senal.operacion_protegida() else {
            return ResultadoDetencion {
                veredicto: Veredicto::Permitir,
                operacion: None,
                interceptable_en_usuario: interceptable,
                motivo: MotivoDetencion::NoAplica,
            };
        };

        // 1. Solicitante de confianza: el kernel (su apagado limpio no se pelea),
        //    el propio agente, o un componente de AegisCore (el watchdog, que ha
        //    de poder pararse y reiniciarse). Se permite SIN gastar el OTP.
        if solicitante.es_kernel || solicitante.es_mismo_agente || solicitante.es_componente_aegis {
            return ResultadoDetencion {
                veredicto: Veredicto::Permitir,
                operacion: Some(operacion),
                interceptable_en_usuario: interceptable,
                motivo: MotivoDetencion::SolicitanteDeConfianza,
            };
        }

        // 2. Un tercero: hace falta un OTP valido. Se verifica CONTRA la clave del
        //    Control Plane, atado a este host y a esta operacion, dentro de su
        //    ventana y sin haberse usado antes. Solo si todo cuadra, autoriza.
        let mut orden_autorizada = false;
        let mut err_otp: Option<TamperError> = None;
        if let Some(bytes) = otp {
            match Otp::desde_bytes(bytes) {
                Ok(orden) => {
                    match orden.verificar_y_consumir(
                        &self.clave_control,
                        &self.host_id,
                        operacion,
                        ahora_unix,
                        &mut self.registro,
                    ) {
                        Ok(()) => orden_autorizada = true,
                        Err(e) => err_otp = Some(e),
                    }
                }
                Err(e) => err_otp = Some(e),
            }
        }

        // 3. La decision, con la MISMA politica que el minifilter de Windows
        //    (espejo en C probado en verificar-windows.sh). Un recurso protegido
        //    sin autorizacion es sabotaje.
        let ctx = ContextoTamper {
            recurso_protegido: true,
            operacion,
            solicitante,
            orden_autorizada,
        };
        let veredicto = decidir(&ctx);

        let motivo = if orden_autorizada {
            MotivoDetencion::AutorizadaPorOtp
        } else if let Some(e) = err_otp {
            MotivoDetencion::OtpRechazado(e)
        } else {
            MotivoDetencion::DenegadaSinAutorizacion
        };

        ResultadoDetencion {
            veredicto,
            operacion: Some(operacion),
            interceptable_en_usuario: interceptable,
            motivo,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_pqc::firma_hibrida::ClaveFirmaHibrida;

    const HORA: u64 = 1_800_000_000;
    const VALIDEZ: u32 = 300;

    fn control() -> (ClaveFirmaHibrida, ClaveVerificacionHibrida) {
        let sk = ClaveFirmaHibrida::desde_semillas(&[7u8; 32], &[13u8; 32]);
        let vk = sk.clave_verificacion();
        (sk, vk)
    }

    fn host() -> [u8; HOST_ID_LEN] {
        [0x5Au8; HOST_ID_LEN]
    }

    fn tercero() -> Solicitante {
        Solicitante {
            es_kernel: false,
            es_mismo_agente: false,
            es_componente_aegis: false,
        }
    }

    fn otp_para(
        sk: &ClaveFirmaHibrida,
        op: OperacionProtegida,
        host_id: [u8; HOST_ID_LEN],
    ) -> Vec<u8> {
        Otp::emitir(sk, host_id, op, HORA, VALIDEZ)
            .expect("emitir OTP")
            .a_bytes()
    }

    #[test]
    fn sigterm_de_un_atacante_sin_otp_se_deniega() {
        // El caso central: un administrador hostil hace `kill -TERM` al EDR.
        let (_sk, vk) = control();
        let mut r = AegisResilience::nuevo(host(), vk);
        let res = r.evaluar_detencion(SenalDetencion::SenalPosix(SIGTERM), tercero(), None, HORA);
        assert_eq!(res.veredicto, Veredicto::Denegar);
        assert_eq!(res.operacion, Some(OperacionProtegida::DetenerServicio));
        assert_eq!(res.motivo, MotivoDetencion::DenegadaSinAutorizacion);
        assert!(res.interceptable_en_usuario);
        assert!(!res.permitida());
    }

    #[test]
    fn sigterm_con_otp_valido_del_dueno_se_permite_y_se_consume() {
        let (sk, vk) = control();
        let mut r = AegisResilience::nuevo(host(), vk);
        let otp = otp_para(&sk, OperacionProtegida::DetenerServicio, host());

        let res = r.evaluar_detencion(
            SenalDetencion::SenalPosix(SIGTERM),
            tercero(),
            Some(&otp),
            HORA + 5,
        );
        assert_eq!(res.veredicto, Veredicto::Permitir);
        assert_eq!(res.motivo, MotivoDetencion::AutorizadaPorOtp);

        // El OTP es de un solo uso: repetir la MISMA parada con el MISMO OTP
        // ahora se rechaza por replay -> se deniega.
        let res2 = r.evaluar_detencion(
            SenalDetencion::SenalPosix(SIGTERM),
            tercero(),
            Some(&otp),
            HORA + 6,
        );
        assert_eq!(res2.veredicto, Veredicto::Denegar);
        assert_eq!(
            res2.motivo,
            MotivoDetencion::OtpRechazado(TamperError::Replay)
        );
    }

    #[test]
    fn desinstalar_con_su_otp_se_permite() {
        let (sk, vk) = control();
        let mut r = AegisResilience::nuevo(host(), vk);
        let otp = otp_para(&sk, OperacionProtegida::Desinstalar, host());
        let res = r.evaluar_detencion(
            SenalDetencion::PeticionDesinstalar,
            tercero(),
            Some(&otp),
            HORA,
        );
        assert_eq!(res.veredicto, Veredicto::Permitir);
        assert_eq!(res.operacion, Some(OperacionProtegida::Desinstalar));
        assert_eq!(res.motivo, MotivoDetencion::AutorizadaPorOtp);
    }

    #[test]
    fn un_otp_para_otra_operacion_no_sirve_para_esta_parada() {
        // OTP de "detener servicio" no autoriza "desinstalar".
        let (sk, vk) = control();
        let mut r = AegisResilience::nuevo(host(), vk);
        let otp = otp_para(&sk, OperacionProtegida::DetenerServicio, host());
        let res = r.evaluar_detencion(
            SenalDetencion::PeticionDesinstalar,
            tercero(),
            Some(&otp),
            HORA,
        );
        assert_eq!(res.veredicto, Veredicto::Denegar);
        assert!(matches!(
            res.motivo,
            MotivoDetencion::OtpRechazado(TamperError::OperacionEquivocada { .. })
        ));
    }

    #[test]
    fn un_otp_de_otro_host_no_sirve_aqui() {
        let (sk, vk) = control();
        let mut r = AegisResilience::nuevo(host(), vk);
        // OTP emitido para OTRO host.
        let otp = otp_para(
            &sk,
            OperacionProtegida::DetenerServicio,
            [0x11u8; HOST_ID_LEN],
        );
        let res = r.evaluar_detencion(
            SenalDetencion::SenalPosix(SIGTERM),
            tercero(),
            Some(&otp),
            HORA,
        );
        assert_eq!(res.veredicto, Veredicto::Denegar);
        assert_eq!(
            res.motivo,
            MotivoDetencion::OtpRechazado(TamperError::HostEquivocado)
        );
    }

    #[test]
    fn un_otp_de_otro_control_plane_no_sirve() {
        let (sk, _vk) = control();
        // El guardian confia en OTRA clave (otro plano de control / un impostor).
        let vk_impostor =
            ClaveFirmaHibrida::desde_semillas(&[1u8; 32], &[2u8; 32]).clave_verificacion();
        let mut r = AegisResilience::nuevo(host(), vk_impostor);
        let otp = otp_para(&sk, OperacionProtegida::DetenerServicio, host());
        let res = r.evaluar_detencion(
            SenalDetencion::SenalPosix(SIGTERM),
            tercero(),
            Some(&otp),
            HORA,
        );
        assert_eq!(res.veredicto, Veredicto::Denegar);
        assert_eq!(
            res.motivo,
            MotivoDetencion::OtpRechazado(TamperError::FirmaInvalida)
        );
    }

    #[test]
    fn el_watchdog_puede_parar_el_servicio_sin_otp() {
        // Un componente de AegisCore (el watchdog) reinicia el agente: se permite
        // sin gastar OTP.
        let (_sk, vk) = control();
        let mut r = AegisResilience::nuevo(host(), vk);
        let comp = Solicitante {
            es_kernel: false,
            es_mismo_agente: false,
            es_componente_aegis: true,
        };
        let res = r.evaluar_detencion(
            SenalDetencion::ControlServicio(abi::SERVICE_CONTROL_STOP),
            comp,
            None,
            HORA,
        );
        assert_eq!(res.veredicto, Veredicto::Permitir);
        assert_eq!(res.motivo, MotivoDetencion::SolicitanteDeConfianza);
    }

    #[test]
    fn un_otp_valido_no_se_gasta_si_el_solicitante_ya_es_de_confianza() {
        // Si el watchdog acompana un OTP (innecesario), NO se consume: sigue
        // disponible para una parada de un tercero despues.
        let (sk, vk) = control();
        let mut r = AegisResilience::nuevo(host(), vk);
        let otp = otp_para(&sk, OperacionProtegida::DetenerServicio, host());
        let comp = Solicitante {
            es_kernel: false,
            es_mismo_agente: false,
            es_componente_aegis: true,
        };
        // El watchdog para el servicio y pasa el OTP: se permite por confianza.
        let r1 = r.evaluar_detencion(SenalDetencion::SenalPosix(SIGTERM), comp, Some(&otp), HORA);
        assert_eq!(r1.motivo, MotivoDetencion::SolicitanteDeConfianza);
        // El MISMO OTP todavia sirve para un tercero: no se habia gastado.
        let r2 = r.evaluar_detencion(
            SenalDetencion::SenalPosix(SIGTERM),
            tercero(),
            Some(&otp),
            HORA,
        );
        assert_eq!(r2.veredicto, Veredicto::Permitir);
        assert_eq!(r2.motivo, MotivoDetencion::AutorizadaPorOtp);
    }

    #[test]
    fn sigkill_se_decide_pero_se_declara_no_interceptable() {
        // LA HONESTIDAD: un SIGKILL de un atacante DEBERIA denegarse, y asi se
        // decide; pero el guardian NO finge poder pararlo desde el usuario. El
        // cumplimiento es del kernel (PPL). El campo lo dice.
        let (_sk, vk) = control();
        let mut r = AegisResilience::nuevo(host(), vk);
        let res = r.evaluar_detencion(SenalDetencion::SenalPosix(SIGKILL), tercero(), None, HORA);
        assert_eq!(res.veredicto, Veredicto::Denegar);
        assert!(
            !res.interceptable_en_usuario,
            "SIGKILL no se puede interceptar desde el espacio de usuario; solo el kernel (PPL)"
        );
        // SIGSTOP, igual.
        let res2 = r.evaluar_detencion(SenalDetencion::SenalPosix(SIGSTOP), tercero(), None, HORA);
        assert!(!res2.interceptable_en_usuario);
    }

    #[test]
    fn una_senal_que_no_es_parada_no_se_toca() {
        // SIGHUP (recargar config) o INTERROGATE (consultar estado) no son
        // paradas de un recurso protegido: no aplica, se permite.
        let (_sk, vk) = control();
        let mut r = AegisResilience::nuevo(host(), vk);
        let hup = r.evaluar_detencion(SenalDetencion::SenalPosix(1), tercero(), None, HORA);
        assert_eq!(hup.veredicto, Veredicto::Permitir);
        assert_eq!(hup.motivo, MotivoDetencion::NoAplica);
        assert_eq!(hup.operacion, None);

        let interrogate = r.evaluar_detencion(
            SenalDetencion::ControlServicio(abi::SERVICE_CONTROL_INTERROGATE),
            tercero(),
            None,
            HORA,
        );
        assert_eq!(interrogate.motivo, MotivoDetencion::NoAplica);
    }

    #[test]
    fn un_otp_mal_formado_se_rechaza_como_formato() {
        let (_sk, vk) = control();
        let mut r = AegisResilience::nuevo(host(), vk);
        let basura = [0u8; 10];
        let res = r.evaluar_detencion(
            SenalDetencion::SenalPosix(SIGTERM),
            tercero(),
            Some(&basura),
            HORA,
        );
        assert_eq!(res.veredicto, Veredicto::Denegar);
        assert!(matches!(
            res.motivo,
            MotivoDetencion::OtpRechazado(TamperError::FormatoInvalido(_))
        ));
    }
}
