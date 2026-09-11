//! La decision de tamper: permitir o denegar una operacion destructiva sobre
//! AegisCore.
//!
//! Es el espejo en Rust de `kernel/windows/aegis/aegis_tamper_politica.c`, la
//! politica portable que el futuro minifilter del WDK incluye. Los dos deciden
//! sobre la MISMA tabla de verdad; este modulo se prueba aqui, en cada
//! `make ci`, y el C se prueba con gcc y clang en `verificar-windows.sh`.
//!
//! # La parte que puede estar MAL de forma peligrosa
//!
//! De MENOS (permitir lo que no se debe): un atacante con privilegios de
//! administrador borra el binario o mata el servicio, y el EDR desaparece justo
//! cuando hace falta. De MAS (denegar lo que se debe): el **dueno** no puede
//! desinstalar AegisCore, y un EDR que no se deja quitar por su dueno es
//! malware. La decision equilibra las dos con una sola regla nueva: la
//! autorizacion del dueno (el OTP) SIEMPRE gana.

use crate::OperacionProtegida;

/// Quien solicita la operacion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Solicitante {
    /// El propio kernel (el gestor de E/S, el de configuracion). Nunca se le
    /// pelea: un atacante ya en el kernel no necesita esto, y estorbarle rompe
    /// el sistema operativo del dueno.
    pub es_kernel: bool,
    /// El propio proceso del agente sobre sus propios recursos.
    pub es_mismo_agente: bool,
    /// Otro componente de AegisCore verificado por firma (el watchdog, que tiene
    /// que poder pararse y reiniciarse para la auto-recuperacion).
    pub es_componente_aegis: bool,
}

/// Contexto de una operacion potencialmente destructiva sobre un recurso.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextoTamper {
    /// El objetivo es un recurso protegido de AegisCore (su binario, su
    /// servicio, su clave de registro, su proceso).
    pub recurso_protegido: bool,
    /// Que se intenta hacer.
    pub operacion: OperacionProtegida,
    /// Quien lo intenta.
    pub solicitante: Solicitante,
    /// Si viene acompanada de un OTP del Control Plane que YA se verifico
    /// (la criptografia la hace [`crate::otp`]; aqui llega el booleano).
    pub orden_autorizada: bool,
}

/// El veredicto de la politica.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Veredicto {
    /// Se deja pasar la operacion.
    Permitir,
    /// Se bloquea la operacion (sabotaje sin autorizacion).
    Denegar,
}

/// Decide si una operacion sobre un recurso de AegisCore se permite o se deniega.
///
/// El orden de las reglas es la decision de seguridad, y termina en la linea
/// etica: con autorizacion del dueno, se permite; sin ella, sobre un recurso
/// nuestro, se deniega.
#[must_use]
pub fn decidir(ctx: &ContextoTamper) -> Veredicto {
    // 1. Nunca pelear contra el sistema operativo ni contra nosotros mismos.
    if ctx.solicitante.es_kernel
        || ctx.solicitante.es_mismo_agente
        || ctx.solicitante.es_componente_aegis
    {
        return Veredicto::Permitir;
    }

    // 2. Solo defendemos lo nuestro. Sobre un recurso ajeno, no nos metemos: un
    //    EDR no es la razon por la que las apps del cliente dejan de funcionar.
    if !ctx.recurso_protegido {
        return Veredicto::Permitir;
    }

    // 3. LA LINEA ETICA. Un recurso protegido, pero con una orden autorizada del
    //    Control Plane: es el dueno de la flota ejerciendo su derecho a
    //    desinstalar/parar/quitar. SIEMPRE se permite. Es lo que separa a
    //    AegisCore de un rootkit.
    if ctx.orden_autorizada {
        return Veredicto::Permitir;
    }

    // 4. Recurso protegido, sin autorizacion: sabotaje. Se deniega.
    Veredicto::Denegar
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nadie() -> Solicitante {
        Solicitante {
            es_kernel: false,
            es_mismo_agente: false,
            es_componente_aegis: false,
        }
    }

    fn ctx(recurso_protegido: bool, orden_autorizada: bool, sol: Solicitante) -> ContextoTamper {
        ContextoTamper {
            recurso_protegido,
            operacion: OperacionProtegida::BorrarBinario,
            solicitante: sol,
            orden_autorizada,
        }
    }

    #[test]
    fn sabotaje_sin_otp_se_deniega() {
        // Un administrador cualquiera intenta borrar el binario del EDR sin OTP.
        assert_eq!(decidir(&ctx(true, false, nadie())), Veredicto::Denegar);
    }

    #[test]
    fn el_dueno_con_otp_puede_desinstalar() {
        // LA LINEA ETICA: con OTP valido, la eliminacion se permite.
        assert_eq!(decidir(&ctx(true, true, nadie())), Veredicto::Permitir);
    }

    #[test]
    fn sobre_recurso_ajeno_no_nos_metemos() {
        assert_eq!(decidir(&ctx(false, false, nadie())), Veredicto::Permitir);
    }

    #[test]
    fn nunca_se_pelea_al_kernel_ni_a_uno_mismo_ni_a_los_componentes() {
        let kernel = Solicitante {
            es_kernel: true,
            ..nadie()
        };
        let mismo = Solicitante {
            es_mismo_agente: true,
            ..nadie()
        };
        let comp = Solicitante {
            es_componente_aegis: true,
            ..nadie()
        };
        // Aunque sea un recurso protegido y sin OTP, a estos tres se les permite.
        assert_eq!(decidir(&ctx(true, false, kernel)), Veredicto::Permitir);
        assert_eq!(decidir(&ctx(true, false, mismo)), Veredicto::Permitir);
        assert_eq!(decidir(&ctx(true, false, comp)), Veredicto::Permitir);
    }

    #[test]
    fn tabla_de_verdad_completa() {
        // Solo se deniega el caso: recurso protegido, sin autorizacion, y el
        // solicitante NO es kernel/self/componente.
        for recurso in [false, true] {
            for otp in [false, true] {
                for k in [false, true] {
                    for s in [false, true] {
                        for c in [false, true] {
                            let sol = Solicitante {
                                es_kernel: k,
                                es_mismo_agente: s,
                                es_componente_aegis: c,
                            };
                            let v = decidir(&ctx(recurso, otp, sol));
                            let debe_denegar = recurso && !otp && !k && !s && !c;
                            assert_eq!(
                                v == Veredicto::Denegar,
                                debe_denegar,
                                "recurso={recurso} otp={otp} k={k} s={s} c={c}"
                            );
                        }
                    }
                }
            }
        }
    }
}
