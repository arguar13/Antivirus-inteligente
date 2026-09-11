//! La orden de operacion autorizada (OTP): la llave que el dueno tiene y el
//! atacante no.
//!
//! # Por que un OTP firmado y de un solo uso
//!
//! El motor de tamper deniega que se borre, se pare o se mate a AegisCore. Si
//! esa negativa fuera absoluta, AegisCore seria imposible de desinstalar —y eso
//! es exactamente lo que hace un rootkit—. La linea etica exige que el **dueno
//! de la flota** pueda quitarlo cuando quiera. La forma de darle esa capacidad
//! SIN darsela tambien al atacante es un token que **solo el Control Plane puede
//! emitir**:
//!
//! - **Firmado** con la firma hibrida (Ed25519 + ML-DSA-65) de la clave del
//!   Control Plane: un atacante no puede fabricar uno sin esa clave privada, ni
//!   siquiera con una computadora cuantica (FASE 59).
//! - **Atado a este host**: un OTP capturado en un endpoint no autoriza nada en
//!   otro (`host_id`).
//! - **Atado a una operacion**: un OTP para "parar el servicio" no vale para
//!   "borrar el binario" (`operacion`).
//! - **Con ventana de validez**: caduca (`emitido` + `validez`).
//! - **De un solo uso**: el `nonce` se consume; un OTP reproducido se rechaza
//!   (ver [`crate::replay`]).

use crate::{RegistroOtp, TamperError};
use aegis_pqc::firma_hibrida::{
    ClaveFirmaHibrida, ClaveVerificacionHibrida, FirmaHibrida, FIRMA_HIBRIDA_LEN,
};

/// Dominio de separacion de la firma del OTP: una firma valida para un OTP no
/// puede reinterpretarse como valida para un artefacto de actualizacion.
const DOMINIO_OTP: &[u8] = b"AegisCore/autodefensa/otp/v1";

/// Longitud del identificador de host (un SHA-256 de la identidad estable).
pub const HOST_ID_LEN: usize = 32;
/// Longitud del nonce anti-replay.
pub const NONCE_LEN: usize = 32;
/// Longitud serializada de la orden (sin la firma): host(32) + op(1) +
/// nonce(32) + emitido(8) + validez(4).
pub const ORDEN_LEN: usize = HOST_ID_LEN + 1 + NONCE_LEN + 8 + 4;
/// Longitud serializada del OTP completo: orden + firma hibrida.
pub const OTP_LEN: usize = ORDEN_LEN + FIRMA_HIBRIDA_LEN;

/// Operacion privilegiada sobre AegisCore que exige autorizacion del dueno.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum OperacionProtegida {
    /// Desinstalar por completo el agente (el camino de salida del dueno).
    Desinstalar = 1,
    /// Detener el servicio del agente.
    DetenerServicio = 2,
    /// Borrar un binario protegido de AegisCore.
    BorrarBinario = 3,
    /// Borrar una clave de registro protegida de AegisCore.
    BorrarClaveRegistro = 4,
    /// Bajar la proteccion del proceso (PPL) para permitir su manipulacion.
    DesprotegerProceso = 5,
}

impl OperacionProtegida {
    /// Byte que se serializa.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for OperacionProtegida {
    type Error = TamperError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(OperacionProtegida::Desinstalar),
            2 => Ok(OperacionProtegida::DetenerServicio),
            3 => Ok(OperacionProtegida::BorrarBinario),
            4 => Ok(OperacionProtegida::BorrarClaveRegistro),
            5 => Ok(OperacionProtegida::DesprotegerProceso),
            _ => Err(TamperError::FormatoInvalido("operacion desconocida")),
        }
    }
}

/// La orden en si: que se autoriza, a quien, cuando y con que frescura.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrdenAutorizada {
    /// SHA-256 de la identidad estable del host autorizado.
    pub host_id: [u8; HOST_ID_LEN],
    /// Operacion autorizada.
    pub operacion: OperacionProtegida,
    /// Nonce de un solo uso.
    pub nonce: [u8; NONCE_LEN],
    /// Instante de emision (segundos Unix).
    pub emitido_unix: u64,
    /// Validez desde `emitido_unix`, en segundos.
    pub validez_seg: u32,
}

impl OrdenAutorizada {
    /// Serializa de forma canonica (enteros en big-endian) a [`ORDEN_LEN`] bytes.
    ///
    /// Es lo que se firma: un orden de bytes fijo es lo que hace la firma
    /// reproducible y no ambigua.
    #[must_use]
    pub fn a_bytes(&self) -> [u8; ORDEN_LEN] {
        let mut out = [0u8; ORDEN_LEN];
        let mut i = 0;
        out[i..i + HOST_ID_LEN].copy_from_slice(&self.host_id);
        i += HOST_ID_LEN;
        out[i] = self.operacion.as_u8();
        i += 1;
        out[i..i + NONCE_LEN].copy_from_slice(&self.nonce);
        i += NONCE_LEN;
        out[i..i + 8].copy_from_slice(&self.emitido_unix.to_be_bytes());
        i += 8;
        out[i..i + 4].copy_from_slice(&self.validez_seg.to_be_bytes());
        out
    }

    /// Reconstruye desde bytes canonicos.
    ///
    /// # Errores
    /// [`TamperError::FormatoInvalido`] si el tamano o la operacion no cuadran.
    pub fn desde_bytes(bytes: &[u8]) -> Result<Self, TamperError> {
        if bytes.len() != ORDEN_LEN {
            return Err(TamperError::FormatoInvalido("tamano de orden invalido"));
        }
        let mut host_id = [0u8; HOST_ID_LEN];
        host_id.copy_from_slice(&bytes[..HOST_ID_LEN]);
        let operacion = OperacionProtegida::try_from(bytes[HOST_ID_LEN])?;
        let mut nonce = [0u8; NONCE_LEN];
        let base = HOST_ID_LEN + 1;
        nonce.copy_from_slice(&bytes[base..base + NONCE_LEN]);
        let base = base + NONCE_LEN;
        let emitido_unix = u64::from_be_bytes(bytes[base..base + 8].try_into().unwrap_or_default());
        let base = base + 8;
        let validez_seg = u32::from_be_bytes(bytes[base..base + 4].try_into().unwrap_or_default());
        Ok(Self {
            host_id,
            operacion,
            nonce,
            emitido_unix,
            validez_seg,
        })
    }

    /// `true` si `ahora_unix` cae dentro de `[emitido, emitido + validez]`.
    #[must_use]
    pub fn dentro_de_ventana(&self, ahora_unix: u64) -> bool {
        // `saturating_add` evita que una validez enorme desborde el u64.
        ahora_unix >= self.emitido_unix
            && ahora_unix
                <= self
                    .emitido_unix
                    .saturating_add(u64::from(self.validez_seg))
    }
}

/// El OTP completo: la orden y su firma hibrida.
#[derive(Clone)]
pub struct Otp {
    /// La orden autorizada.
    pub orden: OrdenAutorizada,
    firma: FirmaHibrida,
}

impl core::fmt::Debug for Otp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Se muestra la orden; la firma (3374 bytes) se resume.
        f.debug_struct("Otp")
            .field("orden", &self.orden)
            .field("firma", &"<firma hibrida, 3374 bytes>")
            .finish()
    }
}

impl Otp {
    /// Emite un OTP: lo firma el Control Plane con su clave hibrida, tomando el
    /// nonce de la entropia del sistema. Es la unica forma de crear uno valido.
    ///
    /// # Errores
    /// [`TamperError::Entropia`] si no hay entropia; [`TamperError::FirmaInvalida`]
    /// si la firma falla (p. ej. un contexto imposible).
    pub fn emitir(
        clave: &ClaveFirmaHibrida,
        host_id: [u8; HOST_ID_LEN],
        operacion: OperacionProtegida,
        emitido_unix: u64,
        validez_seg: u32,
    ) -> Result<Otp, TamperError> {
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce).map_err(|_| TamperError::Entropia)?;
        Self::emitir_con_nonce(clave, host_id, operacion, nonce, emitido_unix, validez_seg)
    }

    /// Como [`Otp::emitir`] pero con el nonce dado (para pruebas reproducibles y
    /// para un Control Plane que gestione su propia fuente de nonces).
    ///
    /// # Errores
    /// [`TamperError::FirmaInvalida`] si la firma falla.
    pub fn emitir_con_nonce(
        clave: &ClaveFirmaHibrida,
        host_id: [u8; HOST_ID_LEN],
        operacion: OperacionProtegida,
        nonce: [u8; NONCE_LEN],
        emitido_unix: u64,
        validez_seg: u32,
    ) -> Result<Otp, TamperError> {
        let orden = OrdenAutorizada {
            host_id,
            operacion,
            nonce,
            emitido_unix,
            validez_seg,
        };
        let firma = clave
            .firmar(&orden.a_bytes(), DOMINIO_OTP)
            .map_err(|_| TamperError::FirmaInvalida)?;
        Ok(Otp { orden, firma })
    }

    /// Serializa como `orden (77) || firma_hibrida (3374)`.
    #[must_use]
    pub fn a_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(OTP_LEN);
        out.extend_from_slice(&self.orden.a_bytes());
        out.extend_from_slice(&self.firma.a_bytes());
        out
    }

    /// Reconstruye desde el formato de wire.
    ///
    /// # Errores
    /// [`TamperError::FormatoInvalido`] si el tamano no cuadra o la firma esta
    /// mal formada / de suite no aceptada.
    pub fn desde_bytes(bytes: &[u8]) -> Result<Otp, TamperError> {
        if bytes.len() != OTP_LEN {
            return Err(TamperError::FormatoInvalido("tamano de OTP invalido"));
        }
        let orden = OrdenAutorizada::desde_bytes(&bytes[..ORDEN_LEN])?;
        let firma = FirmaHibrida::desde_bytes(&bytes[ORDEN_LEN..])
            .map_err(|_| TamperError::FormatoInvalido("firma hibrida mal formada"))?;
        Ok(Otp { orden, firma })
    }

    /// Verifica y CONSUME el OTP para autorizar `operacion_pedida` en este host.
    ///
    /// Comprueba, en este orden (cada paso es una defensa):
    /// 1. La **firma hibrida** contra la clave del Control Plane. Hasta que no
    ///    verifica, la orden son bytes de cualquiera.
    /// 2. El **host**: la orden es para esta maquina.
    /// 3. La **operacion**: la orden autoriza justo lo que se intenta.
    /// 4. La **ventana**: no ha caducado ni viene del futuro.
    /// 5. El **anti-replay**: el nonce no se habia usado; se consume ahora.
    ///
    /// Solo si TODO pasa devuelve `Ok(())`, que significa "autorizado".
    ///
    /// # Errores
    /// La variante de [`TamperError`] que explica por que se rechaza.
    pub fn verificar_y_consumir(
        &self,
        clave_control: &ClaveVerificacionHibrida,
        host_id_local: &[u8; HOST_ID_LEN],
        operacion_pedida: OperacionProtegida,
        ahora_unix: u64,
        registro: &mut RegistroOtp,
    ) -> Result<(), TamperError> {
        // 1. Firma primero: antes de creerse nada del contenido.
        if !clave_control.verificar(&self.orden.a_bytes(), DOMINIO_OTP, &self.firma) {
            return Err(TamperError::FirmaInvalida);
        }
        // 2. Host.
        if &self.orden.host_id != host_id_local {
            return Err(TamperError::HostEquivocado);
        }
        // 3. Operacion.
        if self.orden.operacion != operacion_pedida {
            return Err(TamperError::OperacionEquivocada {
                autorizada: self.orden.operacion,
                pedida: operacion_pedida,
            });
        }
        // 4. Ventana de validez.
        if !self.orden.dentro_de_ventana(ahora_unix) {
            return Err(TamperError::FueraDeVentana);
        }
        // 5. Anti-replay: consume el nonce. Es lo ULTIMO para no gastar un OTP
        //    legitimo por un fallo anterior (host/operacion/firma). Se recuerda
        //    hasta que el OTP expira; despues, la ventana ya lo rechaza sola.
        let expira = self
            .orden
            .emitido_unix
            .saturating_add(u64::from(self.orden.validez_seg));
        registro.consumir(&self.orden.nonce, expira)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HORA: u64 = 1_800_000_000;
    const VALIDEZ: u32 = 300;

    fn claves() -> (ClaveFirmaHibrida, ClaveVerificacionHibrida) {
        let sk = ClaveFirmaHibrida::desde_semillas(&[9u8; 32], &[11u8; 32]);
        let vk = sk.clave_verificacion();
        (sk, vk)
    }

    fn host() -> [u8; HOST_ID_LEN] {
        [0x42u8; HOST_ID_LEN]
    }

    #[test]
    fn un_otp_valido_autoriza_y_se_consume() {
        let (sk, vk) = claves();
        let mut reg = RegistroOtp::nuevo();
        let otp = Otp::emitir(&sk, host(), OperacionProtegida::Desinstalar, HORA, VALIDEZ)
            .expect("emitir");
        assert_eq!(
            otp.verificar_y_consumir(
                &vk,
                &host(),
                OperacionProtegida::Desinstalar,
                HORA + 10,
                &mut reg
            ),
            Ok(())
        );
    }

    #[test]
    fn wire_roundtrip() {
        let (sk, vk) = claves();
        let mut reg = RegistroOtp::nuevo();
        let otp = Otp::emitir(
            &sk,
            host(),
            OperacionProtegida::DetenerServicio,
            HORA,
            VALIDEZ,
        )
        .expect("emitir");
        let bytes = otp.a_bytes();
        assert_eq!(bytes.len(), OTP_LEN);
        let otp2 = Otp::desde_bytes(&bytes).expect("desde_bytes");
        assert!(otp2
            .verificar_y_consumir(
                &vk,
                &host(),
                OperacionProtegida::DetenerServicio,
                HORA,
                &mut reg
            )
            .is_ok());
    }

    #[test]
    fn un_otp_de_otro_control_plane_no_autoriza() {
        let (sk, _) = claves();
        let otro_vk =
            ClaveFirmaHibrida::desde_semillas(&[1u8; 32], &[2u8; 32]).clave_verificacion();
        let mut reg = RegistroOtp::nuevo();
        let otp = Otp::emitir(&sk, host(), OperacionProtegida::Desinstalar, HORA, VALIDEZ)
            .expect("emitir");
        assert_eq!(
            otp.verificar_y_consumir(
                &otro_vk,
                &host(),
                OperacionProtegida::Desinstalar,
                HORA,
                &mut reg
            ),
            Err(TamperError::FirmaInvalida)
        );
    }

    #[test]
    fn un_otp_de_otro_host_no_autoriza_aqui() {
        let (sk, vk) = claves();
        let mut reg = RegistroOtp::nuevo();
        let otp = Otp::emitir(
            &sk,
            [0x11u8; 32],
            OperacionProtegida::Desinstalar,
            HORA,
            VALIDEZ,
        )
        .expect("emitir");
        assert_eq!(
            otp.verificar_y_consumir(
                &vk,
                &host(),
                OperacionProtegida::Desinstalar,
                HORA,
                &mut reg
            ),
            Err(TamperError::HostEquivocado)
        );
    }

    #[test]
    fn un_otp_para_otra_operacion_no_autoriza() {
        let (sk, vk) = claves();
        let mut reg = RegistroOtp::nuevo();
        let otp = Otp::emitir(
            &sk,
            host(),
            OperacionProtegida::DetenerServicio,
            HORA,
            VALIDEZ,
        )
        .expect("emitir");
        assert!(matches!(
            otp.verificar_y_consumir(
                &vk,
                &host(),
                OperacionProtegida::Desinstalar,
                HORA,
                &mut reg
            ),
            Err(TamperError::OperacionEquivocada { .. })
        ));
    }

    #[test]
    fn un_otp_caducado_no_autoriza() {
        let (sk, vk) = claves();
        let mut reg = RegistroOtp::nuevo();
        let otp = Otp::emitir(&sk, host(), OperacionProtegida::Desinstalar, HORA, VALIDEZ)
            .expect("emitir");
        assert_eq!(
            otp.verificar_y_consumir(
                &vk,
                &host(),
                OperacionProtegida::Desinstalar,
                HORA + u64::from(VALIDEZ) + 1,
                &mut reg
            ),
            Err(TamperError::FueraDeVentana)
        );
    }

    #[test]
    fn un_otp_no_se_puede_reproducir() {
        let (sk, vk) = claves();
        let mut reg = RegistroOtp::nuevo();
        let otp = Otp::emitir(&sk, host(), OperacionProtegida::Desinstalar, HORA, VALIDEZ)
            .expect("emitir");
        // Primer uso: OK.
        assert!(otp
            .verificar_y_consumir(
                &vk,
                &host(),
                OperacionProtegida::Desinstalar,
                HORA,
                &mut reg
            )
            .is_ok());
        // Segundo uso del MISMO OTP: rechazado.
        assert_eq!(
            otp.verificar_y_consumir(
                &vk,
                &host(),
                OperacionProtegida::Desinstalar,
                HORA,
                &mut reg
            ),
            Err(TamperError::Replay)
        );
    }

    #[test]
    fn un_bit_alterado_invalida_la_firma() {
        // Como la firma cubre la orden entera y se comprueba PRIMERO, tocar
        // cualquier byte —de la orden o de la firma— la invalida: la manipulacion
        // es detectable, no da un OTP con otro host o otra operacion "colada".
        let (sk, vk) = claves();
        let mut reg = RegistroOtp::nuevo();
        let otp = Otp::emitir(&sk, host(), OperacionProtegida::Desinstalar, HORA, VALIDEZ)
            .expect("emitir");

        // Byte dentro de la orden firmada (el host_id).
        let mut b1 = otp.a_bytes();
        b1[0] ^= 0x01;
        let o1 = Otp::desde_bytes(&b1).expect("tamano");
        assert_eq!(
            o1.verificar_y_consumir(
                &vk,
                &host(),
                OperacionProtegida::Desinstalar,
                HORA,
                &mut reg
            ),
            Err(TamperError::FirmaInvalida)
        );

        // Byte dentro de la propia firma (la cola de ML-DSA).
        let mut b2 = otp.a_bytes();
        let n = b2.len();
        b2[n - 1] ^= 0x01;
        let o2 = Otp::desde_bytes(&b2).expect("tamano");
        assert_eq!(
            o2.verificar_y_consumir(
                &vk,
                &host(),
                OperacionProtegida::Desinstalar,
                HORA,
                &mut reg
            ),
            Err(TamperError::FirmaInvalida)
        );
    }
}
