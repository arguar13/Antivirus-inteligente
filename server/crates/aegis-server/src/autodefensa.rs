//! Emision de ordenes de operacion autorizada (OTP): el camino de
//! desinstalacion del dueno de la flota (FASE 55').
//!
//! La autodefensa del agente (crate `aegis-selfdefense`) deniega que se borre, se
//! pare o se mate a AegisCore salvo que se presente un OTP valido. El **unico**
//! que puede emitir ese OTP es el plano de control, con su clave de firma
//! hibrida. Esto es lo que hace la linea etica REAL y no un eslogan: el dueno de
//! la flota, desde su consola, emite la orden y el agente la obedece; un atacante
//! no puede fabricarla porque no tiene la clave privada.
//!
//! La clave privada de firma vive solo en el plano de control (igual que la clave
//! de firma de actualizaciones); el agente lleva unicamente la publica, con la
//! que verifica.

use aegis_pqc::firma_hibrida::{ClaveFirmaHibrida, ClaveVerificacionHibrida};
use aegis_selfdefense::otp::HOST_ID_LEN;
use aegis_selfdefense::{OperacionProtegida, Otp, TamperError};

/// El emisor de OTP del plano de control. Guarda la clave de firma hibrida.
#[derive(Debug)]
pub struct EmisorOtp {
    clave: ClaveFirmaHibrida,
}

impl EmisorOtp {
    /// Crea un emisor con una clave de firma hibrida ya existente.
    #[must_use]
    pub fn nuevo(clave: ClaveFirmaHibrida) -> Self {
        Self { clave }
    }

    /// Crea un emisor de forma determinista desde dos semillas (para derivar la
    /// clave del plano de control de un secreto maestro, y para pruebas).
    #[must_use]
    pub fn desde_semillas(ed_semilla: &[u8; 32], mldsa_semilla: &[u8; 32]) -> Self {
        Self {
            clave: ClaveFirmaHibrida::desde_semillas(ed_semilla, mldsa_semilla),
        }
    }

    /// La clave publica de verificacion, para publicarla a la flota (por el canal
    /// firmado de actualizaciones, como cualquier otro material de confianza).
    #[must_use]
    pub fn clave_verificacion(&self) -> ClaveVerificacionHibrida {
        self.clave.clave_verificacion()
    }

    /// Emite un OTP para `host_id` que autoriza `operacion` durante `validez_seg`
    /// segundos desde `emitido_unix`. Devuelve el OTP serializado, listo para
    /// enviar al agente.
    ///
    /// # Errores
    /// [`TamperError::Entropia`] si no hay entropia para el nonce;
    /// [`TamperError::FirmaInvalida`] si la firma falla.
    pub fn emitir(
        &self,
        host_id: [u8; HOST_ID_LEN],
        operacion: OperacionProtegida,
        emitido_unix: u64,
        validez_seg: u32,
    ) -> Result<Vec<u8>, TamperError> {
        Ok(Otp::emitir(&self.clave, host_id, operacion, emitido_unix, validez_seg)?.a_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_selfdefense::RegistroOtp;

    const HORA: u64 = 1_800_000_000;

    #[test]
    fn el_plano_de_control_emite_un_otp_que_el_agente_acepta() {
        let emisor = EmisorOtp::desde_semillas(&[5u8; 32], &[6u8; 32]);
        let vk = emisor.clave_verificacion();
        let host = [0xABu8; 32];

        let bytes = emisor
            .emitir(host, OperacionProtegida::Desinstalar, HORA, 300)
            .expect("emitir");

        // El agente lo recibe, lo reconstruye y lo verifica.
        let otp = Otp::desde_bytes(&bytes).expect("desde_bytes");
        let mut reg = RegistroOtp::nuevo();
        assert!(otp
            .verificar_y_consumir(
                &vk,
                &host,
                OperacionProtegida::Desinstalar,
                HORA + 100,
                &mut reg
            )
            .is_ok());
    }

    #[test]
    fn un_otp_no_vale_en_otro_host_ni_dos_veces() {
        let emisor = EmisorOtp::desde_semillas(&[5u8; 32], &[6u8; 32]);
        let vk = emisor.clave_verificacion();
        let host = [0x11u8; 32];
        let otro_host = [0x22u8; 32];

        let bytes = emisor
            .emitir(host, OperacionProtegida::DetenerServicio, HORA, 300)
            .expect("emitir");
        let otp = Otp::desde_bytes(&bytes).expect("desde_bytes");
        let mut reg = RegistroOtp::nuevo();

        // Otro host: rechazado.
        assert_eq!(
            otp.verificar_y_consumir(
                &vk,
                &otro_host,
                OperacionProtegida::DetenerServicio,
                HORA,
                &mut reg
            ),
            Err(TamperError::HostEquivocado)
        );
        // En su host: primera vez OK.
        assert!(otp
            .verificar_y_consumir(
                &vk,
                &host,
                OperacionProtegida::DetenerServicio,
                HORA,
                &mut reg
            )
            .is_ok());
        // Segunda vez (replay): rechazado.
        assert_eq!(
            otp.verificar_y_consumir(
                &vk,
                &host,
                OperacionProtegida::DetenerServicio,
                HORA,
                &mut reg
            ),
            Err(TamperError::Replay)
        );
    }
}
