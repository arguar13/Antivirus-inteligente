//! Fontaneria: emitir el quote hablando con el TPM real. GATED.
//!
//! # Por que esto no se compila en el CI de este proyecto
//!
//! Emitir un quote exige un chip TPM 2.0 accesible por `/dev/tpmrm0` (el
//! *resource manager*, que serializa el acceso multiproceso). Este entorno de
//! integracion no tiene ni chip ni simulador, asi que este modulo esta tras la
//! feature `tpm-hardware` y el CI DECLARA que no se compilo, en vez de fingir.
//!
//! La parte que puede estar mal de forma peligrosa —VERIFICAR el quote— si se
//! compila y se prueba con firmas reales en cada `make ci`; ver [`crate`]. Esto
//! de aqui es E/S contra un dispositivo: se valida ejecutandolo en una maquina
//! con TPM, no en una prueba unitaria.
//!
//! # Lo que hace
//!
//! Escribe el comando `TPM2_Quote` (de [`crate::quote`]) en `/dev/tpmrm0`, lee
//! la respuesta, y separa el `TPMS_ATTEST` de su firma. Maneja con gracia el
//! `EBUSY` que el resource manager devuelve si el TPM esta ocupado, y las
//! respuestas fragmentadas. No provoca panicos ante un TPM que no responde: un
//! agente que se cae porque el TPM esta ocupado es peor que uno que reporta que
//! no pudo atestar.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;

/// El resource manager del kernel. Se usa este y no `/dev/tpm0` directo porque
/// el rm serializa el acceso: dos procesos hablando con `/dev/tpm0` a la vez se
/// corrompen las sesiones mutuamente.
pub const TPM_RM: &str = "/dev/tpmrm0";

/// Un fallo al hablar con el TPM.
#[derive(Debug, thiserror::Error)]
pub enum EmisorError {
    /// No hay TPM accesible. NO es un fallo de atestacion: es "no aplica".
    #[error("no hay TPM accesible en {0}")]
    SinTpm(String),
    /// Error de E/S contra el dispositivo.
    #[error("E/S con el TPM: {0}")]
    Io(#[from] std::io::Error),
    /// El TPM devolvio un codigo de respuesta distinto de exito.
    #[error("el TPM respondio con el codigo {0:#010x}")]
    RespuestaTpm(u32),
    /// La respuesta es demasiado corta para ser un `TPM2_Quote` valido.
    #[error("respuesta del TPM truncada ({0} bytes)")]
    RespuestaTruncada(usize),
}

/// Un quote recien emitido: la estructura firmada y su firma, listos para que el
/// plano de control los verifique.
pub struct QuoteEmitido {
    /// Los bytes del `TPMS_ATTEST`.
    pub attest: Vec<u8>,
    /// La firma sobre ellos.
    pub firma: Vec<u8>,
}

/// `true` si hay un TPM accesible. Un endpoint donde esto es `false` reporta
/// atestacion `NoAplicable`, nunca un fallo.
pub fn hay_tpm() -> bool {
    Path::new(TPM_RM).exists() || Path::new("/dev/tpm0").exists()
}

/// Envia un comando ya construido al TPM y devuelve la respuesta cruda,
/// reintentando ante `EBUSY` con una espera corta.
pub fn transaccion(comando: &[u8]) -> Result<Vec<u8>, EmisorError> {
    if !hay_tpm() {
        return Err(EmisorError::SinTpm(TPM_RM.to_string()));
    }
    let mut intentos = 0;
    loop {
        match transaccion_una_vez(comando) {
            Err(EmisorError::Io(e)) if e.raw_os_error() == Some(libc::EBUSY) && intentos < 10 => {
                intentos += 1;
                std::thread::sleep(Duration::from_millis(20 * intentos as u64));
            }
            otro => return otro,
        }
    }
}

fn transaccion_una_vez(comando: &[u8]) -> Result<Vec<u8>, EmisorError> {
    let mut dev = OpenOptions::new().read(true).write(true).open(TPM_RM)?;
    dev.write_all(comando)?;
    // El TPM contesta un mensaje completo por lectura; se pide un buffer amplio.
    let mut resp = vec![0u8; 4096];
    let n = dev.read(&mut resp)?;
    resp.truncate(n);
    if resp.len() < 10 {
        return Err(EmisorError::RespuestaTruncada(resp.len()));
    }
    // Cabecera de respuesta: tag(2) || size(4) || responseCode(4).
    let rc = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
    if rc != 0 {
        return Err(EmisorError::RespuestaTpm(rc));
    }
    Ok(resp)
}
