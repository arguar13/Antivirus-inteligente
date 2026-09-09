//! Volcado de la region desempaquetada.
//!
//! Se ejecuta mientras el proceso trazado esta DETENIDO en el OEP, de modo que
//! la memoria no cambia bajo los pies del lector. Se usa `process_vm_readv`
//! —el mismo mecanismo del escaner de memoria— porque no requiere parar el
//! proceso otra vez (ya lo esta) ni deja un descriptor abierto.

use crate::error::UnpackError;
use crate::region::Rango;

/// El codigo desempaquetado, listo para el escaner de firmas.
#[derive(Debug, Clone)]
pub struct DumpDesempaquetado {
    /// Region de la que se volco.
    pub region: Rango,
    /// Bytes del codigo real, ya en claro en memoria.
    pub codigo: Vec<u8>,
}

/// Bytes maximos que se vuelcan de una region.
///
/// Una region desempaquetada legitima son kilobytes o pocos megabytes. Un
/// tamano mayor es un intento de que el volcado agote la memoria del agente: se
/// acota.
pub const MAX_VOLCADO: usize = 64 * 1024 * 1024;

/// Vuelca una region de un proceso detenido.
pub fn volcar(pid: i32, region: Rango) -> Result<DumpDesempaquetado, UnpackError> {
    let largo = (region.len() as usize).min(MAX_VOLCADO);
    let bytes = aegis_scal::linux::memory::read_memory(pid, region.inicio, largo)
        .map_err(|e| UnpackError::Volcado(e.to_string()))?;
    Ok(DumpDesempaquetado {
        region,
        codigo: bytes,
    })
}
