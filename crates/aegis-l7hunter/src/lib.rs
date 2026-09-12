//! # `aegis-l7hunter` — caza de C2 sobre TLS por uprobes (FASE 66)
//!
//! Placeholder de la cabecera; se completa al cerrar la fase.

#![deny(missing_docs)]

pub mod abi;
pub mod baliza;
pub mod elf;
pub mod l7;
pub mod modelo;
pub mod objetivo;

/// El clasificador de canales C2 empotrado en el binario del agente.
///
/// Poco mas de un kilobyte: cabe de sobra y no necesita un fichero externo que
/// un atacante pueda borrar o sustituir. El modelo de PRODUCCION —entrenado
/// sobre la telemetria real de la flota— llega por el canal firmado de
/// `aegis-update` con la misma forma de grafo y la misma dimension de entrada.
pub const MODELO_C2: &[u8] = include_bytes!("../models/aegis-c2-l7-v1.onnx");

/// Error del cazador L7.
#[derive(Debug, thiserror::Error)]
pub enum L7Error {
    /// El binario ELF no se puede analizar.
    #[error("ELF invalido: {0}")]
    Elf(String),
    /// Error de entrada/salida.
    #[error("no se pudo leer {ruta}: {causa}")]
    Io {
        /// Ruta implicada.
        ruta: String,
        /// Causa.
        #[source]
        causa: std::io::Error,
    },
}
