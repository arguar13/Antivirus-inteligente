//! # `aegis-l7hunter` — caza de C2 sobre TLS por uprobes (FASE 66)
//!
//! Placeholder de la cabecera; se completa al cerrar la fase.

#![deny(missing_docs)]

pub mod abi;
pub mod baliza;
pub mod elf;
pub mod l7;
pub mod objetivo;

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
