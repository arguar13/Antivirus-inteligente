//! Errores de la malla.

/// Error de la malla.
#[derive(Debug, thiserror::Error)]
pub enum MeshError {
    /// Error de socket.
    #[error("fallo de red en {op}: {source}")]
    Net {
        /// Operacion.
        op: &'static str,
        /// Causa.
        #[source]
        source: std::io::Error,
    },
    /// El mensaje no cabe en un datagrama.
    #[error("el mensaje ocupa {bytes} y el maximo sin fragmentar es {max}")]
    TooLarge {
        /// Tamano del mensaje.
        bytes: usize,
        /// Maximo.
        max: usize,
    },
    /// El cifrado o el descifrado fallo.
    #[error("fallo de cifrado en la malla: {0}")]
    Crypto(&'static str),
    /// Se agotaron los contadores de la sesion.
    #[error("la sesion agoto sus 2^32 mensajes; hay que reiniciarla antes de repetir un nonce")]
    SessionExhausted,
}
