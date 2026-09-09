//! Errores del plano de control.
//!
//! Cada variante dice QUE subsistema fallo. En un servidor que atiende a miles
//! de agentes, un error sin origen identificable es un error que nadie arregla.

use thiserror::Error;

/// Error de cualquier capa del servidor.
#[derive(Debug, Error)]
pub enum ErrorServidor {
    /// Configuracion invalida en el entorno.
    #[error("configuracion invalida: {0}")]
    Config(String),

    /// Fallo de la base de datos.
    #[error("base de datos: {0}")]
    BaseDatos(#[from] sqlx::Error),

    /// Fallo de la cache.
    #[error("cache: {0}")]
    Cache(#[from] redis::RedisError),

    /// Fallo de entrada/salida (escucha de sockets, ficheros de identidad).
    #[error("entrada/salida en {op}: {source}")]
    Io {
        /// Operacion que fallaba.
        op: &'static str,
        /// Causa subyacente.
        #[source]
        source: std::io::Error,
    },

    /// Fallo del transporte de flota (mTLS, enmarcado, protobuf).
    #[error("transporte de flota: {0}")]
    Flota(#[from] aegis_fleet::error::FleetError),

    /// El recurso pedido no existe.
    #[error("no encontrado: {0}")]
    NoEncontrado(String),
}

/// Resultado de las operaciones del servidor.
pub type Resultado<T> = Result<T, ErrorServidor>;
