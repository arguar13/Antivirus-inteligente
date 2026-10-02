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

impl ErrorServidor {
    /// Si el fallo es de una dependencia que VOLVERA (PostgreSQL caido o
    /// saturado, la red, Redis) y no del dato que se intentaba guardar.
    ///
    /// La ingesta lo usa para distinguir contrapresion de rechazo (FASE 6.4 del
    /// MP-16): con PostgreSQL caido, el agente tiene que CONSERVAR el veredicto
    /// y reenviarlo, no descartarlo tras unos cuantos intentos.
    pub fn es_transitorio(&self) -> bool {
        match self {
            ErrorServidor::BaseDatos(e) => match e {
                sqlx::Error::PoolTimedOut
                | sqlx::Error::PoolClosed
                | sqlx::Error::Io(_)
                | sqlx::Error::Tls(_)
                | sqlx::Error::Protocol(_)
                | sqlx::Error::WorkerCrashed => true,
                // 08: conexion; 53: recursos; 57P: el servidor se para o no
                // admite conexiones aun; 40001/40P01: serializacion y bloqueo.
                sqlx::Error::Database(d) => d.code().is_some_and(|c| {
                    c.starts_with("08")
                        || c.starts_with("53")
                        || c.starts_with("57P")
                        || c == "40001"
                        || c == "40P01"
                }),
                _ => false,
            },
            ErrorServidor::Cache(e) => {
                e.is_io_error()
                    || e.is_timeout()
                    || e.is_connection_dropped()
                    || e.is_connection_refusal()
            }
            ErrorServidor::Io { .. } => true,
            _ => false,
        }
    }
}

/// Resultado de las operaciones del servidor.
pub type Resultado<T> = Result<T, ErrorServidor>;
