//! Errores del cliente y del servidor de flota.
//!
//! Como en el resto del producto, ninguna ruta hace `panic!`: un handshake que
//! no cuadra, un certificado caducado, una conexion cortada a media trama —todo
//! viaja como `Result`. Un agente de flota que se cae ante un mensaje malformado
//! es un agente que un atacante saca de la red con un solo paquete.

/// Error de las operaciones de flota.
#[derive(Debug, thiserror::Error)]
pub enum FleetError {
    /// No se pudo generar material criptografico (clave o certificado).
    #[error("no se pudo generar el material criptografico: {0}")]
    Cripto(String),

    /// Fallo al construir la configuracion TLS.
    #[error("configuracion TLS invalida: {0}")]
    ConfigTls(String),

    /// Fallo de red al conectar o aceptar.
    #[error("fallo de red en {op}: {source}")]
    Red {
        /// Operacion.
        op: &'static str,
        /// Causa.
        #[source]
        source: std::io::Error,
    },

    /// Fallo del handshake o de la sesion TLS.
    #[error("fallo TLS en {op}: {detail}")]
    Tls {
        /// Operacion.
        op: &'static str,
        /// Detalle.
        detail: String,
    },

    /// Un mensaje del protocolo no se pudo decodificar.
    #[error("trama del protocolo invalida: {0}")]
    Protocolo(String),

    /// La trama excede el tamano maximo permitido.
    #[error("trama de {tam} bytes supera el maximo de {max}")]
    TramaDemasiadoGrande {
        /// Tamano recibido.
        tam: usize,
        /// Maximo permitido.
        max: usize,
    },

    /// El par no presento un certificado valido (fallo de autenticacion mutua).
    #[error("el par no se autentico: {0}")]
    NoAutenticado(String),

    /// El agente no esta enrolado en la flota.
    #[error("agente no enrolado: {0}")]
    NoEnrolado(String),

    /// Fallo de la capa post-cuantica del canal (sellado/apertura, FASE 59).
    #[error("fallo de la capa PQC del canal: {0}")]
    Pqc(#[from] aegis_pqc::PqcError),
}

/// Alias de resultado del crate.
pub type Resultado<T> = std::result::Result<T, FleetError>;
