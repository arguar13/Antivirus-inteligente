//! Errores del desempaquetador.

/// Error del desempaquetado dinamico.
#[derive(Debug, thiserror::Error)]
pub enum UnpackError {
    /// No se pudo lanzar el proceso bajo traza.
    #[error("no se pudo lanzar el binario a desempaquetar: {0}")]
    Spawn(#[source] std::io::Error),
    /// Fallo de `ptrace`.
    #[error("ptrace({op}) fallo: {source}")]
    Ptrace {
        /// Operacion.
        op: &'static str,
        /// Causa.
        #[source]
        source: std::io::Error,
    },
    /// El proceso trazado murio antes de alcanzar el OEP.
    #[error("el proceso termino (codigo {0:?}) sin desempaquetarse")]
    ProcesoTermino(Option<i32>),
    /// Se agoto el presupuesto de trabajo sin encontrar el OEP.
    #[error("no se alcanzo el OEP en {0} paradas: el binario no parece autoextraerse, o el limite es corto")]
    OepNoAlcanzado(u64),
    /// No se pudo leer la memoria del proceso.
    #[error("no se pudo volcar la region desempaquetada: {0}")]
    Volcado(String),
    /// El sistema operativo no soporta el trazado necesario.
    #[error("este sistema no admite el trazado necesario: {0}")]
    NoSoportado(String),
}
