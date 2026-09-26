//! Errores del sandbox.

/// Error al construir o aplicar un sandbox.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    /// El kernel no admite filtros de seccomp.
    #[error("este kernel no admite seccomp-bpf (falta CONFIG_SECCOMP_FILTER)")]
    SeccompUnsupported,

    /// El kernel no admite Landlock.
    #[error("este kernel no admite Landlock (falta CONFIG_SECURITY_LANDLOCK o no esta activo)")]
    LandlockUnsupported,

    /// La version de ABI de Landlock es menor de la que la politica necesita.
    #[error("Landlock ABI {actual} no soporta '{needs}', hace falta ABI {required}")]
    LandlockAbiTooOld {
        /// Version que ofrece el kernel.
        actual: u32,
        /// Capacidad pedida.
        needs: &'static str,
        /// Version minima que la implementa.
        required: u32,
    },

    /// No se pudo poner `PR_SET_NO_NEW_PRIVS`.
    #[error("no se pudo fijar no_new_privs: {0}")]
    NoNewPrivs(#[source] std::io::Error),

    /// Fallo al instalar el filtro.
    #[error("seccomp(SET_MODE_FILTER) fallo: {0}")]
    Seccomp(#[source] std::io::Error),

    /// Fallo en una llamada de Landlock.
    #[error("{op} fallo: {source}")]
    Landlock {
        /// Llamada que fallo.
        op: &'static str,
        /// Causa.
        #[source]
        source: std::io::Error,
    },

    /// Una ruta de la politica no se pudo abrir.
    #[error("no se pudo abrir '{path}' para la regla de Landlock: {source}")]
    Path {
        /// Ruta.
        path: String,
        /// Causa.
        #[source]
        source: std::io::Error,
    },

    /// El programa compilado esta vacio.
    #[error("un filtro vacio no protege nada")]
    EmptyFilter,

    /// El programa excede el limite de BPF clasico.
    #[error("el filtro tiene {0} instrucciones y el maximo es 65535")]
    FilterTooLong(usize),

    /// Fallo en la supervision de un hijo (FASE 93).
    #[error("supervision: {op}: {source}")]
    Supervision {
        /// Que se estaba haciendo.
        op: &'static str,
        /// Causa.
        #[source]
        source: std::io::Error,
    },

    /// El hijo supervisado murio antes de entregar su escucha.
    #[error("el hijo supervisado termino antes de entregar su escucha (estado {0})")]
    HijoSinEscucha(i32),

    /// Un argumento no se puede pasar a `execve` (lleva un byte nulo).
    #[error("argumento invalido para execve: {0}")]
    Argumento(String),
}

impl SandboxError {
    /// Indica si el error significa "este kernel no puede", que el llamante
    /// debe tratar degradando la politica en vez de reintentando.
    pub fn is_unsupported(&self) -> bool {
        matches!(
            self,
            SandboxError::SeccompUnsupported
                | SandboxError::LandlockUnsupported
                | SandboxError::LandlockAbiTooOld { .. }
        )
    }
}
