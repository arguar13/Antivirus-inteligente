//! Errores del guardia de llamadas al sistema.
//!
//! Ninguna ruta de este crate hace `panic!` ni `unwrap`: todo fallo del kernel
//! —un `ptrace` que no arranca, un `perf_event_open` sin permiso, un mapa de
//! memoria ilegible— viaja como un `Result`. Un detector de evasion que se cae
//! solo es una via de evasion mas: basta con hacerle cosquillas al trazador
//! para que el atacante quede sin vigilancia.

/// Error de las operaciones del guardia de syscalls.
#[derive(Debug, thiserror::Error)]
pub enum SyscallGuardError {
    /// No se pudo lanzar el binario a analizar.
    #[error("no se pudo lanzar el proceso a vigilar: {0}")]
    Spawn(#[source] std::io::Error),

    /// Una operacion de `ptrace` fallo.
    #[error("ptrace fallo en {op}: {source}")]
    Ptrace {
        /// Operacion concreta.
        op: &'static str,
        /// Causa.
        #[source]
        source: std::io::Error,
    },

    /// El proceso trazado termino antes de poder observarlo.
    ///
    /// `Some(code)` si salio por su cuenta; `None` si lo mato una senal.
    #[error("el proceso trazado termino (codigo {0:?}) antes de completar el analisis")]
    ProcesoTermino(Option<i32>),

    /// El presupuesto de paradas de syscall se agoto sin veredicto.
    #[error("se agotaron las {0} paradas de syscall sin terminar el perfilado")]
    LimiteDeParadas(u64),

    /// No se pudo leer el mapa de memoria del proceso.
    #[error("no se pudo leer el mapa de memoria de {pid}: {source}")]
    Maps {
        /// PID.
        pid: i32,
        /// Causa.
        #[source]
        source: std::io::Error,
    },
}
