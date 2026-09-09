//! Tipos de error del agente.
//!
//! Se usa `thiserror` y no `anyhow` en la biblioteca a proposito: quien llama
//! necesita poder distinguir un fallo recuperable (un proceso que murio entre
//! el evento y la consulta) de uno que obliga a degradar el producto (el canal
//! de telemetria corrupto). `anyhow` queda para el binario y las pruebas, donde
//! el error solo se imprime.

use std::path::PathBuf;

/// Error al operar sobre el grafo de procesos.
#[derive(Debug, thiserror::Error)]
pub enum GraphError {
    /// La clave referenciada no esta en el grafo.
    ///
    /// No siempre es un fallo: un evento puede llegar despues de que el
    /// proceso haya salido y su nodo haya expirado.
    #[error("proceso {0:#x} desconocido en el grafo")]
    UnknownProcess(u64),

    /// La cadena de ancestros excede la profundidad maxima configurada.
    ///
    /// Indica un ciclo (imposible en un arbol de procesos sano) o una bomba de
    /// fork anidada. En ambos casos se corta en vez de recorrer sin fin.
    #[error("cadena de ancestros mas profunda que el limite de {limit}")]
    AncestryTooDeep {
        /// Limite configurado.
        limit: u16,
    },
}

/// Error al inicializar o consumir el canal de telemetria.
#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    /// El objeto BPF no se pudo abrir, cargar o enlazar.
    #[error("no se pudo cargar el objeto BPF: {0}")]
    BpfLoad(String),

    /// Una sonda no se pudo enganchar a su tracepoint.
    #[error("no se pudo enganchar la sonda '{probe}': {detail}")]
    ProbeAttach {
        /// Nombre del programa BPF.
        probe: String,
        /// Mensaje de libbpf.
        ///
        /// Es `String` y no un error tipado a proposito: `libbpf_rs::Error` no
        /// debe cruzar la frontera publica del agente, o quien consuma este
        /// tipo acabara dependiendo de la version de libbpf-rs.
        /// El campo tampoco puede llamarse `source`, porque thiserror reserva
        /// ese nombre para la causa encadenada y exigiria que implemente Error.
        detail: String,
    },

    /// El kernel no expone BTF, asi que CO-RE no puede reubicar los accesos.
    #[error(
        "el kernel no expone BTF en {0}; AegisCore necesita CONFIG_DEBUG_INFO_BTF=y \
         para reubicar los accesos a estructuras de kernel"
    )]
    NoKernelBtf(PathBuf),

    /// tracefs no esta montado, asi que no hay forma de resolver el
    /// identificador de perf de ningun tracepoint.
    #[error(
        "tracefs no esta montado en {0}; sin el no se pueden enganchar los tracepoints. \
         Montalo con: mount -t tracefs nodev {0}"
    )]
    TracefsUnavailable(PathBuf),

    /// El kernel no expone un tracepoint que AegisCore necesita.
    #[error(
        "el kernel no expone el tracepoint '{name}'. Requiere CONFIG_FTRACE_SYSCALLS=y \
         y CONFIG_TRACEPOINTS=y"
    )]
    TracepointMissing {
        /// Nombre del tracepoint, en la forma `categoria/evento`.
        name: &'static str,
    },

    /// El proceso no tiene privilegios para cargar programas eBPF.
    #[error(
        "sin privilegios para cargar programas eBPF: hacen falta CAP_BPF y CAP_PERFMON \
         (o CAP_SYS_ADMIN), o ejecutar como root"
    )]
    InsufficientPrivileges,

    /// Un registro del ring buffer no es interpretable.
    #[error("registro de telemetria invalido: {0}")]
    MalformedRecord(&'static str),

    /// Error de entrada/salida del sistema.
    #[error("error de E/S: {0}")]
    Io(#[from] std::io::Error),
}
