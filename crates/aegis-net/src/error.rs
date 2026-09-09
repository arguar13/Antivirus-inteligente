//! Errores del subsistema de red.

/// Error al cargar, configurar o consultar el filtro XDP.
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    /// Error de libbpf al cargar o manipular el objeto.
    #[error("error de BPF: {0}")]
    Bpf(String),

    /// Falta un mapa que el programa deberia declarar.
    #[error("el objeto BPF no declara el mapa '{0}'")]
    MissingMap(String),

    /// Falta un programa que se esperaba en el objeto.
    #[error("el objeto BPF no declara el programa '{0}'")]
    MissingProgram(String),

    /// La interfaz de red no existe.
    #[error("la interfaz de red '{0}' no existe")]
    UnknownInterface(String),

    /// Sin privilegios para cargar programas BPF.
    #[error(
        "sin privilegios para cargar el filtro XDP: hacen falta CAP_BPF y CAP_NET_ADMIN \
         (o root)"
    )]
    InsufficientPrivileges,

    /// Error de entrada/salida.
    #[error("error de E/S: {0}")]
    Io(#[from] std::io::Error),
}
