//! Errores de la verificacion cruzada.

/// Error del motor de integridad de kernel.
#[derive(Debug, thiserror::Error)]
pub enum KiError {
    /// El bytecode empotrado no coincide con su firma.
    #[error("el bytecode de verificacion cruzada no coincide con su firma HMAC: no se carga")]
    BytecodeTampered,

    /// El kernel no ofrece lo que la verificacion cruzada necesita.
    ///
    /// La causa mas comun es un kernel sin `CONFIG_DEBUG_INFO_BTF` o sin los
    /// kfuncs `bpf_task_from_pid` / `bpf_iter_task_*`, que llegaron en 6.2 y
    /// 6.7 respectivamente.
    #[error("este kernel no admite la verificacion cruzada: {0}")]
    Unsupported(String),

    /// Faltan privilegios para cargar el programa.
    #[error("faltan privilegios para cargar el verificador: hace falta CAP_BPF y CAP_PERFMON")]
    InsufficientPrivileges,

    /// Fallo de libbpf al abrir, cargar o ejecutar.
    #[error("fallo de libbpf en {op}: {detail}")]
    Bpf {
        /// Operacion.
        op: &'static str,
        /// Detalle.
        detail: String,
    },

    /// El programa eBPF devolvio un error.
    #[error("el programa de verificacion devolvio {0}")]
    Programa(i32),

    /// Una entrada de un mapa no tiene el tamano esperado.
    ///
    /// Significa que el programa eBPF y el espejo de Rust han divergido, que es
    /// exactamente lo que las comprobaciones de disposicion existen para
    /// impedir; llegar aqui indica que alguien las sorteo.
    #[error("una entrada del mapa {map} mide {got} bytes y se esperaban {want}")]
    LayoutMismatch {
        /// Mapa afectado.
        map: &'static str,
        /// Tamano recibido.
        got: usize,
        /// Tamano esperado.
        want: usize,
    },
}

impl KiError {
    /// Indica si el error significa "aqui no se puede", que el llamante debe
    /// tratar apagando la comprobacion en vez de reintentando.
    pub fn is_unsupported(&self) -> bool {
        matches!(
            self,
            KiError::Unsupported(_) | KiError::InsufficientPrivileges
        )
    }
}
