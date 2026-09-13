//! # aegis-evasion
//!
//! Deteccion de las tecnicas con las que el malware moderno ejecuta codigo sin
//! que ese codigo aparezca en ningun fichero del disco.
//!
//! # El problema que resuelve
//!
//! Todo el analisis estatico del producto — YARA, atributos PE/ELF, el modelo —
//! opera sobre ficheros. Un atacante que nunca escribe su carga util en el
//! disco lo esquiva entero: descarga los bytes, los mapea en memoria y salta a
//! ellos. El fichero que se ejecuto era legitimo y esta firmado; lo que corre
//! dentro no.
//!
//! Las tres formas de conseguirlo, y como se detecta cada una:
//!
//! | Tecnica | Que se ve | Modulo |
//! |---|---|---|
//! | Inyeccion reflectiva | Memoria anonima con permiso de ejecucion | [`inject`] |
//! | Vaciado de proceso | El codigo en memoria no coincide con el del fichero | [`hollow`] |
//! | Desenganche de hooks | Los primeros bytes de un stub de syscall no son los suyos | [`hooks`] |
//!
//! # Por que las tres y no una
//!
//! Cada una tiene un punto ciego que cubren las otras. La memoria anonima
//! ejecutable la producen tambien los JIT, asi que por si sola es demasiado
//! ruidosa. La comparacion con el disco no ve nada si el atacante no toca el
//! mapeo original. Y la integridad de los stubs solo dice algo si alguien los
//! ha tocado. Juntas dejan poco sitio: no hay forma de ejecutar codigo que no
//! este en ningun fichero sin dejar al menos una de las tres marcas.

// SEGURIDAD DE MEMORIA IMPUESTA POR EL COMPILADOR (FASE 80).
//
// Este crate no necesita `unsafe`, asi que lo prohibe. No es una declaracion de
// intenciones: `forbid` no se puede levantar desde dentro ni con un `allow`, asi
// que el dia que alguien optimice un bucle con un puntero crudo, no compila.
//
// La invariante del producto no admite tercera opcion: todo crate del agente O
// declara esto, O esta en `tools/lineabase-unsafe.txt` con su razon escrita. Un
// crate que se cuele sin ninguna de las dos hace fallar
// `tools/verificar-invariantes.sh`.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod hollow;
pub mod hooks;
pub mod inject;
pub mod report;

pub use hollow::{compare_process, HollowFinding, HollowReport};
pub use hooks::{scan_hooks, HookFinding, HookReport, PatchKind};
pub use inject::{scan_injection, InjectionFinding, InjectionKind, InjectionReport};
pub use report::{analyze_process, EvasionReport, EvasionSeverity, EvasionSignal};

/// Error de los analisis de este crate.
#[derive(Debug, thiserror::Error)]
pub enum EvasionError {
    /// No se pudo leer el mapa de memoria del proceso.
    #[error("no se pudo leer el mapa de memoria de {pid}: {detail}")]
    Maps {
        /// PID.
        pid: i32,
        /// Causa.
        detail: std::io::Error,
    },
    /// No se pudo leer un fichero mapeado.
    #[error("no se pudo leer {path}: {detail}")]
    File {
        /// Ruta.
        path: String,
        /// Causa.
        detail: std::io::Error,
    },
    /// El fichero mapeado no es un ELF valido.
    #[error("{path} no es un ELF analizable: {detail}")]
    Elf {
        /// Ruta.
        path: String,
        /// Causa.
        detail: String,
    },
}
