//! Backend de Linux: eBPF, `procfs`, `inotify` y `nftables`.
//!
//! Cada submodulo implementa uno de los rasgos de la capa con la interfaz
//! nativa correspondiente. La regla de este backend es que **todo lo que hay
//! aqui funciona en un kernel sin BTF y dentro de un contenedor**: la via
//! rapida por eBPF es un acelerador que el agente enchufa cuando puede, no un
//! requisito para que la capa exista.

pub mod fsmon;
pub mod memory;
pub mod net;
pub mod netfilter;
pub mod process;
pub mod reloj;
pub mod xattr;

use crate::platform::{Capabilities, Platform, Support};

/// Capacidades del backend de Linux.
pub fn capabilities() -> Capabilities {
    Capabilities {
        platform: Platform::Linux,
        // Sondeo de `/proc`: correcto, pero con la ventana ciega documentada en
        // [`process`]. El agente la sustituye por la sonda de eBPF cuando el
        // kernel se lo permite, y ahi pasa a ser nativa.
        process_events: Support::Degraded("censo de /proc; sin eBPF se pierden procesos efimeros"),
        process_query: Support::Native,
        file_events: Support::Native,
        network_filter: Support::Native,
        memory_inspection: Support::Native,
    }
}
