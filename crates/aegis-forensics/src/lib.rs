//! # aegis-forensics
//!
//! Introspeccion de memoria en vivo y deteccion de exploits de corrupcion.
//!
//! Cuando otra senal ya ha senalado a un proceso, este crate lo mira por dentro
//! SIN pararlo:
//!
//! - [`dump`]: vuelca regiones concretas con `process_vm_readv`, sin `ptrace` ni
//!   congelar el proceso —un paron es observable y ademas frena un proceso que
//!   quiza sea legitimo.
//! - [`exploit`]: busca las marcas de un exploit de corrupcion de memoria en los
//!   bytes volcados: vtables secuestradas (una llamada virtual que salta a
//!   codigo anonimo), gadgets de stack pivot en el codigo, y firmas de shellcode
//!   en la pila y el monton.
//! - [`report`]: combina ambas cosas en un veredicto.
//!
//! Todo el analisis es sobre bytes, asi que se prueba con volcados sinteticos y
//! con memoria real de un proceso, sin necesitar un exploit de verdad.
//!
//! # Recogida automatica de incidentes
//!
//! Un incidente se investiga horas o dias despues. Para entonces el proceso ya
//! murio, sus sockets se cerraron, su memoria se libero y puede que el binario
//! se haya borrado a si mismo: **lo que no se recogio en el momento no existe**.
//! Por eso la recogida la dispara la deteccion, no un analista.
//!
//! - [`collect`]: reune el arbol de procesos, los sockets, los hashes de los
//!   binarios y la memoria, con limites explicitos y anotando en `gaps` todo lo
//!   que no se pudo mirar. Un informe que calla sus huecos induce a concluir que
//!   algo no ocurrio cuando lo unico cierto es que no se comprobo.
//! - [`stix`]: lo exporta en STIX 2.1, que es el formato que leen el SIEM, la
//!   plataforma de inteligencia y los productos de terceros. Un informe que solo
//!   entiende AegisCore obliga a copiar los indicadores a mano.
//! - [`store`]: lo guarda en el registro de auditoria cifrado, porque un `.json`
//!   suelto es lo primero que borra el atacante y contiene lo mas sensible de la
//!   maquina.

#![deny(missing_docs)]

pub mod artifacts;
pub mod collect;
pub mod dump;
pub mod exploit;
pub mod json;
pub mod report;
pub mod stix;
pub mod store;
pub mod tiempo;

pub use artifacts::{
    IncidentArtifacts, MemoryArtifact, ProcessArtifact, RegionArtifact, SocketArtifact,
    SocketProto, Trigger,
};
pub use collect::{CollectConfig, Collector};
pub use dump::{DumpError, DumpPolicy, MemoryDump, RegionDump};
pub use exploit::{
    classify_pointer, scan_pivots, scan_shellcode, scan_vtables, PatternFinding, PointerTarget,
    VtableFinding,
};
pub use report::{ForensicReport, ForensicSeverity};
pub use stix::to_bundle;
