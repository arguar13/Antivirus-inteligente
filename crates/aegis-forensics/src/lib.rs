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

#![deny(missing_docs)]

pub mod dump;
pub mod exploit;
pub mod report;

pub use dump::{DumpError, DumpPolicy, MemoryDump, RegionDump};
pub use exploit::{
    classify_pointer, scan_pivots, scan_shellcode, scan_vtables, PatternFinding, PointerTarget,
    VtableFinding,
};
pub use report::{ForensicReport, ForensicSeverity};
