//! # aegis-resp
//!
//! Motor de respuesta activa de AegisCore: terminar, aislar y contener.
//!
//! Detectar sin responder es telemetria, no proteccion. Este crate ejecuta la
//! decision, y su requisito transversal es que **toda accion sea reversible**:
//! un falso positivo tiene que poder deshacerse por completo, metadatos
//! incluidos.
//!
//! - [`kill`]: terminacion de arboles de procesos sin huerfanos y sin carreras
//!   de reciclado de PID.
//! - [`quarantine`]: contenedor cifrado con AES-256-GCM que conserva los
//!   metadatos forenses y prueba su propia integridad.
//! - [`isolate`]: aislamiento de red en una tabla nftables propia, de modo que
//!   liberar devuelva el sistema exactamente al estado anterior.

#![deny(missing_docs)]

pub mod isolate;
pub mod kill;
pub mod quarantine;

pub use isolate::{IsolationError, IsolationPolicy, IsolationStatus, Isolator};
pub use kill::{kill_process_tree, KillError, KillOptions, KillReport, ProcOutcome, ProcessTree};
pub use quarantine::{FileMetadata, Quarantine, QuarantineError, QuarantineId};
