//! # aegis-sync
//!
//! Sincronizacion diferencial de indicadores de compromiso con arboles de
//! Merkle, en segundo plano y a baja prioridad.
//!
//! El agente y el servidor tienen cada uno una base de indicadores (hashes
//! maliciosos, dominios de C2, reglas revocadas). Ponerlas al dia descargando la
//! lista entera es prohibitivo cuando son cientos de miles y cambian unos pocos
//! al dia.
//!
//! - [`merkle`]: reparte los indicadores en cubos por prefijo de su id y los
//!   resume en un arbol de Merkle. El hash de la raiz resume toda la base.
//! - [`sync`]: compara raices; si difieren, desciende por el arbol y transfiere
//!   solo el contenido de los cubos que cambiaron. El trafico es proporcional al
//!   cambio, no al tamano de la base.
//! - [`priority`]: la sincronizacion corre en un hilo con `nice` rebajado, para
//!   ceder la CPU a la deteccion.

#![deny(missing_docs)]

pub mod ioc;
pub mod merkle;
pub mod priority;
pub mod sync;

pub use ioc::{Ioc, IocKind};
pub use merkle::{Bucket, MerkleTree, CUBOS, PROFUNDIDAD};
pub use priority::{en_hilo_baja_prioridad, rebajar_prioridad};
pub use sync::{reconcile, CountingView, MerkleView, SyncDiff};
