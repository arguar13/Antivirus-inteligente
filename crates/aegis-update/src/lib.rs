//! # aegis-update
//!
//! Actualizacion segura del agente, sus reglas y sus modelos: firma Ed25519 y
//! rollback atomico.
//!
//! Un motor de actualizacion es una via directa para ejecutar codigo del
//! atacante con los permisos del defensor. Las dos defensas que lo impiden:
//!
//! - [`signature`]: nada se aplica sin una firma Ed25519 valida. El servidor
//!   firma cada artefacto con una clave privada que solo el tiene; el agente
//!   lleva la publica y verifica antes de tocar nada.
//! - [`updater`]: aplicar es todo o nada. El artefacto se activa con un
//!   `rename` atomico tras verificar la firma, la version anterior se preserva,
//!   y si la nueva no pasa la comprobacion de salud se restaura sola.

#![deny(missing_docs)]

pub mod artifact;
pub mod signature;
pub mod updater;

pub use artifact::{Artifact, ArtifactKind};
pub use signature::{SignatureError, UpdateKey};
pub use updater::{ApplyOutcome, HealthCheck, UpdateError, Updater};
