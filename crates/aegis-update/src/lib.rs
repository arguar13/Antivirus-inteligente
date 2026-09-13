//! # aegis-update
//!
//! Actualizacion segura del agente, sus reglas y sus modelos: firma Ed25519 y
//! rollback atomico.
//!
//! Un motor de actualizacion es una via directa para ejecutar codigo del
//! atacante con los permisos del defensor. Las dos defensas que lo impiden:
//!
//! - [`signature`]: nada se aplica sin una firma valida. Desde la FASE 59 el
//!   camino objetivo es una firma **hibrida** Ed25519 + ML-DSA-65 (post-cuantica):
//!   un artefacto se acepta solo si verifican las dos, de modo que un
//!   falsificador tendria que romper el primitivo clasico Y el post-cuantico. El
//!   formato de wire lleva un byte de suite (agilidad criptografica) y el
//!   verificador hibrido rechaza una firma clasica (anti-downgrade).
//! - [`updater`]: aplicar es todo o nada. El artefacto se activa con un
//!   `rename` atomico tras verificar la firma, la version anterior se preserva,
//!   y si la nueva no pasa la comprobacion de salud se restaura sola.

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

pub mod artifact;
pub mod signature;
pub mod updater;

pub use artifact::{Artifact, ArtifactKind};
pub use signature::{ClaveActualizacion, SignatureError, UpdateKey};
pub use updater::{ApplyOutcome, HealthCheck, UpdateError, Updater};

// Reexport de los tipos de firma hibrida (FASE 59) para que un consumidor del
// canal de updates no tenga que depender de aegis-pqc directamente.
pub use aegis_pqc::firma_hibrida::{ClaveFirmaHibrida, ClaveVerificacionHibrida, FirmaHibrida};
