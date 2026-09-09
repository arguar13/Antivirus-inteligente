//! # aegis-ransom
//!
//! Motor de deteccion y contencion de ransomware en tiempo real.
//!
//! El ransomware es la unica amenaza donde el tiempo de deteccion se traduce
//! directamente en dano irreversible: un cifrador moderno procesa entre 1.000 y
//! 5.000 ficheros por minuto, y cada segundo de duda son documentos que ya no
//! se recuperan. El presupuesto del producto es detener en menos de 500 ms
//! desde el primer fichero cifrado, con menos de 20 ficheros perdidos.
//!
//! - [`velocity`]: velocidad, dispersion y **transicion de entropia**, que es
//!   lo que separa a un cifrador de un compresor.
//! - [`honeypot`]: ficheros senuelo, la unica senal concluyente por si sola.
//! - [`engine`]: combinacion de senales, veredicto y contencion.
//! - [`fdmap`]: resolucion de descriptor a ruta, porque el sondeo de `write`
//!   recibe un `fd` y no una ruta.

#![deny(missing_docs)]

pub mod engine;
pub mod fdmap;
pub mod honeypot;
pub mod responder;
pub mod velocity;

pub use engine::{
    ContainmentOutcome, Detection, EngineConfig, RansomVerdict, RansomwareEngine, Responder, Signal,
};
pub use fdmap::FdMap;
pub use honeypot::{Canary, HoneypotConfig, HoneypotSet, TamperReason, TamperedCanary};
pub use velocity::{VelocityConfig, VelocityTracker, WriteObservation, RATIO_CIFRADO};
