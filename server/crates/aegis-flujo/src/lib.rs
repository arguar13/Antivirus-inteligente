//! AegisFlow: automatizacion de respuesta con frenos (FASE 97).
//!
//! Un SOAR corriente ejecuta flujos con integraciones: la salida de un paso es
//! un diccionario, la entrada del siguiente una plantilla, y lo que pasa si el
//! flujo falla a medias es que queda a medias. Aqui:
//!
//! - **El flujo es un grafo aciclico TIPADO** ([`flujo`]): un paso que consume
//!   un proceso no se puede enganchar a uno que produce un fichero, y el error
//!   es de compilacion.
//! - **Cada paso declara su reversion** ([`paso`]): sin ella no compila. Si el
//!   flujo falla a medias, lo hecho se revierte en orden inverso volviendo al
//!   estado de ANTES; lo irreversible no se finge deshacer, se escala.
//! - **Idempotencia**: el mismo paso con la misma clave no se repite dentro de
//!   una ejecucion, y cada efecto lleva un identificador derivado de la
//!   ejecucion que hace que reintentarla no duplique nada.
//! - **La aprobacion humana es un tipo** ([`firma`]): un paso de alto impacto
//!   exige una [`firma::Firma`] que solo existe si verifica una firma hibrida
//!   sobre ESA ejecucion —ese flujo, ese paso, esos objetivos—.
//! - **Los cinco frenos de la FASE 69 por paso** ([`frenos`]): antes de cada paso
//!   que toca la flota, con los objetivos reales de ese paso.
//! - **Un catalogo** ([`catalogo`]) sobre el estado real del plano de control
//!   ([`pg`]).

pub mod catalogo;
pub mod firma;
pub mod flujo;
pub mod frenos;
pub mod paso;
pub mod pg;
pub mod tipos;

pub use flujo::{Estado, Flujo, Informe, Motor, Nodo, Registro, ResultadoPaso};
pub use frenos::{CincoFrenos, Decision, Frenos, Motivo};
pub use paso::{ErrorPaso, Paso, Permiso, Reversibilidad, SinFirma};
