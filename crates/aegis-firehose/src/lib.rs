//! `aegis-firehose`: entrega de auditoria hacia SIEM y SOAR sin perdida.
//!
//! # El problema
//!
//! Un EDR produce evidencia que el cliente tiene que conservar: para responder,
//! para cumplir, y a veces para un juicio. Esa evidencia sale del plano de
//! control hacia el SIEM del cliente, y el SIEM se cae, se satura, se reinicia
//! por mantenimiento un martes por la noche. Un productor que envie y olvide
//! pierde exactamente los registros del rato en que el SIEM no estaba —que es,
//! con demasiada frecuencia, el rato en que el atacante contaba con que no
//! estuviera—.
//!
//! # La forma
//!
//! El diario en disco es la fuente de la verdad, no la cola en memoria. Un
//! registro se admite cuando esta EN DISCO, se entrega cuando el destino lo
//! acusa, y se borra solo entonces. Entre medias puede morir el proceso, caerse
//! la red o reiniciarse el SIEM: al volver, el registro sigue ahi.
//!
//! La consecuencia es que la entrega es **al menos una vez**, no exactamente
//! una: un acuse perdido hace que el registro se reenvie. Se dice aqui porque
//! quien integra tiene que saberlo para desduplicar por el identificador del
//! evento, que viaja en cada registro.
//!
//! # Las tres piezas
//!
//! - [`diario`]: el registro en disco, su formato y su ventana de durabilidad.
//! - [`reintento`]: retroceso exponencial con dispersion, contra la estampida.
//! - [`syslog`]: RFC 5424 con marcado por conteo de octetos.

#![forbid(unsafe_code)]

pub mod bomba;
pub mod destino;
pub mod diario;
pub mod error;
#[cfg(feature = "kafka")]
pub mod kafka;
pub mod reintento;
pub mod syslog;
pub mod syslog_tls;

pub use bomba::Bomba;
pub use destino::Destino;
pub use diario::{Config, Contadores, Diario, PoliticaLleno, Posicion, Registro};
pub use error::{ErrorFirehose, Resultado};
pub use reintento::{Politica, Reintento};
