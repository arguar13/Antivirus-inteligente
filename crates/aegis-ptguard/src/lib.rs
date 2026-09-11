//! Trazado de ejecucion por hardware (Intel PT) contra ROP/JOP — FASE 51.
//!
//! # El problema que resuelve
//!
//! Los atacantes modernos evaden los hooks de un EDR con ROP y JOP
//! (return/jump-oriented programming): en vez de inyectar codigo nuevo
//! —que un EDR detecta—, encadenan trocitos de codigo YA presente y legitimo
//! ("gadgets"), cada uno terminado en un `ret` o un salto indirecto. Como no hay
//! codigo nuevo ni llamadas a APIs sospechosas, la deteccion clasica no lo ve.
//!
//! Intel Processor Trace lo delata desde el hardware: la CPU emite un registro
//! de CADA salto que ejecuta el proceso, con un coste minimo. Reconstruido el
//! flujo, una cadena ROP se distingue de la ejecucion normal por su forma —una
//! rafaga de bloques cortisimos, cada uno terminado en un salto indirecto, con
//! los `ret` desparejados de sus `call`—.
//!
//! # La frontera de realidad de esta fase
//!
//! La CAPTURA en vivo necesita el flag `intel_pt` en la CPU y `perf_event_open`
//! con permiso. Este Xeon virtual NO lo tiene (`/proc/cpuinfo` sin `intel_pt`,
//! `perf_event_paranoid=2`), asi que la captura es fisicamente imposible aqui.
//! Siguiendo el patron de la FASE 47:
//!
//! - el NUCLEO —decodificar los paquetes ([`paquete`]), reconstruir el flujo
//!   ([`reconstruccion`]) y decidir si es ROP/JOP ([`analisis`])— es Rust puro y
//!   se PRUEBA con trazas en formato binario real y codigo x86-64 real en cada
//!   `make ci`, sin un solo mock;
//! - la FONTANERIA —`perf_event_open`, el `mmap` del area AUX donde la CPU
//!   vuelca la traza por DMA ([`captura`])— vive tras la feature `pt-live`, y el
//!   CI declara que no se ejercio aqui.
//!
//! [`SoportePt`](report::SoportePt) reporta honestamente si la maquina puede
//! capturar: sin `intel_pt`, el veredicto es `NoAplicable`, nunca un falso "ok".

#![deny(unsafe_code)]

pub mod analisis;
pub mod paquete;
pub mod perf_pt;
pub mod reconstruccion;
pub mod report;

#[cfg(feature = "pt-live")]
#[allow(unsafe_code)] // perf_event_open/mmap/ioctl; cada bloque lleva su SAFETY
pub mod captura;

pub use analisis::{analizar_flujo, Veredicto, VeredictoPt};
pub use paquete::{Decodificador, Paquete, PaqueteError};
pub use reconstruccion::{FlujoEjecucion, TransferenciaControl};
pub use report::SoportePt;
