//! # aegis-net
//!
//! Motor de deteccion de anomalias de red e IDS de AegisCore.
//!
//! Reparte el trabajo entre kernel y userland segun lo que cada uno hace bien:
//!
//! - El **kernel** (XDP) inspecciona cada paquete antes de que el stack TCP/IP
//!   lo toque, aplica la lista de bloqueo y lleva contadores baratos. Descartar
//!   aqui cuesta unos 50 ns frente a los microsegundos de una regla de
//!   netfilter, y un paquete descartado en XDP nunca puede explotar un fallo
//!   del stack, porque nunca llega a el.
//! - **Userland** recibe una muestra, hace la cuenta exacta y decide. Ahi es
//!   donde vive la politica, que es lo que no debe correr por cada paquete.
//!
//! [`packet`] es un analizador de cabeceras independiente del kernel: sirve
//! tanto para inspeccionar trafico capturado como para fabricar las tramas con
//! las que se prueba el programa XDP.

#![deny(missing_docs)]

pub mod error;
pub mod packet;
pub mod scan;

#[cfg(all(target_os = "linux", feature = "xdp"))]
pub mod xdp;

pub use error::NetError;
pub use packet::{Packet, PacketBuilder, ParseError, TcpFlags, Transport};
pub use scan::{ScanConfig, ScanDetector, ScanKind, ScanVerdict};
