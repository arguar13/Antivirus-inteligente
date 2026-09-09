//! # aegis-ipc
//!
//! Contrato de comunicacion entre el driver de AegisCore (Ring 0) y el agente
//! de deteccion (Ring 3).
//!
//! Este crate no habla con el sistema operativo: no abre puertos, no mapea
//! secciones ni carga drivers. Solo define **el formato de los datos** y **el
//! protocolo del ring buffer**, de modo que la parte especifica de cada
//! plataforma (`FltCreateCommunicationPort` en Windows, `BPF_MAP_TYPE_RINGBUF`
//! en Linux) quede aislada en los crates de backend y esta pieza, que es la
//! critica para la correccion, se pueda probar entera en el host.
//!
//! - [`abi`]: espejo `#[repr(C)]` de `shared/include/aegis_abi.h`, con el layout
//!   verificado en tiempo de compilacion.
//! - [`ring`]: consumidor SPSC sin copias del ring compartido.

#![cfg_attr(not(test), no_std)]
#![deny(missing_docs)]

pub mod abi;
pub mod ring;

pub use abi::{AEGIS_ABI_VERSION, AEGIS_EVT_MAGIC, AEGIS_RING_MAGIC};
pub use ring::{EventView, Payload, RingConsumer, RingError};
