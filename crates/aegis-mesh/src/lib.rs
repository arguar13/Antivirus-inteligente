//! # aegis-mesh
//!
//! Malla P2P de la red local: cuando un agente descubre una amenaza, el resto de
//! la flota queda inmunizado en milisegundos.
//!
//! # Por que horizontal y no por la nube
//!
//! El camino normal —el agente informa a la consola, la consola reparte— tiene
//! dos problemas en el momento exacto en que importa. El primero es la latencia:
//! un ataque que se mueve lateralmente por la red local va de un equipo al
//! siguiente en segundos, y un viaje de ida y vuelta a Internet mas el ciclo de
//! sondeo de los demas agentes llega tarde. El segundo es que **el atacante ya
//! esta dentro de la red local**: si lo primero que hace es cortar la salida a
//! Internet, la flota se queda sin actualizaciones justo cuando las necesita.
//!
//! La malla no sustituye al canal central, lo adelanta: la vacuna llega ya, y la
//! sincronizacion diferencial garantiza despues la convergencia.
//!
//! # Por que UDP y no QUIC
//!
//! Un mensaje de esta malla es un hash y cuatro campos: cabe en un datagrama de
//! menos de 200 bytes. QUIC aporta flujos, control de congestion y establecimiento
//! de sesion cifrada, y ninguna de las tres cosas sirve para enviar un datagrama
//! suelto a los vecinos: lo que aportaria es una pila TLS entera —decenas de
//! miles de lineas— dentro de un producto de seguridad, y un apreton de manos
//! por par antes de poder decir nada. Se usa UDP con AEAD propio, que da la
//! misma confidencialidad y autenticidad para este caso y se audita en un
//! fichero.
//!
//! # Lo que la malla NO puede hacer
//!
//! La clave es compartida por toda la red local, asi que un atacante que
//! comprometa **un** equipo puede emitir mensajes validos. De ahi la regla que
//! define el diseno: una vacuna solo puede ANADIR indicadores, jamas retirarlos.
//! Retirar es privilegiado y viaja firmado con Ed25519 por el canal de
//! actualizacion, cuya clave no esta en ningun agente. Ver [`vaccine`].
//!
//! # Las tres cotas que impiden que la malla sea el ataque
//!
//! 1. **Saltos**: una vacuna se reenvia como mucho tres veces. Sin limite, tres
//!    agentes que reciben algo nuevo a la vez lo reenvian los tres y saturan la
//!    red local.
//! 2. **Deduplicacion**: lo ya visto no se reenvia. Corta los caminos redundantes
//!    de la inundacion.
//! 3. **Tasa por par**: un par que inunda se descarta, y la comprobacion va
//!    ANTES de descifrar, para no regalar un amplificador de CPU.

#![deny(missing_docs)]

pub mod crypto;
pub mod error;
pub mod mesh;
pub mod vaccine;
pub mod wire;

pub use error::MeshError;
pub use mesh::{DropReason, Mesh, MeshConfig, MeshStats, NodeId, Received};
pub use vaccine::{Severity, Vaccine};
pub use wire::{Header, MsgType};
