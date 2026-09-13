//! # aegis-ctl
//!
//! Canal de control local del agente: protocolo, servidor, cliente y la
//! herramienta de administracion `aegisctl`.
//!
//! El operador necesita hablar con el agente en ejecucion: ver su estado,
//! lanzar un escaneo, aislar la red en una emergencia, consultar la cuarentena.
//! Ese canal es un socket Unix con permisos 0600 —lo que controla el EDR lo
//! controla root— y un protocolo de texto de una peticion por conexion.
//!
//! - [`protocol`]: peticiones, respuestas y su formato de texto.
//! - [`server`]: el servidor que embebe el agente y el cliente que usa la CLI.
//! - [`handler`]: el manejador real, que conecta cada comando con el motor de
//!   escaneo, el de respuesta y la cuarentena.

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

pub mod handler;
pub mod protocol;
pub mod server;

pub use handler::{AgentControl, StatusSource};
pub use protocol::{
    IsolateInfo, IsolateMode, ProtocolError, Request, Response, ScanInfo, StatusInfo,
};
pub use server::{ControlClient, ControlHandler, ControlServer, ServerError};
