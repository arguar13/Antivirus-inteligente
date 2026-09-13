//! # aegis-invitado
//!
//! El agente que corre **dentro** de la maquina que se esta infectando.
//!
//! ## Donde vive este codigo
//!
//! No es una forma de hablar: la muestra que se detona corre en la misma maquina
//! y con los mismos permisos que este binario, y en cuanto escala los tiene
//! todos. Todo lo de aqui esta escrito partiendo de que **la muestra puede acabar
//! controlando este proceso**.
//!
//! De ahi las tres decisiones que gobiernan el crate:
//!
//! 1. **Arbol minimo.** Solo `libc`. Cada crate enlazado aqui es codigo que el
//!    malware puede intentar subvertir para llegar al anfitrion por el canal.
//! 2. **El canal no admite ordenes.** [`protocolo::Evento`] no tiene ni una
//!    variante que sea una peticion, y esa ausencia **es** la frontera: el
//!    anfitrion no tiene nada que validar porque no tiene nada que ejecutar.
//! 3. **Perder evidencia es peor que tener poca.** Una ruta que no es UTF-8 se
//!    escapa en vez de descartarse, un hueco en la secuencia se anota en vez de
//!    abortar, y un recorte por tope se declara en vez de disimularse.
//!
//! ## Lo que NO ve, declarado
//!
//! - Lo que pasa **dentro** de una llamada al sistema: se ven los argumentos a la
//!   entrada y el resultado a la salida.
//! - Codigo en otro anillo. Una muestra que carga un modulo se ha salido del
//!   alcance de `ptrace`; lo que queda es el `finit_module`, y por eso esa
//!   llamada esta marcada como evasion.
//! - Una muestra que se traza a si misma puede desenganchar al trazador. Eso se
//!   emite como [`protocolo::Evento::Degradado`] en vez de callarse.

#![deny(missing_docs)]
// ptrace, fork y los limites del proceso no tienen forma segura en la biblioteca
// estandar. Cada bloque lleva su justificacion SAFETY.
#![allow(unsafe_code)]

pub mod canal;
pub mod llamadas;
pub mod protocolo;
pub mod trazador;

pub use canal::{Canal, ErrorCanal};
pub use llamadas::{Entrada, Interes};
pub use protocolo::{
    AccionFichero, AccionProceso, AccionRed, Clase, ErrorProtocolo, Evento, Trama,
};
pub use trazador::{Config, Corte, Desenlace, ErrorTrazador, Resultado, Sumidero};

/// Version del agente invitado, para cuadrar informes entre revisiones.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
