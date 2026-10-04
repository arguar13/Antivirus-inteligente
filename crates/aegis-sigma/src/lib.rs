//! # aegis-sigma
//!
//! Reglas Sigma de principio a fin: se leen ([`yaml`]), se compilan a una
//! representacion intermedia con su condicion analizada ([`regla`]) y se evaluan
//! en el camino caliente del agente con coste acotado y sin retroceso
//! ([`compacta`]). Cada regla que se distribuye pasa una puerta
//! ([`contenido`]) con dos eventos generados desde la propia regla
//! ([`generador`]) y un presupuesto de falsos positivos.
//!
//! # Por que es un crate aparte (FASE 4 del MP-16, paso 5)
//!
//! El compilador vivia en `aegis-ruleforge`, en el workspace del plano de
//! control: la fabrica compilaba reglas Sigma que ningun endpoint evaluaba. Para
//! que el agente las ejecute sin enlazar el servidor, el compilador y el
//! evaluador se sacan aqui y la fabrica los reexporta. Hay UN evaluador: el que
//! usa la fabrica para comprobar una regla es el mismo que corre en el endpoint.
//!
//! # Las garantias del camino caliente
//!
//! - **Sin retroceso.** No hay expresiones regulares: el agente rechaza con
//!   nombre las reglas que las usan. Los comodines `*` se evaluan buscando cada
//!   trozo literal con KMP, que nunca vuelve atras sobre el texto: el coste es
//!   lineal en la longitud del campo, sea cual sea el contenido.
//! - **Coste acotado por regla.** Cada regla compilada lleva su coste en el peor
//!   caso (pasos de comparacion con los campos al tope de longitud), y una regla
//!   o un juego que pase del tope se rechaza AL CARGAR, con nombre. Nunca en
//!   mitad de un evento.
//! - **Sin reservas por evento.** El evento se presenta como una tabla fija de
//!   campos ([`compacta::Registro`]) que apunta a bytes que ya existen.
//! - **Nada que pueda entrar en panico con entrada hostil.** Se compara sobre
//!   bytes, nunca cortando un `&str` por una posicion que puede caer en mitad de
//!   un caracter.
//!
//! # El contenido
//!
//! Las reglas de [`incluidas`] se importan del catalogo publico SigmaHQ
//! (licencia DRL 1.1, con su atribucion) por `tools/sigma/importar.sh`, fijado a
//! un commit. No hay reglas escritas a mano en este crate.
//!
//! # Lo que NO hace
//!
//! - Evaluar expresiones regulares (`|re`), palabras clave sueltas, `|base64`,
//!   `|cidr`, correlaciones ni ventanas de tiempo. Todo eso se rechaza con
//!   nombre y se cuenta.
//! - Plegar mayusculas fuera de ASCII: Sigma compara sin distinguir mayusculas y
//!   aqui se hace byte a byte en ASCII.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod compacta;
pub mod contenido;
pub mod generador;
pub mod incluidas;
pub mod patron;
pub mod regla;
pub mod yaml;

pub use compacta::{Campo, Categoria, Juego, Rechazo, Registro, ReglaCompacta};
pub use regla::{compilar_regla, ErrorSigma, Nivel, ReglaSigma, Topes};
