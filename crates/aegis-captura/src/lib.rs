//! # `aegis-captura` — AegisCapture (FASE 90)
//!
//! Retener el trafico y poder buscarlo, sin que el almacen sea la fuga.
//!
//! ## Las dos cosas que el capturador de referencia no hace
//!
//! Arkime indexa metadatos en un motor de busqueda de texto y guarda el PCAP al
//! lado. Funciona, y tiene dos huecos que aqui se cierran:
//!
//! 1. **El indice se construye sobre el modelo de entidad.** Buscar el trafico de
//!    una maquina, un proceso o un fichero no es correlacionar por texto: es
//!    mirar en su sitio. El [`aegis_entidad::entidad::Eid`] se **deriva** de los
//!    hechos y es el mismo que usan la deteccion, el linaje y el caso.
//! 2. **Retencion selectiva por veredicto.** Se guarda entero lo que el arbitro
//!    marco y solo el sobre lo demas. Medido en las pruebas: mas del noventa por
//!    ciento menos de disco para el mismo trafico, sin perder un byte de lo que
//!    importa.
//!
//! ## Lo que nunca se guarda, decidido una sola vez
//!
//! Un capturador que guarda todo es una fuga esperando a ocurrir. Las
//! credenciales en claro y los cuerpos de los ambitos que el cliente declara
//! sensibles **no llegan al disco**, y no por disciplina: el anillo solo acepta
//! [`redaccion::Limpio`], y `Limpio` no tiene mas constructor que
//! [`redaccion::Redactor::limpiar`]. Ver [`redaccion`].
//!
//! ## La politica de retencion esta en el tipo
//!
//! Guardar contenido entero exige una [`retencion::Autorizacion`], y una
//! `Autorizacion` solo se construye desde un veredicto que la justifique. No hay
//! `nueva()`, no hay `Default`: sin veredicto no hay cuerpo. Ver [`retencion`].
//!
//! ## Reproduccion determinista
//!
//! Un flujo guardado se vuelve a pasar por los disectores y por el arbitro y da
//! **el mismo veredicto**. Es la prueba de determinismo mas fuerte que existe,
//! porque la entrada es la real y no una fabricada para la ocasion.
//!
//! Y lleva su honestidad dentro: un flujo del que se tapo una credencial no
//! promete el mismo veredicto, porque si la senal estaba en lo tapado ya no esta.
//! Eso se declara en [`reproduccion::Fidelidad`] en vez de esconderse. Ver
//! [`reproduccion`].
//!
//! ## Sans-IO, como los disectores
//!
//! Este crate no abre sockets, no lee interfaces y no mira el reloj: recibe
//! paquetes con su marca de tiempo y devuelve lo que hizo con ellos. Es lo que
//! permite construir la prueba de carga entera —cien mil paquetes con el anillo
//! al limite— sin red, sin privilegios y sin condiciones de carrera.

// Un capturador toca los bytes de un desconocido y los escribe a disco. Aqui no
// hay ni un `unsafe`, y que lo impida el compilador es parte del diseno.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod anillo;
pub mod capturador;
pub mod indice;
pub mod pcap;
pub mod redaccion;
pub mod reproduccion;
pub mod retencion;

pub use anillo::{Anillo, Contadores, Paquete};
pub use capturador::{ahorro, Capturador, Flujo, Suerte};
pub use indice::{Cursor, Entrada, Indice, Pagina, Particion, MAX_ENTRADAS, MAX_MEMORIA_INDICE};
pub use redaccion::{AmbitoSensible, Donde, Limpio, Redactor};
pub use reproduccion::{reproducir, Fidelidad, FlujoGuardado, Reproduccion};
pub use retencion::{Autorizacion, Caducidad, Decision, Politica};
