//! # aegis-custodia
//!
//! Cadena de custodia verificable para la evidencia forense de una flota.
//!
//! # El problema
//!
//! `aegis-forensics` ya recoge lo que hay que recoger antes de que desaparezca:
//! el arbol de procesos, los sockets, los hashes, la memoria. Lo que produce es
//! un conjunto de bytes correcto, y eso basta para investigar.
//!
//! No basta para **sostener**. En cuanto alguien discute la prueba —el cliente,
//! su aseguradora, un regulador, un juez, o el propio analista seis meses
//! despues— las preguntas que llegan no son sobre el contenido:
//!
//! - ¿Como se sabe que estos bytes salieron de ESA maquina?
//! - ¿Como se sabe que son los mismos que salieron, y no los que alguien puso
//!   despues en el almacen?
//! - ¿Quien los ha tenido en las manos desde entonces, y consta lo que hizo?
//! - ¿La hora que dice el informe es la hora en que ocurrio?
//!
//! Un fichero suelto, por autentico que sea, no contesta ninguna. Y la respuesta
//! «confie en nuestro producto» es exactamente la que un forense no puede dar.
//!
//! # Lo que hay aqui
//!
//! | Pieza | Que ata | Modulo |
//! |---|---|---|
//! | **Codificacion canonica** | que los bytes firmados sean los mismos dentro de diez anos y en otra compilacion | [`canon`] |
//! | **Los dos relojes** | que mover el reloj de la maquina deje de ser invisible | [`reloj`] |
//! | **El sello** | unos bytes a un caso, una maquina, un agente, un momento y un motivo | [`sello`] |
//! | **La cadena** | cada mano por la que paso, en orden, sin poder quitar ni colar pasos | [`cadena`] |
//! | **El veredicto** | lo que queda probado **y lo que no** | [`verificar`] |
//! | **El conjunto de flota** | que una recogida incompleta no se presente como completa | [`flota`] |
//!
//! # Las tres decisiones que sostienen todo lo demas
//!
//! **No se firma JSON.** Una firma cubre bytes, y JSON no tiene forma canonica:
//! el orden de las claves, el escapado y el formato de los numeros cambian entre
//! bibliotecas y entre versiones sin cambiar el significado. La reverificacion
//! fallaria justo cuando hiciera falta, anos despues. Los bytes los define
//! [`canon`], con longitud delante de cada campo.
//!
//! **No se confia en un solo reloj.** El reloj de pared es el unico que sabe que
//! dia es y el unico que un atacante con root puede mover. Cada marca lleva
//! tambien el reloj de arranque, que no se puede fijar, de modo que una
//! contradiccion entre los dos deja de ser invisible y pasa a ser aritmetica.
//!
//! **No se devuelve un booleano.** «Custodia verificada: SI» induce a entender
//! cuatro cosas que la criptografia no prueba. [`verificar::Veredicto`] lleva la
//! lista explicita de lo que no establece, en la estructura de datos y no en una
//! nota al pie, para que quien redacte el informe tenga que pasar por ella.
//!
//! # Lo que este crate NO hace
//!
//! No recoge evidencia —eso es `aegis-forensics`—, no la transporta —eso es
//! `aegis-fleet`— y no la almacena —eso es `aegis-audit` y el plano de control—.
//! Solo responde por ella. Mezclarlo con la recogida seria pedirle al mismo
//! codigo que produzca la prueba y que la avale.

// SEGURIDAD DE MEMORIA IMPUESTA POR EL COMPILADOR (FASE 80).
//
// Este crate no necesita `unsafe`, asi que lo prohibe. Las dos llamadas al
// sistema que hacen falta —los dos relojes— viven en `aegis-scal`, que es donde
// el producto concentra el `unsafe` para tenerlo revisado en un sitio y no
// repartido por veinte crates.
//
// La invariante del producto no admite tercera opcion: todo crate del agente O
// declara esto, O esta en `tools/lineabase-unsafe.txt` con su razon escrita.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod cadena;
pub mod canon;
pub mod error;
pub mod flota;
pub mod reloj;
pub mod sello;
pub mod verificar;

pub use cadena::{CadenaDeCustodia, Claveros, Eslabon, Paso, RegistroDeClaves};
pub use canon::{hex, Resumen};
pub use error::CustodiaError;
pub use flota::{Ausencia, ConjuntoDeFlota, Pieza};
pub use reloj::Marca;
pub use sello::{Clase, Procedencia, Sello};
pub use verificar::{LimiteDeLaPrueba, Veredicto};
