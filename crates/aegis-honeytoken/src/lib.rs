//! Honey-tokens dinamicos y decepcion activa — FASE 52.
//!
//! # La idea, y por que es defensa
//!
//! Un honey-token es una credencial FALSA que ningun proceso legitimo tiene
//! motivo de tocar. Se siembra donde un atacante mira despues de entrar —en la
//! memoria de un proceso critico, en un fichero de credenciales, en un `.pgpass`
//! olvidado— y no da acceso a nada. Su unico proposito es que, en el instante en
//! que alguien la lee o la usa, delata su presencia: no hay falsos positivos,
//! porque nadie honrado toca lo que no sirve para nada.
//!
//! Es una tecnica puramente DEFENSIVA (deception / canary tokens): convierte el
//! movimiento lateral del atacante —el paso en que recolecta credenciales— en la
//! senal que lo descubre.
//!
//! # Que es atribuible y por que
//!
//! Cada token lleva un marcador HMAC unico ([`token`]) que ata la credencial a
//! UN host, UN proceso sembrado y UN identificador. Cuando el marcador aparece
//! —leido de memoria, abierto como fichero— se sabe exactamente que senuelo se
//! toco y donde estaba, y como esta firmado con un secreto de flota, un atacante
//! no puede fabricar un honey-token que nos confunda.
//!
//! # El nucleo se prueba; la colocacion en memoria ajena, no
//!
//! Siguiendo el patron de la FASE 47, el NUCLEO —acunar el marcador, renderizar
//! la credencial como un artefacto CREIBLE (validado por parsers reales), decidir
//! si un evento toco un token ([`trip`])— es Rust puro y se prueba en cada
//! `make ci`. La FONTANERIA que ESCRIBE el token en la memoria de otro proceso
//! (`process_vm_writev` en un ssh-agent, la inyeccion en LSASS en Windows) vive
//! tras la feature `inyeccion` y el CI declara que no se ejercio: escribir en la
//! memoria de otro proceso necesita privilegios y un objetivo vivo.

#![deny(unsafe_code)]

pub mod credformat;
pub mod honeyfile;
pub mod memtoken;
pub mod registry;
pub mod respuesta;
pub mod token;
pub mod trip;

#[cfg(feature = "inyeccion")]
#[allow(unsafe_code)] // process_vm_writev; cada bloque lleva su SAFETY
pub mod inyeccion;

pub use credformat::{render, Artefacto};
pub use registry::Registro;
pub use respuesta::{decidir_respuesta, Respuesta};
pub use token::{Acunador, Atribucion, Marcador};
pub use trip::{clasificar, Disparo, Evento};
