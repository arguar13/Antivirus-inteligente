//! # aegis-intel
//!
//! Reputacion de ficheros en la nube **sin decirle a la nube que ficheros
//! tienes**.
//!
//! # El problema
//!
//! Enviar el SHA-256 completo de cada fichero que se ejecuta parece inocuo y no
//! lo es. El hash identifica el fichero de forma unica, y la secuencia de
//! hashes de un equipo revela que software usa, que documentos abre y que
//! binarios internos propietarios tiene esa empresa. Es un registro de
//! actividad con nombre y apellidos, y el servidor no deberia poder construirlo
//! aunque quisiera.
//!
//! # El mecanismo
//!
//! Del hash salen del equipo **cinco caracteres**. El servidor devuelve todos
//! los hashes que conoce que empiezan por ellos — unos mil — y el cliente busca
//! el suyo en esa lista, localmente.
//!
//! ```text
//! Cliente:  sha256(fichero) = a3f2b8c1d4e5...
//!           envia: a3f2b                         <- 5 caracteres, 20 bits
//! Servidor: devuelve ~1.000 candidatos con su veredicto
//! Cliente:  compara los 59 caracteres restantes, en memoria
//! ```
//!
//! El servidor sabe que se pregunto por *algo* dentro de un millar. No sabe
//! cual, y como el resto del hash no sale nunca del equipo, tampoco puede
//! saberlo despues.
//!
//! # Las dos propiedades que hay que sostener
//!
//! 1. **El sufijo no se transmite.** Por eso [`hash::Prefix`] y
//!    [`hash::Suffix`] son tipos distintos y `Suffix` no implementa un `Debug`
//!    que lo revele: un `derive` habria acabado escribiendo la parte secreta en
//!    el primer registro de error.
//! 2. **Las consultas no se repiten.** El k-anonimato protege una consulta
//!    aislada, no la repeticion: mil consultas del mismo prefijo se pueden
//!    correlacionar. Por eso la [`cache`] es parte del mecanismo de privacidad
//!    y no solo del rendimiento, con caducidad por veredicto y **cache
//!    negativa** incluida.
//!
//! # La nube nunca esta en la ruta de decision
//!
//! Ninguna consulta bloquea un veredicto. Si lo hiciera, cada ejecucion pagaria
//! latencia de red y un corte del enlace dejaria al usuario sin proteccion. Un
//! fallo de red devuelve "desconocido" y el producto decide con YARA, el modelo
//! local y las reglas conductuales.

#![deny(missing_docs)]

pub mod cache;
pub mod client;
pub mod hash;
pub mod protocol;
pub mod transport;
pub mod verdict;

pub use cache::{CacheLookup, CacheStats, ReputationCache};
pub use client::{Answer, ClientStats, Origin, ReputationClient};
pub use hash::{Digest256, HashError, Prefix, Suffix, PREFIJO_LEN, SUFIJO_LEN};
pub use protocol::{parse_bucket, render_bucket, resolve, BucketEntry};
pub use transport::{HttpTransport, Transport, TransportError};
pub use verdict::{Record, Reputation};
