//! # aegis-macho
//!
//! Lector de binarios de macOS: Mach-O y **universales**.
//!
//! # El hueco que cierra, y la trampa que lo hace distinto de Windows
//!
//! La FASE 83 le enseno al agente a abrir un ejecutable de Windows. En macOS el
//! problema tiene una vuelta de tuerca que no existe en ningun otro sistema: un
//! fichero ejecutable puede contener **varios programas a la vez**, uno por
//! arquitectura, y el sistema elige cual corre segun la maquina.
//!
//! Eso convierte una practica habitual de analisis en un punto ciego con nombre:
//! una herramienta que abra el binario, encuentre la primera rodaja y la analice
//! esta analizando **el programa que no se va a ejecutar** en la mitad del parque.
//! Un atacante que ponga codigo limpio en la rodaja x86_64 y su carga en la
//! arm64 pasa por delante de cualquier analisis que no mire las dos, y hoy los
//! Mac son arm64.
//!
//! Por eso aqui un binario universal **no se reduce a una rodaja**. [`Binario`]
//! las trae todas, y quien consuma esto tiene que decidir explicitamente que
//! hace con cada una: no hay una API que devuelva «la» rodaja, porque no existe.
//!
//! # La segunda trampa: dos ordenes de byte en el mismo fichero
//!
//! El encabezado universal es **big-endian siempre**, por herencia de NeXT. Los
//! encabezados Mach-O de dentro son little-endian en todas las maquinas que
//! quedan. Leer el primero en orden nativo funciona en un PowerPC de 2003 y en
//! ningun ordenador actual; leerlo en little-endian da un numero de rodajas
//! absurdo. Se lee cada uno en el suyo, y esta escrito aqui para que no se
//! vuelva a perder.
//!
//! # Lo que este crate NO hace
//!
//! **No valida la firma de codigo.** Localiza el `LC_CODE_SIGNATURE` y dice que
//! bytes ocupa. Validar el `SuperBlob`, su `CodeDirectory`, los hashes de pagina
//! y la cadena hasta Apple es otro trabajo. Decir «firmado» cuando lo comprobado
//! es «declara una firma» seria la misma exageracion que este proyecto no hace
//! en Windows.

// SEGURIDAD DE MEMORIA IMPUESTA POR EL COMPILADOR (FASE 80).
//
// Lee entrada hostil: es exactamente donde el producto no admite `unsafe`.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod error;
pub mod indicios;
pub mod macho;
pub mod universal;

pub use error::MachoError;
pub use indicios::IndicioMac;
pub use macho::{Comando, Macho, Segmento};
pub use universal::{Binario, Rodaja};
