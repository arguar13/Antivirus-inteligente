//! # `aegis-instrumentar` — AegisInstrument: instrumentacion dirigida (FASE 87)
//!
//! ## El problema
//!
//! El analisis estatico se rinde en sitios concretos y sabe decir cuales: las
//! transferencias de control cuyo destino se calcula, los saltos a codigo que no
//! esta en el fichero, lo que un empaquetador despliega al ejecutarse. La
//! ejecucion responde esas preguntas sin esfuerzo.
//!
//! Pero instrumentar todo es inservible: una ejecucion con un punto por
//! instruccion tarda mil veces mas, produce una traza que nadie lee y va tan
//! lenta que la muestra lo nota y se comporta distinto. Lo que hace falta es
//! decidir **donde** mirar, y eso es un problema de analisis.
//!
//! Este crate resuelve ese problema y **solo** ese.
//!
//! ## La invariante que lo define: no hay «escribir en proceso»
//!
//! Un instrumentador escribe en el espacio de direcciones de un proceso: pone un
//! `0xCC` donde habia una instruccion, redirige una llamada, parchea una tabla.
//! Eso es exactamente lo que hace una inyeccion de codigo. La diferencia entre
//! una herramienta de analisis y una primitiva de ataque no esta en la intencion
//! de quien la use: **esta en donde puede escribir**.
//!
//! Por eso [`Plan`] no tiene `aplicar`. No existe. Un plan es una lista de
//! direcciones con sus razones, y lo unico que se puede hacer con el es leerlo.
//! Quien lo aplica es la microVM —otro crate, otra maquina virtual, otro espacio
//! de direcciones—, y ese reparto es la invariante 9 del encargo: **el
//! instrumentador no tiene variante de «escribir en proceso» fuera de la
//! microVM**.
//!
//! Si este crate tuviera un `aplicar(pid)`, cualquiera que se hiciera con el
//! agente tendria una primitiva de inyeccion escrita, probada y firmada por el
//! fabricante.
//!
//! ## Lo que su silencio significa
//!
//! «Esto no aparece en la traza» admite tres lecturas —no ocurrio, no habia
//! punto ahi, la ejecucion se corto antes— y solo una es buena. [`Traza`] lleva
//! dentro el plan con el que se tomo y como termino la ejecucion, que es lo unico
//! que permite separarlas. Ver [`traza`].

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod donde;
pub mod jaula;
pub mod plan;
pub mod punto;
pub mod simbolos;
pub mod traza;

pub use donde::plan_desde;
pub use jaula::{Interventor, Jaula, Observador, PruebaDeJaula};
pub use plan::Plan;
pub use punto::{Punto, Que};
pub use simbolos::{resolver, Firma, Simbolo, Via};
pub use traza::{Final, Suceso, Traza};
