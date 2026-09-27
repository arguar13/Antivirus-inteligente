//! # aegis-patron — el motor de patrones deja de ser prestado (FASE 101)
//!
//! Sustituye a `yara-x` en el arbol del agente. Un producto no puede superar a su
//! propia dependencia: como mucho la iguala, y siempre con el retraso de la version
//! que empaqueta, y cada fallo de esa dependencia es un fallo del agente en el
//! camino que come entrada hostil. Este motor propio cierra eso.
//!
//! # Las cinco propiedades que YARA no tiene, cada una por construccion
//!
//! 1. **Coste acotado por tipo.** Cada cadena lleva su cota demostrable
//!    ([`regla::Cota`]). Una regla cuya cota no se puede demostrar —un salto de hex
//!    sin tope, una repeticion sin acotar— **no compila**, y el error dice que
//!    parte no se acota ([`analizador::ErrorCompilacion::SinCota`]). YARA acepta
//!    esas reglas, y viajan en corpus publicos.
//! 2. **Tri-estado.** Escanear 4 MiB de un fichero de 4 GiB no es «limpio»: el
//!    [`motor::Resultado`] dice cuantos bytes se miraron y si fue completo.
//! 3. **Determinismo y orden.** El conjunto de coincidencias no depende del orden
//!    de carga de las reglas ni del numero de hilos: el escaneo es una funcion pura
//!    de (reglas, entrada), y los resultados salen ordenados.
//! 4. **Sin retroceso.** El motor de expresiones regulares ([`regex`]) es una
//!    simulacion tipo Pike VM del NFA de Thompson: tiempo lineal SIEMPRE, sin
//!    importar la regex. Sin retroceso no hay ReDoS —la propiedad se gana por
//!    construccion, no vigilando un limite—.
//! 5. **Seguridad de memoria.** `#![forbid(unsafe_code)]` en el motor que come
//!    entrada hostil. Es exactamente donde los motores en C han sangrado CVE de
//!    corrupcion de memoria durante veinte anos.
//!
//! # Compatibilidad de entrada, no de comportamiento
//!
//! El frontal ([`analizador`]) lee la sintaxis YARA —cadenas de texto y hex con
//! comodines y saltos, modificadores, condiciones con `and`/`or`/`not` y `N of`—
//! porque el corpus existente esta escrito asi. La SEMANTICA es la nueva. Lo que
//! este incremento aun no implementa —expresiones regulares `/.../`, modulos, xor/
//! base64— se DICE al compilar en vez de mal-escanear en silencio; ninguna regla
//! del conjunto base del agente lo usa, y se anade sobre el motor sin retroceso ya
//! presente.
//!
//! # Un solo motor
//!
//! El mismo codigo escanea fichero, memoria de proceso, flujo y volcado
//! ([`motor::Motor::escanear`]). Dos motores serian dos verdades.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod aho;
pub mod analizador;
pub mod motor;
pub mod regex;
pub mod regla;

pub use analizador::{compilar, ErrorCompilacion};
pub use motor::{Deteccion, Motor, Resultado};
pub use regla::{Cadena, Cond, Patron, Regla, Severidad};
