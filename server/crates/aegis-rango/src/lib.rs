//! # AegisRange — emulacion de adversario y medida de cobertura de deteccion
//!
//! ## Que resuelve, dicho para un defensor
//!
//! Un equipo de deteccion tiene que poder contestar «¿mi EDR ve la tecnica X?».
//! Hoy esa respuesta es una opinion: alguien ejecuta una tecnica, mira el panel y
//! dice «creo que si». MITRE Caldera y Atomic Red Team ejecutan la tecnica y
//! **dejan que tu mires**; el ciclo lo cierra una persona, y lo que una persona
//! cierra no entra en la puerta de calidad.
//!
//! AegisRange cierra el ciclo entero **de forma automatica y reproducible**:
//! ejecuta una emulacion **benigna y reversible** de la tecnica dentro de un rango
//! declarado, pregunta al arbitro por la entidad afectada, y **si no hubo veredicto
//! lo dice como HUECO DE COBERTURA con el nombre de la tecnica**. La cobertura de
//! deteccion deja de ser una opinion y pasa a ser una cifra que `make ci` publica.
//!
//! ## Las tres garantias que lo hacen seguro
//!
//! 1. **Solo en el rango, por tipo.** Una tecnica no se puede ejecutar sin una
//!    [`PruebaDeRango`], y esa prueba solo la acuna un [`Rango`] declarado
//!    explicitamente. No hay forma de ejecutar contra produccion: el tipo no la
//!    ofrece. Ver [`rango`].
//! 2. **Reversion obligatoria, por tipo.** El rasgo [`Tecnica`](tecnica::Tecnica)
//!    exige `revertir` **sin cuerpo por defecto**: una tecnica sin reversion **no
//!    compila**. La medida siempre revierte y comprueba que el rango vuelve a su
//!    estado anterior. Una prueba de cobertura que deja una puerta abierta es un
//!    incidente, no una prueba.
//! 3. **Emulacion benigna.** Lo que la tecnica «hace» es materializar un artefacto
//!    marcador en el directorio del rango y declarar la entidad afectada. El valor
//!    de esta fase esta en la MEDIDA de si la deteccion se dispara, no en un
//!    payload: no hay codigo de ataque, solo el gesto minimo que la deteccion
//!    deberia ver, hecho y deshecho dentro de la jaula.
//!
//! ## La honestidad del informe
//!
//! El informe tiene tres estados por tecnica —**detectada**, **no detectada**,
//! **no aplicable en esta plataforma**— y **nunca** cuenta una «no aplicable» como
//! detectada. Una capacidad que el producto afirma tener y que el rango no puede
//! confirmar sale marcada como afirmacion sin respaldo. Es la misma disciplina de
//! tri-estado que el resto del producto, aplicada a la propia cobertura.
//!
//! ## Lo que el rango revela hoy, y por que eso es el punto
//!
//! El arbitro (`aegis_entidad::arbitrar`) decide sobre las **señales** que se le
//! pasan. Varios motores DETECTAN pero todavia no entregan señal al arbitro —el
//! motor conductual y el forense de memoria, por ejemplo—. El rango no lo esconde:
//! esas tecnicas salen como **hueco de cobertura**, con su nombre, para que se
//! cierre el cableado. Medir la propia ceguera es exactamente para lo que existe.

#![forbid(unsafe_code)]

pub mod catalogo;
pub mod cobertura;
pub mod rango;
pub mod tecnica;

pub use cobertura::{medir_cobertura, Estado, FuenteSenales, InformeCobertura, ResultadoTecnica};
pub use rango::{ConfirmacionRango, ErrorRango, Plataforma, PruebaDeRango, Rango};
pub use tecnica::{Tactica, Tecnica};
