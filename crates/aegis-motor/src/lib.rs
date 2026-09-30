//! # aegis-motor
//!
//! El contrato que cumple todo motor de deteccion del agente, y el arbitro, que es
//! el unico que los invoca y el unico que combina lo que dicen.
//!
//! # La causa raiz que cierra (FASE 1 del MP-16)
//!
//! El agente crecio por bibliotecas: cada motor tenia su propia forma de recibir
//! un evento, de decir lo que pensaba y de gastar tiempo y memoria. Sumar uno
//! mas era cablearlo a mano en el bucle, sin presupuesto y sin forma de decir
//! «no pude mirar». El resultado se ve en la matriz de capacidades: motores
//! enlazados que nadie invoca, y un bucle que imprimia escalados sin decidir.
//!
//! # El contrato
//!
//! ```text
//!   evento tipado ──► Motor::evaluar(evento, plazo) ──► Dictamen
//!                                                        ├─ NoAplica
//!                                                        ├─ Senales (juicio + evidencia)
//!                                                        └─ SinDatos (con su causa)
//! ```
//!
//! - **Tri-estado honesto.** Un motor dice malicioso / sospechoso / limpio, o
//!   «no pude mirar» —[`Dictamen::SinDatos`], con la causa—, que nunca se
//!   confunde con limpio. Es la escala de [`aegis_entidad::Juicio`].
//! - **Presupuesto por motor.** Tiempo por evento y memoria, declarados en su
//!   [`Ficha`]. El arbitro mide el tiempo el mismo (no se lo pregunta al motor),
//!   le pasa un [`Plazo`] para que corte a tiempo, y al motor que se pasa de forma
//!   repetida lo suspende: mientras dura, todo lo que le tocaba mirar es
//!   `SinDatos` por suspension, contado y visible.
//! - **Registro segun el host.** Un motor declara que necesita ([`Requisito`]);
//!   el que no puede correr en esta maquina no se registra y queda declarado,
//!   nunca omitido en silencio.
//! - **Un solo punto de entrada.** Solo [`Arbitro`] llama a
//!   [`Motor::evaluar`], y solo el combina las señales, con la regla de
//!   [`aegis_entidad::arbitrar`]. La puerta `motores` de make ci lo comprueba
//!   sobre el codigo del agente.
//!
//! # Lo que este crate NO hace
//!
//! Cancelar a la fuerza un motor que corre en el mismo proceso: en Rust no se
//! puede interrumpir una funcion desde fuera sin arriesgar el estado. Por eso el
//! plazo es cooperativo y la sancion es la suspension; lo que puede colgarse o
//! reventar de verdad —los parsers de bytes hostiles— no corre aqui, corre en el
//! trabajador confinado, donde el plazo se impone matando el proceso.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod arbitro;
pub mod contrato;
pub mod histograma;

pub use arbitro::{Arbitro, ConfigArbitro, EstadoMotor, Omitido};
pub use contrato::{
    Camino, Causa, Dictamen, Evento, Ficha, Host, Motor, Plazo, Presupuesto, Requisito,
};
pub use histograma::Histograma;
