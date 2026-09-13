//! AegisFabric, lado del plano de control: el tejido que convierte nueve
//! subsistemas en un producto.
//!
//! # Que hay aqui y que hay en `aegis-entidad`
//!
//! El modelo —identidad de entidad, escala, arbitro, linaje— vive en
//! [`aegis_entidad`], en el **workspace del agente**, porque tiene que correr en el
//! endpoint y no solo en el servidor. Una sola dependencia, `sha2`, que el agente
//! ya tenia.
//!
//! Este crate es lo otro: el sitio donde los subsistemas **se encuentran**.
//!
//! | Modulo | Que resuelve |
//! |---|---|
//! | [`inventario`] | Quien produce veredictos hoy, con que vocabulario y sobre que entidad — comprobado, no declarado |
//! | [`traduccion`] | La costura: un solo sitio donde cada vocabulario nativo se convierte en la escala unica |
//! | [`circuito`] | El circuito completo, de paquete en la red a indicador repartido por el enjambre |
//!
//! Depende de **todos** los subsistemas de deteccion; **ninguno** depende de este.
//! La direccion importa: si un subsistema dependiera del tejido, el tejido dejaria
//! de poder cambiar sin tocarlos a todos, y la traduccion volveria a repartirse.
//!
//! # La prueba que justifica la fase
//!
//! [`circuito::recorrer`] encadena once subsistemas sobre **un solo identificador
//! de entidad**:
//!
//! ```text
//! paquete en la red                      → aegis-wire       (FASE 70)
//!   → fichero extraido del flujo         → aegis-wire       (FASE 70)
//!   → escaneado con el corpus mundial    → aegis-ruleforge  (FASE 72)
//!   → detonado en microVM                → aegis-detonate   (FASE 73)
//!   → veredicto del arbitro unificado    → aegis-entidad    (FASE 79)
//!   → caso abierto con su cronologia     → aegis-case       (FASE 76)
//!   → enriquecido                        → aegis-enrich     (FASE 77)
//!   → camino de ataque y radio           → aegis-predict    (FASE 69)
//!   → contencion ejecutada               → aegis-predict    (FASE 64/69)
//!   → indicador compartido por TAXII     → aegis-share      (FASE 78)
//!   → repartido por el enjambre          → aegis-swarm      (FASE 68)
//! ```
//!
//! Que el identificador sea **uno** no es un detalle de presentacion: es lo que
//! permite que el analista pregunte «que sabemos de esta cosa» una sola vez en vez
//! de once, y es lo que un conjunto de productos de fabricantes distintos no puede
//! dar por mucha integracion que se le ponga encima.

#![forbid(unsafe_code)]

pub mod circuito;
pub mod inventario;
pub mod traduccion;

pub use circuito::{recorrer, Parada, Recorrido};
pub use inventario::{fila, Fila, CENSO};
