//! # aegis-consola — el lado servidor de la consola del SOC (FASE 110)
//!
//! Wazuh, TheHive, Velociraptor y Arkime tienen consola, y en varios de ellos la
//! interfaz ES el producto. AegisCore tenia API y CLI. Esta fase construye el lado
//! servidor de la consola, y lo hace respetando dos invariantes que la interfaz no
//! puede saltarse:
//!
//! - **La consola CONSULTA y GUARDA; no decide.** No hay logica de veredicto aqui:
//!   [`rbac`] autoriza, [`inquilino`] aisla, [`consulta`] calcula el coste antes de
//!   ejecutar, [`exportacion`] deja salir solo lo que el juez de difusion permite,
//!   y [`linaje`] es la vista del linaje unificado. Ninguno decide si algo es
//!   malicioso: eso lo dijo el arbitro, y la consola lo muestra.
//! - **La consola no es un camino de salida nuevo.** Todo lo que exporta pasa por
//!   el estrangulamiento de la FASE 78 ([`exportacion`], invariante 8), el mismo
//!   que TAXII, la federacion y el enjambre.
//!
//! Lo que gana a las demas: **el linaje UNIFICADO** ([`linaje`]) —una sola cadena
//! que cruza red, fichero, proceso, identidad y respuesta—, que solo puede ensenar
//! quien tiene un modelo de entidad unico.
//!
//! # La frontera
//!
//! El cliente web (el `panel/` en TypeScript de render directo) y el cableado de
//! cada vista a su subsistema —entidad, veredicto multi-motor, analisis (FASE 100),
//! enriquecimiento (FASE 77), procedencia (FASE 108), perdida del sensor (FASE 103)
//! y atestacion (FASE 105)— se construyen sobre este lado servidor. Aqui esta la
//! parte que DECIDE quien ve que y que puede salir, que es la que puede estar mal
//! de forma peligrosa, en Rust puro y probada.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod consulta;
pub mod exportacion;
pub mod inquilino;
pub mod linaje;
pub mod rbac;

pub use consulta::{previsualizar, CosteConsulta};
pub use exportacion::{exportar, Exportacion};
pub use inquilino::{filtrar, DeInquilino, Sesion};
pub use linaje::{Enlace, Linaje, Nodo, Plano};
pub use rbac::{autorizar, puede, Denegado, Permiso, Rol};
