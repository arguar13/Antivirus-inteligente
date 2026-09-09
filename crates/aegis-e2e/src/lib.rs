//! # aegis-e2e
//!
//! Crate contenedor de las pruebas de integracion de extremo a extremo.
//!
//! No exporta funcionalidad: existe para que las pruebas puedan depender a la
//! vez del agente, del IDS de red, del motor de respuesta y del escaner, y
//! ejercitar la cadena completa igual que lo haria el producto instalado.
//!
//! Lo que estas pruebas cubren y las de cada crate no pueden cubrir: que las
//! piezas encajen. Un agente que detecta perfectamente y un motor de respuesta
//! que termina perfectamente siguen siendo un producto roto si la clave de
//! proceso que emite uno no es la que espera el otro.

#![deny(missing_docs)]

/// Version del conjunto de pruebas de extremo a extremo.
pub const E2E_SUITE_VERSION: &str = "1";
