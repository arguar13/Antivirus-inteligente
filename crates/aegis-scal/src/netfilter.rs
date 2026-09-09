//! Interfaz de bloqueo de direcciones en el cortafuegos del sistema.
//!
//! Es la contencion mas barata que existe: no requiere tocar el proceso
//! atacante, no es reversible por el (no corre como root), y en las tres
//! plataformas hay un punto de aplicacion en el nucleo.
//!
//! El contrato exige que TODO lo que este rasgo aplica sea reversible y este
//! confinado a un contenedor propio del producto —una tabla, un sublayer, un
//! ancla—. Un motor de respuesta que edite las reglas del administrador no
//! puede deshacer su propio cambio sin arriesgarse a borrar las de otro.

use std::net::IpAddr;
use std::time::Duration;

use crate::error::ScalError;
use crate::platform::Platform;

/// Motivo por el que se bloquea una direccion. Se registra junto a la regla
/// para que el bloqueo sea auditable meses despues.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockReason {
    /// Reconocimiento detectado (barrido de puertos, sondeo de senuelos).
    Reconnaissance,
    /// Movimiento lateral hacia otros equipos de la red.
    LateralMovement,
    /// Comunicacion con infraestructura de mando y control conocida.
    CommandAndControl,
    /// Indicador recibido de la malla o del canal de inteligencia.
    ThreatIntel,
    /// Bloqueo pedido a mano por un operador.
    Manual,
}

impl BlockReason {
    /// Etiqueta estable para registros y para el comentario de la regla.
    pub fn as_str(self) -> &'static str {
        match self {
            BlockReason::Reconnaissance => "recon",
            BlockReason::LateralMovement => "lateral",
            BlockReason::CommandAndControl => "c2",
            BlockReason::ThreatIntel => "intel",
            BlockReason::Manual => "manual",
        }
    }
}

/// Una direccion bloqueada y su contexto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockedAddress {
    /// Direccion bloqueada.
    pub addr: IpAddr,
    /// Motivo con el que se aplico.
    pub reason: BlockReason,
    /// Caducidad pedida, si la hay.
    ///
    /// Un bloqueo permanente por un unico barrido de puertos convierte una
    /// deteccion en una interrupcion de servicio permanente; la caducidad es lo
    /// que hace que la respuesta automatica sea aceptable en produccion.
    pub ttl: Option<Duration>,
}

/// Cortafuegos del sistema, visto como una lista de bloqueo.
pub trait NetworkFilter {
    /// Plataforma que implementa este filtro.
    fn platform(&self) -> Platform;

    /// Indica si el punto de aplicacion esta disponible en esta maquina.
    ///
    /// Se consulta ANTES de prometer contencion: un motor de respuesta que cree
    /// haber bloqueado una direccion y no lo hizo es peor que uno que sabe que
    /// no puede y lo dice.
    fn available(&self) -> bool;

    /// Bloquea una direccion.
    ///
    /// Es idempotente: bloquear dos veces la misma direccion no es un error.
    fn block(
        &self,
        addr: IpAddr,
        reason: BlockReason,
        ttl: Option<Duration>,
    ) -> Result<(), ScalError>;

    /// Retira el bloqueo de una direccion. Tambien idempotente.
    fn unblock(&self, addr: IpAddr) -> Result<(), ScalError>;

    /// Enumera lo que hay bloqueado ahora mismo.
    fn blocked(&self) -> Result<Vec<BlockedAddress>, ScalError>;

    /// Retira TODO lo que este filtro aplico, dejando el sistema como estaba.
    fn flush(&self) -> Result<(), ScalError>;
}
