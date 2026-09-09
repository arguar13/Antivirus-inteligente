//! Correlacion de interacciones con senuelos y emision de alertas.
//!
//! # La confianza no se calcula, se hereda del senuelo
//!
//! En el resto del producto la confianza sale de una puntuacion. Aqui no hace
//! falta: el servicio no existe, asi que **cualquier** conexion es no
//! autorizada. Lo que este modulo decide no es *si* alertar, sino *que clase de
//! ataque* describe lo observado, que es lo que cambia la respuesta:
//!
//! - Un contacto suelto puede ser una herramienta de inventario mal apuntada.
//! - Varios puertos distintos desde el mismo origen es un barrido: alguien esta
//!   dibujando el mapa de la red.
//! - Datos que parecen credenciales son un intento de acceso, no reconocimiento.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use crate::decoy::{DecoyKind, Interaction};

/// Que describe lo observado.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlertKind {
    /// Una conexion suelta a un senuelo.
    Contact,
    /// El origen envio datos: no solo miro, hablo.
    Probe,
    /// Varios senuelos distintos desde el mismo origen: barrido.
    PortSweep,
    /// Reconocimiento contra servicios de acceso remoto (SSH, SMB, RDP).
    ///
    /// Es la firma del movimiento lateral: quien ya esta dentro busca por donde
    /// saltar al siguiente equipo, y esos tres puertos son por donde se salta.
    LateralMovement,
}

impl AlertKind {
    /// Etiqueta estable.
    pub fn as_str(self) -> &'static str {
        match self {
            AlertKind::Contact => "contacto",
            AlertKind::Probe => "sondeo",
            AlertKind::PortSweep => "barrido",
            AlertKind::LateralMovement => "movimiento-lateral",
        }
    }
}

/// Alerta emitida por la red de senuelos.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    /// Origen.
    pub peer: IpAddr,
    /// Clase de ataque.
    pub kind: AlertKind,
    /// Senuelos tocados por este origen, ordenados.
    pub decoys: Vec<DecoyKind>,
    /// Numero de interacciones acumuladas.
    pub interactions: u32,
    /// Instante de la primera interaccion.
    pub first_ns: u64,
    /// Instante de la ultima.
    pub last_ns: u64,
    /// Muestra de lo que envio, si envio algo.
    pub evidence: Vec<u8>,
    /// Cierto si el motor pide bloquear el origen.
    pub block: bool,
}

impl Alert {
    /// Resumen de una linea, para el registro.
    pub fn summary(&self) -> String {
        let senuelos: Vec<&str> = self.decoys.iter().map(|d| d.as_str()).collect();
        format!(
            "{} desde {} contra [{}] ({} interacciones){}",
            self.kind.as_str(),
            self.peer,
            senuelos.join(", "),
            self.interactions,
            if self.block { ", BLOQUEAR" } else { "" }
        )
    }
}

/// Servicios cuyo sondeo indica movimiento lateral.
const ACCESO_REMOTO: [DecoyKind; 4] = [
    DecoyKind::Ssh,
    DecoyKind::Smb,
    DecoyKind::Rdp,
    DecoyKind::WinRm,
];

/// Configuracion del sensor.
#[derive(Debug, Clone, Copy)]
pub struct SensorConfig {
    /// Senuelos distintos que constituyen un barrido.
    pub sweep_decoys: usize,
    /// Interacciones a partir de las cuales se pide bloquear.
    ///
    /// No es 1: una sola conexion puede ser un inventario mal configurado de la
    /// propia organizacion, y bloquear por ella acabaria cortando a un
    /// compañero. A partir de la segunda ya no hay excusa.
    pub block_after: u32,
    /// Tiempo tras el cual se olvida un origen inactivo.
    pub forget_after: Duration,
    /// Origenes seguidos como maximo.
    ///
    /// Acota la memoria ante una inundacion con direcciones falsificadas: sin
    /// limite, el detector seria el objetivo.
    pub max_peers: usize,
}

impl Default for SensorConfig {
    fn default() -> Self {
        Self {
            sweep_decoys: 3,
            block_after: 2,
            forget_after: Duration::from_secs(3600),
            max_peers: 4096,
        }
    }
}

/// Estado acumulado de un origen.
#[derive(Debug, Clone)]
struct Peer {
    decoys: Vec<DecoyKind>,
    interactions: u32,
    first_ns: u64,
    last_ns: u64,
    evidence: Vec<u8>,
    /// Clase mas grave ya reportada, para no repetir la misma alerta.
    reportado: Option<AlertKind>,
}

/// Sensor de reconocimiento.
#[derive(Debug)]
pub struct ReconSensor {
    peers: HashMap<IpAddr, Peer>,
    config: SensorConfig,
}

impl ReconSensor {
    /// Crea el sensor.
    pub fn new(config: SensorConfig) -> ReconSensor {
        ReconSensor {
            peers: HashMap::new(),
            config,
        }
    }

    /// Origenes seguidos ahora mismo.
    pub fn tracked(&self) -> usize {
        self.peers.len()
    }

    /// Ingiere una interaccion y devuelve una alerta si hay algo NUEVO que
    /// decir.
    ///
    /// Repetir la misma alerta por cada paquete convierte la consola en ruido y
    /// entrena al analista a ignorarla. Solo se emite cuando la clase de ataque
    /// se agrava.
    pub fn observe(&mut self, i: &Interaction) -> Option<Alert> {
        // El limite se aplica ANTES de insertar: si ya se llego al tope y el
        // origen es nuevo, se olvida el mas antiguo en vez de crecer.
        if self.peers.len() >= self.config.max_peers && !self.peers.contains_key(&i.peer) {
            self.olvidar_mas_antiguo();
        }

        let p = self.peers.entry(i.peer).or_insert_with(|| Peer {
            decoys: Vec::new(),
            interactions: 0,
            first_ns: i.ts_ns,
            last_ns: i.ts_ns,
            evidence: Vec::new(),
            reportado: None,
        });
        p.interactions += 1;
        p.last_ns = i.ts_ns;
        if !p.decoys.contains(&i.kind) {
            p.decoys.push(i.kind);
            p.decoys.sort_unstable();
        }
        if p.evidence.is_empty() && i.spoke() {
            p.evidence = i.evidence.clone();
        }

        let clase = clasificar(&p.decoys, !p.evidence.is_empty(), self.config.sweep_decoys);
        if p.reportado.is_some_and(|previa| previa >= clase) {
            return None;
        }
        p.reportado = Some(clase);

        Some(Alert {
            peer: i.peer,
            kind: clase,
            decoys: p.decoys.clone(),
            interactions: p.interactions,
            first_ns: p.first_ns,
            last_ns: p.last_ns,
            evidence: p.evidence.clone(),
            block: p.interactions >= self.config.block_after
                || matches!(clase, AlertKind::PortSweep | AlertKind::LateralMovement),
        })
    }

    /// Olvida los origenes inactivos. Devuelve cuantos.
    pub fn prune(&mut self, now_ns: u64) -> usize {
        let limite = self.config.forget_after.as_nanos() as u64;
        let antes = self.peers.len();
        self.peers
            .retain(|_, p| now_ns.saturating_sub(p.last_ns) < limite);
        antes - self.peers.len()
    }

    fn olvidar_mas_antiguo(&mut self) {
        if let Some(k) = self
            .peers
            .iter()
            .min_by_key(|(_, p)| p.last_ns)
            .map(|(k, _)| *k)
        {
            self.peers.remove(&k);
        }
    }
}

/// Decide la clase de ataque a partir de lo acumulado.
///
/// El orden importa: se devuelve la clase MAS grave que encaje, porque
/// [`ReconSensor::observe`] solo emite cuando la gravedad sube.
pub fn clasificar(decoys: &[DecoyKind], hablo: bool, sweep: usize) -> AlertKind {
    let remotos = decoys.iter().filter(|d| ACCESO_REMOTO.contains(d)).count();
    // Dos o mas servicios de acceso remoto desde el mismo origen es alguien
    // buscando por donde saltar al siguiente equipo. Uno solo todavia puede ser
    // un inventario; dos ya no.
    if remotos >= 2 {
        return AlertKind::LateralMovement;
    }
    if decoys.len() >= sweep {
        return AlertKind::PortSweep;
    }
    if hablo {
        return AlertKind::Probe;
    }
    AlertKind::Contact
}
