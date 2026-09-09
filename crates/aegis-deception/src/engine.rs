//! El motor: senuelos, correlacion y bloqueo.

use std::net::IpAddr;
use std::time::Duration;

use aegis_scal::netfilter::{BlockReason, NetworkFilter};

use crate::decoy::{DecoyConfig, DecoyNet, Interaction, Skipped};
use crate::guard::Guard;
use crate::sensor::{Alert, AlertKind, ReconSensor, SensorConfig};

/// Resultado de una vuelta del motor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Round {
    /// Interacciones observadas.
    pub interactions: Vec<Interaction>,
    /// Alertas nuevas.
    pub alerts: Vec<Alert>,
    /// Direcciones efectivamente bloqueadas en esta vuelta.
    pub blocked: Vec<IpAddr>,
    /// Bloqueos que la barandilla rechazo, con su motivo.
    ///
    /// Se reportan en vez de callarse: que el motor haya querido bloquear la
    /// puerta de enlace es informacion operativa de primer orden, tanto si
    /// significa que un atacante la esta suplantando como si significa que la
    /// deteccion esta mal calibrada.
    pub refused: Vec<(IpAddr, &'static str)>,
}

impl Round {
    /// Indica si no paso nada.
    pub fn is_empty(&self) -> bool {
        self.interactions.is_empty() && self.alerts.is_empty()
    }
}

/// Configuracion del motor.
#[derive(Debug, Clone)]
pub struct DeceptionConfig {
    /// Senuelos.
    pub decoys: DecoyConfig,
    /// Correlacion.
    pub sensor: SensorConfig,
    /// Direcciones que nunca se bloquean.
    pub allowlist: Vec<IpAddr>,
    /// Caducidad del bloqueo.
    ///
    /// Un bloqueo permanente por un barrido convierte una deteccion en una
    /// interrupcion permanente; el plazo es lo que hace aceptable la respuesta
    /// automatica. El kernel lo expira solo.
    pub block_ttl: Option<Duration>,
    /// Si es falso, se alerta pero no se bloquea.
    pub autonomous: bool,
}

impl Default for DeceptionConfig {
    fn default() -> Self {
        Self {
            decoys: DecoyConfig::default(),
            sensor: SensorConfig::default(),
            allowlist: Vec::new(),
            block_ttl: Some(Duration::from_secs(3600)),
            autonomous: true,
        }
    }
}

/// Contadores del motor.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DeceptionStats {
    /// Interacciones observadas.
    pub interactions: u64,
    /// Alertas emitidas.
    pub alerts: u64,
    /// Direcciones bloqueadas.
    pub blocked: u64,
    /// Bloqueos rechazados por la barandilla.
    pub refused: u64,
}

/// Motor de decepcion.
pub struct DeceptionEngine<F: NetworkFilter> {
    net: DecoyNet,
    sensor: ReconSensor,
    guard: Guard,
    filter: F,
    config: DeceptionConfig,
    stats: DeceptionStats,
}

impl<F: NetworkFilter> std::fmt::Debug for DeceptionEngine<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeceptionEngine")
            .field("senuelos", &self.net.active())
            .field("omitidos", &self.net.skipped().len())
            .field("stats", &self.stats)
            .finish()
    }
}

impl<F: NetworkFilter> DeceptionEngine<F> {
    /// Levanta los senuelos y prepara el motor.
    pub fn start(config: DeceptionConfig, filter: F) -> DeceptionEngine<F> {
        let net = DecoyNet::bind(config.decoys.clone());
        let sensor = ReconSensor::new(config.sensor);
        let guard = Guard::detect(config.allowlist.clone());
        DeceptionEngine {
            net,
            sensor,
            guard,
            filter,
            config,
            stats: DeceptionStats::default(),
        }
    }

    /// Senuelos activos con su puerto real.
    pub fn active(&self) -> Vec<(crate::decoy::DecoyKind, u16)> {
        self.net.active()
    }

    /// Senuelos que no se pudieron levantar.
    pub fn skipped(&self) -> &[Skipped] {
        self.net.skipped()
    }

    /// Barandilla en uso.
    pub fn guard(&self) -> &Guard {
        &self.guard
    }

    /// Contadores.
    pub fn stats(&self) -> DeceptionStats {
        self.stats
    }

    /// Una vuelta del bucle: atiende, correlaciona y bloquea.
    pub fn tick(&mut self, timeout: Duration, now_ns: u64) -> Round {
        let interacciones = self.net.poll(timeout, now_ns);
        self.ingest(interacciones, now_ns)
    }

    /// Procesa interacciones ya obtenidas.
    ///
    /// Publico para poder ejercitar la correlacion y el bloqueo con origenes
    /// concretos sin tener que fabricar trafico desde esas direcciones.
    pub fn ingest(&mut self, interacciones: Vec<Interaction>, _now_ns: u64) -> Round {
        let mut alertas = Vec::new();
        let mut bloqueadas = Vec::new();
        let mut rechazadas = Vec::new();

        for i in &interacciones {
            self.stats.interactions += 1;
            let Some(a) = self.sensor.observe(i) else {
                continue;
            };
            self.stats.alerts += 1;

            if a.block && self.config.autonomous {
                match self.guard.refusal(a.peer) {
                    Some(motivo) => {
                        self.stats.refused += 1;
                        rechazadas.push((a.peer, motivo));
                    }
                    None => {
                        let razon = match a.kind {
                            AlertKind::LateralMovement => BlockReason::LateralMovement,
                            _ => BlockReason::Reconnaissance,
                        };
                        if self
                            .filter
                            .block(a.peer, razon, self.config.block_ttl)
                            .is_ok()
                        {
                            self.stats.blocked += 1;
                            bloqueadas.push(a.peer);
                        }
                    }
                }
            }
            alertas.push(a);
        }

        Round {
            interactions: interacciones,
            alerts: alertas,
            blocked: bloqueadas,
            refused: rechazadas,
        }
    }

    /// Mantenimiento: olvida origenes inactivos.
    pub fn maintain(&mut self, now_ns: u64) -> usize {
        self.sensor.prune(now_ns)
    }

    /// Filtro de red subyacente.
    pub fn filter(&self) -> &F {
        &self.filter
    }
}
