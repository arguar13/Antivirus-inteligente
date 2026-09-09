//! El motor: ingiere eventos, mantiene el grafo y decide.

use std::collections::HashMap;

use aegis_scal::process::{ProcessEvent, ProcessInfo, ProcessKey};

use crate::chain::{ChainPattern, PATRONES};
use crate::dag::{BehaviorGraph, EdgeKind, GraphError, GraphLimits};
use crate::score::{score, Action, RiskScore};
use crate::technique::Technique;

/// Configuracion del motor.
#[derive(Debug, Clone, Copy)]
pub struct EngineConfig {
    /// Limites del grafo.
    pub limits: GraphLimits,
    /// Si esta a falso, el motor nunca devuelve [`Action::Isolate`]: reporta la
    /// puntuacion pero deja la decision a un humano.
    ///
    /// Es lo que permite desplegar el motor en modo observacion durante la
    /// calibracion, que es como se despliega en produccion la primera semana.
    pub autonomous: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            limits: GraphLimits::default(),
            autonomous: true,
        }
    }
}

/// Valoracion de un proceso en un instante.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    /// Proceso valorado.
    pub key: ProcessKey,
    /// Puntuacion desglosada.
    pub score: RiskScore,
    /// Accion recomendada.
    pub action: Action,
}

/// Contadores del motor.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EngineStats {
    /// Procesos dados de alta.
    pub nodos_altas: u64,
    /// Procesos dados de baja.
    pub nodos_bajas: u64,
    /// Observaciones de tecnica anotadas.
    pub observaciones: u64,
    /// Aristas causales rechazadas por cerrar un ciclo.
    ///
    /// Un valor distinto de cero no es un error del motor: significa que dos
    /// procesos se inyectaron mutuamente, que es una tecnica real de evasion.
    pub ciclos_rechazados: u64,
    /// Alertas emitidas.
    pub alertas: u64,
    /// Aislamientos decididos.
    pub aislamientos: u64,
}

/// Motor conductual: grafo de procesos, tecnicas de ATT&CK y decision.
#[derive(Debug)]
pub struct BehavioralGraphEngine {
    graph: BehaviorGraph,
    config: EngineConfig,
    patrones: Vec<ChainPattern>,
    /// Accion mas fuerte ya emitida por cada proceso.
    ///
    /// No es un simple conjunto de "ya decididos". Tiene que guardar el NIVEL,
    /// porque un proceso que alerto a 60 y despues llega a 92 tiene que producir
    /// una decision nueva: si se dedujera solo por presencia, la escalada de
    /// alerta a aislamiento se perderia y el proceso seguiria corriendo con la
    /// alerta antigua como unica constancia. Y sin nivel guardado, cada evento
    /// posterior repetiria la misma orden decenas de veces por segundo.
    decididos: HashMap<ProcessKey, Action>,
    stats: EngineStats,
}

impl BehavioralGraphEngine {
    /// Crea el motor con los patrones por defecto.
    pub fn new(config: EngineConfig) -> BehavioralGraphEngine {
        BehavioralGraphEngine {
            graph: BehaviorGraph::new(config.limits),
            config,
            patrones: PATRONES.to_vec(),
            decididos: HashMap::new(),
            stats: EngineStats::default(),
        }
    }

    /// Crea el motor con un juego de patrones concreto.
    pub fn with_patterns(
        config: EngineConfig,
        patrones: Vec<ChainPattern>,
    ) -> BehavioralGraphEngine {
        let mut m = BehavioralGraphEngine::new(config);
        m.patrones = patrones;
        m
    }

    /// Grafo, para inspeccion y para las pruebas.
    pub fn graph(&self) -> &BehaviorGraph {
        &self.graph
    }

    /// Contadores.
    pub fn stats(&self) -> EngineStats {
        self.stats
    }

    /// Procesa un evento de ciclo de vida de la capa de abstraccion.
    ///
    /// Devuelve una valoracion si el proceso pasa a merecer accion.
    pub fn on_process(&mut self, ev: &ProcessEvent, now_ns: u64) -> Option<Assessment> {
        match ev {
            ProcessEvent::Started(info) => {
                self.graph.insert(info, now_ns);
                self.stats.nodos_altas += 1;
                // Un proceso recien nacido ya puede merecer accion: hereda el
                // riesgo de quien lo lanzo, y la cadena puede cerrarse justo
                // con su llegada.
                self.evaluate(info.key)
            }
            ProcessEvent::Exited { key, .. } => {
                self.graph.mark_dead(*key, now_ns);
                self.stats.nodos_bajas += 1;
                None
            }
        }
    }

    /// Da de alta un proceso directamente, sin pasar por un evento.
    pub fn track(&mut self, info: &ProcessInfo, now_ns: u64) -> Option<Assessment> {
        self.on_process(&ProcessEvent::Started(Box::new(info.clone())), now_ns)
    }

    /// Anota una tecnica observada sobre un proceso.
    pub fn observe(
        &mut self,
        key: ProcessKey,
        t: Technique,
    ) -> Result<Option<Assessment>, GraphError> {
        self.graph.observe(key, t)?;
        self.stats.observaciones += 1;
        Ok(self.evaluate(key))
    }

    /// Registra una relacion causal distinta del linaje.
    ///
    /// La arista que cerraria un ciclo se rechaza y se cuenta: dos procesos que
    /// se inyectan mutuamente son una tecnica real, y colgar el recorrido de
    /// ancestros por creerse el grafo un arbol seria una denegacion de servicio
    /// contra el propio motor.
    pub fn link(
        &mut self,
        from: ProcessKey,
        to: ProcessKey,
        kind: EdgeKind,
        ts_ns: u64,
    ) -> Result<Option<Assessment>, GraphError> {
        match self.graph.link(from, to, kind, ts_ns) {
            Ok(()) => Ok(self.evaluate(to)),
            Err(GraphError::WouldCycle { .. }) => {
                self.stats.ciclos_rechazados += 1;
                Ok(self.evaluate(to))
            }
            Err(e) => Err(e),
        }
    }

    /// Puntua un proceso sin cambiar el estado del motor.
    pub fn assess(&self, key: ProcessKey) -> Option<Assessment> {
        self.graph.node(key)?;
        let s = score(&self.graph, key, &self.patrones);
        let accion = self.decide(&s);
        Some(Assessment {
            key,
            score: s,
            action: accion,
        })
    }

    /// Mantenimiento: expira nodos y libera las decisiones de los que ya no
    /// estan. Devuelve cuantos nodos se eliminaron.
    pub fn maintain(&mut self, now_ns: u64) -> usize {
        let fuera = self.graph.reap(now_ns);
        if fuera > 0 {
            let g = &self.graph;
            self.decididos.retain(|k, _| g.node(*k).is_some());
        }
        fuera
    }

    fn decide(&self, s: &RiskScore) -> Action {
        let accion = s.action();
        // En modo observacion la puntuacion no cambia: lo que cambia es que el
        // motor no ordena cortar. Rebajar la puntuacion escondería el hecho de
        // que la maquina tiene un proceso que MERECE aislamiento.
        if accion == Action::Isolate && !self.config.autonomous {
            Action::Alert
        } else {
            accion
        }
    }

    /// Valora un nodo y devuelve la valoracion SOLO si hay que actuar y no se
    /// habia actuado ya sobre ese proceso.
    fn evaluate(&mut self, key: ProcessKey) -> Option<Assessment> {
        let a = self.assess(key)?;
        match a.action {
            Action::Observe => None,
            Action::Alert | Action::Isolate => {
                // Solo se emite si ESCALA respecto a lo ya emitido. `Action`
                // esta ordenada: Observe < Alert < Isolate.
                if self
                    .decididos
                    .get(&key)
                    .is_some_and(|previa| *previa >= a.action)
                {
                    return None;
                }
                self.decididos.insert(key, a.action);
                if a.action == Action::Isolate {
                    self.stats.aislamientos += 1;
                } else {
                    self.stats.alertas += 1;
                }
                Some(a)
            }
        }
    }
}

impl Default for BehavioralGraphEngine {
    fn default() -> Self {
        BehavioralGraphEngine::new(EngineConfig::default())
    }
}
