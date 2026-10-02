//! # aegis-agent
//!
//! Agente de deteccion de AegisCore (Ring 3).
//!
//! Recibe telemetria del kernel, la convierte en contexto y decide. La
//! separacion de modulos no es cosmetica: [`graph`], [`triage`] y [`decode`] no
//! tocan el sistema operativo y se prueban enteros en el host, mientras que
//! [`bpf`] concentra todo lo que necesita privilegios, BTF y un kernel real.
//!
//! Esa frontera es deliberada. La logica de correlacion es la mayor parte del
//! valor del producto y la que mas cobertura de pruebas necesita; si estuviera
//! entretejida con la carga de programas eBPF, solo se podria probar en una
//! maquina con root, y en la practica eso significa que no se prueba.

#![deny(missing_docs)]

pub mod capacidades;
pub mod decode;
pub mod edge_ml;
pub mod error;
pub mod graph;
pub mod motores;
pub mod plano;
pub mod scal;
pub mod triage;

#[cfg(all(target_os = "linux", feature = "bpf"))]
pub mod bpf;

pub use error::{GraphError, TelemetryError};
pub use graph::{ExecEvent, GraphConfig, ImageClass, ProcKey, ProcessGraph, TaintSet};
pub use motores::secuestro::{RansomAction, RansomStage, RansomStats};
pub use triage::{
    DiscardReason, Escalation, EscalationReason, TelemetryEvent, Triage, TriageConfig, Verdict,
};

use std::sync::atomic::{AtomicU64, Ordering};

/// Contadores del pipeline de telemetria.
///
/// Se publican para la consola de administracion. `escalated` frente a
/// `discarded` es la metrica que dice si el triaje esta bien calibrado: un
/// ratio de escalado alto significa que el motor de heuristica esta recibiendo
/// ruido, y uno de cero significa que probablemente no se esta viendo nada.
#[derive(Debug, Default)]
pub struct PipelineStats {
    /// Eventos recibidos del kernel.
    pub received: AtomicU64,
    /// Eventos descartados en el camino rapido.
    pub discarded: AtomicU64,
    /// Eventos que solo actualizaron el grafo.
    pub recorded: AtomicU64,
    /// Eventos enviados al motor de heuristica.
    pub escalated: AtomicU64,
    /// Registros que no se pudieron interpretar.
    pub malformed: AtomicU64,
    /// Tipos de evento desconocidos para esta version del agente.
    pub unknown_kind: AtomicU64,
}

impl PipelineStats {
    /// Instantanea legible de los contadores.
    pub fn snapshot(&self) -> [(&'static str, u64); 6] {
        [
            ("recibidos", self.received.load(Ordering::Relaxed)),
            ("descartados", self.discarded.load(Ordering::Relaxed)),
            ("registrados", self.recorded.load(Ordering::Relaxed)),
            ("escalados", self.escalated.load(Ordering::Relaxed)),
            ("malformados", self.malformed.load(Ordering::Relaxed)),
            ("desconocidos", self.unknown_kind.load(Ordering::Relaxed)),
        ]
    }
}

/// Pipeline completo: decodifica, actualiza el grafo y triaja.
///
/// Es el unico punto donde se juntan las tres piezas, y es deliberadamente
/// delgado: toda la logica esta en los modulos, de modo que este tipo se pueda
/// alimentar igual desde el ring buffer de BPF que desde una prueba.
#[derive(Debug)]
pub struct Pipeline {
    /// Grafo de linaje.
    pub graph: ProcessGraph,
    /// Motor de triaje.
    pub triage: Triage,
    /// Contadores.
    pub stats: PipelineStats,
}

impl Pipeline {
    /// Crea un pipeline con la configuracion indicada.
    pub fn new(graph_config: GraphConfig, triage_config: TriageConfig) -> Self {
        Self {
            graph: ProcessGraph::new(graph_config),
            triage: Triage::new(triage_config),
            stats: PipelineStats::default(),
        }
    }

    /// Procesa un registro crudo del ABI.
    ///
    /// Devuelve el escalado si el evento lo merece. Un registro ilegible
    /// incrementa el contador y devuelve `None` en vez de propagar el error:
    /// abortar el consumo por un registro malo dejaria de procesar todos los
    /// siguientes, que es peor que perder uno.
    pub fn ingest_raw(&self, bytes: &[u8]) -> Option<Escalation> {
        self.decodificar(bytes).and_then(|ev| self.ingest(ev))
    }

    /// Decodifica un registro crudo del ABI y lo cuenta, sin triarlo.
    ///
    /// Es la entrada del bucle del agente: el evento decodificado va al
    /// arbitro, que lo reparte a los motores (el triaje, entre ellos). Un
    /// registro ilegible o de un tipo desconocido se cuenta y se descarta.
    pub fn decodificar(&self, bytes: &[u8]) -> Option<TelemetryEvent> {
        self.stats.received.fetch_add(1, Ordering::Relaxed);
        match decode::decode(bytes) {
            Ok(Some(ev)) => Some(ev),
            Ok(None) => {
                self.stats.unknown_kind.fetch_add(1, Ordering::Relaxed);
                None
            }
            Err(_) => {
                self.stats.malformed.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// Procesa un evento ya decodificado.
    pub fn ingest(&self, ev: TelemetryEvent) -> Option<Escalation> {
        // El grafo se actualiza ANTES del triaje: el triaje consulta las marcas
        // del actor, y en un `exec` esas marcas solo existen despues de dar de
        // alta el nodo con la herencia de su padre.
        match &ev {
            TelemetryEvent::Exec {
                actor,
                pid,
                parent,
                image,
                cmdline,
                started_ns,
                ..
            } => {
                self.graph.on_exec(ExecEvent {
                    key: *actor,
                    pid: *pid,
                    parent: *parent,
                    creator: *parent,
                    image: image.clone(),
                    cmdline: cmdline.clone(),
                    started_ns: *started_ns,
                });
            }
            TelemetryEvent::Exit { actor, ts_ns } => {
                self.graph.on_exit(*actor, *ts_ns);
            }
            _ => {}
        }

        match self.triage.classify(&self.graph, &ev) {
            Verdict::Discard(_) => {
                self.stats.discarded.fetch_add(1, Ordering::Relaxed);
                None
            }
            Verdict::Record => {
                self.stats.recorded.fetch_add(1, Ordering::Relaxed);
                None
            }
            Verdict::Escalate(e) => {
                self.stats.escalated.fetch_add(1, Ordering::Relaxed);
                Some(*e)
            }
        }
    }

    /// Mantenimiento periodico: expira nodos muertos y sesiones de trazado.
    ///
    /// Se llama desde el bucle del colector entre lotes, nunca por evento.
    /// Devuelve `(nodos expirados, sesiones de trazado olvidadas)`.
    pub fn maintain(&self, now_ns: u64) -> (usize, usize) {
        (self.graph.reap(now_ns), self.triage.prune_sessions(now_ns))
    }
}

impl Default for Pipeline {
    fn default() -> Self {
        Self::new(GraphConfig::default(), TriageConfig::default())
    }
}
