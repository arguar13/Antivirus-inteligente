//! El triaje conductual del agente, como motor del contrato unico.
//!
//! Envuelve el [`Pipeline`] (grafo de linaje + triaje) que ya existia: el grafo
//! se actualiza con cada evento y el triaje decide si el evento merece atencion.
//! Lo que antes era un `println!` de «escalado» es ahora una señal firmada por el
//! plano conductual que llega al arbitro con su evidencia.

use std::sync::Arc;

use aegis_entidad::{Confianza, Juicio, Motor as Firma, Senal, Severidad};
use aegis_motor::{Camino, Dictamen, Ficha, Motor, Plazo, Presupuesto, Requisito};

use crate::motores::EventoAgente;
use crate::triage::{Escalation, EscalationReason};
use crate::Pipeline;

/// Bytes que retiene cada nodo del grafo, contando su ruta y su linea de
/// comandos compartidas. Es una cota, no una medida: sirve para comparar con el
/// techo declarado.
const BYTES_POR_NODO: usize = 512;
/// Bytes por sesion de trazado vigilada.
const BYTES_POR_SESION: usize = 96;

/// El triaje conductual.
pub struct MotorTriaje {
    pipeline: Arc<Pipeline>,
    techo: usize,
}

impl MotorTriaje {
    /// Sobre un pipeline compartido: el hilo de control lee sus contadores.
    pub fn nuevo(pipeline: Arc<Pipeline>, max_nodos: usize) -> MotorTriaje {
        // El techo es el del propio grafo lleno, mas un margen para las sesiones
        // de trazado: el grafo ya se poda solo al llegar a su maximo, asi que
        // pasar de aqui seria un error del grafo, no carga.
        let techo = max_nodos * BYTES_POR_NODO + 4096 * BYTES_POR_SESION;
        MotorTriaje { pipeline, techo }
    }
}

fn severidad(r: EscalationReason) -> Severidad {
    match r {
        EscalationReason::CredentialStore
        | EscalationReason::DynamicLoader
        | EscalationReason::SystemBinary
        | EscalationReason::CrossProcessMemory => Severidad::Alta,
        _ => Severidad::Media,
    }
}

fn motivo(r: EscalationReason) -> &'static str {
    match r {
        EscalationReason::CrossProcessMemory => "manipula la memoria de otro proceso",
        EscalationReason::CredentialStore => "escribe en las credenciales del sistema",
        EscalationReason::PersistenceMechanism => "escribe en un mecanismo de persistencia",
        EscalationReason::SystemBinary => "escribe sobre un binario del sistema",
        EscalationReason::DynamicLoader => "escribe en la precarga del cargador dinamico",
        EscalationReason::SuspiciousExecOrigin => {
            "ejecuta desde un directorio temporal con linaje sospechoso"
        }
        EscalationReason::LivingOffTheLand => "cadena de ejecucion de abuso de aplicacion",
        EscalationReason::TaintedEgress => "conecta hacia fuera desde un proceso contaminado",
        EscalationReason::BehaviorThreshold => "su puntuacion conductual paso el umbral",
    }
}

/// La señal que corresponde a un escalado del triaje.
///
/// El triaje ve la accion, no la intencion: dice `Sospechoso`, nunca
/// `Malicioso`. Llegar a malicioso exige que otro plano lo corrobore, que es
/// justo lo que hace el arbitro.
pub fn senal_de(e: &Escalation, ev: &EventoAgente) -> Senal {
    let confianza = Confianza::nueva(u8::try_from(e.score.min(90)).unwrap_or(90));
    Senal::nueva(
        Firma::Conductual,
        ev.entidad.clone(),
        Juicio::Sospechoso,
        severidad(e.reason),
        confianza,
        format!("triaje: {} (puntuacion {})", motivo(e.reason), e.score),
        ev.evento.ts_ns(),
    )
}

impl Motor<EventoAgente> for MotorTriaje {
    fn ficha(&self) -> Ficha {
        Ficha {
            nombre: "triaje",
            firma: Firma::Conductual,
            camino: Camino::Caliente,
            // Grafo y clasificacion son O(profundidad del linaje) por evento: en
            // las pruebas de carga, decenas de microsegundos. 500 us deja margen
            // para un planificador ocupado sin tapar un triaje que se degrade.
            presupuesto: Presupuesto::caliente(500, self.techo),
            requisitos: &[Requisito::TelemetriaKernel],
        }
    }

    fn evaluar(&mut self, ev: &EventoAgente, _plazo: &Plazo) -> Dictamen {
        match self.pipeline.ingest(ev.evento.clone()) {
            Some(e) => Dictamen::Senales(vec![senal_de(&e, ev)]),
            None => Dictamen::NoAplica,
        }
    }

    fn memoria(&self) -> usize {
        self.pipeline.graph.len() * BYTES_POR_NODO
            + self.pipeline.triage.tracked_ptrace_sessions() * BYTES_POR_SESION
    }

    fn mantener(&mut self, ahora_ns: u64) -> Vec<(aegis_entidad::Eid, aegis_motor::Dictamen)> {
        self.pipeline.maintain(ahora_ns);
        Vec::new()
    }
}
