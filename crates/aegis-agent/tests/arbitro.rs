//! Los motores REALES del agente detras del arbitro: el camino que recorre cada
//! evento del kernel en produccion, sin kernel.

use std::sync::Arc;

use aegis_agent::motores::conducta::MotorConducta;
use aegis_agent::motores::secuestro::MotorSecuestro;
use aegis_agent::motores::triaje::MotorTriaje;
use aegis_agent::motores::{EventoAgente, Identidad};
use aegis_agent::{GraphConfig, Pipeline, ProcKey, TelemetryEvent};
use aegis_entidad::entidad::proceso_por_clave;
use aegis_entidad::Resultado;
use aegis_motor::{Arbitro, ConfigArbitro, Host, Requisito};

const S: u64 = 1_000_000_000;

struct TodoVale;
impl Host for TodoVale {
    fn ofrece(&self, _: Requisito) -> Result<(), String> {
        Ok(())
    }
}

fn arbitro(id: &Identidad) -> Arbitro<EventoAgente> {
    let mut a = Arbitro::nuevo(ConfigArbitro::default());
    let p = Arc::new(Pipeline::default());
    a.registrar(
        Box::new(MotorTriaje::nuevo(p, GraphConfig::default().max_nodes)),
        &TodoVale,
    )
    .unwrap();
    a.registrar(Box::new(MotorConducta::nuevo(id.clone())), &TodoVale)
        .unwrap();
    a.registrar(Box::new(MotorSecuestro::nuevo(id.clone())), &TodoVale)
        .unwrap();
    a
}

fn exec(key: u64, image: &str, ts: u64) -> TelemetryEvent {
    TelemetryEvent::Exec {
        actor: ProcKey(key),
        pid: key as u32,
        parent: ProcKey(0),
        image: Arc::from(image),
        cmdline: Arc::from(image),
        started_ns: ts,
        ts_ns: ts,
    }
}

fn escritura(actor: u64, path: &str, ts: u64) -> TelemetryEvent {
    TelemetryEvent::FileWrite {
        actor: ProcKey(actor),
        pid: actor as u32,
        path: Arc::from(path),
        flags: 0o1101,
        ts_ns: ts,
    }
}

#[test]
fn escribir_en_la_precarga_del_cargador_llega_como_veredicto_con_su_evidencia() {
    let id = Identidad::fija("prueba");
    let mut a = arbitro(&id);
    assert!(a
        .procesar(&EventoAgente::nuevo(exec(7, "/usr/bin/tee", 0), &id))
        .is_none());
    let v = a
        .procesar(&EventoAgente::nuevo(
            escritura(7, "/etc/ld.so.preload", S),
            &id,
        ))
        .expect("escribir en ld.so.preload tiene que producir un veredicto");
    assert!(matches!(
        v.resultado,
        Resultado::Sospechoso | Resultado::Malicioso
    ));
    // El veredicto es sobre el proceso que escribio, con la identidad del agente.
    assert_eq!(v.entidad, proceso_por_clave(&id.maquina, id.boot, 7));
    assert!(
        v.senales
            .iter()
            .any(|s| s.porque.contains("cargador dinamico")),
        "la evidencia del triaje tiene que viajar en el veredicto: {:?}",
        v.senales
    );
    assert!(!v.porque.is_empty());
}

#[test]
fn el_ruido_no_produce_veredictos_y_cada_motor_mide_cada_evento() {
    let id = Identidad::fija("prueba");
    let mut a = arbitro(&id);
    let n = 300u64;
    for i in 0..n {
        let ev = EventoAgente::nuevo(exec(100 + i, "/usr/bin/true", i * 1000), &id);
        assert!(a.procesar(&ev).is_none());
    }
    for m in a.estado() {
        assert_eq!(m.evaluaciones, n, "{}", m.nombre);
        assert_eq!(m.latencia.cuenta(), n, "{}", m.nombre);
        assert_eq!(m.suspensiones, 0, "{}", m.nombre);
    }
    assert_eq!(a.por_evento().cuenta(), n);
    assert_eq!(a.veredictos(), 0);
}
