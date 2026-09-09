//! Pruebas del watchdog.
//!
//! La decision de reiniciar se prueba con la tabla de estados. El reinicio de
//! verdad se prueba con un proceso hijo REAL: se lanza, se le hace SIGKILL
//! —que no se puede bloquear— y se comprueba que el watchdog lo detecta muerto y
//! arranca uno nuevo. Es el escenario que la FASE 17 dejo pendiente.

use std::path::{Path, PathBuf};
use std::time::Duration;

use aegis_watchdog::heartbeat::Heartbeat;
use aegis_watchdog::supervisor::{decide, Decision, TargetState};
use aegis_watchdog::watchdog::{now_ns, Target, Watchdog};

struct Lab(PathBuf);
impl Lab {
    fn nuevo(n: &str) -> Lab {
        let p = std::env::temp_dir().join(format!("aegis-wd-{n}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Lab(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for Lab {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ---------------------------------------------------------------------------
// Tabla de decision
// ---------------------------------------------------------------------------

#[test]
fn la_tabla_de_decision_cubre_los_casos() {
    let max = 15_000u64;

    assert_eq!(
        decide(
            TargetState {
                alive: true,
                heartbeat_age_ms: Some(500),
                shutdown_requested: false,
            },
            max
        ),
        Decision::Healthy
    );
    assert_eq!(
        decide(
            TargetState {
                alive: false,
                heartbeat_age_ms: Some(500),
                shutdown_requested: false,
            },
            max
        ),
        Decision::RestartDead
    );
    assert_eq!(
        decide(
            TargetState {
                alive: true,
                heartbeat_age_ms: Some(30_000),
                shutdown_requested: false,
            },
            max
        ),
        Decision::RestartHung
    );
    assert_eq!(
        decide(
            TargetState {
                alive: true,
                heartbeat_age_ms: None,
                shutdown_requested: false,
            },
            max
        ),
        Decision::Starting
    );
    // La parada autorizada manda sobre todo, incluso si murio.
    assert_eq!(
        decide(
            TargetState {
                alive: false,
                heartbeat_age_ms: None,
                shutdown_requested: true,
            },
            max
        ),
        Decision::Stop
    );
}

// ---------------------------------------------------------------------------
// Latido
// ---------------------------------------------------------------------------

#[test]
fn el_latido_va_y_vuelve() {
    let lab = Lab::nuevo("beat");
    let hb = Heartbeat::new(lab.path().join("hb"));
    assert_eq!(hb.read(), None);
    hb.beat(123_456_789).unwrap();
    assert_eq!(hb.read(), Some(123_456_789));
    hb.beat(999).unwrap();
    assert_eq!(hb.read(), Some(999));
}

// ---------------------------------------------------------------------------
// Reinicio real ante SIGKILL
// ---------------------------------------------------------------------------

/// El "agente" de prueba: `/bin/sh` que se queda dormido mucho tiempo. Es lo que
/// el watchdog supervisa. No escribe latido porque un shell no puede producir un
/// instante del reloj monotono; la deteccion de estas pruebas es por presencia
/// del proceso, y el latido rancio ya se prueba en la tabla de decision.
fn agente_de_prueba(lab: &Lab) -> Target {
    Target {
        program: PathBuf::from("/bin/sh"),
        args: vec!["-c".into(), "sleep 3600".into()],
        heartbeat: lab.path().join("hb"),
        shutdown_marker: lab.path().join("shutdown"),
        max_heartbeat_age_ms: 60_000,
    }
}

/// Espera hasta que el watchdog reporte el objetivo vivo (proceso presente).
fn esperar_vivo(wd: &mut Watchdog) {
    for _ in 0..200 {
        if wd.observe(now_ns()).alive {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("el objetivo no llego a estar vivo");
}

fn proceso_vivo(pid: i32) -> bool {
    // kill(pid, 0) no envia senal: solo comprueba si el proceso existe.
    unsafe { libc::kill(pid, 0) == 0 }
}

#[test]
fn el_watchdog_reinicia_al_agente_tras_un_sigkill() {
    let lab = Lab::nuevo("sigkill");
    let mut wd = Watchdog::new(agente_de_prueba(&lab));
    wd.spawn().unwrap();
    let pid_original = wd.pid().unwrap();
    esperar_vivo(&mut wd);

    // El atacante mata el agente con SIGKILL, que no se puede bloquear.
    unsafe {
        libc::kill(pid_original as i32, libc::SIGKILL);
    }

    // El watchdog, en sus ciclos de supervision, tiene que detectarlo muerto
    // (recolectando el zombi con try_wait) y reiniciarlo. Se sondea el propio
    // watchdog y no kill(pid,0): un proceso recien muerto es un zombi hasta que
    // su padre lo recolecta, y kill(pid,0) sobre un zombi sigue devolviendo 0.
    let mut reinicio = false;
    for _ in 0..200 {
        let d = wd.supervise_once(now_ns()).unwrap();
        if d == Decision::RestartDead {
            reinicio = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(reinicio, "el watchdog no reinicio al agente muerto");
    assert_eq!(wd.restarts(), 1);

    let pid_nuevo = wd.pid().unwrap();
    assert_ne!(pid_nuevo, pid_original, "tiene que ser un proceso nuevo");
    assert!(
        proceso_vivo(pid_nuevo as i32),
        "el proceso reiniciado esta vivo"
    );

    wd.stop();
}

#[test]
fn una_parada_autorizada_no_se_reinicia() {
    let lab = Lab::nuevo("authstop");
    let target = agente_de_prueba(&lab);
    let marker = target.shutdown_marker.clone();
    let mut wd = Watchdog::new(target);
    wd.spawn().unwrap();
    let pid = wd.pid().unwrap();
    esperar_vivo(&mut wd);

    // Se pide una parada autorizada (marca) y se mata el agente.
    std::fs::write(&marker, b"stop").unwrap();
    unsafe {
        libc::kill(pid as i32, libc::SIGKILL);
    }

    // Con la marca puesta, el watchdog decide Stop en todos sus ciclos y jamas
    // reinicia, aunque el proceso este muerto.
    for _ in 0..10 {
        let d = wd.supervise_once(now_ns()).unwrap();
        assert_eq!(d, Decision::Stop, "con marca de apagado siempre es Stop");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(wd.restarts(), 0, "una parada autorizada no puede reiniciar");
    wd.stop();
}

// ---------------------------------------------------------------------------
// Reinicio ante cuelgue (latido rancio)
// ---------------------------------------------------------------------------

#[test]
fn el_watchdog_reinicia_al_agente_colgado() {
    let lab = Lab::nuevo("hung");
    // El objetivo esta VIVO (sleep) pero su latido es antiquisimo: colgado.
    let hb = Heartbeat::new(lab.path().join("hb"));
    hb.beat(1).unwrap(); // un instante monotono minusculo => muy viejo

    let mut target = agente_de_prueba(&lab);
    target.max_heartbeat_age_ms = 100; // margen minusculo para que sea "rancio"
    let mut wd = Watchdog::new(target);
    wd.spawn().unwrap();
    esperar_vivo(&mut wd);

    // El proceso sigue vivo pero el latido no avanza: el watchdog lo reinicia.
    let d = wd.supervise_once(now_ns()).unwrap();
    assert_eq!(
        d,
        Decision::RestartHung,
        "un latido rancio tiene que reiniciar"
    );
    assert_eq!(wd.restarts(), 1);
    wd.stop();
}
