//! Pruebas del watchdog.
//!
//! La decision de reiniciar se prueba con la tabla de estados. El reinicio de
//! verdad se prueba con un proceso hijo REAL: se lanza, se le hace SIGKILL
//! —que no se puede bloquear— y se comprueba que el watchdog lo detecta muerto y
//! arranca uno nuevo. Es el escenario que la FASE 17 dejo pendiente.

use std::path::{Path, PathBuf};
use std::time::Duration;

use aegis_presupuesto::Presupuesto;
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
                ..TargetState::default()
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
                ..TargetState::default()
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
                ..TargetState::default()
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
                ..TargetState::default()
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
                ..TargetState::default()
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
        args: vec![
            "-c".into(),
            // El hijo cierra lo que hereda antes de dormirse. Sin esto, una
            // prueba que falle antes de `wd.stop()` deja un huerfano sujetando
            // el extremo de escritura de la tuberia de `cargo test`, y quien lea
            // esa salida no vera nunca el EOF: parece un cuelgue cuando en
            // realidad las pruebas ya terminaron.
            "exec 1>/dev/null 2>/dev/null; exec sleep 3600".into(),
        ],
        heartbeat: lab.path().join("hb"),
        shutdown_marker: lab.path().join("shutdown"),
        max_heartbeat_age_ms: 60_000,
        presupuesto: Presupuesto::del_host(),
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

// ---------------------------------------------------------------------------
// Desbordamiento de memoria
// ---------------------------------------------------------------------------
//
// Sin simulacion: proceso real, medida real de /proc, decision real. Lo que se
// ajusta es el presupuesto, no la medida — un techo de 256 KiB lo desborda
// cualquier proceso de verdad, incluido un `/bin/sh` dormido, y eso deja la
// prueba determinista sin tener que fabricar una fuga.

/// Presupuesto que ningun proceso real puede cumplir.
fn presupuesto_imposible() -> Presupuesto {
    Presupuesto {
        perfil: aegis_presupuesto::Perfil::Incrustado,
        memoria_host: 1024 * 1024,
        reposo: 16 * 1024,
        pico: 32 * 1024,
        techo: 64 * 1024,
    }
}

/// Espera a que el objetivo se haya asentado por ENCIMA de un techo dado.
///
/// Un proceso recien lanzado empieza por debajo: `/bin/sh` ocupa unos 24 KiB
/// antes de hacer `exec` y de que se le falten las paginas. Sin esta espera, las
/// primeras muestras caerian por debajo del techo y el contador de muestras
/// seguidas se reiniciaria —correctamente, es lo que tiene que hacer— dejando la
/// prueba sin su precondicion. El watchdog real muestrea una vez por segundo y
/// no llega a ver nunca ese instante.
///
/// Sondea la medida directamente y no via `supervise_once`, para no gastar
/// muestras del propio contador que la prueba va a ejercitar despues.
fn esperar_por_encima(wd: &mut Watchdog, techo: u64) {
    for _ in 0..400 {
        if let Some(u) = wd.pid().and_then(aegis_presupuesto::uso_de) {
            if u.anonima > techo {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("el objetivo nunca paso de {techo} bytes");
}

#[test]
fn el_watchdog_reinicia_a_un_agente_que_se_come_la_maquina() {
    // El fallo que el watchdog anterior no veia: el proceso existe y late, y
    // esta consumiendo memoria hasta llevarse el host por delante.
    let lab = Lab::nuevo("memoria");
    let mut target = agente_de_prueba(&lab);
    target.presupuesto = presupuesto_imposible();
    let mut wd = Watchdog::new(target);
    wd.spawn().unwrap();
    let pid_original = wd.pid().unwrap();
    esperar_vivo(&mut wd);
    esperar_por_encima(&mut wd, 64 * 1024);

    // Las primeras muestras NO reinician: una sola lectura sobre el techo puede
    // ser un pico legitimo, y reiniciar el EDR abre una ventana sin proteccion.
    for muestra in 1..aegis_presupuesto::MUESTRAS_PARA_REINICIO {
        let d = wd.supervise_once(now_ns()).unwrap();
        assert!(
            !d.is_restart(),
            "la muestra {muestra} no deberia reiniciar todavia, dio {d:?}"
        );
    }

    // La ultima confirma y reinicia.
    let d = wd.supervise_once(now_ns()).unwrap();
    match d {
        Decision::RestartMemoria { observado, techo } => {
            assert_eq!(techo, 64 * 1024);
            assert!(
                observado > techo,
                "observado {observado} no pasa de {techo}"
            );
        }
        otro => panic!("se esperaba RestartMemoria, hubo {otro:?}"),
    }
    assert_eq!(wd.restarts(), 1);
    assert_ne!(
        wd.pid().unwrap(),
        pid_original,
        "tiene que ser un proceso nuevo"
    );

    wd.stop();
}

#[test]
fn el_seguimiento_de_memoria_no_sobrevive_al_reinicio() {
    // Si el contador de muestras sobre el techo sobreviviera al reinicio, el
    // proceso nuevo naceria condenado y el watchdog lo mataria en el primer
    // ciclo, sin parar: una fuga acotada se convertiria en una maquina sin EDR.
    let lab = Lab::nuevo("memreset");
    let mut target = agente_de_prueba(&lab);
    target.presupuesto = presupuesto_imposible();
    let mut wd = Watchdog::new(target);
    wd.spawn().unwrap();
    esperar_vivo(&mut wd);
    esperar_por_encima(&mut wd, 64 * 1024);

    for _ in 0..aegis_presupuesto::MUESTRAS_PARA_REINICIO {
        wd.supervise_once(now_ns()).unwrap();
    }
    assert_eq!(wd.restarts(), 1);
    // Tras el reinicio el seguimiento arranca limpio.
    assert_eq!(wd.vigilante().muestras(), 0);
    assert_eq!(
        wd.vigilante().veredicto(),
        aegis_presupuesto::Veredicto::Seguir
    );

    // Y el ciclo siguiente vuelve a contar desde cero en vez de rematarlo.
    let d = wd.supervise_once(now_ns()).unwrap();
    assert!(
        !d.is_restart(),
        "el proceso nuevo no puede morir en su primer ciclo: {d:?}"
    );
    assert_eq!(wd.restarts(), 1);

    wd.stop();
}

#[test]
fn con_el_presupuesto_real_del_host_no_se_reinicia_nada() {
    // La contraparte: el mismo proceso, medido igual, contra el presupuesto que
    // de verdad se despliega. Sin esta, la prueba de arriba solo demostraria que
    // el watchdog sabe reiniciar, no que sepa distinguir.
    let lab = Lab::nuevo("memok");
    let mut wd = Watchdog::new(agente_de_prueba(&lab));
    wd.spawn().unwrap();
    esperar_vivo(&mut wd);

    for _ in 0..(aegis_presupuesto::MUESTRAS_PARA_REINICIO * 3) {
        let d = wd.supervise_once(now_ns()).unwrap();
        assert!(
            !d.is_restart(),
            "un /bin/sh dormido no desborda un EDR: {d:?}"
        );
    }
    assert_eq!(wd.restarts(), 0);
    assert_eq!(
        wd.vigilante().veredicto(),
        aegis_presupuesto::Veredicto::Seguir
    );
    // Y se ha medido de verdad: un maximo de cero seria una medida rota.
    assert!(
        wd.vigilante().maximo() > 0,
        "no se llego a medir el proceso"
    );

    wd.stop();
}
