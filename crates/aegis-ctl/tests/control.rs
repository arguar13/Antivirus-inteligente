//! Pruebas del canal de control, de extremo a extremo sobre un socket Unix real.
//!
//! No se prueba el protocolo contra si mismo con estructuras en memoria: se
//! levanta un servidor en un socket de verdad, se conecta un cliente de verdad,
//! y se comprueba lo que llega al otro lado. Un canal de control que solo se
//! probara en memoria no demostraria que el marco, los permisos y el cierre de
//! conexion funcionan.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use aegis_ctl::handler::{AgentControl, StatusSource};
use aegis_ctl::protocol::{IsolateMode, Request, Response};
use aegis_ctl::server::{ControlClient, ControlHandler, ControlServer};
use aegis_scan::YaraEngine;

struct Lab(PathBuf);
impl Lab {
    fn nuevo(n: &str) -> Lab {
        let p = std::env::temp_dir().join(format!("aegis-ctl-{n}-{}", std::process::id()));
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

/// Fuente de estado de prueba con valores fijos.
struct EstadoFijo;
impl StatusSource for EstadoFijo {
    fn events_received(&self) -> u64 {
        12345
    }
    fn events_escalated(&self) -> u64 {
        42
    }
    fn state(&self) -> String {
        "running".into()
    }
}

/// Levanta el servidor real en un hilo y devuelve la ruta del socket y la señal
/// de parada, para ejercitarlo con el cliente real.
fn servidor_en_hilo<H: ControlHandler + 'static>(
    lab: &Lab,
    handler: H,
) -> (PathBuf, Arc<AtomicBool>, std::thread::JoinHandle<()>) {
    let socket = lab.path().join("agent.sock");
    let server = ControlServer::bind(&socket).unwrap();
    let ruta = server.path().to_path_buf();
    let parar = Arc::new(AtomicBool::new(false));
    let parar_hilo = parar.clone();
    let hilo = std::thread::spawn(move || {
        server.serve(&handler, &parar_hilo);
    });
    // Espera activa breve a que el socket exista.
    for _ in 0..100 {
        if ruta.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    (ruta, parar, hilo)
}

fn agente(lab: &Lab, quarantine_dir: PathBuf) -> AgentControl<EstadoFijo> {
    let yara = Arc::new(YaraEngine::with_base_rules().unwrap());
    let _ = lab;
    AgentControl::new(
        yara,
        quarantine_dir,
        /*dry_run=*/ true,
        Arc::new(EstadoFijo),
    )
}

fn eicar() -> String {
    format!(
        "{}{}",
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}", "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    )
}

// ---------------------------------------------------------------------------
// Serializacion del protocolo
// ---------------------------------------------------------------------------

#[test]
fn las_peticiones_van_y_vuelven_por_texto() {
    for req in [
        Request::Status,
        Request::Scan {
            path: "/tmp/x".into(),
        },
        Request::Isolate {
            mode: IsolateMode::Total,
        },
        Request::QuarantineList,
    ] {
        let linea = req.encode();
        assert_eq!(Request::parse(&linea).unwrap(), req);
    }
}

#[test]
fn una_peticion_malformada_se_rechaza_con_su_motivo() {
    assert!(Request::parse("scan").is_err(), "scan sin ruta");
    assert!(Request::parse("isolate\tmarciano").is_err());
    assert!(Request::parse("bailar").is_err());
    assert!(Request::parse("quarantine\tborrar").is_err());
}

// ---------------------------------------------------------------------------
// Extremo a extremo sobre el socket
// ---------------------------------------------------------------------------

#[test]
fn status_devuelve_el_estado_real_del_agente() {
    let lab = Lab::nuevo("status");
    let q = lab.path().join("quarantine");
    let (ruta, parar, hilo) = servidor_en_hilo(&lab, agente(&lab, q));

    let resp = ControlClient::request(&ruta, &Request::Status).unwrap();
    match resp {
        Response::Status(s) => {
            assert_eq!(s.state, "running");
            assert_eq!(s.events_received, 12345);
            assert_eq!(s.events_escalated, 42);
            assert!(s.rss_kb > 0, "el agente reporta memoria residente real");
        }
        otro => panic!("se esperaba Status, llego {otro:?}"),
    }

    parar.store(true, Ordering::Relaxed);
    hilo.join().unwrap();
}

#[test]
fn scan_detecta_el_eicar_bajo_demanda() {
    let lab = Lab::nuevo("scan");
    let muestra = lab.path().join("muestra.bin");
    std::fs::write(&muestra, eicar()).unwrap();
    let q = lab.path().join("quarantine");
    let (ruta, parar, hilo) = servidor_en_hilo(&lab, agente(&lab, q));

    let req = Request::Scan {
        path: muestra.to_str().unwrap().to_string(),
    };
    let resp = ControlClient::request(&ruta, &req).unwrap();
    match resp {
        Response::Scan(s) => {
            assert!(s.detected, "el EICAR tiene que detectarse");
            assert!(!s.rules.is_empty(), "y reportar la regla que disparo");
        }
        otro => panic!("se esperaba Scan, llego {otro:?}"),
    }

    // Un fichero limpio no dispara.
    let limpio = lab.path().join("limpio.txt");
    std::fs::write(&limpio, "esto es un documento inocuo\n").unwrap();
    let resp = ControlClient::request(
        &ruta,
        &Request::Scan {
            path: limpio.to_str().unwrap().to_string(),
        },
    )
    .unwrap();
    assert!(matches!(resp, Response::Scan(s) if !s.detected));

    parar.store(true, Ordering::Relaxed);
    hilo.join().unwrap();
}

#[test]
fn scan_rechaza_rutas_relativas() {
    let lab = Lab::nuevo("relativa");
    let q = lab.path().join("quarantine");
    let (ruta, parar, hilo) = servidor_en_hilo(&lab, agente(&lab, q));

    let resp = ControlClient::request(
        &ruta,
        &Request::Scan {
            path: "relativa/mala".into(),
        },
    )
    .unwrap();
    assert!(matches!(resp, Response::Error(_)));

    parar.store(true, Ordering::Relaxed);
    hilo.join().unwrap();
}

#[test]
fn isolate_en_dry_run_genera_reglas_sin_aplicarlas() {
    let lab = Lab::nuevo("isolate");
    let q = lab.path().join("quarantine");
    let (ruta, parar, hilo) = servidor_en_hilo(&lab, agente(&lab, q));

    let resp = ControlClient::request(
        &ruta,
        &Request::Isolate {
            mode: IsolateMode::Total,
        },
    )
    .unwrap();
    match resp {
        Response::Isolated(i) => {
            assert_eq!(i.mode, "total");
            assert!(!i.applied, "en dry-run no se aplica");
            assert!(i.rule_lines > 0, "pero si se genera el conjunto de reglas");
        }
        otro => panic!("se esperaba Isolated, llego {otro:?}"),
    }

    parar.store(true, Ordering::Relaxed);
    hilo.join().unwrap();
}

#[test]
fn quarantine_list_devuelve_vacio_cuando_no_hay_nada() {
    let lab = Lab::nuevo("qlist");
    let q = lab.path().join("quarantine");
    let (ruta, parar, hilo) = servidor_en_hilo(&lab, agente(&lab, q));

    let resp = ControlClient::request(&ruta, &Request::QuarantineList).unwrap();
    match resp {
        Response::Quarantine(ids) => assert!(ids.is_empty()),
        otro => panic!("se esperaba Quarantine, llego {otro:?}"),
    }

    parar.store(true, Ordering::Relaxed);
    hilo.join().unwrap();
}

// ---------------------------------------------------------------------------
// Permisos del socket
// ---------------------------------------------------------------------------

#[test]
fn el_socket_se_crea_con_permisos_0600() {
    use std::os::unix::fs::PermissionsExt;
    let lab = Lab::nuevo("perms");
    let socket = lab.path().join("agent.sock");
    let server = ControlServer::bind(&socket).unwrap();
    let modo = std::fs::metadata(server.path())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        modo, 0o600,
        "el socket de control tiene que ser 0600: es una via para escanear y \
         aislar la red, no puede quedar abierta a cualquier usuario"
    );
}

#[test]
fn el_socket_se_retira_al_cerrar_el_servidor() {
    let lab = Lab::nuevo("cleanup");
    let socket = lab.path().join("agent.sock");
    {
        let server = ControlServer::bind(&socket).unwrap();
        assert!(server.path().exists());
    }
    assert!(
        !socket.exists(),
        "el socket huerfano no debe sobrevivir al servidor"
    );
}

/// El servidor atiende peticiones sucesivas, no solo una.
#[test]
fn el_servidor_atiende_varias_peticiones_seguidas() {
    let lab = Lab::nuevo("varias");
    let q = lab.path().join("quarantine");
    let (ruta, parar, hilo) = servidor_en_hilo(&lab, agente(&lab, q));

    for _ in 0..10 {
        let resp = ControlClient::request(&ruta, &Request::Status).unwrap();
        assert!(matches!(resp, Response::Status(_)));
    }

    parar.store(true, Ordering::Relaxed);
    hilo.join().unwrap();
}
