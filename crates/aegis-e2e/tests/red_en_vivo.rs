//! La telemetria de red del kernel lleva la direccion y el puerto DE VERDAD.
//!
//! Regresion de la FASE 0 del MP-15. La sonda `aegis_tp_sock_state` leia las
//! direcciones con `bpf_core_read(dst, 4, ctx->saddr)`: `saddr` es un array, y
//! dentro de `__builtin_preserve_access_index` no decae a puntero, asi que el
//! compilador CARGABA el contenido del array y lo usaba como direccion de origen.
//! La lectura fallaba en silencio y el campo quedaba a cero en TODOS los kernels:
//! ningun evento de red llevo nunca su IP, y la clasificacion del destino
//! (loopback, red privada) que se hace sobre ella tampoco funcionaba. Solo el
//! verificador de 5.15 (Ubuntu 22.04) lo rechazaba, y asi se descubrio.
//!
//! Esta prueba abre una conexion TCP real contra un puerto local y exige que el
//! evento del kernel traiga `127.0.0.1`, ese puerto y la marca de loopback.
//! Necesita privilegios para cargar las sondas; sin ellos se salta con aviso, y
//! en la matriz de kernels corre como root en cada distribucion.

#![cfg(target_os = "linux")]

use std::net::{TcpListener, TcpStream};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aegis_agent::bpf;
use aegis_agent::decode::decode;
use aegis_agent::TelemetryEvent;

/// Lo que interesa de cada evento de conexion: destino, puerto y marca de loopback.
type Conexion = ([u8; 16], u16, bool);

fn esperar_hasta(limite: Duration, cond: impl Fn() -> bool) -> bool {
    let inicio = Instant::now();
    while inicio.elapsed() < limite {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    cond()
}

#[test]
fn una_conexion_tcp_llega_con_su_direccion_y_su_puerto() {
    if let Err(e) = bpf::preflight() {
        eprintln!("SALTADA: el entorno no soporta la telemetria eBPF: {e}");
        return;
    }

    let parar = Arc::new(AtomicBool::new(false));
    let recibidos = Arc::new(AtomicU64::new(0));
    let conexiones: Arc<Mutex<Vec<Conexion>>> = Arc::default();

    let (p, r, c) = (
        Arc::clone(&parar),
        Arc::clone(&recibidos),
        Arc::clone(&conexiones),
    );
    let hilo = std::thread::spawn(move || {
        let cfg = bpf::SourceConfig {
            // La conexion la abre ESTE proceso, que por defecto es el «agente» y
            // se excluye de la telemetria. Aqui no hay agente que excluir.
            agent_pid: 0,
            poll_timeout: Duration::from_millis(50),
            ..Default::default()
        };
        bpf::run(&cfg, &p, move |registro| {
            r.fetch_add(1, Ordering::Relaxed);
            if let Ok(Some(TelemetryEvent::NetConnect {
                daddr,
                dport,
                loopback,
                ..
            })) = decode(registro)
            {
                if let Ok(mut v) = c.lock() {
                    v.push((daddr, dport, loopback));
                }
            }
        })
    });

    // La senal real de que las sondas estan vivas, no un tiempo supuesto. Si la
    // carga falla, el hilo termina y su error es el diagnostico: antes se
    // descartaba y la prueba solo decia que no habia eventos. El limite cubre
    // el verificador bajo emulacion completa (aarch64 en la matriz), decenas de
    // veces mas lento que en nativo.
    let vivas = esperar_hasta(Duration::from_secs(180), || {
        let _ = Command::new("/bin/true").status();
        recibidos.load(Ordering::Relaxed) > 0 || hilo.is_finished()
    });
    if hilo.is_finished() {
        match hilo.join() {
            Ok(Ok(_)) => panic!("el consumo de telemetria termino sin que nadie lo parase"),
            Ok(Err(e)) => panic!("las sondas no se cargaron: {e}"),
            Err(_) => panic!("el hilo de telemetria entro en panico"),
        }
    }
    assert!(vivas, "las sondas no entregaron ningun evento en 180 s");

    let escucha = TcpListener::bind("127.0.0.1:0").expect("escuchar en loopback");
    let puerto = escucha.local_addr().expect("puerto local").port();
    let _cliente = TcpStream::connect(("127.0.0.1", puerto)).expect("conectar");

    let visto = esperar_hasta(Duration::from_secs(5), || {
        conexiones
            .lock()
            .map(|v| {
                v.iter()
                    .any(|(d, p, lo)| *p == puerto && d[..4] == [127, 0, 0, 1] && *lo)
            })
            .unwrap_or(false)
    });
    let observadas = conexiones.lock().map(|v| v.clone()).unwrap_or_default();

    parar.store(true, Ordering::Relaxed);
    if let Ok(Err(e)) = hilo.join() {
        panic!("el consumo de telemetria fallo: {e}");
    }

    assert!(
        visto,
        "el evento de la conexion a 127.0.0.1:{puerto} tiene que llevar esa direccion, \
         ese puerto y la marca de loopback; observadas (daddr, dport, loopback): {:?}",
        observadas
            .iter()
            .map(|(d, p, lo)| (d[..4].to_vec(), *p, *lo))
            .collect::<Vec<_>>()
    );
}
