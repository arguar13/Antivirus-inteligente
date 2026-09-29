//! Binario del agente de AegisCore.
//!
//! Engancha las sondas de kernel, consume la telemetria y publica los eventos
//! que el triaje escala. El motor de heuristica que consumira esa cola es el
//! siguiente componente; hasta entonces los escalados se imprimen, que es lo
//! que permite validar la calibracion del triaje contra carga real.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aegis_agent::{GraphConfig, Pipeline, TriageConfig};

/// Bandera de parada. La toca el manejador de senales, que solo puede usar
/// operaciones seguras en ese contexto: un store atomico lo es, imprimir o
/// reservar memoria no.
static PARAR: AtomicBool = AtomicBool::new(false);

#[cfg(all(target_os = "linux", feature = "bpf"))]
extern "C" fn manejar_senal(_sig: libc::c_int) {
    PARAR.store(true, Ordering::Relaxed);
}

#[cfg(all(target_os = "linux", feature = "bpf"))]
fn instalar_manejadores() {
    // SAFETY: se instala un manejador que solo hace un store atomico
    // `Relaxed`, que es seguro en contexto de senal. No reserva memoria, no
    // toma locks y no llama a funciones no reentrantes.
    unsafe {
        // El doble cast pasando por *const () es obligatorio: convertir un
        // item de funcion directamente a entero es un lint denegado, porque el
        // tamano del item de funcion no es el de un puntero en toda plataforma.
        let manejador = manejar_senal as *const () as libc::sighandler_t;
        libc::signal(libc::SIGINT, manejador);
        libc::signal(libc::SIGTERM, manejador);
    }
}

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        eprintln!(
            "aegis-agent - agente de deteccion de AegisCore\n\
             \n\
             USO: aegis-agent [--stats-interval SEGUNDOS] [--harden] \n\
             \x20    [--control-socket RUTA]\n\
             \x20    aegis-agent --capacidades [--maquina]\n\
             \n\
             --capacidades  informa de lo que ofrece este kernel (BTF, tracefs,\n\
             \x20              ringbuf, BPF LSM, cgroup, SELinux/AppArmor, lockdown)\n\
             \x20              y de lo que se degrada; sale con 3 si no habria\n\
             \x20              telemetria de kernel. Con --maquina, lineas AEGIS-CAP/DEG.\n\
             \n\
             Requiere CAP_BPF y CAP_PERFMON (o root) para cargar las sondas,\n\
             y un kernel con CONFIG_DEBUG_INFO_BTF=y."
        );
        return std::process::ExitCode::SUCCESS;
    }

    if args.iter().any(|a| a == "--capacidades") {
        return informar_capacidades(args.iter().any(|a| a == "--maquina"));
    }

    let intervalo = args
        .windows(2)
        .find(|w| w[0] == "--stats-interval")
        .and_then(|w| w[1].parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(10));

    blindar(args.iter().any(|a| a == "--harden"));

    let control_socket = args
        .windows(2)
        .find(|w| w[0] == "--control-socket")
        .map(|w| w[1].clone());

    ejecutar(intervalo, control_socket)
}

/// Capacidades del kernel, con el sondeo directo por `bpf()` si se compilo con
/// la caracteristica `bpf`.
fn capacidades() -> aegis_agent::capacidades::Capacidades {
    #[cfg(all(target_os = "linux", feature = "bpf"))]
    {
        aegis_agent::bpf::capacidades()
    }
    #[cfg(not(all(target_os = "linux", feature = "bpf")))]
    {
        use aegis_agent::capacidades::{detectar_en, SondeoBpf};
        detectar_en(
            std::path::Path::new("/"),
            SondeoBpf::no_realizado("agente compilado sin la caracteristica bpf"),
        )
    }
}

/// `--capacidades`: el informe, y un codigo de salida que un script puede usar
/// sin leerlo (3 = no habria telemetria de kernel).
fn informar_capacidades(maquina: bool) -> std::process::ExitCode {
    use aegis_agent::capacidades::{informe, plan_degradacion, salida_maquina};
    let caps = capacidades();
    let plan = plan_degradacion(&caps);
    if maquina {
        print!("{}", salida_maquina(&caps, &plan));
    } else {
        print!("{}", informe(&caps, &plan));
    }
    if plan.iter().any(|d| d.bloquea_telemetria) {
        std::process::ExitCode::from(3)
    } else {
        std::process::ExitCode::SUCCESS
    }
}

/// Fuente de estado para el canal de control, respaldada por el pipeline.
///
/// Solo lee contadores atomicos, asi que compartir el pipeline con el hilo de
/// control no introduce contencion ni bloqueos con el bucle de eventos.
#[cfg(all(target_os = "linux", feature = "bpf"))]
struct EstadoPipeline {
    pipeline: Arc<Pipeline>,
}

#[cfg(all(target_os = "linux", feature = "bpf"))]
impl aegis_ctl::StatusSource for EstadoPipeline {
    fn events_received(&self) -> u64 {
        self.pipeline
            .stats
            .received
            .load(std::sync::atomic::Ordering::Relaxed)
    }
    fn events_escalated(&self) -> u64 {
        self.pipeline
            .stats
            .escalated
            .load(std::sync::atomic::Ordering::Relaxed)
    }
    fn state(&self) -> String {
        "running".to_string()
    }
}

/// Blindaje del agente (FASE 13).
///
/// Descifra en memoria la tabla de cadenas criticas y comprueba si hay un
/// depurador adjunto. La respuesta AGRESIVA (`PTRACE_TRACEME` + cierre ante un
/// depurador) es opcional y se activa con `--harden`, no por defecto, por una
/// razon operativa concreta: un proceso que reclama el trazador convierte la
/// senal de parada del propio sistema (SIGTERM) en una parada de trazado en vez
/// de una terminacion, con lo que un supervisor que lo detenga con `kill` se
/// quedaria esperando. En produccion, donde el agente lo lanza el watchdog y no
/// un supervisor generico, se pasa `--harden`.
fn blindar(agresivo: bool) {
    match aegis_harden::unseal_builtin() {
        Ok(vault) => {
            // Se informa del NUMERO, nunca del contenido: un secreto que aparece
            // en un log deja de serlo.
            eprintln!(
                "aegis-agent: blindaje activo, {} cadenas criticas descifradas en memoria",
                vault.len()
            );
        }
        Err(e) => {
            // Que el binario no pueda descifrar sus propias cadenas indica una
            // tabla corrupta o manipulada: es un fallo de integridad, no un
            // aviso. Se sigue arrancando porque la deteccion no depende de esas
            // cadenas, pero se deja constancia ruidosa.
            eprintln!("aegis-agent: AVISO de integridad - no se descifro el blindaje: {e}");
        }
    }

    // Comprobacion pasiva SIEMPRE: no reclama el trazador ni cierra el proceso,
    // asi que es segura bajo cualquier supervisor.
    let chequeo = aegis_harden::detect();
    if chequeo.detected {
        eprintln!(
            "aegis-agent: AVISO - depurador detectado ({:?}). La integridad de la              deteccion no se puede garantizar bajo depuracion.",
            chequeo.proc_check
        );
    }

    if agresivo {
        // Respuesta de produccion: reclama el trazador (bloquea adjuntar un
        // depurador despues) y cierra si ya habia uno.
        aegis_harden::enforce(aegis_harden::Policy::Terminate);
    }
}

#[cfg(all(target_os = "linux", feature = "bpf"))]
fn ejecutar(intervalo: Duration, control_socket: Option<String>) -> std::process::ExitCode {
    use aegis_agent::bpf;

    instalar_manejadores();

    // Lo que este kernel ofrece y lo que se degrada, SIEMPRE al arrancar: una
    // degradacion que solo se ve pidiendola es una degradacion silenciosa.
    {
        let caps = capacidades();
        let plan = aegis_agent::capacidades::plan_degradacion(&caps);
        for linea in aegis_agent::capacidades::informe(&caps, &plan).lines() {
            eprintln!("aegis-agent: {linea}");
        }
    }

    let pipeline = Arc::new(Pipeline::new(
        GraphConfig::default(),
        TriageConfig::default(),
    ));

    // Canal de control opcional: si se pidio un socket, se levanta el servidor
    // en un hilo aparte. Lo caro del control (YARA) se carga en diferido, asi
    // que el hilo en reposo no anade memoria al presupuesto.
    let control_stop = Arc::new(AtomicBool::new(false));
    let control_hilo = control_socket.as_ref().and_then(|ruta| {
        match aegis_ctl::ControlServer::bind(ruta) {
            Ok(server) => {
                eprintln!("aegis-agent: canal de control en {ruta}");
                let handler = aegis_ctl::AgentControl::lazy(
                    std::path::PathBuf::from("/var/lib/aegiscore/quarantine"),
                    /*isolate_dry_run=*/ false,
                    Arc::new(EstadoPipeline {
                        pipeline: Arc::clone(&pipeline),
                    }),
                );
                let parar = Arc::clone(&control_stop);
                Some(std::thread::spawn(move || {
                    server.serve(&handler, &parar);
                }))
            }
            Err(e) => {
                eprintln!("aegis-agent: no se pudo abrir el canal de control: {e}");
                None
            }
        }
    });

    let config = bpf::SourceConfig::default();

    eprintln!(
        "aegis-agent: enganchando sondas (pid propio {}, excluido de la telemetria)",
        config.agent_pid
    );

    let p = Arc::clone(&pipeline);
    let mut ultimo_informe = Instant::now();
    let arranque = Instant::now();

    let resultado = bpf::run(&config, &PARAR, move |registro| {
        if let Some(esc) = p.ingest_raw(registro) {
            println!(
                "[ESCALADO] {:?} score={} evento={:?}",
                esc.reason, esc.score, esc.event
            );
        }

        // Mantenimiento y estadisticas entre lotes, nunca por evento.
        if ultimo_informe.elapsed() >= intervalo {
            ultimo_informe = Instant::now();
            let ahora_ns = arranque.elapsed().as_nanos() as u64;
            let (expirados, sesiones_olvidadas) = p.maintain(ahora_ns);
            let s = p.stats.snapshot();
            eprintln!(
                "aegis-agent: {} | nodos={} expirados={} ptrace_sesiones={} olvidadas={}",
                s.iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(" "),
                p.graph.len(),
                expirados,
                p.triage.tracked_ptrace_sessions(),
                sesiones_olvidadas
            );
        }
    });

    // El hilo de control se detiene cuando el bucle de eventos termina.
    control_stop.store(true, Ordering::Relaxed);
    if let Some(h) = control_hilo {
        let _ = h.join();
    }

    match resultado {
        Ok(stats) => {
            eprintln!(
                "aegis-agent: parada limpia. kernel: emitidos={} perdidos={} filtrados={} truncados={}",
                stats.emitted, stats.dropped_full, stats.filtered, stats.truncated
            );
            if stats.dropped_full > 0 {
                eprintln!(
                    "aegis-agent: AVISO - {} eventos se perdieron por ring lleno. \
                     Eso es un punto ciego de deteccion, no una metrica de rendimiento.",
                    stats.dropped_full
                );
            }
            let s = pipeline.stats.snapshot();
            eprintln!(
                "aegis-agent: pipeline: {}",
                s.iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            );
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("aegis-agent: error fatal: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(not(all(target_os = "linux", feature = "bpf")))]
fn ejecutar(_intervalo: Duration, _control_socket: Option<String>) -> std::process::ExitCode {
    let _ = (&PARAR, Arc::new(0u8), Instant::now());
    let _ = Pipeline::new(GraphConfig::default(), TriageConfig::default());
    eprintln!(
        "aegis-agent se compilo sin la caracteristica 'bpf' o para un sistema que no es Linux.\n\
         La logica de correlacion esta disponible como biblioteca, pero no hay origen de\n\
         telemetria: recompila en Linux con --features bpf."
    );
    std::process::ExitCode::FAILURE
}
