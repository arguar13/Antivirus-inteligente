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
             USO: aegis-agent [--stats-interval SEGUNDOS]\n\
             \n\
             Requiere CAP_BPF y CAP_PERFMON (o root) para cargar las sondas,\n\
             y un kernel con CONFIG_DEBUG_INFO_BTF=y."
        );
        return std::process::ExitCode::SUCCESS;
    }

    let intervalo = args
        .windows(2)
        .find(|w| w[0] == "--stats-interval")
        .and_then(|w| w[1].parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(Duration::from_secs(10));

    ejecutar(intervalo)
}

#[cfg(all(target_os = "linux", feature = "bpf"))]
fn ejecutar(intervalo: Duration) -> std::process::ExitCode {
    use aegis_agent::bpf;

    instalar_manejadores();

    let pipeline = Arc::new(Pipeline::new(
        GraphConfig::default(),
        TriageConfig::default(),
    ));
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
fn ejecutar(_intervalo: Duration) -> std::process::ExitCode {
    let _ = (&PARAR, Arc::new(0u8), Instant::now());
    let _ = Pipeline::new(GraphConfig::default(), TriageConfig::default());
    eprintln!(
        "aegis-agent se compilo sin la caracteristica 'bpf' o para un sistema que no es Linux.\n\
         La logica de correlacion esta disponible como biblioteca, pero no hay origen de\n\
         telemetria: recompila en Linux con --features bpf."
    );
    std::process::ExitCode::FAILURE
}
