//! Una ejecucion llega del kernel con la ruta y los argumentos DE VERDAD.
//!
//! Regresion de la FASE 1 del MP-16. Las sondas de syscalls declaraban su
//! contexto con la estructura de `raw_syscalls` en vez de la de su tracepoint;
//! en RHEL 9, donde `trace_entry` es mas larga, CO-RE reubicaba los argumentos
//! ocho bytes mas alla y la ruta de `execve` salia del puntero a `argv`: basura.
//! Nada lo veia, porque ninguna prueba miraba el CONTENIDO de un evento de
//! ejecucion. Esta lo mira en cada kernel de la matriz.

#![cfg(target_os = "linux")]

use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aegis_agent::bpf;
use aegis_agent::decode::decode;
use aegis_agent::TelemetryEvent;

const MARCA: &str = "aegis-marca-de-ejecucion";

#[test]
fn una_ejecucion_llega_con_su_ruta_y_sus_argumentos() {
    if let Err(e) = bpf::preflight() {
        eprintln!("SALTADA: el entorno no soporta la telemetria eBPF: {e}");
        return;
    }
    let verdadero = ["/bin/true", "/usr/bin/true"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .expect("/bin/true");

    let parar = Arc::new(AtomicBool::new(false));
    let vivas = Arc::new(AtomicBool::new(false));
    let vistas: Arc<Mutex<Vec<(String, String)>>> = Arc::default();
    let (p, v, x) = (Arc::clone(&parar), Arc::clone(&vivas), Arc::clone(&vistas));
    let hilo = std::thread::spawn(move || {
        let cfg = bpf::SourceConfig {
            agent_pid: 0,
            poll_timeout: Duration::from_millis(50),
            ..Default::default()
        };
        bpf::run(&cfg, &p, move |registro| {
            v.store(true, Ordering::Relaxed);
            if let Ok(Some(TelemetryEvent::Exec { image, cmdline, .. })) = decode(registro) {
                if let Ok(mut g) = x.lock() {
                    g.push((image.to_string(), cmdline.to_string()));
                }
            }
        })
    });

    // La señal real de que las sondas estan vivas, no un tiempo supuesto.
    let inicio = Instant::now();
    while !vivas.load(Ordering::Relaxed)
        && inicio.elapsed() < Duration::from_secs(180)
        && !hilo.is_finished()
    {
        let _ = Command::new(verdadero).status();
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        vivas.load(Ordering::Relaxed),
        "las sondas no entregaron ningun evento"
    );

    let _ = Command::new(verdadero).arg(MARCA).status();
    let buscada = |g: &[(String, String)]| {
        g.iter()
            .any(|(img, cmd)| img == verdadero && cmd.contains(MARCA))
    };
    let inicio = Instant::now();
    while inicio.elapsed() < Duration::from_secs(10)
        && !vistas.lock().map(|g| buscada(&g)).unwrap_or(false)
    {
        std::thread::sleep(Duration::from_millis(100));
    }
    parar.store(true, Ordering::Relaxed);
    if let Ok(Err(e)) = hilo.join() {
        panic!("el consumo de telemetria fallo: {e}");
    }
    let g = vistas.lock().map(|g| g.clone()).unwrap_or_default();
    assert!(
        buscada(&g),
        "la ejecucion de {verdadero} {MARCA} no llego con su ruta y sus argumentos; \
         ultimas vistas: {:?}",
        g.iter().rev().take(5).collect::<Vec<_>>()
    );
}
