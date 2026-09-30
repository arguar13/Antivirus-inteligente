//! Perder con prioridad: con el ring bajo presion, las escrituras y aperturas de
//! fichero ceden su sitio, y NINGUNA ejecucion se pierde.
//!
//! Regresion de la FASE 1 del MP-16. Con el ring lleno se perdia lo que llegara,
//! y en una tormenta de escrituras —justo lo que hace un cifrador— lo que llega
//! son escrituras: el `exec` del propio cifrador podia perderse detras de miles
//! de aperturas. Ahora las familias de prioridad baja ceden el ring por encima
//! del 75 % y el ultimo cuarto queda para ejecuciones, salidas y ptrace (ver
//! «PERDER CON PRIORIDAD» en `aegis_bpf_common.h`).
//!
//! La prueba DETIENE el consumo del ring (el callback se bloquea con el primer
//! evento), lo inunda con veinte mil aperturas de fichero, ejecuta doscientos
//! `true` en medio de la inundacion y solo entonces deja consumir. Exige que
//! lleguen los doscientos, que las aperturas hayan cedido, y que la perdida
//! quede atribuida a su familia y no a la de ejecucion.

#![cfg(target_os = "linux")]

use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aegis_agent::bpf;
use aegis_agent::capacidades::Familia;
use aegis_agent::decode::decode;
use aegis_agent::TelemetryEvent;

const EJECUCIONES: u64 = 200;
const APERTURAS: usize = 20_000;

#[test]
fn con_el_ring_saturado_ninguna_ejecucion_se_pierde() {
    if let Err(e) = bpf::preflight() {
        eprintln!("SALTADA: el entorno no soporta la telemetria eBPF: {e}");
        return;
    }
    let dir = std::env::temp_dir().join(format!("aegis-prioridad-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("directorio de la prueba");
    let verdadero = ["/bin/true", "/usr/bin/true"]
        .into_iter()
        .find(|p| std::path::Path::new(p).exists())
        .expect("/bin/true");

    let parar = Arc::new(AtomicBool::new(false));
    let bloquear = Arc::new(AtomicBool::new(true));
    let recibidos = Arc::new(AtomicU64::new(0));
    let execs = Arc::new(AtomicU64::new(0));
    let vivas = Arc::new(AtomicBool::new(false));
    let (p, bl, r, x, v) = (
        Arc::clone(&parar),
        Arc::clone(&bloquear),
        Arc::clone(&recibidos),
        Arc::clone(&execs),
        Arc::clone(&vivas),
    );
    let hilo = std::thread::spawn(move || {
        let cfg = bpf::SourceConfig {
            // Las aperturas las hace ESTE proceso: no hay agente que excluir.
            agent_pid: 0,
            poll_timeout: Duration::from_millis(50),
            ..Default::default()
        };
        bpf::run(&cfg, &p, move |registro| {
            // El primer evento dice que las sondas estan vivas, y bloquea el
            // consumo: el ring se llena detras.
            v.store(true, Ordering::Relaxed);
            while bl.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(5));
            }
            r.fetch_add(1, Ordering::Relaxed);
            if let Ok(Some(TelemetryEvent::Exec { image, .. })) = decode(registro) {
                if image.ends_with("/true") {
                    x.fetch_add(1, Ordering::Relaxed);
                }
            }
        })
    });

    // Espera la SENAL real de que las sondas estan vivas —el primer evento,
    // que se queda bloqueado en el callback—, no un tiempo supuesto. El limite
    // cubre el verificador bajo emulacion completa.
    let inicio = Instant::now();
    while !vivas.load(Ordering::Relaxed)
        && inicio.elapsed() < Duration::from_secs(180)
        && !hilo.is_finished()
    {
        let _ = Command::new(verdadero).status();
        std::thread::sleep(Duration::from_millis(100));
    }
    if hilo.is_finished() {
        match hilo.join() {
            Ok(Err(e)) => panic!("las sondas no se cargaron: {e}"),
            _ => panic!("el consumo de telemetria termino antes de empezar"),
        }
    }
    assert!(
        vivas.load(Ordering::Relaxed),
        "las sondas no entregaron ningun evento en 180 s"
    );

    // La inundacion de prioridad baja, con las ejecuciones en medio.
    for i in 0..APERTURAS {
        abrir_para_escribir(&dir.join(format!("f{}", i % 512)));
        if i == APERTURAS / 2 {
            for _ in 0..EJECUCIONES {
                let _ = Command::new(verdadero).status();
            }
        }
    }

    // Se deja consumir hasta que llegan las ejecuciones, con un plazo. No se
    // espera a que el ring «se quede quieto»: la prueba ve TODA la actividad de
    // la maquina, y en una con servicios nunca se queda quieto.
    bloquear.store(false, Ordering::Relaxed);
    let inicio = Instant::now();
    while execs.load(Ordering::Relaxed) < EJECUCIONES && inicio.elapsed() < Duration::from_secs(60)
    {
        std::thread::sleep(Duration::from_millis(100));
    }
    std::thread::sleep(Duration::from_millis(500));
    parar.store(true, Ordering::Relaxed);
    let stats = match hilo.join() {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => panic!("las sondas no se cargaron: {e}"),
        Err(_) => panic!("el hilo de telemetria entro en panico"),
    };
    let _ = std::fs::remove_dir_all(&dir);

    if !stats.plan.activos.iter().any(|a| a == "aegis_tp_openat") {
        eprintln!(
            "NO APLICA: la sonda de openat no esta activa en este kernel (declarado); \
             sin ella no se puede saturar el ring con prioridad baja"
        );
        return;
    }
    let perdidas = |f: Familia| {
        stats
            .perdidas_por_familia
            .iter()
            .find(|(g, _)| *g == f)
            .map_or(0, |(_, n)| *n)
    };
    eprintln!(
        "recibidos={} execs={} cedidos={} perdidos_llenos={} perdidas ejecucion={} ficheros={}",
        recibidos.load(Ordering::Relaxed),
        execs.load(Ordering::Relaxed),
        stats.cedidos,
        stats.dropped_full,
        perdidas(Familia::Ejecucion),
        perdidas(Familia::Ficheros)
    );
    assert!(
        stats.cedidos > 0,
        "con el ring bloqueado y veinte mil aperturas, la prioridad baja tenia que ceder"
    );
    assert_eq!(
        perdidas(Familia::Ejecucion),
        0,
        "se perdieron ejecuciones con el ring bajo presion"
    );
    assert!(perdidas(Familia::Ficheros) > 0);
    assert!(
        execs.load(Ordering::Relaxed) >= EJECUCIONES,
        "llegaron {} de {EJECUCIONES} ejecuciones",
        execs.load(Ordering::Relaxed)
    );
}

/// Abre para escritura con `openat` explicito y cierra. No se usa
/// `File::create`: la syscall la elige la libc (glibc usa `openat`, musl usa
/// `open`), y la prueba tiene que saber que via inunda para saber que sonda
/// necesita.
fn abrir_para_escribir(ruta: &std::path::Path) {
    let Ok(c) = std::ffi::CString::new(ruta.to_string_lossy().as_bytes()) else {
        return;
    };
    // SAFETY: syscall de apertura con una ruta valida terminada en NUL; el
    // descriptor se cierra enseguida.
    unsafe {
        let fd = libc::syscall(
            libc::SYS_openat,
            libc::AT_FDCWD,
            c.as_ptr(),
            (libc::O_WRONLY | libc::O_CREAT) as libc::c_long,
            0o600,
        );
        if fd >= 0 {
            libc::close(fd as libc::c_int);
        }
    }
}
