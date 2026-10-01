//! Toda via de apertura de ficheros llega a la telemetria.
//!
//! Regresion de la FASE 1 del MP-16. Solo se enganchaba `openat` —lo que usa
//! glibc—, y musl abre con `open`: un binario estatico con musl, o un programa
//! que hace la syscall a mano, escribia ficheros sin que la familia de ficheros
//! lo viera. Lo destapo la matriz de kernels, donde las pruebas son estaticas con
//! musl. Esta prueba abre para escritura por CADA via y exige que la ruta llegue
//! del kernel.

#![cfg(target_os = "linux")]

use std::collections::BTreeSet;
use std::ffi::CString;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aegis_agent::bpf;
use aegis_agent::decode::decode;
use aegis_agent::TelemetryEvent;
use aegis_prueba::{omitir, Requisito};

const O_WRONLY_CREAT: libc::c_long = (libc::O_WRONLY | libc::O_CREAT) as libc::c_long;

/// Abre `ruta` para escritura con la syscall indicada, a mano (sin pasar por la
/// libc, que elegiria ella la via).
fn abrir(via: &str, ruta: &CString) -> bool {
    let p = ruta.as_ptr();
    // SAFETY: syscalls de apertura con una ruta valida terminada en NUL; el
    // descriptor devuelto se cierra enseguida.
    let fd = unsafe {
        match via {
            #[cfg(target_arch = "x86_64")]
            "open" => libc::syscall(libc::SYS_open, p, O_WRONLY_CREAT, 0o600),
            #[cfg(target_arch = "x86_64")]
            "creat" => libc::syscall(libc::SYS_creat, p, 0o600),
            "openat" => libc::syscall(libc::SYS_openat, libc::AT_FDCWD, p, O_WRONLY_CREAT, 0o600),
            "openat2" => {
                // struct open_how { u64 flags; u64 mode; u64 resolve; }
                let como: [u64; 3] = [O_WRONLY_CREAT as u64, 0o600, 0];
                libc::syscall(
                    libc::SYS_openat2,
                    libc::AT_FDCWD,
                    p,
                    como.as_ptr(),
                    std::mem::size_of_val(&como),
                )
            }
            _ => -1,
        }
    };
    if fd >= 0 {
        // SAFETY: descriptor propio recien abierto.
        unsafe { libc::close(fd as libc::c_int) };
        true
    } else {
        false
    }
}

#[test]
fn cada_via_de_apertura_llega_con_su_ruta() {
    if let Err(e) = bpf::preflight() {
        omitir(
            &format!("el entorno no soporta la telemetria eBPF: {e}"),
            Requisito::Ebpf,
        );
        return;
    }
    let dir = std::env::temp_dir().join(format!("aegis-ficheros-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("directorio de la prueba");

    let parar = Arc::new(AtomicBool::new(false));
    let vivas = Arc::new(AtomicBool::new(false));
    let rutas: Arc<Mutex<BTreeSet<String>>> = Arc::default();
    let (p, v, r) = (Arc::clone(&parar), Arc::clone(&vivas), Arc::clone(&rutas));
    let hilo = std::thread::spawn(move || {
        let cfg = bpf::SourceConfig {
            // Las aperturas las hace ESTE proceso: no hay agente que excluir.
            agent_pid: 0,
            poll_timeout: Duration::from_millis(50),
            ..Default::default()
        };
        bpf::run(&cfg, &p, move |registro| {
            v.store(true, Ordering::Relaxed);
            if let Ok(Some(TelemetryEvent::FileWrite { path, .. })) = decode(registro) {
                if let Ok(mut g) = r.lock() {
                    g.insert(path.to_string());
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
        let _ = Command::new("/bin/true").status();
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        vivas.load(Ordering::Relaxed),
        "las sondas no entregaron ningun evento"
    );

    let mut vias = vec!["openat", "openat2"];
    if cfg!(target_arch = "x86_64") {
        // En aarch64 `open` y `creat` no existen como syscall.
        vias.extend(["open", "creat"]);
    }
    let mut esperadas = Vec::new();
    for via in &vias {
        let ruta = dir.join(format!("por-{via}"));
        let c = CString::new(ruta.to_string_lossy().as_bytes()).expect("ruta sin NUL");
        assert!(abrir(via, &c), "{via} no pudo abrir {}", ruta.display());
        esperadas.push((via.to_string(), ruta.to_string_lossy().into_owned()));
    }

    let inicio = Instant::now();
    let faltan = || {
        let g = rutas.lock().map(|g| g.clone()).unwrap_or_default();
        esperadas
            .iter()
            .filter(|(_, r)| !g.contains(r))
            .map(|(v, _)| v.clone())
            .collect::<Vec<_>>()
    };
    while !faltan().is_empty() && inicio.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(100));
    }
    parar.store(true, Ordering::Relaxed);
    let stats = match hilo.join() {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => panic!("el consumo de telemetria fallo: {e}"),
        Err(_) => panic!("el hilo de telemetria entro en panico"),
    };
    let _ = std::fs::remove_dir_all(&dir);

    // Se juzga POR VIA, segun el plan: una via cuya sonda no se pudo enganchar
    // en este kernel (SELinux la deniega en Rocky, `open` no existe en
    // aarch64) esta DECLARADA por el agente como degradada; lo que no puede
    // pasar es que una via con su sonda activa no llegue.
    let activa = |via: &str| {
        stats
            .plan
            .activos
            .iter()
            .any(|a| a == &format!("aegis_tp_{via}"))
    };
    for via in &vias {
        if !activa(via) {
            eprintln!("NO APLICA: la sonda de {via} no esta activa en este kernel (declarado)");
        }
    }
    let faltan: Vec<String> = faltan().into_iter().filter(|v| activa(v)).collect();
    assert!(
        faltan.is_empty(),
        "escrituras que la telemetria no vio, por via: {faltan:?}"
    );
}
