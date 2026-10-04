//! `aegis-watchdog` — supervisor de alta disponibilidad del agente.
//!
//! Minimalista a proposito: su unica mision es que el agente siga en marcha, y
//! cuanto menos haga y menos memoria ocupe, menos superficie tiene el que quiera
//! tumbarlo a el.

use std::path::PathBuf;
use std::time::Duration;

use aegis_watchdog::watchdog::{now_ns, Target, Watchdog};

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // El techo de memoria del servicio para ESTE host, como drop-in de systemd.
    // Lo escribe el paquete al instalar: el numero sale de aegis-presupuesto,
    // el mismo codigo con el que este watchdog vigila, y nunca de una plantilla
    // (el despliegue anterior fijaba 64 MiB a mano, por debajo del minimo que
    // calcula el propio presupuesto; FASE 3 del MP-16).
    if args.first().map(String::as_str) == Some("--unidad") {
        if args.len() != 1 {
            eprintln!("--unidad no admite mas argumentos");
            return std::process::ExitCode::from(2);
        }
        print!(
            "{}",
            aegis_presupuesto::dropin(&aegis_presupuesto::efectivo())
        );
        return std::process::ExitCode::SUCCESS;
    }

    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        eprintln!(
            "aegis-watchdog - supervisor de alta disponibilidad\n\
             \n\
             USO: aegis-watchdog --program RUTA [--arg A]... \\\n\
             \x20                  [--heartbeat RUTA] [--marker RUTA] [--max-age-ms N]\n\
             \x20      aegis-watchdog --unidad   (drop-in de memoria de este host)\n\
             \n\
             Lanza el programa y lo reinicia si muere o se cuelga, salvo que\n\
             exista la marca de apagado autorizado."
        );
        return std::process::ExitCode::SUCCESS;
    }

    let mut program = None;
    let mut prog_args = Vec::new();
    let mut heartbeat = PathBuf::from("/run/aegiscore/agent.heartbeat");
    let mut marker = PathBuf::from("/run/aegiscore/agent.shutdown");
    let mut max_age_ms = 15_000u64;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--program" => {
                program = args.get(i + 1).map(PathBuf::from);
                i += 2;
            }
            "--arg" => {
                if let Some(a) = args.get(i + 1) {
                    prog_args.push(a.clone());
                }
                i += 2;
            }
            "--heartbeat" => {
                if let Some(a) = args.get(i + 1) {
                    heartbeat = PathBuf::from(a);
                }
                i += 2;
            }
            "--marker" => {
                if let Some(a) = args.get(i + 1) {
                    marker = PathBuf::from(a);
                }
                i += 2;
            }
            "--max-age-ms" => {
                if let Some(a) = args.get(i + 1).and_then(|v| v.parse().ok()) {
                    max_age_ms = a;
                }
                i += 2;
            }
            otro => {
                eprintln!("argumento desconocido: {otro}");
                return std::process::ExitCode::from(2);
            }
        }
    }

    let Some(program) = program else {
        eprintln!("falta --program");
        return std::process::ExitCode::from(2);
    };

    // El presupuesto sale del host y de AEGIS_PERFIL, no de un argumento: que el
    // que lanza el watchdog pueda aflojarle el techo por linea de ordenes seria
    // dejar la ultima defensa a merced de quien edite un script de arranque.
    let presupuesto = aegis_presupuesto::efectivo();
    eprintln!(
        "aegis-watchdog: {}",
        aegis_presupuesto::resumen(&presupuesto).trim_end()
    );

    // Con la unidad del paquete (Delegate=yes), bajarse a la hoja
    // `supervision` del subarbol delegado ANTES de lanzar al agente: el agente
    // la hereda, y el cgroup del servicio queda sin procesos propios para poder
    // repartir controladores al cgroup del trabajador confinado.
    if let Some(aviso) = bajar_a_la_hoja() {
        eprintln!("aegis-watchdog: {aviso}");
    }

    let target = Target {
        program,
        args: prog_args,
        heartbeat,
        shutdown_marker: marker,
        max_heartbeat_age_ms: max_age_ms,
        presupuesto,
    };
    let mut wd = Watchdog::new(target);
    if let Err(e) = wd.spawn() {
        eprintln!("aegis-watchdog: no se pudo lanzar el objetivo: {e}");
        return std::process::ExitCode::FAILURE;
    }
    eprintln!("aegis-watchdog: supervisando pid {:?}", wd.pid());

    loop {
        std::thread::sleep(Duration::from_millis(1000));
        match wd.supervise_once(now_ns()) {
            Ok(aegis_watchdog::Decision::Stop) => {
                eprintln!("aegis-watchdog: parada autorizada, termino");
                wd.stop();
                return std::process::ExitCode::SUCCESS;
            }
            Ok(d) if d.is_restart() => {
                eprintln!(
                    "aegis-watchdog: {d:?} -> reiniciado (pid {:?}, reinicios {})",
                    wd.pid(),
                    wd.restarts()
                );
            }
            Ok(_) => {}
            Err(e) => eprintln!("aegis-watchdog: error supervisando: {e}"),
        }
    }
}

/// Mueve este proceso a `<servicio>/supervision` si la unidad le delega su
/// cgroup (`AEGIS_CGROUP_DELEGADO`). Devuelve lo que haya que avisar; `None` si
/// no hay delegacion o si ya esta abajo.
fn bajar_a_la_hoja() -> Option<String> {
    std::env::var_os("AEGIS_CGROUP_DELEGADO")?;
    if !std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").is_file() {
        return Some("sin cgroup v2 unificado: el trabajador no colgara del servicio".into());
    }
    let propio = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let ruta = propio
        .lines()
        .find_map(|l| l.strip_prefix("0::"))?
        .trim()
        .to_string();
    if ruta.ends_with("/supervision") {
        return None;
    }
    let hoja = PathBuf::from("/sys/fs/cgroup")
        .join(ruta.trim_start_matches('/'))
        .join("supervision");
    if let Err(e) = std::fs::create_dir(&hoja) {
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            return Some(format!("no se pudo crear {}: {e}", hoja.display()));
        }
    }
    match std::fs::write(hoja.join("cgroup.procs"), std::process::id().to_string()) {
        Ok(()) => None,
        Err(e) => Some(format!("no se pudo bajar a {}: {e}", hoja.display())),
    }
}
