//! Recogida de un incidente cuyo binario ya no existe, para la Red Team.
//!
//! Reproduce una tecnica antiforense real: el proceso se borra a si mismo del
//! disco nada mas arrancar, de modo que cuando alguien vaya a investigarlo no
//! quede nada que analizar. La recogida tiene que capturar el incidente **igual**
//! y dejar constancia explicita de que la evidencia se destruyo.
//!
//! Sale con 0 si el incidente se capturo y el informe STIX sigue siendo valido.

use std::path::{Path, PathBuf};
use std::time::Duration;

use aegis_forensics::artifacts::Trigger;
use aegis_forensics::collect::{CollectConfig, Collector};
use aegis_forensics::stix;
use aegis_scal::linux::process::ProcFsProcesses;

/// El binario del que se hace la copia que hara de implante.
///
/// Un INTERPRETE DE ORDENES y no `sleep`: la copia se ejecuta bajo otro nombre
/// (`.implante`), y no todo binario lo admite. Ubuntu 26.04 trae uutils coreutils
/// (paquete `rust-coreutils`), que es un unico binario MULTI-LLAMADA y decide que
/// orden ejecutar mirando su `argv[0]`: una copia llamada `.implante` responde
/// "unknown program" y muere al instante, con lo que no habria proceso vivo al
/// que borrarle el binario y el escenario no se montaria.
///
/// Un interprete arranca con el nombre que se le ponga —distinguirse por
/// `argv[0]` es lo que hace (`sh` frente a `bash`)—, que es justo la propiedad
/// que hace falta aqui.
fn fuente_del_implante() -> Option<&'static Path> {
    for c in ["/bin/dash", "/bin/bash", "/bin/sh", "/usr/bin/bash"] {
        let p = Path::new(c);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

fn main() -> std::process::ExitCode {
    let Some(fuente) = fuente_del_implante() else {
        eprintln!("no hay un interprete con el que montar el escenario");
        return std::process::ExitCode::FAILURE;
    };

    let lab: PathBuf =
        std::env::temp_dir().join(format!("aegis-antiforense-{}", std::process::id()));
    if std::fs::create_dir_all(&lab).is_err() {
        eprintln!("no se pudo preparar el laboratorio");
        return std::process::ExitCode::FAILURE;
    }
    let carga = lab.join(".implante");
    if std::fs::copy(fuente, &carga).is_err() {
        eprintln!("no se pudo preparar la carga");
        return std::process::ExitCode::FAILURE;
    }
    // Permisos de ejecucion; sin ellos no arranca.
    if let Ok(m) = std::fs::metadata(&carga) {
        let mut p = m.permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut p, 0o755);
        let _ = std::fs::set_permissions(&carga, p);
    }

    // Bloqueado en `read` sobre una tuberia que este proceso conserva abierta: se
    // queda vivo el tiempo que haga falta y muere solo al acabar, sin dejar un
    // huerfano durmiendo ni un hijo aparte al que habria que perseguir.
    let mut hijo = match std::process::Command::new(&carga)
        .args(["-c", "read x"])
        .stdin(std::process::Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("no se pudo lanzar la carga: {e}");
            let _ = std::fs::remove_dir_all(&lab);
            return std::process::ExitCode::FAILURE;
        }
    };
    // Que haya arrancado no basta: un binario multi-llamada acepta el `spawn` y
    // se muere al mirarse el `argv[0]`. Se comprueba aqui, con su causa, en vez
    // de dejar que el escenario falle luego por un motivo que no lo parece.
    std::thread::sleep(Duration::from_millis(50));
    if !matches!(hijo.try_wait(), Ok(None)) {
        eprintln!(
            "la copia de {} llamada «.implante» murio al instante; \
             ¿es un binario multi-llamada?",
            fuente.display()
        );
        let _ = std::fs::remove_dir_all(&lab);
        return std::process::ExitCode::FAILURE;
    }
    // La tecnica: el proceso sigue vivo, su binario ya no esta.
    std::thread::sleep(Duration::from_millis(150));
    let _ = std::fs::remove_file(&carga);
    println!("BORRADO {}", carga.display());

    let c = Collector::new(
        ProcFsProcesses::new(),
        CollectConfig {
            inspect_memory: true,
            ..CollectConfig::default()
        },
    );
    let a = c.collect(
        hijo.id(),
        Trigger {
            source: "red-team".into(),
            reason: "binario borrado en caliente".into(),
            score: Some(90),
            techniques: vec!["T1070".into()],
        },
    );

    let bundle = stix::to_bundle(&a);
    let capturado = a.processes.iter().any(|p| p.pid == hijo.id());
    let hueco = a
        .gaps
        .iter()
        .any(|g| g.contains("la evidencia se destruyo"));

    println!("CAPTURADO {capturado}");
    println!("HUECO_REGISTRADO {hueco}");
    println!("BUNDLE_BYTES {}", bundle.len());
    println!("PROCESOS {}", a.processes.len());
    println!("INCIDENTE {}", a.id);

    let _ = hijo.kill();
    let _ = hijo.wait();
    let _ = std::fs::remove_dir_all(&lab);

    if capturado && hueco && bundle.contains("\"type\":\"bundle\"") {
        std::process::ExitCode::SUCCESS
    } else {
        eprintln!("el incidente no se capturo con la constancia esperada");
        std::process::ExitCode::FAILURE
    }
}
