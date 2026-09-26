//! Desempaquetado de un binario empaquetado, para la simulacion de Red Team.
//!
//! Compila un empaquetador de prueba REAL —codigo cifrado en disco, que se
//! descifra en memoria al ejecutarse—, lo desempaqueta bajo control y comprueba
//! con el motor YARA que la firma escondida en el fichero aparece en el volcado.
//! Todo real: ejecucion, ptrace, deteccion de OEP, volcado y escaneo.
//!
//! Sale 0 si la firma NO estaba en el disco pero SI en el codigo desempaquetado.

use std::path::PathBuf;

fn main() -> std::process::ExitCode {
    if !aegis_unpacker::soportado() {
        eprintln!("OMITIDO: sin seccomp no se puede confinar el desempaquetado");
        return std::process::ExitCode::from(2);
    }

    let fuente = PathBuf::from(raiz_crate()).join("tests/fixtures/packer_stub.c");
    let bin = std::env::temp_dir().join(format!("aegis-rt-packer-{}", std::process::id()));
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".into());
    let compilar = std::process::Command::new(&cc)
        .args(["-O0", "-no-pie", "-o"])
        .arg(&bin)
        .arg(&fuente)
        .output();
    match compilar {
        Ok(o) if o.status.success() => {}
        _ => {
            eprintln!("OMITIDO: no se pudo compilar el empaquetador de prueba");
            return std::process::ExitCode::from(2);
        }
    }

    let regla = r#"rule payload { strings: $s = "AEGIS_UNPACKED_OK_7F3A" condition: $s }"#;
    let motor = match aegis_scan::yara::YaraEngine::from_sources(&[regla]) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("no se pudo compilar la regla: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    // En disco: la firma no esta.
    let bytes = std::fs::read(&bin).unwrap_or_default();
    let en_disco = motor
        .scan_bytes(&bytes)
        .map(|d| !d.is_empty())
        .unwrap_or(false);

    // Desempaquetar.
    let cfg = aegis_unpacker::TraceConfig::default();
    let resultado = aegis_unpacker::desempaquetar(&bin, &[], &cfg);
    let _ = std::fs::remove_file(&bin);

    let u = match resultado {
        Ok(u) => u,
        Err(e) => {
            eprintln!("BRECHA: el desempaquetado fallo: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let en_memoria = motor
        .scan_bytes(&u.dump.codigo)
        .map(|d| d.iter().any(|x| x.rule == "payload"))
        .unwrap_or(false);

    println!(
        "firma en disco: {} | region desempaquetada: {:#x}..{:#x} ({} bytes) | firma en memoria: {}",
        en_disco,
        u.oep.region.inicio,
        u.oep.region.fin,
        u.dump.codigo.len(),
        en_memoria
    );

    if !en_disco && en_memoria {
        println!("DESEMPAQUETADO: el codigo que el disco escondia quedo al descubierto en memoria");
        std::process::ExitCode::SUCCESS
    } else {
        eprintln!("BRECHA: el desempaquetado no expuso el codigo escondido");
        std::process::ExitCode::FAILURE
    }
}

/// La raiz del crate, leida al EJECUTAR y no congelada al compilar.
///
/// Con `env!("CARGO_MANIFEST_DIR")` la ruta quedaba fijada en el binario, y
/// Cargo no lo recompila al mover el repositorio de carpeta (el hash de un
/// paquete de ruta es relativo al workspace): la prueba seguia buscando sus
/// ficheros en la ruta vieja y fallaba diciendo que no existian. Cargo define la
/// variable al lanzar pruebas y ejemplos; el valor de compilacion queda solo para
/// quien ejecute el binario a mano.
fn raiz_crate() -> String {
    std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").to_string())
}
