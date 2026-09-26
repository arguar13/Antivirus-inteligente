//! Deteccion de una syscall directa real, para la simulacion de Red Team.
//!
//! Compila un vector REAL que evade los enganches de userland: mete su propia
//! instruccion `syscall` en una pagina anonima y salta al kernel sin pasar por
//! libc. El guardia lo traza y tiene que cazar esa syscall por su origen —la
//! memoria anonima— cruzando la palabra del kernel con los bytes de la memoria.
//!
//! Sale 0 si el guardia caza la syscall directa; !=0 si se le escapa.

use std::path::PathBuf;

fn main() -> std::process::ExitCode {
    let soporte = aegis_syscallguard::SoporteSyscallGuard::sondear();
    if !soporte.deteccion_operativa() {
        eprintln!("OMITIDO: esta plataforma no ofrece el trazado de syscalls");
        return std::process::ExitCode::from(2);
    }

    let fuente = PathBuf::from(raiz_crate()).join("tests/fixtures/syscall_stub.c");
    let bin = std::env::temp_dir().join(format!("aegis-rt-syscall-{}", std::process::id()));
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".into());
    let compilar = std::process::Command::new(&cc)
        .args(["-O2", "-o"])
        .arg(&bin)
        .arg(&fuente)
        .output();
    match compilar {
        Ok(o) if o.status.success() => {}
        _ => {
            eprintln!("OMITIDO: no se pudo compilar el vector de syscall directa");
            return std::process::ExitCode::from(2);
        }
    }

    let guardia = aegis_syscallguard::SyscallGuard::nuevo();
    let resultado = guardia.perfilar_comando(&bin, &[]);
    let _ = std::fs::remove_file(&bin);

    let informe = match resultado {
        Ok(i) => i,
        Err(e) => {
            eprintln!("BRECHA: el perfilado fallo: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    let directa = informe
        .anomalias
        .iter()
        .find(|a| a.origen == aegis_syscallguard::OrigenSyscall::MemoriaAnonima);

    println!(
        "syscalls por libc: {} | directas desde memoria anonima: {} | veredicto: {:?}",
        informe.conteos.libc,
        informe.conteos.memoria_anonima,
        informe.estado()
    );

    match directa {
        Some(a) if a.opcode_confirmado => {
            println!(
                "DETECTADO: syscall directa nr={} desde {:#x} (memoria anonima, opcode syscall confirmado): evasion de enganches al descubierto",
                a.nr, a.ip
            );
            std::process::ExitCode::SUCCESS
        }
        Some(a) => {
            // Cazada por origen, pero el opcode no cuadra: aun asi es deteccion,
            // pero se avisa de la incoherencia (posible info de syscall falseada).
            println!(
                "DETECTADO (con reserva): syscall directa nr={} desde {:#x}, pero el opcode no se confirmo: el kernel pudo mentir",
                a.nr, a.ip
            );
            std::process::ExitCode::SUCCESS
        }
        None => {
            eprintln!("BRECHA: la syscall directa se escapo del guardia");
            std::process::ExitCode::FAILURE
        }
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
