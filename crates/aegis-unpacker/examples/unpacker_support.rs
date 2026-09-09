//! Informa de si el desempaquetado dinamico puede correr en esta maquina.
//!
//! Requiere ptrace y seccomp. Ambos existen en cualquier Linux razonable; el
//! informe existe para que la puerta de calidad lo confirme en la maquina donde
//! corre, igual que el del sandbox y el de firmware.

fn main() -> std::process::ExitCode {
    let seccomp = aegis_unpacker::soportado();
    println!(
        "seccomp (confinamiento): {}",
        if seccomp { "SI" } else { "NO" }
    );
    // ptrace no tiene una consulta previa barata; se confirma al desempaquetar.
    println!("ptrace: se ejercita en la simulacion de Red Team (escenario 12)");
    if !seccomp {
        eprintln!(
            "AVISO: sin seccomp el desempaquetado correria SIN confinar; se \
             desactiva por seguridad en esta maquina."
        );
    }
    std::process::ExitCode::SUCCESS
}
