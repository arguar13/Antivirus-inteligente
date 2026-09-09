//! Informa de las capacidades de hardware del guardia de syscalls en esta
//! maquina.
//!
//! Igual que el informe del sandbox y el del firmware: la puerta de calidad lo
//! ejecuta para dejar constancia HONESTA de que ofrece el hardware donde se
//! corre. La deteccion principal (trazador + verificacion cruzada) no depende
//! de la PMU; el informe lo deja claro.

fn main() -> std::process::ExitCode {
    let s = aegis_syscallguard::SoporteSyscallGuard::sondear();

    print!("PMU (contador hardware): ");
    match &s.pmu {
        aegis_syscallguard::SoportePmu::Disponible => println!("SI"),
        aegis_syscallguard::SoportePmu::NoDisponible(m) => println!("NO ({m})"),
    }

    print!("DRx (breakpoint hardware): ");
    match &s.drx {
        aegis_syscallguard::SoporteDrx::Disponible => println!("SI"),
        aegis_syscallguard::SoporteDrx::NoDisponible(m) => println!("NO ({m})"),
    }

    println!(
        "PTRACE_GET_SYSCALL_INFO (verificacion cruzada): {}",
        if s.ptrace_syscall_info { "SI" } else { "NO" }
    );
    println!(
        "deteccion operativa (independiente de la PMU): {}",
        if s.deteccion_operativa() { "SI" } else { "NO" }
    );

    if !s.pmu.hay() {
        println!(
            "AVISO: sin PMU expuesta, el cribado barato por hardware no aplica \
             en esta maquina. La deteccion por trazado y verificacion cruzada SI \
             opera, y los registros de depuracion (DRx) tambien se ejercitan."
        );
    }
    std::process::ExitCode::SUCCESS
}
