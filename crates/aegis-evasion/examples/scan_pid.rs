//! Escanea un proceso vivo en busca de evasion (inyeccion, vaciado, hooks) y
//! sale con codigo distinto de cero si la gravedad alcanza el umbral.
//!
//! Lo usa `tests/red_team_sim.py` para comprobar, sobre un proceso victima real
//! que ha mapeado memoria RWX anonima, que el detector de la FASE 10 lo marca.
//!
//! Uso: scan_pid <PID> [umbral]
//!   codigo 0  = por debajo del umbral (limpio)
//!   codigo 3  = gravedad alta o superior detectada
//!   codigo 2  = error de uso o de acceso al proceso

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let pid: i32 = match args.next().and_then(|s| s.parse().ok()) {
        Some(p) => p,
        None => {
            eprintln!("uso: scan_pid <PID> [umbral]");
            return ExitCode::from(2);
        }
    };
    // Umbral de puntuacion a partir del cual se considera deteccion.
    let umbral: u32 = args.next().and_then(|s| s.parse().ok()).unwrap_or(40);

    match aegis_evasion::analyze_process(pid) {
        Ok(informe) => {
            let score = informe.score();
            println!("pid={pid} score={score} severity={:?}", informe.severity());
            for s in informe.signals() {
                println!("  senal: {} ({})", s.what, s.score);
            }
            if score >= umbral {
                ExitCode::from(3)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(e) => {
            eprintln!("no se pudo analizar el pid {pid}: {e}");
            ExitCode::from(2)
        }
    }
}
