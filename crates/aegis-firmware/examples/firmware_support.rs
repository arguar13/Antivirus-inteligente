//! Informa de que puede verificar el escaner de firmware en esta maquina.
//!
//! Igual que el informe del sandbox: la puerta de calidad tiene que DECIR que
//! capas de firmware existen aqui, para que la diferencia entre "verificado" y
//! "no aplicable en esta maquina" este a la vista y no en un comentario.
//!
//! Sale 0 salvo que el escaner detecte un compromiso REAL. La ausencia de TPM o
//! UEFI no es un compromiso: es una capacidad que la maquina no tiene.

use aegis_firmware::report::CheckState;
use aegis_firmware::FirmwareSupport;

fn main() -> std::process::ExitCode {
    let s = FirmwareSupport::detect();
    println!("TPM:        {}", if s.tpm { "SI" } else { "NO" });
    if let Some(v) = s.tpm_version {
        println!("  version:  {v}.x");
    }
    if !s.bancos.is_empty() {
        let nombres: Vec<&str> = s.bancos.iter().map(|b| b.sysfs_name()).collect();
        println!("  bancos:   {}", nombres.join(", "));
    }
    println!("UEFI:       {}", if s.uefi { "SI" } else { "NO" });
    println!("  efivars:  {}", if s.efivars { "montado" } else { "no" });
    println!("event log:  {}", if s.event_log { "SI" } else { "NO" });

    let r = aegis_firmware::escanear(None);
    println!("\nveredicto de firmware:");
    for c in &r.checks {
        let etiqueta = match &c.estado {
            CheckState::Ok => "OK".to_string(),
            CheckState::Fallo(m) => format!("COMPROMISO: {m}"),
            CheckState::NoAplicable(m) => format!("no aplicable ({m})"),
            CheckState::Indeterminado(m) => format!("indeterminado ({m})"),
        };
        println!("  {:32} {etiqueta}", c.nombre);
    }

    if r.comprometido() {
        eprintln!("\nFALLO: el firmware muestra evidencia de compromiso");
        return std::process::ExitCode::FAILURE;
    }
    if !s.algo_que_verificar() {
        println!(
            "\nAVISO: esta maquina no tiene TPM ni UEFI; el escaner de firmware no \
             aplica aqui. La logica de analisis (event log, DBX, PCR) SI se prueba \
             con vectores binarios reales."
        );
    }
    std::process::ExitCode::SUCCESS
}
