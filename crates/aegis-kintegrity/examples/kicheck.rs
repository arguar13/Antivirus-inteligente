//! Barrido de verificacion cruzada contra el kernel de esta maquina.
//!
//! Sale con 0 si no hay anomalias confirmadas, 1 si las hay y 2 si la maquina
//! no puede sostener la comprobacion. Un kernel sin los kfuncs necesarios NO es
//! un fallo del producto: es una limitacion que hay que decir, no ocultar.

use aegis_kintegrity::engine::{KernelIntegrity, KiConfig};

fn main() -> std::process::ExitCode {
    let verboso = std::env::args().any(|a| a == "--verbose");
    let vueltas: u32 = std::env::args()
        .collect::<Vec<_>>()
        .windows(2)
        .find(|w| w[0] == "--rounds")
        .and_then(|w| w[1].parse().ok())
        .unwrap_or(1);

    if !aegis_kintegrity::soportado() {
        eprintln!("OMITIDO: sin /sys/kernel/btf/vmlinux no hay verificacion cruzada");
        return std::process::ExitCode::from(2);
    }

    let vistas = match aegis_kintegrity::BpfViews::cargar() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("OMITIDO: {e}");
            return std::process::ExitCode::from(2);
        }
    };

    let config = KiConfig::default();
    println!(
        "barriendo PID {}..{} ({} confirmaciones para acusar)",
        config.primero, config.ultimo, config.verdict.confirmaciones_requeridas
    );
    let mut motor = KernelIntegrity::new(vistas, config);

    let mut ultimo = None;
    for i in 1..=vueltas {
        match motor.scan() {
            Ok(r) => {
                println!(
                    "vuelta {i}: lista={} pidmap={} procfs={} candidatos={} \
                     carreras={} desbordes={} confirmadas={} pendientes={}",
                    r.en_lista,
                    r.en_pidmap,
                    r.en_procfs,
                    r.candidatos,
                    r.descartados_por_carrera,
                    r.desbordes,
                    r.anomalies.len(),
                    r.pendientes.len()
                );
                if verboso {
                    for a in r.pendientes.iter().chain(r.anomalies.iter()) {
                        println!(
                            "    [{}] tid={} tgid={:?} comm={:?} gravedad={} racha={}",
                            a.kind.as_str(),
                            a.tid,
                            a.tgid,
                            a.comm,
                            a.severity,
                            a.confirmaciones
                        );
                    }
                }
                ultimo = Some(r);
            }
            Err(e) => {
                eprintln!("FALLO: el barrido no se pudo completar: {e}");
                return std::process::ExitCode::FAILURE;
            }
        }
    }

    let Some(r) = ultimo else {
        return std::process::ExitCode::FAILURE;
    };
    if r.anomalies.is_empty() {
        println!("LIMPIO: ninguna anomalia confirmada");
        std::process::ExitCode::SUCCESS
    } else {
        for a in &r.anomalies {
            println!(
                "ANOMALIA {} tid={} :: {}",
                a.kind.as_str(),
                a.tid,
                a.detalle
            );
        }
        std::process::ExitCode::FAILURE
    }
}
