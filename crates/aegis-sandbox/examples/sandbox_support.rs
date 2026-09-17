//! Informa de que mecanismos de aislamiento ofrece este kernel.
//!
//! Existe para que la puerta de calidad pueda DECIR que capas se estan
//! ejerciendo de verdad en la maquina donde corre. Un kernel sin Landlock hace
//! que la restriccion por rutas no se pueda probar; callarlo dejaria una
//! diferencia enorme entre lo que el proyecto afirma y lo que ha verificado.
//!
//! Sale con codigo 1 si falta seccomp, porque sin el no queda ninguna capa de
//! aislamiento real y el sandbox del producto no se puede aplicar.

use aegis_sandbox::{CompiledSandbox, SandboxPolicy, Support};

fn main() -> std::process::ExitCode {
    let s = Support::detect();

    println!("seccomp-bpf: {}", if s.seccomp { "SI" } else { "NO" });
    match s.landlock_abi {
        Some(abi) => println!("Landlock:    SI (ABI {abi})"),
        None => println!("Landlock:    NO (falta CONFIG_SECURITY_LANDLOCK)"),
    }
    println!("  restriccion por rutas:   {}", s.can_restrict_paths());
    println!("  restriccion por puertos: {}", s.can_restrict_ports());

    if !s.seccomp {
        eprintln!(
            "FALLO: sin seccomp no hay ninguna capa de aislamiento aplicable en \
             esta maquina."
        );
        return std::process::ExitCode::FAILURE;
    }

    let p = SandboxPolicy::untrusted_binary();
    match CompiledSandbox::compile(&p) {
        Ok(c) => {
            let r = c.summary();
            println!(
                "politica '{}': {} llamadas bloqueadas, {} rutas permitidas, \
                 landlock={:?}",
                p.name, r.blocked_syscalls, r.allowed_paths, r.landlock_abi
            );
            if r.landlock_abi.is_none() {
                println!(
                    "AVISO: la restriccion por rutas NO se aplica en esta maquina. \
                     La capa de llamadas al sistema si."
                );
            }
            if r.skipped_paths > 0 {
                println!(
                    "AVISO: {} ruta(s) de la politica no admitian ni uno de los \
                     derechos pedidos —derechos de directorio sobre algo que no \
                     lo es— y quedan PROHIBIDAS.",
                    r.skipped_paths
                );
            }
            if r.landlock_net_skipped {
                println!(
                    "AVISO: la restriccion de puertos de Landlock necesita ABI 4; \
                     la red la sigue cortando seccomp por completo."
                );
            }
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("FALLO: la politica no se pudo compilar: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
