//! Prueba de deteccion de ocultacion para la simulacion de Red Team.
//!
//! Un rootkit de DKOM de verdad exige cargar un modulo de kernel, y este kernel
//! esta compilado SIN soporte de modulos (`# CONFIG_MODULES is not set`): no se
//! puede montar aqui, y fingirlo con datos inventados violaria la regla de cero
//! simulaciones. Lo que SI es real y se demuestra es el mecanismo de deteccion
//! completo contra el kernel de verdad:
//!
//!   1. Se lanza un proceso hijo vivo (`sleep`).
//!   2. Se cargan y ejecutan las sondas eBPF reales, que lo ven por sus dos
//!      estructuras internas de kernel.
//!   3. Se le entrega al motor una vista de `/proc` de la que ese TID ha sido
//!      retirado: es EXACTAMENTE lo que hace un rootkit que engancha `getdents`.
//!   4. La confirmacion vuelve a preguntar al kernel real (lo ve) y a la vista
//!      de userland manipulada (no lo ve): la asimetria persiste y se acusa.
//!
//! Todo lo de kernel es autentico. Solo la vista de usuario esta manipulada,
//! que es justo lo que un rootkit manipula. Sale 0 si la ocultacion se detecta.

use aegis_kintegrity::engine::{pid_max, KernelIntegrity, KernelViews, KiConfig};
use aegis_kintegrity::verdict::{AnomalyKind, VerdictConfig};
use aegis_kintegrity::views::{leer_procfs, ViewSet};

fn main() -> std::process::ExitCode {
    if !aegis_kintegrity::soportado() {
        eprintln!("OMITIDO: sin BTF no hay verificacion cruzada en esta maquina");
        return std::process::ExitCode::from(2);
    }
    let vistas = match aegis_kintegrity::BpfViews::cargar() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("OMITIDO: {e}");
            return std::process::ExitCode::from(2);
        }
    };

    // El "proceso a esconder": un hijo real y vivo.
    let mut hijo = match std::process::Command::new("/bin/sh")
        .args(["-c", "sleep 30"])
        .spawn()
    {
        Ok(h) => h,
        Err(e) => {
            eprintln!("no se pudo lanzar el proceso victima: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let victima = hijo.id();

    // El motor con una relectura de /proc que esconde al hijo, como un getdents
    // hookeado. Una sola confirmacion basta: es una deteccion dirigida.
    let cfg = KiConfig {
        verdict: VerdictConfig {
            confirmaciones_requeridas: 1,
            ..VerdictConfig::default()
        },
        ..KiConfig::default()
    };
    let mut motor = KernelIntegrity::con_relectura(vistas, cfg, move || {
        let mut v = leer_procfs();
        v.remove(&victima);
        v
    });

    // Se toman las vistas de kernel REALES y se manipula solo la de userland.
    let (lista, pidmap, desbordes) = match motor.kernel_mut().barrer(1, pid_max()) {
        Ok(t) => t,
        Err(e) => {
            let _ = hijo.kill();
            let _ = hijo.wait();
            eprintln!("el barrido real fallo: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    let en_kernel = lista.contains_key(&victima) || pidmap.contains_key(&victima);
    if !en_kernel {
        let _ = hijo.kill();
        let _ = hijo.wait();
        eprintln!("OMITIDO: el proceso victima no aparecio en la vista de kernel");
        return std::process::ExitCode::from(2);
    }

    let mut procfs = leer_procfs();
    procfs.remove(&victima); // el getdents hookeado

    let vistas = ViewSet {
        procfs,
        task_list: lista,
        pid_space: pidmap,
        desbordes,
    };
    let r = match motor.evaluar(&vistas) {
        Ok(r) => r,
        Err(e) => {
            let _ = hijo.kill();
            let _ = hijo.wait();
            eprintln!("la evaluacion fallo: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    let _ = hijo.kill();
    let _ = hijo.wait();

    let detectada = r
        .anomalies
        .iter()
        .find(|a| a.tid == victima && a.kind == AnomalyKind::UserlandHidden);

    match detectada {
        Some(a) => {
            println!(
                "DETECTADA ocultacion del pid {} (gravedad {}, mitigar={})",
                a.tid,
                a.severity,
                a.exige_mitigacion()
            );
            println!("  {}", a.detalle);
            std::process::ExitCode::SUCCESS
        }
        None => {
            eprintln!(
                "BRECHA: el proceso escondido de /proc pero visible para el kernel \
                 NO se detecto: {:?}",
                r.anomalies
            );
            std::process::ExitCode::FAILURE
        }
    }
}
