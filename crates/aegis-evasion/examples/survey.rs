//! Recorre los procesos vivos y ejecuta el analisis completo de evasion.
//! Sirve para calibrar con datos reales y no a ojo.

fn main() {
    let mut n = 0usize;
    let mut peor = 0u32;
    for e in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
        let Some(s) = e.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let Ok(pid) = s.parse::<i32>() else { continue };
        if aegis_scan::memory::is_kernel_thread(pid) {
            continue;
        }
        let Ok(inf) = aegis_evasion::analyze_process(pid) else {
            continue;
        };
        if inf.hollow.regions_compared == 0 && inf.hooks.checked == 0 {
            continue;
        }
        n += 1;
        peor = peor.max(inf.score());
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
        println!(
            "{:>7} {:<18} score {:>3} {:?} | hollow {} reg / {} hall | hooks {} chk / {} eng | anon-exec {}",
            pid,
            comm.trim(),
            inf.score(),
            inf.severity(),
            inf.hollow.regions_compared,
            inf.hollow.findings.len(),
            inf.hooks.checked,
            inf.hooks.hooked(),
            inf.injection.anon_exec_regions,
        );
        for sig in inf.signals() {
            println!("          -> {} ({})", sig.what, sig.score);
        }
        for f in inf.hooks.findings.iter().take(5) {
            println!(
                "          -> hook {} en {} ({:?})",
                f.symbol, f.library, f.kind
            );
        }
    }
    println!("--- {n} procesos, peor puntuacion {peor}");
}
