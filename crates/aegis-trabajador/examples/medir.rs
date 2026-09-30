//! Mide la memoria maxima de un analizador sobre un fichero, fuera del
//! trabajador: `cargo run --release --example medir -- <analizador> <ruta>`.
//! Es lo que se usa para fijar el techo del cgroup con datos y no a ojo.

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (Some(nombre), Some(ruta)) = (args.get(1), args.get(2)) else {
        eprintln!("uso: medir <analizador> <ruta>");
        std::process::exit(2);
    };
    let Some(a) = aegis_trabajador::Analizador::todos()
        .iter()
        .copied()
        .find(|a| a.nombre() == nombre)
    else {
        eprintln!("analizador desconocido: {nombre}");
        std::process::exit(2);
    };
    let bytes = std::fs::read(ruta).expect("leer");
    let t = std::time::Instant::now();
    let r = aegis_trabajador::Analizadores::default().analizar(a, &bytes);
    let pico = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("VmHWM:"))
                .map(|v| v.trim().to_string())
        })
        .unwrap_or_default();
    println!(
        "{nombre} {ruta} {} KiB-fichero pico={pico} {:?} {}",
        bytes.len() / 1024,
        t.elapsed(),
        match r {
            Ok(i) => format!("ok ({} hallazgos)", i.hallazgos.len()),
            Err(e) => format!("error: {e}"),
        }
    );
}
