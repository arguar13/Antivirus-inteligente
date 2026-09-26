//! El ciclo completo de AegisConfine sobre un programa real de ESTA maquina, con
//! sus medidas.
//!
//! Uso: `confinar_support [programa] [args-aprender] -- [args-ensayo]`
//! Por defecto aprende `/bin/ls /usr` y ensaya `/bin/ls /etc`, que lee un
//! directorio que el aprendizaje no vio: el ensayo tiene que anotarlo sin
//! bloquearlo.
//!
//! Mide: el tiempo de aprender, la superficie que queda (llamadas permitidas de
//! las de la tabla), y el coste de ejecutar libre, confinado y supervisado.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use aegis_confinar::compilar;
use aegis_confinar::supervision;
use aegis_confinar::{ActivosProtegidos, Confirmacion, ObjetivoConfinable};
use aegis_sandbox::syscalls;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (programa, resto) = match args.split_first() {
        Some((p, r)) => (PathBuf::from(p), r.to_vec()),
        None => (
            PathBuf::from("/bin/ls"),
            vec!["/usr".into(), "--".into(), "/etc".into()],
        ),
    };
    let corte = resto.iter().position(|a| a == "--").unwrap_or(resto.len());
    let a_aprender: Vec<String> = resto[..corte].to_vec();
    let a_ensayar: Vec<String> = resto
        .get(corte + 1..)
        .map(<[String]>::to_vec)
        .unwrap_or_else(|| a_aprender.clone());

    let objetivo = match ObjetivoConfinable::nuevo(&programa, &ActivosProtegidos::default()) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("FALLO: {e}");
            return ExitCode::FAILURE;
        }
    };
    let ventana = Duration::from_secs(60);

    let a = match supervision::aprender(&objetivo, &a_aprender, ventana) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("FALLO al aprender: {e}");
            return ExitCode::FAILURE;
        }
    };
    let total = syscalls::todas().len();
    let t = compilar::traduccion(&a.perfil);
    println!(
        "programa:       {} {:?}",
        objetivo.ejecutable().display(),
        a_aprender
    );
    println!(
        "aprendido:      {} llamadas vistas en {:?}; {} distintas de {total} ({:.1} % de la superficie se cierra)",
        a.llamadas_vistas,
        a.duracion,
        t.llamadas_permitidas,
        100.0 * t.llamadas_denegadas as f64 / total as f64
    );
    println!(
        "reglas:         {} de lectura, {} de escritura; capacidades retenidas {:#x}; root: {}",
        t.reglas_lectura,
        t.reglas_escritura,
        t.capacidades_retenidas,
        if a.perfil.root { "si" } else { "no" }
    );

    let e = match supervision::ensayar(&objetivo, &a.perfil, &a_ensayar, ventana) {
        Ok(e) => e,
        Err(err) => {
            eprintln!("FALLO al ensayar: {err}");
            return ExitCode::FAILURE;
        }
    };
    println!(
        "ensayo {:?}:  termino {:?}; habria bloqueado {} cosa(s){}",
        a_ensayar,
        e.fin,
        e.habria_bloqueado.len(),
        if e.habria_bloqueado.is_empty() {
            String::new()
        } else {
            format!(
                ": {}",
                e.habria_bloqueado
                    .iter()
                    .take(6)
                    .map(|d| d.frase())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
    );

    // Coste: libre, confinado (obligatorio con lo aprendido) y supervisado.
    let conf = match Confirmacion::nueva("confinar_support", "medida de coste", 0) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("FALLO: {err}");
            return ExitCode::FAILURE;
        }
    };
    let medir = |f: &dyn Fn() -> bool| -> Option<Duration> {
        let mut menor = Duration::MAX;
        for _ in 0..5 {
            let t = Instant::now();
            if !f() {
                return None;
            }
            menor = menor.min(t.elapsed());
        }
        Some(menor)
    };
    let libre = medir(&|| {
        supervision::ejecutar_libre(&objetivo, &a_aprender).is_ok_and(|(f, _)| f.limpio())
    });
    let confinado = medir(&|| {
        supervision::ejecutar_obligatorio(&objetivo, &a.perfil, &conf, &a_aprender)
            .is_ok_and(|(f, _)| f.limpio())
    });
    let supervisado = medir(&|| {
        supervision::aprender(&objetivo, &a_aprender, ventana)
            .is_ok_and(|x| x.fin.is_some_and(|f| f.limpio()))
    });
    println!(
        "coste:          libre {libre:?}, confinado {confinado:?}, supervisado (aprender) {supervisado:?}"
    );
    match confinado {
        Some(_) => {
            println!("obligatorio:    el programa funciona con su perfil impuesto");
            ExitCode::SUCCESS
        }
        None => {
            eprintln!("FALLO: el programa NO funciona con el perfil aprendido de si mismo");
            ExitCode::FAILURE
        }
    }
}
