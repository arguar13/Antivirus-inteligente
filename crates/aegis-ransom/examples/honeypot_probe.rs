//! Herramienta de apoyo para la simulacion de Red Team del ransomware.
//!
//! Modo principal:
//!   watch <dir>   despliega senuelos en <dir>, imprime sus rutas y luego READY,
//!                 espera una linea por stdin (el momento en que el atacante ya
//!                 manipulo un senuelo), y verifica contra el estado ORIGINAL
//!                 capturado al desplegar. Sale 3 si alguno fue manipulado.
//!
//! Este modo es el correcto para la simulacion porque conserva EN MEMORIA las
//! sumas de comprobacion originales mientras el atacante actua: reconstruirlas
//! leyendo el fichero despues (como haria un `verify` en dos procesos) captaria
//! el estado ya manipulado como si fuera el bueno, y no detectaria nada.
//!
//! Modos auxiliares:
//!   deploy <dir>            despliega e imprime rutas (sin vigilar)

use std::path::PathBuf;
use std::process::ExitCode;

use aegis_ransom::honeypot::{HoneypotConfig, HoneypotSet};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let modo = args.next().unwrap_or_default();
    match modo.as_str() {
        "deploy" => {
            let dir = match args.next() {
                Some(d) => PathBuf::from(d),
                None => {
                    eprintln!("uso: honeypot_probe deploy <dir>");
                    return ExitCode::from(2);
                }
            };
            let set = match HoneypotSet::deploy(&HoneypotConfig {
                directories: vec![dir],
                per_directory: 3,
            }) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("despliegue fallido: {e}");
                    return ExitCode::from(2);
                }
            };
            for p in set.paths() {
                println!("{}", p.display());
            }
            ExitCode::SUCCESS
        }
        "watch" => {
            let dir = match args.next() {
                Some(d) => PathBuf::from(d),
                None => {
                    eprintln!("uso: honeypot_probe watch <dir>");
                    return ExitCode::from(2);
                }
            };
            // Se despliega y se conserva el conjunto con sus sumas ORIGINALES.
            let set = match HoneypotSet::deploy(&HoneypotConfig {
                directories: vec![dir],
                per_directory: 3,
            }) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("despliegue fallido: {e}");
                    return ExitCode::from(2);
                }
            };
            for p in set.paths() {
                println!("{}", p.display());
            }
            println!("READY");
            use std::io::Write;
            let _ = std::io::stdout().flush();

            // Se bloquea hasta que el orquestador avise (una linea) de que ya
            // manipulo un senuelo.
            let mut linea = String::new();
            let _ = std::io::stdin().read_line(&mut linea);

            // Verificacion contra el estado original en memoria.
            let manipulados = set.verify();
            for t in &manipulados {
                println!("MANIPULADO {} {:?}", t.path.display(), t.reason);
            }
            if manipulados.is_empty() {
                println!("intactos");
                ExitCode::SUCCESS
            } else {
                ExitCode::from(3)
            }
        }
        _ => {
            eprintln!("uso: honeypot_probe deploy|verify ...");
            ExitCode::from(2)
        }
    }
}
