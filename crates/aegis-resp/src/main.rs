//! CLI del motor de respuesta activa.
//!
//! Todas las acciones de este binario son destructivas o afectan a la
//! conectividad. Las que no se pueden deshacer con un solo comando exigen
//! confirmacion explicita.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use aegis_resp::isolate::{build_ruleset, IsolationPolicy, Isolator};
use aegis_resp::kill::{kill_process_tree, KillOptions, ProcOutcome};
use aegis_resp::quarantine::{Quarantine, QuarantineId};

fn uso() -> &'static str {
    "aegis-resp - motor de respuesta activa de AegisCore

USO:
    aegis-resp <SUBCOMANDO>

TERMINACION:
    tree <PID>                 Muestra el arbol de procesos sin tocarlo
    kill <PID> [--now]         Termina el arbol. --now omite el periodo de gracia
                               (correcto ante ransomware activo: cada ms de
                               gracia son ficheros cifrados)

CUARENTENA:
    quarantine <RUTA> [MOTIVO] Cifra el fichero y ELIMINA el original
    qlist                      Lista los elementos en cuarentena
    qinspect <ID>              Muestra los metadatos sin restaurar
    qrestore <ID> [DESTINO]    Restaura contenido, permisos y marcas de tiempo

AISLAMIENTO DE RED:
    isolate-preview [--total]  Muestra las reglas SIN aplicarlas
    isolate --confirm [--total] Aplica el aislamiento
    release                    Retira el aislamiento
    isolation-status           Consulta el estado

OPCIONES GLOBALES:
    --store RUTA               Directorio de cuarentena (por defecto
                               /var/lib/aegiscore/quarantine)"
}

/// Opciones que consumen un valor. Hay que conocerlas para poder separar los
/// argumentos posicionales de las opciones.
const OPCIONES_CON_VALOR: [&str; 1] = ["--store"];

/// Separa argumentos en (posicionales, opciones).
///
/// Sin esta separacion, `qrestore <ID> --store /ruta` toma "--store" como
/// destino posicional y restaura el fichero a una ruta llamada asi. Es un fallo
/// real que aparecio en la primera prueba de extremo a extremo: el comando
/// devolvia exito y el fichero no aparecia donde el operador lo esperaba.
fn separar(args: &[String]) -> (Vec<String>, Vec<String>) {
    let mut posicionales = Vec::new();
    let mut opciones = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a.starts_with("--") {
            opciones.push(a.clone());
            if OPCIONES_CON_VALOR.contains(&a.as_str()) && i + 1 < args.len() {
                opciones.push(args[i + 1].clone());
                i += 1;
            }
        } else {
            posicionales.push(a.clone());
        }
        i += 1;
    }
    (posicionales, opciones)
}

fn store_dir(args: &[String]) -> PathBuf {
    args.windows(2)
        .find(|w| w[0] == "--store")
        .map(|w| PathBuf::from(&w[1]))
        .unwrap_or_else(|| PathBuf::from("/var/lib/aegiscore/quarantine"))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(sub) = args.first().map(String::as_str) else {
        println!("{}", uso());
        return ExitCode::from(2);
    };

    match sub {
        "-h" | "--help" | "help" => {
            println!("{}", uso());
            ExitCode::SUCCESS
        }

        "tree" | "kill" => cmd_procesos(sub, &args),
        "quarantine" | "qlist" | "qinspect" | "qrestore" => cmd_cuarentena(sub, &args),
        "isolate-preview" | "isolate" | "release" | "isolation-status" => cmd_red(sub, &args),

        otro => {
            eprintln!("error: subcomando desconocido '{otro}'\n\n{}", uso());
            ExitCode::from(2)
        }
    }
}

fn cmd_procesos(sub: &str, args: &[String]) -> ExitCode {
    let (pos, _) = separar(args);
    let Some(pid) = pos.get(1).and_then(|s| s.parse::<i32>().ok()) else {
        eprintln!("error: '{sub}' necesita un PID");
        return ExitCode::from(2);
    };

    let opts = KillOptions {
        immediate: args.iter().any(|a| a == "--now"),
        ..Default::default()
    };

    if sub == "tree" {
        match aegis_resp::kill::collect_tree(&opts.proc_root, pid) {
            Ok(t) => {
                println!("arbol con raiz en {} ({}):", t.root.pid, t.root.comm);
                // Se muestra en el mismo orden en que se terminaria: de las
                // hojas a la raiz.
                for p in &t.members {
                    println!(
                        "  pid={:<8} ppid={:<8} estado={} {}",
                        p.pid, p.ppid, p.state, p.comm
                    );
                }
                println!("total: {} procesos", t.members.len());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        }
    } else {
        match kill_process_tree(pid, &opts) {
            Ok(informe) => {
                for (p, o) in &informe.outcomes {
                    let etiqueta = match o {
                        ProcOutcome::Killed => "TERMINADO".to_string(),
                        ProcOutcome::AlreadyGone => "YA NO ESTABA".to_string(),
                        ProcOutcome::Refused { reason } => format!("PROTEGIDO ({reason})"),
                        ProcOutcome::Survived { reason } => format!("SOBREVIVIO ({reason})"),
                        ProcOutcome::PermissionDenied => "SIN PERMISOS".to_string(),
                    };
                    println!("  {:<10} pid={:<8} {}", etiqueta, p.pid, p.comm);
                }
                println!(
                    "\n{} terminados de {} procesos del arbol",
                    informe.killed(),
                    informe.outcomes.len()
                );
                if !informe.complete() {
                    // Decirlo importa: un informe que dice "hecho" ocultando
                    // supervivientes destruye la confianza en el producto la
                    // primera vez que el operador lo descubre por su cuenta.
                    eprintln!("AVISO: el arbol NO quedo completamente terminado.");
                    return ExitCode::FAILURE;
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        }
    }
}

fn cmd_cuarentena(sub: &str, args: &[String]) -> ExitCode {
    let (pos, _) = separar(args);
    let dir = store_dir(args);
    let q = match Quarantine::open(&dir) {
        Ok(q) => q,
        Err(e) => {
            eprintln!("error al abrir el almacen en {}: {e}", dir.display());
            return ExitCode::FAILURE;
        }
    };

    match sub {
        "quarantine" => {
            let Some(ruta) = pos.get(1) else {
                eprintln!("error: 'quarantine' necesita una ruta");
                return ExitCode::from(2);
            };
            let motivo = pos.get(2).cloned().unwrap_or_else(|| "manual".into());
            match q.quarantine_file(Path::new(ruta), "operador", &motivo) {
                Ok(id) => {
                    println!("en cuarentena: {id}");
                    println!("original eliminado: {ruta}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }

        "qlist" => match q.list() {
            Ok(ids) if ids.is_empty() => {
                println!("cuarentena vacia");
                ExitCode::SUCCESS
            }
            Ok(ids) => {
                for id in ids {
                    match q.inspect(id) {
                        Ok(m) => println!(
                            "{}  {}  {} bytes  motivo: {}",
                            id,
                            m.original_path.display(),
                            m.size,
                            m.reason
                        ),
                        Err(e) => println!("{id}  <ilegible: {e}>"),
                    }
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        },

        "qinspect" => {
            let Some(id) = pos.get(1).and_then(|s| QuarantineId::from_hex(s)) else {
                eprintln!("error: identificador invalido");
                return ExitCode::from(2);
            };
            match q.inspect(id) {
                Ok(m) => {
                    println!("{}", m.encode());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }

        "qrestore" => {
            let Some(id) = pos.get(1).and_then(|s| QuarantineId::from_hex(s)) else {
                eprintln!("error: identificador invalido");
                return ExitCode::from(2);
            };
            let destino = pos.get(2).map(PathBuf::from);
            match q.restore(id, destino.as_deref()) {
                Ok(p) => {
                    println!("restaurado en {}", p.display());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }

        _ => unreachable!("subcomando de cuarentena no contemplado"),
    }
}

fn cmd_red(sub: &str, args: &[String]) -> ExitCode {
    let total = args.iter().any(|a| a == "--total");
    let politica = if total {
        IsolationPolicy::total()
    } else {
        IsolationPolicy::containment()
    };

    match sub {
        "isolate-preview" => {
            println!("{}", build_ruleset(&politica));
            if !politica.leaves_admin_path() {
                println!(
                    "# AVISO: esta politica NO deja ninguna via de administracion.\n\
                     # El equipo quedara inalcanzable por red."
                );
            }
            ExitCode::SUCCESS
        }

        "isolate" => {
            if !args.iter().any(|a| a == "--confirm") {
                eprintln!(
                    "error: 'isolate' cambia la conectividad de esta maquina y exige --confirm.\n\
                     Revisa antes lo que se va a aplicar con 'isolate-preview'."
                );
                return ExitCode::from(2);
            }
            if total {
                eprintln!(
                    "AVISO: aislamiento TOTAL. El equipo quedara inalcanzable por red y solo \
                     se podra recuperar por consola fuera de banda o acceso fisico."
                );
            }
            match Isolator::new().isolate(&politica) {
                Ok(reglas) => {
                    println!(
                        "aislamiento aplicado en la tabla inet '{}'",
                        aegis_resp::isolate::TABLE
                    );
                    println!("--- reglas aplicadas ---\n{reglas}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }

        "release" => match Isolator::new().release() {
            Ok(()) => {
                println!("aislamiento retirado; el sistema vuelve a su estado anterior");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        },

        "isolation-status" => match Isolator::new().status() {
            Ok(s) => {
                println!("{s:?}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::FAILURE
            }
        },

        _ => unreachable!("subcomando de red no contemplado"),
    }
}
