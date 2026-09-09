//! CLI del escaner de postura y vulnerabilidades.
//!
//! Codigo de salida:
//!   0  sin hallazgos de gravedad alta o critica
//!   1  hay hallazgos accionables
//!   2  error de uso o de entrada
//!
//! Que un hallazgo accionable devuelva 1 es deliberado: permite usar el escaner
//! como puerta en un pipeline de despliegue sin envolverlo en un script que
//! interprete la salida de texto.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use aegis_vuln::{Category, Scanner, Severity};

fn uso() -> &'static str {
    "aegis-vuln - escaner de postura y vulnerabilidades del host

USO:
    aegis-vuln [OPCIONES]

OPCIONES:
    --feed RUTA      Feed de CVE a cargar (por defecto: sin feed, solo postura)
    --root RUTA      Raiz del sistema de ficheros a escanear (por defecto: /)
    --min-severity S info|low|medium|high|critical (por defecto: low)
    --quiet          Solo el resumen
    -h, --help       Esta ayuda

CODIGOS DE SALIDA:
    0  sin hallazgos de gravedad alta o critica
    1  hay hallazgos accionables
    2  error de uso o de entrada"
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{}", uso());
        return ExitCode::SUCCESS;
    }

    let mut feed: Option<PathBuf> = None;
    let mut root = PathBuf::from("/");
    let mut min = Severity::Low;
    let mut quiet = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--feed" | "--root" | "--min-severity" if i + 1 >= args.len() => {
                eprintln!("error: '{}' necesita un valor\n\n{}", args[i], uso());
                return ExitCode::from(2);
            }
            "--feed" => {
                feed = Some(PathBuf::from(&args[i + 1]));
                i += 1;
            }
            "--root" => {
                root = PathBuf::from(&args[i + 1]);
                i += 1;
            }
            "--min-severity" => {
                min = Severity::parse(&args[i + 1]);
                i += 1;
            }
            "--quiet" => quiet = true,
            otro => {
                eprintln!("error: opcion desconocida '{otro}'\n\n{}", uso());
                return ExitCode::from(2);
            }
        }
        i += 1;
    }

    let mut scanner = Scanner::new();
    if let Some(ruta) = &feed {
        match scanner.load_feed(ruta) {
            Ok(n) => eprintln!("feed cargado: {n} registros desde {}", ruta.display()),
            Err(e) => {
                eprintln!("error: {e}");
                return ExitCode::from(2);
            }
        }
    } else {
        eprintln!(
            "aviso: sin --feed solo se ejecutan las comprobaciones de postura; \
             no se buscaran CVE."
        );
    }

    let informe = scanner.scan(&root);
    imprimir(&informe, min, quiet, &root);

    if informe.has_actionable() {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn imprimir(informe: &aegis_vuln::ScanReport, min: Severity, quiet: bool, root: &Path) {
    let s = &informe.inventory.system;
    println!("== AegisCore - informe de postura y vulnerabilidades ==");
    println!("raiz analizada : {}", root.display());
    println!(
        "sistema        : {} {}",
        if s.os_pretty.is_empty() {
            "(desconocido)"
        } else {
            &s.os_pretty
        },
        s.os_version
    );
    println!("kernel         : {}", s.kernel_release);
    println!("paquetes       : {}", informe.inventory.len());
    println!("feed           : {} registros", informe.feed_records);
    println!();

    if !quiet {
        let mut mostrados = 0;
        for f in &informe.findings {
            if f.severity < min {
                continue;
            }
            mostrados += 1;
            println!("[{}] {} · {}", f.severity.label(), f.category.label(), f.id);
            println!("    {}", f.title);
            println!("    evidencia  : {}", f.evidence);
            println!("    remediacion: {}", f.remediation);
            println!();
        }
        if mostrados == 0 {
            println!("Sin hallazgos por encima de {}.\n", min.label());
        }
    }

    println!(
        "RESUMEN: {} criticos · {} altos · {} medios · {} bajos · {} informativos",
        informe.count(Severity::Critical),
        informe.count(Severity::High),
        informe.count(Severity::Medium),
        informe.count(Severity::Low),
        informe.count(Severity::Info),
    );

    // La ausencia de feed es la causa mas probable de un informe vacio de CVE,
    // y decirlo evita que se lea como "el sistema esta limpio".
    if informe.feed_records == 0
        && !informe
            .findings
            .iter()
            .any(|f| f.category == Category::Vulnerability)
    {
        println!(
            "NOTA: no se cargo ningun feed, asi que la ausencia de CVE en este informe \
             no significa que no los haya."
        );
    }
}
