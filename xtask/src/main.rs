//! `cargo xtask`: las tareas del repositorio de AegisCore.
//!
//! Una sola herramienta, con ayuda integrada, en vez de scripts sueltos. Los
//! datos que gobiernan cada tarea viven en `tools/config/*.toml`, editables y
//! comentados; el codigo de aqui solo los aplica.

mod amenazas;
mod auditoria;
mod capas;
mod config;
mod docs;
mod enlace;
mod incrustados;
mod invariantes;
mod kernels;
mod marcador;
mod matriz;
mod nombres;
mod plataformas;
mod repo;
mod sbom;

use std::path::PathBuf;
use std::process::ExitCode;

/// Error de cualquier tarea: un mensaje para una persona.
pub type Resultado<T> = Result<T, Box<dyn std::error::Error>>;

const AYUDA: &str = "\
cargo xtask <orden> [opciones]

Documentacion generada
  docs [--comprobar]      Regenera README.md y docs/matriz-capacidades.md desde
                          el codigo, docs/plantillas/README.md y tools/config/.
                          Con --comprobar no escribe: falla si difieren.

Arquitectura
  capas                   Las dependencias solo bajan de capa (tools/config/capas.toml).
  nombres [--inventario]  Un solo idioma en crates y modulos (tools/config/nombres.toml).
  amenazas                Estructura y evidencias del modelo de amenazas.
  incrustados             Todo fichero incrustado (include_bytes!) esta en git.
  arquitectura            capas + nombres + amenazas + incrustados.

Auditoria externa (tools/config/auditoria.toml)
  sbom [--comprobar] [--dist DIR]
                          SBOM CycloneDX 1.5 de cada instalable, desde Cargo.lock
                          (docs/generado/auditoria/sbom/). --comprobar: falla si no
                          corresponde al Cargo.lock o si un crate no declara licencia.
                          --dist DIR: comprueba que los binarios de DIR salen de este
                          arbol y coinciden con su SHA256SUMS, y escribe a su lado el
                          SBOM con su SHA-256 y la procedencia SLSA v1 (sin firmar).
                          `docs` genera ademas docs/generado/auditoria/ (indice,
                          SBOM, nivel SLSA y alcance del pentest).

Matriz de kernels (tools/config/kernels.toml)
  kernels traer [--solo ID]... [--arquitectura ARQ]
                          Descarga las imagenes y las verifica con las sumas oficiales.
  kernels ejecutar [--solo ID]... [--arquitectura ARQ]
                          Arranca cada distribucion en una microVM y ejecuta la matriz.
  kernels btf --solo ID   Extrae el BTF del kernel de una imagen (para compilar las
                          sondas de otra arquitectura).

Scorecard
  marcador [--publicar]   Scorecard (cobertura ATT&CK, deteccion, FP, latencia) desde
                          la matriz, docs/generado/motores.txt y la tarjeta del
                          modelo, en target/marcador/; --publicar lo copia a
                          docs/generado/scorecard.md.

Para los scripts de construccion
  instalables [--hermetico] [--workspace WS]
                          Imprime `paquete:binario:features` de tools/config/instalables.toml.
";

fn raiz() -> PathBuf {
    // xtask/ esta en la raiz del repositorio.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(PathBuf::from)
        .unwrap_or_default()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match ejecutar(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtask: {e}");
            ExitCode::FAILURE
        }
    }
}

fn opcion(args: &[String], nombre: &str) -> Option<String> {
    args.windows(2)
        .find(|w| w[0] == nombre)
        .map(|w| w[1].clone())
}

fn repetida(args: &[String], nombre: &str) -> Vec<String> {
    args.windows(2)
        .filter(|w| w[0] == nombre)
        .map(|w| w[1].clone())
        .collect()
}

fn ejecutar(args: &[String]) -> Resultado<()> {
    let raiz = raiz();
    let tiene = |f: &str| args.iter().any(|a| a == f);
    match args.first().map(String::as_str) {
        None | Some("-h" | "--help" | "ayuda") => {
            print!("{AYUDA}");
            Ok(())
        }
        Some("docs") => {
            let repo = repo::Repo::cargar(&raiz)?;
            println!("{}", capas::comprobar(&repo)?);
            let m = matriz::calcular(&repo)?;
            let generados = docs::generar(&repo, &m)?;
            docs::escribir(&repo.raiz, &generados, tiene("--comprobar"))?;
            if tiene("--comprobar") {
                println!("docs: README.md y docs/matriz-capacidades.md coinciden con el codigo");
            }
            Ok(())
        }
        Some("capas") => {
            let repo = repo::Repo::cargar(&raiz)?;
            println!("{}", capas::comprobar(&repo)?);
            Ok(())
        }
        Some("nombres") => {
            let repo = repo::Repo::cargar(&raiz)?;
            if tiene("--inventario") {
                print!("{}", nombres::inventario(&repo)?);
            } else {
                println!("{}", nombres::comprobar(&repo)?);
            }
            Ok(())
        }
        Some("incrustados") => {
            let repo = repo::Repo::cargar(&raiz)?;
            println!("{}", incrustados::comprobar(&repo)?);
            Ok(())
        }
        Some("amenazas") => {
            let repo = repo::Repo::cargar(&raiz)?;
            println!("{}", amenazas::comprobar(&repo)?);
            Ok(())
        }
        Some("arquitectura") => {
            // Las tres puertas se ejecutan siempre y se informa de todas: parar en
            // la primera esconderia las demas hasta la siguiente vuelta.
            let repo = repo::Repo::cargar(&raiz)?;
            let resultados = [
                capas::comprobar(&repo),
                nombres::comprobar(&repo),
                amenazas::comprobar(&repo),
                incrustados::comprobar(&repo),
                invariantes::comprobar(&repo),
                plataformas::comprobar(&repo),
            ];
            let mut fallos = Vec::new();
            for r in resultados {
                match r {
                    Ok(texto) => println!("{texto}"),
                    Err(e) => fallos.push(e.to_string()),
                }
            }
            if fallos.is_empty() {
                Ok(())
            } else {
                Err(fallos.join("\n").into())
            }
        }
        Some("kernels") => {
            let repo = repo::Repo::cargar(&raiz)?;
            let filtro = kernels::Filtro {
                solo: repetida(args, "--solo"),
                arquitectura: opcion(args, "--arquitectura"),
            };
            match args.get(1).map(String::as_str) {
                Some("traer") => kernels::traer(&repo, &filtro),
                Some("ejecutar") => kernels::ejecutar(&repo, &filtro),
                Some("btf") => kernels::btf(&repo, &filtro),
                _ => Err(
                    "uso: cargo xtask kernels (traer|ejecutar|btf) [--solo ID] [--arquitectura ARQ]"
                        .into(),
                ),
            }
        }
        Some("marcador") => {
            let repo = repo::Repo::cargar(&raiz)?;
            println!("{}", marcador::escribir(&repo, tiene("--publicar"))?);
            Ok(())
        }
        Some("sbom") => {
            // FASE 7 del MP-16: el SBOM de cada instalable y, con --dist, el del
            // build con el hash de cada binario y su procedencia.
            let repo = repo::Repo::cargar(&raiz)?;
            let comprobar = tiene("--comprobar");
            let sboms = sbom::calcular_todos(&repo)?;
            if comprobar {
                let d = sbom::diferencias(&repo, &sboms);
                if !d.is_empty() {
                    return Err(format!(
                        "el SBOM versionado no corresponde al Cargo.lock actual:\n    {}\n\
                         Regeneralo con `cargo xtask sbom` (o `cargo xtask docs`) y comitea el resultado.",
                        d.join("\n    ")
                    )
                    .into());
                }
            }
            let mut ficheros = Vec::new();
            for s in &sboms {
                ficheros.push((s.ruta(), sbom::texto(s, None)?));
            }
            docs::escribir(&repo.raiz, &ficheros, comprobar)?;
            println!("{}", sbom::resumen(&sboms));
            if let Some(dir) = opcion(args, "--dist") {
                println!("{}", sbom::dist(&repo, &sboms, &repo.raiz.join(dir))?);
            }
            Ok(())
        }
        Some("instalables") => {
            let inst: config::Instalables = config::leer(&raiz, "instalables.toml")?;
            let ws = opcion(args, "--workspace");
            for i in &inst.instalable {
                if ws.as_ref().is_some_and(|w| *w != i.workspace) {
                    continue;
                }
                let features = if tiene("--hermetico") {
                    match &i.hermetico {
                        Some(f) => f.join(","),
                        None => continue,
                    }
                } else {
                    i.caracteristicas.join(",")
                };
                println!("{}:{}:{}", i.paquete, i.binario, features);
            }
            Ok(())
        }
        Some(otra) => Err(format!("orden desconocida: {otra}\n\n{AYUDA}").into()),
    }
}
