//! Que crates ENLAZA cada ejecutable y cuales INVOCA de verdad.
//!
//! # Enlazar no es invocar
//!
//! Que un crate este en el arbol de dependencias de un binario no significa que
//! su codigo se ejecute. El agente, por ejemplo, declara modulos que envuelven
//! el motor conductual, el de ransomware o el micro-sandbox, pero su bucle
//! principal no los llama: el enlazador los descarta enteros. Contar esos crates
//! como «parte del producto» fue exactamente el error de documentacion que esta
//! fase corrige.
//!
//! Por eso hay dos medidas:
//!
//! - **enlaza**: el cierre de dependencias normales del paquete con las features
//!   del artefacto publicado (`cargo tree -e normal`).
//! - **invoca**: los crates de los que queda CODIGO en el binario compilado con
//!   el perfil `matriz` —el de release (LTO completo, un solo codegen unit) sin
//!   `strip` y con informacion de funciones—. El LTO y `--gc-sections` eliminan
//!   todo lo que no es alcanzable desde `main`, asi que lo que queda es lo que el
//!   programa puede ejecutar. Se mira por dos caminos, porque ninguno basta solo:
//!   los simbolos DEFINIDOS (`nm`) ven las funciones que siguen siendo funciones,
//!   y los espacios de nombres de la informacion de depuracion (`.debug_str`) ven
//!   las que el LTO INLINEO entero, que no dejan simbolo. Sin el segundo, un crate
//!   que se ejecuta en cada arranque —`aegis-kguard` verifica el bytecode antes de
//!   cargarlo— salia como «enlazado sin invocar».

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;

use crate::repo::{cargo, Repo};
use crate::Resultado;

/// Perfil con el que se compilan los binarios que se inspeccionan. Hereda de
/// `release` y solo desactiva el `strip` y activa la informacion de funciones.
pub const PERFIL: &str = "matriz";

/// Cierre de dependencias normales de `paquete` con esas features, restringido
/// a los crates del repositorio.
pub fn cierre(
    repo: &Repo,
    workspace: &str,
    paquete: &str,
    features: &[String],
) -> Resultado<BTreeSet<String>> {
    let mut cmd = Command::new(cargo());
    cmd.args([
        "tree", "-e", "normal", "--prefix", "none", "--format", "{p}",
    ])
    .args(["-p", paquete])
    .arg("--manifest-path")
    .arg(repo.dir_workspace(workspace).join("Cargo.toml"));
    if !features.is_empty() {
        cmd.args(["--features", &features.join(",")]);
    }
    let salida = cmd.output().map_err(|e| format!("cargo tree: {e}"))?;
    if !salida.status.success() {
        return Err(format!(
            "cargo tree -p {paquete}: {}",
            String::from_utf8_lossy(&salida.stderr)
        )
        .into());
    }
    let propios: BTreeSet<&str> = repo.paquetes.iter().map(|p| p.nombre.as_str()).collect();
    Ok(String::from_utf8_lossy(&salida.stdout)
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|n| propios.contains(n))
        .map(str::to_string)
        .collect())
}

/// Compila un binario con el perfil `matriz` y devuelve la ruta del ejecutable.
pub fn compilar_binario(
    repo: &Repo,
    workspace: &str,
    paquete: &str,
    binario: &str,
    features: &[String],
) -> Resultado<PathBuf> {
    let mut cmd = Command::new(cargo());
    cmd.args(["build", "--locked", "--profile", PERFIL])
        .args(["-p", paquete, "--bin", binario]);
    if !features.is_empty() {
        cmd.args(["--features", &features.join(",")]);
    }
    ejecutable_de(repo, workspace, cmd, |t| {
        t["name"] == binario
            && t["kind"]
                .as_array()
                .is_some_and(|k| k.iter().any(|x| x == "bin"))
    })
    .map_err(|e| format!("compilar {binario}: {e}").into())
}

/// Compila (sin ejecutar) una prueba de integracion y devuelve su ejecutable.
pub fn compilar_prueba(
    repo: &Repo,
    workspace: &str,
    paquete: &str,
    prueba: &str,
    features: &[String],
) -> Resultado<PathBuf> {
    let mut cmd = Command::new(cargo());
    cmd.args(["test", "--locked", "--no-run"])
        .args(["-p", paquete, "--test", prueba]);
    if !features.is_empty() {
        cmd.args(["--features", &features.join(",")]);
    }
    ejecutable_de(repo, workspace, cmd, |t| t["name"] == prueba)
        .map_err(|e| format!("compilar la prueba {paquete}/{prueba}: {e}").into())
}

/// Ejecuta un `cargo build`/`cargo test --no-run` con salida JSON y devuelve el
/// ejecutable del artefacto que cumple `es_el`.
fn ejecutable_de(
    repo: &Repo,
    workspace: &str,
    mut cmd: Command,
    es_el: impl Fn(&Value) -> bool,
) -> Resultado<PathBuf> {
    cmd.arg("--manifest-path")
        .arg(repo.dir_workspace(workspace).join("Cargo.toml"))
        .arg("--message-format=json-render-diagnostics")
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut hijo = cmd.spawn().map_err(|e| format!("cargo: {e}"))?;
    let mut ruta = None;
    if let Some(out) = hijo.stdout.take() {
        for linea in BufReader::new(out).lines().map_while(Result::ok) {
            let Ok(v) = serde_json::from_str::<Value>(&linea) else {
                continue;
            };
            if v["reason"] == "compiler-artifact" && es_el(&v["target"]) {
                if let Some(e) = v["executable"].as_str() {
                    ruta = Some(PathBuf::from(e));
                }
            }
        }
    }
    let estado = hijo.wait()?;
    if !estado.success() {
        return Err("la compilacion fallo".into());
    }
    ruta.ok_or_else(|| "cargo no informo del ejecutable".into())
}

/// Crates del repositorio de los que queda codigo en el ejecutable: simbolos
/// definidos, o funciones inlineadas registradas en la informacion de depuracion.
pub fn invocados(repo: &Repo, ejecutable: &Path) -> Resultado<BTreeSet<String>> {
    let simbolos = herramienta(
        Command::new("nm")
            .args(["--demangle", "--defined-only"])
            .arg(ejecutable),
        "nm",
    )?;
    // `.debug_str` guarda, entre otros, el nombre de cada espacio de nombres con
    // funciones en el binario: el de un crate aparece si hay codigo suyo, aunque
    // este todo inlineado. Sin informacion de depuracion la seccion no existe y
    // se sigue solo con los simbolos, lo que se dice.
    let depuracion = herramienta(
        Command::new("readelf")
            .args(["--wide", "--string-dump=.debug_str"])
            .arg(ejecutable),
        "readelf",
    )
    .unwrap_or_default();
    if depuracion.is_empty() {
        eprintln!(
            "xtask: {} no tiene .debug_str: las funciones inlineadas no se ven (perfil sin debug?)",
            ejecutable.display()
        );
    }
    let cadenas: BTreeSet<&str> = depuracion
        .lines()
        .filter_map(|l| l.split_once(']').map(|(_, c)| c.trim()))
        .collect();

    let mut vistos = BTreeSet::new();
    for p in &repo.paquetes {
        let ident = p.ident();
        let ruta = format!("{ident}::");
        if cadenas.contains(ident.as_str()) || simbolos.lines().any(|l| contiene_ruta(l, &ruta)) {
            vistos.insert(p.nombre.clone());
        }
    }
    Ok(vistos)
}

/// Ejecuta una herramienta de binutils y devuelve su salida estandar.
fn herramienta(cmd: &mut Command, nombre: &str) -> Resultado<String> {
    let salida = cmd
        .output()
        .map_err(|e| format!("{nombre} (binutils): {e}"))?;
    if !salida.status.success() {
        return Err(format!("{nombre}: {}", String::from_utf8_lossy(&salida.stderr)).into());
    }
    Ok(String::from_utf8_lossy(&salida.stdout).into_owned())
}

/// `linea` contiene `patron` (`aegis_scan::`) como inicio de ruta, no como cola
/// de otro identificador (`xaegis_scan::`).
fn contiene_ruta(linea: &str, patron: &str) -> bool {
    let mut desde = 0;
    while let Some(i) = linea[desde..].find(patron) {
        let pos = desde + i;
        let previo = linea[..pos].chars().next_back();
        if !previo.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
            return true;
        }
        desde = pos + patron.len();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::contiene_ruta;

    #[test]
    fn una_ruta_de_simbolo_no_es_la_cola_de_otra() {
        assert!(contiene_ruta(
            "aegis_scan::Escaner::escanear",
            "aegis_scan::"
        ));
        assert!(contiene_ruta(
            "<aegis_scan::X as core::fmt::Debug>::fmt",
            "aegis_scan::"
        ));
        assert!(!contiene_ruta("aegis_edgeml::modelo::f", "aegis_ml::"));
        assert!(!contiene_ruta("xaegis_scan::f", "aegis_scan::"));
    }
}
