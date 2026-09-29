//! Inventario del repositorio: los tres workspaces, sus crates y sus fuentes.
//!
//! Todo sale de `cargo metadata`, no de listas escritas a mano: si manana se
//! anade un crate, aparece aqui sin tocar nada, y las puertas que exigen que
//! este clasificado (capas, nombres, matriz) fallan hasta que alguien decida
//! donde va.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

use crate::Resultado;

/// Los workspaces del repositorio: (nombre, directorio relativo a la raiz).
pub const WORKSPACES: [(&str, &str); 3] = [
    ("agente", "."),
    ("servidor", "server"),
    ("enjambre", "swarm-net"),
];

/// Un crate del repositorio.
#[derive(Debug, Clone)]
pub struct Paquete {
    /// Nombre de paquete (`aegis-scan`).
    pub nombre: String,
    /// Workspace al que pertenece.
    pub workspace: &'static str,
    /// Directorio, relativo a la raiz del repositorio.
    pub dir: PathBuf,
    /// `description` del Cargo.toml.
    pub descripcion: String,
    /// Dependencias normales internas (path), por nombre.
    pub deps: BTreeSet<String>,
}

impl Paquete {
    /// Identificador de Rust del crate (`aegis_scan`).
    pub fn ident(&self) -> String {
        self.nombre.replace('-', "_")
    }
}

/// El repositorio entero.
#[derive(Debug)]
pub struct Repo {
    /// Raiz del repositorio.
    pub raiz: PathBuf,
    /// Todos los crates de los tres workspaces, ordenados por nombre.
    pub paquetes: Vec<Paquete>,
}

impl Repo {
    /// Carga el inventario con `cargo metadata`.
    pub fn cargar(raiz: &Path) -> Resultado<Self> {
        let raiz = raiz
            .canonicalize()
            .map_err(|e| format!("raiz {}: {e}", raiz.display()))?;
        let mut paquetes = Vec::new();
        for (ws, dir) in WORKSPACES {
            let manifiesto = raiz.join(dir).join("Cargo.toml");
            let salida = Command::new(cargo())
                .args(["metadata", "--format-version", "1", "--no-deps"])
                .arg("--manifest-path")
                .arg(&manifiesto)
                .output()
                .map_err(|e| format!("cargo metadata: {e}"))?;
            if !salida.status.success() {
                return Err(format!(
                    "cargo metadata ({ws}): {}",
                    String::from_utf8_lossy(&salida.stderr)
                )
                .into());
            }
            let meta: Value = serde_json::from_slice(&salida.stdout)?;
            for p in meta["packages"].as_array().into_iter().flatten() {
                let manifiesto = PathBuf::from(p["manifest_path"].as_str().unwrap_or_default());
                let dir_abs = manifiesto
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_default();
                let dir_rel = dir_abs
                    .canonicalize()
                    .ok()
                    .and_then(|d| d.strip_prefix(&raiz).ok().map(Path::to_path_buf))
                    .unwrap_or(dir_abs);
                let deps = p["dependencies"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|d| d["kind"].is_null() && d["path"].is_string())
                    .filter_map(|d| d["name"].as_str().map(str::to_string))
                    .collect();
                paquetes.push(Paquete {
                    nombre: p["name"].as_str().unwrap_or_default().to_string(),
                    workspace: ws,
                    dir: dir_rel,
                    descripcion: p["description"].as_str().unwrap_or_default().to_string(),
                    deps,
                });
            }
        }
        paquetes.sort_by(|a, b| a.nombre.cmp(&b.nombre));
        Ok(Repo { raiz, paquetes })
    }

    /// Busca un crate por nombre.
    pub fn paquete(&self, nombre: &str) -> Option<&Paquete> {
        self.paquetes.iter().find(|p| p.nombre == nombre)
    }

    /// Directorio absoluto de un workspace.
    pub fn dir_workspace(&self, ws: &str) -> PathBuf {
        let rel = WORKSPACES
            .iter()
            .find(|(n, _)| *n == ws)
            .map(|(_, d)| *d)
            .unwrap_or(".");
        self.raiz.join(rel)
    }
}

/// El `cargo` con el que se invoco a xtask (respeta el toolchain elegido).
pub fn cargo() -> String {
    std::env::var("CARGO").unwrap_or_else(|_| "cargo".into())
}

/// Ficheros `.rs` bajo `dir`, sin entrar en `target/`, ordenados.
pub fn fuentes_rust(dir: &Path) -> Vec<PathBuf> {
    let mut v = Vec::new();
    recorrer(dir, &mut v, &|p| p.extension().is_some_and(|e| e == "rs"));
    v.sort();
    v
}

/// Recorre `dir` recogiendo los ficheros que cumplen `filtro`.
pub fn recorrer(dir: &Path, v: &mut Vec<PathBuf>, filtro: &dyn Fn(&Path) -> bool) {
    let Ok(entradas) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entradas.flatten() {
        let p = e.path();
        let nombre = e.file_name();
        if p.is_dir() {
            if nombre != "target" && nombre != ".git" && nombre != "node_modules" {
                recorrer(&p, v, filtro);
            }
        } else if filtro(&p) {
            v.push(p);
        }
    }
}

/// Numero de funciones de prueba de un crate (`#[test]` y sus variantes
/// asincronas), contadas en sus fuentes.
pub fn contar_pruebas(dir: &Path) -> usize {
    fuentes_rust(dir)
        .iter()
        .filter_map(|f| std::fs::read_to_string(f).ok())
        .map(|t| {
            t.lines()
                .map(str::trim_start)
                .filter(|l| {
                    l.starts_with("#[test]")
                        || l.starts_with("#[tokio::test")
                        || l.starts_with("#[sqlx::test")
                })
                .count()
        })
        .sum()
}

/// Lineas de codigo Rust de un directorio (sin `target/`).
pub fn contar_lineas(dir: &Path) -> usize {
    fuentes_rust(dir)
        .iter()
        .filter_map(|f| std::fs::read_to_string(f).ok())
        .map(|t| t.lines().count())
        .sum()
}

/// Ruta relativa a la raiz, con barras `/`, para enlaces de Markdown.
pub fn relativa(raiz: &Path, p: &Path) -> String {
    p.strip_prefix(raiz)
        .unwrap_or(p)
        .to_string_lossy()
        .replace('\\', "/")
}
