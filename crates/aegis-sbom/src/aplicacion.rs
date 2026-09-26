//! Las dependencias de aplicacion: lo que ningun gestor de paquetes del sistema
//! conoce.
//!
//! # Manifiesto frente a instalado
//!
//! Un `Cargo.lock` o un `package-lock.json` dicen con que se CONSTRUYO algo; los
//! `*.dist-info/METADATA` de Python dicen que esta INSTALADO. Son dos hechos
//! distintos y se marcan distinto ([`Procedencia::Manifiesto`] frente a
//! [`Procedencia::Instalado`]): un `requirements.txt` olvidado en un directorio
//! no instala nada, y un informe que no lo distingue manda a parchear lo que no
//! esta.
//!
//! # Entrada hostil
//!
//! Estos ficheros los escribe cualquiera con permiso de escritura en el
//! directorio de una aplicacion. Todo lleva tope: tamano de fichero, numero de
//! componentes, profundidad del recorrido y numero de entradas visitadas.

use std::path::{Path, PathBuf};

use crate::componente::{Componente, Ecosistema, Procedencia};

/// Tope de bytes de un manifiesto.
pub const MAX_MANIFIESTO: u64 = 32 * 1024 * 1024;

/// Tope de componentes de un manifiesto.
pub const MAX_COMPONENTES: usize = 50_000;

/// Tope de profundidad del recorrido.
pub const MAX_PROFUNDIDAD: usize = 24;

/// Tope de entradas de directorio visitadas en un recorrido.
pub const MAX_ENTRADAS: usize = 3_000_000;

/// Lee un fichero con tope de tamano.
fn leer(ruta: &Path) -> Option<String> {
    let md = std::fs::metadata(ruta).ok()?;
    if md.len() > MAX_MANIFIESTO {
        return None;
    }
    std::fs::read_to_string(ruta).ok()
}

/// Analiza un `Cargo.lock`.
///
/// Es TOML, pero su forma es fija y la escribe `cargo`: bloques `[[package]]` con
/// `name = "..."` y `version = "..."`. Se analiza esa forma y nada mas, sin un
/// analizador de TOML entero que meter en el agente.
#[must_use]
pub fn cargo_lock(texto: &str, fichero: &Path) -> Vec<Componente> {
    let mut out = Vec::new();
    let mut nombre: Option<String> = None;
    let mut version: Option<String> = None;
    let cerrar = |n: &mut Option<String>, v: &mut Option<String>, out: &mut Vec<Componente>| {
        if let (Some(n), Some(v)) = (n.take(), v.take()) {
            if out.len() < MAX_COMPONENTES {
                out.push(Componente::nuevo(
                    Ecosistema::Cargo,
                    n,
                    v,
                    Procedencia::Manifiesto {
                        fichero: fichero.to_path_buf(),
                    },
                ));
            }
        }
    };
    for linea in texto.lines() {
        let l = linea.trim();
        if l.starts_with('[') {
            cerrar(&mut nombre, &mut version, &mut out);
            continue;
        }
        let Some((k, v)) = l.split_once('=') else {
            continue;
        };
        let v = v.trim().trim_matches('"');
        match k.trim() {
            "name" => nombre = Some(v.to_string()),
            "version" => version = Some(v.to_string()),
            _ => {}
        }
    }
    cerrar(&mut nombre, &mut version, &mut out);
    out
}

/// Analiza un `package-lock.json`, en sus tres versiones de formato.
///
/// Las versiones 2 y 3 traen un mapa `packages` cuyas claves son la ruta en
/// `node_modules` —el nombre es lo que va detras del ultimo `node_modules/`, con
/// su ambito si lo tiene—. La version 1 trae `dependencies` anidado; se recorre
/// con tope de profundidad.
#[must_use]
pub fn package_lock(texto: &str, fichero: &Path) -> Vec<Componente> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(texto) else {
        return Vec::new();
    };
    let proc = || Procedencia::Manifiesto {
        fichero: fichero.to_path_buf(),
    };
    let mut out = Vec::new();
    if let Some(pk) = v.get("packages").and_then(|p| p.as_object()) {
        for (clave, datos) in pk.iter().take(MAX_COMPONENTES) {
            let Some(pos) = clave.rfind("node_modules/") else {
                continue; // "" es el proyecto raiz
            };
            let nombre = &clave[pos + "node_modules/".len()..];
            if let Some(ver) = datos.get("version").and_then(|x| x.as_str()) {
                if !nombre.is_empty() && datos.get("link").and_then(|x| x.as_bool()) != Some(true) {
                    out.push(Componente::nuevo(Ecosistema::Npm, nombre, ver, proc()));
                }
            }
        }
        return out;
    }
    fn v1(
        deps: &serde_json::Map<String, serde_json::Value>,
        prof: usize,
        out: &mut Vec<Componente>,
        proc: &dyn Fn() -> Procedencia,
    ) {
        if prof > MAX_PROFUNDIDAD {
            return;
        }
        for (nombre, datos) in deps {
            if out.len() >= MAX_COMPONENTES {
                return;
            }
            if let Some(ver) = datos.get("version").and_then(|x| x.as_str()) {
                out.push(Componente::nuevo(
                    Ecosistema::Npm,
                    nombre.clone(),
                    ver,
                    proc(),
                ));
            }
            if let Some(d) = datos.get("dependencies").and_then(|x| x.as_object()) {
                v1(d, prof + 1, out, proc);
            }
        }
    }
    if let Some(d) = v.get("dependencies").and_then(|x| x.as_object()) {
        v1(d, 0, &mut out, &proc);
    }
    out
}

/// Analiza un `requirements.txt`: solo lo fijado con `==`.
///
/// Un `requests>=2.0` no dice que version habra instalada; ponerle una seria
/// inventar. Se ignoran comentarios, opciones (`-r`, `--hash`) y marcadores de
/// entorno (lo que va tras `;`).
#[must_use]
pub fn requirements(texto: &str, fichero: &Path) -> Vec<Componente> {
    let mut out = Vec::new();
    for linea in texto.lines().take(MAX_COMPONENTES) {
        let l = linea
            .split('#')
            .next()
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("");
        let l = l.split_whitespace().next().unwrap_or("");
        if l.starts_with('-') {
            continue;
        }
        let Some((nombre, version)) = l.split_once("==") else {
            continue;
        };
        // `paquete[extra]==1.0`: el extra no es parte del nombre.
        let nombre = nombre.split('[').next().unwrap_or(nombre).trim();
        let version = version.trim_start_matches('=').trim();
        if !nombre.is_empty() && !version.is_empty() {
            out.push(Componente::nuevo(
                Ecosistema::PyPI,
                nombre,
                version,
                Procedencia::Manifiesto {
                    fichero: fichero.to_path_buf(),
                },
            ));
        }
    }
    out
}

/// Analiza los metadatos de un paquete de Python instalado (`METADATA`,
/// `PKG-INFO`): cabeceras `Name:` y `Version:` hasta la primera linea en blanco.
#[must_use]
pub fn metadatos_python(texto: &str, fichero: &Path) -> Option<Componente> {
    let mut nombre = None;
    let mut version = None;
    for linea in texto.lines() {
        if linea.is_empty() {
            break;
        }
        if let Some(v) = linea.strip_prefix("Name:") {
            nombre = Some(v.trim().to_string());
        } else if let Some(v) = linea.strip_prefix("Version:") {
            version = Some(v.trim().to_string());
        }
    }
    let mut c = Componente::nuevo(
        Ecosistema::PyPI,
        nombre.filter(|n| !n.is_empty())?,
        version.filter(|v| !v.is_empty())?,
        Procedencia::Instalado {
            fichero: fichero.to_path_buf(),
        },
    );
    // Las extensiones compiladas del paquete son lo unico de el que un proceso
    // puede tener proyectado en memoria: se buscan en el directorio hermano.
    c.ficheros = extensiones_python(fichero);
    Some(c)
}

/// Las extensiones `.so` de un paquete de Python instalado, leidas de su
/// `RECORD`.
fn extensiones_python(metadata: &Path) -> Vec<PathBuf> {
    let Some(dist) = metadata.parent() else {
        return Vec::new();
    };
    let Some(sitio) = dist.parent() else {
        return Vec::new();
    };
    let Some(record) = leer(&dist.join("RECORD")) else {
        return Vec::new();
    };
    record
        .lines()
        .filter_map(|l| l.split(',').next())
        .filter(|r| r.ends_with(".so") && !r.starts_with(".."))
        .take(1024)
        .map(|r| sitio.join(r))
        .collect()
}

/// Que tipo de fichero de dependencias es una ruta, por su nombre.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tipo {
    /// `Cargo.lock`.
    CargoLock,
    /// `package-lock.json`.
    PackageLock,
    /// `requirements*.txt`.
    Requirements,
    /// `*.dist-info/METADATA` o `*.egg-info/PKG-INFO`.
    Python,
}

/// Reconoce un fichero de dependencias por su ruta.
#[must_use]
pub fn tipo_de(ruta: &Path) -> Option<Tipo> {
    let nombre = ruta.file_name()?.to_str()?;
    let padre = ruta
        .parent()
        .and_then(Path::file_name)
        .and_then(|p| p.to_str())
        .unwrap_or("");
    match nombre {
        "Cargo.lock" => Some(Tipo::CargoLock),
        "package-lock.json" => Some(Tipo::PackageLock),
        "METADATA" if padre.ends_with(".dist-info") => Some(Tipo::Python),
        "PKG-INFO" if padre.ends_with(".egg-info") => Some(Tipo::Python),
        n if n.starts_with("requirements") && n.ends_with(".txt") => Some(Tipo::Requirements),
        _ => None,
    }
}

/// Los componentes de un fichero de dependencias.
#[must_use]
pub fn componentes_de(ruta: &Path, tipo: Tipo) -> Vec<Componente> {
    let Some(texto) = leer(ruta) else {
        return Vec::new();
    };
    match tipo {
        Tipo::CargoLock => cargo_lock(&texto, ruta),
        Tipo::PackageLock => package_lock(&texto, ruta),
        Tipo::Requirements => requirements(&texto, ruta),
        Tipo::Python => metadatos_python(&texto, ruta).into_iter().collect(),
    }
}

/// Lo que un recorrido encontro y si se corto.
#[derive(Debug, Clone, Default)]
pub struct Recorrido {
    /// Ficheros de dependencias encontrados.
    pub ficheros: Vec<(PathBuf, Tipo)>,
    /// Si se llego a algun tope: el recorrido NO es completo, y se dice.
    pub cortado: bool,
}

/// Recorre `raiz` buscando ficheros de dependencias.
///
/// No sigue enlaces simbolicos —un bucle de enlaces no puede colgar el
/// inventario, y un enlace a `/` no puede multiplicarlo— y no entra en
/// `excluidos` (los sistemas de ficheros virtuales y los montajes ajenos).
#[must_use]
pub fn recorrer(raiz: &Path, excluidos: &[&Path]) -> Recorrido {
    let mut r = Recorrido::default();
    let mut pila: Vec<(PathBuf, usize)> = vec![(raiz.to_path_buf(), 0)];
    let mut vistas = 0usize;
    while let Some((dir, prof)) = pila.pop() {
        if excluidos.iter().any(|e| dir == *e) {
            continue;
        }
        let Ok(it) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in it.flatten() {
            vistas += 1;
            if vistas > MAX_ENTRADAS {
                r.cortado = true;
                return r;
            }
            let Ok(ft) = e.file_type() else {
                continue;
            };
            let ruta = e.path();
            if ft.is_dir() {
                if prof < MAX_PROFUNDIDAD {
                    pila.push((ruta, prof + 1));
                } else {
                    r.cortado = true;
                }
            } else if ft.is_file() {
                if let Some(t) = tipo_de(&ruta) {
                    r.ficheros.push((ruta, t));
                }
            }
        }
    }
    r.ficheros.sort_by(|a, b| a.0.cmp(&b.0));
    r
}

#[cfg(test)]
mod pruebas {
    use super::*;

    const F: &str = "/app/x";

    #[test]
    fn cargo_lock_real() {
        // Forma exacta de un Cargo.lock de version 3.
        let t = "# This file is automatically @generated by Cargo.\nversion = 3\n\n\
                 [[package]]\nname = \"libc\"\nversion = \"0.2.153\"\n\
                 source = \"registry+https://github.com/rust-lang/crates.io-index\"\n\
                 checksum = \"abc\"\n\n[[package]]\nname = \"miapp\"\nversion = \"0.1.0\"\n\
                 dependencies = [\n \"libc\",\n]\n";
        let v = cargo_lock(t, Path::new(F));
        let pares: Vec<(&str, &str)> = v
            .iter()
            .map(|c| (c.nombre.as_str(), c.version.as_str()))
            .collect();
        assert_eq!(pares, [("libc", "0.2.153"), ("miapp", "0.1.0")]);
    }

    #[test]
    fn package_lock_v3_con_ambito_y_anidado() {
        let t = r#"{"lockfileVersion":3,"packages":{
            "":{"name":"app","version":"1.0.0"},
            "node_modules/@babel/core":{"version":"7.24.0"},
            "node_modules/a/node_modules/lodash":{"version":"4.17.20"},
            "node_modules/enlazado":{"link":true,"version":"9.9.9"}}}"#;
        let v = package_lock(t, Path::new(F));
        let pares: Vec<(&str, &str)> = v
            .iter()
            .map(|c| (c.nombre.as_str(), c.version.as_str()))
            .collect();
        assert_eq!(pares, [("@babel/core", "7.24.0"), ("lodash", "4.17.20")]);
    }

    #[test]
    fn package_lock_v1_anidado_con_tope() {
        // Un anidamiento profundo se corta en NUESTRO tope. Cincuenta niveles
        // son cien objetos JSON: por debajo del limite de recursion de
        // `serde_json` (128), para que lo que se mida sea este tope y no aquel.
        let mut t = String::from(r#"{"dependencies":"#);
        for _ in 0..50 {
            t.push_str(r#"{"x":{"version":"1.0.0","dependencies":"#);
        }
        t.push_str("{}");
        for _ in 0..50 {
            t.push_str("}}");
        }
        t.push('}');
        let v = package_lock(&t, Path::new(F));
        assert_eq!(
            v.len(),
            MAX_PROFUNDIDAD + 1,
            "se leen los niveles 0..=tope y ni uno mas"
        );
    }

    #[test]
    fn requirements_solo_lo_fijado() {
        let t = "# comentario\nrequests==2.31.0\nflask>=2\nDjango[bcrypt]==4.2.1 ; python_version>'3'\n\
                 -r otro.txt\nurllib3 == 1.26.18 # fijado\n";
        let v = requirements(t, Path::new(F));
        let pares: Vec<(&str, &str)> = v
            .iter()
            .map(|c| (c.nombre.as_str(), c.version.as_str()))
            .collect();
        assert_eq!(pares, [("requests", "2.31.0"), ("Django", "4.2.1")]);
    }

    #[test]
    fn metadatos_de_python_hasta_la_linea_en_blanco() {
        let t = "Metadata-Version: 2.1\nName: jaraco.functools\nVersion: 4.1.0\n\n\
                 Version: esto es la descripcion\n";
        let c =
            metadatos_python(t, Path::new("/x/jaraco_functools-4.1.0.dist-info/METADATA")).unwrap();
        assert_eq!(
            (c.nombre.as_str(), c.version.as_str()),
            ("jaraco.functools", "4.1.0")
        );
        assert_eq!(c.purl(), "pkg:pypi/jaraco-functools@4.1.0");
    }

    #[test]
    fn se_reconoce_cada_fichero_por_su_nombre() {
        assert_eq!(tipo_de(Path::new("/a/Cargo.lock")), Some(Tipo::CargoLock));
        assert_eq!(
            tipo_de(Path::new("/a/x-1.0.dist-info/METADATA")),
            Some(Tipo::Python)
        );
        assert_eq!(tipo_de(Path::new("/a/METADATA")), None);
        assert_eq!(
            tipo_de(Path::new("/a/requirements-dev.txt")),
            Some(Tipo::Requirements)
        );
    }
}
