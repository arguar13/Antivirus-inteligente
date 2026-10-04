//! `cargo xtask sbom`: la lista de materiales (SBOM) de cada instalable.
//!
//! # Que se genera
//!
//! Un documento CycloneDX 1.5 JSON por ejecutable de
//! `tools/config/instalables.toml`, en `docs/generado/auditoria/sbom/`. Sale de
//! dos fuentes y de ninguna otra:
//!
//! - `cargo tree --locked`, con las features y el objetivo del artefacto que se
//!   publica: que crates entran y quien depende de quien. Con `-e normal` se
//!   sabe lo que llega al binario (sin bajar por las macros procedurales, que
//!   solo corren al compilar); con `-e normal,build`, ademas lo que solo corre
//!   al compilar. Lo segundo va con `scope: excluded`.
//! - `Cargo.lock`: el origen y la suma SHA-256 de cada crate de terceros.
//!
//! Ademas, lo que cargo no ve y el codigo si dice: los ficheros que los crates
//! del binario incrustan (`include_bytes!`), y el codigo C o de sistema que
//! declara `tools/config/auditoria.toml`, cada uno con su condicion.
//!
//! No usa `cargo-cyclonedx` ni otra herramienta externa: el formato es simple,
//! y una herramienta mas en el runner es una dependencia mas que auditar.
//!
//! # La puerta
//!
//! `--comprobar` regenera en memoria y compara con lo versionado. Falla si un
//! crate entra o sale del arbol de un instalable sin regenerar (el SBOM ya no
//! corresponde al `Cargo.lock`), si cambia cualquier otro dato, o si un crate no
//! declara licencia. `--locked` hace que cargo falle ademas si el `Cargo.lock`
//! no corresponde a los manifiestos.
//!
//! # Lo que no puede estar versionado
//!
//! El SHA-256 de cada binario depende del constructor: la reproducibilidad solo
//! se comprueba en la misma maquina (grupo `reproducible` de make ci, H-06). Por
//! eso el SBOM versionado no lo lleva, y `--dist` escribe JUNTO
//! a los binarios una copia con su hash y la procedencia del build (declaracion
//! in-toto v1 con predicado SLSA v1, sin firmar). Antes de escribir nada
//! comprueba que esos binarios salen de este arbol (HUELLA) y que coinciden con
//! su `SHA256SUMS`: una procedencia de otro arbol seria una procedencia falsa.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use serde_json::{json, Value};

use crate::config::{self, Auditoria, ComponenteSistema, Instalable, Instalables, Vendorizado};
use crate::repo::{self, cargo, Repo};
use crate::Resultado;

/// Directorio de los SBOM versionados.
pub const DIR: &str = "docs/generado/auditoria/sbom";
/// Version de la especificacion CycloneDX.
const ESPECIFICACION: &str = "1.5";
/// El indice de crates.io, en sus dos formas.
const CRATES_IO: [&str; 2] = [
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
];
/// Tipo de build de la procedencia: el guion hermetico, version 1.
const TIPO_DE_BUILD: &str = "urn:aegiscore:construccion:hermetico:v1";

// ── Cargo.lock ──────────────────────────────────────────────────────────────

/// `Cargo.lock`, lo que interesa de el.
#[derive(Debug, Deserialize)]
struct Lock {
    #[serde(default)]
    package: Vec<PaqueteLock>,
}

/// Un paquete del `Cargo.lock`.
#[derive(Debug, Clone, Deserialize)]
struct PaqueteLock {
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
}

/// Paquetes del lock por (nombre, version).
type IndiceLock = BTreeMap<(String, String), PaqueteLock>;

fn cargar_lock(repo: &Repo, workspace: &str) -> Resultado<IndiceLock> {
    let ruta = repo.dir_workspace(workspace).join("Cargo.lock");
    let texto = std::fs::read_to_string(&ruta).map_err(|e| format!("{}: {e}", ruta.display()))?;
    let lock: Lock = toml::from_str(&texto).map_err(|e| format!("{}: {e}", ruta.display()))?;
    let mut m = IndiceLock::new();
    for p in lock.package {
        let clave = (p.name.clone(), p.version.clone());
        if m.insert(clave.clone(), p).is_some() {
            return Err(format!(
                "{}: {} {} aparece dos veces, de dos origenes: el SBOM no sabria cual entra",
                ruta.display(),
                clave.0,
                clave.1
            )
            .into());
        }
    }
    Ok(m)
}

// ── El modelo ───────────────────────────────────────────────────────────────

/// Un crate del arbol de un instalable.
#[derive(Debug, Clone)]
pub struct Componente {
    /// Nombre del paquete.
    pub nombre: String,
    /// Version.
    pub version: String,
    /// Expresion SPDX; vacia si el crate no declara licencia.
    pub licencia: String,
    /// `source` del lock; `None` para los crates del repositorio.
    pub origen: Option<String>,
    /// SHA-256 del `.crate`, del lock.
    pub suma: Option<String>,
    /// Llega al binario: alcanzable por aristas normales sin pasar por una
    /// macro procedural.
    pub en_ejecucion: bool,
    /// Es una macro procedural.
    pub proc_macro: bool,
    /// `ejecucion`, `macro procedural` o `build.rs`.
    pub uso: &'static str,
}

impl Componente {
    /// Identificador del componente en el SBOM: el purl para los de terceros.
    pub fn referencia(&self) -> String {
        self.purl()
            .unwrap_or_else(|| format!("repo:{}@{}", self.nombre, self.version))
    }

    fn purl(&self) -> Option<String> {
        let o = self.origen.as_deref()?;
        // La version va codificada: `libbpf-sys 1.7.0+v1.7.0` lleva un `+`.
        let version = porcentaje(&self.version);
        if CRATES_IO.contains(&o) {
            Some(format!("pkg:cargo/{}@{version}", self.nombre))
        } else {
            Some(format!(
                "pkg:cargo/{}@{version}?repository_url={}",
                self.nombre,
                porcentaje(o)
            ))
        }
    }

    fn origen_legible(&self) -> String {
        match self.origen.as_deref() {
            None => "repositorio".into(),
            Some(o) if CRATES_IO.contains(&o) => "crates.io".into(),
            Some(o) => o.to_string(),
        }
    }
}

/// Un fichero que un crate del binario incrusta al compilar.
#[derive(Debug, Clone)]
pub struct Incrustado {
    /// Nombre del fichero.
    pub nombre: String,
    /// Ruta en el repositorio; `None` si lo genera `build.rs` en `OUT_DIR`.
    pub ruta: Option<String>,
    /// Crate que lo incrusta.
    pub krate: String,
    /// SHA-256 del fichero versionado.
    pub suma: Option<String>,
}

/// El SBOM de un instalable.
#[derive(Debug)]
pub struct Sbom {
    /// El instalable.
    pub instalable: Instalable,
    /// Triple para el que se resuelve el arbol.
    pub objetivo: String,
    /// Features con las que se construye.
    pub caracteristicas: Vec<String>,
    /// El crate que define el binario.
    pub raiz: Componente,
    /// El resto de crates, por referencia.
    pub componentes: BTreeMap<String, Componente>,
    /// Quien depende de quien, por referencia.
    pub aristas: BTreeMap<String, BTreeSet<String>>,
    /// Ficheros incrustados.
    pub incrustados: Vec<Incrustado>,
    /// Codigo C que un crate lleva dentro.
    pub vendorizados: Vec<Vendorizado>,
    /// Bibliotecas de sistema enlazadas (std de Rust, libc...).
    pub sistema: Vec<ComponenteSistema>,
}

impl Sbom {
    /// Si se publica como binario hermetico.
    pub fn es_hermetico(&self) -> bool {
        self.instalable.hermetico.is_some()
    }

    /// Ruta del SBOM versionado, relativa a la raiz.
    pub fn ruta(&self) -> PathBuf {
        PathBuf::from(DIR).join(format!("{}.cdx.json", self.instalable.binario))
    }

    /// Crates que llegan al binario (sin contar la raiz).
    pub fn en_ejecucion(&self) -> usize {
        self.componentes.values().filter(|c| c.en_ejecucion).count()
    }

    /// Crates que solo corren al compilar.
    pub fn de_construccion(&self) -> usize {
        self.componentes
            .values()
            .filter(|c| !c.en_ejecucion)
            .count()
    }

    /// Licencias distintas del arbol.
    pub fn licencias(&self) -> BTreeSet<&str> {
        std::iter::once(&self.raiz)
            .chain(self.componentes.values())
            .map(|c| c.licencia.as_str())
            .collect()
    }
}

// ── Calculo ─────────────────────────────────────────────────────────────────

/// El SBOM de cada instalable. Falla si algun crate no declara licencia o si
/// una declaracion de `auditoria.toml` no aplica a nada.
pub fn calcular_todos(repo: &Repo) -> Resultado<Vec<Sbom>> {
    let inst: Instalables = config::leer(&repo.raiz, "instalables.toml")?;
    let aud: Auditoria = config::leer(&repo.raiz, "auditoria.toml")?;
    let mut locks: BTreeMap<String, IndiceLock> = BTreeMap::new();
    let mut sboms = Vec::new();
    for i in &inst.instalable {
        let lock = match locks.entry(i.workspace.clone()) {
            Entry::Occupied(o) => o.into_mut(),
            Entry::Vacant(v) => v.insert(cargar_lock(repo, &i.workspace)?),
        };
        eprintln!("xtask: SBOM de {}", i.binario);
        sboms.push(calcular(repo, &aud, i, lock)?);
    }

    let mut problemas = Vec::new();
    let mut sin_licencia = BTreeSet::new();
    for s in &sboms {
        for c in std::iter::once(&s.raiz).chain(s.componentes.values()) {
            if c.licencia.is_empty() {
                sin_licencia.insert(format!("{} {}", c.nombre, c.version));
            }
        }
    }
    if !sin_licencia.is_empty() {
        problemas.push(format!(
            "crates sin licencia declarada (un SBOM sin licencia no le sirve al auditor): {}",
            sin_licencia.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    for v in &aud.vendorizado {
        if let Some(e) = &v.evidencia {
            if let Err(err) = e.comprobar(&repo.raiz) {
                problemas.push(format!("[[vendorizado]] {}: {err}", v.nombre));
            }
        }
        let aplica = sboms.iter().any(|s| {
            s.vendorizados
                .iter()
                .any(|x| x.krate == v.krate && x.nombre == v.nombre)
        });
        if !aplica {
            problemas.push(format!(
                "[[vendorizado]] {} (en {}) no aplica a ningun instalable: la declaracion esta muerta, borrala",
                v.nombre, v.krate
            ));
        }
    }
    if problemas.is_empty() {
        Ok(sboms)
    } else {
        Err(format!("sbom:\n    {}", problemas.join("\n    ")).into())
    }
}

/// Una linea de `cargo tree --prefix depth --format "{l}|{p}"`.
#[derive(Debug, PartialEq)]
struct Linea {
    profundidad: usize,
    licencia: String,
    nombre: String,
    version: String,
    proc_macro: bool,
}

/// `0MIT OR Apache-2.0|serde v1.0.219` -> Linea. El `(*)` de las repeticiones
/// y el origen de los crates que no son de crates.io se ignoran: el origen se
/// toma del lock, no de una ruta que puede llevar espacios.
fn parsear_linea(l: &str) -> Option<Linea> {
    let digitos = l.chars().take_while(char::is_ascii_digit).count();
    if digitos == 0 {
        return None;
    }
    let profundidad = l[..digitos].parse::<usize>().ok()?;
    let (licencia, paquete) = l[digitos..].split_once('|')?;
    let mut t = paquete.split_whitespace();
    let nombre = t.next()?.to_string();
    let version = t.next()?.strip_prefix('v')?.to_string();
    Some(Linea {
        profundidad,
        licencia: licencia.trim().to_string(),
        nombre,
        version,
        proc_macro: paquete.contains("(proc-macro)"),
    })
}

/// `MIT/Apache-2.0` (forma antigua de cargo) -> `MIT OR Apache-2.0`.
fn normalizar_licencia(l: &str) -> String {
    l.split('/')
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .collect::<Vec<_>>()
        .join(" OR ")
}

/// Ejecuta `cargo tree` para un instalable.
fn arbol(
    repo: &Repo,
    inst: &Instalable,
    caracteristicas: &[String],
    objetivo: &str,
    aristas: &str,
) -> Resultado<Vec<Linea>> {
    let mut cmd = Command::new(cargo());
    cmd.args(["tree", "--locked", "-e", aristas, "--prefix", "depth"])
        .args(["--format", "{l}|{p}", "--target", objetivo])
        .args(["-p", inst.paquete.as_str()])
        .arg("--manifest-path")
        .arg(repo.dir_workspace(&inst.workspace).join("Cargo.toml"));
    if !caracteristicas.is_empty() {
        let f = caracteristicas.join(",");
        cmd.args(["--features", f.as_str()]);
    }
    let salida = cmd.output().map_err(|e| format!("cargo tree: {e}"))?;
    if !salida.status.success() {
        return Err(format!(
            "cargo tree -p {} -e {aristas}: {}\n(con --locked esto falla tambien si el Cargo.lock \
             no corresponde a los manifiestos)",
            inst.paquete,
            String::from_utf8_lossy(&salida.stderr)
        )
        .into());
    }
    let lineas: Vec<Linea> = String::from_utf8_lossy(&salida.stdout)
        .lines()
        .filter_map(parsear_linea)
        .collect();
    if lineas.is_empty() {
        return Err(format!("cargo tree -p {} no devolvio ningun paquete", inst.paquete).into());
    }
    Ok(lineas)
}

/// El grafo que describe una salida de `cargo tree`.
struct Grafo {
    raiz: Componente,
    nodos: BTreeMap<String, Componente>,
    aristas: BTreeMap<String, BTreeSet<String>>,
}

fn grafo(lineas: &[Linea], lock: &IndiceLock, inst: &Instalable) -> Resultado<Grafo> {
    let mut raiz: Option<Componente> = None;
    let mut nodos = BTreeMap::new();
    let mut aristas: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut pila: Vec<String> = Vec::new();
    for l in lineas {
        let pl = lock
            .get(&(l.nombre.clone(), l.version.clone()))
            .ok_or_else(|| {
                format!(
                    "{}: cargo tree cita {} {}, que no esta en el Cargo.lock del workspace {}",
                    inst.binario, l.nombre, l.version, inst.workspace
                )
            })?;
        let c = Componente {
            nombre: l.nombre.clone(),
            version: l.version.clone(),
            licencia: normalizar_licencia(&l.licencia),
            origen: pl.source.clone(),
            suma: pl.checksum.clone(),
            en_ejecucion: false,
            proc_macro: l.proc_macro,
            uso: "build.rs",
        };
        let r = c.referencia();
        if l.profundidad > pila.len() {
            return Err(format!(
                "cargo tree: salto de profundidad en {} {} (salida inesperada)",
                l.nombre, l.version
            )
            .into());
        }
        pila.truncate(l.profundidad);
        if let Some(padre) = pila.last() {
            aristas.entry(padre.clone()).or_default().insert(r.clone());
        }
        pila.push(r.clone());
        if l.profundidad == 0 {
            if raiz.is_some() {
                return Err("cargo tree devolvio mas de una raiz".into());
            }
            raiz = Some(c);
        } else {
            nodos.entry(r).or_insert(c);
        }
    }
    let raiz = raiz.ok_or("cargo tree no devolvio la raiz")?;
    if raiz.nombre != inst.paquete {
        return Err(format!(
            "cargo tree -p {} devolvio como raiz {}",
            inst.paquete, raiz.nombre
        )
        .into());
    }
    Ok(Grafo {
        raiz,
        nodos,
        aristas,
    })
}

fn calcular(repo: &Repo, aud: &Auditoria, inst: &Instalable, lock: &IndiceLock) -> Resultado<Sbom> {
    // Lo que se publica: el hermetico si lo hay, con su objetivo musl.
    let (caracteristicas, objetivo) = match &inst.hermetico {
        Some(f) => (f.clone(), aud.sbom.objetivo_hermetico.clone()),
        None => (
            inst.caracteristicas.clone(),
            aud.sbom.objetivo_nativo.clone(),
        ),
    };
    let normal = grafo(
        &arbol(repo, inst, &caracteristicas, &objetivo, "normal")?,
        lock,
        inst,
    )?;
    let completo = grafo(
        &arbol(repo, inst, &caracteristicas, &objetivo, "normal,build")?,
        lock,
        inst,
    )?;

    // Llega al binario lo alcanzable por aristas normales SIN pasar por una
    // macro procedural: la macro y lo que solo ella usa corren en el
    // compilador, no en la maquina del cliente.
    let raiz_ref = normal.raiz.referencia();
    let mut ejecucion = BTreeSet::new();
    let mut pendientes = vec![raiz_ref];
    while let Some(r) = pendientes.pop() {
        for h in normal.aristas.get(&r).into_iter().flatten() {
            let es_macro = normal.nodos.get(h).is_some_and(|c| c.proc_macro);
            if !es_macro && ejecucion.insert(h.clone()) {
                pendientes.push(h.clone());
            }
        }
    }

    let mut raiz = completo.raiz;
    raiz.en_ejecucion = true;
    raiz.uso = "ejecucion";
    let mut componentes = completo.nodos;
    for (r, c) in componentes.iter_mut() {
        c.en_ejecucion = ejecucion.contains(r);
        c.uso = if c.en_ejecucion {
            "ejecucion"
        } else if normal.nodos.contains_key(r) {
            "macro procedural"
        } else {
            "build.rs"
        };
    }
    if let Some(falta) = ejecucion.iter().find(|r| !componentes.contains_key(*r)) {
        return Err(format!(
            "{}: {falta} esta en el arbol normal y no en el completo (cargo tree incoherente)",
            inst.binario
        )
        .into());
    }

    // Lo que incrustan los crates del repositorio que llegan al binario.
    let mut incrustados = Vec::new();
    let mut vistos = BTreeSet::new();
    let propios = std::iter::once(&raiz)
        .chain(componentes.values())
        .filter(|c| c.origen.is_none() && c.en_ejecucion);
    for c in propios {
        for i in incrustados_de(repo, &c.nombre)? {
            if vistos.insert((i.krate.clone(), i.nombre.clone())) {
                incrustados.push(i);
            }
        }
    }

    let vendorizados = aud
        .vendorizado
        .iter()
        .filter(|v| componentes.values().any(|c| c.nombre == v.krate))
        .filter(|v| {
            v.exige_caracteristica
                .as_ref()
                .is_none_or(|f| caracteristicas.contains(f))
        })
        .cloned()
        .collect();

    let mut sistema = Vec::new();
    for c in &aud.sistema {
        match c.aplica.as_str() {
            "todos" => sistema.push(c.clone()),
            "hermetico" => {
                if inst.hermetico.is_some() {
                    sistema.push(c.clone());
                }
            }
            otro => {
                return Err(format!(
                    "auditoria.toml: [[sistema]] {}: aplica = «{otro}»; validos: todos, hermetico",
                    c.nombre
                )
                .into())
            }
        }
    }

    Ok(Sbom {
        instalable: inst.clone(),
        objetivo,
        caracteristicas,
        raiz,
        componentes,
        aristas: completo.aristas,
        incrustados,
        vendorizados,
        sistema,
    })
}

/// Los ficheros que incrusta un crate del repositorio, fuera de sus pruebas.
fn incrustados_de(repo: &Repo, krate: &str) -> Resultado<Vec<Incrustado>> {
    let Some(p) = repo.paquete(krate) else {
        return Ok(Vec::new());
    };
    let mut v = Vec::new();
    for f in repo::fuentes_rust(&repo.raiz.join(&p.dir).join("src")) {
        let Ok(texto) = std::fs::read_to_string(&f) else {
            continue;
        };
        // Lo que viene detras de `#[cfg(test)]` son pruebas: no llega al binario.
        let producto = texto.split("#[cfg(test)]").next().unwrap_or_default();
        for macro_ in ["include_bytes!(", "include_str!("] {
            for (i, _) in producto.match_indices(macro_) {
                let resto = producto[i + macro_.len()..].trim_start();
                if let Some(literal) = resto.strip_prefix('"') {
                    let Some(fin) = literal.find('"') else {
                        continue;
                    };
                    let ruta = normalizar(repo, &f, &literal[..fin]);
                    let nombre = ruta.rsplit('/').next().unwrap_or_default().to_string();
                    let suma = sha256(&repo.raiz.join(&ruta))?;
                    v.push(Incrustado {
                        nombre,
                        ruta: Some(ruta),
                        krate: krate.to_string(),
                        suma: Some(suma),
                    });
                } else if resto.starts_with("concat!(") {
                    // Salida de build.rs: el ultimo literal de la linea es el nombre.
                    let linea = resto.lines().next().unwrap_or_default();
                    let nombre = linea
                        .rsplit('"')
                        .nth(1)
                        .unwrap_or_default()
                        .trim_start_matches('/')
                        .to_string();
                    if !nombre.is_empty() {
                        v.push(Incrustado {
                            nombre,
                            ruta: None,
                            krate: krate.to_string(),
                            suma: None,
                        });
                    }
                }
            }
        }
    }
    Ok(v)
}

/// Ruta de un `include_bytes!` relativa a la raiz, sin `..`.
fn normalizar(repo: &Repo, fichero: &Path, rel: &str) -> String {
    let base = fichero.parent().unwrap_or(Path::new("."));
    let r = repo::relativa(&repo.raiz, &base.join(rel));
    let mut partes: Vec<&str> = Vec::new();
    for c in r.split('/') {
        match c {
            ".." => {
                partes.pop();
            }
            "." | "" => {}
            otro => partes.push(otro),
        }
    }
    partes.join("/")
}

/// SHA-256 de un fichero con `sha256sum` (coreutils, ya exigido por el build
/// hermetico). Sin dependencia nueva en xtask.
pub fn sha256(fichero: &Path) -> Resultado<String> {
    let salida = Command::new("sha256sum")
        .arg(fichero)
        .output()
        .map_err(|e| format!("sha256sum (coreutils): {e}"))?;
    if !salida.status.success() {
        return Err(format!(
            "sha256sum {}: {}",
            fichero.display(),
            String::from_utf8_lossy(&salida.stderr)
        )
        .into());
    }
    let texto = String::from_utf8_lossy(&salida.stdout);
    match texto.split_whitespace().next() {
        Some(h) if h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()) => Ok(h.to_string()),
        _ => Err(format!("sha256sum {}: salida inesperada", fichero.display()).into()),
    }
}

/// Codificacion por porcentaje para un calificador de purl.
fn porcentaje(s: &str) -> String {
    let mut r = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            r.push(b as char);
        } else {
            r.push_str(&format!("%{b:02X}"));
        }
    }
    r
}

// ── CycloneDX ───────────────────────────────────────────────────────────────

/// Lo que solo existe despues de un build: el binario y su procedencia.
pub struct Artefacto<'a> {
    /// SHA-256 del binario, si se publica hermetico.
    pub sha256: Option<String>,
    /// `MANIFIESTO.txt`, por clave.
    pub manifiesto: &'a BTreeMap<String, String>,
    /// Huella del arbol del que salen.
    pub huella: String,
    /// Version medida de cada componente de sistema, por `version_de`.
    pub versiones: &'a BTreeMap<String, String>,
}

fn prop(nombre: &str, valor: impl Into<String>) -> Value {
    let valor: String = valor.into();
    json!({ "name": nombre, "value": valor })
}

fn licencias(l: &str) -> Value {
    if l.is_empty() {
        json!([])
    } else {
        json!([{ "expression": l }])
    }
}

fn json_componente(c: &Componente) -> Value {
    let mut props = vec![
        prop("aegis:origen", c.origen_legible()),
        prop("aegis:uso", c.uso),
    ];
    if c.proc_macro {
        props.push(prop("aegis:proc-macro", "si"));
    }
    let alcance = if c.en_ejecucion {
        "required"
    } else {
        "excluded"
    };
    let mut v = json!({
        "type": "library",
        "bom-ref": c.referencia(),
        "name": c.nombre,
        "version": c.version,
        "scope": alcance,
        "licenses": licencias(&c.licencia),
        "properties": props
    });
    if let Some(p) = c.purl() {
        v["purl"] = json!(p);
    }
    if let Some(h) = &c.suma {
        v["hashes"] = json!([{ "alg": "SHA-256", "content": h }]);
    }
    v
}

fn ref_incrustado(i: &Incrustado) -> String {
    format!("incrustado:{}/{}", i.krate, i.nombre)
}

fn ref_vendorizado(v: &Vendorizado) -> String {
    format!("vendorizado:{}/{}", v.krate, v.nombre)
}

fn ref_sistema(c: &ComponenteSistema) -> String {
    format!("sistema:{}", c.nombre)
}

/// El documento CycloneDX. Sin `serialNumber` ni `timestamp` A PROPOSITO: son
/// opcionales, y uno aleatorio haria que la puerta no pudiera comparar.
fn documento(s: &Sbom, a: Option<&Artefacto>) -> Value {
    let raiz_ref = s.raiz.referencia();
    let mut componentes: Vec<Value> = s.componentes.values().map(json_componente).collect();
    let mut de_la_raiz: Vec<String> = s
        .aristas
        .get(&raiz_ref)
        .into_iter()
        .flatten()
        .cloned()
        .collect();

    for i in &s.incrustados {
        let tipo = if i.nombre.ends_with(".onnx") {
            "machine-learning-model"
        } else {
            "file"
        };
        let ruta = i
            .ruta
            .clone()
            .unwrap_or_else(|| "generado por build.rs (OUT_DIR)".to_string());
        let props = vec![
            prop("aegis:incrustado-por", i.krate.as_str()),
            prop("aegis:ruta", ruta),
        ];
        let mut v = json!({
            "type": tipo,
            "bom-ref": ref_incrustado(i),
            "name": i.nombre,
            "scope": "required",
            "properties": props
        });
        if let Some(h) = &i.suma {
            v["hashes"] = json!([{ "alg": "SHA-256", "content": h }]);
        }
        componentes.push(v);
        de_la_raiz.push(ref_incrustado(i));
    }

    let mut de_un_crate: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for v in &s.vendorizados {
        let dueno = s.componentes.values().find(|c| c.nombre == v.krate);
        let version = dueno.map(|c| c.version.clone()).unwrap_or_default();
        let props = vec![
            prop("aegis:vendorizado-en", format!("{} {version}", v.krate)),
            prop(
                "aegis:version",
                format!("la que fija {} {version}", v.krate),
            ),
            prop("aegis:nota", v.nota.as_str()),
        ];
        componentes.push(json!({
            "type": "library",
            "bom-ref": ref_vendorizado(v),
            "name": v.nombre,
            "scope": "required",
            "licenses": licencias(&v.licencia),
            "properties": props
        }));
        if let Some(d) = dueno {
            de_un_crate
                .entry(d.referencia())
                .or_default()
                .push(ref_vendorizado(v));
        }
    }

    for c in &s.sistema {
        let mut props = vec![prop("aegis:version-de", c.version_de.as_str())];
        let version = a.and_then(|a| a.versiones.get(&c.version_de)).cloned();
        if version.is_none() {
            props.push(prop(
                "aegis:version",
                "no fijada en el repositorio: la registra el SBOM del build",
            ));
        }
        let mut v = json!({
            "type": "library",
            "bom-ref": ref_sistema(c),
            "name": c.nombre,
            "scope": "required",
            "description": c.descripcion,
            "licenses": licencias(&c.licencia),
            "properties": props
        });
        if let Some(ver) = version {
            v["version"] = json!(ver);
        }
        componentes.push(v);
        de_la_raiz.push(ref_sistema(c));
    }

    // Cada componente de cargo con sus aristas, vacias incluidas: CycloneDX
    // distingue «no depende de nada» de «no se sabe».
    de_la_raiz.sort();
    let mut dependencias = vec![json!({ "ref": raiz_ref, "dependsOn": de_la_raiz })];
    for r in s.componentes.keys() {
        let mut hijos: Vec<String> = s.aristas.get(r).into_iter().flatten().cloned().collect();
        if let Some(extra) = de_un_crate.get(r) {
            hijos.extend(extra.iter().cloned());
        }
        hijos.sort();
        dependencias.push(json!({ "ref": r, "dependsOn": hijos }));
    }

    let caracteristicas = if s.caracteristicas.is_empty() {
        "(ninguna)".to_string()
    } else {
        s.caracteristicas.join(",")
    };
    let props_raiz = vec![
        prop("aegis:paquete", s.instalable.paquete.as_str()),
        prop("aegis:workspace", s.instalable.workspace.as_str()),
        prop("aegis:lado", s.instalable.lado.as_str()),
        prop("aegis:caracteristicas", caracteristicas),
        prop("aegis:objetivo", s.objetivo.as_str()),
    ];
    let mut raiz = json!({
        "type": "application",
        "bom-ref": raiz_ref,
        "name": s.instalable.binario,
        "version": s.raiz.version,
        "description": s.instalable.descripcion,
        "licenses": licencias(&s.raiz.licencia),
        "properties": props_raiz
    });

    let mut metadatos = vec![
        prop(
            "aegis:fuente",
            format!(
                "Cargo.lock del workspace {} + cargo tree --locked -e normal,build --target {}",
                s.instalable.workspace, s.objetivo
            ),
        ),
        prop(
            "aegis:alcance",
            "solo la arquitectura del objetivo indicado",
        ),
    ];
    if let Some(a) = a {
        match &a.sha256 {
            Some(h) => raiz["hashes"] = json!([{ "alg": "SHA-256", "content": h }]),
            None => metadatos.push(prop(
                "aegis:artefacto",
                "sin binario hermetico publicado: el SBOM no lleva hash",
            )),
        }
        for (clave, nombre) in [
            ("commit", "aegis:commit"),
            ("arbol limpio", "aegis:arbol-limpio"),
            ("construido", "aegis:construido"),
            ("compilador", "aegis:compilador"),
        ] {
            if let Some(v) = a.manifiesto.get(clave) {
                metadatos.push(prop(nombre, v.as_str()));
            }
        }
        metadatos.push(prop("aegis:huella", a.huella.as_str()));
    }

    let herramienta = json!({
        "type": "application",
        "name": "cargo xtask sbom",
        "version": env!("CARGO_PKG_VERSION")
    });
    json!({
        "bomFormat": "CycloneDX",
        "specVersion": ESPECIFICACION,
        "version": 1,
        "metadata": {
            "tools": { "components": [herramienta] },
            "component": raiz,
            "properties": metadatos
        },
        "components": componentes,
        "dependencies": dependencias
    })
}

/// El SBOM como texto JSON, con salto de linea final.
pub fn texto(s: &Sbom, a: Option<&Artefacto>) -> Resultado<String> {
    let mut t = serde_json::to_string_pretty(&documento(s, a))?;
    t.push('\n');
    Ok(t)
}

/// Una linea para la salida de la orden.
pub fn resumen(sboms: &[Sbom]) -> String {
    let distintos: BTreeSet<&String> = sboms.iter().flat_map(|s| s.componentes.keys()).collect();
    format!(
        "sbom: {} instalables, {} crates distintos, todos con licencia; coinciden con su Cargo.lock",
        sboms.len(),
        distintos.len()
    )
}

/// Por que el SBOM versionado no corresponde al `Cargo.lock` actual: crates
/// que entran o salen. Vacio si el conjunto coincide (otras diferencias las
/// encuentra la comparacion de texto).
pub fn diferencias(repo: &Repo, sboms: &[Sbom]) -> Vec<String> {
    let mut v = Vec::new();
    for s in sboms {
        let ruta = s.ruta();
        let Ok(texto) = std::fs::read_to_string(repo.raiz.join(&ruta)) else {
            v.push(format!("{} no existe", ruta.display()));
            continue;
        };
        let Ok(doc) = serde_json::from_str::<Value>(&texto) else {
            v.push(format!("{} no es JSON valido", ruta.display()));
            continue;
        };
        let versionados: BTreeSet<String> = doc["components"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|c| c["bom-ref"].as_str())
            .filter(|r| r.starts_with("pkg:cargo/") || r.starts_with("repo:"))
            .map(str::to_string)
            .collect();
        let actuales: BTreeSet<String> = s.componentes.keys().cloned().collect();
        for r in actuales.difference(&versionados) {
            v.push(format!(
                "{}: {r} entra en el arbol segun el Cargo.lock y el SBOM no lo cita",
                s.instalable.binario
            ));
        }
        for r in versionados.difference(&actuales) {
            v.push(format!(
                "{}: el SBOM cita {r}, que ya no esta en el arbol segun el Cargo.lock",
                s.instalable.binario
            ));
        }
    }
    v
}

// ── --dist: el SBOM del build y su procedencia ──────────────────────────────

/// `clave : valor` de `MANIFIESTO.txt`.
fn parsear_manifiesto(t: &str) -> BTreeMap<String, String> {
    t.lines()
        .filter_map(|l| l.split_once(" : "))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

/// `nombre -> sha256` de un `SHA256SUMS` (formato GNU, con o sin `*`).
fn parsear_sumas(t: &str) -> Resultado<BTreeMap<String, String>> {
    let mut m = BTreeMap::new();
    for l in t.lines().filter(|l| !l.trim().is_empty()) {
        let mut p = l.split_whitespace();
        match (p.next(), p.next()) {
            (Some(h), Some(n)) => {
                m.insert(n.trim_start_matches('*').to_string(), h.to_string());
            }
            _ => return Err(format!("SHA256SUMS: linea ilegible «{l}»").into()),
        }
    }
    Ok(m)
}

/// Version instalada de un paquete Debian del constructor, si hay dpkg.
fn version_dpkg(paquete: &str) -> Option<String> {
    let s = Command::new("dpkg-query")
        .args(["-W", "--showformat=${Version}", paquete])
        .output()
        .ok()?;
    let v = String::from_utf8_lossy(&s.stdout).trim().to_string();
    (s.status.success() && !v.is_empty()).then_some(v)
}

/// El remoto `origin`, sin credenciales.
fn origen_git(repo: &Repo) -> String {
    let url = Command::new("git")
        .args(["remote", "get-url", "origin"])
        .current_dir(&repo.raiz)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    if url.is_empty() {
        return "desconocido".into();
    }
    match url.split_once("://") {
        Some((esquema, resto)) => {
            let (autoridad, camino) = resto.split_once('/').unwrap_or((resto, ""));
            let host = autoridad.rsplit_once('@').map_or(autoridad, |(_, h)| h);
            format!("{esquema}://{host}/{camino}")
        }
        None => url,
    }
}

/// Quien construye: la ejecucion del CI si la hay, si no la maquina.
fn constructor() -> String {
    let v = |k: &str| std::env::var(k).ok().filter(|s| !s.is_empty());
    match (
        v("GITHUB_SERVER_URL"),
        v("GITHUB_REPOSITORY"),
        v("GITHUB_RUN_ID"),
    ) {
        (Some(s), Some(r), Some(id)) => format!("{s}/{r}/actions/runs/{id}"),
        _ => {
            let host = std::fs::read_to_string("/proc/sys/kernel/hostname")
                .map(|h| h.trim().to_string())
                .unwrap_or_else(|_| "desconocido".into());
            format!("local:{host}")
        }
    }
}

/// Si el constructor es un WSL: el PC de desarrollo, no una maquina dedicada.
fn es_wsl() -> bool {
    std::fs::read_to_string("/proc/version")
        .map(|v| v.to_lowercase().contains("microsoft"))
        .unwrap_or(false)
}

/// Escribe en `dir` el SBOM de cada instalable con el hash de su binario y la
/// procedencia del build. Falla sin escribir nada si los binarios no salen de
/// este arbol o no coinciden con sus sumas.
pub fn dist(repo: &Repo, sboms: &[Sbom], dir: &Path) -> Resultado<String> {
    let leer = |n: &str| {
        std::fs::read_to_string(dir.join(n)).map_err(|e| format!("{}: {e}", dir.join(n).display()))
    };

    // 1. Que salen de este arbol: la misma comprobacion que la matriz de kernels.
    let actual = crate::kernels::huella_del_arbol(repo)?;
    let grabada = leer("HUELLA").ok();
    crate::kernels::procedencia(grabada.as_deref(), &actual, dir, "tools/ci/hermetico.sh")?;

    // 2. Que los binarios son los de SHA256SUMS, y que estan todos y solo ellos.
    let sumas = parsear_sumas(&leer("SHA256SUMS")?)?;
    let comprobacion = Command::new("sha256sum")
        .args(["--check", "--quiet", "--strict", "SHA256SUMS"])
        .current_dir(dir)
        .output()
        .map_err(|e| format!("sha256sum (coreutils): {e}"))?;
    if !comprobacion.status.success() {
        return Err(format!(
            "{}: los binarios no coinciden con SHA256SUMS:\n{}{}",
            dir.display(),
            String::from_utf8_lossy(&comprobacion.stdout),
            String::from_utf8_lossy(&comprobacion.stderr)
        )
        .into());
    }
    let hermeticos: BTreeSet<&str> = sboms
        .iter()
        .filter(|s| s.es_hermetico())
        .map(|s| s.instalable.binario.as_str())
        .collect();
    let listados: BTreeSet<&str> = sumas.keys().map(String::as_str).collect();
    if hermeticos != listados {
        return Err(format!(
            "{}/SHA256SUMS lista {listados:?} y los instalables hermeticos son {hermeticos:?}",
            dir.display()
        )
        .into());
    }

    // 3. Lo que dice el build de si mismo, y lo que se mide en el constructor.
    let manifiesto = parsear_manifiesto(&leer("MANIFIESTO.txt")?);
    let mut versiones = BTreeMap::new();
    if let Some(v) = manifiesto
        .get("compilador")
        .and_then(|c| c.split_whitespace().nth(1))
    {
        versiones.insert("rustc".to_string(), v.to_string());
    }
    for s in sboms {
        for c in &s.sistema {
            let Some(p) = c.version_de.strip_prefix("dpkg:") else {
                continue;
            };
            if let Entry::Vacant(e) = versiones.entry(c.version_de.clone()) {
                if let Some(v) = version_dpkg(p) {
                    e.insert(v);
                }
            }
        }
    }

    // 4. Un SBOM por instalable, con el hash de su binario.
    let dir_sbom = dir.join("sbom");
    std::fs::create_dir_all(&dir_sbom)?;
    let suma_manifiesto = sha256(&dir.join("MANIFIESTO.txt"))?;
    let mut subproductos = vec![json!({
        "name": "MANIFIESTO.txt",
        "digest": { "sha256": suma_manifiesto }
    })];
    for s in sboms {
        let a = Artefacto {
            sha256: sumas.get(&s.instalable.binario).cloned(),
            manifiesto: &manifiesto,
            huella: actual.clone(),
            versiones: &versiones,
        };
        let nombre = format!("{}.cdx.json", s.instalable.binario);
        let destino = dir_sbom.join(&nombre);
        std::fs::write(&destino, texto(s, Some(&a))?)?;
        let suma = sha256(&destino)?;
        let publicado = format!("sbom/{nombre}");
        subproductos.push(json!({ "name": publicado, "digest": { "sha256": suma } }));
    }

    // 5. La procedencia: declaracion in-toto v1 con predicado SLSA v1, SIN
    //    firmar. Sin firma es nivel 1 como mucho (docs/generado/auditoria/slsa.md).
    let commit = manifiesto.get("commit").cloned().unwrap_or_default();
    let origen = origen_git(repo);
    let sujetos: Vec<Value> = sumas
        .iter()
        .map(|(n, h)| json!({ "name": n, "digest": { "sha256": h } }))
        .collect();
    let instalables: Vec<Value> = sboms
        .iter()
        .filter(|s| s.es_hermetico())
        .map(|s| {
            json!({
                "binario": s.instalable.binario,
                "paquete": s.instalable.paquete,
                "caracteristicas": s.caracteristicas
            })
        })
        .collect();
    let terminado = manifiesto
        .get("construido")
        .and_then(|c| c.split_whitespace().next())
        .unwrap_or_default()
        .to_string();
    let arbol_limpio = manifiesto
        .get("arbol limpio")
        .is_some_and(|v| v.as_str() == "si");
    let uri_fuente = format!("git+{origen}");
    let uri_commit = format!("git+{origen}@{commit}");
    let suma_lock = sha256(&repo.raiz.join("Cargo.lock"))?;
    let fuente = json!({ "uri": uri_fuente, "digest": { "gitCommit": commit } });
    let externos = json!({
        "fuente": fuente,
        "guion": "tools/ci/hermetico.sh",
        "objetivo": manifiesto.get("objetivo"),
        "instalables": instalables
    });
    let internos = json!({
        "arbolLimpio": arbol_limpio,
        "huellaArbol": actual,
        "enlazado": manifiesto.get("enlazado"),
        "sysroot": manifiesto.get("sysroot"),
        "compilador": manifiesto.get("compilador"),
        "compiladorC": manifiesto.get("compilador C"),
        "constructorEnWsl": es_wsl()
    });
    let resueltas = json!([
        { "uri": uri_commit, "digest": { "gitCommit": commit } },
        { "name": "Cargo.lock", "digest": { "sha256": suma_lock } }
    ]);
    let definicion = json!({
        "buildType": TIPO_DE_BUILD,
        "externalParameters": externos,
        "internalParameters": internos,
        "resolvedDependencies": resueltas
    });
    let ejecucion = json!({
        "builder": { "id": constructor() },
        "metadata": { "finishedOn": terminado },
        "byproducts": subproductos
    });
    let declaracion = json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": sujetos,
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": { "buildDefinition": definicion, "runDetails": ejecucion }
    });
    let mut t = serde_json::to_string_pretty(&declaracion)?;
    t.push('\n');
    std::fs::write(dir.join("procedencia.intoto.json"), t)?;
    Ok(format!(
        "sbom --dist: {} SBOM con el hash de cada binario hermetico y procedencia SLSA v1 \
         (sin firmar) en {}",
        sboms.len(),
        dir.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lee_las_lineas_de_cargo_tree() {
        assert_eq!(
            parsear_linea("0Apache-2.0|aegis-agent v0.1.0 (/mnt/c/dev - x/crates/aegis-agent)"),
            Some(Linea {
                profundidad: 0,
                licencia: "Apache-2.0".into(),
                nombre: "aegis-agent".into(),
                version: "0.1.0".into(),
                proc_macro: false,
            })
        );
        let l =
            parsear_linea("12MIT OR Apache-2.0|serde_derive v1.0.219 (proc-macro) (*)").unwrap();
        assert_eq!(l.profundidad, 12);
        assert_eq!(l.licencia, "MIT OR Apache-2.0");
        assert!(l.proc_macro);
        let sin = parsear_linea("3|raro v0.2.0").unwrap();
        assert!(sin.licencia.is_empty());
        assert!(parsear_linea("warning: algo").is_none());
    }

    #[test]
    fn licencias_con_barra_pasan_a_or() {
        assert_eq!(normalizar_licencia("MIT/Apache-2.0"), "MIT OR Apache-2.0");
        assert_eq!(normalizar_licencia("Apache-2.0"), "Apache-2.0");
        assert_eq!(normalizar_licencia(""), "");
    }

    #[test]
    fn manifiesto_y_sumas() {
        let m = parsear_manifiesto(
            "AegisCore\n=====\ncommit        : abc\ncompilador C  : gcc 15\nconstruido    : 2026-01-01T00:00:00Z (UTC)\n",
        );
        assert_eq!(m["commit"], "abc");
        assert_eq!(m["compilador C"], "gcc 15");
        assert_eq!(m.len(), 3);
        let s = parsear_sumas("aa  aegis-agent\nbb *aegisctl\n").unwrap();
        assert_eq!(s["aegis-agent"], "aa");
        assert_eq!(s["aegisctl"], "bb");
    }

    #[test]
    fn purl_de_otro_registro_va_codificado() {
        assert_eq!(
            porcentaje("sparse+https://x.y/"),
            "sparse%2Bhttps%3A%2F%2Fx.y%2F"
        );
        let c = Componente {
            nombre: "libbpf-sys".into(),
            version: "1.7.0+v1.7.0".into(),
            licencia: "BSD-2-Clause".into(),
            origen: Some(CRATES_IO[0].into()),
            suma: None,
            en_ejecucion: true,
            proc_macro: false,
            uso: "ejecucion",
        };
        assert_eq!(c.referencia(), "pkg:cargo/libbpf-sys@1.7.0%2Bv1.7.0");
    }
}
