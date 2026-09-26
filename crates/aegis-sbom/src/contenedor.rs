//! Imagenes de contenedor, capa a capa.
//!
//! # Por que capa a capa y no la imagen aplanada
//!
//! «Esta imagen tiene `openssl` vulnerable» no dice a quien le toca arreglarlo.
//! «Lo trae la capa 0, que es la imagen base» dice que la arregla quien mantiene
//! la base; «lo trae la capa 4» dice que la arregla quien escribio el
//! `Dockerfile` de la aplicacion. Cada componente sale atribuido a la capa que lo
//! introdujo, y lo que una capa superior borra no sale.
//!
//! # Tres formas en que una imagen esta en disco
//!
//! - El tar de `docker save`: un `manifest.json` con la lista de capas.
//! - Un directorio con el layout OCI: `index.json`, manifiestos y blobs.
//! - El almacen `overlay2` de un Docker vivo: cada capa es un directorio `diff`.
//!
//! Las dos primeras se leen con el mismo codigo; la tercera se lee sobre
//! directorios en vez de sobre tars, con la misma logica de atribucion.
//!
//! # Borrados
//!
//! En un tar de capa, un fichero `.wh.nombre` borra `nombre` de las capas de
//! debajo, y `.wh..wh..opq` vacia el directorio. En `overlay2` el borrado es un
//! dispositivo de caracteres 0/0 con el mismo nombre. Sin aplicarlos, una capa
//! que desinstala un paquete lo dejaria en el inventario para siempre.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use aegis_vuln::inventory::{parse_apk_installed, parse_dpkg_status, PackageSource};
use sha2::{Digest, Sha256};

use crate::aplicacion::{self, Tipo};
use crate::componente::{Capa, Componente, Distro, Ecosistema, Procedencia};
use crate::tar::{self, Gzip};

/// Tope de capas de una imagen.
pub const MAX_CAPAS: usize = 256;

/// Tope de ficheros interesantes por imagen.
pub const MAX_INTERESANTES: usize = 10_000;

/// Tope de bytes de un documento JSON de la imagen (manifiesto, configuracion).
pub const MAX_JSON: u64 = 4 * 1024 * 1024;

/// Las rutas fijas que interesan dentro de una capa.
const FIJAS: &[&str] = &[
    "var/lib/dpkg/status",
    "lib/apk/db/installed",
    "etc/os-release",
    "usr/lib/os-release",
];

/// Si una ruta dentro de una capa es de las que dan componentes.
#[must_use]
pub fn interesa(ruta: &str) -> bool {
    FIJAS.contains(&ruta) || aplicacion::tipo_de(Path::new(ruta)).is_some()
}

/// Lo que una capa hace con un fichero interesante.
#[derive(Debug, Clone)]
enum Cambio {
    Escrito(Vec<u8>),
    Borrado,
}

/// Una capa ya leida: sus cambios sobre las rutas interesantes, y sus borrados
/// de directorio completo.
#[derive(Debug, Clone, Default)]
struct CapaLeida {
    resumen: String,
    cambios: BTreeMap<String, Cambio>,
    opacos: Vec<String>,
}

/// Lee una capa en tar (ya descomprimida si hacia falta).
fn leer_capa_tar(r: &mut dyn Read, resumen: String) -> io::Result<CapaLeida> {
    let mut c = CapaLeida {
        resumen,
        ..CapaLeida::default()
    };
    let mut borrados: Vec<String> = Vec::new();
    let mut opacos: Vec<String> = Vec::new();
    let mut escritos: Vec<(String, Vec<u8>)> = Vec::new();
    // El tope se cuenta aparte: `visitar` decide antes de leer el contenido y
    // `recibir` lo guarda despues, y los dos no pueden tocar el mismo vector.
    let guardados = std::cell::Cell::new(0usize);
    tar::recorrer(
        r,
        &mut |e| {
            let nombre = e.ruta.rsplit('/').next().unwrap_or(&e.ruta);
            if nombre == ".wh..wh..opq" {
                opacos.push(
                    e.ruta
                        .trim_end_matches(".wh..wh..opq")
                        .trim_end_matches('/')
                        .into(),
                );
                return false;
            }
            if let Some(borrado) = nombre.strip_prefix(".wh.") {
                let dir = e.ruta.rsplit_once('/').map_or("", |(d, _)| d);
                let ruta = if dir.is_empty() {
                    borrado.to_string()
                } else {
                    format!("{dir}/{borrado}")
                };
                borrados.push(ruta);
                return false;
            }
            interesa(&e.ruta) && guardados.get() < MAX_INTERESANTES
        },
        &mut |e, contenido| {
            guardados.set(guardados.get() + 1);
            escritos.push((e.ruta.clone(), contenido));
        },
    )?;
    for b in borrados {
        c.cambios.insert(b, Cambio::Borrado);
    }
    for (r, contenido) in escritos {
        c.cambios.insert(r, Cambio::Escrito(contenido));
    }
    c.opacos = opacos;
    Ok(c)
}

/// Un tar en disco con su indice de entradas, para leer capas por
/// desplazamiento sin descomprimir el tar exterior entero en memoria.
struct TarExterior {
    fichero: File,
    indice: BTreeMap<String, (u64, u64)>,
}

impl TarExterior {
    fn abrir(ruta: &Path) -> io::Result<TarExterior> {
        let mut f = File::open(ruta)?;
        let mut indice = BTreeMap::new();
        let mut pos = 0u64;
        let mut cab = [0u8; 512];
        let mut nombre_largo: Option<String> = None;
        loop {
            f.seek(SeekFrom::Start(pos))?;
            if f.read(&mut cab[..1])? == 0 {
                break;
            }
            f.read_exact(&mut cab[1..])?;
            if cab.iter().all(|b| *b == 0) {
                break;
            }
            let tamano = std::str::from_utf8(&cab[124..136])
                .ok()
                .map(|s| s.trim_matches(|c: char| c == '\0' || c == ' '))
                .and_then(|s| u64::from_str_radix(if s.is_empty() { "0" } else { s }, 8).ok())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "tamano ilegible"))?;
            let datos = pos + 512;
            let pad = (512 - tamano % 512) % 512;
            match cab[156] {
                b'L' if tamano <= tar::MAX_NOMBRE => {
                    let mut n = vec![0u8; usize::try_from(tamano).unwrap_or(0)];
                    f.read_exact(&mut n)?;
                    let fin = n.iter().position(|b| *b == 0).unwrap_or(n.len());
                    nombre_largo = Some(String::from_utf8_lossy(&n[..fin]).into_owned());
                }
                b'x' | b'g' => {}
                _ => {
                    let nombre = nombre_largo.take().unwrap_or_else(|| {
                        let fin = cab[..100].iter().position(|b| *b == 0).unwrap_or(100);
                        String::from_utf8_lossy(&cab[..fin]).into_owned()
                    });
                    if indice.len() >= tar::MAX_ENTRADAS {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "demasiadas entradas",
                        ));
                    }
                    indice.insert(tar::normalizar(&nombre), (datos, tamano));
                }
            }
            pos = datos
                .checked_add(tamano + pad)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "desplazamiento"))?;
        }
        Ok(TarExterior { fichero: f, indice })
    }

    fn lector(&self, ruta: &str) -> io::Result<io::Take<File>> {
        let (off, tam) = *self
            .indice
            .get(&tar::normalizar(ruta))
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("falta {ruta}")))?;
        let mut f = self.fichero.try_clone()?;
        f.seek(SeekFrom::Start(off))?;
        Ok(f.take(tam))
    }

    fn texto(&self, ruta: &str) -> io::Result<String> {
        let (_, tam) = *self
            .indice
            .get(&tar::normalizar(ruta))
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("falta {ruta}")))?;
        if tam > MAX_JSON {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "documento por encima del tope",
            ));
        }
        let mut s = String::new();
        self.lector(ruta)?.read_to_string(&mut s)?;
        Ok(s)
    }
}

/// Abre una capa: gzip o tar sin comprimir, por la magia de sus dos primeros
/// bytes.
fn leer_capa_de(mut r: impl Read, resumen: String) -> io::Result<CapaLeida> {
    let mut magia = [0u8; 2];
    let n = r.read(&mut magia)?;
    let cadena = io::Cursor::new(magia[..n].to_vec()).chain(r);
    if n == 2 && magia == [0x1f, 0x8b] {
        let mut gz = Gzip::nuevo(cadena);
        let capa = leer_capa_tar(&mut gz, resumen)?;
        // El tar termina en sus dos bloques de ceros, pero el gzip sigue: su
        // cola lleva el CRC y la longitud. Sin consumirla, una capa corrupta
        // pasaba por buena porque el lector se paraba antes de llegar a lo que
        // lo habria delatado. Se consume hasta el final, y ahi se comprueba.
        io::copy(&mut gz, &mut io::sink())?;
        Ok(capa)
    } else {
        let mut c = cadena;
        leer_capa_tar(&mut c, resumen)
    }
}

/// Una imagen analizada.
#[derive(Debug, Clone)]
pub struct Imagen {
    /// Su nombre (la primera etiqueta, o el resumen de la configuracion).
    pub nombre: String,
    /// Sus capas, desde la base.
    pub capas: Vec<String>,
    /// Sus componentes, cada uno con su capa.
    pub componentes: Vec<Componente>,
}

/// Lee el tar de `docker save` o de un layout OCI empaquetado en tar.
///
/// # Errors
///
/// Si el tar no se puede leer, no trae manifiesto o una capa esta corrupta.
pub fn desde_tar(ruta: &Path) -> io::Result<Vec<Imagen>> {
    let t = TarExterior::abrir(ruta)?;
    let manifiesto: serde_json::Value = serde_json::from_str(&t.texto("manifest.json")?)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("manifest.json: {e}")))?;
    let mut out = Vec::new();
    for m in manifiesto.as_array().into_iter().flatten().take(64) {
        let nombre = m
            .get("RepoTags")
            .and_then(|r| r.as_array())
            .and_then(|r| r.first())
            .and_then(|x| x.as_str())
            .or_else(|| m.get("Config").and_then(|c| c.as_str()))
            .unwrap_or("sin-nombre")
            .to_string();
        let capas: Vec<String> = m
            .get("Layers")
            .and_then(|l| l.as_array())
            .into_iter()
            .flatten()
            .filter_map(|x| x.as_str().map(str::to_string))
            .take(MAX_CAPAS + 1)
            .collect();
        if capas.len() > MAX_CAPAS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "demasiadas capas",
            ));
        }
        let mut leidas = Vec::with_capacity(capas.len());
        for c in &capas {
            leidas.push(leer_capa_de(t.lector(c)?, resumen_de_ruta(c))?);
        }
        out.push(componer(&nombre, &leidas));
    }
    Ok(out)
}

/// El resumen de una capa a partir de su ruta en el tar: `blobs/sha256/<hex>` o
/// `<hex>/layer.tar`.
fn resumen_de_ruta(r: &str) -> String {
    if let Some(h) = r.strip_prefix("blobs/sha256/") {
        return format!("sha256:{h}");
    }
    match r.split('/').next() {
        Some(h) if h.len() == 64 => format!("sha256:{h}"),
        _ => r.to_string(),
    }
}

/// Lee un directorio con el layout OCI (`index.json` + `blobs/`).
///
/// # Errors
///
/// Si falta el indice, un manifiesto o una capa.
pub fn desde_oci(dir: &Path) -> io::Result<Vec<Imagen>> {
    let json = |p: &Path| -> io::Result<serde_json::Value> {
        let md = std::fs::metadata(p)?;
        if md.len() > MAX_JSON {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "documento por encima del tope",
            ));
        }
        serde_json::from_slice(&std::fs::read(p)?)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    };
    let blob = |digest: &str| -> io::Result<PathBuf> {
        let hex = digest
            .strip_prefix("sha256:")
            .filter(|h| h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "resumen no valido"))?;
        Ok(dir.join("blobs/sha256").join(hex))
    };
    let indice = json(&dir.join("index.json"))?;
    let mut out = Vec::new();
    for m in indice
        .get("manifests")
        .and_then(|m| m.as_array())
        .into_iter()
        .flatten()
        .take(64)
    {
        let Some(d) = m.get("digest").and_then(|d| d.as_str()) else {
            continue;
        };
        let nombre = m
            .get("annotations")
            .and_then(|a| a.get("org.opencontainers.image.ref.name"))
            .and_then(|x| x.as_str())
            .unwrap_or(d)
            .to_string();
        let manifiesto = json(&blob(d)?)?;
        let capas: Vec<String> = manifiesto
            .get("layers")
            .and_then(|l| l.as_array())
            .into_iter()
            .flatten()
            .filter_map(|l| l.get("digest").and_then(|x| x.as_str()).map(str::to_string))
            .take(MAX_CAPAS + 1)
            .collect();
        if capas.len() > MAX_CAPAS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "demasiadas capas",
            ));
        }
        let mut leidas = Vec::with_capacity(capas.len());
        for c in &capas {
            leidas.push(leer_capa_de(File::open(blob(c)?)?, c.clone())?);
        }
        out.push(componer(&nombre, &leidas));
    }
    Ok(out)
}

/// El `chainID` de OCI: el de la primera capa es su `diffID`; el de cada una de
/// las siguientes es el SHA-256 de «chainID anterior + espacio + diffID».
#[must_use]
pub fn cadena_de(diff_ids: &[String]) -> Vec<String> {
    let mut v: Vec<String> = Vec::with_capacity(diff_ids.len());
    for d in diff_ids {
        let siguiente = match v.last() {
            None => d.clone(),
            Some(previo) => {
                let h = Sha256::digest(format!("{previo} {d}").as_bytes());
                format!("sha256:{}", hex(&h))
            }
        };
        v.push(siguiente);
    }
    v
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Lee una capa de `overlay2` (un directorio `diff`).
fn leer_capa_dir(diff: &Path, resumen: String) -> CapaLeida {
    let mut c = CapaLeida {
        resumen,
        ..CapaLeida::default()
    };
    for f in FIJAS {
        let p = diff.join(f);
        if let Ok(md) = std::fs::symlink_metadata(&p) {
            if es_borrado_overlay(&md) {
                c.cambios.insert((*f).to_string(), Cambio::Borrado);
            } else if md.is_file() && md.len() <= tar::MAX_ENTRADA {
                if let Ok(b) = std::fs::read(&p) {
                    c.cambios.insert((*f).to_string(), Cambio::Escrito(b));
                }
            }
        }
    }
    for (p, _) in aplicacion::recorrer(diff, &[])
        .ficheros
        .into_iter()
        .take(MAX_INTERESANTES)
    {
        if let (Ok(rel), Ok(b)) = (p.strip_prefix(diff), std::fs::read(&p)) {
            c.cambios
                .insert(rel.to_string_lossy().into_owned(), Cambio::Escrito(b));
        }
    }
    c
}

/// Un borrado de overlayfs: dispositivo de caracteres con numero 0/0.
#[cfg(unix)]
fn es_borrado_overlay(md: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    md.file_type().is_char_device() && md.rdev() == 0
}

#[cfg(not(unix))]
fn es_borrado_overlay(_: &std::fs::Metadata) -> bool {
    false
}

/// Lee las imagenes del almacen `overlay2` de un Docker bajo `raiz`.
///
/// # Errors
///
/// Si no hay almacen o su indice no se puede leer.
pub fn desde_overlay2(raiz: &Path) -> io::Result<Vec<Imagen>> {
    let base = raiz.join("var/lib/docker/image/overlay2");
    let repos: serde_json::Value =
        serde_json::from_slice(&std::fs::read(base.join("repositories.json"))?)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let mut nombres: BTreeMap<String, String> = BTreeMap::new();
    if let Some(r) = repos.get("Repositories").and_then(|r| r.as_object()) {
        for etiquetas in r.values() {
            for (etiqueta, id) in etiquetas.as_object().into_iter().flatten() {
                if let Some(id) = id.as_str() {
                    nombres
                        .entry(id.to_string())
                        .or_insert_with(|| etiqueta.clone());
                }
            }
        }
    }
    let mut out = Vec::new();
    for (id, nombre) in nombres.iter().take(1024) {
        let Some(hex) = id.strip_prefix("sha256:") else {
            continue;
        };
        let conf: serde_json::Value =
            match std::fs::read(base.join("imagedb/content/sha256").join(hex))
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
            {
                Some(c) => c,
                None => continue,
            };
        let diff_ids: Vec<String> = conf
            .get("rootfs")
            .and_then(|r| r.get("diff_ids"))
            .and_then(|d| d.as_array())
            .into_iter()
            .flatten()
            .filter_map(|x| x.as_str().map(str::to_string))
            .take(MAX_CAPAS)
            .collect();
        let mut leidas = Vec::new();
        for (cadena, diff) in cadena_de(&diff_ids).iter().zip(&diff_ids) {
            let Some(h) = cadena.strip_prefix("sha256:") else {
                continue;
            };
            let Ok(cache) =
                std::fs::read_to_string(base.join("layerdb/sha256").join(h).join("cache-id"))
            else {
                continue;
            };
            let dir = raiz
                .join("var/lib/docker/overlay2")
                .join(cache.trim())
                .join("diff");
            leidas.push(leer_capa_dir(&dir, diff.clone()));
        }
        out.push(componer(nombre, &leidas));
    }
    Ok(out)
}

/// Los componentes de una version de un fichero interesante.
fn componentes_de(ruta: &str, contenido: &[u8], distro: Option<&Distro>) -> Vec<Componente> {
    let texto = String::from_utf8_lossy(contenido);
    let p = Path::new(ruta);
    let del_sistema = |eco: Ecosistema, fuente: PackageSource, base: &str| {
        let mut m = BTreeMap::new();
        match fuente {
            PackageSource::Apk => parse_apk_installed(&texto, &mut m),
            _ => parse_dpkg_status(&texto, &mut m),
        }
        m.into_values()
            .map(|pk| {
                let mut c = Componente::nuevo(
                    eco,
                    pk.name.clone(),
                    pk.version.to_string(),
                    Procedencia::GestorDePaquetes {
                        base: PathBuf::from(base),
                    },
                );
                c.fuente = pk.source_package.clone();
                c.version_fuente = pk.source_version.as_ref().map(ToString::to_string);
                c.arquitectura = (!pk.arch.is_empty()).then(|| pk.arch.clone());
                c.distro = distro.cloned();
                c
            })
            .collect::<Vec<_>>()
    };
    match ruta {
        "var/lib/dpkg/status" => {
            del_sistema(Ecosistema::Deb, PackageSource::Dpkg, "/var/lib/dpkg/status")
        }
        "lib/apk/db/installed" => {
            del_sistema(Ecosistema::Apk, PackageSource::Apk, "/lib/apk/db/installed")
        }
        _ => match aplicacion::tipo_de(p) {
            Some(Tipo::CargoLock) => aplicacion::cargo_lock(&texto, p),
            Some(Tipo::PackageLock) => aplicacion::package_lock(&texto, p),
            Some(Tipo::Requirements) => aplicacion::requirements(&texto, p),
            Some(Tipo::Python) => aplicacion::metadatos_python(&texto, p)
                .into_iter()
                .collect(),
            None => Vec::new(),
        },
    }
}

/// La distribucion de un `os-release`.
fn distro_de(texto: &str) -> Option<Distro> {
    let mut id = None;
    let mut version = String::new();
    for l in texto.lines() {
        if let Some((k, v)) = l.split_once('=') {
            let v = v.trim().trim_matches('"');
            match k.trim() {
                "ID" => id = Some(v.to_ascii_lowercase()),
                "VERSION_ID" => version = v.to_string(),
                _ => {}
            }
        }
    }
    Some(Distro { id: id?, version })
}

/// Aplica las capas en orden y atribuye cada componente superviviente a la capa
/// que lo introdujo.
///
/// Por cada fichero interesante se sigue su historia capa a capa. Un componente
/// se atribuye a la primera capa desde la que esta presente SIN interrupcion
/// hasta la ultima: si la capa 2 lo instala, la 3 lo quita y la 5 lo vuelve a
/// poner, es de la 5, que es la que habria que cambiar.
fn componer(nombre: &str, capas: &[CapaLeida]) -> Imagen {
    // El estado vivo de cada ruta tras cada capa.
    let mut vivo: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    // (ruta, clave del componente) -> capa desde la que esta presente.
    let mut desde: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut distro: Option<Distro> = None;
    for (i, c) in capas.iter().enumerate() {
        for dir in &c.opacos {
            let prefijo = format!("{dir}/");
            vivo.retain(|r, _| !r.starts_with(&prefijo));
        }
        for (ruta, cambio) in &c.cambios {
            match cambio {
                Cambio::Borrado => {
                    // Borrar un directorio borra lo que habia debajo.
                    let prefijo = format!("{ruta}/");
                    vivo.retain(|r, _| r != ruta && !r.starts_with(&prefijo));
                }
                Cambio::Escrito(b) => {
                    vivo.insert(ruta.clone(), b.clone());
                }
            }
        }
        for r in ["etc/os-release", "usr/lib/os-release"] {
            if let Some(b) = vivo.get(r) {
                distro = distro_de(&String::from_utf8_lossy(b));
                break;
            }
        }
        // Rehacer la presencia de cada componente de las rutas vivas.
        let mut presentes: BTreeSet<(String, String)> = BTreeSet::new();
        for (ruta, b) in &vivo {
            if FIJAS[2..].contains(&ruta.as_str()) {
                continue;
            }
            for comp in componentes_de(ruta, b, distro.as_ref()) {
                presentes.insert((ruta.clone(), clave_texto(&comp)));
            }
        }
        desde.retain(|k, _| presentes.contains(k));
        for k in presentes {
            desde.entry(k).or_insert(i);
        }
    }
    let mut componentes = Vec::new();
    for (ruta, b) in &vivo {
        if FIJAS[2..].contains(&ruta.as_str()) {
            continue;
        }
        for mut comp in componentes_de(ruta, b, distro.as_ref()) {
            let k = (ruta.clone(), clave_texto(&comp));
            let i = desde.get(&k).copied().unwrap_or(0);
            comp.capa = Some(Capa {
                imagen: nombre.to_string(),
                resumen: capas.get(i).map(|c| c.resumen.clone()).unwrap_or_default(),
                indice: i,
            });
            componentes.push(comp);
        }
    }
    Imagen {
        nombre: nombre.to_string(),
        capas: capas.iter().map(|c| c.resumen.clone()).collect(),
        componentes,
    }
}

fn clave_texto(c: &Componente) -> String {
    format!(
        "{}\u{1f}{}\u{1f}{}\u{1f}{}",
        c.ecosistema.nombre(),
        c.nombre,
        c.version,
        c.arquitectura.as_deref().unwrap_or("")
    )
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::tar::pruebas_tar::{gzip, tar};

    const STATUS_BASE: &[u8] =
        b"Package: libc6\nStatus: install ok installed\nArchitecture: amd64\n\
Source: glibc\nVersion: 2.36-9\n\nPackage: openssl\nStatus: install ok installed\n\
Architecture: amd64\nVersion: 3.0.11-1\n";
    const STATUS_APP: &[u8] =
        b"Package: libc6\nStatus: install ok installed\nArchitecture: amd64\n\
Source: glibc\nVersion: 2.36-9\n\nPackage: openssl\nStatus: install ok installed\n\
Architecture: amd64\nVersion: 3.0.11-1\n\nPackage: curl\nStatus: install ok installed\n\
Architecture: amd64\nVersion: 7.88.1-10\n";

    /// Un `docker save` de tres capas: la base, una que instala curl y un
    /// Cargo.lock, y una que borra el Cargo.lock y un requirements.
    fn docker_save(dir: &Path) -> PathBuf {
        let capa0 = tar(&[
            ("etc/os-release", b"ID=debian\nVERSION_ID=\"12\"\n"),
            ("var/lib/dpkg/status", STATUS_BASE),
            ("app/requirements.txt", b"requests==2.31.0\n"),
        ]);
        let capa1 = gzip(&tar(&[
            ("var/lib/dpkg/status", STATUS_APP),
            (
                "app/Cargo.lock",
                b"[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\n",
            ),
        ]));
        let capa2 = tar(&[("app/.wh.Cargo.lock", b"")]);
        let manifiesto = br#"[{"Config":"cfg.json","RepoTags":["miapp:1"],
            "Layers":["aaaa/layer.tar","bbbb/layer.tar","cccc/layer.tar"]}]"#;
        let exterior = tar(&[
            ("manifest.json", manifiesto),
            ("aaaa/layer.tar", &capa0),
            ("bbbb/layer.tar", &capa1),
            ("cccc/layer.tar", &capa2),
        ]);
        let ruta = dir.join("imagen.tar");
        std::fs::write(&ruta, exterior).unwrap();
        ruta
    }

    fn tmp(n: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("aegis-sbom-cont-{n}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn cada_componente_sale_con_la_capa_que_lo_trajo_y_lo_borrado_no_sale() {
        let d = tmp("save");
        let imgs = desde_tar(&docker_save(&d)).unwrap();
        assert_eq!(imgs.len(), 1);
        let img = &imgs[0];
        assert_eq!(img.nombre, "miapp:1");
        let capa_de = |n: &str| {
            img.componentes
                .iter()
                .find(|c| c.nombre == n)
                .and_then(|c| c.capa.as_ref())
                .map(|c| c.indice)
        };
        assert_eq!(capa_de("libc6"), Some(0), "la base trae libc6");
        assert_eq!(capa_de("openssl"), Some(0));
        assert_eq!(
            capa_de("curl"),
            Some(1),
            "curl lo instala la capa de la aplicacion"
        );
        assert_eq!(capa_de("requests"), Some(0));
        assert_eq!(capa_de("serde"), None, "la capa 2 borro el Cargo.lock");
        let libc = img
            .componentes
            .iter()
            .find(|c| c.nombre == "libc6")
            .unwrap();
        assert_eq!(libc.nombre_fuente(), "glibc");
        assert_eq!(
            libc.distro,
            Some(Distro {
                id: "debian".into(),
                version: "12".into()
            })
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn un_directorio_opaco_vacia_lo_de_debajo() {
        let d = tmp("opaco");
        let capa0 = tar(&[("app/requirements.txt", b"flask==3.0.0\n")]);
        let capa1 = tar(&[("app/.wh..wh..opq", b"")]);
        let exterior = tar(&[
            (
                "manifest.json",
                br#"[{"RepoTags":["x:1"],"Layers":["a/layer.tar","b/layer.tar"]}]"#,
            ),
            ("a/layer.tar", &capa0),
            ("b/layer.tar", &capa1),
        ]);
        let r = d.join("x.tar");
        std::fs::write(&r, exterior).unwrap();
        let imgs = desde_tar(&r).unwrap();
        assert!(imgs[0].componentes.is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn una_capa_corrupta_es_un_error_y_no_un_inventario_vacio() {
        let d = tmp("corrupta");
        let mut capa = gzip(&tar(&[("var/lib/dpkg/status", STATUS_BASE)]));
        let n = capa.len();
        capa[n - 6] ^= 0xff;
        let exterior = tar(&[
            (
                "manifest.json",
                br#"[{"RepoTags":["x:1"],"Layers":["a/layer.tar"]}]"#,
            ),
            ("a/layer.tar", &capa),
        ]);
        let r = d.join("x.tar");
        std::fs::write(&r, exterior).unwrap();
        assert!(desde_tar(&r).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn el_layout_oci_da_lo_mismo_que_el_tar() {
        let d = tmp("oci");
        let capa = gzip(&tar(&[
            ("etc/os-release", b"ID=alpine\nVERSION_ID=3.19.1\n"),
            (
                "lib/apk/db/installed",
                b"P:libcrypto3\nV:3.1.4-r5\nA:x86_64\no:openssl\n\n",
            ),
        ]));
        let hc = hex(&Sha256::digest(&capa));
        let manifiesto = format!(
            r#"{{"schemaVersion":2,"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:{hc}"}}]}}"#
        );
        let hm = hex(&Sha256::digest(manifiesto.as_bytes()));
        let blobs = d.join("blobs/sha256");
        std::fs::create_dir_all(&blobs).unwrap();
        std::fs::write(blobs.join(&hc), &capa).unwrap();
        std::fs::write(blobs.join(&hm), &manifiesto).unwrap();
        std::fs::write(
            d.join("index.json"),
            format!(
                r#"{{"manifests":[{{"digest":"sha256:{hm}","annotations":{{"org.opencontainers.image.ref.name":"alpine:3.19"}}}}]}}"#
            ),
        )
        .unwrap();
        let imgs = desde_oci(&d).unwrap();
        let c = &imgs[0].componentes[0];
        assert_eq!(imgs[0].nombre, "alpine:3.19");
        assert_eq!(c.nombre_fuente(), "openssl");
        assert_eq!(
            c.purl(),
            "pkg:apk/alpine/libcrypto3@3.1.4-r5?arch=x86_64&distro=alpine-3.19.1&upstream=openssl"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn chain_id_como_lo_calcula_docker() {
        let a = format!("sha256:{}", "a".repeat(64));
        let b = format!("sha256:{}", "b".repeat(64));
        let v = cadena_de(&[a.clone(), b.clone()]);
        assert_eq!(v[0], a);
        let esperado = format!(
            "sha256:{}",
            hex(&Sha256::digest(format!("{a} {b}").as_bytes()))
        );
        assert_eq!(v[1], esperado);
    }
}
