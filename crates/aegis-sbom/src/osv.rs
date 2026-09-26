//! Avisos de vulnerabilidad en formato OSV.
//!
//! # El formato de entrada es OSV, y ninguna base de datos concreta
//!
//! OSV es el esquema abierto en que publican sus avisos Debian, Ubuntu, Alpine,
//! GitHub, RustSec, PyPA, Go y otros, y el que agrega osv.dev. Leer OSV y no el
//! formato de una base de datos concreta significa que el cliente elige de donde
//! salen sus avisos —la exportacion de osv.dev, su propio espejo, un aviso
//! interno escrito a mano— sin que cambie una linea de aqui.
//!
//! # Lo que se lee y lo que no
//!
//! - Rangos `ECOSYSTEM` y `SEMVER` con sus eventos `introduced`, `fixed` y
//!   `last_affected`, y la lista explicita `versions`.
//! - Rangos `GIT`: **no se evaluan**. Un rango de commits no dice nada de una
//!   version instalada sin el repositorio de ese proyecto; un aviso que solo
//!   trae rangos GIT no casa y se cuenta como tal.
//! - Gravedad: el vector CVSS v3 se convierte en puntuacion con la formula
//!   publicada; la de CVSS v4 exige las tablas de macrovectores de la
//!   especificacion y **no se calcula** —se usa la gravedad textual del aviso si
//!   la trae, y si no, se dice que es desconocida—.
//! - Funciones vulnerables: las de Go (`ecosystem_specific.imports[].symbols`)
//!   y las de RustSec (`ecosystem_specific.affects.functions`). Son las que
//!   alimentan la pregunta «¿es alcanzable?».
//!
//! # Entrada hostil
//!
//! Un aviso lo puede escribir cualquiera que publique en la base de datos que el
//! cliente consuma. Todo lleva tope.

use std::path::Path;

use serde_json::Value;

use crate::componente::{Distro, Ecosistema};

/// Tope de bytes de un fichero de avisos.
pub const MAX_FICHERO: u64 = 64 * 1024 * 1024;

/// Tope de avisos que se cargan.
pub const MAX_AVISOS: usize = 2_000_000;

/// Tope de paquetes afectados por aviso.
pub const MAX_AFECTADOS: usize = 10_000;

/// Tope de eventos por rango.
pub const MAX_EVENTOS: usize = 1_000;

/// Tope de versiones explicitas por paquete afectado.
pub const MAX_VERSIONES: usize = 100_000;

/// Un evento de un rango.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Evento {
    /// Desde esta version (incluida) es vulnerable. `"0"` es «desde siempre».
    Introducida(String),
    /// Desde esta version (incluida) ya no lo es.
    Arreglada(String),
    /// Esta es la ultima vulnerable; las posteriores no.
    UltimaAfectada(String),
}

/// Tipo de rango.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TipoRango {
    /// Versiones del ecosistema.
    Ecosistema,
    /// SemVer.
    Semver,
    /// Commits: no evaluable contra una version instalada.
    Git,
}

/// Un rango de versiones afectadas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rango {
    /// Tipo.
    pub tipo: TipoRango,
    /// Eventos, en el orden del aviso.
    pub eventos: Vec<Evento>,
}

/// Un paquete afectado por un aviso.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Afectado {
    /// El ecosistema tal como lo escribe OSV (`Debian:12`, `PyPI`).
    pub ecosistema_osv: String,
    /// Nombre del paquete.
    pub nombre: String,
    /// Rangos.
    pub rangos: Vec<Rango>,
    /// Versiones afectadas enumeradas.
    pub versiones: Vec<String>,
    /// Las funciones vulnerables, si el aviso las dice.
    pub simbolos: Vec<String>,
}

/// La gravedad de un aviso.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum Gravedad {
    /// Puntuacion CVSS v3 calculada del vector.
    Cvss(f32),
    /// Nivel textual del aviso (`critical`, `high`...), en una escala 1..=4.
    Nivel(u8),
    /// El aviso no trae nada que se sepa interpretar.
    Desconocida,
}

impl Gravedad {
    /// Una clave para ordenar de mas grave a menos. Desconocida va al final.
    #[must_use]
    pub fn peso(&self) -> f32 {
        match self {
            Gravedad::Cvss(p) => *p,
            Gravedad::Nivel(n) => f32::from(*n) * 2.5,
            Gravedad::Desconocida => -1.0,
        }
    }

    /// Texto para el informe.
    #[must_use]
    pub fn texto(&self) -> String {
        match self {
            Gravedad::Cvss(p) => format!("CVSS {p:.1}"),
            Gravedad::Nivel(n) => ["baja", "media", "alta", "critica"]
                .get(usize::from(n.saturating_sub(1)))
                .unwrap_or(&"?")
                .to_string(),
            Gravedad::Desconocida => "desconocida".into(),
        }
    }
}

/// Un aviso.
#[derive(Debug, Clone, PartialEq)]
pub struct Aviso {
    /// Identificador (`CVE-...`, `GHSA-...`, `USN-...`, `DSA-...`).
    pub id: String,
    /// Otros identificadores del mismo fallo.
    pub alias: Vec<String>,
    /// Resumen.
    pub resumen: String,
    /// Gravedad.
    pub gravedad: Gravedad,
    /// Paquetes afectados.
    pub afectados: Vec<Afectado>,
    /// Si el aviso esta retirado (`withdrawn`): no aplica a nada.
    pub retirado: bool,
}

// --- CVSS v3 --------------------------------------------------------------------

/// El redondeo hacia arriba a un decimal de CVSS v3.1, sin el error de coma
/// flotante que tenia el de v3.0.
fn redondeo_cvss(x: f64) -> f64 {
    let i = (x * 100_000.0).round() as i64;
    if i % 10_000 == 0 {
        i as f64 / 100_000.0
    } else {
        ((i / 10_000) + 1) as f64 / 10.0
    }
}

/// Puntuacion base de un vector CVSS v3.0 o v3.1.
///
/// Es la formula de la especificacion, sin simplificar: una puntuacion
/// «aproximada» ordena mal justo las vulnerabilidades que estan en la frontera
/// entre alta y critica.
#[must_use]
pub fn cvss3(vector: &str) -> Option<f32> {
    let mut m = std::collections::BTreeMap::new();
    let mut it = vector.split('/');
    let cab = it.next()?;
    if !cab.starts_with("CVSS:3.") {
        return None;
    }
    for p in it {
        let (k, v) = p.split_once(':')?;
        m.insert(k, v);
    }
    let cambia = *m.get("S")? == "C";
    let av = match *m.get("AV")? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return None,
    };
    let ac = match *m.get("AC")? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let pr = match (*m.get("PR")?, cambia) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };
    let ui = match *m.get("UI")? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let cia = |k: &str| -> Option<f64> {
        Some(match *m.get(k)? {
            "H" => 0.56,
            "L" => 0.22,
            "N" => 0.0,
            _ => return None,
        })
    };
    let (c, i, a) = (cia("C")?, cia("I")?, cia("A")?);
    let iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
    let impacto = if cambia {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02f64).powi(15)
    } else {
        6.42 * iss
    };
    let explotabilidad = 8.22 * av * ac * pr * ui;
    if impacto <= 0.0 {
        return Some(0.0);
    }
    let base = if cambia {
        redondeo_cvss((1.08 * (impacto + explotabilidad)).min(10.0))
    } else {
        redondeo_cvss((impacto + explotabilidad).min(10.0))
    };
    Some(base as f32)
}

fn nivel_textual(s: &str) -> Option<u8> {
    Some(match s.trim().to_ascii_lowercase().as_str() {
        "critical" | "critica" => 4,
        "high" | "important" | "alta" => 3,
        "medium" | "moderate" | "media" => 2,
        "low" | "negligible" | "baja" => 1,
        _ => return None,
    })
}

fn gravedad_de(v: &Value) -> Gravedad {
    let mut textual = None;
    for s in v
        .get("severity")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(16)
    {
        let tipo = s.get("type").and_then(Value::as_str).unwrap_or("");
        let pun = s.get("score").and_then(Value::as_str).unwrap_or("");
        if tipo == "CVSS_V3" {
            if let Some(p) = cvss3(pun) {
                return Gravedad::Cvss(p);
            }
        }
        if let Some(n) = nivel_textual(pun) {
            textual = Some(n);
        }
    }
    let db = v
        .get("database_specific")
        .and_then(|d| d.get("severity"))
        .and_then(Value::as_str)
        .and_then(nivel_textual);
    match textual.or(db) {
        Some(n) => Gravedad::Nivel(n),
        None => Gravedad::Desconocida,
    }
}

fn texto(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or("").to_string()
}

fn simbolos_de(eco: &Value) -> Vec<String> {
    let mut s = Vec::new();
    // Go: imports[].symbols, con la ruta del paquete delante.
    for imp in eco
        .get("imports")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(256)
    {
        let ruta = texto(imp, "path");
        for sim in imp
            .get("symbols")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .take(1024)
        {
            if let Some(n) = sim.as_str() {
                s.push(if ruta.is_empty() {
                    n.to_string()
                } else {
                    format!("{ruta}.{n}")
                });
            }
        }
    }
    // RustSec: affects.functions, rutas completas `crate::modulo::funcion`.
    for f in eco
        .get("affects")
        .and_then(|a| a.get("functions"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(1024)
    {
        if let Some(n) = f.as_str() {
            s.push(n.to_string());
        }
    }
    s
}

/// Que paquetes afectados de un aviso interesan: (ecosistema de OSV, nombre).
pub type Filtro<'a> = &'a dyn Fn(&str, &str) -> bool;

/// Analiza un aviso OSV entero.
#[must_use]
pub fn aviso(v: &Value) -> Option<Aviso> {
    aviso_filtrado(v, &|_, _| true)
}

/// Analiza un aviso OSV quedandose solo con los paquetes afectados que pasan el
/// filtro.
///
/// # Por que se filtra AL LEER
///
/// Un aviso de Ubuntu trae los paquetes afectados de TODAS sus versiones, y cada
/// uno con la lista entera de versiones afectadas: un CVE del nucleo enumera
/// decenas de variantes con cientos de versiones cada una. Cargar la exportacion
/// de Ubuntu entera para cotejar una maquina costo 3,5 GB, medido. Lo que no
/// puede casar con nada del inventario —otra version de la distribucion, un
/// paquete que no esta instalado— se descarta antes de leer sus rangos y sus
/// versiones, que es donde esta el volumen.
#[must_use]
pub fn aviso_filtrado(v: &Value, filtro: Filtro<'_>) -> Option<Aviso> {
    let id = texto(v, "id");
    if id.is_empty() {
        return None;
    }
    let mut afectados = Vec::new();
    for a in v
        .get("affected")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_AFECTADOS)
    {
        // Una entrada sin paquete no invalida el resto del aviso: se salta ella.
        let Some(p) = a.get("package") else {
            continue;
        };
        if !filtro(
            p.get("ecosystem").and_then(Value::as_str).unwrap_or(""),
            p.get("name").and_then(Value::as_str).unwrap_or(""),
        ) {
            continue;
        }
        let mut rangos = Vec::new();
        for r in a
            .get("ranges")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .take(64)
        {
            let tipo = match r.get("type").and_then(Value::as_str) {
                Some("ECOSYSTEM") => TipoRango::Ecosistema,
                Some("SEMVER") => TipoRango::Semver,
                Some("GIT") => TipoRango::Git,
                _ => continue,
            };
            let mut eventos = Vec::new();
            for e in r
                .get("events")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .take(MAX_EVENTOS)
            {
                if let Some(x) = e.get("introduced").and_then(Value::as_str) {
                    eventos.push(Evento::Introducida(x.into()));
                } else if let Some(x) = e.get("fixed").and_then(Value::as_str) {
                    eventos.push(Evento::Arreglada(x.into()));
                } else if let Some(x) = e.get("last_affected").and_then(Value::as_str) {
                    eventos.push(Evento::UltimaAfectada(x.into()));
                }
            }
            rangos.push(Rango { tipo, eventos });
        }
        afectados.push(Afectado {
            ecosistema_osv: texto(p, "ecosystem"),
            nombre: texto(p, "name"),
            rangos,
            versiones: a
                .get("versions")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .take(MAX_VERSIONES)
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect(),
            simbolos: a
                .get("ecosystem_specific")
                .map(simbolos_de)
                .unwrap_or_default(),
        });
    }
    Some(Aviso {
        id,
        alias: v
            .get("aliases")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .take(64)
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect(),
        resumen: texto(v, "summary").chars().take(512).collect(),
        gravedad: gravedad_de(v),
        afectados,
        retirado: v.get("withdrawn").is_some(),
    })
}

/// Analiza un documento OSV: un aviso o una lista de avisos.
#[must_use]
pub fn documento(texto: &str) -> Vec<Aviso> {
    let Ok(v) = serde_json::from_str::<Value>(texto) else {
        return Vec::new();
    };
    match v {
        Value::Array(a) => a.iter().take(MAX_AVISOS).filter_map(aviso).collect(),
        o => aviso(&o).into_iter().collect(),
    }
}

/// Lo que se cargo de un directorio de avisos.
#[derive(Debug, Clone, Default)]
pub struct Carga {
    /// Los avisos.
    pub avisos: Vec<Aviso>,
    /// Ficheros leidos.
    pub ficheros: usize,
    /// Ficheros que no se pudieron leer o analizar: se cuentan, porque un
    /// aviso que no se cargo es una vulnerabilidad que no se buscara.
    pub ilegibles: usize,
    /// Avisos validos que no afectan a nada del inventario y se descartaron al
    /// leer. Van aparte de los ilegibles: no son un fallo de lectura.
    pub descartados: usize,
}

/// Carga todos los `*.json` de un directorio (sin recursion).
#[must_use]
pub fn cargar_directorio(dir: &Path) -> Carga {
    cargar_directorio_filtrado(dir, &|_, _| true)
}

/// Carga los avisos de un directorio quedandose con lo que pasa el filtro.
///
/// Ver [`aviso_filtrado`] para el porque. Un aviso sin ningun paquete afectado
/// que interese se descarta entero y se cuenta en [`Carga::descartados`].
#[must_use]
pub fn cargar_directorio_filtrado(dir: &Path, filtro: Filtro<'_>) -> Carga {
    let mut c = Carga::default();
    let Ok(it) = std::fs::read_dir(dir) else {
        return c;
    };
    let mut rutas: Vec<_> = it
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    rutas.sort();
    for r in rutas {
        if c.avisos.len() >= MAX_AVISOS {
            break;
        }
        let Some(t) = std::fs::metadata(&r)
            .ok()
            .filter(|m| m.len() <= MAX_FICHERO)
            .and_then(|_| std::fs::read_to_string(&r).ok())
        else {
            c.ilegibles += 1;
            continue;
        };
        let Ok(doc) = serde_json::from_str::<Value>(&t) else {
            c.ilegibles += 1;
            continue;
        };
        drop(t);
        let crudos: Vec<&Value> = match &doc {
            Value::Array(a) => a.iter().take(MAX_AVISOS).collect(),
            o => vec![o],
        };
        let mut validos = 0usize;
        for v in crudos {
            let Some(a) = aviso_filtrado(v, filtro) else {
                continue;
            };
            validos += 1;
            if a.afectados.is_empty() {
                c.descartados += 1;
            } else {
                c.avisos.push(a);
            }
        }
        if validos == 0 {
            c.ilegibles += 1;
        } else {
            c.ficheros += 1;
        }
    }
    c
}

/// A que ecosistema del inventario corresponde un ecosistema de OSV, y para que
/// distribucion.
///
/// `Ubuntu:Pro:...` son avisos de paquetes de mantenimiento extendido: sus
/// versiones corregidas solo existen con una suscripcion, y casarlos contra una
/// maquina sin ella diria «actualiza a una version que no puedes instalar». Se
/// dejan fuera y se dice aqui.
#[must_use]
pub fn ecosistema_de(osv: &str) -> Option<(Ecosistema, Option<Distro>)> {
    let partes: Vec<&str> = osv.split(':').collect();
    let distro = |id: &str, v: &str| {
        Some(Distro {
            id: id.into(),
            version: v.into(),
        })
    };
    Some(match partes.as_slice() {
        ["Debian", v, ..] => (Ecosistema::Deb, distro("debian", v)),
        ["Ubuntu", "Pro", ..] => return None,
        ["Ubuntu", v, ..] => (Ecosistema::Deb, distro("ubuntu", v)),
        ["Alpine", v, ..] => (Ecosistema::Apk, distro("alpine", v.trim_start_matches('v'))),
        ["crates.io"] => (Ecosistema::Cargo, None),
        ["npm"] => (Ecosistema::Npm, None),
        ["PyPI"] => (Ecosistema::PyPI, None),
        ["Go"] => (Ecosistema::Go, None),
        _ => return None,
    })
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn cvss_31_con_los_ejemplos_de_la_especificacion() {
        let casos = [
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
            ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
            ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
            ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ];
        for (v, p) in casos {
            assert_eq!(cvss3(v), Some(p), "{v}");
        }
        assert_eq!(
            cvss3("CVSS:4.0/AV:N"),
            None,
            "v4 no se calcula con la formula de v3"
        );
        assert_eq!(cvss3("CVSS:3.1/AV:X/AC:L"), None);
    }

    const AVISO: &str = r#"{
      "id": "GO-2023-2102", "aliases": ["CVE-2023-39325","GHSA-4374-p667-p6c8"],
      "summary": "HTTP/2 rapid reset",
      "severity": [{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}],
      "affected": [{
        "package": {"ecosystem":"Go","name":"golang.org/x/net"},
        "ranges": [{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.17.0"}]},
                   {"type":"GIT","repo":"x","events":[{"introduced":"0"}]}],
        "ecosystem_specific": {"imports":[{"path":"golang.org/x/net/http2",
            "symbols":["Server.ServeConn","serverConn.serve"]}]}
      }]
    }"#;

    #[test]
    fn se_lee_un_aviso_de_go_con_sus_funciones() {
        let a = &documento(AVISO)[0];
        assert_eq!(a.id, "GO-2023-2102");
        assert_eq!(a.gravedad, Gravedad::Cvss(7.5));
        let af = &a.afectados[0];
        assert_eq!(af.rangos.len(), 2);
        assert_eq!(af.rangos[1].tipo, TipoRango::Git);
        assert_eq!(
            af.simbolos,
            [
                "golang.org/x/net/http2.Server.ServeConn",
                "golang.org/x/net/http2.serverConn.serve"
            ]
        );
    }

    #[test]
    fn gravedad_textual_de_ubuntu_y_de_la_base_de_datos() {
        let u = r#"{"id":"UBUNTU-CVE-2024-1","severity":[{"type":"Ubuntu","score":"medium"}],"affected":[]}"#;
        assert_eq!(documento(u)[0].gravedad, Gravedad::Nivel(2));
        let g = r#"{"id":"GHSA-x","database_specific":{"severity":"HIGH"},"affected":[]}"#;
        assert_eq!(documento(g)[0].gravedad, Gravedad::Nivel(3));
        let n = r#"{"id":"X-1","affected":[]}"#;
        assert_eq!(documento(n)[0].gravedad, Gravedad::Desconocida);
    }

    #[test]
    fn ecosistemas() {
        assert_eq!(
            ecosistema_de("Ubuntu:24.04:LTS"),
            Some((
                Ecosistema::Deb,
                Some(Distro {
                    id: "ubuntu".into(),
                    version: "24.04".into()
                })
            ))
        );
        assert_eq!(ecosistema_de("Ubuntu:Pro:24.04:LTS"), None);
        assert_eq!(
            ecosistema_de("Alpine:v3.19").unwrap().1.unwrap().version,
            "3.19"
        );
        assert_eq!(ecosistema_de("crates.io").unwrap().0, Ecosistema::Cargo);
        assert_eq!(ecosistema_de("Maven"), None);
    }

    #[test]
    fn un_documento_basura_no_da_avisos() {
        assert!(documento("{no es json").is_empty());
        assert!(documento(r#"{"sin":"id"}"#).is_empty());
    }
}
