//! Las relaciones que define STIX 2.1, y las que admite OpenCTI, como DATOS.
//!
//! # Por que tablas y no una lista escrita a mano
//!
//! Una lista de relaciones escrita de memoria se parece mucho a la de la
//! especificacion y no es la de la especificacion. Estas salen de sus fuentes,
//! fijadas a una version y regeneradas por `tools/tablas-stix.py`:
//!
//! - `datos/relaciones-stix21.tsv`: el Apendice B del texto normativo de STIX
//!   2.1 y el validador oficial de OASIS, con la procedencia de cada fila. Donde
//!   discrepan, manda lo que la especificacion declara autoritativo (las
//!   secciones de cada objeto); lo que solo esta en el validador se registra y
//!   queda FUERA del canon.
//! - `datos/relaciones-opencti.tsv`: el `stixCoreRelationshipsMapping` de
//!   OpenCTI, con cada constante resuelta leyendo el fichero que la define.
//!
//! # Lo que el catalogo NO hace: rechazar
//!
//! Una relacion fuera del vocabulario no es un error: la especificacion dice que
//! `relationship_type` «SHOULD» ser uno de los definidos «but MAY be any
//! string», y ATT&CK usa `subtechnique-of`, `detects` y `revoked-by`. El
//! catalogo la CLASIFICA ([`Admision`]); el grafo la conserva y la recorre
//! igual. Rechazarla perderia justo lo que otro nodo si entiende.

use std::collections::BTreeSet;

const STIX21: &str = include_str!("../datos/relaciones-stix21.tsv");
const OPENCTI: &str = include_str!("../datos/relaciones-opencti.tsv");

/// Las relaciones comunes a cualquier par de objetos (seccion 3.7).
pub const COMUNES: [&str; 3] = ["derived-from", "duplicate-of", "related-to"];

/// Como encaja una relacion en la especificacion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Admision {
    /// Definida por STIX 2.1 para esos tipos.
    Especificacion,
    /// Una de las comunes, valida entre cualquier par.
    Comun,
    /// Fuera del vocabulario: se conserva y se recorre, y se dice.
    Personalizada,
}

impl Admision {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Admision::Especificacion => "especificacion",
            Admision::Comun => "comun",
            Admision::Personalizada => "personalizada",
        }
    }
}

/// Una relacion entre tipos: origen, tipo de relacion, destino.
pub type Triple = (String, String, String);

fn filas(tsv: &'static str) -> impl Iterator<Item = Vec<&'static str>> {
    tsv.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| l.split('\t').collect())
}

/// Las relaciones del canon de STIX 2.1 (sin las que solo trae el validador).
#[must_use]
pub fn canon_stix21() -> BTreeSet<Triple> {
    filas(STIX21)
        .filter(|c| c.len() >= 4 && c[3] != "solo-validador")
        .map(|c| (c[0].to_string(), c[1].to_string(), c[2].to_string()))
        .collect()
}

/// Las que el validador trae y la especificacion no: fuera del canon.
#[must_use]
pub fn solo_validador() -> BTreeSet<Triple> {
    filas(STIX21)
        .filter(|c| c.len() >= 4 && c[3] == "solo-validador")
        .map(|c| (c[0].to_string(), c[1].to_string(), c[2].to_string()))
        .collect()
}

/// Los tipos de objeto de dominio (SDO) de STIX 2.1.
#[must_use]
pub fn sdo() -> Vec<&'static str> {
    cabecera(STIX21, "# SDO: ")
        .into_iter()
        // La linea del validador mezcla los SDO con los objetos que no lo son.
        .filter(|t| {
            !matches!(
                *t,
                "bundle"
                    | "relationship"
                    | "sighting"
                    | "language-content"
                    | "marking-definition"
                    | "extension-definition"
            )
        })
        .collect()
}

/// Los tipos de objeto observable (SCO) de STIX 2.1.
#[must_use]
pub fn sco() -> Vec<&'static str> {
    cabecera(STIX21, "# SCO: ")
}

fn cabecera(tsv: &'static str, prefijo: &str) -> Vec<&'static str> {
    tsv.lines()
        .find_map(|l| l.strip_prefix(prefijo))
        .map(|l| l.split(',').map(str::trim).collect())
        .unwrap_or_default()
}

/// Clasifica una relacion concreta.
#[must_use]
pub fn admision(canon: &BTreeSet<Triple>, origen: &str, tipo: &str, destino: &str) -> Admision {
    if COMUNES.contains(&tipo) {
        return Admision::Comun;
    }
    if canon.contains(&(origen.to_string(), tipo.to_string(), destino.to_string())) {
        Admision::Especificacion
    } else {
        Admision::Personalizada
    }
}

/// Las relaciones que admite OpenCTI, TRADUCIDAS a tipos STIX.
///
/// OpenCTI subdivide tipos STIX (`identity` en `Individual`, `Organization`,
/// `Sector`, `System`, `SecurityPlatform`; `location` en cinco; `threat-actor`
/// en dos mas el abstracto) y anade otros propios (`Event`, `Channel`,
/// `Narrative`, observables que STIX no tiene). Para comparar cobertura se
/// traduce cada tipo suyo al STIX que representa; los que no representan
/// ninguno se cuentan aparte ([`Opencti::propios`]).
#[derive(Debug, Clone, Default)]
pub struct Opencti {
    /// Relaciones entre tipos STIX que admite.
    pub relaciones: BTreeSet<Triple>,
    /// Tipos suyos que no son de STIX.
    pub propios: BTreeSet<String>,
    /// Filas cuyo extremo es OTRA relacion (un `targets` situado en un lugar,
    /// un indicador que indica un `uses`): OpenCTI las admite; STIX 2.1 no
    /// (`source_ref` y `target_ref` no pueden apuntar a una SRO, seccion 5.1.2).
    pub sobre_relaciones: usize,
    /// Filas de su tabla.
    pub filas: usize,
}

/// El tipo STIX que representa un tipo de OpenCTI, si representa alguno.
#[must_use]
pub fn stix_de_opencti(t: &str) -> Option<&'static str> {
    Some(match t {
        "Attack-Pattern" => "attack-pattern",
        "Campaign" => "campaign",
        "Course-Of-Action" => "course-of-action",
        "Individual" | "Organization" | "Sector" | "System" | "SecurityPlatform"
        | "Security-Platform" | "Identity" => "identity",
        "Incident" => "incident",
        "Indicator" => "indicator",
        "Infrastructure" => "infrastructure",
        "Intrusion-Set" => "intrusion-set",
        "City" | "Country" | "Region" | "Position" | "Administrative-Area" | "Location" => {
            "location"
        }
        "Malware" => "malware",
        "Malware-Analysis" => "malware-analysis",
        "Observed-Data" => "observed-data",
        "Report" => "report",
        "Note" => "note",
        "Opinion" => "opinion",
        "Grouping" => "grouping",
        "Threat-Actor" | "Threat-Actor-Group" | "Threat-Actor-Individual" => "threat-actor",
        "Tool" => "tool",
        "Vulnerability" => "vulnerability",
        "Artifact" => "artifact",
        "Autonomous-System" => "autonomous-system",
        "Directory" => "directory",
        "Domain-Name" => "domain-name",
        "Email-Addr" => "email-addr",
        "Email-Message" => "email-message",
        "StixFile" => "file",
        "IPv4-Addr" => "ipv4-addr",
        "IPv6-Addr" => "ipv6-addr",
        "Mac-Addr" => "mac-addr",
        "Mutex" => "mutex",
        "Network-Traffic" => "network-traffic",
        "Process" => "process",
        "Software" => "software",
        "Url" => "url",
        "User-Account" => "user-account",
        "Windows-Registry-Key" => "windows-registry-key",
        "X509-Certificate" => "x509-certificate",
        // Los tipos personalizados de ATT&CK que OpenCTI modela con nombre
        // propio (su conector de MITRE los traduce a estos).
        "Data-Component" => "x-mitre-data-component",
        "Data-Source" => "x-mitre-data-source",
        _ => return None,
    })
}

/// La tabla de OpenCTI, traducida.
#[must_use]
pub fn opencti() -> Opencti {
    // Un extremo en minusculas es el nombre de una relacion, no de un tipo.
    let es_relacion = |t: &str| t.bytes().all(|b| b.is_ascii_lowercase() || b == b'-');
    // `Stix-Cyber-Observable` es el tipo ABSTRACTO de todos los observables:
    // una fila con el vale para cada uno de los 18 SCO.
    let expandir = |t: &str| -> Option<Vec<&'static str>> {
        if t == "Stix-Cyber-Observable" {
            Some(sco())
        } else {
            stix_de_opencti(t).map(|s| vec![s])
        }
    };
    let mut o = Opencti::default();
    for c in filas(OPENCTI) {
        if c.len() < 3 {
            continue;
        }
        o.filas += 1;
        if es_relacion(c[0]) || es_relacion(c[2]) {
            o.sobre_relaciones += 1;
            continue;
        }
        match (expandir(c[0]), expandir(c[2])) {
            (Some(origenes), Some(destinos)) => {
                for a in &origenes {
                    for b in &destinos {
                        o.relaciones
                            .insert(((*a).to_string(), c[1].to_string(), (*b).to_string()));
                    }
                }
            }
            (a, b) => {
                if a.is_none() {
                    o.propios.insert(c[0].to_string());
                }
                if b.is_none() {
                    o.propios.insert(c[2].to_string());
                }
            }
        }
    }
    o
}

/// La comparacion con OpenCTI sobre el canon de STIX 2.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comparativa {
    /// Relaciones del canon.
    pub canon: usize,
    /// Las del canon que el mapeo de OpenCTI admite.
    pub canon_en_opencti: usize,
    /// Las del canon que el mapeo de OpenCTI NO admite.
    pub canon_fuera_de_opencti: Vec<Triple>,
    /// Relaciones entre tipos STIX que OpenCTI admite y el canon no define.
    pub opencti_fuera_del_canon: usize,
    /// Tipos STIX (SDO y SCO).
    pub tipos_stix: usize,
    /// Los que aparecen en alguna relacion de OpenCTI.
    pub tipos_stix_en_opencti: usize,
}

/// Compara el canon con el mapeo de OpenCTI.
///
/// Este lado las cubre todas por construccion: el grafo recorre cualquier
/// relacion, dentro del canon o fuera, y solo la clasifica. Lo que se mide es
/// que admite OpenCTI, cuyo mapeo si es cerrado: una relacion fuera de el no se
/// puede crear en la plataforma.
#[must_use]
pub fn comparar() -> Comparativa {
    let canon = canon_stix21();
    let o = opencti();
    let fuera: Vec<Triple> = canon.difference(&o.relaciones).cloned().collect();
    let tipos: BTreeSet<&str> = sdo().into_iter().chain(sco()).collect();
    let en_opencti: BTreeSet<&str> = o
        .relaciones
        .iter()
        .flat_map(|(a, _, b)| [a.as_str(), b.as_str()])
        .filter(|t| tipos.contains(t))
        .collect();
    Comparativa {
        canon: canon.len(),
        canon_en_opencti: canon.len() - fuera.len(),
        canon_fuera_de_opencti: fuera,
        opencti_fuera_del_canon: o.relaciones.difference(&canon).count(),
        tipos_stix: tipos.len(),
        tipos_stix_en_opencti: en_opencti.len(),
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn el_canon_sale_de_la_tabla_y_excluye_lo_que_solo_trae_el_validador() {
        let c = canon_stix21();
        assert!(c.len() > 120, "{}", c.len());
        assert!(c.contains(&(
            "malware".into(),
            "exfiltrates-to".into(),
            "infrastructure".into()
        )));
        assert!(c.contains(&(
            "course-of-action".into(),
            "remediates".into(),
            "malware".into()
        )));
        assert!(
            !c.iter().any(|(_, r, _)| r == "impacts"),
            "impacts no esta en la especificacion"
        );
        assert!(solo_validador().iter().all(|(_, r, _)| r == "impacts"));
        assert_eq!(sdo().len(), 19);
        assert_eq!(sco().len(), 18);
    }

    #[test]
    fn clasifica_sin_rechazar() {
        let c = canon_stix21();
        assert_eq!(
            admision(&c, "intrusion-set", "uses", "malware"),
            Admision::Especificacion
        );
        assert_eq!(
            admision(&c, "malware", "related-to", "vulnerability"),
            Admision::Comun
        );
        assert_eq!(
            admision(&c, "attack-pattern", "subtechnique-of", "attack-pattern"),
            Admision::Personalizada
        );
    }

    #[test]
    fn opencti_se_traduce_y_sus_tipos_propios_se_cuentan_aparte() {
        let o = opencti();
        assert!(o.filas > 400);
        assert!(o
            .relaciones
            .contains(&("intrusion-set".into(), "uses".into(), "malware".into())));
        assert!(o.propios.contains("Event"));
    }
}
