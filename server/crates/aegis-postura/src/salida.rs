//! El unico camino por el que un inventario de componentes sale del producto.
//!
//! # El escaner como reconocimiento para el atacante
//!
//! Un SBOM es exactamente el mapa que un atacante querria antes de elegir por
//! donde entrar: que version de que biblioteca hay en que maquina. El producto lo
//! construye para defender, y el mismo documento, fuera de la organizacion, sirve
//! para atacar. Por eso:
//!
//! 1. **El agente no sabe escribirlo.** `aegis-sbom` no tiene serializador (la
//!    invariante 12 lo comprueba por ausencia).
//! 2. **Aqui, los formatos son privados.** CycloneDX y SPDX se escriben en
//!    funciones privadas de este modulo; lo unico publico es [`exportar`].
//! 3. **[`exportar`] pasa por el juez de difusion** —el unico estrangulamiento
//!    del producto, [`aegis_share::Difusor`]— con el inventario marcado
//!    [`MARCADO_INVENTARIO`]: `TLP:AMBER+STRICT`, «solo mi organizacion». El
//!    llamante no elige el marcado: no hay parametro con el que rebajarlo.
//!
//! Consecuencias, que las pruebas comprueban canal a canal: el enjambre no lo
//! saca nunca (su tope duro es GREEN); ningun destino que no sea la propia
//! organizacion lo recibe, por ningun canal; y un destino no declarado es un
//! error, no un permiso.
//!
//! Escribir el documento sin pasar por el juez no compila (E0603, privado):
//!
//! ```compile_fail,E0603
//! let _ = aegis_postura::salida::cyclonedx;
//! ```
//!
//! ```compile_fail,E0603
//! let _ = aegis_postura::salida::spdx;
//! ```
//!
//! Y el marcado no se elige: `exportar` no tiene parametro de marcado (E0061,
//! numero de argumentos):
//!
//! ```compile_fail,E0061
//! # use aegis_postura::salida::{exportar, Formato};
//! # let (s, d) = (aegis_sbom::Sbom::default(), aegis_share::Difusor::nuevo());
//! let m = aegis_share::Marcado { tlp: aegis_share::Tlp::Clear, pap: aegis_share::Pap::Clear };
//! let _ = exportar(&s, Formato::Spdx, "x", &d, 0, m);
//! ```

use std::collections::BTreeSet;

use aegis_sbom::componente::{Componente, Ecosistema, Procedencia};
use aegis_sbom::Sbom;
use aegis_share::{Difusor, Marcado, Pap, Retenido, Tlp};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// El marcado de un inventario de componentes.
///
/// `AMBER+STRICT` y no `RED`: el SBOM existe para que el equipo de seguridad de
/// la organizacion trabaje con el —si fuera `RED` no podria salir ni hacia el
/// propio equipo—. `PAP:AMBER`: se puede usar para defender dentro de casa, no
/// para publicar.
pub const MARCADO_INVENTARIO: Marcado = Marcado {
    tlp: Tlp::AmberStrict,
    pap: Pap::Amber,
};

/// En que formato.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Formato {
    /// CycloneDX 1.5, JSON.
    CycloneDx,
    /// SPDX 2.3, JSON.
    Spdx,
}

/// Un documento que ya paso por el juez.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Documento {
    /// Formato.
    pub formato: Formato,
    /// A que destino se autorizo.
    pub destino: String,
    /// El documento.
    pub contenido: String,
}

/// Por que no se exporta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoSale {
    /// El destino no esta declarado: no se reparte a ciegas.
    DestinoDesconocido(String),
    /// El juez lo retiene, con su motivo.
    Retenido(Retenido),
}

impl std::fmt::Display for NoSale {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NoSale::DestinoDesconocido(d) => {
                write!(f, "destino «{d}» no declarado: no se exporta a ciegas")
            }
            NoSale::Retenido(r) => write!(f, "el inventario se retiene: {}", r.texto()),
        }
    }
}

/// Exporta un inventario hacia un destino declarado, si el juez lo permite.
///
/// # Errors
///
/// [`NoSale`] si el destino no existe o el marcado no le deja llegar.
pub fn exportar(
    sbom: &Sbom,
    formato: Formato,
    destino: &str,
    difusor: &Difusor,
    generado_ns: u64,
) -> Result<Documento, NoSale> {
    let d = difusor
        .destino(destino)
        .ok_or_else(|| NoSale::DestinoDesconocido(destino.to_string()))?;
    Difusor::juzgar_marcado(MARCADO_INVENTARIO, false, d).map_err(NoSale::Retenido)?;
    let v = match formato {
        Formato::CycloneDx => cyclonedx(sbom, generado_ns),
        Formato::Spdx => spdx(sbom, generado_ns),
    };
    Ok(Documento {
        formato,
        destino: destino.to_string(),
        contenido: serde_json::to_string_pretty(&v).unwrap_or_default(),
    })
}

/// Fecha RFC 3339 en UTC de un instante en nanosegundos.
fn rfc3339(ns: u64) -> String {
    let s = ns / 1_000_000_000;
    let dias = i64::try_from(s / 86_400).unwrap_or(0);
    let r = s % 86_400;
    let (a, m, d) = aegis_ingest::tiempo::civil_desde_dias(dias);
    format!(
        "{a:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        r / 3600,
        (r / 60) % 60,
        r % 60
    )
}

/// Un identificador estable del inventario: el mismo inventario da el mismo
/// documento, y dos exportaciones se pueden comparar byte a byte.
fn huella(sbom: &Sbom) -> [u8; 32] {
    let mut h = Sha256::new();
    for c in &sbom.componentes {
        h.update(c.purl().as_bytes());
        h.update([0x1f]);
    }
    h.finalize().into()
}

/// Un UUID con la forma de la version 5 sacado de la huella: derivado, no
/// aleatorio, para que el documento sea reproducible.
fn uuid_de(h: &[u8; 32]) -> String {
    let mut b = [0u8; 16];
    b.copy_from_slice(&h[..16]);
    b[6] = (b[6] & 0x0f) | 0x50;
    b[8] = (b[8] & 0x3f) | 0x80;
    let x: String = b.iter().map(|v| format!("{v:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &x[..8],
        &x[8..12],
        &x[12..16],
        &x[16..20],
        &x[20..]
    )
}

fn propiedades(c: &Componente) -> Vec<Value> {
    let mut p = vec![json!({"name": "aegis:procedencia", "value": c.procedencia.nombre()})];
    if let Procedencia::Firma { firma, .. } = &c.procedencia {
        p.push(json!({"name": "aegis:firma", "value": firma}));
    }
    if let Some(k) = &c.capa {
        p.push(json!({"name": "aegis:imagen", "value": k.imagen}));
        p.push(json!({"name": "aegis:capa", "value": k.resumen}));
        p.push(json!({"name": "aegis:capa-indice", "value": k.indice.to_string()}));
    }
    // EL PAQUETE FUENTE, EN LA FORMA QUE LEEN LOS CONSUMIDORES. Los avisos de
    // Debian, Ubuntu y Alpine se publican por paquete fuente, y CycloneDX no
    // tiene un campo estandar para el. El purl ya lo lleva en el calificador
    // `upstream` (la convencion de Syft), pero Trivy no lo lee: lee sus propias
    // propiedades. Medido sobre esta maquina: sin ellas, Trivy encontraba 454
    // vulnerabilidades en el documento; con ellas, 15 818 —las 15 899 de su propio
    // analisis, menos lo que no es un paquete instalado—.
    if matches!(c.ecosistema, Ecosistema::Deb | Ecosistema::Apk) {
        if let Some(f) = &c.fuente {
            p.push(json!({"name": "aquasecurity:trivy:SrcName", "value": f}));
        }
        if let Some(v) = &c.version_fuente {
            let (epoca, resto) = v.split_once(':').unwrap_or(("", v.as_str()));
            let (version, revision) = resto.rsplit_once('-').unwrap_or((resto, ""));
            if !epoca.is_empty() {
                p.push(json!({"name": "aquasecurity:trivy:SrcEpoch", "value": epoca}));
            }
            p.push(json!({"name": "aquasecurity:trivy:SrcVersion", "value": version}));
            if !revision.is_empty() {
                p.push(json!({"name": "aquasecurity:trivy:SrcRelease", "value": revision}));
            }
        }
    }
    p
}

/// CycloneDX 1.5. Privado: solo sale por [`exportar`].
fn cyclonedx(sbom: &Sbom, generado_ns: u64) -> Value {
    let h = huella(sbom);
    let mut refs: BTreeSet<String> = BTreeSet::new();
    // (distro, refs de sus paquetes): el grafo que dice de que sistema es cada
    // paquete del sistema.
    let mut por_distro: std::collections::BTreeMap<(String, String), Vec<String>> =
        std::collections::BTreeMap::new();
    let mut componentes: Vec<Value> = sbom
        .componentes
        .iter()
        .map(|c| {
            let purl = c.purl();
            // `bom-ref` tiene que ser unico en el documento; el mismo purl en
            // dos capas se distingue por la capa.
            let mut r = purl.clone();
            if let Some(k) = &c.capa {
                r.push_str(&format!("#{}@{}", k.imagen, k.indice));
            }
            let mut n = 1;
            let base = r.clone();
            while !refs.insert(r.clone()) {
                n += 1;
                r = format!("{base}#{n}");
            }
            if let (Some(d), None) = (&c.distro, &c.capa) {
                por_distro
                    .entry((d.id.clone(), d.version.clone()))
                    .or_default()
                    .push(r.clone());
            }
            json!({
                "type": "library",
                "bom-ref": r,
                "name": c.nombre,
                "version": c.version,
                "purl": purl,
                "properties": propiedades(c),
            })
        })
        .collect();
    // EL SISTEMA OPERATIVO COMO COMPONENTE. Un paquete deb o apk no se puede
    // evaluar sin saber de que distribucion es: la misma version tiene parches
    // distintos en Ubuntu 22.04 y en Debian 12. CycloneDX lo expresa con un
    // componente `operating-system` del que dependen sus paquetes. Sin el, un
    // consumidor solo puede evaluar las dependencias de lenguaje: medido, Trivy
    // encontraba 408 vulnerabilidades en el documento de esta maquina frente a
    // las 15 899 de su propio analisis, y todas las que faltaban eran del sistema.
    let mut dependencias: Vec<Value> = Vec::new();
    for ((id, version), paquetes) in por_distro {
        let r = format!("os:{id}@{version}");
        componentes.push(json!({
            "type": "operating-system",
            "bom-ref": r,
            "name": id,
            "version": version,
        }));
        dependencias.push(json!({"ref": r, "dependsOn": paquetes}));
    }
    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": format!("urn:uuid:{}", uuid_de(&h)),
        "version": 1,
        "metadata": {
            "timestamp": rfc3339(generado_ns),
            "tools": {"components": [{
                "type": "application",
                "name": "aegis-sbom",
                "version": env!("CARGO_PKG_VERSION"),
            }]},
            "properties": [
                {"name": "aegis:tlp", "value": "TLP:AMBER+STRICT"},
                {"name": "aegis:pap", "value": "PAP:AMBER"},
            ],
        },
        "components": componentes,
        "dependencies": dependencias,
    })
}

/// SPDX 2.3. Privado: solo sale por [`exportar`].
fn spdx(sbom: &Sbom, generado_ns: u64) -> Value {
    let h = huella(sbom);
    let paquetes: Vec<Value> = sbom
        .componentes
        .iter()
        .enumerate()
        .map(|(i, c)| {
            json!({
                "name": c.nombre,
                "SPDXID": format!("SPDXRef-Package-{i}"),
                "versionInfo": c.version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": false,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "externalRefs": [{
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": c.purl(),
                }],
            })
        })
        .collect();
    let relaciones: Vec<Value> = (0..sbom.componentes.len())
        .map(|i| {
            json!({
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": format!("SPDXRef-Package-{i}"),
            })
        })
        .collect();
    let hex: String = h.iter().map(|v| format!("{v:02x}")).collect();
    json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "aegis-sbom",
        "documentNamespace": format!("https://aegiscore.invalid/spdx/{hex}"),
        "comment": "TLP:AMBER+STRICT PAP:AMBER — inventario de componentes de una maquina",
        "creationInfo": {
            "created": rfc3339(generado_ns),
            "creators": [format!("Tool: aegis-sbom-{}", env!("CARGO_PKG_VERSION"))],
        },
        "packages": paquetes,
        "relationships": relaciones,
    })
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn la_fecha_es_rfc_3339() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_700_000_000_000_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn el_uuid_derivado_tiene_la_forma_de_la_version_5() {
        let u = uuid_de(&[0xab; 32]);
        assert_eq!(u.len(), 36);
        assert_eq!(&u[14..15], "5");
        assert!(matches!(&u[19..20], "8" | "9" | "a" | "b"));
    }
}
