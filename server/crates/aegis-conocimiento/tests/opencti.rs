//! Comparativa MEDIDA con OpenCTI: tipos de objeto y relaciones cubiertos.
//!
//! Se mide contra su mapeo de relaciones REAL (`stixCoreRelationshipsMapping`,
//! fijado a un commit en `datos/relaciones-opencti.tsv`), no contra una
//! instancia en marcha: OpenCTI se despliega con Docker, Elasticsearch, Redis,
//! RabbitMQ y MinIO, y esta maquina no tiene Docker. Lo que su mapeo no admite,
//! la plataforma no lo deja crear; asi que la medida es de lo que PUEDE
//! representar.

mod comun;

use std::collections::BTreeMap;

use aegis_conocimiento::catalogo::{self, comparar};
use aegis_prueba::{omitir, Requisito};
use serde_json::Value;

#[test]
fn el_canon_de_stix_contra_el_mapeo_de_opencti() {
    let c = comparar();
    println!(
        "canon STIX 2.1: {} relaciones; AegisKnowledge las recorre todas; OpenCTI admite {} ({} fuera)",
        c.canon,
        c.canon_en_opencti,
        c.canon_fuera_de_opencti.len()
    );
    for (a, r, b) in &c.canon_fuera_de_opencti {
        println!("  fuera de OpenCTI: {a} {r} {b}");
    }
    println!(
        "tipos STIX (SDO+SCO): {}; en alguna relacion de OpenCTI: {}; relaciones suyas fuera del canon: {}; \n         filas cuyo extremo es otra relacion (STIX no lo admite): {}",
        c.tipos_stix,
        c.tipos_stix_en_opencti,
        c.opencti_fuera_del_canon,
        catalogo::opencti().sobre_relaciones
    );
    assert_eq!(c.canon, catalogo::canon_stix21().len());
    assert_eq!(c.canon_en_opencti + c.canon_fuera_de_opencti.len(), c.canon);
    assert_eq!(c.tipos_stix, 37);
}

#[test]
fn las_relaciones_reales_de_attack_contra_el_mapeo_de_opencti() {
    let o = catalogo::opencti();
    let mut total = 0usize;
    let mut admitidas = 0usize;
    let mut fuera: BTreeMap<String, usize> = BTreeMap::new();
    for c in ["enterprise-attack", "ics-attack", "mobile-attack"] {
        let Ok(texto) = std::fs::read_to_string(format!("/opt/aegis-comparativa/attack/{c}.json"))
        else {
            omitir("no esta ATT&CK", Requisito::Attack);
            return;
        };
        let doc: Value = serde_json::from_str(&texto).unwrap();
        let objetos = doc["objects"].as_array().unwrap();
        let tipo: BTreeMap<&str, &str> = objetos
            .iter()
            .map(|x| (x["id"].as_str().unwrap(), x["type"].as_str().unwrap()))
            .collect();
        for r in objetos.iter().filter(|x| x["type"] == "relationship") {
            let (Some(a), Some(b)) = (
                tipo.get(r["source_ref"].as_str().unwrap()),
                tipo.get(r["target_ref"].as_str().unwrap()),
            ) else {
                continue;
            };
            let rel = r["relationship_type"].as_str().unwrap();
            total += 1;
            if o.relaciones
                .contains(&(a.to_string(), rel.to_string(), b.to_string()))
            {
                admitidas += 1;
            } else {
                *fuera.entry(format!("{a} {rel} {b}")).or_insert(0) += 1;
            }
        }
    }
    println!(
        "ATT&CK: {total} relaciones; AegisKnowledge conserva y recorre {total}; el mapeo de OpenCTI admite {admitidas} ({:.1} %)",
        admitidas as f64 * 100.0 / total as f64
    );
    for (t, n) in &fuera {
        println!("  fuera del mapeo de OpenCTI: {t}: {n}");
    }
    assert!(total > 24_000);
    assert!(admitidas < total);
}
