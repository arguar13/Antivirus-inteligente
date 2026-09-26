//! Utilidades comunes: fuentes con su fiabilidad y paquetes STIX 2.1 marcados.

#![allow(dead_code)]

use aegis_conocimiento::grafo::Grafo;
use aegis_conocimiento::intercambio;
use aegis_entidad::entidad;
use aegis_share::procedencia::{Aporte, Fiabilidad};
use serde_json::{json, Value};

/// 2026-09-26T00:00:00Z.
pub const AHORA: u64 = 1_790_380_800_000_000_000;

/// La definicion TLP 2.0 de TLP:GREEN (identificador publicado por FIRST/OASIS).
pub const TLP_GREEN: &str = "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb";

/// Un aporte de una fuente.
pub fn aporte(fuente: &str, fiabilidad: Fiabilidad, confianza: u8) -> Aporte {
    Aporte {
        fuente: fuente.to_string(),
        fiabilidad,
        cadena: Vec::new(),
        cuando_ns: AHORA,
        confianza_declarada: confianza,
        id_en_origen: String::new(),
    }
}

/// Un identificador STIX estable para un tipo y un numero.
pub fn id(tipo: &str, n: u32) -> String {
    format!("{tipo}--00000000-0000-4000-8000-{n:012}")
}

fn base(tipo: &str, n: u32) -> serde_json::Map<String, Value> {
    let mut m = serde_json::Map::new();
    m.insert("type".into(), json!(tipo));
    m.insert("spec_version".into(), json!("2.1"));
    m.insert("id".into(), json!(id(tipo, n)));
    m.insert("created".into(), json!("2026-09-01T00:00:00Z"));
    m.insert("modified".into(), json!("2026-09-01T00:00:00Z"));
    m
}

/// Un SDO con nombre.
pub fn sdo(tipo: &str, n: u32, nombre: &str) -> Value {
    let mut m = base(tipo, n);
    m.insert("name".into(), json!(nombre));
    if tipo == "malware" {
        m.insert("is_family".into(), json!(true));
    }
    Value::Object(m)
}

/// Una relacion.
pub fn relacion(n: u32, origen: &str, tipo: &str, destino: &str) -> Value {
    let mut m = base("relationship", n);
    m.insert("relationship_type".into(), json!(tipo));
    m.insert("source_ref".into(), json!(origen));
    m.insert("target_ref".into(), json!(destino));
    Value::Object(m)
}

/// Un indicador de un SHA-256.
pub fn indicador_sha(n: u32, sha: &str) -> Value {
    let mut m = base("indicator", n);
    m.insert("name".into(), json!(format!("hash {}", &sha[..8])));
    m.insert(
        "pattern".into(),
        json!(format!("[file:hashes.'SHA-256' = '{sha}']")),
    );
    m.insert("pattern_type".into(), json!("stix"));
    m.insert("valid_from".into(), json!("2026-09-01T00:00:00Z"));
    Value::Object(m)
}

/// Un paquete TLP:GREEN con estos objetos.
pub fn paquete(objetos: Vec<Value>) -> String {
    let mut todos = vec![json!({
        "type": "marking-definition", "spec_version": "2.1", "id": TLP_GREEN,
        "created": "2022-10-01T00:00:00Z", "name": "TLP:GREEN", "extensions": {}
    })];
    for mut o in objetos {
        o["object_marking_refs"] = json!([TLP_GREEN]);
        todos.push(o);
    }
    json!({"type": "bundle", "id": "bundle--00000000-0000-4000-8000-000000000000", "objects": todos}).to_string()
}

/// Importa un paquete de una fuente.
pub fn importar(
    g: &mut Grafo,
    fuente: &str,
    fiabilidad: Fiabilidad,
    confianza: u8,
    objetos: Vec<Value>,
) {
    intercambio::importar(g, &paquete(objetos), &aporte(fuente, fiabilidad, confianza))
        .unwrap_or_else(|e| panic!("{fuente}: {}", e.texto()));
}

/// La maquina `n` de la flota.
pub fn maquina(n: u32) -> aegis_entidad::Eid {
    entidad::maquina(&format!("srv-{n:03}"))
}

/// Un SHA-256 de prueba derivado de un texto.
pub fn sha(texto: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(texto.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
