//! MITRE ATT&CK en STIX 2.1, entero, contra el lector por objetos.
//!
//! Son las colecciones reales que publica MITRE (Enterprise, ICS y Mobile, unos
//! 31 000 objetos): tipos personalizados (`x-mitre-*`), propiedades
//! personalizadas (`x_mitre_*`) y tipos de relacion fuera del vocabulario
//! (`subtechnique-of`, `detects`, `revoked-by`). Se comprueba que cada objeto se
//! valida y que su documento sale IGUAL que entro: lo que este nodo no entiende
//! no se pierde.
//!
//! Los ficheros los descarga `tools/verificar-conocimiento.sh` en
//! `/opt/aegis-comparativa/attack`; sin ellos, la prueba se OMITE y lo dice.

use aegis_prueba::{omitir, Requisito};
use aegis_share::stix::Paquete;
use serde_json::Value;

const DIR: &str = "/opt/aegis-comparativa/attack";

#[test]
fn attack_entero_ida_y_vuelta_sin_perder_nada() {
    let mut total = 0;
    for coleccion in ["enterprise-attack", "ics-attack", "mobile-attack"] {
        let ruta = format!("{DIR}/{coleccion}.json");
        let Ok(texto) = std::fs::read_to_string(&ruta) else {
            omitir(&format!("no esta {ruta}"), Requisito::Attack);
            return;
        };
        // La referencia: el documento analizado entero por serde_json.
        let original: Value = serde_json::from_str(&texto).unwrap();
        let originales: std::collections::BTreeMap<String, &Value> = original["objects"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| (o["id"].as_str().unwrap().to_string(), o))
            .collect();

        let mut vistos = 0usize;
        let mut distintos = Vec::new();
        let r = Paquete::recorrer(&texto, |o| {
            vistos += 1;
            if originales.get(&o.id) != Some(&&Value::Object(o.crudo.clone())) {
                distintos.push(o.id.clone());
            }
        })
        .unwrap_or_else(|e| panic!("{coleccion}: {}", e.texto()));
        assert_eq!(r.objetos, originales.len(), "{coleccion}");
        assert_eq!(vistos, originales.len());
        assert!(
            distintos.is_empty(),
            "{coleccion}: salen distintos {:?}",
            &distintos[..distintos.len().min(5)]
        );
        // Paquete::validar no puede con el entero: el tope de seguridad sigue.
        if texto.len() > aegis_share::stix::MAX_PAQUETE {
            assert!(Paquete::validar(&texto).is_err());
        }
        println!("{coleccion}: {} objetos, ida y vuelta identica", r.objetos);
        total += r.objetos;
    }
    println!("ATT&CK: {total} objetos");
}

/// Un paquete pequeno con cuatro objetos: uno sin marcado, uno marcado AMBER
/// por la definicion TLP 2.0, uno cuya referencia de marcado no resuelve, y la
/// propia definicion.
fn cuatro() -> String {
    serde_json::json!({
        "type": "bundle", "id": "bundle--11111111-1111-4111-8111-111111111111",
        "objects": [
            {"type": "marking-definition", "spec_version": "2.1",
             "id": "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
             "created": "2022-10-01T00:00:00Z", "name": "TLP:AMBER", "extensions": {}},
            {"type": "malware", "spec_version": "2.1", "id": "malware--00000000-0000-4000-8000-000000000001",
             "created": "2026-01-01T00:00:00Z", "modified": "2026-01-01T00:00:00Z",
             "name": "sin marcado", "is_family": true},
            {"type": "malware", "spec_version": "2.1", "id": "malware--00000000-0000-4000-8000-000000000002",
             "created": "2026-01-01T00:00:00Z", "modified": "2026-01-01T00:00:00Z",
             "name": "ambar", "is_family": true,
             "object_marking_refs": ["marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421"]},
            {"type": "malware", "spec_version": "2.1", "id": "malware--00000000-0000-4000-8000-000000000003",
             "created": "2026-01-01T00:00:00Z", "modified": "2026-01-01T00:00:00Z",
             "name": "marca que no viaja", "is_family": true,
             "object_marking_refs": ["marking-definition--99999999-9999-4999-8999-999999999999"]}
        ]
    })
    .to_string()
}

fn marcados(
    declaracion: Option<&aegis_share::Declaracion>,
) -> std::collections::BTreeMap<String, aegis_share::Tlp> {
    let mut m = std::collections::BTreeMap::new();
    let mut anotar = |o: aegis_share::Objeto| {
        if let Some(n) = o.texto("name") {
            m.insert(n.to_string(), o.marcado.tlp);
        }
    };
    match declaracion {
        Some(d) => Paquete::recorrer_declarado(&cuatro(), d, &mut anotar).unwrap(),
        None => Paquete::recorrer(&cuatro(), &mut anotar).unwrap(),
    };
    m
}

#[test]
fn una_coleccion_declarada_publica_solo_abre_lo_que_calla() {
    use aegis_share::{Declaracion, Marcado, Tlp};
    // Sin declaracion: lo que calla es RED.
    let sin = marcados(None);
    assert_eq!(sin["sin marcado"], Tlp::Red);
    assert_eq!(sin["ambar"], Tlp::Amber);
    // Con la coleccion declarada publica, con autor:
    let d = Declaracion {
        marcado: Marcado::publico(),
        por: "ana (ATT&CK es publico por licencia)".into(),
    };
    let con = marcados(Some(&d));
    assert_eq!(
        con["sin marcado"],
        Tlp::Clear,
        "lo que calla toma lo declarado"
    );
    assert_eq!(con["ambar"], Tlp::Amber, "lo que el objeto dice manda");
    assert_eq!(
        con["marca que no viaja"],
        Tlp::Red,
        "lo que no resuelve sigue en RED"
    );
    // Una declaracion sin autor no es una declaracion.
    let anonima = Declaracion {
        marcado: Marcado::publico(),
        por: " ".into(),
    };
    assert!(Paquete::recorrer_declarado(&cuatro(), &anonima, |_| {}).is_err());
}
