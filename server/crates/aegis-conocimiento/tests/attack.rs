//! El grafo con conocimiento REAL: MITRE ATT&CK Enterprise, ICS y Mobile en
//! STIX 2.1 (unos 31 000 objetos, 24 800 relaciones), descargados por
//! `tools/verificar-conocimiento.sh` en `/opt/aegis-comparativa/attack`. Sin
//! ellos, las pruebas se OMITEN y lo dicen.

mod comun;

use std::collections::BTreeMap;

use aegis_conocimiento::catalogo::Admision;
use aegis_conocimiento::grafo::Grafo;
use aegis_conocimiento::inferencia::proponer;
use aegis_conocimiento::intercambio;
use aegis_conocimiento::observado::{Avistamiento, Observable};
use aegis_share::difusion::{Canal, Destino, Difusor};
use aegis_share::marcado::{Marcado, Tlp};
use aegis_share::procedencia::Fiabilidad;
use aegis_share::stix::{Declaracion, Paquete};
use aegis_share::taxii::{Cliente, Coleccion, Servidor};
use comun::*;
use serde_json::Value;

const DIR: &str = "/opt/aegis-comparativa/attack";
const COLECCIONES: [&str; 3] = ["enterprise-attack", "ics-attack", "mobile-attack"];

fn leer(c: &str) -> Option<String> {
    let r = std::fs::read_to_string(format!("{DIR}/{c}.json")).ok();
    if r.is_none() {
        eprintln!("OMITIDA: no esta {DIR}/{c}.json");
    }
    r
}

/// ATT&CK es publico por su licencia, pero no lo dice en TLP: sin declaracion,
/// la regla de lo desconocido lo deja en RED. La declaracion tiene autor.
fn declaracion() -> Declaracion {
    Declaracion {
        marcado: Marcado::publico(),
        por: "operador de la prueba: ATT&CK se publica bajo licencia abierta de MITRE".into(),
    }
}

fn attack() -> Option<(Grafo, BTreeMap<String, Value>)> {
    let mut g = Grafo::nuevo();
    let mut originales = BTreeMap::new();
    for c in COLECCIONES {
        let texto = leer(c)?;
        let doc: Value = serde_json::from_str(&texto).unwrap();
        for o in doc["objects"].as_array().unwrap() {
            originales.insert(o["id"].as_str().unwrap().to_string(), o.clone());
        }
        let r = intercambio::importar_declarado(
            &mut g,
            &texto,
            &aporte(&format!("mitre-{c}"), Fiabilidad::Acordada, 90),
            &declaracion(),
        )
        .unwrap_or_else(|e| panic!("{c}: {}", e.texto()));
        println!(
            "{c}: {} nuevos, {} anotados (compartidos con otra coleccion)",
            r.nuevos, r.anotados
        );
    }
    Some((g, originales))
}

#[test]
fn attack_entero_entra_y_sale_por_el_juez_sin_perder_nada() {
    let Some((g, originales)) = attack() else {
        return;
    };
    assert_eq!(g.cuantos(), originales.len());

    let mut d = Difusor::nuevo();
    d.declarar(Destino {
        nombre: "comunidad".into(),
        canal: Canal::Exportacion,
        tope_tlp: Tlp::Clear,
        es_propia_organizacion: false,
    });
    let s = intercambio::exportar(
        &g,
        &d,
        "comunidad",
        "bundle--00000000-0000-4000-8000-00000000a77c",
    )
    .unwrap();
    println!("{}", s.reparto.resumen("comunidad"));
    // Lo revocado por MITRE no se reemite: el juez lo retiene, y se dice.
    let revocados = originales
        .values()
        .filter(|o| o["revoked"] == Value::Bool(true))
        .count();
    assert_eq!(
        s.reparto.retenidos.len(),
        revocados,
        "{:?}",
        s.reparto.por_motivo()
    );

    // Lo que sale, releido: identico objeto a objeto.
    let mut vueltos = 0;
    Paquete::recorrer(&s.documento, |o| {
        vueltos += 1;
        assert_eq!(
            originales.get(&o.id),
            Some(&Value::Object(o.crudo.clone())),
            "{}",
            o.id
        );
    })
    .unwrap();
    assert_eq!(vueltos, originales.len() - revocados);

    // La cobertura: todo tipo de relacion de ATT&CK entra, dentro del canon o
    // fuera, y ninguna se descarta.
    let mut por_admision: BTreeMap<&str, usize> = BTreeMap::new();
    for a in g.aristas().filter(|a| !a.embebida) {
        *por_admision.entry(a.admision.nombre()).or_insert(0) += 1;
    }
    println!("relaciones de ATT&CK por admision: {por_admision:?}");
    let sro = originales
        .values()
        .filter(|o| o["type"] == "relationship")
        .count();
    assert_eq!(por_admision.values().sum::<usize>(), sro);
    assert!(
        por_admision
            .get(Admision::Personalizada.nombre())
            .copied()
            .unwrap_or(0)
            > 0
    );
}

#[test]
fn ver_cobalt_strike_reparte_la_atribucion_entre_todos_los_que_lo_usan() {
    let Some((mut g, _)) = attack() else { return };
    let cobalt = g
        .objetos()
        .find(|o| o.texto("name") == Some("Cobalt Strike") && !o.revocado)
        .map(|o| o.id.clone())
        .expect("ATT&CK tiene Cobalt Strike");
    // Un canal de la comunidad aporta un indicador de un beacon, que indica
    // Cobalt Strike; este despliegue lo ve en una maquina.
    let hash = sha("beacon-x64");
    importar(
        &mut g,
        "comunidad",
        Fiabilidad::Comunidad,
        70,
        vec![
            indicador_sha(1, &hash),
            relacion(2, &id("indicator", 1), "indicates", &cobalt),
        ],
    );
    g.observar(Avistamiento {
        observable: Observable::sha256(&hash).unwrap(),
        maquina: maquina(1),
        cuando_ns: AHORA,
    });
    let hs = proponer(&g, AHORA);
    let usuarios = g.entrantes(&cobalt).filter(|a| a.tipo == "uses").count();
    println!(
        "Cobalt Strike visto: {} hipotesis (lo usan {usuarios} en ATT&CK); la mejor: {}/100",
        hs.len(),
        hs.first().map_or(0, |h| h.confianza())
    );
    println!(
        "{}",
        hs[0]
            .explicacion()
            .lines()
            .take(6)
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(hs.len() > 20, "{}", hs.len());
    // Con decenas de alternativas, ninguna atribucion pasa de unas pocas
    // centesimas: ver Cobalt Strike no dice quien es.
    assert!(
        hs.iter().all(|h| h.confianza() <= 5),
        "{:?}",
        hs.iter().map(|h| h.confianza()).max()
    );
    assert!(hs.iter().all(|h| !h.alternativas().is_empty()));
}

#[test]
fn taxii_entra_por_la_misma_puerta() {
    let Some((g, _)) = attack() else { return };
    // Un servidor TAXII de la comunidad sirve un subconjunto de ATT&CK.
    let mut d = Difusor::nuevo();
    d.declarar(Destino {
        nombre: "lectores".into(),
        canal: Canal::Taxii,
        tope_tlp: Tlp::Green,
        es_propia_organizacion: false,
    });
    let mut s = Servidor::nuevo(d);
    s.declarar(Coleccion {
        id: "attack".into(),
        titulo: "ATT&CK".into(),
        descripcion: String::new(),
        lectura: true,
        escritura: true,
        destino: "lectores".into(),
    })
    .unwrap();
    let muestra: Vec<_> = g
        .objetos()
        .filter(|o| !o.revocado)
        .take(2500)
        .cloned()
        .collect();
    s.anadir("attack", muestra, AHORA).unwrap();

    let mut destino = Grafo::nuevo();
    let r = intercambio::sondear(
        &mut destino,
        &mut Cliente::nuevo(),
        &s,
        "attack",
        &aporte("taxii-comunidad", Fiabilidad::Comunidad, 60),
    )
    .unwrap();
    println!(
        "TAXII: {} objetos en {} paginas de hasta 1000",
        r.total(),
        r.total().div_ceil(1000)
    );
    assert_eq!(r.nuevos, 2500);
    assert_eq!(destino.cuantos(), 2500);
}
