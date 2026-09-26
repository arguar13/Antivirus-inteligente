//! Una hipotesis de atribucion sale con su cadena completa, acotada, se puede
//! rebatir, y solo sale del sistema si una persona la confirma. Y «que se de
//! este actor» y «que he visto yo de este actor» son el mismo recorrido.

mod comun;

use aegis_conocimiento::grafo::Grafo;
use aegis_conocimiento::inferencia::{
    proponer, Apoyo, NoConfirmada, Rebatida, MAX_SALTOS_ATRIBUCION,
};
use aegis_conocimiento::observado::{Avistamiento, Observable};
use aegis_share::procedencia::Fiabilidad;
use comun::*;

/// Un escenario: una campana atribuida a un conjunto de intrusion atribuido a
/// un actor atribuido a otro (cadena de tres atribuciones), que usa un
/// malware con un indicador cuyo hash se ha visto aqui.
fn escenario() -> (Grafo, String) {
    let mut g = Grafo::nuevo();
    let hash = sha("emotet-epoch5");
    let malware = id("malware", 1);
    let campana = id("campaign", 2);
    let conjunto = id("intrusion-set", 3);
    let actor = id("threat-actor", 4);
    let patrocinador = id("threat-actor", 5);
    let indicador = id("indicator", 6);
    importar(
        &mut g,
        "isac-banca",
        Fiabilidad::Acordada,
        80,
        vec![
            sdo("malware", 1, "Emotet"),
            sdo("campaign", 2, "Epoch 5"),
            sdo("intrusion-set", 3, "TA542"),
            sdo("threat-actor", 4, "Mummy Spider"),
            sdo("threat-actor", 5, "Patrocinador hipotetico"),
            indicador_sha(6, &hash),
            relacion(10, &indicador, "indicates", &malware),
            relacion(11, &campana, "uses", &malware),
            relacion(12, &campana, "attributed-to", &conjunto),
            relacion(13, &conjunto, "attributed-to", &actor),
            relacion(14, &actor, "attributed-to", &patrocinador),
        ],
    );
    g.observar(Avistamiento {
        observable: Observable::sha256(&hash).unwrap(),
        maquina: maquina(7),
        cuando_ns: AHORA,
    });
    (g, hash)
}

#[test]
fn la_hipotesis_sale_con_su_cadena_completa_y_acotada() {
    let (g, _) = escenario();
    let hs = proponer(&g, AHORA);
    let actores: Vec<&str> = hs.iter().map(|h| h.actor()).collect();
    // La campana, y DOS atribuciones mas: el patrocinador (tercera) no se
    // alcanza.
    assert_eq!(MAX_SALTOS_ATRIBUCION, 2);
    assert!(actores.contains(&id("campaign", 2).as_str()));
    assert!(actores.contains(&id("intrusion-set", 3).as_str()));
    assert!(actores.contains(&id("threat-actor", 4).as_str()));
    assert!(
        !actores.contains(&id("threat-actor", 5).as_str()),
        "la inferencia esta acotada: {actores:?}"
    );

    let h = hs
        .iter()
        .find(|h| h.actor() == id("threat-actor", 4))
        .unwrap();
    println!("{}", h.explicacion());
    // observado -> indicador declara -> indica malware -> campana usa ->
    // atribuida a conjunto -> atribuido a actor.
    assert_eq!(h.cadena().len(), 6, "{:#?}", h.cadena());
    assert!(matches!(h.cadena()[0].apoyo, Apoyo::Observacion { .. }));
    assert!(matches!(h.cadena()[1].apoyo, Apoyo::Objeto(_)));
    assert!(h.cadena()[2..]
        .iter()
        .all(|e| matches!(e.apoyo, Apoyo::Arista(_))));
    assert!(h.cadena().iter().all(|e| !e.fuentes.is_empty()));
    // Cada atribucion encadenada rebaja: el actor queda por debajo de la
    // campana.
    let c = hs.iter().find(|h| h.actor() == id("campaign", 2)).unwrap();
    assert!(
        h.confianza() < c.confianza(),
        "{} < {}",
        h.confianza(),
        c.confianza()
    );
    assert!(h
        .explicacion()
        .starts_with("HIPOTESIS (propuesta, no afirmada)"));
}

#[test]
fn se_puede_rebatir_contra_el_grafo_de_ahora() {
    let (mut g, _) = escenario();
    let h = proponer(&g, AHORA)
        .into_iter()
        .find(|h| h.actor() == id("threat-actor", 4))
        .unwrap();
    assert!(matches!(h.rebatir(&g, AHORA), Rebatida::Sostenida { .. }));
    // La atribucion conjunto -> actor la retira su autor con una version
    // revocada del objeto: el eslabon cae, y la hipotesis con el.
    let mut revocada = relacion(
        13,
        &id("intrusion-set", 3),
        "attributed-to",
        &id("threat-actor", 4),
    );
    revocada["modified"] = serde_json::json!("2026-09-20T00:00:00Z");
    revocada["revoked"] = serde_json::json!(true);
    importar(
        &mut g,
        "isac-banca",
        Fiabilidad::Acordada,
        80,
        vec![revocada],
    );
    let Rebatida::Cae { eslabon, motivo } = h.rebatir(&g, AHORA) else {
        panic!("tenia que caer");
    };
    println!("cae en el eslabon {eslabon}: {motivo}");
    assert_eq!(eslabon, 5);
    assert!(proponer(&g, AHORA)
        .iter()
        .all(|x| x.actor() != id("threat-actor", 4)));
}

#[test]
fn solo_sale_confirmada_por_una_persona_y_como_avistamiento() {
    let (g, _) = escenario();
    let h = proponer(&g, AHORA).into_iter().next().unwrap();
    assert_eq!(
        h.clone().confirmar("  ", &id("identity", 9), AHORA),
        Err(NoConfirmada::SinAutor)
    );
    let o = h.confirmar("ana.lopez", &id("identity", 9), AHORA).unwrap();
    assert_eq!(o.tipo.nombre(), "sighting");
    assert_eq!(o.texto("x_aegis_confirmado_por"), Some("ana.lopez"));
    assert!(o.texto("description").unwrap().contains("HIPOTESIS"));
    assert!(o.referencias.contains(&id("identity", 9)));
}

#[test]
fn lo_que_se_y_lo_que_he_visto_son_el_mismo_recorrido() {
    let (g, hash) = escenario();
    let v = g.alrededor(&id("campaign", 2), 2);
    // Lo que se: el malware, el indicador, el conjunto de intrusion…
    for n in [id("malware", 1), id("indicator", 6), id("intrusion-set", 3)] {
        assert!(v.nodos.contains(&n), "{n}");
    }
    // …y lo que he visto, en la MISMA vista: el hash, por el indicador.
    let local = Observable::sha256(&hash).unwrap().local();
    assert_eq!(
        v.observado
            .get(&id("indicator", 6))
            .map(|s| s.contains(&local)),
        Some(true)
    );
    assert_eq!(v.locales().len(), 1);
    // La autoria no se sigue: no convierte el vecindario en la base entera.
    assert!(!v.aristas.iter().any(|a| a.contains("#created_by_ref#")));
}
