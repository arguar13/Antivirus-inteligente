//! AUTOATAQUE: el conocimiento como via de envenenamiento.
//!
//! El ataque: un canal abierto de inteligencia inyecta una relacion FALSA
//! —«la operacion Nacion-X usa el malware QakBot»— sobre conocimiento legitimo
//! que otras fuentes si sostienen. El objetivo del atacante es que, cuando este
//! despliegue vea QakBot, la atribucion apunte a quien el quiere: un incidente
//! atribuido a un estado provoca decisiones que un incidente de cibercrimen no.
//!
//! Lo que se comprueba:
//!
//! 1. LA PROCEDENCIA LA AISLA: la hipotesis falsa sale, pero dice que cae si se
//!    revoca solo ese canal; la legitima no depende de el. Y la confianza de
//!    las dos se reparte: ninguna se afirma.
//! 2. LA REVOCACION LA REVIERTE: revocar el canal retira el actor inventado y
//!    la relacion falsa, la hipotesis falsa CAE al rebatirla contra el grafo de
//!    ahora, y deja de proponerse.
//! 3. SIN TIRAR LO QUE SOSTENIAN LOS DEMAS: el malware, el indicador, el actor
//!    real y su relacion siguen en pie —el canal envenenado TAMBIEN los habia
//!    repetido, y solo pierden su aporte—, lo observado sigue, y la hipotesis
//!    legitima gana la confianza que le quitaba la falsa.

mod comun;

use aegis_conocimiento::grafo::Grafo;
use aegis_conocimiento::inferencia::{proponer, Rebatida};
use aegis_conocimiento::observado::{Avistamiento, Observable};
use aegis_share::procedencia::Fiabilidad;
use comun::*;

#[test]
fn autoataque_una_relacion_falsa_se_aisla_y_se_revierte_sin_tirar_lo_demas() {
    let mut g = Grafo::nuevo();
    let hash = sha("qakbot-loader");
    let qakbot = id("malware", 1);
    let indicador = id("indicator", 2);
    let fin7 = id("intrusion-set", 3);
    let nacion = id("intrusion-set", 66);

    // Conocimiento legitimo, de dos canales independientes.
    for (fuente, fiabilidad, conf) in [
        ("isac-banca", Fiabilidad::Acordada, 85),
        ("vendor-b", Fiabilidad::Comunidad, 70),
    ] {
        importar(
            &mut g,
            fuente,
            fiabilidad,
            conf,
            vec![
                sdo("malware", 1, "QakBot"),
                indicador_sha(2, &hash),
                relacion(10, &indicador, "indicates", &qakbot),
                sdo("intrusion-set", 3, "FIN7"),
                relacion(11, &fin7, "uses", &qakbot),
            ],
        );
    }
    // El canal envenenado repite lo legitimo (para parecer fiable) e inyecta
    // un actor y una relacion falsos.
    importar(
        &mut g,
        "feed-abierto-x",
        Fiabilidad::Abierta,
        90,
        vec![
            sdo("malware", 1, "QakBot"),
            indicador_sha(2, &hash),
            relacion(10, &indicador, "indicates", &qakbot),
            sdo("intrusion-set", 66, "Operacion Nacion-X"),
            relacion(99, &nacion, "uses", &qakbot),
        ],
    );
    // Este despliegue ve el hash en tres maquinas.
    for m in 1..=3 {
        g.observar(Avistamiento {
            observable: Observable::sha256(&hash).unwrap(),
            maquina: maquina(m),
            cuando_ns: AHORA,
        });
    }

    // 1. La procedencia la aisla.
    let hs = proponer(&g, AHORA);
    let falsa = hs
        .iter()
        .find(|h| h.actor() == nacion)
        .expect("la falsa sale");
    let legitima = hs
        .iter()
        .find(|h| h.actor() == fin7)
        .expect("la legitima sale");
    println!("{}\n\n{}", falsa.explicacion(), legitima.explicacion());
    assert!(
        falsa.depende_de().contains("feed-abierto-x"),
        "{:?}",
        falsa.depende_de()
    );
    assert!(
        !legitima.depende_de().contains("feed-abierto-x"),
        "{:?}",
        legitima.depende_de()
    );
    assert_eq!(falsa.alternativas(), std::slice::from_ref(&fin7));
    assert_eq!(legitima.alternativas(), std::slice::from_ref(&nacion));
    assert!(
        falsa.confianza() <= 50 && legitima.confianza() <= 50,
        "ninguna se afirma con una alternativa viva"
    );
    // La cifra de riesgo de la base: lo que depende en exclusiva de ese canal.
    let dependencia = g.procedencia().dependencia_unica(AHORA);
    assert_eq!(
        dependencia.get("feed-abierto-x"),
        Some(&2),
        "{dependencia:?}"
    );

    // 2. La revocacion la revierte.
    let antes_legitima = legitima.confianza();
    let falsa = falsa.clone();
    let r = g.revocar_fuente("feed-abierto-x", AHORA);
    println!("revocado feed-abierto-x: {r:?}");
    let mut retirados = r.objetos.clone();
    retirados.sort();
    assert_eq!(retirados, [nacion.clone(), id("relationship", 99)]);
    assert!(matches!(falsa.rebatir(&g, AHORA), Rebatida::Cae { .. }));
    let hs = proponer(&g, AHORA);
    assert!(
        hs.iter().all(|h| h.actor() != nacion),
        "la falsa ya no se propone"
    );

    // 3. Sin tirar lo que sostenian los demas.
    for sigue in [
        &qakbot,
        &indicador,
        &fin7,
        &id("relationship", 10),
        &id("relationship", 11),
    ] {
        assert!(g.objeto(sigue).is_some(), "{sigue} tenia que seguir");
    }
    assert_eq!(
        g.vistos(&Observable::sha256(&hash).unwrap().local()).len(),
        3
    );
    let legitima = hs
        .iter()
        .find(|h| h.actor() == fin7)
        .expect("la legitima sigue");
    assert!(legitima.alternativas().is_empty());
    assert!(
        legitima.confianza() > antes_legitima,
        "sin la alternativa falsa, la legitima gana confianza: {} -> {}",
        antes_legitima,
        legitima.confianza()
    );
    // Lo que el canal repetia sigue sostenido por los otros dos, con una
    // fuente menos.
    let ficha = g.procedencia().ficha(&qakbot).unwrap();
    assert_eq!(ficha.fuentes_independientes(AHORA), 2);
}
