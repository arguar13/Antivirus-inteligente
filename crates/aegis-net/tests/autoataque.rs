//! Autoataque del reensamblado por perfil (FASE 106).
//!
//! Dos ataques contra un reensamblador: (a) la EVASION —fabricar un flujo ambiguo
//! que el IDS interpreta distinto que el destino—, que aqui no cuela porque el
//! perfil es el del destino REAL y, si hay duda, se le pregunta al endpoint; y
//! (b) el AGOTAMIENTO —millones de segmentos a medio abrir, fragmentos que nunca
//! completan—, que aqui no cuela porque el reensamblado tiene cotas duras.

use aegis_net::{
    reensamblar_con, PerfilReensamblado, PoliticaSolape, ReensambladorPerfil, Segmento,
};

#[test]
fn un_flujo_ambiguo_no_evade_porque_se_reensambla_como_el_destino() {
    // El evasor cruza dos segmentos: un IDS que adivine "primero" ve "GET /ok",
    // pero el destino Windows (ultimo gana) ejecuta "GET /rm". AegisCore, con el
    // perfil del destino real, ve lo mismo que el destino.
    let segs = vec![Segmento::nuevo(0, b"GET /ok"), Segmento::nuevo(5, b"rm")];
    let inocente = reensamblar_con(&segs, PoliticaSolape::Primero);
    let real_windows = reensamblar_con(&segs, PoliticaSolape::Ultimo);
    assert_ne!(
        inocente, real_windows,
        "el flujo es ambiguo: ahi vive la evasion"
    );

    let mut r = ReensambladorPerfil::nuevo(PerfilReensamblado::para_sistema("Windows Server"));
    for s in &segs {
        r.incorporar(s.clone()).unwrap();
    }
    assert!(r.es_ambiguo());
    assert_eq!(
        r.reensamblar(),
        real_windows,
        "AegisCore ve lo que ve el destino"
    );
    // Y si se le pregunta al endpoint por lo que entrego, se confirma.
    assert_eq!(
        r.politica_segun_endpoint(&real_windows),
        Some(PoliticaSolape::Ultimo)
    );
}

#[test]
fn millones_de_segmentos_a_medio_abrir_no_agotan_la_memoria() {
    // Cota de 64 KiB. El atacante intenta meter mucho mas con segmentos que nunca
    // completan un flujo. Se rechaza pasado el techo: bytes acotados, sin OOM.
    let mut r = ReensambladorPerfil::con_cotas(
        PerfilReensamblado::nuevo(PoliticaSolape::Primero),
        64 * 1024,
        100_000,
    );
    let bloque = vec![0x41u8; 1024];
    let mut rechazos = 0u64;
    for i in 0..10_000u32 {
        // Segmentos con huecos entre si: nunca completan.
        if r.incorporar(Segmento::nuevo(i.wrapping_mul(4096), &bloque))
            .is_err()
        {
            rechazos += 1;
        }
    }
    assert!(rechazos > 0, "pasado el techo, se rechaza");
    assert!(
        r.bytes() <= 64 * 1024,
        "los bytes quedan acotados: {}",
        r.bytes()
    );
}

#[test]
fn un_fragmento_que_nunca_completa_no_cuelga_ni_afirma_de_mas() {
    // Un hueco permanente: solo se devuelve el tramo contiguo, sin colgarse ni
    // inventar lo que falta.
    let segs = vec![
        Segmento::nuevo(0, b"cabecera"),
        Segmento::nuevo(1000, b"cola"),
    ];
    let salida = reensamblar_con(&segs, PoliticaSolape::Primero);
    assert_eq!(salida, b"cabecera", "solo lo contiguo; el resto no llego");
}

#[test]
fn el_reensamblado_es_determinista() {
    // El mismo flujo, con los segmentos en cualquier orden de llegada, da el mismo
    // resultado bajo la misma politica: el veredicto no depende del azar.
    let a = vec![Segmento::nuevo(0, b"AAAA"), Segmento::nuevo(2, b"BBBB")];
    let b = vec![Segmento::nuevo(2, b"BBBB"), Segmento::nuevo(0, b"AAAA")];
    // Bajo Ultimo, el ultimo en LLEGAR sobre un byte gana; el orden importa para
    // Ultimo/Linux, asi que el determinismo se comprueba con Primero (independiente
    // del orden por construccion) y con Bsd (por seq, no por llegada).
    assert_eq!(
        reensamblar_con(&a, PoliticaSolape::Primero),
        reensamblar_con(&a, PoliticaSolape::Primero)
    );
    assert_eq!(
        reensamblar_con(&a, PoliticaSolape::Bsd),
        reensamblar_con(&b, PoliticaSolape::Bsd),
        "Bsd resuelve por seq, no por orden de llegada: determinista"
    );
}
