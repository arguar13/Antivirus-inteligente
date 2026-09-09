//! Prueba de extremo a extremo del servicio de flota sobre mTLS real.

mod common;
use common::{agente_legitimo, montar_flota};

use aegis_fleet::proto::{Latido, ReporteEvento};

#[test]
fn ciclo_completo_enrolar_latir_reportar() {
    let flota = montar_flota();
    let agente = agente_legitimo(&flota, "agente-001");
    let mut sesion = agente.abrir_sesion().unwrap();

    // Enrolar.
    let enrol = sesion
        .enrolar(&agente.solicitud_enrolamiento().unwrap())
        .unwrap();
    assert!(enrol.aceptado);

    // Publicar una politica nueva y comprobar que el ack del latido la anuncia.
    flota.plano.publicar_politica(7);
    let ack = sesion
        .latir(&Latido {
            id_agente: "agente-001".into(),
            momento_unix: 1_726_000_000,
            rss_kb: 22_000,
            amenazas_activas: 0,
            version_politica: 1,
        })
        .unwrap();
    assert!(ack.recibido);
    assert_eq!(ack.version_politica_disponible, 7);

    // Reportar un evento.
    let ack_ev = sesion
        .reportar_evento(&ReporteEvento {
            id_agente: "agente-001".into(),
            severidad: 3,
            categoria: "syscall-directa".into(),
            descripcion: "evasion detectada".into(),
            momento_unix: 1_726_000_100,
        })
        .unwrap();
    assert!(ack_ev.recibido);
    assert!(ack_ev.id_incidente.starts_with("INC-"));

    // El registro del plano refleja la actividad.
    let reg = flota.plano.registro("agente-001").unwrap();
    assert_eq!(reg.latidos, 1);
    assert_eq!(reg.eventos, 1);
    assert_eq!(reg.version, "1.0.0");
}

#[test]
fn varios_latidos_sobre_la_misma_sesion() {
    let flota = montar_flota();
    let agente = agente_legitimo(&flota, "agente-xyz");
    let mut sesion = agente.abrir_sesion().unwrap();
    sesion
        .enrolar(&agente.solicitud_enrolamiento().unwrap())
        .unwrap();

    for i in 0..5 {
        let ack = sesion
            .latir(&Latido {
                id_agente: "agente-xyz".into(),
                momento_unix: 1_726_000_000 + i,
                ..Default::default()
            })
            .unwrap();
        assert!(ack.recibido);
    }
    assert_eq!(flota.plano.registro("agente-xyz").unwrap().latidos, 5);
}

#[test]
fn el_certificado_rota_y_la_sesion_nueva_sigue_autenticando() {
    let flota = montar_flota();
    let agente = agente_legitimo(&flota, "agente-rot");

    // Primera sesion.
    let mut s1 = agente.abrir_sesion().unwrap();
    s1.enrolar(&agente.solicitud_enrolamiento().unwrap())
        .unwrap();
    let huella1 = agente.huella_actual().unwrap();
    drop(s1);

    // Fuerza una rotacion de la identidad del agente.
    // (la API publica de rotacion se ejercita en tests/rotacion; aqui se
    // comprueba que una identidad nueva sigue autenticando contra la MISMA CA).
    let agente2 = agente_legitimo(&flota, "agente-rot");
    let huella2 = agente2.huella_actual().unwrap();
    assert_ne!(huella1, huella2, "otra identidad, otra huella");

    let mut s2 = agente2.abrir_sesion().unwrap();
    let enrol = s2
        .enrolar(&agente2.solicitud_enrolamiento().unwrap())
        .unwrap();
    assert!(
        enrol.aceptado,
        "un certificado nuevo de la flota sigue valiendo"
    );
}
