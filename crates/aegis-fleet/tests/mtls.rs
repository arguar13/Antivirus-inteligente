//! Pruebas de la autenticacion mutua: quien puede hablar con el plano de control.

mod common;
use common::{agente_impostor, agente_legitimo, montar_flota};

#[test]
fn un_agente_legitimo_se_enrola_y_autentica_al_servidor() {
    let flota = montar_flota();
    let agente = agente_legitimo(&flota, "agente-001");

    let mut sesion = agente.abrir_sesion().unwrap();
    let resp = sesion
        .enrolar(&agente.solicitud_enrolamiento().unwrap())
        .unwrap();
    assert!(
        resp.aceptado,
        "un agente con certificado de la flota se enrola"
    );
    assert_eq!(resp.id_flota, "fleet:agente-001");

    // El agente autentico al servidor por su certificado.
    assert_eq!(sesion.servidor_autenticado(), Some("control-plane"));
    // El plano registro al agente.
    assert_eq!(flota.plano.num_agentes(), 1);
}

#[test]
fn un_impostor_con_certificado_de_otra_ca_es_rechazado() {
    let flota = montar_flota();
    let impostor = agente_impostor(&flota, "agente-001");

    // El handshake mTLS falla: el servidor exige un certificado firmado por la
    // CA de la flota, y el del impostor es de otra CA. La llamada falla.
    let resultado = impostor
        .abrir_sesion()
        .and_then(|mut s| s.enrolar(&impostor.solicitud_enrolamiento().unwrap()));
    assert!(
        resultado.is_err(),
        "un certificado que no firma la CA de la flota no debe pasar del handshake"
    );
    // Y el impostor NO queda registrado.
    assert_eq!(flota.plano.num_agentes(), 0);
}

#[test]
fn un_agente_no_puede_suplantar_a_otro() {
    let flota = montar_flota();
    // Certificado legitimo para "agente-A", pero declara ser "agente-B".
    let agente = agente_legitimo(&flota, "agente-A");
    let mut sesion = agente.abrir_sesion().unwrap();

    let mut solicitud = agente.solicitud_enrolamiento().unwrap();
    solicitud.id_agente = "agente-B".into(); // miente sobre su identidad

    let resp = sesion.enrolar(&solicitud);
    // El plano compara el id declarado con el CN AUTENTICADO del certificado y
    // rechaza la suplantacion.
    assert!(
        resp.is_err(),
        "declarar un id distinto al del certificado debe rechazarse"
    );
}
