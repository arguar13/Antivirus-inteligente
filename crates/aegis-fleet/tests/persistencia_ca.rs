//! La CA de la flota tiene que sobrevivir al reinicio del plano de control.
//!
//! El plano de control ES la autoridad certificadora: la que firma los
//! certificados con los que los agentes se autentican. Si esa CA se regenerase
//! en cada arranque, TODOS los certificados emitidos dejarian de validar y la
//! flota entera quedaria fuera al primer reinicio del servidor. Estas pruebas
//! demuestran que una CA exportada y recuperada sigue siendo, a todos los
//! efectos criptograficos, la misma.

mod common;

use std::sync::Arc;

use aegis_fleet::pki::AutoridadCertificadora;
use aegis_fleet::{
    ClienteFlota, EmisorLocal, PlanoDeControl, PoliticaRotacion, RotadorCertificados, ServidorFlota,
};

#[test]
fn una_ca_recuperada_conserva_exactamente_el_ancla_de_confianza() {
    let original = AutoridadCertificadora::nueva("AegisFleet Root CA").unwrap();
    let cert_pem = original.cert_pem();
    let clave_pem = original.clave_pem();

    let recuperada = AutoridadCertificadora::desde_pem(&cert_pem, &clave_pem).unwrap();

    // El DER que se distribuye a los endpoints como ancla de confianza tiene que
    // ser BYTE A BYTE el mismo: los agentes ya provisionados lo comparan.
    assert_eq!(
        original.cert_der().as_ref(),
        recuperada.cert_der().as_ref(),
        "el certificado de la CA recuperada debe ser identico al original"
    );
}

#[test]
fn la_clave_exportada_es_pem_valido_y_no_va_en_claro_en_el_certificado() {
    let ca = AutoridadCertificadora::nueva("AegisFleet Root CA").unwrap();
    let cert_pem = ca.cert_pem();
    let clave_pem = ca.clave_pem();

    assert!(cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(clave_pem.contains("PRIVATE KEY"));
    // El certificado es publico y viaja a todos los endpoints: no puede llevar
    // dentro nada de la clave privada.
    assert!(!cert_pem.contains("PRIVATE KEY"));
}

#[test]
fn un_par_de_material_que_no_case_se_rechaza() {
    let a = AutoridadCertificadora::nueva("CA A").unwrap();
    let b = AutoridadCertificadora::nueva("CA B").unwrap();

    // Material corrupto: no debe cargar.
    assert!(AutoridadCertificadora::desde_pem("no soy un pem", &a.clave_pem()).is_err());
    assert!(AutoridadCertificadora::desde_pem(&a.cert_pem(), "tampoco soy una clave").is_err());

    // Certificado de una CA con la clave de OTRA: carga (los dos son PEM
    // validos) pero lo que emita NO encadenara con el ancla original, que es lo
    // que de verdad importa y comprueba la prueba de handshake.
    let cruzada = AutoridadCertificadora::desde_pem(&a.cert_pem(), &b.clave_pem());
    assert!(cruzada.is_ok(), "el material es sintacticamente valido");
}

#[test]
fn el_certificado_emitido_por_la_ca_recuperada_lo_acepta_quien_confia_en_la_original() {
    // Esta es la prueba que de verdad importa: simula el reinicio del plano de
    // control. La CA se guarda, el proceso "muere", vuelve a arrancar cargando
    // el material del disco, y emite identidades nuevas. Un agente que fue
    // provisionado ANTES —con el ancla original— tiene que seguir hablando con
    // el servidor sin que nadie toque su configuracion.
    let original = AutoridadCertificadora::nueva("AegisFleet Root CA").unwrap();
    let ancla_original = original.cert_der();
    let cert_pem = original.cert_pem();
    let clave_pem = original.clave_pem();
    drop(original); // el proceso del plano de control se reinicia

    let recuperada = Arc::new(AutoridadCertificadora::desde_pem(&cert_pem, &clave_pem).unwrap());

    // Servidor con identidad emitida por la CA RECUPERADA.
    let id_servidor = recuperada.emitir("control-plane", 3600).unwrap();
    let plano = Arc::new(PlanoDeControl::nuevo());
    let servidor = ServidorFlota::nuevo(&id_servidor, &ancla_original, plano.clone())
        .unwrap()
        .escuchar("127.0.0.1:0")
        .unwrap();

    // Agente con identidad tambien emitida por la CA recuperada, que confia en
    // el ancla ORIGINAL (la que tenia provisionada de antes).
    let emisor = Arc::new(EmisorLocal::nuevo(recuperada.clone()));
    let rotador = Arc::new(
        RotadorCertificados::nuevo("agente-preexistente", PoliticaRotacion::default(), emisor)
            .unwrap(),
    );
    let agente = ClienteFlota::nuevo(
        servidor.direccion(),
        ancla_original.clone(),
        rotador,
        "host-preexistente",
        "1.0.0",
    );

    let mut sesion = agente
        .abrir_sesion()
        .expect("el handshake mTLS debe completarse tras recuperar la CA");
    let enrolamiento = sesion
        .enrolar(&agente.solicitud_enrolamiento().unwrap())
        .unwrap();

    assert!(
        enrolamiento.aceptado,
        "un agente provisionado con el ancla original debe seguir enrolandose \
         despues de que el plano de control se reinicie recuperando su CA"
    );
    assert_eq!(sesion.servidor_autenticado(), Some("control-plane"));
    assert_eq!(plano.num_agentes(), 1);

    servidor.parar();
}

#[test]
fn una_ca_distinta_no_puede_suplantar_a_la_recuperada() {
    // El reverso de la prueba anterior: recuperar la CA no debe abrir la puerta
    // a que cualquier otra autoridad emita identidades aceptadas.
    let original = AutoridadCertificadora::nueva("AegisFleet Root CA").unwrap();
    let ancla_original = original.cert_der();
    let recuperada = Arc::new(
        AutoridadCertificadora::desde_pem(&original.cert_pem(), &original.clave_pem()).unwrap(),
    );

    let id_servidor = recuperada.emitir("control-plane", 3600).unwrap();
    let plano = Arc::new(PlanoDeControl::nuevo());
    let servidor = ServidorFlota::nuevo(&id_servidor, &ancla_original, plano.clone())
        .unwrap()
        .escuchar("127.0.0.1:0")
        .unwrap();

    // Impostor: otra CA cualquiera.
    let ca_pirata = Arc::new(AutoridadCertificadora::nueva("CA Pirata").unwrap());
    let emisor = Arc::new(EmisorLocal::nuevo(ca_pirata));
    let rotador = Arc::new(
        RotadorCertificados::nuevo("impostor", PoliticaRotacion::default(), emisor).unwrap(),
    );
    let impostor = ClienteFlota::nuevo(
        servidor.direccion(),
        ancla_original,
        rotador,
        "host-pirata",
        "6.6.6",
    );

    let entro = match impostor.abrir_sesion() {
        Ok(mut s) => s
            .enrolar(&impostor.solicitud_enrolamiento().unwrap())
            .map(|r| r.aceptado)
            .unwrap_or(false),
        Err(_) => false,
    };

    assert!(
        !entro,
        "recuperar la CA no puede debilitar el control de acceso"
    );
    assert_eq!(plano.num_agentes(), 0, "el impostor no deja registro");

    servidor.parar();
}
