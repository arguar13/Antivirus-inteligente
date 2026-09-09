//! Pruebas del extractor de CN sobre certificados reales de rcgen.

use aegis_fleet::pki::AutoridadCertificadora;
use aegis_fleet::x509::subject_cn;

#[test]
fn extrae_el_cn_de_un_certificado_de_agente() {
    let ca = AutoridadCertificadora::nueva("AegisFleet Root").unwrap();
    let id = ca.emitir("agente-berlin-42", 300).unwrap();
    let cn = subject_cn(id.cert_der.as_ref()).expect("debe haber CN");
    assert_eq!(cn, "agente-berlin-42");
}

#[test]
fn el_cn_del_subject_no_se_confunde_con_el_del_issuer() {
    // El issuer (CA) tiene un CN distinto; el extractor debe devolver el del
    // SUBJECT, no el del issuer.
    let ca = AutoridadCertificadora::nueva("Autoridad Raiz Distinta").unwrap();
    let id = ca.emitir("hoja-xyz", 300).unwrap();
    assert_eq!(
        subject_cn(id.cert_der.as_ref()).as_deref(),
        Some("hoja-xyz")
    );
}

#[test]
fn cn_de_varios_agentes() {
    let ca = AutoridadCertificadora::nueva("CA").unwrap();
    for cn in ["a", "agente-con-guiones-001", "HOST01"] {
        let id = ca.emitir(cn, 300).unwrap();
        assert_eq!(subject_cn(id.cert_der.as_ref()).as_deref(), Some(cn));
    }
}

#[test]
fn datos_no_der_no_entran_en_panico() {
    assert_eq!(subject_cn(&[]), None);
    assert_eq!(subject_cn(&[0x30, 0x00]), None);
    assert_eq!(subject_cn(&[0xff; 50]), None);
}
