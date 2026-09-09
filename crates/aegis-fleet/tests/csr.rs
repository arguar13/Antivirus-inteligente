//! Pruebas del flujo CSR: la clave nunca sale del endpoint.

use aegis_fleet::pki::{ahora_unix, AutoridadCertificadora};
use aegis_fleet::x509::subject_cn;
use aegis_fleet::PeticionFirmaLocal;

#[test]
fn el_endpoint_genera_la_csr_y_la_ca_la_firma() {
    // Lado endpoint: clave + CSR, todo en memoria.
    let peticion = PeticionFirmaLocal::generar("agente-remoto-01").unwrap();
    assert_eq!(peticion.cn(), "agente-remoto-01");
    assert!(!peticion.csr_der.is_empty());

    // Lado CA: firma la CSR SIN ver la clave privada (solo recibe csr_der).
    let ca = AutoridadCertificadora::nueva("AegisFleet CA").unwrap();
    let (cert_der, no_antes, no_despues) = ca.firmar_csr(&peticion.csr_der, 300).unwrap();

    // El certificado firmado lleva el CN que pidio el endpoint.
    assert_eq!(
        subject_cn(cert_der.as_ref()).as_deref(),
        Some("agente-remoto-01")
    );

    // El endpoint ensambla su identidad con la clave que nunca envio.
    let id = peticion.ensamblar(cert_der, no_antes, no_despues);
    assert_eq!(id.cn, "agente-remoto-01");
    assert!(id.vigente(ahora_unix() + 5));
    assert_eq!(id.huella().len(), 32);
}

#[test]
fn la_ca_impone_la_validez_no_el_solicitante() {
    let peticion = PeticionFirmaLocal::generar("agente-x").unwrap();
    let ca = AutoridadCertificadora::nueva("CA").unwrap();
    let (_cert, no_antes, no_despues) = ca.firmar_csr(&peticion.csr_der, 120).unwrap();
    assert_eq!(
        no_despues - no_antes,
        120,
        "la validez es la que fija la CA"
    );
}

#[test]
fn una_csr_corrupta_no_entra_en_panico() {
    let ca = AutoridadCertificadora::nueva("CA").unwrap();
    assert!(ca.firmar_csr(&[], 300).is_err());
    assert!(ca.firmar_csr(&[0xff; 40], 300).is_err());
}
