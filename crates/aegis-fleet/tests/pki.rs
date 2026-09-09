//! Pruebas de la CA y de las identidades.

use aegis_fleet::pki::{ahora_unix, AutoridadCertificadora};

#[test]
fn la_ca_emite_una_identidad_con_cn_y_validez() {
    let ca = AutoridadCertificadora::nueva("AegisFleet CA").unwrap();
    let ahora = ahora_unix();
    let id = ca.emitir("agente-001", 300).unwrap();
    assert_eq!(id.cn, "agente-001");
    assert!(id.vigente(ahora + 10), "recien emitido esta vigente");
    assert!(!id.vigente(ahora + 400), "tras la validez ya no");
    assert!(!id.huella().is_empty(), "la huella SHA-256 no es vacia");
    assert_eq!(id.huella().len(), 32, "SHA-256 son 32 bytes");
}

#[test]
fn dos_identidades_tienen_claves_y_huellas_distintas() {
    let ca = AutoridadCertificadora::nueva("AegisFleet CA").unwrap();
    let a = ca.emitir("agente-001", 300).unwrap();
    let b = ca.emitir("agente-001", 300).unwrap();
    // Mismo CN, pero cada emision genera clave y certificado nuevos.
    assert_ne!(a.huella(), b.huella(), "cada certificado es unico");
}

#[test]
fn la_ventana_de_caducidad_se_calcula_bien() {
    let ca = AutoridadCertificadora::nueva("AegisFleet CA").unwrap();
    let id = ca.emitir("agente-001", 300).unwrap();
    let base = id.no_antes_unix;
    assert_eq!(id.segundos_para_caducar(base), 300);
    assert_eq!(id.segundos_para_caducar(base + 100), 200);
    assert_eq!(id.segundos_para_caducar(base + 500), 0, "ya caducado -> 0");
}

#[test]
fn la_clave_privada_no_se_filtra_en_el_debug() {
    let ca = AutoridadCertificadora::nueva("AegisFleet CA").unwrap();
    let id = ca.emitir("agente-001", 300).unwrap();
    let repr = format!("{:?}", id.clave);
    assert!(repr.contains("en memoria"));
    // El Debug no puede llevar el material de clave en claro.
    assert!(!repr.contains("0x30"), "no se imprime el DER de la clave");
}
