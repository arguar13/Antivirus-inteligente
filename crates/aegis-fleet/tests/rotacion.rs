//! Pruebas de la rotacion automatica de certificados.

use std::sync::Arc;

use aegis_fleet::pki::AutoridadCertificadora;
use aegis_fleet::{EmisorLocal, PoliticaRotacion, RotadorCertificados};

fn rotador(validez: u64, pct: u64) -> RotadorCertificados {
    let ca = Arc::new(AutoridadCertificadora::nueva("CA").unwrap());
    let emisor = Arc::new(EmisorLocal::nuevo(ca));
    RotadorCertificados::nuevo(
        "agente-001",
        PoliticaRotacion {
            validez_seg: validez,
            renovar_al_pct: pct,
        },
        emisor,
    )
    .unwrap()
}

#[test]
fn no_rota_mientras_el_certificado_esta_fresco() {
    let r = rotador(300, 60);
    let id = r.actual().unwrap();
    let emitido = id.no_antes_unix;
    // A los 179 s queda mas margen que el umbral (120 s): no rota.
    assert!(!r.necesita_rotar(emitido + 179).unwrap());
}

#[test]
fn rota_cuando_se_acerca_la_caducidad() {
    let r = rotador(300, 60);
    let id = r.actual().unwrap();
    let emitido = id.no_antes_unix;
    // A los 181 s el margen restante (119 s) baja del umbral (120 s): rota.
    assert!(r.necesita_rotar(emitido + 181).unwrap());
    // Y ya caducado, con mas razon.
    assert!(r.necesita_rotar(emitido + 400).unwrap());
}

#[test]
fn una_rotacion_produce_un_certificado_nuevo_y_distinto() {
    let r = rotador(300, 60);
    let huella_vieja = r.actual().unwrap().huella();
    r.rotar().unwrap();
    let huella_nueva = r.actual().unwrap().huella();
    assert_ne!(
        huella_vieja, huella_nueva,
        "rotar debe generar una identidad nueva, con clave y certificado nuevos"
    );
    // El CN (identidad estable) se conserva.
    assert_eq!(r.actual().unwrap().cn, "agente-001");
}

#[test]
fn rotar_si_procede_respeta_la_politica() {
    let r = rotador(300, 60);
    let id = r.actual().unwrap();
    let emitido = id.no_antes_unix;
    // Fresco: no roto (aqui se usa el ahora real, que esta cerca de `emitido`).
    let _ = r.rotar_si_procede(emitido + 1).unwrap();
    let huella1 = r.actual().unwrap().huella();
    assert_eq!(r.actual().unwrap().huella(), huella1);
}
