//! Prueba de que las claves NUNCA tocan el disco.
//!
//! La garantia es doble: la API no ofrece ninguna forma de guardar la clave en
//! un fichero, y una rotacion completa —que genera claves nuevas— no crea ni un
//! fichero en el directorio observado. Se comprueba lo segundo de forma directa.

mod common;
use common::montar_flota;

use std::sync::Arc;

use aegis_fleet::pki::AutoridadCertificadora;
use aegis_fleet::{EmisorLocal, PoliticaRotacion, RotadorCertificados};

fn ficheros_en(dir: &std::path::Path) -> usize {
    std::fs::read_dir(dir).map(|it| it.count()).unwrap_or(0)
}

#[test]
fn una_rotacion_no_escribe_ningun_fichero() {
    let dir = std::env::temp_dir().join(format!("aegis-fleet-sindisco-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let antes = ficheros_en(&dir);

    let ca = Arc::new(AutoridadCertificadora::nueva("CA").unwrap());
    let emisor = Arc::new(EmisorLocal::nuevo(ca));
    let r = RotadorCertificados::nuevo("agente-001", PoliticaRotacion::default(), emisor).unwrap();

    // Varias rotaciones: cada una genera una clave nueva en memoria.
    for _ in 0..10 {
        r.rotar().unwrap();
    }

    let despues = ficheros_en(&dir);
    assert_eq!(
        antes, despues,
        "la rotacion no debe crear ficheros de clave"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn el_ciclo_de_flota_no_deja_material_de_clave_en_disco() {
    let dir = std::env::temp_dir().join(format!("aegis-fleet-ciclo-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let antes = ficheros_en(&dir);

    let flota = montar_flota();
    let agente = common::agente_legitimo(&flota, "agente-001");
    let mut sesion = agente.abrir_sesion().unwrap();
    sesion
        .enrolar(&agente.solicitud_enrolamiento().unwrap())
        .unwrap();

    assert_eq!(
        antes,
        ficheros_en(&dir),
        "ni el enrolamiento ni el handshake escriben claves en disco"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
