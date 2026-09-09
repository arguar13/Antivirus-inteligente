#![allow(dead_code)]
//! Utilidades compartidas por las pruebas de red de flota.

use std::sync::Arc;

use aegis_fleet::pki::AutoridadCertificadora;
use aegis_fleet::{
    ClienteFlota, EmisorLocal, PlanoDeControl, PoliticaRotacion, RotadorCertificados,
    ServidorEnEjecucion, ServidorFlota,
};

/// Una flota montada sobre loopback: CA, servidor en ejecucion y su direccion.
pub struct Flota {
    pub ca: Arc<AutoridadCertificadora>,
    pub servidor: ServidorEnEjecucion,
    pub plano: Arc<PlanoDeControl>,
}

/// Monta una flota real escuchando en un puerto efimero.
pub fn montar_flota() -> Flota {
    let ca = Arc::new(AutoridadCertificadora::nueva("AegisFleet Test CA").unwrap());
    let id_servidor = ca.emitir("control-plane", 3600).unwrap();
    let plano = Arc::new(PlanoDeControl::nuevo());
    let servidor = ServidorFlota::nuevo(&id_servidor, &ca.cert_der(), plano.clone())
        .unwrap()
        .escuchar("127.0.0.1:0")
        .unwrap();
    Flota {
        ca,
        servidor,
        plano,
    }
}

/// Crea un agente legitimo, con identidad firmada por la CA de la flota.
pub fn agente_legitimo(flota: &Flota, cn: &str) -> ClienteFlota {
    let emisor = Arc::new(EmisorLocal::nuevo(flota.ca.clone()));
    let rotador =
        Arc::new(RotadorCertificados::nuevo(cn, PoliticaRotacion::default(), emisor).unwrap());
    ClienteFlota::nuevo(
        flota.servidor.direccion(),
        flota.ca.cert_der(),
        rotador,
        "host-de-prueba",
        "1.0.0",
    )
}

/// Crea un agente IMPOSTOR: confia en la CA de la flota (para aceptar al
/// servidor) pero se autentica con un certificado de OTRA CA.
pub fn agente_impostor(flota: &Flota, cn: &str) -> ClienteFlota {
    let ca_pirata = Arc::new(AutoridadCertificadora::nueva("CA Pirata").unwrap());
    let emisor = Arc::new(EmisorLocal::nuevo(ca_pirata));
    let rotador =
        Arc::new(RotadorCertificados::nuevo(cn, PoliticaRotacion::default(), emisor).unwrap());
    ClienteFlota::nuevo(
        flota.servidor.direccion(),
        flota.ca.cert_der(), // confia en la CA legitima como raiz del servidor
        rotador,
        "host-pirata",
        "6.6.6",
    )
}
