//! El plano de control solo habla con endpoints de la flota, para la
//! simulacion de Red Team.
//!
//! Levanta un plano de control real con mTLS y lanza dos agentes contra el: uno
//! LEGITIMO (certificado firmado por la CA de la flota) y uno IMPOSTOR
//! (certificado de otra CA, como el que fabricaria un atacante que alcanza el
//! puerto). El legitimo se enrola; el impostor no pasa del handshake. Todo real:
//! CA, certificados, handshake mTLS mutuo.
//!
//! Sale 0 si el impostor es rechazado Y el legitimo se enrola.

use std::sync::Arc;

use aegis_fleet::pki::AutoridadCertificadora;
use aegis_fleet::{
    ClienteFlota, EmisorLocal, PlanoDeControl, PoliticaRotacion, RotadorCertificados, ServidorFlota,
};

fn agente(
    dir: std::net::SocketAddr,
    ca_confianza: &AutoridadCertificadora,
    ca_identidad: Arc<AutoridadCertificadora>,
    cn: &str,
) -> aegis_fleet::Resultado<ClienteFlota> {
    let emisor = Arc::new(EmisorLocal::nuevo(ca_identidad));
    let rotador = Arc::new(RotadorCertificados::nuevo(
        cn,
        PoliticaRotacion::default(),
        emisor,
    )?);
    Ok(ClienteFlota::nuevo(
        dir,
        ca_confianza.cert_der(),
        rotador,
        "host",
        "1.0.0",
    ))
}

fn main() -> std::process::ExitCode {
    match ejecutar() {
        Ok(true) => {
            println!(
                "DEFENDIDO: el plano de control enrolo al agente legitimo y rechazo al impostor"
            );
            std::process::ExitCode::SUCCESS
        }
        Ok(false) => {
            eprintln!("BRECHA: el control de acceso de la flota no se comporto como debe");
            std::process::ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("BRECHA: fallo inesperado: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn ejecutar() -> aegis_fleet::Resultado<bool> {
    let ca = Arc::new(AutoridadCertificadora::nueva("AegisFleet Root CA")?);
    let id_srv = ca.emitir("control-plane", 3600)?;
    let plano = Arc::new(PlanoDeControl::nuevo());
    let servidor =
        ServidorFlota::nuevo(&id_srv, &ca.cert_der(), plano.clone())?.escuchar("127.0.0.1:0")?;
    let dir = servidor.direccion();

    // Agente legitimo: certificado de la CA de la flota.
    let legitimo = agente(dir, &ca, ca.clone(), "agente-legitimo")?;
    let mut s = legitimo.abrir_sesion()?;
    let enrol = s.enrolar(&legitimo.solicitud_enrolamiento()?)?;
    let legitimo_ok = enrol.aceptado;
    println!(
        "agente legitimo: enrolado={} (servidor autenticado como {:?})",
        legitimo_ok,
        s.servidor_autenticado()
    );
    drop(s);

    // Agente impostor: certificado de OTRA CA.
    let ca_pirata = Arc::new(AutoridadCertificadora::nueva("CA Pirata")?);
    let impostor = agente(dir, &ca, ca_pirata, "agente-legitimo")?;
    let rechazado = impostor
        .abrir_sesion()
        .and_then(|mut s| s.enrolar(&impostor.solicitud_enrolamiento()?))
        .is_err();
    println!("agente impostor (otra CA): rechazado={rechazado}");

    servidor.parar();
    Ok(legitimo_ok && rechazado && plano.num_agentes() == 1)
}
