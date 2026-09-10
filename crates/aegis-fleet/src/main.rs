//! Binario del agente de flota: levanta un plano de control y un agente sobre
//! `localhost` y ejecuta un ciclo real de enrolamiento, latido y reporte.
//!
//! No es un demo de juguete: usa la misma pila que produccion —CA real, mTLS
//! mutuo, certificados en memoria— sobre el bucle de red local. Sirve para ver
//! el modulo en marcha y como arranque de un despliegue de un solo nodo.

use std::sync::Arc;

use aegis_fleet::proto::{Latido, ReporteEvento};
use aegis_fleet::{
    ahora_unix, AutoridadCertificadora, ClienteFlota, EmisorLocal, PlanoDeControl,
    PoliticaRotacion, RotadorCertificados, ServidorFlota,
};

fn main() -> std::process::ExitCode {
    match ejecutar() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("aegis-fleet: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn ejecutar() -> aegis_fleet::Resultado<()> {
    // CA de la flota y certificado del plano de control.
    let ca = Arc::new(AutoridadCertificadora::nueva("AegisFleet Root CA")?);
    let ca_der = ca.cert_der();
    let id_servidor = ca.emitir("control-plane", 3600)?;

    let plano = Arc::new(PlanoDeControl::nuevo());
    let servidor =
        ServidorFlota::nuevo(&id_servidor, &ca_der, plano.clone())?.escuchar("127.0.0.1:0")?;
    let addr = servidor.direccion();
    println!("plano de control escuchando en {addr}");

    // Agente con rotacion automatica de su identidad.
    let emisor = Arc::new(EmisorLocal::nuevo(ca.clone()));
    let rotador = Arc::new(RotadorCertificados::nuevo(
        "agente-001",
        PoliticaRotacion::default(),
        emisor,
    )?);
    let agente = ClienteFlota::nuevo(addr, ca_der.clone(), rotador, "endpoint-01", "1.0.0");

    // Enrolamiento.
    let mut sesion = agente.abrir_sesion()?;
    let enrol = sesion.enrolar(&agente.solicitud_enrolamiento()?)?;
    println!(
        "enrolamiento: aceptado={} id_flota={} intervalo={}s",
        enrol.aceptado, enrol.id_flota, enrol.intervalo_latido_seg
    );
    println!(
        "servidor autenticado como: {}",
        sesion.servidor_autenticado().unwrap_or("?")
    );

    // Un latido y un reporte de evento reales.
    let ack = sesion.latir(&Latido {
        id_agente: agente.cn().to_string(),
        momento_unix: ahora_unix(),
        rss_kb: 22_000,
        amenazas_activas: 0,
        version_politica: 1,
    })?;
    println!(
        "latido: recibido={} politica_disponible={}",
        ack.recibido, ack.version_politica_disponible
    );

    let ack_ev = sesion.reportar_evento(&ReporteEvento {
        id_agente: agente.cn().to_string(),
        severidad: 2,
        categoria: "syscall-directa".into(),
        descripcion: "evasion de enganches detectada".into(),
        momento_unix: ahora_unix(),
        detalles_json: String::new(),
    })?;
    println!(
        "evento: recibido={} incidente={}",
        ack_ev.recibido, ack_ev.id_incidente
    );

    if let Some(reg) = plano.registro("agente-001") {
        println!(
            "registro en el plano: latidos={} eventos={}",
            reg.latidos, reg.eventos
        );
    }

    drop(sesion);
    servidor.parar();
    Ok(())
}
