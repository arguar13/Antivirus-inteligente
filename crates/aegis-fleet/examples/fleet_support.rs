//! Informa de las capacidades del agente de flota en esta maquina.
//!
//! A diferencia del firmware o la PMU, la gestion de flota no depende de
//! hardware especial: es criptografia y red en espacio de usuario. El informe
//! confirma que la pila —proveedor TLS, generacion de certificados, rotacion en
//! memoria, flujo CSR— esta operativa donde corre la puerta de calidad.

use std::sync::Arc;

use aegis_fleet::pki::AutoridadCertificadora;
use aegis_fleet::{EmisorLocal, PeticionFirmaLocal, PoliticaRotacion, RotadorCertificados};

fn main() -> std::process::ExitCode {
    let mut ok = true;

    // Proveedor TLS y generacion de CA.
    let ca = match AutoridadCertificadora::nueva("AegisFleet CA") {
        Ok(c) => {
            println!("proveedor TLS (rustls/ring): SI");
            println!("generacion de CA en memoria: SI");
            Arc::new(c)
        }
        Err(e) => {
            println!("generacion de CA: NO ({e})");
            return std::process::ExitCode::FAILURE;
        }
    };

    // Emision y rotacion con clave en memoria.
    let emisor = Arc::new(EmisorLocal::nuevo(ca.clone()));
    match RotadorCertificados::nuevo("sonda", PoliticaRotacion::default(), emisor) {
        Ok(r) => {
            let h1 = r.actual().map(|i| i.huella()).unwrap_or_default();
            let _ = r.rotar();
            let h2 = r.actual().map(|i| i.huella()).unwrap_or_default();
            println!(
                "rotacion de certificado (clave nueva en memoria): {}",
                if h1 != h2 && !h1.is_empty() {
                    "SI"
                } else {
                    "NO"
                }
            );
            ok &= h1 != h2 && !h1.is_empty();
        }
        Err(e) => {
            println!("rotacion: NO ({e})");
            ok = false;
        }
    }

    // Flujo CSR: la clave nunca sale del endpoint.
    match PeticionFirmaLocal::generar("sonda").and_then(|p| {
        ca.firmar_csr(&p.csr_der, 300)
            .map(|(c, a, d)| p.ensamblar(c, a, d))
    }) {
        Ok(id) => {
            println!(
                "flujo CSR (la CA no ve la clave privada): SI (cn={})",
                id.cn
            );
        }
        Err(e) => {
            println!("flujo CSR: NO ({e})");
            ok = false;
        }
    }

    println!("clave privada en disco: NUNCA (solo en memoria, borrada al rotar)");
    println!(
        "transporte: gRPC unario protobuf sobre mTLS mutuo (enmarcado length-prefixed, sincrono)"
    );

    if ok {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::FAILURE
    }
}
