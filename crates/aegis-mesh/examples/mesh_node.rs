//! Nodo de la malla, para la simulacion de Red Team.
//!
//! Dos procesos SEPARADOS que se hablan por UDP, que es como funciona en
//! produccion: la propagacion entre hilos del mismo proceso no demuestra que el
//! formato de red, el cifrado y el descubrimiento funcionen de verdad.
//!
//! - `--listen --seconds N`: escucha y anuncia por la salida estandar lo que
//!   acepta y lo que descarta.
//! - `--send <ip:puerto> [--wrong-key]`: emite una vacuna, con la clave de la
//!   malla o con otra, para comprobar que un intruso no puede inyectar nada.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use aegis_mesh::mesh::{DropReason, Mesh, MeshConfig};
use aegis_mesh::vaccine::{Severity, Vaccine};
use aegis_sync::ioc::{Ioc, IocKind};

/// Clave de la malla para el escenario. En produccion la reparte el
/// aprovisionamiento; aqui es fija para que el escenario sea reproducible.
const CLAVE: [u8; 32] = [0x5a; 32];

fn ahora() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let escuchar = args.iter().any(|a| a == "--listen");
    let clave_mala = args.iter().any(|a| a == "--wrong-key");
    let destino = args
        .windows(2)
        .find(|w| w[0] == "--send")
        .and_then(|w| w[1].parse::<SocketAddr>().ok());
    let segundos: u64 = args
        .windows(2)
        .find(|w| w[0] == "--seconds")
        .and_then(|w| w[1].parse().ok())
        .unwrap_or(6);

    let key = if clave_mala { [0xAA; 32] } else { CLAVE };
    let config = MeshConfig {
        bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        peers: destino.into_iter().collect(),
        key,
        ..MeshConfig::default()
    };

    let mut malla = match Mesh::bind(config) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("no se pudo levantar la malla: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    if escuchar {
        println!("PUERTO {}", malla.local_addr().port());
        let fin = Instant::now() + Duration::from_secs(segundos);
        while Instant::now() < fin {
            for r in malla.poll(Duration::from_millis(200), ahora()) {
                println!(
                    "RECIBIDA {} {} saltos={}",
                    r.vaccine.ioc.kind.as_str(),
                    r.vaccine.ioc.value,
                    r.vaccine.hops
                );
            }
        }
        let s = malla.stats();
        println!(
            "RESUMEN recibidos={} aceptadas={} no_autenticos={} total_descartes={}",
            s.received,
            s.accepted,
            s.drops_of(DropReason::NotAuthentic),
            s.dropped()
        );
        return std::process::ExitCode::SUCCESS;
    }

    let Some(_) = destino else {
        eprintln!("uso: mesh_node --listen | --send <ip:puerto> [--wrong-key]");
        return std::process::ExitCode::FAILURE;
    };

    let v = Vaccine::new(
        Ioc::new(IocKind::FileSha256, "d".repeat(64)),
        Severity::Contained,
        ahora(),
    )
    .with_techniques(vec!["T1486".into()]);

    match malla.broadcast(&v) {
        Ok(n) => {
            println!(
                "ENVIADA a {n} par(es), clave={}",
                if clave_mala { "intrusa" } else { "de la malla" }
            );
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("no se pudo emitir: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
