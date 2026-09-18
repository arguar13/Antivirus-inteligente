//! Red de senuelos en marcha, para la simulacion de Red Team.
//!
//! Levanta senuelos de SSH, SMB y RDP en puertos efimeros de la interfaz local,
//! anuncia en que puertos escucha y despues informa de cada alerta que produce
//! el trafico que reciba. Quien lo lanza hace de atacante y comprueba que la
//! deteccion ocurre.
//!
//! Se liga a `127.0.0.1` y a puertos efimeros a proposito: una simulacion no
//! debe exponer servicios a la red de la maquina donde corre.

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use aegis_deception::decoy::{DecoyConfig, DecoyKind};
use aegis_deception::engine::{DeceptionConfig, DeceptionEngine};
use aegis_deception::sensor::SensorConfig;
use aegis_scal::linux::netfilter::NftablesFilter;

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let segundos: u64 = args
        .windows(2)
        .find(|w| w[0] == "--seconds")
        .and_then(|w| w[1].parse().ok())
        .unwrap_or(5);

    let mut motor = DeceptionEngine::start(
        DeceptionConfig {
            decoys: DecoyConfig {
                bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
                services: vec![
                    (DecoyKind::Ssh, 0),
                    (DecoyKind::Smb, 0),
                    (DecoyKind::Rdp, 0),
                ],
                speak_timeout: Duration::from_millis(100),
                max_evidence: 256,
                max_per_poll: 32,
                cebo: String::new(),
            },
            sensor: SensorConfig::default(),
            allowlist: Vec::new(),
            block_ttl: Some(Duration::from_secs(300)),
            autonomous: true,
        },
        // El filtro de verdad: si el atacante viniera de fuera, el bloqueo se
        // aplicaria en nftables. Viniendo de la propia maquina, la barandilla
        // lo impide, y eso tambien es lo que se quiere demostrar.
        NftablesFilter::new(),
    );

    let activos = motor.active();
    if activos.len() != 3 {
        eprintln!("no se pudieron levantar los tres senuelos: {activos:?}");
        return std::process::ExitCode::FAILURE;
    }
    let puertos: Vec<String> = activos.iter().map(|(_, p)| p.to_string()).collect();
    println!("PUERTOS {}", puertos.join(" "));
    let _ = std::io::stdout().flush();

    let fin = Instant::now() + Duration::from_secs(segundos);
    while Instant::now() < fin {
        let r = motor.tick(Duration::from_millis(200), 0);
        for a in &r.alerts {
            println!("ALERTA {} {} block={}", a.kind.as_str(), a.peer, a.block);
        }
        for (ip, motivo) in &r.refused {
            println!("RECHAZO {ip} {motivo}");
        }
        for ip in &r.blocked {
            println!("BLOQUEADA {ip}");
        }
        let _ = std::io::stdout().flush();
    }

    let s = motor.stats();
    println!(
        "RESUMEN interacciones={} alertas={} bloqueadas={} rechazadas={}",
        s.interactions, s.alerts, s.blocked, s.refused
    );
    std::process::ExitCode::SUCCESS
}
