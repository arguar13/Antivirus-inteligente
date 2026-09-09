//! CLI del IDS de red.

use std::net::Ipv4Addr;
use std::process::ExitCode;

fn uso() -> &'static str {
    "aegis-net - IDS de red y filtro XDP de AegisCore

USO:
    aegis-net <SUBCOMANDO>

SUBCOMANDOS:
    selftest              Carga el filtro y lo ejercita con tramas sinteticas
    stats                 Carga el filtro e imprime sus contadores
    block <IP> [SEGUNDOS] Bloquea una direccion
    blocklist             Lista las direcciones bloqueadas
    attach <INTERFAZ>     Engancha el filtro a una interfaz y se queda activo

NOTA SOBRE attach:
    Enganchar el filtro afecta al trafico REAL de esa interfaz. Se recomienda
    probar primero con 'selftest', que ejercita exactamente el mismo codigo de
    kernel contra tramas fabricadas y sin tocar ninguna interfaz."
}

#[cfg(all(target_os = "linux", feature = "xdp"))]
fn main() -> ExitCode {
    use aegis_net::xdp::{BlockReason, XdpConfig, XdpFilter};
    use aegis_net::PacketBuilder;
    use std::time::Duration;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(sub) = args.first().map(String::as_str) else {
        println!("{}", uso());
        return ExitCode::from(2);
    };

    let cargar = || match XdpFilter::load(&XdpConfig::default()) {
        Ok(f) => Ok(f),
        Err(e) => {
            eprintln!("error: {e}");
            Err(ExitCode::FAILURE)
        }
    };

    match sub {
        "-h" | "--help" | "help" => {
            println!("{}", uso());
            ExitCode::SUCCESS
        }

        "selftest" => {
            let mut f = match cargar() {
                Ok(f) => f,
                Err(c) => return c,
            };
            let atacante = Ipv4Addr::new(203, 0, 113, 66);
            let victima = Ipv4Addr::new(198, 51, 100, 10);

            println!("== Autoprueba del filtro XDP (sin tocar ninguna interfaz) ==");

            let syn = PacketBuilder::tcp_syn(atacante, victima, 40000, 22);
            match f.test_packet(&syn) {
                Ok(a) => println!("  SYN normal              -> {a:?}"),
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::FAILURE;
                }
            }

            if let Err(e) = f.block(atacante, Some(Duration::from_secs(60)), BlockReason::Manual) {
                eprintln!("error al bloquear: {e}");
                return ExitCode::FAILURE;
            }
            match f.test_packet(&syn) {
                Ok(a) => println!("  SYN de IP bloqueada     -> {a:?}"),
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::FAILURE;
                }
            }

            let otro = PacketBuilder::tcp_syn(Ipv4Addr::new(203, 0, 113, 67), victima, 40000, 22);
            match f.test_packet(&otro) {
                Ok(a) => println!("  SYN de IP no bloqueada  -> {a:?}"),
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::FAILURE;
                }
            }

            match f.stats() {
                Ok(s) => println!("\n  contadores: {s:?}"),
                Err(e) => eprintln!("aviso: no se pudieron leer contadores: {e}"),
            }
            ExitCode::SUCCESS
        }

        "stats" => match cargar() {
            Ok(f) => match f.stats() {
                Ok(s) => {
                    println!("{s:#?}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            },
            Err(c) => c,
        },

        "block" => {
            let Some(ip) = args.get(1).and_then(|s| s.parse::<Ipv4Addr>().ok()) else {
                eprintln!("error: 'block' necesita una direccion IPv4 valida");
                return ExitCode::from(2);
            };
            let ttl = args
                .get(2)
                .and_then(|s| s.parse::<u64>().ok())
                .map(Duration::from_secs);
            let f = match cargar() {
                Ok(f) => f,
                Err(c) => return c,
            };
            match f.block(ip, ttl, BlockReason::Manual) {
                Ok(()) => {
                    println!("bloqueada {ip}");
                    // El bloqueo vive en un mapa del objeto BPF cargado. Al
                    // salir el proceso, el objeto se libera y el bloqueo
                    // desaparece: decirlo evita que alguien crea que persiste.
                    println!(
                        "aviso: este mapa vive con el proceso. Para que el bloqueo tenga \
                         efecto real hay que mantener el filtro enganchado con 'attach'."
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }

        "blocklist" => match cargar() {
            Ok(f) => match f.blocklist() {
                Ok(l) if l.is_empty() => {
                    println!("lista de bloqueo vacia");
                    ExitCode::SUCCESS
                }
                Ok(l) => {
                    for e in l {
                        println!(
                            "{:>15}  motivo={:?}  descartes={}  restante={}",
                            e.address,
                            e.reason,
                            e.hits,
                            match e.remaining_ns {
                                None => "permanente".to_string(),
                                Some(ns) => format!("{} s", ns / 1_000_000_000),
                            }
                        );
                    }
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            },
            Err(c) => c,
        },

        "attach" => {
            let Some(iface) = args.get(1) else {
                eprintln!("error: 'attach' necesita el nombre de una interfaz");
                return ExitCode::from(2);
            };
            let mut f = match cargar() {
                Ok(f) => f,
                Err(c) => return c,
            };
            match f.attach(iface) {
                Ok(_link) => {
                    println!("filtro enganchado a {iface}. Ctrl-C para desenganchar.");
                    // El enlace tiene que seguir vivo: al soltarlo, el filtro se
                    // desengancha y el trafico deja de inspeccionarse.
                    loop {
                        std::thread::sleep(Duration::from_secs(5));
                        if let Ok(s) = f.stats() {
                            println!(
                                "paquetes={} syn={} descartados={} barridos={}",
                                s.packets, s.syn, s.dropped, s.scans
                            );
                        }
                    }
                }
                Err(e) => {
                    eprintln!("error al enganchar en {iface}: {e}");
                    ExitCode::FAILURE
                }
            }
        }

        otro => {
            eprintln!("error: subcomando desconocido '{otro}'\n\n{}", uso());
            ExitCode::from(2)
        }
    }
}

#[cfg(not(all(target_os = "linux", feature = "xdp")))]
fn main() -> ExitCode {
    eprintln!(
        "aegis-net se compilo sin la caracteristica 'xdp' o para un sistema que no es \
         Linux.\nEl analizador de paquetes y el detector de barridos estan disponibles \
         como biblioteca.\n\n{}",
        uso()
    );
    ExitCode::FAILURE
}
