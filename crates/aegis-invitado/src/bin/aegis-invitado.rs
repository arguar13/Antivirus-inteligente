//! El binario que va dentro de la imagen del invitado.
//!
//! Hace exactamente tres cosas, y no hace ninguna mas a proposito: abre el canal,
//! traza la muestra, y cierra el canal diciendo lo que perdio. Cada capacidad de
//! mas que tuviera este binario seria una capacidad que la muestra puede tomar
//! prestada en cuanto escale, asi que no lee configuracion de disco, no abre
//! sockets de red, y no ejecuta nada que no sea la muestra.
//!
//! ```text
//! aegis-invitado --muestra RUTA [--arg X]... [--plazo SEGUNDOS]
//!                [--canal-unix RUTA | --canal-vsock PUERTO]
//! ```

use std::path::PathBuf;
use std::time::Duration;

use aegis_invitado::canal::{Canal, PUERTO};
use aegis_invitado::protocolo::Evento;
use aegis_invitado::trazador::{self, Config, Sumidero};

/// Sumidero que manda cada hecho por el canal segun se observa.
///
/// Se emite al vuelo y no al final: si la muestra consigue matar al agente a
/// mitad de la detonacion, lo ya enviado sigue siendo evidencia valida. Acumular
/// para mandarlo al terminar regalaria al malware una forma trivial de borrarlo
/// todo — basta con no dejar que termine.
struct PorElCanal(Canal);

impl Sumidero for PorElCanal {
    fn emitir(&mut self, evento: Evento) {
        self.0.enviar(evento);
    }
}

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut muestra: Option<PathBuf> = None;
    let mut argumentos: Vec<String> = Vec::new();
    let mut plazo = Duration::from_secs(60);
    let mut ruta_unix: Option<PathBuf> = None;
    let mut puerto_vsock: Option<u32> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--muestra" => {
                muestra = args.get(i + 1).map(PathBuf::from);
                i += 2;
            }
            "--arg" => {
                if let Some(a) = args.get(i + 1) {
                    argumentos.push(a.clone());
                }
                i += 2;
            }
            "--plazo" => {
                if let Some(s) = args.get(i + 1).and_then(|v| v.parse().ok()) {
                    plazo = Duration::from_secs(s);
                }
                i += 2;
            }
            "--canal-unix" => {
                ruta_unix = args.get(i + 1).map(PathBuf::from);
                i += 2;
            }
            "--canal-vsock" => {
                puerto_vsock = args
                    .get(i + 1)
                    .and_then(|v| v.parse().ok())
                    .or(Some(PUERTO));
                i += 2;
            }
            otro => {
                eprintln!("argumento desconocido: {otro}");
                return std::process::ExitCode::from(2);
            }
        }
    }

    let Some(muestra) = muestra else {
        eprintln!("falta --muestra");
        return std::process::ExitCode::from(2);
    };

    let canal = match (ruta_unix, puerto_vsock) {
        (Some(r), _) => Canal::unix(&r),
        (None, Some(p)) => Canal::vsock(p),
        (None, None) => Canal::vsock(PUERTO),
    };
    let canal = match canal {
        Ok(c) => c,
        Err(e) => {
            // Sin canal no hay informe posible. Se dice y se sale, en vez de
            // detonar a ciegas: una detonacion cuya traza no llega a ningun
            // sitio es una maquina infectada sin contrapartida.
            eprintln!("aegis-invitado: {e}");
            return std::process::ExitCode::from(3);
        }
    };

    let mut sumidero = PorElCanal(canal);
    sumidero.emitir(Evento::Preparado {
        version: aegis_invitado::VERSION.to_string(),
    });

    let mut cfg = Config::nueva(muestra);
    cfg.argumentos = argumentos;
    cfg.plazo = plazo;

    let (codigo, completo) = match trazador::trazar(&cfg, &mut sumidero) {
        Ok(r) => {
            if !r.desenlace.completo() {
                sumidero.emitir(Evento::Degradado {
                    causa: format!("la detonacion se corto: {:?}", r.desenlace),
                });
            }
            match r.desenlace {
                trazador::Desenlace::Termino { codigo } => (codigo, true),
                // Que la matara una senal cuenta como final de la muestra: paso
                // lo que tenia que pasar y se vio entero.
                trazador::Desenlace::Senal { senal } => (-senal, true),
                // Cortada. El agente sale limpiamente igual, asi que si no lo
                // dijera aqui el anfitrion veria un cero y leeria «termino».
                trazador::Desenlace::Cortado { .. } => (-1, false),
            }
        }
        Err(e) => {
            sumidero.emitir(Evento::Degradado {
                causa: format!("el trazador no pudo arrancar: {e}"),
            });
            (-1, false)
        }
    };

    sumidero.0.cerrar(codigo, completo);
    std::process::ExitCode::SUCCESS
}
