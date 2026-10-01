//! `aegisctl` — interfaz de administracion local del agente AegisCore.
//!
//! Habla con el agente en ejecucion por su socket Unix de control. No requiere
//! privilegios propios mas alla de poder abrir el socket (0600, de root), que es
//! justamente lo que se quiere: el control del EDR es de root.

use std::process::ExitCode;

use aegis_ctl::protocol::{IsolateMode, Request, Response};
use aegis_ctl::server::ControlClient;

/// Ruta por defecto del socket de control. En produccion la fija el agente y
/// sale de su tabla de cadenas cifradas; aqui es el valor conocido.
const SOCKET_POR_DEFECTO: &str = "/run/aegiscore/agent.sock";

fn uso() -> String {
    format!(
        "aegisctl - control local del agente AegisCore\n\
         \n\
         USO: aegisctl [--socket RUTA] COMANDO\n\
         \n\
         COMANDOS:\n\
         \x20 status                estado de recursos, memoria y pipeline\n\
         \x20 scan <ruta>           escaneo YARA bajo demanda de una ruta absoluta\n\
         \x20 isolate [modo]        aislamiento de red de emergencia\n\
         \x20                       modo: containment (por defecto) | total\n\
         \x20 quarantine list       lista los identificadores en cuarentena\n\
         \n\
         Socket por defecto: {SOCKET_POR_DEFECTO} (--socket para cambiarlo)."
    )
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut socket = SOCKET_POR_DEFECTO.to_string();
    let mut resto: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--socket" => {
                if i + 1 >= args.len() {
                    eprintln!("--socket requiere una ruta");
                    return ExitCode::from(2);
                }
                socket = args[i + 1].clone();
                i += 2;
            }
            "-h" | "--help" => {
                println!("{}", uso());
                return ExitCode::SUCCESS;
            }
            _ => {
                resto.push(args[i].clone());
                i += 1;
            }
        }
    }

    let req = match construir_peticion(&resto) {
        Ok(r) => r,
        Err(msg) => {
            eprintln!("{msg}\n\n{}", uso());
            return ExitCode::from(2);
        }
    };

    match ControlClient::request(&socket, &req) {
        Ok(resp) => {
            imprimir(&resp);
            match resp {
                Response::Error(_) => ExitCode::FAILURE,
                _ => ExitCode::SUCCESS,
            }
        }
        Err(e) => {
            eprintln!(
                "no se pudo hablar con el agente en {socket}: {e}\n\
                 (¿esta el agente en marcha? ¿tienes permiso sobre el socket?)"
            );
            ExitCode::FAILURE
        }
    }
}

fn construir_peticion(resto: &[String]) -> Result<Request, String> {
    let verbo = resto.first().map(String::as_str).unwrap_or("");
    match verbo {
        "status" => Ok(Request::Status),
        "scan" => {
            let ruta = resto
                .get(1)
                .ok_or("scan requiere una ruta absoluta")?
                .clone();
            Ok(Request::Scan { path: ruta })
        }
        "isolate" => {
            let modo = match resto.get(1).map(String::as_str) {
                None | Some("containment") => IsolateMode::Containment,
                Some("total") => IsolateMode::Total,
                Some(otro) => return Err(format!("modo de aislamiento desconocido: {otro}")),
            };
            Ok(Request::Isolate { mode: modo })
        }
        "quarantine" => match resto.get(1).map(String::as_str) {
            Some("list") => Ok(Request::QuarantineList),
            _ => Err("uso: aegisctl quarantine list".to_string()),
        },
        "" => Err("falta el comando".to_string()),
        otro => Err(format!("comando desconocido: {otro}")),
    }
}

fn imprimir(resp: &Response) {
    match resp {
        Response::Status(s) => {
            println!("estado:        {}", s.state);
            println!("memoria:       {} KB", s.rss_kb);
            println!("en marcha:     {} s", s.uptime_s);
            println!(
                "eventos:       {} recibidos, {} escalados",
                s.events_received, s.events_escalated
            );
            for d in &s.detalle {
                println!("  {d}");
            }
        }
        Response::Scan(s) => {
            if s.detected {
                println!("DETECTADO en {}", s.path);
                for r in &s.rules {
                    println!("  regla: {r}");
                }
            } else {
                println!("limpio: {}", s.path);
            }
        }
        Response::Isolated(i) => {
            let verbo = if i.applied {
                "aplicado"
            } else {
                "simulado (dry-run)"
            };
            println!(
                "aislamiento {verbo}: modo {} ({} reglas)",
                i.mode, i.rule_lines
            );
        }
        Response::Quarantine(ids) => {
            if ids.is_empty() {
                println!("cuarentena vacia");
            } else {
                println!("{} elemento(s) en cuarentena:", ids.len());
                for id in ids {
                    println!("  {id}");
                }
            }
        }
        Response::Error(msg) => {
            eprintln!("error: {msg}");
        }
    }
}
