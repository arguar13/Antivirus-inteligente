//! El binario del rango: ejecuta las emulaciones REALES dentro de una microVM,
//! contra el agente publicado, para que la prueba de matriz `rango-en-vivo` mida
//! la cobertura de verdad (no la que permitirian los motores, sino la que el
//! agente detecta cuando el ataque ocurre).
//!
//! # Interfaz, pensada para `tools/matriz-kernels/dentro.sh`
//!
//! - `aegis-rango --listar`
//!   imprime una linea por emulacion aplicable:
//!   `AEGIS-RANGO|tecnica|<id>|<motor>|<ventana_s>|<patron>`
//!   El `<patron>` es la subcadena que la prueba busca en el `porque` de la
//!   señal del `<motor>` para contar la tecnica como detectada.
//!
//! - `aegis-rango --tecnica <id> --jaula <dir>`
//!   declara un rango en `<dir>`, EJECUTA esa emulacion, espera su ventana y la
//!   REVIERTE. Imprime:
//!   `AEGIS-RANGO|ejecuta|<id>|<pid|->`     (el pid del proceso implicado, si lo hay)
//!   `AEGIS-RANGO|revierte|<id>|<ok|residuo>`
//!
//! Trae las cinco tecnicas que se hacen con `std` y utilidades del sistema.

use std::process::ExitCode;

use aegis_rango::rango::{ConfirmacionRango, Plataforma, Rango};
use aegis_rango::tecnicas_reales::{catalogo_seguro, Emulacion};

const AYUDA: &str = "aegis-rango - emulador de adversario del rango de AegisCore\n\
     \n\
     USO:\n\
       aegis-rango --listar\n\
       aegis-rango --tecnica <id> --jaula <dir>\n\
     \n\
     SOLO emula tecnicas benignas y reversibles dentro del rango declarado.";

/// Puerto del servidor local de la VM al que baliza la emulacion de C2.
const PUERTO_BALIZA: u16 = 8443;

/// La IP no-loopback de esta maquina, para que la baliza tenga un destino que las
/// sondas no descarten (el loopback lo ignora el detector). El truco del socket
/// UDP «conectado» no envia ningun paquete: solo hace que el kernel elija la IP de
/// origen que usaria hacia fuera.
fn ip_local() -> String {
    use std::net::UdpSocket;
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("10.255.255.255:9")?;
            Ok(s.local_addr()?.ip().to_string())
        })
        .unwrap_or_else(|_| "10.0.2.15".to_string())
}

/// Todas las emulaciones aplicables en esta VM.
fn catalogo() -> Vec<Emulacion> {
    let destino = format!("{}:{PUERTO_BALIZA}", ip_local());
    catalogo_seguro(&destino)
}

/// Nombre del subdirectorio de la tecnica (igual que `dir_tecnica` del crate).
fn dir_sanitizado(id: &str) -> String {
    let s: String = id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    format!("real_{s}")
}

fn listar() -> ExitCode {
    for e in catalogo() {
        if !e.tecnica.aplica_en(Plataforma::actual()) {
            continue;
        }
        println!(
            "AEGIS-RANGO|tecnica|{}|{}|{}|{}",
            e.tecnica.id(),
            e.tecnica.deteccion_esperada().nombre(),
            e.ventana_s,
            e.patron
        );
    }
    ExitCode::SUCCESS
}

fn ejecutar_una(id: &str, jaula: &str) -> ExitCode {
    let Some(e) = catalogo().into_iter().find(|e| e.tecnica.id() == id) else {
        eprintln!("aegis-rango: tecnica desconocida: {id}");
        return ExitCode::from(2);
    };
    let rango = match Rango::declarar(
        Plataforma::actual(),
        jaula,
        ConfirmacionRango::nueva("matriz", "prueba rango-en-vivo"),
    ) {
        Ok(r) => r,
        Err(err) => {
            eprintln!("aegis-rango: no se pudo declarar el rango: {err}");
            return ExitCode::FAILURE;
        }
    };
    let prueba = rango.prueba();

    if let Err(err) = e.tecnica.ejecutar(&prueba, &rango) {
        eprintln!("aegis-rango: la emulacion {id} fallo al ejecutarse: {err}");
        return ExitCode::FAILURE;
    }
    // El pid del proceso implicado, si la tecnica dejo uno en su subdirectorio.
    let pid = std::fs::read_to_string(rango.raiz().join(dir_sanitizado(id)).join("pid"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "-".to_string());
    println!("AEGIS-RANGO|ejecuta|{id}|{pid}");

    // La ventana durante la cual el agente tiene que reaccionar: la prueba
    // consulta el journal mientras tanto.
    std::thread::sleep(std::time::Duration::from_secs(e.ventana_s));

    let residuo = match e.tecnica.revertir(&prueba, &rango) {
        Ok(()) => e.tecnica.exito(&rango),
        Err(err) => {
            eprintln!("aegis-rango: AVISO la reversion de {id} fallo: {err}");
            true
        }
    };
    println!(
        "AEGIS-RANGO|revierte|{id}|{}",
        if residuo { "residuo" } else { "ok" }
    );
    if residuo {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn valor(args: &[String], bandera: &str) -> Option<String> {
    args.iter()
        .position(|a| a == bandera)
        .and_then(|i| args.get(i + 1).cloned())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        eprintln!("{AYUDA}");
        return ExitCode::SUCCESS;
    }
    if args.iter().any(|a| a == "--listar") {
        return listar();
    }
    if let Some(id) = valor(&args, "--tecnica") {
        let Some(jaula) = valor(&args, "--jaula") else {
            eprintln!("aegis-rango: --tecnica necesita --jaula <dir>");
            return ExitCode::from(2);
        };
        return ejecutar_una(&id, &jaula);
    }
    eprintln!("{AYUDA}");
    ExitCode::from(2)
}
