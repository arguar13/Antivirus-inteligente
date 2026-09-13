//! Imprime el presupuesto de este host y el de las clases de referencia.
//!
//! Lo usa el instalador para ensenar lo que va a imponer antes de imponerlo, y
//! `tools/verificar-presupuesto.sh` para comprobar que las cifras de la
//! documentacion siguen siendo las que calcula el codigo.
//!
//! ```text
//! reparto                    tabla legible de este host y de las referencias
//! reparto --dropin           fragmento de systemd para este host
//! reparto --campo <nombre>   un unico numero en bytes, para los scripts
//! ```

use aegis_presupuesto::{dropin, reparto::LINEA_BASE_ARRANQUE, resumen, Componente, Presupuesto};

const GIB: u64 = 1024 * 1024 * 1024;

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let propio = aegis_presupuesto::efectivo();

    // Modo para scripts: un numero y nada mas, para que `$(...)` en sh no tenga
    // que recortar nada ni adivinar el formato.
    if let Some(i) = args.iter().position(|a| a == "--campo") {
        let Some(campo) = args.get(i + 1) else {
            eprintln!("--campo necesita un nombre");
            return std::process::ExitCode::from(2);
        };
        let valor = match campo.as_str() {
            "reposo" => propio.reposo,
            "pico" => propio.pico,
            "techo" => propio.techo,
            "memoria_host" => propio.memoria_host,
            "linea_base" => LINEA_BASE_ARRANQUE,
            "perfil" => {
                println!("{}", propio.perfil.nombre());
                return std::process::ExitCode::SUCCESS;
            }
            otro => match Componente::todos().iter().find(|c| c.nombre() == otro) {
                Some(c) => propio.cuota(*c),
                None => {
                    eprintln!("campo desconocido: {otro}");
                    return std::process::ExitCode::from(2);
                }
            },
        };
        println!("{valor}");
        return std::process::ExitCode::SUCCESS;
    }

    if args.iter().any(|a| a == "--dropin") {
        print!("{}", dropin(&propio));
        return std::process::ExitCode::SUCCESS;
    }

    println!("== este host ==");
    print!("{}", resumen(&propio));
    println!(
        "  linea base de arranque {} (puerta de regresion, no escala con el host)",
        aegis_presupuesto::humano(LINEA_BASE_ARRANQUE)
    );

    println!("\n== clases de referencia ==");
    for (nombre, memoria) in [
        ("pasarela IoT", GIB),
        ("VM minima", 2 * GIB),
        ("portatil", 8 * GIB),
        ("estacion", 16 * GIB),
        ("servidor", 64 * GIB),
        ("host de BBDD", 768 * GIB),
    ] {
        let p = Presupuesto::para(memoria);
        print!("{nombre}: {}", resumen(&p));
    }
    std::process::ExitCode::SUCCESS
}
