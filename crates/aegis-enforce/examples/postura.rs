//! Imprime la postura de esta maquina, medida: una linea por capacidad.
//!
//! ```text
//! cargo run -q -p aegis-enforce --example postura [-- --testigo PID[:landlock=ABI] ...]
//! ```
//!
//! Formato, una capacidad por linea: `capacidad|ETIQUETA|detalle`, y al final
//! `# frase` con la frase con la que el agente debe describirse. Es lo que lee
//! `tools/verificar-mac.sh`: asi ningun script escribe a mano el estado de una
//! capa, que es como se acaba afirmando que se impone lo que solo esta
//! disponible (hallazgo H-28).
//!
//! Sin testigos ninguna capacidad puede salir APLICA: no hay proceso del
//! producto sobre el que medirla. Con `--testigo` se mide ese proceso (por
//! ejemplo, el trabajador confinado del agente).

use std::process::ExitCode;

use aegis_enforce::{Postura, Testigo};

fn main() -> ExitCode {
    let mut testigos = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let valor = match (a.as_str(), args.next()) {
            ("--testigo", Some(v)) => v,
            _ => {
                eprintln!("uso: postura [--testigo PID[:landlock=ABI]]...");
                return ExitCode::from(2);
            }
        };
        match valor.parse::<Testigo>() {
            Ok(t) => testigos.push(t),
            Err(m) => {
                eprintln!("postura: {m}");
                return ExitCode::from(2);
            }
        }
    }

    let p = Postura::medida_con(&testigos);
    for (c, e) in &p.capacidades {
        // El separador no puede aparecer dentro de un campo.
        println!(
            "{}|{}|{}",
            c.nombre(),
            e.etiqueta(),
            e.detalle().replace('|', "/")
        );
    }
    println!("# {}", p.como_describirse());
    ExitCode::SUCCESS
}
