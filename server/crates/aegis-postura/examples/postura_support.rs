//! Imprime el informe de postura de un lote de fixtures de los tres
//! proveedores, pasado por `aegis_pipeline::nube::analizar_lote` como en
//! produccion.
//!
//! Lo usa la puerta de calidad para enseñar, en una salida legible, que cada
//! hallazgo cita su evento y su entidad, y que lo que no se observo dice
//! `SIN DATOS`. Se ejecuta dos veces el mismo lote: con el crudo conservado y
//! sin el, para que la diferencia —Azure y GCP sin cuerpo que leer— se vea en
//! vez de contarse.
//!
//! ```text
//! cargo run -p aegis-postura --example postura_support
//! ```

use aegis_ingest::tiempo::desde_rfc3339;
use aegis_pipeline::nube::{analizar_lote, Contexto};
use aegis_postura::{Estado, Informe};

const LOTES: [(&str, &str); 4] = [
    ("aws.json", include_str!("../fixtures/aws.json")),
    (
        "aws_correccion.json",
        include_str!("../fixtures/aws_correccion.json"),
    ),
    ("azure.json", include_str!("../fixtures/azure.json")),
    ("gcp.jsonl", include_str!("../fixtures/gcp.jsonl")),
];

fn main() {
    let Some(ahora) = desde_rfc3339("2026-09-26T00:00:00Z") else {
        eprintln!("fecha de referencia ilegible");
        std::process::exit(1);
    };
    let mut resumen = Vec::new();
    for conservar_crudo in [true, false] {
        let ctx = Contexto {
            inquilino: "demostracion".into(),
            observado_ns: ahora,
            conservar_crudo,
        };
        let mut eventos = Vec::new();
        for (nombre, doc) in LOTES {
            let v = analizar_lote(doc.as_bytes(), &ctx);
            if conservar_crudo {
                println!("lote {nombre}: {} eventos", v.len());
            }
            eventos.extend(v);
        }
        let inf = Informe::evaluar(&eventos, ahora);
        if conservar_crudo {
            println!();
            print!("{}", inf.texto());
            println!();
            println!(
                "{} exposicion(es) al informe de postura; {} compromiso(s) a respuesta a \
                 incidentes; ninguno mueve el juicio del arbitro (ver la documentacion del crate)",
                inf.exposiciones().len(),
                inf.compromisos().len()
            );
        }
        let (mut cumple, mut incumple, mut sin_datos) = (0, 0, 0);
        for c in &inf.comprobaciones {
            for (_, e) in &c.por_proveedor {
                match e {
                    Estado::Cumple(_) => cumple += 1,
                    Estado::Incumple(_) => incumple += 1,
                    Estado::SinDatos(_) => sin_datos += 1,
                }
            }
        }
        resumen.push((conservar_crudo, cumple, incumple, sin_datos));
    }
    println!("\nCOMPARACION (comprobacion x proveedor)");
    for (crudo, c, i, s) in resumen {
        println!(
            "  {:<12} cumple={c:<3} incumple={i:<3} sin-datos={s:<3}",
            if crudo { "con crudo" } else { "sin crudo" }
        );
    }
}
