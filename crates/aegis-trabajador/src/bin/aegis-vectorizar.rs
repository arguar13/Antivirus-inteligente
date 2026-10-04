//! `aegis-vectorizar`: el vector de cada fichero, con EL MISMO codigo que el
//! trabajador confinado usa antes de inferir (FASE 4.4 del MP-16).
//!
//! Entrada (stdin), una linea por fichero:   `<sha256>\t<ruta>`
//! Salida (stdout):
//!
//! ```text
//!   # aegis-vectorizar version_vector=1 dim=256 huella_extractor=<hex> aegis-ml=<version>
//!   <sha256>\tOK\t<microsegundos>\t<v0>,<v1>,...,<v255>
//!   <sha256>\tSINDATOS\t<motivo>
//! ```
//!
//! # Por que existe y por que vive aqui
//!
//! El entrenamiento (`tools/ml/entrenar.py`) no calcula caracteristicas: las
//! LEE de esta salida. Asi no hay un segundo extractor que pueda divergir del
//! de produccion: este binario llama a `aegis_ml::vectorizar`, la misma
//! funcion que `Analizadores::modelo`, y graba la huella del extractor que la
//! tarjeta del modelo copia y la puerta del agente comprueba.
//!
//! El tope de tamaño es el del canal del trabajador (`MAX_DATOS`): un fichero
//! que el agente no analizaria tampoco entra en el entrenamiento.
//!
//! # Donde se ejecuta
//!
//! Lee bytes no confiables con los parsers del producto, como el trabajador,
//! pero SIN su confinamiento. Las muestras solo se abren dentro de la microVM
//! desechable y sin red del laboratorio (pendiente/fase4/CORPUS.md); los
//! benignos de las imagenes, donde se quiera. De la VM salen estas lineas, que
//! son numeros, nunca bytes.

use std::io::{self, BufRead, BufWriter, Write};
use std::time::Instant;

use aegis_trabajador::protocolo::MAX_DATOS;

fn main() -> io::Result<()> {
    let salida = io::stdout();
    let mut out = BufWriter::new(salida.lock());
    writeln!(
        out,
        "# aegis-vectorizar version_vector={} dim={} huella_extractor={} aegis-ml={}",
        aegis_ml::VERSION_VECTOR,
        aegis_ml::FEATURE_DIM,
        aegis_ml::huella_extractor(),
        env!("CARGO_PKG_VERSION"),
    )?;
    for linea in io::stdin().lock().lines() {
        let linea = linea?;
        let linea = linea.trim_end_matches('\r');
        if linea.is_empty() || linea.starts_with('#') {
            continue;
        }
        let Some((id, ruta)) = linea.split_once('\t') else {
            writeln!(out, "{linea}\tSINDATOS\tlinea sin tabulador")?;
            continue;
        };
        match std::fs::metadata(ruta) {
            Ok(m) if m.len() > MAX_DATOS as u64 => {
                writeln!(out, "{id}\tSINDATOS\tmayor que el tope del trabajador")?;
                continue;
            }
            Err(e) => {
                writeln!(out, "{id}\tSINDATOS\t{}", e.kind())?;
                continue;
            }
            Ok(_) => {}
        }
        let datos = match std::fs::read(ruta) {
            Ok(d) => d,
            Err(e) => {
                writeln!(out, "{id}\tSINDATOS\t{}", e.kind())?;
                continue;
            }
        };
        let t0 = Instant::now();
        let v = aegis_ml::vectorizar(&datos);
        let us = t0.elapsed().as_micros();
        let texto: Vec<String> = v.iter().map(f32::to_string).collect();
        writeln!(out, "{id}\tOK\t{us}\t{}", texto.join(","))?;
    }
    out.flush()
}
