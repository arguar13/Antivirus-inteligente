//! Exporta el inventario REAL de esta maquina por el unico camino que existe:
//! el juez de difusion, hacia un destino de la propia organizacion.
//!
//! Uso: `exportar_sbom <cyclonedx|spdx> <fichero>`
//!
//! Lo usa la puerta de calidad para comprobar que el documento que sale lo lee
//! otra herramienta (Trivy consume CycloneDX), y que un destino ajeno no lo
//! recibe con el mismo inventario.

use aegis_postura::salida::{exportar, Formato};
use aegis_sbom::{recoger, Opciones};
use aegis_share::{Canal, Destino, Difusor, Tlp};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (Some(f), Some(fichero)) = (args.first(), args.get(1)) else {
        eprintln!("uso: exportar_sbom <cyclonedx|spdx> <fichero>");
        std::process::exit(2);
    };
    let formato = match f.as_str() {
        "cyclonedx" => Formato::CycloneDx,
        "spdx" => Formato::Spdx,
        _ => {
            eprintln!("formato desconocido: {f}");
            std::process::exit(2);
        }
    };
    let sbom = recoger(&Opciones::del_sistema());
    let mut d = Difusor::nuevo();
    for (nombre, propia) in [("soc-propio", true), ("socio-externo", false)] {
        d.declarar(Destino {
            nombre: nombre.into(),
            canal: Canal::Exportacion,
            tope_tlp: Tlp::Red,
            es_propia_organizacion: propia,
        });
    }
    let ahora = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
    // Hacia fuera: el mismo inventario, retenido.
    match exportar(&sbom, formato, "socio-externo", &d, ahora) {
        Err(e) => println!("hacia socio-externo: {e}"),
        Ok(_) => {
            eprintln!("EL INVENTARIO SALIO HACIA FUERA DE LA ORGANIZACION");
            std::process::exit(1);
        }
    }
    match exportar(&sbom, formato, "soc-propio", &d, ahora) {
        Ok(doc) => {
            if let Err(e) = std::fs::write(fichero, &doc.contenido) {
                eprintln!("no se pudo escribir {fichero}: {e}");
                std::process::exit(1);
            }
            println!(
                "hacia soc-propio: {} componentes, {} bytes en {fichero}",
                sbom.componentes.len(),
                doc.contenido.len()
            );
        }
        Err(e) => {
            eprintln!("hacia soc-propio: {e}");
            std::process::exit(1);
        }
    }
}
