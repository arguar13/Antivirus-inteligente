//! La puerta de contenido sobre las reglas que viajan en el agente.
//!
//! Para CADA regla incluida: entra en el juego del agente sin rechazo, tiene
//! un evento generado que la dispara y otro que no, tiene presupuesto de falsos
//! positivos y esta en la atribucion. Y el directorio y la lista generada
//! coinciden: una regla en disco que no viaja, o una que viaja sin estar en
//! disco, es contenido que nadie reviso.
//!
//! Sin reglas importadas, lo unico que se exige es que el vacio sea coherente:
//! ni presupuestos ni ficheros sueltos. `tools/verificar-sigma.sh` lo declara
//! («sin contenido») en cada make ci.

use std::collections::BTreeSet;
use std::path::PathBuf;

use aegis_sigma::compacta::{Categoria, Juego};
use aegis_sigma::contenido::{leer_presupuestos, prueba_de};
use aegis_sigma::generador::registro;
use aegis_sigma::incluidas::{LINUX, PRESUPUESTOS};
use aegis_sigma::regla::Topes;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("reglas")
        .join("linux")
}

#[test]
fn el_directorio_y_la_lista_incluida_coinciden() {
    let mut en_disco = BTreeSet::new();
    if let Ok(entradas) = std::fs::read_dir(dir()) {
        for e in entradas.flatten() {
            let p = e.path();
            if p.extension().is_some_and(|x| x == "yml") {
                if let Some(n) = p.file_name().and_then(|n| n.to_str()) {
                    en_disco.insert(n.to_string());
                }
            }
        }
    }
    let incluidas: BTreeSet<String> = LINUX.iter().map(|(n, _)| (*n).to_string()).collect();
    assert_eq!(
        en_disco, incluidas,
        "reglas/linux/ y src/incluidas.rs no coinciden: reimportar con tools/sigma/importar.sh"
    );
    assert_eq!(
        incluidas.len(),
        LINUX.len(),
        "un fichero incluido dos veces"
    );
}

#[test]
fn cada_regla_incluida_pasa_la_puerta() {
    // Se decide sobre el juego cargado y no con `LINUX.is_empty()`: la lista es
    // una constante y clippy (`const_is_empty`) la daria por siempre vacia.
    let juego = Juego::cargar(LINUX, &Topes::default());
    assert!(
        juego.rechazos().is_empty(),
        "reglas incluidas que el agente rechaza: {:#?}",
        juego.rechazos()
    );
    assert_eq!(juego.len(), LINUX.len());

    let presupuestos = leer_presupuestos(PRESUPUESTOS).expect("PRESUPUESTOS legible");
    if juego.is_empty() {
        assert!(
            presupuestos.is_empty(),
            "presupuestos de reglas que no viajan: {presupuestos:?}"
        );
        eprintln!("sin reglas incluidas: SIN CONTENIDO (el motor sigma no evalua nada)");
        return;
    }
    let atribucion = std::fs::read_to_string(dir().join("ATRIBUCION")).expect("ATRIBUCION");
    assert!(
        dir().join("LICENCIA-DRL-1.1.md").is_file(),
        "falta la licencia DRL 1.1"
    );

    let mut fallos = Vec::new();
    let mut ids = BTreeSet::new();
    for c in Categoria::TODAS {
        for r in juego.reglas(c) {
            ids.insert(r.id().to_string());
            match prueba_de(r, &presupuestos) {
                Ok(p) => {
                    if !r.casa(&registro(&p.dispara)) || r.casa(&registro(&p.no_dispara)) {
                        fallos.push(format!("{}: los eventos generados no se comportan", r.id()));
                    }
                }
                Err(e) => fallos.push(format!("{} [{}] {}", r.id(), e.codigo, e.detalle)),
            }
            if !atribucion.contains(r.id()) {
                fallos.push(format!("{}: no esta en ATRIBUCION", r.id()));
            }
        }
    }
    for id in presupuestos.keys() {
        if !ids.contains(id) {
            fallos.push(format!("{id}: presupuesto de una regla que no viaja"));
        }
    }
    assert!(
        fallos.is_empty(),
        "{} fallo(s):\n{}",
        fallos.len(),
        fallos.join("\n")
    );
    println!(
        "{} reglas: {} process_creation, {} file_event, {} network_connection",
        juego.len(),
        juego.reglas(Categoria::CreacionProceso).len(),
        juego.reglas(Categoria::EventoFichero).len(),
        juego.reglas(Categoria::ConexionRed).len()
    );
}
