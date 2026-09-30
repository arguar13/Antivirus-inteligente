//! La invariante del fuzzing del trabajador, y sus regresiones.
//!
//! 1. **Ningun parser entra en el trabajador sin objetivo de fuzzing.** Todo
//!    analizador de [`Analizador::todos`] tiene su objetivo
//!    `fuzz/fuzz_targets/trabajador_<nombre>.rs`, registrado en
//!    `fuzz/Cargo.toml`, y semillas en `fuzz/semillas/trabajador_<nombre>/`. Lo
//!    mismo el protocolo, que el agente decodifica de un proceso que hay que
//!    suponer comprometido.
//! 2. **Las semillas son tambien las regresiones.** Cuando el fuzzing encuentra
//!    un caso que rompe un parser, se arregla el parser y el caso se copia a
//!    `fuzz/semillas/<objetivo>/`: desde ese momento, esta prueba lo pasa por el
//!    analizador en cada `cargo test`, sin toolchain nightly.

use std::path::{Path, PathBuf};

use aegis_trabajador::protocolo::{self, Hola, Informe, Peticion};
use aegis_trabajador::{Analizador, Analizadores};

fn raiz() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn objetivos() -> Vec<String> {
    Analizador::todos()
        .iter()
        .map(|a| format!("trabajador_{}", a.nombre()))
        .chain(["trabajador_protocolo".to_string()])
        .collect()
}

fn semillas(objetivo: &str) -> Vec<(PathBuf, Vec<u8>)> {
    let dir = raiz().join("fuzz/semillas").join(objetivo);
    let mut v: Vec<(PathBuf, Vec<u8>)> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .flatten()
        .filter(|e| e.path().is_file())
        .map(|e| {
            let b = std::fs::read(e.path()).expect("semilla legible");
            (e.path(), b)
        })
        .collect();
    v.sort();
    v
}

#[test]
fn todo_parser_del_trabajador_tiene_objetivo_de_fuzzing_y_semillas() {
    let cargo = std::fs::read_to_string(raiz().join("fuzz/Cargo.toml")).expect("fuzz/Cargo.toml");
    for o in objetivos() {
        let fuente = raiz().join(format!("fuzz/fuzz_targets/{o}.rs"));
        assert!(
            fuente.is_file(),
            "falta el objetivo de fuzzing {}",
            fuente.display()
        );
        assert!(
            cargo.contains(&format!("name = \"{o}\"")),
            "{o} no esta registrado en fuzz/Cargo.toml"
        );
        assert!(
            !semillas(&o).is_empty(),
            "{o} no tiene semillas en fuzz/semillas/{o}/"
        );
    }
}

#[test]
fn las_semillas_y_regresiones_no_rompen_ningun_parser() {
    let mut a = Analizadores::default();
    for an in Analizador::todos() {
        for (ruta, bytes) in semillas(&format!("trabajador_{}", an.nombre())) {
            // Ok o Err, pero sin panico: es lo que exige el objetivo de fuzzing.
            if let Ok(i) = a.analizar(*an, &bytes) {
                let vuelta = Informe::decodificar(&i.codificar()).unwrap_or_else(|e| {
                    panic!("{}: el informe no va y vuelve: {e}", ruta.display())
                });
                assert_eq!(
                    vuelta.hallazgos.len(),
                    i.hallazgos.len().min(protocolo::MAX_HALLAZGOS)
                );
            }
        }
    }
    for (_, bytes) in semillas("trabajador_protocolo") {
        let _ = protocolo::leer(&mut bytes.as_slice());
        let _ = Informe::decodificar(&bytes);
        let _ = Hola::decodificar(&bytes);
        let _ = Peticion::decodificar(&bytes);
        let _ = protocolo::decodificar_fallo(&bytes);
    }
}
