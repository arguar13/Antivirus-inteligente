#![no_main]
//! Fuzzing del protocolo del trabajador confinado (FASE 1 del MP-16).
//!
//! El AGENTE decodifica lo que le manda un proceso que acaba de leer bytes de un
//! atacante: hay que suponerlo comprometido. La invariante: ninguna secuencia de
//! bytes hace entrar en panico al decodificador ni le hace reservar mas de lo
//! que el protocolo permite; y un informe que se decodifica solo lleva firmas
//! del plano estatico.

use libfuzzer_sys::fuzz_target;

use aegis_entidad::Motor;
use aegis_trabajador::protocolo::{self, Hola, Informe, Peticion};

fuzz_target!(|datos: &[u8]| {
    let _ = protocolo::leer(&mut &datos[..]);
    if let Ok(i) = Informe::decodificar(datos) {
        assert!(i
            .hallazgos
            .iter()
            .all(|h| matches!(h.firma, Motor::Estatico | Motor::Aprendizaje)));
        assert!(i.hallazgos.len() <= protocolo::MAX_HALLAZGOS);
    }
    let _ = Hola::decodificar(datos);
    let _ = Peticion::decodificar(datos);
    let _ = protocolo::decodificar_fallo(datos);
});
