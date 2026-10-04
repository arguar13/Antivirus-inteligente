#![no_main]
//! Fuzzing del analizador «emulacion» del trabajador confinado (FASE 1 del MP-16).
//!
//! Es exactamente la funcion que ejecuta el trabajador sobre los bytes que
//! recibe: [`aegis_trabajador::Analizadores::analizar`]. La invariante: para
//! CUALQUIER entrada devuelve `Ok` o `Err`, sin panico, sin colgarse y sin
//! agotar la memoria (libFuzzer corta con `-rss_limit_mb` y `-timeout`).
//! Un fallo aqui es un fichero que, confinado, mata al trabajador: no apaga la
//! proteccion, pero ciega al motor estatico. Cada uno encontrado se arregla en
//! el parser y se convierte en prueba.

use libfuzzer_sys::fuzz_target;

use aegis_trabajador::{Analizador, Analizadores};

/// Una sola instancia por proceso, como en el trabajador: el modelo se carga
/// una vez y no en cada entrada (a 2 entradas por segundo, el fuzzing no
/// llegaba a ningun camino profundo).
///
/// Se carga en `init`, que libFuzzer ejecuta UNA vez antes de la primera
/// entrada y fuera de su plazo por entrada (`-timeout`). Cargada perezosamente
/// en la primera entrada, la carga del modelo (con su puerta: hash del ONNX y
/// sondas) contaba como si la entrada vacia tardase mas de 10 s.
static ANALIZADORES: std::sync::Mutex<Option<Analizadores>> = std::sync::Mutex::new(None);

fuzz_target!(init: {
    let mut a = Analizadores::default();
    a.precargar();
    *ANALIZADORES.lock().unwrap_or_else(|e| e.into_inner()) = Some(a);
}, |datos: &[u8]| {
    let mut guarda = ANALIZADORES.lock().unwrap_or_else(|e| e.into_inner());
    let a = guarda
        .as_mut()
        .expect("init carga los analizadores antes de la primera entrada");
    if let Ok(informe) = a.analizar(Analizador::Emulacion, datos) {
        // El protocolo tiene que poder llevar lo que el analizador produce.
        let ida = informe.codificar();
        let vuelta = aegis_trabajador::protocolo::Informe::decodificar(&ida)
            .expect("un informe del propio analizador siempre se decodifica");
        assert_eq!(vuelta.hallazgos.len(), informe.hallazgos.len().min(64));
    }
});
