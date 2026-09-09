#![no_main]
//! Fuzz de los decodificadores protobuf del servicio de flota.
//!
//! Los mensajes llegan por la red desde un par que puede ser hostil. Cada
//! decodificador tiene que devolver `Err` ante bytes malformados, jamas entrar
//! en panico. Este objetivo dispara los cuatro decodificadores contra la misma
//! entrada arbitraria; si alguno pancia, libFuzzer lo captura.

use libfuzzer_sys::fuzz_target;

use aegis_fleet::proto::{
    AckEvento, AckLatido, Latido, ReporteEvento, RespuestaEnrolamiento, SolicitudEnrolamiento,
};

fuzz_target!(|data: &[u8]| {
    // Cada decodificacion que tenga exito se vuelve a codificar: el redondeo no
    // puede fallar ni divergir en tamano de forma absurda.
    if let Ok(m) = SolicitudEnrolamiento::decodificar(data) {
        let _ = m.codificar();
    }
    if let Ok(m) = RespuestaEnrolamiento::decodificar(data) {
        let _ = m.codificar();
    }
    let _ = Latido::decodificar(data);
    let _ = AckLatido::decodificar(data);
    let _ = ReporteEvento::decodificar(data);
    let _ = AckEvento::decodificar(data);
});
