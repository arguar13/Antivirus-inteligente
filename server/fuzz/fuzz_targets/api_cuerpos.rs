#![no_main]
//! Fuzzing de la API de administracion del plano de control (H-17, E6.13 de la
//! FASE 6.2 del MP-16).
//!
//! Cubre lo que la API hace con bytes de un cliente ANTES de tocar la base de
//! datos, con el MISMO codigo que los manejadores (`api::validar_cuerpo` usa
//! los tipos y los validadores de cada ruta, y `api::validar_consulta` los
//! extractores de consulta):
//!
//! - el cuerpo de cada ruta de escritura (JSON hostil, tipos cambiados,
//!   anidamiento y numeros extremos), con sus validadores: reglas, heuristicas,
//!   lotes ITDR, AegisQL, direcciones de cuarentena;
//! - la cadena de consulta de cada ruta de lectura;
//! - la sesion guardada en Redis (`SesionOperador::desde_json`) y el inquilino
//!   que se deriva de un CN.
//!
//! El primer byte elige la ruta entre las DECLARADAS por el enrutador: una ruta
//! nueva entra sola en el fuzzing. Invariante: ningun panico.

use libfuzzer_sys::fuzz_target;

use aegis_server::api;
use aegis_server::autorizacion::{inquilino_de_cn, SesionOperador};

fuzz_target!(|datos: &[u8]| {
    let Some((&selector, resto)) = datos.split_first() else {
        return;
    };
    let rutas = api::rutas_declaradas();
    let r = rutas[selector as usize % rutas.len()];
    if r.metodo == "GET" {
        if let Ok(consulta) = std::str::from_utf8(resto) {
            let _ = api::validar_consulta(r.patron, consulta);
        }
    } else {
        let _ = api::validar_cuerpo(r.metodo, r.patron, resto);
    }

    if let Ok(texto) = std::str::from_utf8(resto) {
        if let Some(s) = SesionOperador::desde_json(texto) {
            assert_eq!(SesionOperador::desde_json(&s.json()), Some(s));
        }
        assert!(inquilino_de_cn(texto).starts_with("flota-"));
    }
});
