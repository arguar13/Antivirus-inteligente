#![no_main]
//! Fuzzing del analizador de AegisQL.
//!
//! POR QUE ESTE OBJETIVO
//! --------------------
//! El texto de una consulta de caza entra por la consola del cliente, lo
//! analiza el plano de control y de ahi se difunde a decenas de miles de
//! endpoints. Un panico en el analizador es, por tanto, una denegacion de
//! servicio contra el plano de control con una sola cadena de texto: no hace
//! falta ni estar autenticado como administrador si en algun punto se analiza
//! antes de autorizar.
//!
//! La invariante es sencilla y absoluta: `analizar` devuelve `Ok` o `Err` para
//! CUALQUIER secuencia de bytes, y nunca entra en panico ni desborda la pila.
//!
//! Se ejercita ademas el planificador sobre las consultas que sí analizan,
//! porque reordenar un arbol es donde suelen aparecer los indices fuera de
//! rango y las recursiones sin fondo.

use libfuzzer_sys::fuzz_target;

use aegis_parser::plan::planificar;
use aegis_parser::sintaxis::analizar;

fuzz_target!(|datos: &[u8]| {
    // AegisQL es texto. La entrada que no es UTF-8 valido no llega nunca al
    // analizador en produccion —la rechaza antes la capa de transporte—, asi
    // que fuzzear con ella gastaria ciclos en un camino que no existe.
    let Ok(consulta) = std::str::from_utf8(datos) else {
        return;
    };

    match analizar(consulta) {
        Ok(c) => {
            // Toda consulta que sale del analizador tiene que cumplir sus
            // invariantes. Si alguna vez no las cumpliera, el endpoint
            // ejecutaria algo que nadie valido.
            assert!(c.limite > 0, "una consulta sin techo llegaria al endpoint");
            assert!(
                c.limite <= aegis_parser::sintaxis::LIMITE_MAXIMO,
                "el techo absoluto no se respeto"
            );
            assert!(
                aegis_parser::esquema::tabla(c.tabla).is_some(),
                "tabla fuera del esquema"
            );

            // El plan no puede perder ni inventar columnas.
            let plan = planificar(c);
            for col in &plan.columnas_necesarias {
                assert!(
                    aegis_parser::esquema::tabla(plan.consulta.tabla)
                        .and_then(|t| t.columna(col))
                        .is_some(),
                    "el plan pide una columna que no existe: {col}"
                );
            }
        }
        Err(e) => {
            // El error tambien es superficie: se dibuja en la consola del
            // cliente. Dibujarlo no puede entrar en panico por una posicion
            // fuera de rango ni por un limite en mitad de un caracter.
            let _ = e.dibujar(consulta);
        }
    }
});
