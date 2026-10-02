#![no_main]
//! Fuzzing del COSTE de AegisQL (H-25, FASE 6.2 del MP-16).
//!
//! El plano de control decide si una caza sale o no por su coste
//! (`Plan::coste_maximo` contra el tope del rol). Si el coste del plan pudiera
//! quedarse por debajo del de alguna columna que la consulta usa, una caza cara
//! pasaria por barata. Y el `LIKE` se evalua contra cada proceso de cada
//! endpoint: tiene que acabar en tiempo acotado con cualquier patron.
//!
//! Entrada: `consulta \0 texto \0 patron`. Las dos ultimas partes alimentan el
//! `LIKE`, con techo de longitud (el texto real es una linea de comandos).

use libfuzzer_sys::fuzz_target;

use aegis_parser::esquema;
use aegis_parser::plan::planificar;
use aegis_parser::sintaxis::analizar;
use aegis_parser::valor::Valor;

fuzz_target!(|datos: &[u8]| {
    let Ok(todo) = std::str::from_utf8(datos) else {
        return;
    };
    let mut partes = todo.splitn(3, '\0');
    let consulta = partes.next().unwrap_or("");
    let texto = partes.next().unwrap_or("");
    let patron = partes.next().unwrap_or("");

    if let Ok(c) = analizar(consulta) {
        let tabla = c.tabla;
        let plan = planificar(c);
        for col in &plan.columnas_necesarias {
            let coste = esquema::tabla(tabla)
                .and_then(|t| t.columna(col))
                .map(|c| c.coste)
                .expect("el plan solo pide columnas del esquema");
            assert!(
                coste <= plan.coste_maximo,
                "el coste del plan no cubre la columna {col}"
            );
        }
    }

    if texto.len() <= 4096 && patron.len() <= 4096 {
        let _ = Valor::Texto(texto.to_string()).casa_patron(patron);
    }
});
