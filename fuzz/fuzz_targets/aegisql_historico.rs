#![no_main]
//! Fuzzing del analizador de AegisQL HISTORICO (H-17, FASE 6.2 del MP-16).
//!
//! `aegisql` cubre el dialecto del endpoint; este cubre el del almacen del
//! plano de control (`historico::analizar`), que acepta ventanas, agrupaciones
//! y subconsultas: mas gramatica, mas sitios donde un techo puede escaparse.
//!
//! Invariantes: nunca panico ni desborde de pila, y toda consulta aceptada
//! respeta sus techos (filas, subconsultas, grupos, cubo y ventana).

use libfuzzer_sys::fuzz_target;

use aegis_parser::historico::{self, Ventana};

fuzz_target!(|datos: &[u8]| {
    let Ok(consulta) = std::str::from_utf8(datos) else {
        return;
    };
    match historico::analizar(consulta) {
        Ok(c) => {
            assert!(c.limite > 0, "una consulta sin techo");
            let subconsultas = c.filtro.as_ref().map_or(0, |f| f.subconsultas().len());
            assert!(subconsultas <= historico::SUBCONSULTAS_MAXIMAS);
            assert!(c.agrupar.len() <= historico::GRUPOS_MAXIMOS);
            if let Some(cada) = c.cada_ns {
                assert!(cada >= historico::CUBO_MINIMO_NS);
            }
            if let Some(Ventana::Ultimos { ns }) = c.ventana {
                assert!(ns <= historico::VENTANA_MAXIMA_NS);
            }
            // La ventana se resuelve en el almacen con el reloj: ningun
            // instante (ni el cero ni el maximo) puede desbordar.
            if let Some(v) = &c.ventana {
                let _ = v.intervalo(0);
                let _ = v.intervalo(u64::MAX);
            }
        }
        Err(e) => {
            let _ = e.dibujar(consulta);
        }
    }
});
