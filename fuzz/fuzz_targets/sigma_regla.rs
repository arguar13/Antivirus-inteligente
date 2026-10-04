#![no_main]
//! Fuzzing del compilador y del evaluador Sigma (FASE 4 del MP-16).
//!
//! La entrada se parte en dos por el primer byte 0: la primera mitad es una
//! regla (lo que llegaria de un feed o del canal de contenido), la segunda un
//! valor de campo (lo que elige quien nombra un proceso o un fichero). La
//! invariante: compilar, atar a la telemetria, generar los eventos de prueba y
//! evaluar NUNCA entran en panico ni se cuelgan, para cualquier entrada.

use libfuzzer_sys::fuzz_target;

use aegis_sigma::compacta::{Campo, Categoria, Juego, Registro};
use aegis_sigma::generador;
use aegis_sigma::regla::{analizar_condicion, Topes};

fuzz_target!(|datos: &[u8]| {
    let corte = datos.iter().position(|b| *b == 0).unwrap_or(datos.len());
    let (regla, resto) = datos.split_at(corte);
    let valor = resto.get(1..).unwrap_or_default();
    let Ok(fuente) = std::str::from_utf8(regla) else {
        return;
    };
    let topes = Topes::default();
    let _ = analizar_condicion(fuente, &topes);
    let juego = Juego::cargar(&[("fuzz.yml", fuente)], &topes);
    let mut r = Registro::nuevo();
    for campo in Campo::TODOS {
        let _ = r.poner(campo, valor);
    }
    for c in Categoria::TODAS {
        for regla in juego.reglas(c) {
            let _ = regla.casa(&r);
            let _ = regla.casa(&Registro::nuevo());
            if let Some(si) = generador::dispara(regla) {
                assert!(regla.casa(&generador::registro(&si)));
                if let Some(no) = generador::no_dispara(regla, &si) {
                    assert!(!regla.casa(&generador::registro(&no)));
                }
            }
        }
    }
});
