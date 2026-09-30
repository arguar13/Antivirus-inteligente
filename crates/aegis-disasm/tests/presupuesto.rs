//! El presupuesto del analisis cubre TODAS sus fases, y ninguna es cuadratica.
//!
//! Regresion de la FASE 1 del MP-16. El plazo solo lo miraba la construccion del
//! grafo de flujo; el grafo de llamadas, la propagacion de constantes y las
//! reglas corrian despues sin cota, y una de las señales recorria todos los
//! bloques por cada arista. Sobre `python3` —un ejecutable corriente— eran 21 s y
//! 600 MiB con un plazo declarado de 500 ms. Lo encontro el trabajador
//! confinado, que lo mato por pasar de su techo de memoria.

use std::time::{Duration, Instant};

use aegis_disasm::{analizar, Arquitectura, Entrada, Plazo};

const BASE: u64 = 0x40_0000;
const ANCHO: usize = 16;

/// `n` funciones de 16 bytes: cada una llama FUERA del codigo (a memoria que el
/// binario habria preparado) y a la siguiente, y vuelve.
fn codigo(n: usize) -> Vec<u8> {
    let fin = BASE + (n * ANCHO) as u64;
    let mut v = Vec::with_capacity(n * ANCHO);
    for k in 0..n {
        let aqui = BASE + (k * ANCHO) as u64;
        let fuera = fin + 0x10_0000 + (k as u64) * 0x40;
        let siguiente = if k + 1 < n { aqui + ANCHO as u64 } else { BASE };
        for (desde, a) in [(aqui, fuera), (aqui + 5, siguiente)] {
            let rel = (a as i64 - (desde as i64 + 5)) as i32;
            v.push(0xE8);
            v.extend_from_slice(&rel.to_le_bytes());
        }
        v.push(0xC3);
        while v.len() % ANCHO != 0 {
            v.push(0x90);
        }
    }
    v
}

#[test]
fn el_plazo_cubre_todas_las_fases_y_el_corte_se_declara() {
    let c = codigo(4000);
    let entradas = [BASE];
    let e = Entrada::minima(&c, BASE, Arquitectura::X86_64, &entradas);

    // Sin cota: cuanto trabajo cuesta el analisis entero.
    let mut libre = Plazo::sin_cota();
    let completo = analizar(&e, &mut libre);
    assert!(completo.informe.cobertura.completa());
    let total = libre.gastadas();

    // Con un tope que el grafo de flujo cumple pero las fases de despues no: la
    // version vieja solo cobraba el grafo de flujo y no se cortaba nunca.
    let instrucciones = completo.informe.cobertura.instrucciones;
    assert!(
        total > instrucciones * 2,
        "las fases posteriores cobran su trabajo"
    );
    let tope = instrucciones + (total - instrucciones) / 3;
    let mut plazo = Plazo::nuevo(Duration::MAX, tope);
    let cortado = analizar(&e, &mut plazo);
    assert!(
        !cortado.informe.cobertura.completa(),
        "agotar el tope en las fases de despues tiene que declararse"
    );
    assert!(cortado.informe.cobertura.cortado_por_tope);
    // Ninguna fase siguio trabajando despues de agotarlo: el sobrepaso es como
    // mucho un cobro, acotado por el tamaño de lo analizado.
    assert!(
        plazo.gastadas() <= tope + instrucciones * 4,
        "gastadas {} con tope {tope}",
        plazo.gastadas()
    );
}

#[test]
fn saltar_fuera_del_codigo_se_evalua_en_tiempo_lineal() {
    // 20.000 funciones, 20.000 llamadas a fuera del codigo. La version vieja
    // hacia aristas x bloques comparaciones —del orden de 10^9 aqui—, minutos
    // en una compilacion de depuracion. La lineal, milisegundos. El margen es de
    // ordenes de magnitud: no depende de lo cargada que este la maquina.
    let c = codigo(20_000);
    let entradas = [BASE];
    let e = Entrada::minima(&c, BASE, Arquitectura::X86_64, &entradas);
    let inicio = Instant::now();
    let a = analizar(&e, &mut Plazo::sin_cota());
    let tardo = inicio.elapsed();
    assert!(a.informe.cobertura.completa());
    assert!(
        tardo < Duration::from_secs(20),
        "el analisis de 20.000 funciones tardo {tardo:?}: alguna fase es cuadratica"
    );
}
