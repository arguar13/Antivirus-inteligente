//! El punto de entrada: bytes inertes dentro, pseudo-C con su calidad fuera.
//!
//! # No ejecuta nada, y se ve de un vistazo
//!
//! Entra un `&[u8]`, sale una estructura de datos. En todo el camino no hay una
//! sola llamada que transfiera control a esos bytes, ni que los escriba, ni que
//! abra un proceso. La invariante 10 del megaprompt se cumple por lo que FALTA: no
//! hay variante de ejecucion en ningun tipo de este crate, y el crate declara
//! `#![forbid(unsafe_code)]`, que cierra la via del puntero a funcion.
//!
//! # Cota de tiempo heredada
//!
//! El desensamblado y la elevacion comparten el [`Plazo`] de `aegis-disasm`: un
//! analisis que se corta lo DICE en su [`Cobertura`], y aqui esa cobertura viaja
//! con el pseudo-C. Un resultado truncado en silencio se lee como «no habia mas», y
//! son dos frases distintas.

use std::collections::BTreeMap;

use aegis_disasm::instruccion::Arquitectura;
use aegis_disasm::plazo::{Cobertura, Plazo};
use aegis_disasm::{analizar, Entrada};

use crate::calidad::Calidad;
use crate::elevar::elevar_funcion;
use crate::emitir::{emitir, PseudoC};
use crate::ir::FuncionIr;
use crate::ir::ValId;
use crate::tipos::Tipo;

/// Todo lo que sale de decompilar un tramo de codigo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decompilacion {
    /// El pseudo-C de todas las funciones, en orden de entrada.
    pub pseudo_c: String,
    /// La calidad agregada del binario entero.
    pub calidad: Calidad,
    /// Que se llego a mirar (heredada del desensamblado).
    pub cobertura: Cobertura,
    /// La IR de cada funcion, para las fases que la consumen (la 102).
    pub funciones: Vec<FuncionIr>,
}

/// Decompila un tramo de codigo dentro de un plazo.
///
/// Solo x86-64 produce IR hoy; para otras arquitecturas el desensamblado y el
/// grafo se hacen igual, pero la elevacion queda vacia y la calidad lo dice (cero
/// instrucciones elevadas), que es honesto.
#[must_use]
pub fn decompilar(entrada: &Entrada, plazo: &mut Plazo) -> Decompilacion {
    let analisis = analizar(entrada, plazo);

    // Una funcion por cada raiz descubierta y por cada entrada pedida.
    let mut entradas_fn: Vec<u64> = analisis.cfg.raices.clone();
    entradas_fn.extend_from_slice(&analisis.cfg.entradas);
    entradas_fn.sort_unstable();
    entradas_fn.dedup();

    let mut funciones = Vec::new();
    let mut calidad = Calidad::default();
    for &ent in &entradas_fn {
        let elev = elevar_funcion(
            &analisis.cfg,
            entrada.arquitectura,
            entrada.codigo,
            entrada.base,
            ent,
        );
        calidad = calidad.mas(elev.calidad);
        funciones.push(elev.funcion);
    }
    funciones.sort_by_key(|f| f.entrada);

    // Emision. Sin mapa de tipos por ahora (la reconstruccion afina en incrementos
    // posteriores); las variables salen tipadas por su ancho, que es un hecho.
    let tipos: BTreeMap<ValId, Tipo> = BTreeMap::new();
    let mut texto = String::new();
    let mut calidad_emision = Calidad::default();
    for f in &funciones {
        let p: PseudoC = emitir(f, &tipos, Calidad::default());
        texto.push_str(&p.texto);
        texto.push('\n');
        calidad_emision = calidad_emision.mas(p.calidad);
    }

    // La calidad final combina lo de la elevacion (instrucciones) con lo de la
    // emision (gotos, variables, funciones).
    let total = Calidad {
        instrucciones_elevadas: calidad.instrucciones_elevadas,
        instrucciones_totales: calidad.instrucciones_totales,
        ..calidad_emision
    };

    Decompilacion {
        pseudo_c: texto,
        calidad: total,
        cobertura: analisis.informe.cobertura.clone(),
        funciones,
    }
}

/// Decompila directamente unos bytes de x86-64, con lo minimo.
///
/// Comodidad para las pruebas y para quien no tenga tabla de importaciones ni
/// lector de datos.
#[must_use]
pub fn decompilar_x86_64(
    codigo: &[u8],
    base: u64,
    entradas: &[u64],
    plazo: &mut Plazo,
) -> Decompilacion {
    let e = Entrada::minima(codigo, base, Arquitectura::X86_64, entradas);
    decompilar(&e, plazo)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn una_funcion_recta_se_decompila_y_es_determinista() {
        // mov eax, 5 ; ret  =>  B8 05 00 00 00 C3
        let bytes = &[0xB8, 0x05, 0x00, 0x00, 0x00, 0xC3];
        let a = decompilar_x86_64(bytes, 0x1000, &[0x1000], &mut Plazo::determinista());
        let b = decompilar_x86_64(bytes, 0x1000, &[0x1000], &mut Plazo::determinista());
        assert_eq!(
            a.pseudo_c, b.pseudo_c,
            "la decompilacion tiene que ser determinista"
        );
        assert!(a.pseudo_c.contains("return"), "{}", a.pseudo_c);
        assert!(a.calidad.instrucciones_elevadas >= 1);
    }

    #[test]
    fn no_ejecuta_ni_entra_en_panico_con_bytes_hostiles() {
        // Entrada hostil: el analisis termina y no ejecuta nada.
        let mut x = 0x1234_5678_9abc_def0u64;
        for _ in 0..16 {
            let mut bytes = Vec::with_capacity(4096);
            for _ in 0..4096 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                bytes.push(x as u8);
            }
            let d = decompilar_x86_64(&bytes, 0x1000, &[0x1000], &mut Plazo::determinista());
            // No se afirma nada del resultado: solo que termino y produjo texto.
            let _ = d.pseudo_c.len();
        }
    }
}
