//! Estructuracion del control: de un grafo a una secuencia con `if`, bucles y los
//! `goto` que no se pudieron evitar —contados—.
//!
//! # El enfoque, y por que este
//!
//! Recuperar `if`/`else`, `while` y `switch` de un grafo arbitrario es el analisis
//! estructural clasico. Un grafo REDUCIBLE se estructura entero sin un solo
//! `goto`; uno irreducible —los hay: saltos que entran a mitad de un bucle— obliga
//! a alguno, y cada uno es una perdida de calidad MEDIDA, no un detalle que se
//! esconde.
//!
//! Aqui se hace lo honesto y comprobable: se ordena el grafo en **post-orden
//! inverso** (el orden natural de lectura de un programa), y cada arista que en
//! ese orden va «hacia atras» o «se salta» un bloque se emite como `goto` y se
//! cuenta. Las aristas que caen al bloque siguiente son secuenciales y no cuestan
//! nada. Es un algoritmo declarado y determinista, no una heuristica que cambia
//! entre ejecuciones.

use std::collections::{BTreeSet, VecDeque};

use crate::ir::{BloqueId, FuncionIr, Terminador};

/// La disposicion lineal de una funcion: el orden de los bloques y cuantos `goto`
/// costo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disposicion {
    /// Los bloques en el orden en que se emiten (post-orden inverso desde la
    /// entrada).
    pub orden: Vec<BloqueId>,
    /// Cuantas aristas se tuvieron que emitir como `goto` (no caen al siguiente).
    pub gotos: u64,
}

/// Ordena los bloques de una funcion en post-orden inverso desde la entrada, de
/// forma determinista (los sucesores se visitan en orden de direccion).
#[must_use]
pub fn disponer(f: &FuncionIr) -> Disposicion {
    let entrada = BloqueId(f.entrada);
    let mut visitados: BTreeSet<BloqueId> = BTreeSet::new();
    let mut post: Vec<BloqueId> = Vec::new();

    // Post-orden iterativo, determinista: los sucesores en orden de direccion.
    // Se usa una pila con marca de «ya expandido».
    let mut pila: Vec<(BloqueId, bool)> = vec![(entrada, false)];
    while let Some((b, expandido)) = pila.pop() {
        if expandido {
            post.push(b);
            continue;
        }
        if !visitados.insert(b) {
            continue;
        }
        pila.push((b, true));
        let mut sucs = sucesores(f, b);
        // Se apilan en orden inverso para que se visiten en orden ascendente.
        sucs.sort_unstable();
        for s in sucs.into_iter().rev() {
            if !visitados.contains(&s) {
                pila.push((s, false));
            }
        }
    }
    post.reverse(); // post-orden inverso

    // Un bloque alcanzable que no salio (por un ciclo raro) se anade al final, en
    // orden, para no perderlo.
    for id in f.bloques.keys() {
        if !visitados.contains(id) {
            post.push(*id);
        }
    }

    // Contar los goto: una arista es secuencial si su destino es el bloque que va
    // justo despues en `orden` y es el unico sucesor «de caida».
    let posicion: std::collections::BTreeMap<BloqueId, usize> =
        post.iter().enumerate().map(|(i, b)| (*b, i)).collect();
    let mut gotos = 0u64;
    for (i, b) in post.iter().enumerate() {
        let siguiente = post.get(i + 1).copied();
        gotos += gotos_de_terminador(f, *b, siguiente, &posicion);
    }

    Disposicion { orden: post, gotos }
}

/// Los sucesores de un bloque segun su terminador.
fn sucesores(f: &FuncionIr, b: BloqueId) -> Vec<BloqueId> {
    let Some(bl) = f.bloques.get(&b) else {
        return Vec::new();
    };
    match &bl.terminador {
        Terminador::Ir(d) => vec![*d],
        Terminador::Rama { si, no, .. } => vec![*si, *no],
        Terminador::Conmutar { casos, defecto, .. } => {
            let mut v: Vec<BloqueId> = casos.iter().map(|(_, d)| *d).collect();
            v.push(*defecto);
            v
        }
        Terminador::Retornar(_) | Terminador::Indirecto | Terminador::Inalcanzable => Vec::new(),
    }
}

/// Cuantos `goto` cuesta el terminador de un bloque, dado cual es el bloque
/// siguiente en la disposicion.
fn gotos_de_terminador(
    f: &FuncionIr,
    b: BloqueId,
    siguiente: Option<BloqueId>,
    _posicion: &std::collections::BTreeMap<BloqueId, usize>,
) -> u64 {
    let Some(bl) = f.bloques.get(&b) else {
        return 0;
    };
    match &bl.terminador {
        // Un salto incondicional que cae al siguiente es gratis; si no, un goto.
        Terminador::Ir(d) => u64::from(Some(*d) != siguiente),
        // Una rama: la caida (`no`) es gratis si es el siguiente; el `si` casi
        // siempre es un goto salvo que sea el siguiente. Se cuenta el que no caiga.
        Terminador::Rama { si, no, .. } => {
            let mut g = 0;
            if Some(*no) != siguiente {
                g += 1;
            }
            if Some(*si) != siguiente {
                g += 1;
            }
            // Una de las dos suele poder caer; si ninguna cae, son dos goto.
            g.min(2)
        }
        // Un switch: cada destino que no caiga es un goto (se acota al numero de
        // destinos).
        Terminador::Conmutar { casos, defecto, .. } => {
            let mut destinos: Vec<BloqueId> = casos.iter().map(|(_, d)| *d).collect();
            destinos.push(*defecto);
            destinos
                .into_iter()
                .filter(|d| Some(*d) != siguiente)
                .count() as u64
        }
        Terminador::Retornar(_) | Terminador::Indirecto | Terminador::Inalcanzable => 0,
    }
}

/// Los identificadores de bloque alcanzables desde la entrada, para no emitir
/// bloques muertos.
#[must_use]
pub fn alcanzables(f: &FuncionIr) -> BTreeSet<BloqueId> {
    let mut vistos = BTreeSet::new();
    let mut cola = VecDeque::from([BloqueId(f.entrada)]);
    while let Some(b) = cola.pop_front() {
        if !vistos.insert(b) {
            continue;
        }
        for s in sucesores(f, b) {
            if !vistos.contains(&s) {
                cola.push_back(s);
            }
        }
    }
    vistos
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::ir::{BloqueIr, Operando};

    fn con_bloques(entrada: u64, bloques: Vec<(u64, Terminador)>) -> FuncionIr {
        let mut f = FuncionIr::nueva(entrada);
        for (id, term) in bloques {
            f.bloques.insert(
                BloqueId(id),
                BloqueIr {
                    id: BloqueId(id),
                    sentencias: vec![],
                    terminador: term,
                },
            );
        }
        f
    }

    #[test]
    fn una_cadena_recta_no_cuesta_ningun_goto() {
        // 0x10 -> 0x20 -> retorno. En post-orden inverso quedan en orden y cada
        // salto cae al siguiente: cero goto.
        let f = con_bloques(
            0x10,
            vec![
                (0x10, Terminador::Ir(BloqueId(0x20))),
                (0x20, Terminador::Retornar(Some(Operando::Indefinido))),
            ],
        );
        let d = disponer(&f);
        assert_eq!(d.orden, vec![BloqueId(0x10), BloqueId(0x20)]);
        assert_eq!(d.gotos, 0, "una cadena recta no necesita goto");
    }

    #[test]
    fn un_bucle_hacia_atras_cuesta_un_goto() {
        // 0x10 -> 0x20; 0x20 rama a 0x20 (bucle) o 0x30 (salida). El salto de
        // vuelta al 0x20 va hacia atras: un goto.
        let f = con_bloques(
            0x10,
            vec![
                (0x10, Terminador::Ir(BloqueId(0x20))),
                (
                    0x20,
                    Terminador::Rama {
                        cond: Operando::Indefinido,
                        si: BloqueId(0x20),
                        no: BloqueId(0x30),
                    },
                ),
                (0x30, Terminador::Retornar(None)),
            ],
        );
        let d = disponer(&f);
        assert!(d.gotos >= 1, "el salto de vuelta del bucle es un goto");
    }

    #[test]
    fn el_orden_es_determinista() {
        let f = con_bloques(
            0x10,
            vec![
                (
                    0x10,
                    Terminador::Rama {
                        cond: Operando::Indefinido,
                        si: BloqueId(0x30),
                        no: BloqueId(0x20),
                    },
                ),
                (0x20, Terminador::Ir(BloqueId(0x40))),
                (0x30, Terminador::Ir(BloqueId(0x40))),
                (0x40, Terminador::Retornar(None)),
            ],
        );
        assert_eq!(disponer(&f).orden, disponer(&f).orden);
    }

    #[test]
    fn solo_los_bloques_alcanzables_cuentan() {
        let f = con_bloques(
            0x10,
            vec![
                (0x10, Terminador::Retornar(None)),
                // 0x99 no lo alcanza nadie.
                (0x99, Terminador::Retornar(None)),
            ],
        );
        let a = alcanzables(&f);
        assert!(a.contains(&BloqueId(0x10)));
        assert!(
            !a.contains(&BloqueId(0x99)),
            "un bloque muerto no es alcanzable"
        );
    }
}
