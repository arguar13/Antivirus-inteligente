//! Aho-Corasick: casar muchos literales a la vez, en una sola pasada.
//!
//! # Por que hace falta ademas del motor de regex
//!
//! Un conjunto de reglas YARA tiene miles de cadenas literales. Probar cada una
//! por separado es O(reglas x entrada); Aho-Corasick las casa TODAS en O(entrada)
//! con un solo automata. Es el prefiltro: primero se ve que literales aparecen, y
//! solo las reglas cuyas cadenas aparecen se evaluan del todo. Sin el, el motor no
//! escala al corpus mundial.
//!
//! # Cota y determinismo
//!
//! El automata se construye una vez; escanear es una pasada lineal que no reserva
//! nada por byte. El conjunto de coincidencias no depende del orden en que se
//! anadieron los patrones: se devuelve ordenado. Como el resto del motor,
//! `#![forbid(unsafe_code)]` en el crate: come entrada hostil.

use std::collections::{BTreeMap, VecDeque};

/// Un automata de Aho-Corasick sobre bytes.
#[derive(Debug, Clone)]
pub struct Automata {
    /// Transiciones goto por nodo: `[nodo]` es un mapa byte -> nodo.
    goto: Vec<BTreeMap<u8, usize>>,
    /// Enlace de fallo por nodo.
    fallo: Vec<usize>,
    /// Patrones que terminan en cada nodo (indices en el orden de insercion).
    salida: Vec<Vec<usize>>,
    /// Longitud de cada patron, para reconstruir el desplazamiento de inicio.
    largos: Vec<usize>,
}

/// Una coincidencia: que patron y donde empieza.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Coincidencia {
    /// El desplazamiento de inicio en la entrada.
    pub inicio: usize,
    /// El indice del patron (en el orden en que se dieron).
    pub patron: usize,
}

/// Constructor del automata.
#[derive(Debug, Default)]
pub struct Constructor {
    patrones: Vec<Vec<u8>>,
}

impl Constructor {
    /// Un constructor vacio.
    #[must_use]
    pub fn nuevo() -> Constructor {
        Constructor::default()
    }

    /// Anade un patron literal. Devuelve su indice.
    pub fn anadir(&mut self, patron: &[u8]) -> usize {
        let i = self.patrones.len();
        self.patrones.push(patron.to_vec());
        i
    }

    /// Construye el automata (goto, fallo y salida) con el algoritmo clasico.
    #[must_use]
    pub fn construir(self) -> Automata {
        let mut goto: Vec<BTreeMap<u8, usize>> = vec![BTreeMap::new()];
        let mut salida: Vec<Vec<usize>> = vec![Vec::new()];
        let mut largos: Vec<usize> = Vec::with_capacity(self.patrones.len());

        // Arbol de prefijos (goto).
        for (idx, p) in self.patrones.iter().enumerate() {
            largos.push(p.len());
            let mut nodo = 0usize;
            for &b in p {
                if let Some(&sig) = goto[nodo].get(&b) {
                    nodo = sig;
                } else {
                    let nuevo = goto.len();
                    goto.push(BTreeMap::new());
                    salida.push(Vec::new());
                    goto[nodo].insert(b, nuevo);
                    nodo = nuevo;
                }
            }
            salida[nodo].push(idx);
        }

        // Enlaces de fallo por anchura (BFS), y propagacion de salidas.
        let mut fallo = vec![0usize; goto.len()];
        let mut cola = VecDeque::new();
        for (&_b, &hijo) in &goto[0] {
            fallo[hijo] = 0;
            cola.push_back(hijo);
        }
        while let Some(nodo) = cola.pop_front() {
            // Se recogen los hijos primero para no tomar prestado goto dos veces.
            let hijos: Vec<(u8, usize)> = goto[nodo].iter().map(|(&b, &h)| (b, h)).collect();
            for (b, hijo) in hijos {
                cola.push_back(hijo);
                // Buscar el enlace de fallo del hijo.
                let mut f = fallo[nodo];
                while f != 0 && !goto[f].contains_key(&b) {
                    f = fallo[f];
                }
                let destino = goto[f].get(&b).copied().unwrap_or(0);
                fallo[hijo] = if destino == hijo { 0 } else { destino };
                // Propagar las salidas del enlace de fallo.
                let extra = salida[fallo[hijo]].clone();
                salida[hijo].extend(extra);
            }
        }

        Automata {
            goto,
            fallo,
            salida,
            largos,
        }
    }
}

impl Automata {
    /// Escanea la entrada y devuelve todas las coincidencias, ordenadas por
    /// (inicio, patron). Una sola pasada, sin retroceso.
    #[must_use]
    pub fn escanear(&self, entrada: &[u8]) -> Vec<Coincidencia> {
        let mut nodo = 0usize;
        let mut res = Vec::new();
        for (pos, &b) in entrada.iter().enumerate() {
            // Seguir enlaces de fallo hasta poder avanzar.
            while nodo != 0 && !self.goto[nodo].contains_key(&b) {
                nodo = self.fallo[nodo];
            }
            nodo = self.goto[nodo].get(&b).copied().unwrap_or(0);
            for &pat in &self.salida[nodo] {
                let largo = self.largos[pat];
                let inicio = pos + 1 - largo;
                res.push(Coincidencia {
                    inicio,
                    patron: pat,
                });
            }
        }
        res.sort_unstable();
        res
    }

    /// Numero de nodos, que es la cota de memoria del automata.
    #[must_use]
    pub fn nodos(&self) -> usize {
        self.goto.len()
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn construir(pats: &[&[u8]]) -> (Automata, Vec<usize>) {
        let mut c = Constructor::nuevo();
        let idx: Vec<usize> = pats.iter().map(|p| c.anadir(p)).collect();
        (c.construir(), idx)
    }

    #[test]
    fn casa_varios_literales_en_una_pasada() {
        let (a, _) = construir(&[b"he", b"she", b"his", b"hers"]);
        let m = a.escanear(b"ushers");
        // "she" en 1, "he" en 2, "hers" en 2.
        assert!(
            m.contains(&Coincidencia {
                inicio: 1,
                patron: 1
            }),
            "she"
        );
        assert!(
            m.contains(&Coincidencia {
                inicio: 2,
                patron: 0
            }),
            "he"
        );
        assert!(
            m.contains(&Coincidencia {
                inicio: 2,
                patron: 3
            }),
            "hers"
        );
    }

    #[test]
    fn el_solape_de_sufijos_se_detecta_por_el_enlace_de_fallo() {
        // "he" es sufijo de "she": al casar "she" tambien tiene que salir "he".
        let (a, _) = construir(&[b"he", b"she"]);
        let m = a.escanear(b"she");
        assert!(m.iter().any(|c| c.patron == 1 && c.inicio == 0), "she");
        assert!(
            m.iter().any(|c| c.patron == 0 && c.inicio == 1),
            "he por fallo"
        );
    }

    #[test]
    fn sin_coincidencias_devuelve_vacio() {
        let (a, _) = construir(&[b"abc"]);
        assert!(a.escanear(b"xyz").is_empty());
    }

    #[test]
    fn el_resultado_es_determinista_y_ordenado() {
        let (a, _) = construir(&[b"a", b"ab", b"b"]);
        let m1 = a.escanear(b"ab");
        let m2 = a.escanear(b"ab");
        assert_eq!(m1, m2);
        // Ordenado por (inicio, patron).
        let mut ordenado = m1.clone();
        ordenado.sort_unstable();
        assert_eq!(m1, ordenado);
    }

    #[test]
    fn la_entrada_grande_no_reserva_por_byte() {
        // No es una prueba de rendimiento; es que termina en una pasada.
        let (a, _) = construir(&[b"aegis"]);
        let entrada = vec![b'a'; 1_000_000];
        assert!(a.escanear(&entrada).is_empty());
    }
}
