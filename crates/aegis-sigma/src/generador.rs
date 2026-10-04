//! Los eventos de prueba de una regla, generados DESDE la regla.
//!
//! Cada regla del contenido tiene que traer un evento que la dispara y uno que
//! no (FASE 4 del MP-16). Escribirlos a mano tiene dos problemas: se
//! desincronizan de la regla en cuanto alguien la endurece, y obligan a
//! redactar ejemplos de ataque. Aqui salen de la propia regla:
//!
//! - **dispara**: el caso positivo minimo que la condicion acepta. Se buscan
//!   las asignaciones de verdad de las selecciones que satisfacen la condicion,
//!   de menos a mas selecciones ciertas, y para cada una se construye un valor
//!   por campo con los testigos de sus patrones ([`crate::patron::Patron::testigo`]).
//!   Solo vale si la regla, evaluada con el evaluador de verdad, dispara.
//! - **no dispara**: el mismo evento con UN campo obligatorio alterado (primero
//!   cambiado, despues quitado). Si ningun campo es obligatorio —la regla
//!   dispara aunque se le quite cualquiera—, no hay evento que no dispare y la
//!   regla se rechaza: dispararia sobre casi todo.

use std::collections::BTreeMap;

use crate::compacta::{Campo, Nodo, Registro, ReglaCompacta};
use crate::regla::{Comparacion, Condicion};

/// Un evento de prueba: valor por campo.
pub type Evento = BTreeMap<Campo, Vec<u8>>;

/// Asignaciones de verdad que se prueban como mucho.
const MAX_ASIGNACIONES: usize = 1 << 14;
/// Variantes por asignacion (que alternativa y que valor de cada lista).
const VARIANTES: usize = 4;
/// Valor con el que se altera un campo obligatorio.
pub const ALTERADO: &[u8] = b"aegis-alterado";

/// El evento como [`Registro`].
#[must_use]
pub fn registro(ev: &Evento) -> Registro<'_> {
    let mut r = Registro::nuevo();
    for (campo, v) in ev {
        let _ = r.poner(*campo, v);
    }
    r
}

/// Si la condicion vale con esta asignacion de verdad de las selecciones.
fn vale(n: &Nodo, mascara: u64) -> bool {
    let sel = |i: &usize| mascara & (1u64 << *i) != 0;
    match n {
        Nodo::Sel(i) => sel(i),
        Nodo::Todos(v) => v.iter().all(|x| vale(x, mascara)),
        Nodo::Alguno(v) => v.iter().any(|x| vale(x, mascara)),
        Nodo::No(x) => !vale(x, mascara),
        Nodo::AlMenos(k, de) => de.iter().filter(|i| sel(i)).count() >= *k,
    }
}

/// Lo que piden las condiciones de un campo.
#[derive(Default)]
struct Partes {
    exacto: Option<Vec<u8>>,
    prefijos: Vec<Vec<u8>>,
    medios: Vec<Vec<u8>>,
    sufijos: Vec<Vec<u8>>,
    numero: Option<i64>,
    vacio: bool,
}

impl Partes {
    fn anadir(&mut self, c: &Condicion, variante: usize) {
        match c.comparacion {
            Comparacion::Vacio => self.vacio = true,
            Comparacion::Mayor
            | Comparacion::MayorIgual
            | Comparacion::Menor
            | Comparacion::MenorIgual => {
                if let Some(n) = elegir(c.numeros(), variante) {
                    self.numero = Some(match c.comparacion {
                        Comparacion::Mayor => n.saturating_add(1),
                        Comparacion::Menor => n.saturating_sub(1),
                        _ => *n,
                    });
                }
            }
            _ => {
                let patrones: Vec<_> = if c.todos {
                    c.patrones().iter().collect()
                } else {
                    elegir(c.patrones(), variante).into_iter().collect()
                };
                for p in patrones {
                    let t = p.testigo();
                    match (p.inicio(), p.fin()) {
                        (true, true) => self.exacto = Some(t),
                        (true, false) => self.prefijos.push(t),
                        (false, true) => self.sufijos.push(t),
                        (false, false) => self.medios.push(t),
                    }
                }
            }
        }
    }

    fn valor(self) -> Option<Vec<u8>> {
        if let Some(e) = self.exacto {
            return Some(e);
        }
        if let Some(n) = self.numero {
            return Some(n.to_string().into_bytes());
        }
        let v: Vec<u8> = self
            .prefijos
            .into_iter()
            .chain(self.medios)
            .chain(self.sufijos)
            .flatten()
            .collect();
        if v.is_empty() {
            // Solo «vacio»: el campo no se pone. Sin ninguna exigencia: un
            // valor cualquiera.
            return if self.vacio {
                None
            } else {
                Some(b"x".to_vec())
            };
        }
        Some(v)
    }
}

fn elegir<T>(v: &[T], variante: usize) -> Option<&T> {
    if v.is_empty() {
        None
    } else {
        v.get(variante % v.len())
    }
}

fn construir(regla: &ReglaCompacta, mascara: u64, variante: usize) -> Evento {
    let mut partes: BTreeMap<Campo, Partes> = BTreeMap::new();
    for (i, s) in regla.selecciones.iter().enumerate() {
        if mascara & (1u64 << i) == 0 {
            continue;
        }
        let Some(alt) = elegir(&s.alternativas, variante) else {
            continue;
        };
        for (campo, c) in alt {
            partes.entry(*campo).or_default().anadir(c, variante);
        }
    }
    partes
        .into_iter()
        .filter_map(|(campo, p)| p.valor().map(|v| (campo, v)))
        .collect()
}

/// Recorre las mascaras de `n` bits de menos a mas bits a uno (Gosper).
fn mascaras(n: usize) -> impl Iterator<Item = u64> {
    let tope = 1u64 << n.min(63);
    (0..=n).flat_map(move |bits| {
        let mut m = if bits == 0 {
            Some(0u64)
        } else {
            (1u64 << bits).checked_sub(1)
        };
        std::iter::from_fn(move || {
            let actual = m?;
            m = if actual == 0 {
                None
            } else {
                let c = actual & actual.wrapping_neg();
                let r = actual + c;
                let sig = (((r ^ actual) >> 2) / c) | r;
                (sig < tope).then_some(sig)
            };
            (actual < tope).then_some(actual)
        })
    })
}

/// El caso positivo minimo que la regla acepta, o `None` si no se encontro
/// dentro del presupuesto de busqueda.
#[must_use]
pub fn dispara(regla: &ReglaCompacta) -> Option<Evento> {
    let n = regla.selecciones.len();
    for mascara in mascaras(n).take(MAX_ASIGNACIONES) {
        if !vale(&regla.condicion, mascara) {
            continue;
        }
        for variante in 0..VARIANTES {
            let ev = construir(regla, mascara, variante);
            if regla.casa(&registro(&ev)) {
                return Some(ev);
            }
        }
    }
    None
}

/// El mismo evento con un campo obligatorio alterado o quitado, de forma que
/// la regla ya no dispare. `None` si ningun campo es obligatorio.
#[must_use]
pub fn no_dispara(regla: &ReglaCompacta, dispara: &Evento) -> Option<Evento> {
    for campo in dispara.keys() {
        let mut alterado = dispara.clone();
        alterado.insert(*campo, ALTERADO.to_vec());
        if !regla.casa(&registro(&alterado)) {
            return Some(alterado);
        }
        alterado.remove(campo);
        if !regla.casa(&registro(&alterado)) {
            return Some(alterado);
        }
    }
    None
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::compacta::{Categoria, Juego};
    use crate::regla::Topes;

    /// Reglas SINTETICAS con valores inocuos: lo que se prueba es la forma de
    /// la condicion, no un contenido.
    fn regla(categoria: &str, deteccion: &str) -> ReglaCompacta {
        let fuente = format!(
            "title: Sintetica\nid: sintetica\nlogsource:\n    product: linux\n    category: \
             {categoria}\ndetection:\n{deteccion}level: low\n"
        );
        let j = Juego::cargar(&[("s.yml", fuente.as_str())], &Topes::default());
        assert!(j.rechazos().is_empty(), "{:?}", j.rechazos());
        let c = Categoria::desde(categoria).unwrap();
        j.reglas(c)[0].clone()
    }

    fn comprobar(r: &ReglaCompacta) -> (Evento, Evento) {
        let si = dispara(r).expect("hay un evento que dispara");
        assert!(r.casa(&registro(&si)));
        let no = no_dispara(r, &si).expect("hay un campo obligatorio");
        assert!(!r.casa(&registro(&no)));
        (si, no)
    }

    #[test]
    fn una_conjuncion_con_filtro_da_sus_dos_eventos() {
        let r = regla(
            "process_creation",
            "    imagen:\n        Image|endswith: '/alfa'\n    linea:\n        \
             CommandLine|contains|all:\n            - 'beta'\n            - 'gamma'\n    \
             filtro:\n        CommandLine|contains: 'delta'\n    \
             condition: imagen and linea and not filtro\n",
        );
        let (si, _) = comprobar(&r);
        assert!(si[&Campo::Imagen].ends_with(b"/alfa"));
        assert!(!si.contains_key(&Campo::ImagenPadre));
    }

    #[test]
    fn los_cuantificadores_y_las_alternativas_se_satisfacen() {
        let r = regla(
            "process_creation",
            "    sel_a:\n        CommandLine|startswith: 'uno'\n    sel_b:\n        \
             ParentImage: 'x'\n    condition: 1 of sel_*\n",
        );
        comprobar(&r);
        let r = regla(
            "file_event",
            "    sel:\n        - TargetFilename|startswith: '/opt/prueba/'\n          \
             TargetFilename|endswith: '.conf'\n        - Image: '/usr/bin/epsilon'\n    \
             condition: sel\n",
        );
        let (si, _) = comprobar(&r);
        assert!(si.contains_key(&Campo::FicheroDestino) || si.contains_key(&Campo::Imagen));
    }

    #[test]
    fn un_umbral_numerico_y_un_vacio_se_respetan() {
        let r = regla(
            "network_connection",
            "    puerto:\n        DestinationPort|gt: 50000\n    sin_imagen:\n        Image: ''\n    \
             condition: puerto and sin_imagen\n",
        );
        let (si, _) = comprobar(&r);
        assert_eq!(si[&Campo::PuertoDestino], b"50001".to_vec());
        assert!(!si.contains_key(&Campo::Imagen));
    }

    /// Una regla que dispara sobre cualquier evento no tiene «no dispara»: la
    /// puerta la rechaza.
    #[test]
    fn una_regla_que_casa_con_todo_no_tiene_evento_negativo() {
        let r = regla(
            "process_creation",
            "    filtro:\n        Image|endswith: '/zeta'\n    condition: not filtro\n",
        );
        let si = dispara(&r).expect("el vacio la dispara");
        assert!(si.is_empty());
        assert!(no_dispara(&r, &si).is_none());
    }

    #[test]
    fn las_mascaras_van_de_menos_a_mas_bits() {
        let v: Vec<u64> = mascaras(3).collect();
        assert_eq!(v, vec![0, 1, 2, 4, 3, 5, 6, 7]);
        assert_eq!(mascaras(20).take(5).count(), 5);
    }
}
