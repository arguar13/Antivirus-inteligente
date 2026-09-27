//! El modelo de una regla y la evaluacion de su condicion.
//!
//! Una regla es un identificador, unos metadatos, unas cadenas (literales, hex o
//! expresiones regulares) y una condicion booleana sobre que cadenas casaron. La
//! condicion se evalua sobre el CONJUNTO de cadenas que coincidieron, que es una
//! funcion pura: mismo conjunto, mismo resultado.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use crate::regex::Programa;

/// El patron de una cadena: lo que se busca en los bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Patron {
    /// Una secuencia de bytes literal (una cadena de texto o un `{ hex }`).
    Literal(Vec<u8>),
    /// Una expresion regular compilada, sin retroceso.
    Regex(Programa),
}

/// La cota de coste de un patron: lo que hace demostrable que no explota.
///
/// Para un literal, es su longitud. Para una regex, el numero de estados de su
/// programa (la memoria de la simulacion) por el tamano de la entrada (el tiempo,
/// que es lineal por construccion). Un patron cuya cota no se puede demostrar no
/// llega a existir: el compilador lo rechaza antes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cota {
    /// Estados del automata (cota de memoria).
    pub estados: usize,
    /// Bytes minimos que tiene que casar (longitud del literal, o del prefijo).
    pub longitud_minima: usize,
}

/// Una cadena de una regla: su identificador, su patron y sus modificadores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cadena {
    /// El identificador dentro de la regla, con el `$` (p. ej. `$a`).
    pub id: String,
    /// Que se busca.
    pub patron: Patron,
    /// `nocase`: insensible a mayusculas.
    pub nocase: bool,
    /// `ascii`: se busca en ASCII (el valor por defecto de YARA).
    pub ascii: bool,
    /// `wide`: se busca tambien en UTF-16LE (dos bytes por caracter).
    pub wide: bool,
    /// `fullword`: solo casa si esta delimitado por no-alfanumericos.
    pub fullword: bool,
}

impl Cadena {
    /// La cota de coste de esta cadena.
    #[must_use]
    pub fn cota(&self) -> Cota {
        match &self.patron {
            Patron::Literal(b) => Cota {
                estados: b.len().max(1),
                longitud_minima: b.len(),
            },
            Patron::Regex(p) => Cota {
                estados: p.estados(),
                longitud_minima: 1,
            },
        }
    }
}

/// El cuantificador de un `N of`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cuantificador {
    /// `N of ...`: al menos N.
    AlMenos(u64),
    /// `any of ...`: al menos una.
    Alguna,
    /// `all of ...`: todas.
    Todas,
}

/// El conjunto de cadenas de un `... of ...`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Conjunto {
    /// `them`: todas las cadenas de la regla.
    Todas,
    /// Una lista explicita de identificadores (`($a, $b, $c)`), ya resueltos los
    /// comodines como `$pre*` a la lista concreta.
    Lista(Vec<String>),
}

/// La condicion de una regla: un arbol booleano sobre que cadenas casaron.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cond {
    /// Siempre cierta (`condition: true`, o una regla sin condicion util).
    Verdadero,
    /// Una cadena concreta caso (`$a`).
    Cadena(String),
    /// Conjuncion.
    Y(Box<Cond>, Box<Cond>),
    /// Disyuncion.
    O(Box<Cond>, Box<Cond>),
    /// Negacion.
    No(Box<Cond>),
    /// `N of (conjunto)` / `any of them` / `all of them`.
    NDe(Cuantificador, Conjunto),
}

impl Cond {
    /// Evalua la condicion sobre el conjunto de cadenas que coincidieron y la lista
    /// completa de identificadores de la regla (para resolver `them`).
    #[must_use]
    pub fn evaluar(&self, casaron: &BTreeSet<String>, todas: &[String]) -> bool {
        match self {
            Cond::Verdadero => true,
            Cond::Cadena(id) => casaron.contains(id),
            Cond::Y(a, b) => a.evaluar(casaron, todas) && b.evaluar(casaron, todas),
            Cond::O(a, b) => a.evaluar(casaron, todas) || b.evaluar(casaron, todas),
            Cond::No(a) => !a.evaluar(casaron, todas),
            Cond::NDe(cuant, conjunto) => {
                let lista: Vec<&String> = match conjunto {
                    Conjunto::Todas => todas.iter().collect(),
                    Conjunto::Lista(v) => v.iter().collect(),
                };
                let n = lista.iter().filter(|id| casaron.contains(**id)).count() as u64;
                match cuant {
                    Cuantificador::AlMenos(k) => n >= *k,
                    Cuantificador::Alguna => n >= 1,
                    Cuantificador::Todas => n as usize == lista.len() && !lista.is_empty(),
                }
            }
        }
    }
}

/// Gravedad declarada por una regla en su metadato `severity`. Espeja la de
/// `aegis-scan` para que la sustitucion sea transparente.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severidad {
    /// Informativa.
    Info,
    /// Baja.
    Baja,
    /// Media.
    Media,
    /// Alta.
    Alta,
    /// Critica.
    Critica,
}

impl Severidad {
    /// Interpreta el metadato `severity`. Lo desconocido es media, no baja:
    /// infravalorar por no saber es como algo real acaba ignorado.
    #[must_use]
    pub fn parsear(s: &str) -> Severidad {
        match s.trim().to_ascii_lowercase().as_str() {
            "critical" => Severidad::Critica,
            "high" => Severidad::Alta,
            "low" => Severidad::Baja,
            "info" | "none" => Severidad::Info,
            _ => Severidad::Media,
        }
    }
}

/// Una regla compilada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Regla {
    /// El identificador de la regla.
    pub nombre: String,
    /// El espacio de nombres.
    pub namespace: String,
    /// Los metadatos (`meta:`).
    pub meta: BTreeMap<String, String>,
    /// Las cadenas.
    pub cadenas: Vec<Cadena>,
    /// La condicion.
    pub condicion: Cond,
}

impl Regla {
    /// La gravedad declarada, o media si no la declara.
    #[must_use]
    pub fn severidad(&self) -> Severidad {
        self.meta
            .get("severity")
            .map_or(Severidad::Media, |s| Severidad::parsear(s))
    }

    /// La descripcion declarada.
    #[must_use]
    pub fn descripcion(&self) -> &str {
        self.meta.get("description").map_or("", String::as_str)
    }

    /// La tecnica ATT&CK declarada, si la hay.
    #[must_use]
    pub fn tecnica(&self) -> Option<&str> {
        self.meta.get("technique").map(String::as_str)
    }

    /// Los identificadores de todas sus cadenas, para resolver `them`.
    #[must_use]
    pub fn ids(&self) -> Vec<String> {
        self.cadenas.iter().map(|c| c.id.clone()).collect()
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn conjunto(ids: &[&str]) -> BTreeSet<String> {
        ids.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn una_condicion_booleana_se_evalua_sobre_lo_que_caso() {
        // $a and ($b or $c)
        let cond = Cond::Y(
            Box::new(Cond::Cadena("$a".into())),
            Box::new(Cond::O(
                Box::new(Cond::Cadena("$b".into())),
                Box::new(Cond::Cadena("$c".into())),
            )),
        );
        let todas = vec!["$a".to_string(), "$b".into(), "$c".into()];
        assert!(cond.evaluar(&conjunto(&["$a", "$c"]), &todas));
        assert!(!cond.evaluar(&conjunto(&["$b", "$c"]), &todas), "falta $a");
        assert!(!cond.evaluar(&conjunto(&["$a"]), &todas), "falta $b y $c");
    }

    #[test]
    fn n_of_cuenta_las_que_casaron() {
        // 2 of ($a, $b, $c, $d)
        let cond = Cond::NDe(
            Cuantificador::AlMenos(2),
            Conjunto::Lista(vec!["$a".into(), "$b".into(), "$c".into(), "$d".into()]),
        );
        let todas = vec!["$a".to_string(), "$b".into(), "$c".into(), "$d".into()];
        assert!(cond.evaluar(&conjunto(&["$a", "$c"]), &todas));
        assert!(!cond.evaluar(&conjunto(&["$a"]), &todas), "solo una");
    }

    #[test]
    fn any_y_all_of_them() {
        let todas = vec!["$a".to_string(), "$b".into()];
        let any = Cond::NDe(Cuantificador::Alguna, Conjunto::Todas);
        let all = Cond::NDe(Cuantificador::Todas, Conjunto::Todas);
        assert!(any.evaluar(&conjunto(&["$b"]), &todas));
        assert!(!all.evaluar(&conjunto(&["$b"]), &todas), "falta $a");
        assert!(all.evaluar(&conjunto(&["$a", "$b"]), &todas));
    }

    #[test]
    fn la_cota_de_un_literal_es_su_longitud() {
        let c = Cadena {
            id: "$a".into(),
            patron: Patron::Literal(b"abcd".to_vec()),
            nocase: false,
            ascii: true,
            wide: false,
            fullword: false,
        };
        assert_eq!(c.cota().longitud_minima, 4);
    }
}
