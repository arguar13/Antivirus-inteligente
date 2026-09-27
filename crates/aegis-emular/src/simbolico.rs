//! Ejecucion simbolica ACOTADA sobre la IR de la FASE 100.
//!
//! # Por que acotada, y por que gana a angr
//!
//! angr resuelve saltos indirectos y condiciones anti-analisis explorando caminos
//! simbolicamente, y no acota: una funcion con un bucle sobre datos simbolicos le
//! hace explotar el numero de estados. Aqui la exploracion tiene un PRESUPUESTO de
//! estados que es parte del tipo: pasado el, se devuelve «no resuelto» —que es la
//! verdad—, en vez de agotar la maquina. No hay via de explosion.
//!
//! # Que resuelve
//!
//! Evalua el valor de un [`ValId`] propagando constantes por la IR en forma SSA:
//! sigue las definiciones, dobla las operaciones sobre constantes, y en un `phi`
//! une las fuentes (si todas coinciden, es ese valor; si difieren, es un CONJUNTO
//! acotado de posibles; si el conjunto crece demasiado, se rinde). Es lo que hace
//! falta para decir a donde va un `jmp rax` cuyo valor se calculo antes, sin
//! ejecutar la muestra.

use std::collections::{BTreeMap, BTreeSet};

use aegis_decompile::ir::{FuncionIr, OpBin, OpUn, Operacion, Operando, Sentencia, ValId};

/// El valor abstracto de un `ValId` tras la evaluacion simbolica.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Abstracto {
    /// Un valor concreto unico: el salto indirecto esta resuelto.
    Concreto(u64),
    /// Un conjunto acotado de valores posibles (varias ramas de un phi).
    Conjunto(BTreeSet<u64>),
    /// No se pudo resolver: dependia de algo no constante, o se agoto el
    /// presupuesto. **No es cero**: es «no se».
    NoResuelto,
}

/// El tope de valores distintos que un conjunto puede tener antes de rendirse.
pub const MAX_CONJUNTO: usize = 32;

/// El evaluador simbolico acotado de una funcion.
pub struct Evaluador<'a> {
    /// Definicion de cada valor SSA (de las sentencias `Definir`).
    defs: BTreeMap<ValId, &'a Operacion>,
    /// Presupuesto de pasos restante (cota dura de tiempo).
    presupuesto: u64,
    /// Memo de valores ya resueltos, para no reevaluar (y romper ciclos).
    memo: BTreeMap<ValId, Abstracto>,
}

impl<'a> Evaluador<'a> {
    /// Construye el evaluador de una funcion con un presupuesto de estados.
    #[must_use]
    pub fn nuevo(f: &'a FuncionIr, presupuesto: u64) -> Evaluador<'a> {
        let mut defs = BTreeMap::new();
        for bl in f.bloques_ordenados() {
            for s in &bl.sentencias {
                if let Sentencia::Definir { destino, op, .. } = s {
                    defs.insert(*destino, op);
                }
            }
        }
        Evaluador {
            defs,
            presupuesto,
            memo: BTreeMap::new(),
        }
    }

    /// Resuelve el valor abstracto de un `ValId`.
    #[must_use]
    pub fn resolver(&mut self, v: ValId) -> Abstracto {
        if let Some(a) = self.memo.get(&v) {
            return a.clone();
        }
        if self.presupuesto == 0 {
            return Abstracto::NoResuelto;
        }
        self.presupuesto -= 1;
        // Marcar en curso como NoResuelto para romper ciclos (un phi que se
        // referencia a si mismo no debe recurrir sin fin).
        self.memo.insert(v, Abstracto::NoResuelto);
        let Some(op) = self.defs.get(&v).copied() else {
            return Abstracto::NoResuelto;
        };
        let r = self.eval_op(op);
        self.memo.insert(v, r.clone());
        r
    }

    /// Resuelve un operando a su valor abstracto.
    fn eval_operando(&mut self, o: &Operando) -> Abstracto {
        match o {
            Operando::Const(k, _) => Abstracto::Concreto(*k),
            Operando::Val(v) => self.resolver(*v),
            Operando::Indefinido => Abstracto::NoResuelto,
        }
    }

    /// Evalua una operacion.
    fn eval_op(&mut self, op: &Operacion) -> Abstracto {
        match op {
            Operacion::Copiar(o) => self.eval_operando(o),
            Operacion::Bin { op, a, b } => {
                let (va, vb) = (self.eval_operando(a), self.eval_operando(b));
                self.combinar_bin(*op, &va, &vb)
            }
            Operacion::Un { op, a } => {
                let va = self.eval_operando(a);
                self.aplicar_un(*op, &va)
            }
            Operacion::Fi(fi) => {
                // Union acotada de las fuentes.
                let mut conj: BTreeSet<u64> = BTreeSet::new();
                for o in fi.fuentes.values() {
                    match self.eval_operando(o) {
                        Abstracto::Concreto(k) => {
                            conj.insert(k);
                        }
                        Abstracto::Conjunto(s) => {
                            conj.extend(s);
                        }
                        Abstracto::NoResuelto => return Abstracto::NoResuelto,
                    }
                    if conj.len() > MAX_CONJUNTO {
                        return Abstracto::NoResuelto;
                    }
                }
                match conj.len() {
                    0 => Abstracto::NoResuelto,
                    1 => Abstracto::Concreto(*conj.iter().next().unwrap()),
                    _ => Abstracto::Conjunto(conj),
                }
            }
            // Un resultado de llamada o un argumento no es constante: no resuelto.
            Operacion::ResultadoLlamada | Operacion::Argumento(_) | Operacion::Indefinido => {
                Abstracto::NoResuelto
            }
            // Una carga de memoria simbolica no se resuelve aqui (haria falta el
            // estado de memoria); se declara no resuelto en vez de inventar.
            Operacion::Cargar { .. } | Operacion::Comparar { .. } => Abstracto::NoResuelto,
        }
    }

    /// Combina dos valores abstractos con una operacion binaria, propagando el
    /// «no resuelto» y acotando el producto de conjuntos.
    fn combinar_bin(&self, op: OpBin, a: &Abstracto, b: &Abstracto) -> Abstracto {
        let aes = valores(a);
        let bes = valores(b);
        let (Some(aes), Some(bes)) = (aes, bes) else {
            return Abstracto::NoResuelto;
        };
        if aes.len().saturating_mul(bes.len()) > MAX_CONJUNTO {
            return Abstracto::NoResuelto;
        }
        let mut conj = BTreeSet::new();
        for &x in &aes {
            for &y in &bes {
                conj.insert(aplicar_bin(op, x, y));
            }
        }
        match conj.len() {
            0 => Abstracto::NoResuelto,
            1 => Abstracto::Concreto(*conj.iter().next().unwrap()),
            _ => Abstracto::Conjunto(conj),
        }
    }

    /// Aplica una operacion unaria a un valor abstracto.
    fn aplicar_un(&self, op: OpUn, a: &Abstracto) -> Abstracto {
        let Some(aes) = valores(a) else {
            return Abstracto::NoResuelto;
        };
        let mut conj = BTreeSet::new();
        for &x in &aes {
            conj.insert(match op {
                OpUn::Negar => 0u64.wrapping_sub(x),
                OpUn::No => !x,
                OpUn::ExtenderU(_) | OpUn::ExtenderS(_) | OpUn::Truncar(_) => x,
            });
        }
        match conj.len() {
            1 => Abstracto::Concreto(*conj.iter().next().unwrap()),
            _ => Abstracto::Conjunto(conj),
        }
    }
}

/// Los valores concretos de un abstracto, o `None` si no esta resuelto.
fn valores(a: &Abstracto) -> Option<Vec<u64>> {
    match a {
        Abstracto::Concreto(k) => Some(vec![*k]),
        Abstracto::Conjunto(s) => Some(s.iter().copied().collect()),
        Abstracto::NoResuelto => None,
    }
}

/// Aplica una operacion binaria a dos valores concretos.
fn aplicar_bin(op: OpBin, a: u64, b: u64) -> u64 {
    match op {
        OpBin::Sumar => a.wrapping_add(b),
        OpBin::Restar => a.wrapping_sub(b),
        OpBin::Multiplicar => a.wrapping_mul(b),
        OpBin::DividirU => a.checked_div(b).unwrap_or(0),
        OpBin::DividirS => (a as i64).checked_div(b as i64).unwrap_or(0) as u64,
        OpBin::RestoU => a.checked_rem(b).unwrap_or(0),
        OpBin::RestoS => (a as i64).checked_rem(b as i64).unwrap_or(0) as u64,
        OpBin::Y => a & b,
        OpBin::O => a | b,
        OpBin::Xor => a ^ b,
        OpBin::DesplazarIzq => a.wrapping_shl((b & 63) as u32),
        OpBin::DesplazarDerL => a.wrapping_shr((b & 63) as u32),
        OpBin::DesplazarDerA => ((a as i64) >> (b & 63)) as u64,
        OpBin::RotarIzq => a.rotate_left((b & 63) as u32),
        OpBin::RotarDer => a.rotate_right((b & 63) as u32),
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_decompile::ir::{Ancho, BloqueId, BloqueIr, Terminador};
    use aegis_decompile::Tipo;

    /// Una funcion con: v0 = 0x1000; v1 = v0 + 0x40; (resuelve v1 = 0x1040).
    fn funcion_lineal() -> FuncionIr {
        let mut f = FuncionIr::nueva(0x1000);
        f.bloques.insert(
            BloqueId(0x1000),
            BloqueIr {
                id: BloqueId(0x1000),
                sentencias: vec![
                    Sentencia::Definir {
                        destino: ValId(0),
                        ancho: Ancho::B64,
                        tipo: Tipo::Desconocido,
                        op: Operacion::Copiar(Operando::Const(0x1000, Ancho::B64)),
                        origen: vec![0x1000],
                    },
                    Sentencia::Definir {
                        destino: ValId(1),
                        ancho: Ancho::B64,
                        tipo: Tipo::Desconocido,
                        op: Operacion::Bin {
                            op: OpBin::Sumar,
                            a: Operando::Val(ValId(0)),
                            b: Operando::Const(0x40, Ancho::B64),
                        },
                        origen: vec![0x1006],
                    },
                ],
                terminador: Terminador::Retornar(None),
            },
        );
        f
    }

    #[test]
    fn resuelve_un_salto_indirecto_calculado_por_constantes() {
        let f = funcion_lineal();
        let mut e = Evaluador::nuevo(&f, 1000);
        assert_eq!(e.resolver(ValId(1)), Abstracto::Concreto(0x1040));
    }

    #[test]
    fn un_argumento_no_es_constante() {
        let mut f = FuncionIr::nueva(0x2000);
        f.bloques.insert(
            BloqueId(0x2000),
            BloqueIr {
                id: BloqueId(0x2000),
                sentencias: vec![Sentencia::Definir {
                    destino: ValId(0),
                    ancho: Ancho::B64,
                    tipo: Tipo::Desconocido,
                    op: Operacion::Argumento(0),
                    origen: vec![0x2000],
                }],
                terminador: Terminador::Retornar(None),
            },
        );
        let mut e = Evaluador::nuevo(&f, 1000);
        assert_eq!(e.resolver(ValId(0)), Abstracto::NoResuelto);
    }

    #[test]
    fn el_presupuesto_acota_la_exploracion() {
        // Con presupuesto 0 no se resuelve nada: la cota es dura.
        let f = funcion_lineal();
        let mut e = Evaluador::nuevo(&f, 0);
        assert_eq!(e.resolver(ValId(1)), Abstracto::NoResuelto);
    }

    #[test]
    fn un_ciclo_de_definiciones_no_cuelga() {
        // Un phi que se referencia a si mismo (v0 = phi(v0, const)) no debe recurrir
        // sin fin: se rompe con la memo en curso.
        let mut f = FuncionIr::nueva(0x3000);
        let mut fuentes = BTreeMap::new();
        fuentes.insert(BloqueId(0x3000), Operando::Val(ValId(0)));
        fuentes.insert(BloqueId(0x2fff), Operando::Const(7, Ancho::B64));
        f.bloques.insert(
            BloqueId(0x3000),
            BloqueIr {
                id: BloqueId(0x3000),
                sentencias: vec![Sentencia::Definir {
                    destino: ValId(0),
                    ancho: Ancho::B64,
                    tipo: Tipo::Desconocido,
                    op: Operacion::Fi(aegis_decompile::ir::Fi { fuentes }),
                    origen: vec![0x3000],
                }],
                terminador: Terminador::Retornar(None),
            },
        );
        let mut e = Evaluador::nuevo(&f, 1000);
        // Termina (no cuelga); el resultado es no resuelto o el valor concreto 7.
        let _ = e.resolver(ValId(0));
    }
}
