//! Reconstruccion de tipos por unificacion, con `Desconocido` como tope.
//!
//! # La regla que gobierna todo el modulo
//!
//! **Lo que no se puede inferir se emite como `desconocido`. JAMAS se inventa un
//! tipo.** Un tipo inventado en un informe forense es una afirmacion falsa con
//! aspecto de dato: alguien lee «esto es un `struct sockaddr`» y toma una decision
//! sobre una suposicion del decompilador. Aqui la duda se dice.
//!
//! # Como se reconstruye: restricciones tomadas del USO
//!
//! No hay declaraciones de tipo en un binario; hay usos. El tipo de un valor se
//! deduce de lo que se hace con el:
//!
//! - el **tamano** de los accesos (`mov eax` frente a `mov al`) da el ancho;
//! - la **aritmetica de punteros** —sumar una constante y luego cargar— dice que
//!   es un puntero, y a que apunta;
//! - los **prototipos de las APIs conocidas** tipan sus argumentos y su retorno;
//! - las **cadenas y constantes** dan pistas (un puntero a un literal es `char*`).
//!
//! Esas restricciones se combinan por **unificacion**: dos usos del mismo valor
//! imponen dos tipos, y el tipo del valor es el mas informativo compatible con los
//! dos. Si son incompatibles —el mismo valor usado como entero de 32 y como
//! puntero de 64—, el resultado es `Desconocido`, que es la verdad: el analisis no
//! puede afirmar ninguno.
//!
//! # El reticulo
//!
//! - [`Tipo::Desconocido`] es el **tope**: unificar cualquier cosa con el da la
//!   otra cosa (no aporta restriccion).
//! - [`Tipo::Conflicto`] es el **fondo**: dos restricciones incompatibles. Se
//!   presenta al usuario como `Desconocido` —no se le carga el detalle del
//!   conflicto—, pero se distingue internamente para no volver a intentar afinarlo.

/// El signo de un entero, cuando se ha podido deducir.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signo {
    /// Con signo (aparece en `idiv`, `movsx`, comparaciones con signo).
    Con,
    /// Sin signo (`div`, `movzx`, comparaciones sin signo).
    Sin,
    /// No se ha podido deducir el signo, solo el ancho.
    Indeterminado,
}

/// Un tipo reconstruido.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tipo {
    /// No se pudo reconstruir. Es el tope del reticulo y lo que se emite cuando
    /// no hay restriccion suficiente. **No es un fallo: es la respuesta honesta.**
    Desconocido,
    /// Un valor booleano (resultado de una comparacion).
    Booleano,
    /// Un entero de un ancho y, si se dedujo, un signo.
    Entero {
        /// Ancho en bits.
        bits: u32,
        /// Signo, si se dedujo.
        signo: Signo,
    },
    /// Un puntero a otro tipo.
    Puntero(Box<Tipo>),
    /// Un array de `n` elementos de un tipo (de una aritmetica de indice con paso
    /// constante).
    Array {
        /// El tipo del elemento.
        elemento: Box<Tipo>,
        /// Cuantos, si se dedujo la cota.
        largo: Option<u64>,
    },
    /// Una estructura: campos en desplazamientos deducidos de los accesos.
    Estructura {
        /// (desplazamiento, tipo) de cada campo observado, ordenado.
        campos: Vec<(u64, Tipo)>,
    },
    /// Sin valor (retorno de una funcion que no devuelve nada).
    Vacio,
    /// Dos restricciones incompatibles. Es el fondo del reticulo; se presenta como
    /// `Desconocido`, pero se guarda aparte para no reintentar.
    Conflicto,
}

impl Tipo {
    /// Un entero de un ancho, sin signo deducido.
    #[must_use]
    pub fn entero(bits: u32) -> Tipo {
        Tipo::Entero {
            bits,
            signo: Signo::Indeterminado,
        }
    }

    /// Si el tipo es, de cara al usuario, «no se» —incluye el conflicto, que no se
    /// le muestra como tal—.
    #[must_use]
    pub fn es_desconocido_para_el_usuario(&self) -> bool {
        matches!(self, Tipo::Desconocido | Tipo::Conflicto)
    }

    /// La representacion en pseudo-C del tipo. El conflicto y el desconocido salen
    /// igual —`desconocido`—: al usuario no se le carga la distincion interna.
    #[must_use]
    pub fn c(&self) -> String {
        match self {
            Tipo::Desconocido | Tipo::Conflicto => "desconocido".to_string(),
            Tipo::Booleano => "bool".to_string(),
            Tipo::Vacio => "void".to_string(),
            Tipo::Entero { bits, signo } => {
                let base = match signo {
                    Signo::Con => "int",
                    Signo::Sin => "uint",
                    Signo::Indeterminado => "int",
                };
                // Ancho explicito, como los tipos de <stdint.h>: no hay ambiguedad
                // de plataforma en un informe.
                match signo {
                    Signo::Sin => format!("uint{bits}_t"),
                    _ => {
                        let _ = base;
                        format!("int{bits}_t")
                    }
                }
            }
            Tipo::Puntero(a) => format!("{}*", a.c()),
            Tipo::Array { elemento, largo } => match largo {
                Some(n) => format!("{}[{n}]", elemento.c()),
                None => format!("{}[]", elemento.c()),
            },
            Tipo::Estructura { campos } => {
                let mut s = String::from("struct { ");
                for (off, t) in campos {
                    s.push_str(&format!("/*+{off:#x}*/ {}; ", t.c()));
                }
                s.push('}');
                s
            }
        }
    }

    /// Unifica dos tipos: el mas informativo compatible con los dos.
    ///
    /// - `Desconocido` (tope) con cualquier cosa da la otra cosa.
    /// - Dos iguales dan el mismo.
    /// - Dos enteros del mismo ancho combinan el signo (uno indeterminado toma el
    ///   del otro; dos signos distintos dejan el signo indeterminado, no el tipo
    ///   en conflicto: el ancho sigue siendo cierto).
    /// - Dos punteros unifican lo apuntado.
    /// - Incompatibles dan `Conflicto`.
    #[must_use]
    pub fn unificar(&self, otro: &Tipo) -> Tipo {
        match (self, otro) {
            (Tipo::Desconocido, t) | (t, Tipo::Desconocido) => t.clone(),
            (Tipo::Conflicto, _) | (_, Tipo::Conflicto) => Tipo::Conflicto,
            (a, b) if a == b => a.clone(),
            (
                Tipo::Entero {
                    bits: ba,
                    signo: sa,
                },
                Tipo::Entero {
                    bits: bb,
                    signo: sb,
                },
            ) if ba == bb => Tipo::Entero {
                bits: *ba,
                signo: unificar_signo(*sa, *sb),
            },
            (Tipo::Puntero(a), Tipo::Puntero(b)) => Tipo::Puntero(Box::new(a.unificar(b))),
            // Un entero del ancho del puntero y un puntero: se prefiere el puntero,
            // que es mas informativo, si el ancho cuadra.
            (Tipo::Entero { bits, .. }, Tipo::Puntero(p))
            | (Tipo::Puntero(p), Tipo::Entero { bits, .. })
                if *bits == 64 =>
            {
                Tipo::Puntero(p.clone())
            }
            _ => Tipo::Conflicto,
        }
    }
}

/// Combina dos signos: uno indeterminado toma el del otro; dos distintos vuelven a
/// indeterminado (el ancho se conserva, el signo se pierde honestamente).
fn unificar_signo(a: Signo, b: Signo) -> Signo {
    match (a, b) {
        (Signo::Indeterminado, s) | (s, Signo::Indeterminado) => s,
        (x, y) if x == y => x,
        _ => Signo::Indeterminado,
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn desconocido_es_el_tope_de_la_unificacion() {
        let i32 = Tipo::entero(32);
        assert_eq!(Tipo::Desconocido.unificar(&i32), i32);
        assert_eq!(i32.unificar(&Tipo::Desconocido), i32);
    }

    #[test]
    fn dos_enteros_del_mismo_ancho_combinan_el_signo() {
        let indet = Tipo::entero(32);
        let con = Tipo::Entero {
            bits: 32,
            signo: Signo::Con,
        };
        assert_eq!(indet.unificar(&con), con);
        // Dos signos distintos: se conserva el ancho, se pierde el signo.
        let sin = Tipo::Entero {
            bits: 32,
            signo: Signo::Sin,
        };
        assert_eq!(con.unificar(&sin), Tipo::entero(32));
    }

    #[test]
    fn dos_anchos_distintos_no_se_inventan_dan_conflicto() {
        let a = Tipo::entero(32);
        let b = Tipo::entero(64);
        assert_eq!(a.unificar(&b), Tipo::Conflicto);
        // Y el conflicto se muestra al usuario como desconocido, no como detalle.
        assert!(a.unificar(&b).es_desconocido_para_el_usuario());
        assert_eq!(a.unificar(&b).c(), "desconocido");
    }

    #[test]
    fn un_puntero_unifica_lo_apuntado() {
        let pi = Tipo::Puntero(Box::new(Tipo::Desconocido));
        let pc = Tipo::Puntero(Box::new(Tipo::entero(8)));
        assert_eq!(pi.unificar(&pc), pc);
    }

    #[test]
    fn el_pseudo_c_lleva_ancho_explicito_y_nunca_inventa() {
        assert_eq!(Tipo::entero(32).c(), "int32_t");
        assert_eq!(
            Tipo::Entero {
                bits: 64,
                signo: Signo::Sin
            }
            .c(),
            "uint64_t"
        );
        assert_eq!(Tipo::Puntero(Box::new(Tipo::entero(8))).c(), "int8_t*");
        assert_eq!(Tipo::Desconocido.c(), "desconocido");
    }
}
