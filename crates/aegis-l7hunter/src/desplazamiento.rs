//! Desplazamientos DERIVADOS, nunca adivinados (FASE 107).
//!
//! # El defecto estructural de eCapture
//!
//! Todo lo que engancha bibliotecas necesita saber en QUE desplazamiento del
//! fichero esta la funcion y donde estan sus argumentos. eCapture y compania
//! traen desplazamientos precalculados por version: cuando el binario no es una de
//! las versiones conocidas —recompilado, despojado, estatico, una rama que no
//! vieron—, leen en el sitio de siempre y devuelven BASURA con aspecto de dato. Un
//! dato falso es peor que un hueco: nadie sospecha de el.
//!
//! Aqui un desplazamiento SOLO existe si se pudo DERIVAR, y se dice de donde: de la
//! tabla de simbolos, de DWARF, de BTF, o —cuando no hay nada de eso— analizando
//! el binario con el desensamblador (FASE 85) y el decompilador (FASE 100): el
//! producto se usa a si mismo. Si ninguna via lo deriva, el resultado es
//! `NoConcluyente` con su motivo. **La tercera salida —leer igualmente— no
//! existe**: no hay ningun camino en el tipo que devuelva un offset «a ciegas».

/// De donde se derivo un desplazamiento. Nunca «adivinado por version».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuenteOffset {
    /// Exportado en la tabla de simbolos del ELF (el caso facil y el mas comun).
    TablaSimbolos,
    /// Derivado de la informacion de depuracion DWARF.
    Dwarf,
    /// Derivado del BTF (BPF Type Format) del binario o del kernel.
    Btf,
    /// Derivado ANALIZANDO el binario con el desensamblador (FASE 85) y el
    /// decompilador (FASE 100). Es la via para un binario despojado y estatico.
    AnalisisBinario,
}

impl FuenteOffset {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            FuenteOffset::TablaSimbolos => "tabla-de-simbolos",
            FuenteOffset::Dwarf => "dwarf",
            FuenteOffset::Btf => "btf",
            FuenteOffset::AnalisisBinario => "analisis-binario",
        }
    }

    /// El orden en que se intentan las fuentes: de la mas barata y fiable a la mas
    /// cara. El analisis del binario es el ultimo recurso, pero existe.
    #[must_use]
    pub fn orden_de_intento() -> [FuenteOffset; 4] {
        [
            FuenteOffset::TablaSimbolos,
            FuenteOffset::Dwarf,
            FuenteOffset::Btf,
            FuenteOffset::AnalisisBinario,
        ]
    }
}

/// El resultado de intentar derivar el desplazamiento de un simbolo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Desplazamiento {
    /// Se derivo, y se dice de donde. Un desplazamiento sin fuente no existe.
    Derivado {
        /// Desplazamiento dentro del fichero.
        offset: u64,
        /// De donde se derivo.
        fuente: FuenteOffset,
    },
    /// No se pudo derivar por NINGUNA via. Es `NoConcluyente`, no una lectura a
    /// ciegas: el gancho no se pone y se dice por que.
    NoConcluyente {
        /// Por que no se pudo.
        motivo: String,
    },
}

impl Desplazamiento {
    /// Si se derivo un offset utilizable.
    #[must_use]
    pub fn es_derivado(&self) -> bool {
        matches!(self, Desplazamiento::Derivado { .. })
    }

    /// El offset, si se derivo.
    #[must_use]
    pub fn offset(&self) -> Option<u64> {
        match self {
            Desplazamiento::Derivado { offset, .. } => Some(*offset),
            Desplazamiento::NoConcluyente { .. } => None,
        }
    }
}

/// Una fuente de derivacion: intenta dar el offset de un simbolo, o `None` si esa
/// via no lo tiene (p. ej. un binario despojado no tiene DWARF).
pub trait Fuente {
    /// La clase de fuente que representa.
    fn clase(&self) -> FuenteOffset;
    /// Intenta derivar el offset del simbolo.
    fn derivar(&self, simbolo: &str) -> Option<u64>;
}

/// Deriva el desplazamiento de un simbolo probando las fuentes EN ORDEN, y se
/// queda con la primera que lo da. Si ninguna lo da, `NoConcluyente` —jamas un
/// offset inventado—.
///
/// Este es el corazon de la fase: la decision «derivar o decir que no», separada
/// de la fontaneria de cada fuente (que es la que habla con DWARF/BTF/el
/// desensamblador). Asi la decision se prueba de forma determinista.
#[must_use]
pub fn derivar(simbolo: &str, fuentes: &[&dyn Fuente]) -> Desplazamiento {
    // Se respeta el orden canonico de intento, no el orden en que llegaron.
    for clase in FuenteOffset::orden_de_intento() {
        for f in fuentes {
            if f.clase() == clase {
                if let Some(offset) = f.derivar(simbolo) {
                    return Desplazamiento::Derivado {
                        offset,
                        fuente: clase,
                    };
                }
            }
        }
    }
    Desplazamiento::NoConcluyente {
        motivo: format!(
            "el simbolo «{simbolo}» no se pudo derivar por ninguna via (tabla, DWARF, \
             BTF ni analisis del binario): no se engancha a ciegas"
        ),
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use std::collections::BTreeMap;

    struct FuenteFalsa {
        clase: FuenteOffset,
        tabla: BTreeMap<&'static str, u64>,
    }
    impl Fuente for FuenteFalsa {
        fn clase(&self) -> FuenteOffset {
            self.clase
        }
        fn derivar(&self, simbolo: &str) -> Option<u64> {
            self.tabla.get(simbolo).copied()
        }
    }

    #[test]
    fn se_prefiere_la_fuente_mas_barata_y_se_dice_cual() {
        let simbolos = FuenteFalsa {
            clase: FuenteOffset::TablaSimbolos,
            tabla: [("SSL_write", 0x1000)].into(),
        };
        let dwarf = FuenteFalsa {
            clase: FuenteOffset::Dwarf,
            tabla: [("SSL_write", 0x2000)].into(),
        };
        // Aunque DWARF tambien lo tenga, gana la tabla de simbolos (mas barata).
        let d = derivar("SSL_write", &[&dwarf, &simbolos]);
        assert_eq!(
            d,
            Desplazamiento::Derivado {
                offset: 0x1000,
                fuente: FuenteOffset::TablaSimbolos
            }
        );
    }

    #[test]
    fn un_binario_despojado_cae_en_el_analisis_del_binario() {
        // Sin tabla ni DWARF ni BTF: solo el analisis del binario lo deriva.
        let analisis = FuenteFalsa {
            clase: FuenteOffset::AnalisisBinario,
            tabla: [("crypto/tls.(*Conn).Write", 0x4abc)].into(),
        };
        let d = derivar("crypto/tls.(*Conn).Write", &[&analisis]);
        assert_eq!(d.offset(), Some(0x4abc));
        assert!(matches!(
            d,
            Desplazamiento::Derivado {
                fuente: FuenteOffset::AnalisisBinario,
                ..
            }
        ));
    }

    #[test]
    fn si_ninguna_via_lo_deriva_es_noconcluyente_no_una_lectura_a_ciegas() {
        // Un binario despojado y estatico donde ni el analisis lo saca: la salida
        // correcta es NoConcluyente. La tercera —leer igualmente— no existe.
        let vacia = FuenteFalsa {
            clase: FuenteOffset::AnalisisBinario,
            tabla: BTreeMap::new(),
        };
        let d = derivar("SSL_write", &[&vacia]);
        assert!(!d.es_derivado());
        assert_eq!(d.offset(), None);
        assert!(matches!(d, Desplazamiento::NoConcluyente { .. }));
    }

    #[test]
    fn sin_fuentes_es_noconcluyente() {
        assert!(matches!(
            derivar("SSL_read", &[]),
            Desplazamiento::NoConcluyente { .. }
        ));
    }
}
