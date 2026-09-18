//! Donde poner un punto de observacion, y por que ahi.
//!
//! # Lo que un punto de instrumentacion ES aqui
//!
//! Una direccion, una razon escrita y lo que se quiere ver. **Nada mas.** Un
//! punto de este crate no es un parche, ni un byte `0xCC`, ni una llamada a
//! `ptrace`: es una anotacion sobre un binario que alguien ya desensamblo.
//!
//! Esa distincion no es de estilo. Ver [`crate::plan`].

use std::fmt;

/// Que se quiere observar en un punto.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Que {
    /// Que se llego a ejecutar esta direccion.
    ///
    /// Es la observacion mas barata y la que mas dice en un desempaquetador:
    /// saber que el control llego a una region que no existia en el fichero.
    Paso,
    /// A donde fue una transferencia de control cuyo destino no se sabia.
    ///
    /// Es lo que el analisis estatico **no puede** responder —lo dice
    /// `aegis-disasm` contando las que deja sin resolver— y lo que la ejecucion
    /// responde sin esfuerzo.
    DestinoDeLaTransferencia,
    /// Los argumentos de una llamada al sistema.
    Argumentos,
    /// Que bytes quedaron escritos en una region.
    ///
    /// Para ver la carga que un desempaquetador despliega, que es el codigo real
    /// y el que hay que analizar.
    ContenidoEscrito,
}

impl Que {
    /// Como se lee en un informe.
    pub fn frase(&self) -> &'static str {
        match self {
            Que::Paso => "si el control llega hasta aqui",
            Que::DestinoDeLaTransferencia => "a donde va esta transferencia de control",
            Que::Argumentos => "con que argumentos se llama",
            Que::ContenidoEscrito => "que queda escrito en esta region",
        }
    }
}

/// Un punto de observacion.
///
/// La razon va **dentro del tipo** y no se puede omitir. Un plan de
/// instrumentacion sin razones es una lista de direcciones que nadie puede
/// revisar, y revisarlo es justo lo que hay que poder hacer antes de ejecutar
/// nada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Punto {
    /// En que direccion.
    pub direccion: u64,
    /// Que se quiere ver.
    pub que: Que,
    /// Por que aqui y no en otro sitio.
    pub porque: String,
}

impl Punto {
    /// Construye un punto. Devuelve `None` sin razon escrita.
    ///
    /// Es el unico constructor, igual que en `aegis_disasm::Capacidad`: un punto
    /// sin razon **no existe como valor**, y por tanto un plan no puede llevar
    /// ninguno.
    pub fn nuevo(direccion: u64, que: Que, porque: impl Into<String>) -> Option<Punto> {
        let porque = porque.into();
        if porque.trim().is_empty() {
            return None;
        }
        Some(Punto {
            direccion,
            que,
            porque,
        })
    }
}

impl fmt::Display for Punto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:#x}: observar {} — {}",
            self.direccion,
            self.que.frase(),
            self.porque
        )
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn un_punto_sin_razon_no_se_puede_construir() {
        // Un plan de instrumentacion sin razones es una lista de direcciones que
        // nadie puede revisar, y revisarlo es justo lo que hay que poder hacer
        // antes de ejecutar nada.
        assert!(Punto::nuevo(0x1000, Que::Paso, "").is_none());
        assert!(Punto::nuevo(0x1000, Que::Paso, "   ").is_none());
        assert!(Punto::nuevo(0x1000, Que::Paso, "porque si").is_some());
    }

    #[test]
    fn un_punto_se_lee_entero_en_una_linea() {
        let p = Punto::nuevo(
            0x401000,
            Que::DestinoDeLaTransferencia,
            "el analisis estatico dejo esta sin resolver",
        )
        .unwrap();
        let s = p.to_string();
        assert!(s.contains("0x401000"), "{s}");
        assert!(s.contains("a donde va"), "{s}");
        assert!(s.contains("sin resolver"), "{s}");
    }
}
