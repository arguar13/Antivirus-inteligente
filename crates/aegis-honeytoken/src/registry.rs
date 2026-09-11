//! Registro de honey-tokens sembrados.
//!
//! Mapea cada marcador a su atribucion, para que cuando un marcador reaparezca
//! —en un volcado de memoria, en una ruta de fichero abierta— se pueda decir de
//! inmediato que senuelo se toco y donde estaba. Tambien permite escanear un
//! bloque de bytes buscando CUALQUIER marcador conocido, que es como se detecta
//! que un atacante ha leido un token de la memoria de un proceso.

use crate::token::{Atribucion, Marcador};
use std::collections::HashMap;

/// El registro de tokens vivos.
#[derive(Default)]
pub struct Registro {
    por_marcador: HashMap<String, Atribucion>,
}

impl Registro {
    /// Un registro vacio.
    pub fn new() -> Registro {
        Registro {
            por_marcador: HashMap::new(),
        }
    }

    /// Registra un token sembrado.
    pub fn registrar(&mut self, marcador: &Marcador, atrib: Atribucion) {
        self.por_marcador.insert(marcador.hex(), atrib);
    }

    /// Cuantos tokens hay sembrados.
    pub fn len(&self) -> usize {
        self.por_marcador.len()
    }

    /// `true` si no hay tokens.
    pub fn is_empty(&self) -> bool {
        self.por_marcador.is_empty()
    }

    /// Busca la atribucion de un marcador concreto.
    pub fn atribucion(&self, marcador: &Marcador) -> Option<&Atribucion> {
        self.por_marcador.get(&marcador.hex())
    }

    /// Escanea un bloque de bytes buscando el hex de cualquier marcador
    /// registrado. Devuelve todos los que aparezcan (un volcado de memoria puede
    /// contener varios). Es como se detecta que el token se filtro.
    pub fn buscar_en(&self, datos: &[u8]) -> Vec<(Marcador, Atribucion)> {
        // El hex del marcador es ASCII; se busca como subsecuencia de bytes.
        let mut encontrados = Vec::new();
        for (hex, atrib) in &self.por_marcador {
            if contiene_subsecuencia(datos, hex.as_bytes()) {
                if let Some(m) = Marcador::desde_hex(hex) {
                    encontrados.push((m, atrib.clone()));
                }
            }
        }
        encontrados
    }
}

/// Busca `aguja` dentro de `pajar` (subsecuencia contigua de bytes).
fn contiene_subsecuencia(pajar: &[u8], aguja: &[u8]) -> bool {
    if aguja.is_empty() || aguja.len() > pajar.len() {
        return false;
    }
    pajar.windows(aguja.len()).any(|v| v == aguja)
}
