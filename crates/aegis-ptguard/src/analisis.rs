//! Analisis anti ROP/JOP sobre el flujo reconstruido.
//!
//! Es el nucleo de decision, y lo que puede estar mal de forma peligrosa: un
//! falso positivo interrumpe un proceso legitimo; uno negativo deja pasar la
//! evasion que justifica toda la fase. La heuristica es la de kBouncer/ROPecker,
//! afinada sobre la forma que la traza revela:
//!
//! - **ROP**: una rafaga de gadgets CORTOS (pocas instrucciones) que terminan en
//!   `ret`, encadenados. La ejecucion normal tiene bloques largos entre saltos
//!   indirectos y sus `ret` emparejan con `call`s; una cadena ROP no.
//! - **JOP**: lo mismo pero terminando en saltos indirectos en vez de `ret`.
//!
//! No se decide sobre un solo gadget —un `ret` corto suelto es normal— sino
//! sobre una VENTANA: hacen falta varios gadgets cortos seguidos para que sea
//! una cadena.

use crate::reconstruccion::{FlujoEjecucion, Terminal};

/// Un gadget se considera "corto" (sospechoso de ser un eslabon de cadena) si
/// tiene como mucho estas instrucciones. Los gadgets utiles de ROP son de 1 a
/// unas pocas instrucciones.
pub const GADGET_CORTO: usize = 6;

/// Cuantos gadgets cortos seguidos hacen una cadena sospechosa. Uno o dos son
/// ruido normal; una rafaga larga no ocurre por casualidad.
pub const CADENA_MINIMA: usize = 8;

/// El veredicto sobre un flujo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Veredicto {
    /// Nada anomalo.
    Benigno,
    /// Cadena de retornos: ROP. Lleva la longitud de la cadena mas larga.
    Rop {
        /// Gadgets encadenados detectados.
        longitud: usize,
    },
    /// Cadena de saltos indirectos: JOP.
    Jop {
        /// Gadgets encadenados detectados.
        longitud: usize,
    },
}

/// Veredicto con severidad derivada, para el consumidor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VeredictoPt {
    /// Que se detecto.
    pub veredicto: Veredicto,
    /// Severidad 0..4; una cadena mas larga es mas concluyente.
    pub severidad: u8,
}

impl Veredicto {
    /// `true` si hay evasion.
    pub fn es_evasion(&self) -> bool {
        !matches!(self, Veredicto::Benigno)
    }
}

/// Analiza un flujo reconstruido y decide.
pub fn analizar_flujo(flujo: &FlujoEjecucion) -> VeredictoPt {
    let (mejor_ret, mejor_jmp) = cadenas_mas_largas(flujo);

    // Se prioriza la cadena mas larga; empate a favor de ROP (mas comun).
    let veredicto = if mejor_ret >= CADENA_MINIMA && mejor_ret >= mejor_jmp {
        Veredicto::Rop {
            longitud: mejor_ret,
        }
    } else if mejor_jmp >= CADENA_MINIMA {
        Veredicto::Jop {
            longitud: mejor_jmp,
        }
    } else {
        Veredicto::Benigno
    };

    let severidad = match &veredicto {
        Veredicto::Benigno => 0,
        Veredicto::Rop { longitud } | Veredicto::Jop { longitud } => {
            // A partir del minimo, sube con la longitud; se satura en 4.
            let extra = (longitud - CADENA_MINIMA) / 4;
            (2 + extra).min(4) as u8
        }
    };

    VeredictoPt {
        veredicto,
        severidad,
    }
}

/// Recorre el flujo midiendo la racha mas larga de gadgets cortos terminados en
/// `ret` y la mas larga terminada en salto indirecto.
fn cadenas_mas_largas(flujo: &FlujoEjecucion) -> (usize, usize) {
    let mut mejor_ret = 0;
    let mut mejor_jmp = 0;
    let mut racha_ret = 0;
    let mut racha_jmp = 0;

    for g in &flujo.gadgets {
        let corto = g.num_instrucciones > 0 && g.num_instrucciones <= GADGET_CORTO;
        match (corto, g.terminal) {
            (true, Terminal::Ret) => {
                racha_ret += 1;
                mejor_ret = mejor_ret.max(racha_ret);
                racha_jmp = 0;
            }
            (true, Terminal::SaltoIndirecto) => {
                racha_jmp += 1;
                mejor_jmp = mejor_jmp.max(racha_jmp);
                racha_ret = 0;
            }
            _ => {
                // Un gadget largo, o una llamada, o algo que no es gadget, rompe
                // la cadena: la ejecucion normal.
                racha_ret = 0;
                racha_jmp = 0;
            }
        }
    }
    (mejor_ret, mejor_jmp)
}
