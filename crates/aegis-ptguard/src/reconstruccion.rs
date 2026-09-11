//! Reconstruccion del flujo de ejecucion a partir de la traza y la imagen.
//!
//! La traza sola no basta: dice "aqui hubo un salto indirecto a la direccion X",
//! pero no que codigo hay en X. Cruzandola con la IMAGEN del proceso —los bytes
//! del codigo— y desensamblando con iced-x86 se reconstruye la secuencia de
//! "gadgets": el trozo de codigo que se ejecuto desde el destino de un salto
//! indirecto hasta el siguiente. Esa forma —cuantas instrucciones y como
//! termina cada gadget— es lo que distingue una cadena ROP de la ejecucion
//! normal.
//!
//! Se aproxima el gadget como el desensamblado LINEAL desde el destino hasta el
//! primer salto indirecto o `ret`. Los gadgets de ROP/JOP, por construccion, no
//! tienen saltos condicionales internos: son rectos y cortos. Esta aproximacion
//! es exactamente la que usan kBouncer y ROPecker, y es la que se prueba.

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};

/// Como termina un gadget: la instruccion de transferencia de control final.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Terminal {
    /// `ret`: la instruccion caracteristica de ROP.
    Ret,
    /// `jmp` indirecto (registro o memoria): la de JOP.
    SaltoIndirecto,
    /// `call` indirecto.
    LlamadaIndirecta,
    /// El desensamblado no encontro un salto indirecto en la ventana: no parece
    /// un gadget.
    NoEsGadget,
}

/// Una transferencia de control reconstruida: el gadget que arranca en `inicio`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferenciaControl {
    /// Direccion donde empieza el gadget (destino del salto indirecto anterior).
    pub inicio: u64,
    /// Cuantas instrucciones se ejecutaron hasta el salto final.
    pub num_instrucciones: usize,
    /// Como termino.
    pub terminal: Terminal,
}

/// El flujo reconstruido: la secuencia de gadgets, en orden de ejecucion.
#[derive(Debug, Clone, Default)]
pub struct FlujoEjecucion {
    /// Los gadgets, uno por cada salto indirecto de la traza.
    pub gadgets: Vec<TransferenciaControl>,
}

/// La imagen del codigo del proceso: los bytes y la direccion virtual del primer
/// byte. En produccion se obtiene con `process_vm_readv` (aegis-scal); en las
/// pruebas se construye a mano con codigo x86-64 real.
pub struct Imagen<'a> {
    /// Direccion virtual del byte 0 de `bytes`.
    pub base: u64,
    /// Los bytes del codigo.
    pub bytes: &'a [u8],
}

impl Imagen<'_> {
    fn rango(&self, dir: u64) -> Option<&[u8]> {
        let off = dir.checked_sub(self.base)? as usize;
        self.bytes.get(off..)
    }
}

/// Cuantas instrucciones se desensamblan como maximo por gadget antes de darse
/// por vencido: un "gadget" de ROP real es corto; algo mas largo ya no lo es.
const MAX_INSTR_GADGET: usize = 32;

/// Reconstruye el flujo a partir de los destinos de los saltos indirectos
/// (los `Tip` de la traza) y la imagen del codigo.
pub fn reconstruir(imagen: &Imagen, destinos: &[u64]) -> FlujoEjecucion {
    let mut gadgets = Vec::with_capacity(destinos.len());
    for &dir in destinos {
        gadgets.push(reconstruir_gadget(imagen, dir));
    }
    FlujoEjecucion { gadgets }
}

/// Desensambla desde `dir` hasta el primer salto indirecto o `ret`.
fn reconstruir_gadget(imagen: &Imagen, dir: u64) -> TransferenciaControl {
    let Some(code) = imagen.rango(dir) else {
        return TransferenciaControl {
            inicio: dir,
            num_instrucciones: 0,
            terminal: Terminal::NoEsGadget,
        };
    };
    let mut dec = Decoder::with_ip(64, code, dir, DecoderOptions::NONE);
    let mut instr = Instruction::default();
    let mut n = 0;
    while dec.can_decode() && n < MAX_INSTR_GADGET {
        dec.decode_out(&mut instr);
        n += 1;
        if let Some(t) = terminal_de(&instr) {
            return TransferenciaControl {
                inicio: dir,
                num_instrucciones: n,
                terminal: t,
            };
        }
    }
    TransferenciaControl {
        inicio: dir,
        num_instrucciones: n,
        terminal: Terminal::NoEsGadget,
    }
}

/// Clasifica la instruccion terminal, o `None` si no corta el gadget.
fn terminal_de(instr: &Instruction) -> Option<Terminal> {
    match instr.flow_control() {
        FlowControl::Return => Some(Terminal::Ret),
        FlowControl::IndirectBranch => Some(Terminal::SaltoIndirecto),
        FlowControl::IndirectCall => Some(Terminal::LlamadaIndirecta),
        _ => None,
    }
}
