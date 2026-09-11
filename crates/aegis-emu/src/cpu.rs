//! El estado de la CPU emulada: los 16 registros de proposito general de
//! x86-64, el puntero de instruccion y las banderas.
//!
//! Los registros se indexan 0..15 con la MISMA numeracion que la codificacion
//! de x86-64 (`rax`=0, `rcx`=1, `rdx`=2, `rbx`=3, `rsp`=4, `rbp`=5, `rsi`=6,
//! `rdi`=7, `r8`..`r15`=8..15), asi que el decodificador puede pasar el numero
//! de registro tal cual sale del byte ModRM/REX sin traducir.

/// Nombres de los 16 registros, para la traza y los mensajes de error.
pub const NOMBRES: [&str; 16] = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15",
];

/// Indice del puntero de pila (`rsp`).
pub const RSP: usize = 4;

/// Las banderas de estado que el subconjunto emulado necesita. No estan todas
/// las de x86 —falta la de acarreo auxiliar (AF), que ninguna instruccion del
/// subconjunto consulta—; se documenta en vez de fingir que se calculan.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Banderas {
    /// Acarreo (Carry Flag).
    pub cf: bool,
    /// Paridad (Parity Flag): 1 si el byte bajo del resultado tiene un numero
    /// par de bits a 1.
    pub pf: bool,
    /// Cero (Zero Flag).
    pub zf: bool,
    /// Signo (Sign Flag): el bit mas alto del resultado.
    pub sf: bool,
    /// Desbordamiento con signo (Overflow Flag).
    pub of: bool,
}

/// El estado completo de la CPU emulada.
#[derive(Debug, Clone)]
pub struct Cpu {
    /// Los 16 registros de proposito general.
    r: [u64; 16],
    /// Puntero de instruccion.
    pub rip: u64,
    /// Banderas de estado.
    pub banderas: Banderas,
}

impl Default for Cpu {
    fn default() -> Self {
        Self::nueva()
    }
}

impl Cpu {
    /// Una CPU con todos los registros a cero.
    #[must_use]
    pub fn nueva() -> Self {
        Self {
            r: [0; 16],
            rip: 0,
            banderas: Banderas::default(),
        }
    }

    /// Lee `idx` como un registro completo de 64 bits.
    #[must_use]
    pub fn leer64(&self, idx: usize) -> u64 {
        self.r[idx & 0xF]
    }

    /// Escribe `idx` como un registro completo de 64 bits.
    pub fn escribir64(&mut self, idx: usize, valor: u64) {
        self.r[idx & 0xF] = valor;
    }

    /// Lee el registro `idx` con un tamano de `tam` bytes (1, 2, 4 u 8). Para 1
    /// byte devuelve la parte BAJA (semantica REX: `al`, `cl`, ...); el byte alto
    /// heredado (`ah`, `bh`) se lee con [`Cpu::leer8_alto`].
    #[must_use]
    pub fn leer(&self, idx: usize, tam: u8) -> u64 {
        let v = self.r[idx & 0xF];
        match tam {
            1 => v & 0xFF,
            2 => v & 0xFFFF,
            4 => v & 0xFFFF_FFFF,
            _ => v,
        }
    }

    /// Escribe `valor` en el registro `idx` con un tamano de `tam` bytes,
    /// respetando la semantica de x86-64:
    ///
    /// - 8 bytes: registro completo.
    /// - 4 bytes: la parte baja Y **pone a cero los 32 bits altos** (regla de
    ///   x86-64 que sorprende a quien viene de x86 de 32 bits).
    /// - 2 y 1 bytes: solo la parte baja; el resto del registro se conserva.
    pub fn escribir(&mut self, idx: usize, tam: u8, valor: u64) {
        let i = idx & 0xF;
        match tam {
            1 => self.r[i] = (self.r[i] & !0xFF) | (valor & 0xFF),
            2 => self.r[i] = (self.r[i] & !0xFFFF) | (valor & 0xFFFF),
            4 => self.r[i] = valor & 0xFFFF_FFFF,
            _ => self.r[i] = valor,
        }
    }

    /// Lee el byte ALTO heredado de uno de los cuatro registros clasicos
    /// (`ah`=4, `ch`=5, `dh`=6, `bh`=7): los bits 8..15.
    #[must_use]
    pub fn leer8_alto(&self, idx_clasico: usize) -> u64 {
        (self.r[idx_clasico & 0x3] >> 8) & 0xFF
    }

    /// Escribe el byte ALTO heredado (`ah`, `ch`, `dh`, `bh`), conservando el
    /// resto del registro.
    pub fn escribir8_alto(&mut self, idx_clasico: usize, valor: u64) {
        let i = idx_clasico & 0x3;
        self.r[i] = (self.r[i] & !0xFF00) | ((valor & 0xFF) << 8);
    }

    /// Fija las banderas de paridad, cero y signo a partir de un `resultado` de
    /// `tam` bytes (lo comun a casi toda operacion aritmetica/logica).
    pub fn fijar_pzs(&mut self, resultado: u64, tam: u8) {
        let bits = u32::from(tam) * 8;
        let masc = mascara(tam);
        let r = resultado & masc;
        self.banderas.zf = r == 0;
        self.banderas.sf = (r >> (bits - 1)) & 1 == 1;
        self.banderas.pf = (r as u8).count_ones() % 2 == 0;
    }
}

/// La mascara de `tam` bytes (`0xFF`, `0xFFFF`, ...). Para 8 bytes es todo unos.
#[must_use]
pub fn mascara(tam: u8) -> u64 {
    match tam {
        1 => 0xFF,
        2 => 0xFFFF,
        4 => 0xFFFF_FFFF,
        _ => u64::MAX,
    }
}

/// El bit de signo de un valor de `tam` bytes.
#[must_use]
pub fn bit_signo(valor: u64, tam: u8) -> bool {
    let bits = u32::from(tam) * 8;
    (valor >> (bits - 1)) & 1 == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escribir_32_bits_pone_a_cero_la_parte_alta() {
        // Regla de x86-64: escribir eax borra los 32 bits altos de rax.
        let mut c = Cpu::nueva();
        c.escribir64(0, 0xDEAD_BEEF_CAFE_1234);
        c.escribir(0, 4, 0x1111_2222);
        assert_eq!(c.leer64(0), 0x0000_0000_1111_2222);
    }

    #[test]
    fn escribir_8_y_16_conserva_la_parte_alta() {
        let mut c = Cpu::nueva();
        c.escribir64(3, 0xAAAA_BBBB_CCCC_DDDD);
        c.escribir(3, 1, 0x42);
        assert_eq!(c.leer64(3), 0xAAAA_BBBB_CCCC_DD42);
        c.escribir(3, 2, 0x9999);
        assert_eq!(c.leer64(3), 0xAAAA_BBBB_CCCC_9999);
    }

    #[test]
    fn byte_alto_heredado_ah() {
        let mut c = Cpu::nueva();
        c.escribir64(0, 0x0000_0000_0000_1234); // rax
        assert_eq!(c.leer8_alto(0), 0x12); // ah = bits 8..15
        c.escribir8_alto(0, 0xFF);
        assert_eq!(c.leer64(0), 0x0000_0000_0000_FF34);
    }

    #[test]
    fn banderas_pzs() {
        let mut c = Cpu::nueva();
        c.fijar_pzs(0, 4);
        assert!(c.banderas.zf && !c.banderas.sf);
        c.fijar_pzs(0xFFFF_FFFF, 4);
        assert!(!c.banderas.zf && c.banderas.sf);
        // 0xFF tiene 8 bits a 1 -> paridad par -> PF=1.
        c.fijar_pzs(0xFF, 1);
        assert!(c.banderas.pf);
        // 0x07 tiene 3 bits a 1 -> impar -> PF=0.
        c.fijar_pzs(0x07, 1);
        assert!(!c.banderas.pf);
    }
}
