//! Decodificador de instrucciones x86-64 para el subconjunto que soporta el
//! micro-sandbox.
//!
//! # Que subconjunto y por que
//!
//! No se decodifica el x86 entero —son cientos de opcodes, muchos irrelevantes
//! para el analisis de malware—. Se cubre lo que usan de verdad los
//! descompresores, los cifradores y el shellcode:
//!
//! - Movimiento de datos: `MOV` (todas las formas), `LEA`, `MOVZX`, `MOVSX`,
//!   `PUSH`, `POP`.
//! - Aritmetica y logica: `ADD`, `SUB`, `ADC`, `SBB`, `XOR`, `AND`, `OR`, `CMP`,
//!   `TEST`, `INC`, `DEC`, `NEG`, `NOT`, `IMUL` (dos operandos).
//! - Desplazamientos y rotaciones: `SHL`, `SHR`, `SAR`, `ROL`, `ROR` (las
//!   rotaciones aparecen en la criptografia de los empaquetadores).
//! - Control de flujo: `JMP`, `Jcc`, `CALL`, `RET`, `LOOP`.
//! - Frontera con el sistema: `SYSCALL`, `INT n`, `HLT`, `NOP`.
//!
//! Todo lo demas se rechaza con [`EmuError::InstruccionNoSoportada`]: el emulador
//! NUNCA finge ejecutar un opcode que no entiende.
//!
//! # Codificacion
//!
//! Se decodifican los prefijos heredados relevantes (`0x66` tamano de operando,
//! y `0xF0`/`0xF2`/`0xF3` se ignoran como prefijo), el prefijo `REX`
//! (`0x40`..`0x4F`, con sus bits W/R/X/B), el opcode (de uno o dos bytes con
//! `0x0F`), el byte `ModRM`, el `SIB`, el desplazamiento y el inmediato.

use crate::EmuError;

/// Condicion de un salto condicional (`Jcc`) o de `LOOPcc`. El nombre sigue la
/// nomenclatura de Intel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cond {
    /// Desbordamiento (OF=1).
    O,
    /// No desbordamiento.
    No,
    /// Por debajo / acarreo (CF=1).
    B,
    /// Por encima o igual (CF=0).
    Ae,
    /// Igual / cero (ZF=1).
    E,
    /// Distinto / no cero (ZF=0).
    Ne,
    /// Por debajo o igual (CF=1 o ZF=1).
    Be,
    /// Por encima (CF=0 y ZF=0).
    A,
    /// Signo (SF=1).
    S,
    /// No signo (SF=0).
    Ns,
    /// Paridad (PF=1).
    P,
    /// No paridad (PF=0).
    Np,
    /// Menor, con signo (SF!=OF).
    L,
    /// Mayor o igual, con signo (SF=OF).
    Ge,
    /// Menor o igual, con signo (ZF=1 o SF!=OF).
    Le,
    /// Mayor, con signo (ZF=0 y SF=OF).
    G,
}

impl Cond {
    /// Traduce el nibble bajo de un opcode `Jcc`/`SETcc` (0..15) a la condicion.
    fn desde_nibble(n: u8) -> Cond {
        match n & 0xF {
            0x0 => Cond::O,
            0x1 => Cond::No,
            0x2 => Cond::B,
            0x3 => Cond::Ae,
            0x4 => Cond::E,
            0x5 => Cond::Ne,
            0x6 => Cond::Be,
            0x7 => Cond::A,
            0x8 => Cond::S,
            0x9 => Cond::Ns,
            0xA => Cond::P,
            0xB => Cond::Np,
            0xC => Cond::L,
            0xD => Cond::Ge,
            0xE => Cond::Le,
            _ => Cond::G,
        }
    }
}

/// La operacion de una instruccion decodificada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// Copia `src` en `dst`.
    Mov,
    /// Copia con extension de ceros (`MOVZX`).
    Movzx,
    /// Copia con extension de signo (`MOVSX`).
    Movsx,
    /// Carga la direccion efectiva de `src` en `dst` (`LEA`).
    Lea,
    /// Suma.
    Add,
    /// Suma con acarreo.
    Adc,
    /// Resta.
    Sub,
    /// Resta con prestamo.
    Sbb,
    /// O exclusivo.
    Xor,
    /// Y logico.
    And,
    /// O logico.
    Or,
    /// Comparacion (resta que solo fija banderas).
    Cmp,
    /// Prueba (Y logico que solo fija banderas).
    Test,
    /// Multiplicacion con signo de dos operandos (`IMUL r, r/m`).
    Imul,
    /// Incremento.
    Inc,
    /// Decremento.
    Dec,
    /// Negacion aritmetica (complemento a dos).
    Neg,
    /// Negacion de bits (complemento a uno).
    Not,
    /// Desplazamiento logico a la izquierda.
    Shl,
    /// Desplazamiento logico a la derecha.
    Shr,
    /// Desplazamiento aritmetico a la derecha.
    Sar,
    /// Rotacion a la izquierda.
    Rol,
    /// Rotacion a la derecha.
    Ror,
    /// Mete `src` en la pila.
    Push,
    /// Saca de la pila a `dst`.
    Pop,
    /// Salto incondicional (a `dst`: relativo o registro/memoria).
    Jmp,
    /// Salto condicional (a `dst`, relativo).
    Jcc(Cond),
    /// Llamada (apila la direccion de retorno y salta a `dst`).
    Call,
    /// Retorno.
    Ret,
    /// Decrementa `rcx` y salta si no es cero (con la condicion opcional de
    /// `LOOPE`/`LOOPNE` sobre ZF).
    Loop(Option<bool>),
    /// Ninguna operacion.
    Nop,
    /// Llamada al sistema por `syscall` (`0F 05`).
    Syscall,
    /// Interrupcion software `INT n` (para `int 0x80`, la ABI de 32 bits).
    Int(u8),
    /// Detiene la emulacion (`HLT`).
    Hlt,
}

/// Un operando de memoria: `base + indice*escala + desplazamiento`, o relativo a
/// `rip`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mem {
    /// Registro base, si lo hay.
    pub base: Option<usize>,
    /// Registro indice, si lo hay.
    pub indice: Option<usize>,
    /// Escala del indice (1, 2, 4 u 8).
    pub escala: u8,
    /// Desplazamiento con signo.
    pub desp: i64,
    /// Si la direccion es relativa a `rip` (modo especial de x86-64).
    pub rip_relativo: bool,
}

/// Un operando decodificado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operando {
    /// Un registro por su indice (0..15).
    Reg(usize),
    /// El byte alto heredado de un registro clasico (`ah`..`bh`).
    Reg8Alto(usize),
    /// Un operando en memoria.
    Mem(Mem),
    /// Un valor inmediato, ya extendido a 64 bits segun corresponda.
    Imm(u64),
    /// Un desplazamiento relativo con signo (para saltos).
    Rel(i64),
    /// Sin operando.
    Ninguno,
}

/// Una instruccion decodificada, con su longitud en bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Instr {
    /// Bytes que ocupa (para avanzar `rip`).
    pub longitud: usize,
    /// La operacion.
    pub op: Op,
    /// Tamano del operando destino en bytes (1, 2, 4 u 8).
    pub tam: u8,
    /// Tamano del operando fuente en bytes. Igual a `tam` salvo en `MOVZX`/
    /// `MOVSX`, donde la fuente es mas pequena (1 o 2) que el destino.
    pub tam_fuente: u8,
    /// Operando destino.
    pub dst: Operando,
    /// Operando fuente.
    pub src: Operando,
}

/// Cursor de lectura sobre los bytes de codigo, que se queja si se pasa del
/// final.
struct Cursor<'a> {
    datos: &'a [u8],
    pos: usize,
    dir: u64,
}

impl<'a> Cursor<'a> {
    fn u8(&mut self) -> Result<u8, EmuError> {
        let b = *self
            .datos
            .get(self.pos)
            .ok_or(EmuError::CodigoTruncado(self.dir))?;
        self.pos += 1;
        Ok(b)
    }

    fn i8(&mut self) -> Result<i64, EmuError> {
        Ok(i64::from(self.u8()? as i8))
    }

    fn u16(&mut self) -> Result<u16, EmuError> {
        Ok(u16::from(self.u8()?) | (u16::from(self.u8()?) << 8))
    }

    fn i32(&mut self) -> Result<i64, EmuError> {
        let mut v = 0u32;
        for i in 0..4 {
            v |= u32::from(self.u8()?) << (i * 8);
        }
        Ok(i64::from(v as i32))
    }

    fn u64(&mut self) -> Result<u64, EmuError> {
        let mut v = 0u64;
        for i in 0..8 {
            v |= u64::from(self.u8()?) << (i * 8);
        }
        Ok(v)
    }
}

/// Los bits del prefijo REX.
#[derive(Default, Clone, Copy)]
struct Rex {
    presente: bool,
    w: bool,
    r: bool,
    x: bool,
    b: bool,
}

/// Decodifica una instruccion en `dir`, cuyos bytes son `codigo` (hasta 15).
///
/// # Errores
/// [`EmuError::InstruccionNoSoportada`] o [`EmuError::PrefijoNoSoportado`] si el
/// opcode/prefijo esta fuera del subconjunto; [`EmuError::CodigoTruncado`] si la
/// instruccion pide mas bytes de los disponibles.
pub fn decodificar(codigo: &[u8], dir: u64) -> Result<Instr, EmuError> {
    let mut c = Cursor {
        datos: codigo,
        pos: 0,
        dir,
    };

    // --- Prefijos -----------------------------------------------------------
    let mut op16 = false;
    let mut rex = Rex::default();
    loop {
        let b = c.u8()?;
        match b {
            0x66 => op16 = true,
            0xF0 | 0xF2 | 0xF3 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65 => {
                // lock/rep/segmentos: se ignoran como prefijo (el subconjunto no
                // tiene operaciones de cadena ni segmentacion real).
            }
            0x67 => {
                return Err(EmuError::PrefijoNoSoportado {
                    direccion: dir,
                    prefijo: 0x67,
                })
            }
            0x40..=0x4F => {
                rex = Rex {
                    presente: true,
                    w: b & 0x8 != 0,
                    r: b & 0x4 != 0,
                    x: b & 0x2 != 0,
                    b: b & 0x1 != 0,
                };
                break; // REX es el ultimo prefijo antes del opcode.
            }
            _ => {
                c.pos -= 1; // no era prefijo; devolverlo.
                break;
            }
        }
    }

    // Tamano de operando por defecto (para opcodes no-8-bit).
    let tam_def: u8 = if rex.w {
        8
    } else if op16 {
        2
    } else {
        4
    };

    let opcode = c.u8()?;

    // Helper de opcode no soportado.
    let no_sop = |c: &Cursor| EmuError::InstruccionNoSoportada {
        direccion: dir,
        opcode: format!("{opcode:#04x} (len {})", c.pos),
    };

    match opcode {
        // --- MOV r/m, r  y  r, r/m (0x88..0x8B) -----------------------------
        0x88..=0x8B => {
            let tam = if opcode & 1 == 0 { 1 } else { tam_def };
            let (reg, rm) = modrm(&mut c, &rex, tam)?;
            let (dst, src) = if opcode & 2 == 0 {
                (rm, reg_operando(reg, tam, rex.presente))
            } else {
                (reg_operando(reg, tam, rex.presente), rm)
            };
            instr(&c, Op::Mov, tam, dst, src)
        }
        // LEA r, m (0x8D)
        0x8D => {
            let (reg, rm) = modrm(&mut c, &rex, tam_def)?;
            instr(
                &c,
                Op::Lea,
                tam_def,
                reg_operando(reg, tam_def, rex.presente),
                rm,
            )
        }
        // MOV r/m, imm (0xC6 8-bit, 0xC7 tam)
        0xC6 | 0xC7 => {
            let tam = if opcode == 0xC6 { 1 } else { tam_def };
            let (_reg, rm) = modrm(&mut c, &rex, tam)?;
            let imm = leer_inmediato(&mut c, tam, true)?;
            instr(&c, Op::Mov, tam, rm, Operando::Imm(imm))
        }
        // MOV r8, imm8 (0xB0..0xB7)
        0xB0..=0xB7 => {
            let reg = (opcode & 0x7) as usize | ((rex.b as usize) << 3);
            let imm = u64::from(c.u8()?);
            instr(
                &c,
                Op::Mov,
                1,
                reg_operando(reg, 1, rex.presente),
                Operando::Imm(imm),
            )
        }
        // MOV r, imm (0xB8..0xBF): imm64 si REX.W, si no imm32.
        0xB8..=0xBF => {
            let reg = (opcode & 0x7) as usize | ((rex.b as usize) << 3);
            let (tam, imm) = if rex.w {
                (8, c.u64()?)
            } else if op16 {
                (2, u64::from(c.u16()?))
            } else {
                (4, u64::from(c.i32()? as u32))
            };
            instr(&c, Op::Mov, tam, Operando::Reg(reg), Operando::Imm(imm))
        }
        // MOVZX / MOVSX viven en 0x0F (ver abajo). Aqui la aritmetica r/m,r:
        0x00 | 0x01 | 0x08 | 0x09 | 0x10 | 0x11 | 0x18 | 0x19 | 0x20 | 0x21 | 0x28 | 0x29
        | 0x30 | 0x31 | 0x38 | 0x39 | 0x02 | 0x03 | 0x0A | 0x0B | 0x12 | 0x13 | 0x1A | 0x1B
        | 0x22 | 0x23 | 0x2A | 0x2B | 0x32 | 0x33 | 0x3A | 0x3B => {
            let op = match opcode & 0x38 {
                0x00 => Op::Add,
                0x08 => Op::Or,
                0x10 => Op::Adc,
                0x18 => Op::Sbb,
                0x20 => Op::And,
                0x28 => Op::Sub,
                0x30 => Op::Xor,
                _ => Op::Cmp,
            };
            let tam = if opcode & 1 == 0 { 1 } else { tam_def };
            let (reg, rm) = modrm(&mut c, &rex, tam)?;
            let (dst, src) = if opcode & 2 == 0 {
                (rm, reg_operando(reg, tam, rex.presente))
            } else {
                (reg_operando(reg, tam, rex.presente), rm)
            };
            instr(&c, op, tam, dst, src)
        }
        // TEST r/m, r (0x84 8-bit, 0x85 tam)
        0x84 | 0x85 => {
            let tam = if opcode == 0x84 { 1 } else { tam_def };
            let (reg, rm) = modrm(&mut c, &rex, tam)?;
            instr(&c, Op::Test, tam, rm, reg_operando(reg, tam, rex.presente))
        }
        // Aritmetica acumulador, imm (0x04/05, 0x0C/0D, 0x14/15, 0x1C/1D, 0x24/25, 0x2C/2D, 0x34/35, 0x3C/3D)
        0x04 | 0x05 | 0x0C | 0x0D | 0x14 | 0x15 | 0x1C | 0x1D | 0x24 | 0x25 | 0x2C | 0x2D
        | 0x34 | 0x35 | 0x3C | 0x3D => {
            let op = match opcode & 0x38 {
                0x00 => Op::Add,
                0x08 => Op::Or,
                0x10 => Op::Adc,
                0x18 => Op::Sbb,
                0x20 => Op::And,
                0x28 => Op::Sub,
                0x30 => Op::Xor,
                _ => Op::Cmp,
            };
            let tam = if opcode & 1 == 0 { 1 } else { tam_def };
            let imm = leer_inmediato(&mut c, tam, true)?;
            instr(&c, op, tam, Operando::Reg(0), Operando::Imm(imm))
        }
        // TEST acumulador, imm (0xA8/A9)
        0xA8 | 0xA9 => {
            let tam = if opcode == 0xA8 { 1 } else { tam_def };
            let imm = leer_inmediato(&mut c, tam, true)?;
            instr(&c, Op::Test, tam, Operando::Reg(0), Operando::Imm(imm))
        }
        // Grupo 1: r/m, imm (0x80 8-bit imm8, 0x81 imm, 0x83 imm8 con signo)
        0x80 | 0x81 | 0x83 => {
            let tam = if opcode == 0x80 { 1 } else { tam_def };
            let (reg, rm) = modrm(&mut c, &rex, tam)?;
            let op = match reg & 0x7 {
                0 => Op::Add,
                1 => Op::Or,
                2 => Op::Adc,
                3 => Op::Sbb,
                4 => Op::And,
                5 => Op::Sub,
                6 => Op::Xor,
                _ => Op::Cmp,
            };
            let imm = if opcode == 0x83 {
                c.i8()? as u64
            } else {
                leer_inmediato(&mut c, tam, true)?
            };
            instr(&c, op, tam, rm, Operando::Imm(imm))
        }
        // Grupo 2: desplazamientos/rotaciones
        0xC0 | 0xC1 | 0xD0 | 0xD1 | 0xD2 | 0xD3 => {
            let tam = if opcode & 1 == 0 { 1 } else { tam_def };
            let (reg, rm) = modrm(&mut c, &rex, tam)?;
            let op = match reg & 0x7 {
                0 => Op::Rol,
                1 => Op::Ror,
                4 | 6 => Op::Shl,
                5 => Op::Shr,
                7 => Op::Sar,
                _ => return Err(no_sop(&c)),
            };
            let cuenta = match opcode {
                0xC0 | 0xC1 => Operando::Imm(u64::from(c.u8()?)),
                0xD0 | 0xD1 => Operando::Imm(1),
                _ => Operando::Reg(1), // CL
            };
            instr(&c, op, tam, rm, cuenta)
        }
        // Grupo 3: 0xF6/0xF7 -> TEST/NOT/NEG
        0xF6 | 0xF7 => {
            let tam = if opcode == 0xF6 { 1 } else { tam_def };
            let (reg, rm) = modrm(&mut c, &rex, tam)?;
            match reg & 0x7 {
                0 | 1 => {
                    let imm = leer_inmediato(&mut c, tam, true)?;
                    instr(&c, Op::Test, tam, rm, Operando::Imm(imm))
                }
                2 => instr(&c, Op::Not, tam, rm, Operando::Ninguno),
                3 => instr(&c, Op::Neg, tam, rm, Operando::Ninguno),
                _ => Err(no_sop(&c)),
            }
        }
        // Grupo 0xFE: INC/DEC r/m8
        0xFE => {
            let (reg, rm) = modrm(&mut c, &rex, 1)?;
            let op = if reg & 0x7 == 0 { Op::Inc } else { Op::Dec };
            instr(&c, op, 1, rm, Operando::Ninguno)
        }
        // Grupo 0xFF: INC/DEC/CALL/JMP/PUSH r/m
        0xFF => {
            let (reg, rm) = modrm(&mut c, &rex, tam_def)?;
            match reg & 0x7 {
                0 => instr(&c, Op::Inc, tam_def, rm, Operando::Ninguno),
                1 => instr(&c, Op::Dec, tam_def, rm, Operando::Ninguno),
                2 => instr(&c, Op::Call, 8, rm, Operando::Ninguno),
                4 => instr(&c, Op::Jmp, 8, rm, Operando::Ninguno),
                6 => instr(&c, Op::Push, 8, rm, Operando::Ninguno),
                _ => Err(no_sop(&c)),
            }
        }
        // PUSH/POP r64 (0x50..0x5F)
        0x50..=0x57 => {
            let reg = (opcode & 0x7) as usize | ((rex.b as usize) << 3);
            instr(&c, Op::Push, 8, Operando::Reg(reg), Operando::Ninguno)
        }
        0x58..=0x5F => {
            let reg = (opcode & 0x7) as usize | ((rex.b as usize) << 3);
            instr(&c, Op::Pop, 8, Operando::Reg(reg), Operando::Ninguno)
        }
        // PUSH imm (0x68 imm32, 0x6A imm8)
        0x68 => {
            let imm = c.i32()? as u64;
            instr(&c, Op::Push, 8, Operando::Imm(imm), Operando::Ninguno)
        }
        0x6A => {
            let imm = c.i8()? as u64;
            instr(&c, Op::Push, 8, Operando::Imm(imm), Operando::Ninguno)
        }
        // CALL rel32 (0xE8), JMP rel32 (0xE9), JMP rel8 (0xEB)
        0xE8 => {
            let rel = c.i32()?;
            instr(&c, Op::Call, 8, Operando::Rel(rel), Operando::Ninguno)
        }
        0xE9 => {
            let rel = c.i32()?;
            instr(&c, Op::Jmp, 8, Operando::Rel(rel), Operando::Ninguno)
        }
        0xEB => {
            let rel = c.i8()?;
            instr(&c, Op::Jmp, 8, Operando::Rel(rel), Operando::Ninguno)
        }
        // Jcc rel8 (0x70..0x7F)
        0x70..=0x7F => {
            let rel = c.i8()?;
            instr(
                &c,
                Op::Jcc(Cond::desde_nibble(opcode)),
                8,
                Operando::Rel(rel),
                Operando::Ninguno,
            )
        }
        // LOOP/LOOPE/LOOPNE (0xE0..0xE2)
        0xE0 => {
            let rel = c.i8()?;
            instr(
                &c,
                Op::Loop(Some(false)),
                8,
                Operando::Rel(rel),
                Operando::Ninguno,
            )
        }
        0xE1 => {
            let rel = c.i8()?;
            instr(
                &c,
                Op::Loop(Some(true)),
                8,
                Operando::Rel(rel),
                Operando::Ninguno,
            )
        }
        0xE2 => {
            let rel = c.i8()?;
            instr(&c, Op::Loop(None), 8, Operando::Rel(rel), Operando::Ninguno)
        }
        // RET (0xC3), RET imm16 (0xC2)
        0xC3 => instr(&c, Op::Ret, 8, Operando::Imm(0), Operando::Ninguno),
        0xC2 => {
            let n = c.u16()?;
            instr(
                &c,
                Op::Ret,
                8,
                Operando::Imm(u64::from(n)),
                Operando::Ninguno,
            )
        }
        // NOP (0x90) / HLT (0xF4)
        0x90 => instr(&c, Op::Nop, tam_def, Operando::Ninguno, Operando::Ninguno),
        0xF4 => instr(&c, Op::Hlt, tam_def, Operando::Ninguno, Operando::Ninguno),
        // INT n (0xCD ib)
        0xCD => {
            let n = c.u8()?;
            instr(
                &c,
                Op::Int(n),
                tam_def,
                Operando::Ninguno,
                Operando::Ninguno,
            )
        }
        // Opcodes de dos bytes.
        0x0F => decodificar_0f(&mut c, &rex, tam_def, dir),
        _ => Err(no_sop(&c)),
    }
}

/// Decodifica un opcode de dos bytes (`0x0F ..`).
fn decodificar_0f(c: &mut Cursor, rex: &Rex, tam_def: u8, dir: u64) -> Result<Instr, EmuError> {
    let segundo = c.u8()?;
    match segundo {
        // SYSCALL
        0x05 => instr(
            c,
            Op::Syscall,
            tam_def,
            Operando::Ninguno,
            Operando::Ninguno,
        ),
        // NOP multibyte (0F 1F /0)
        0x1F => {
            let (_r, _rm) = modrm(c, rex, tam_def)?;
            instr(c, Op::Nop, tam_def, Operando::Ninguno, Operando::Ninguno)
        }
        // Jcc rel32 (0F 80..8F)
        0x80..=0x8F => {
            let rel = c.i32()?;
            instr(
                c,
                Op::Jcc(Cond::desde_nibble(segundo)),
                8,
                Operando::Rel(rel),
                Operando::Ninguno,
            )
        }
        // MOVZX (0F B6 r/m8, 0F B7 r/m16), MOVSX (0F BE, 0F BF)
        0xB6 | 0xB7 | 0xBE | 0xBF => {
            let tf = if segundo & 1 == 0 { 1 } else { 2 };
            let (reg, rm) = modrm(c, rex, tf)?;
            let op = if segundo < 0xBE { Op::Movzx } else { Op::Movsx };
            let mut ins = instr(c, op, tam_def, reg_operando(reg, tam_def, rex.presente), rm)?;
            ins.tam_fuente = tf;
            Ok(ins)
        }
        // IMUL r, r/m (0F AF)
        0xAF => {
            let (reg, rm) = modrm(c, rex, tam_def)?;
            instr(
                c,
                Op::Imul,
                tam_def,
                reg_operando(reg, tam_def, rex.presente),
                rm,
            )
        }
        _ => Err(EmuError::InstruccionNoSoportada {
            direccion: dir,
            opcode: format!("0x0f {segundo:#04x}"),
        }),
    }
}

/// Construye la instruccion con su longitud (la posicion del cursor).
fn instr(c: &Cursor, op: Op, tam: u8, dst: Operando, src: Operando) -> Result<Instr, EmuError> {
    Ok(Instr {
        longitud: c.pos,
        op,
        tam,
        tam_fuente: tam,
        dst,
        src,
    })
}

/// Un operando de registro del tamano dado, distinguiendo el byte alto heredado
/// (`ah`..`bh`) cuando el tamano es 1 y NO hay prefijo REX.
fn reg_operando(idx: usize, tam: u8, rex_presente: bool) -> Operando {
    if tam == 1 && !rex_presente && (4..8).contains(&idx) {
        Operando::Reg8Alto(idx - 4)
    } else {
        Operando::Reg(idx)
    }
}

/// Lee un inmediato de tamano de operando `tam`, con extension de signo cuando
/// `con_signo` y el operando es mayor que el inmediato (imm32 -> 64).
fn leer_inmediato(c: &mut Cursor, tam: u8, con_signo: bool) -> Result<u64, EmuError> {
    Ok(match tam {
        1 => {
            if con_signo {
                c.i8()? as u64
            } else {
                u64::from(c.u8()?)
            }
        }
        2 => u64::from(c.u16()?),
        _ => {
            // 4 y 8 bytes usan un inmediato de 32 bits (regla de x86-64);
            // extendido con signo a 64 cuando el operando es de 64.
            let v = c.i32()?;
            if tam == 8 && con_signo {
                v as u64
            } else {
                (v as u32) as u64
            }
        }
    })
}

/// Decodifica el byte ModRM (y SIB/desplazamiento). El operando r/m usa `tam_rm`
/// bytes; el operando de registro (el campo `reg`) lo dimensiona el llamante, que
/// en `MOVZX`/`MOVSX` es mayor que la fuente r/m.
fn modrm(c: &mut Cursor, rex: &Rex, tam_rm: u8) -> Result<(usize, Operando), EmuError> {
    let byte = c.u8()?;
    let modo = byte >> 6;
    let reg = ((byte >> 3) & 0x7) as usize | ((rex.r as usize) << 3);
    let rm = (byte & 0x7) as usize;

    if modo == 3 {
        // Operando r/m es un registro directo.
        let idx = rm | ((rex.b as usize) << 3);
        return Ok((reg, reg_operando(idx, tam_rm, rex.presente)));
    }

    // Operando en memoria.
    let mut base: Option<usize> = None;
    let mut indice: Option<usize> = None;
    let mut escala: u8 = 1;
    let mut rip_relativo = false;

    if rm == 4 {
        // Sigue un byte SIB.
        let sib = c.u8()?;
        escala = 1 << (sib >> 6);
        let idx = ((sib >> 3) & 0x7) as usize | ((rex.x as usize) << 3);
        let bas = (sib & 0x7) as usize | ((rex.b as usize) << 3);
        if idx != 4 {
            indice = Some(idx);
        }
        // base==5 con modo 0 -> sin base, desplazamiento de 32 bits.
        if (sib & 0x7) == 5 && modo == 0 {
            base = None;
        } else {
            base = Some(bas);
        }
    } else if rm == 5 && modo == 0 {
        // Relativo a rip.
        rip_relativo = true;
    } else {
        base = Some(rm | ((rex.b as usize) << 3));
    }

    let desp = match modo {
        0 => {
            if rip_relativo || (rm == 4 && base.is_none()) {
                c.i32()?
            } else {
                0
            }
        }
        1 => c.i8()?,
        _ => c.i32()?,
    };

    Ok((
        reg,
        Operando::Mem(Mem {
            base,
            indice,
            escala,
            desp,
            rip_relativo,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodifica_mov_reg_reg_64() {
        // 48 89 d8 = mov rax, rbx   (REX.W, 0x89 /r, ModRM 11 011 000)
        let i = decodificar(&[0x48, 0x89, 0xD8], 0).unwrap();
        assert_eq!(i.op, Op::Mov);
        assert_eq!(i.tam, 8);
        assert_eq!(i.dst, Operando::Reg(0)); // rax
        assert_eq!(i.src, Operando::Reg(3)); // rbx
        assert_eq!(i.longitud, 3);
    }

    #[test]
    fn decodifica_xor_reg_reg_32() {
        // 31 c0 = xor eax, eax
        let i = decodificar(&[0x31, 0xC0], 0).unwrap();
        assert_eq!(i.op, Op::Xor);
        assert_eq!(i.tam, 4);
        assert_eq!(i.dst, Operando::Reg(0));
        assert_eq!(i.src, Operando::Reg(0));
    }

    #[test]
    fn decodifica_mov_imm32() {
        // b8 2a 00 00 00 = mov eax, 0x2a
        let i = decodificar(&[0xB8, 0x2A, 0x00, 0x00, 0x00], 0).unwrap();
        assert_eq!(i.op, Op::Mov);
        assert_eq!(i.tam, 4);
        assert_eq!(i.dst, Operando::Reg(0));
        assert_eq!(i.src, Operando::Imm(0x2A));
    }

    #[test]
    fn decodifica_jmp_rel8_y_syscall() {
        // eb fe = jmp -2 (a si mismo)
        let i = decodificar(&[0xEB, 0xFE], 0).unwrap();
        assert_eq!(i.op, Op::Jmp);
        assert_eq!(i.src, Operando::Ninguno);
        assert_eq!(i.dst, Operando::Rel(-2));
        // 0f 05 = syscall
        let s = decodificar(&[0x0F, 0x05], 0).unwrap();
        assert_eq!(s.op, Op::Syscall);
        assert_eq!(s.longitud, 2);
    }

    #[test]
    fn decodifica_operando_de_memoria_con_desplazamiento() {
        // 8b 43 10 = mov eax, [rbx+0x10]
        let i = decodificar(&[0x8B, 0x43, 0x10], 0).unwrap();
        assert_eq!(i.op, Op::Mov);
        assert_eq!(i.dst, Operando::Reg(0));
        assert_eq!(
            i.src,
            Operando::Mem(Mem {
                base: Some(3),
                indice: None,
                escala: 1,
                desp: 0x10,
                rip_relativo: false,
            })
        );
    }

    #[test]
    fn opcode_no_soportado_falla_ruidosamente() {
        // f1 = INT1/ICEBP, fuera del subconjunto.
        let e = decodificar(&[0xF1], 0);
        assert!(matches!(e, Err(EmuError::InstruccionNoSoportada { .. })));
    }
}
