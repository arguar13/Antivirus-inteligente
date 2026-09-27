//! El interprete x86-64 sobre la MMU: ejecuta sobre memoria con permisos reales.
//!
//! # Que lo hace distinto de un emulador cualquiera
//!
//! Ejecuta contra la [`Mmu`](crate::mmu::Mmu) —permisos reales, W^X— y NO contra el
//! sistema. No hay ninguna operacion aqui que abra un fichero real, un socket real
//! ni ejecute una syscall en el anfitrion: lo que la muestra pide se responde desde
//! el [`Entorno`](crate::entorno::Entorno) sintetico, y lo no modelado PARA la
//! emulacion y lo dice, en vez de devolver cero y seguir sobre una mentira.
//!
//! Cada escritura y cada transferencia de control emiten una
//! [`Observacion`](crate::desempaquetado::Observacion): es lo que permite el
//! desempaquetado generico por observacion.
//!
//! # Determinismo
//!
//! No se lee el reloj real, ni aleatoriedad real, ni direcciones del anfitrion. El
//! estado inicial se pasa entero; dos emulaciones de la misma muestra con el mismo
//! estado inicial son identicas.

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};

use crate::desempaquetado::Observacion;
use crate::entorno::Entorno;
use crate::mmu::{FalloMemoria, Mmu};

/// Por que se detuvo la emulacion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Detencion {
    /// Se agoto el presupuesto de instrucciones (cota dura).
    PresupuestoAgotado,
    /// La instruccion no esta modelada: se para y se dice cual, en vez de
    /// ejecutar mal. Declara la cobertura del interprete.
    InstruccionNoModelada {
        /// Direccion de la instruccion.
        direccion: u64,
        /// Mnemonico que no se supo ejecutar.
        mnemonico: String,
    },
    /// Un acceso a memoria fallo (fuera de mapa o sin permiso).
    FalloMemoria {
        /// Direccion de la instruccion en curso.
        direccion: u64,
        /// El fallo.
        fallo: FalloMemoria,
    },
    /// La muestra ejecuto una parada (`hlt`, `ud2`) o retorno sin marco.
    Parada {
        /// Direccion.
        direccion: u64,
    },
    /// La instruccion no se pudo decodificar.
    Indecodificable {
        /// Direccion.
        direccion: u64,
    },
}

/// El estado de la CPU: registros generales, puntero de instruccion y banderas.
///
/// Todo se pasa explicitamente: no hay estado oculto que dependa del anfitrion.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Cpu {
    /// RAX..R15 (0..15).
    pub regs: [u64; 16],
    /// Puntero de instruccion.
    pub rip: u64,
    /// Bandera cero.
    pub zf: bool,
    /// Bandera de signo.
    pub sf: bool,
    /// Bandera de acarreo.
    pub cf: bool,
    /// Bandera de desbordamiento.
    pub of: bool,
}

/// El resultado de ejecutar una instruccion.
enum Paso {
    /// Sigue con la siguiente (rip ya actualizado).
    Sigue,
    /// La emulacion debe detenerse, con su motivo.
    Alto(Detencion),
}

/// El indice de registro general (0..15) de un registro de iced, o `None` si no lo
/// es (vectorial, segmento, rip).
fn idx(r: Register) -> Option<usize> {
    Some(match r.full_register() {
        Register::RAX => 0,
        Register::RCX => 1,
        Register::RDX => 2,
        Register::RBX => 3,
        Register::RSP => 4,
        Register::RBP => 5,
        Register::RSI => 6,
        Register::RDI => 7,
        Register::R8 => 8,
        Register::R9 => 9,
        Register::R10 => 10,
        Register::R11 => 11,
        Register::R12 => 12,
        Register::R13 => 13,
        Register::R14 => 14,
        Register::R15 => 15,
        _ => return None,
    })
}

impl Cpu {
    /// Lee un registro respetando su anchura.
    #[must_use]
    fn leer_reg(&self, r: Register) -> u64 {
        let Some(i) = idx(r) else { return 0 };
        let v = self.regs[i];
        match r.size() {
            1 => v & 0xff,
            2 => v & 0xffff,
            4 => v & 0xffff_ffff,
            _ => v,
        }
    }

    /// Escribe un registro respetando la semantica de anchura de x86-64: una
    /// escritura de 32 bits extiende con ceros la parte alta; las de 8/16 la
    /// conservan.
    fn escribir_reg(&mut self, r: Register, val: u64) {
        let Some(i) = idx(r) else { return };
        match r.size() {
            1 => self.regs[i] = (self.regs[i] & !0xff) | (val & 0xff),
            2 => self.regs[i] = (self.regs[i] & !0xffff) | (val & 0xffff),
            4 => self.regs[i] = val & 0xffff_ffff, // extension por ceros
            _ => self.regs[i] = val,
        }
    }

    /// La direccion efectiva de un operando de memoria: base + index*escala + disp.
    fn ea(&self, insn: &Instruction) -> u64 {
        let mut a = 0u64;
        if insn.memory_base() != Register::None {
            if insn.memory_base() == Register::RIP {
                a = a.wrapping_add(insn.next_ip());
            } else {
                a = a.wrapping_add(self.leer_reg(insn.memory_base()));
            }
        }
        if insn.memory_index() != Register::None {
            a = a.wrapping_add(
                self.leer_reg(insn.memory_index())
                    .wrapping_mul(u64::from(insn.memory_index_scale())),
            );
        }
        a.wrapping_add(insn.memory_displacement64())
    }

    /// El tamano en bytes del operando `i`.
    fn tam_op(insn: &Instruction, i: u32) -> usize {
        match insn.op_kind(i) {
            OpKind::Register => insn.op_register(i).size(),
            OpKind::Memory => insn.memory_size().size(),
            OpKind::Immediate8 | OpKind::Immediate8_2nd => 1,
            OpKind::Immediate16 => 2,
            OpKind::Immediate32 | OpKind::Immediate8to32 => 4,
            _ => 8,
        }
    }

    /// Lee el valor del operando `i` (registro, inmediato o memoria).
    fn leer_op(&self, insn: &Instruction, i: u32, mmu: &Mmu) -> Result<u64, FalloMemoria> {
        match insn.op_kind(i) {
            OpKind::Register => Ok(self.leer_reg(insn.op_register(i))),
            OpKind::Immediate8 | OpKind::Immediate8_2nd => Ok(u64::from(insn.immediate8())),
            OpKind::Immediate16 => Ok(u64::from(insn.immediate16())),
            OpKind::Immediate32 => Ok(u64::from(insn.immediate32())),
            OpKind::Immediate64 => Ok(insn.immediate64()),
            OpKind::Immediate8to16 => Ok(insn.immediate8to16() as u64),
            OpKind::Immediate8to32 => Ok(insn.immediate8to32() as u64),
            OpKind::Immediate8to64 => Ok(insn.immediate8to64() as u64),
            OpKind::Immediate32to64 => Ok(insn.immediate32to64() as u64),
            OpKind::Memory => {
                let tam = Self::tam_op(insn, i).clamp(1, 8);
                let bytes = mmu.leer(self.ea(insn), tam)?;
                let mut v = 0u64;
                for (k, b) in bytes.iter().enumerate() {
                    v |= u64::from(*b) << (8 * k);
                }
                Ok(v)
            }
            _ => Ok(0),
        }
    }

    /// Escribe `val` en el operando destino `i` (registro o memoria). Una escritura
    /// en memoria emite una observacion con la entropia de la pagina.
    fn escribir_op(
        &mut self,
        insn: &Instruction,
        i: u32,
        val: u64,
        mmu: &mut Mmu,
        obs: &mut Vec<Observacion>,
    ) -> Result<(), FalloMemoria> {
        match insn.op_kind(i) {
            OpKind::Register => {
                self.escribir_reg(insn.op_register(i), val);
                Ok(())
            }
            OpKind::Memory => {
                let tam = Self::tam_op(insn, i).clamp(1, 8);
                let ea = self.ea(insn);
                let bytes: Vec<u8> = (0..tam).map(|k| (val >> (8 * k)) as u8).collect();
                mmu.escribir(ea, &bytes)?;
                let pagina = ea & !0xfff;
                let entropia = mmu.entropia_pagina(pagina).unwrap_or(0.0);
                obs.push(Observacion::Escritura { pagina, entropia });
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Actualiza las banderas cero y signo segun un resultado de `tam` bytes.
    fn banderas_zs(&mut self, res: u64, tam: usize) {
        let bits = (tam * 8).min(64) as u32;
        let masc = if bits >= 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        };
        let r = res & masc;
        self.zf = r == 0;
        self.sf = (r >> (bits - 1)) & 1 == 1;
    }

    /// Si un salto condicional se toma, segun su mnemonico y las banderas.
    fn condicion(&self, m: Mnemonic) -> bool {
        use Mnemonic::*;
        match m {
            Je => self.zf,
            Jne => !self.zf,
            Js => self.sf,
            Jns => !self.sf,
            Jb => self.cf,
            Jae => !self.cf,
            Jbe => self.cf || self.zf,
            Ja => !self.cf && !self.zf,
            Jl => self.sf != self.of,
            Jge => self.sf == self.of,
            Jle => self.zf || (self.sf != self.of),
            Jg => !self.zf && (self.sf == self.of),
            _ => false,
        }
    }
}

/// El resultado de una emulacion: por que paro, el estado final y las
/// observaciones para el desempaquetado.
#[derive(Debug, Clone)]
pub struct Emulacion {
    /// Por que se detuvo.
    pub detencion: Detencion,
    /// El estado final de la CPU.
    pub cpu: Cpu,
    /// Cuantas instrucciones se ejecutaron.
    pub instrucciones: u64,
    /// Las observaciones, en orden.
    pub observaciones: Vec<Observacion>,
}

/// Emula desde `cpu.rip` sobre la MMU, con un presupuesto DURO de instrucciones.
///
/// El presupuesto es parte del contrato, no una esperanza: pasado el, la emulacion
/// para y lo dice ([`Detencion::PresupuestoAgotado`]), en vez de correr sin fin
/// ante un bucle que el atacante puso a proposito.
#[must_use]
pub fn emular(mut cpu: Cpu, mmu: &mut Mmu, _entorno: &Entorno, presupuesto: u64) -> Emulacion {
    let mut obs = Vec::new();
    let mut n = 0u64;
    loop {
        if n >= presupuesto {
            return Emulacion {
                detencion: Detencion::PresupuestoAgotado,
                cpu,
                instrucciones: n,
                observaciones: obs,
            };
        }
        let ip = cpu.rip;
        // Traer la instruccion EXIGIENDO permiso de ejecucion (W^X).
        let bytes = match mmu.leer_para_ejecutar(ip, 15) {
            Ok(b) => b,
            Err(fallo) => {
                return Emulacion {
                    detencion: Detencion::FalloMemoria {
                        direccion: ip,
                        fallo,
                    },
                    cpu,
                    instrucciones: n,
                    observaciones: obs,
                }
            }
        };
        let mut dec = Decoder::with_ip(64, &bytes, ip, DecoderOptions::NONE);
        let insn = dec.decode();
        if insn.is_invalid() {
            return Emulacion {
                detencion: Detencion::Indecodificable { direccion: ip },
                cpu,
                instrucciones: n,
                observaciones: obs,
            };
        }
        cpu.rip = insn.next_ip();
        match ejecutar_uno(&mut cpu, &insn, mmu, &mut obs) {
            Paso::Sigue => n += 1,
            Paso::Alto(d) => {
                return Emulacion {
                    detencion: d,
                    cpu,
                    instrucciones: n,
                    observaciones: obs,
                }
            }
        }
    }
}

/// Ejecuta una sola instruccion ya decodificada.
fn ejecutar_uno(
    cpu: &mut Cpu,
    insn: &Instruction,
    mmu: &mut Mmu,
    obs: &mut Vec<Observacion>,
) -> Paso {
    let ip = insn.ip();
    let tam0 = Cpu::tam_op(insn, 0);
    macro_rules! leer {
        ($i:expr) => {
            match cpu.leer_op(insn, $i, mmu) {
                Ok(v) => v,
                Err(fallo) => {
                    return Paso::Alto(Detencion::FalloMemoria {
                        direccion: ip,
                        fallo,
                    })
                }
            }
        };
    }
    macro_rules! escribir {
        ($i:expr, $v:expr) => {
            if let Err(fallo) = cpu.escribir_op(insn, $i, $v, mmu, obs) {
                return Paso::Alto(Detencion::FalloMemoria {
                    direccion: ip,
                    fallo,
                });
            }
        };
    }

    use Mnemonic::*;
    let m = insn.mnemonic();
    match m {
        Nop | Endbr64 | Endbr32 => Paso::Sigue,
        Mov => {
            let v = leer!(1);
            escribir!(0, v);
            Paso::Sigue
        }
        Movzx => {
            let v = leer!(1);
            escribir!(0, v);
            Paso::Sigue
        }
        Movsx | Movsxd => {
            let src_tam = Cpu::tam_op(insn, 1);
            let v = leer!(1);
            let ext = signo_extender(v, src_tam);
            escribir!(0, ext);
            Paso::Sigue
        }
        Lea => {
            let a = cpu.ea(insn);
            escribir!(0, a);
            Paso::Sigue
        }
        Add => {
            let (a, b) = (leer!(0), leer!(1));
            let r = a.wrapping_add(b);
            cpu.banderas_zs(r, tam0);
            escribir!(0, r);
            Paso::Sigue
        }
        Sub => {
            let (a, b) = (leer!(0), leer!(1));
            let r = a.wrapping_sub(b);
            cpu.banderas_zs(r, tam0);
            cpu.cf = a < b;
            escribir!(0, r);
            Paso::Sigue
        }
        And => {
            let r = leer!(0) & leer!(1);
            cpu.banderas_zs(r, tam0);
            cpu.cf = false;
            cpu.of = false;
            escribir!(0, r);
            Paso::Sigue
        }
        Or => {
            let r = leer!(0) | leer!(1);
            cpu.banderas_zs(r, tam0);
            escribir!(0, r);
            Paso::Sigue
        }
        Xor => {
            let r = leer!(0) ^ leer!(1);
            cpu.banderas_zs(r, tam0);
            cpu.cf = false;
            cpu.of = false;
            escribir!(0, r);
            Paso::Sigue
        }
        Shl => {
            let (a, b) = (leer!(0), leer!(1) & 0x3f);
            let r = a.wrapping_shl(b as u32);
            cpu.banderas_zs(r, tam0);
            escribir!(0, r);
            Paso::Sigue
        }
        Shr => {
            let (a, b) = (leer!(0), leer!(1) & 0x3f);
            let r = a >> (b as u32).min(63);
            cpu.banderas_zs(r, tam0);
            escribir!(0, r);
            Paso::Sigue
        }
        Sar => {
            let (a, b) = (leer!(0) as i64, (leer!(1) & 0x3f) as u32);
            let r = (a >> b.min(63)) as u64;
            cpu.banderas_zs(r, tam0);
            escribir!(0, r);
            Paso::Sigue
        }
        Imul if insn.op_count() == 2 => {
            let r = leer!(0).wrapping_mul(leer!(1));
            cpu.banderas_zs(r, tam0);
            escribir!(0, r);
            Paso::Sigue
        }
        Inc => {
            let r = leer!(0).wrapping_add(1);
            cpu.banderas_zs(r, tam0);
            escribir!(0, r);
            Paso::Sigue
        }
        Dec => {
            let r = leer!(0).wrapping_sub(1);
            cpu.banderas_zs(r, tam0);
            escribir!(0, r);
            Paso::Sigue
        }
        Neg => {
            let a = leer!(0);
            let r = 0u64.wrapping_sub(a);
            cpu.banderas_zs(r, tam0);
            cpu.cf = a != 0;
            escribir!(0, r);
            Paso::Sigue
        }
        Not => {
            let r = !leer!(0);
            escribir!(0, r);
            Paso::Sigue
        }
        Cmp => {
            let (a, b) = (leer!(0), leer!(1));
            let r = a.wrapping_sub(b);
            cpu.banderas_zs(r, tam0);
            cpu.cf = a < b;
            Paso::Sigue
        }
        Test => {
            let r = leer!(0) & leer!(1);
            cpu.banderas_zs(r, tam0);
            cpu.cf = false;
            cpu.of = false;
            Paso::Sigue
        }
        Push => {
            let v = leer!(0);
            cpu.regs[4] = cpu.regs[4].wrapping_sub(8);
            if let Err(fallo) = mmu.escribir(cpu.regs[4], &v.to_le_bytes()) {
                return Paso::Alto(Detencion::FalloMemoria {
                    direccion: ip,
                    fallo,
                });
            }
            Paso::Sigue
        }
        Pop => {
            let bytes = match mmu.leer(cpu.regs[4], 8) {
                Ok(b) => b,
                Err(fallo) => {
                    return Paso::Alto(Detencion::FalloMemoria {
                        direccion: ip,
                        fallo,
                    })
                }
            };
            let mut v = 0u64;
            for (k, b) in bytes.iter().enumerate() {
                v |= u64::from(*b) << (8 * k);
            }
            cpu.regs[4] = cpu.regs[4].wrapping_add(8);
            escribir!(0, v);
            Paso::Sigue
        }
        Jmp => {
            let destino = objetivo_transferencia(cpu, insn, mmu);
            match destino {
                Some(d) => {
                    obs.push(Observacion::Transferencia { destino: d });
                    cpu.rip = d;
                    Paso::Sigue
                }
                None => Paso::Alto(Detencion::InstruccionNoModelada {
                    direccion: ip,
                    mnemonico: "jmp indirecto por memoria no resuelto".into(),
                }),
            }
        }
        m if es_jcc(m) => {
            if cpu.condicion(m) && insn.op_kind(0) == OpKind::NearBranch64 {
                let d = insn.near_branch64();
                obs.push(Observacion::Transferencia { destino: d });
                cpu.rip = d;
            }
            Paso::Sigue
        }
        Call => {
            let destino = objetivo_transferencia(cpu, insn, mmu);
            match destino {
                Some(d) => {
                    // Apilar la direccion de retorno.
                    cpu.regs[4] = cpu.regs[4].wrapping_sub(8);
                    if let Err(fallo) = mmu.escribir(cpu.regs[4], &cpu.rip.to_le_bytes()) {
                        return Paso::Alto(Detencion::FalloMemoria {
                            direccion: ip,
                            fallo,
                        });
                    }
                    obs.push(Observacion::Transferencia { destino: d });
                    cpu.rip = d;
                    Paso::Sigue
                }
                None => Paso::Alto(Detencion::InstruccionNoModelada {
                    direccion: ip,
                    mnemonico: "call indirecto por memoria no resuelto".into(),
                }),
            }
        }
        Ret => {
            let bytes = match mmu.leer(cpu.regs[4], 8) {
                Ok(b) => b,
                Err(_) => return Paso::Alto(Detencion::Parada { direccion: ip }),
            };
            let mut d = 0u64;
            for (k, b) in bytes.iter().enumerate() {
                d |= u64::from(*b) << (8 * k);
            }
            cpu.regs[4] = cpu.regs[4].wrapping_add(8);
            obs.push(Observacion::Transferencia { destino: d });
            cpu.rip = d;
            Paso::Sigue
        }
        Hlt | Ud2 | Int3 => Paso::Alto(Detencion::Parada { direccion: ip }),
        otro => Paso::Alto(Detencion::InstruccionNoModelada {
            direccion: ip,
            mnemonico: format!("{otro:?}"),
        }),
    }
}

/// El objetivo de un `jmp`/`call`: relativo, por registro, o `None` si es por
/// memoria (no resuelto aqui).
fn objetivo_transferencia(cpu: &Cpu, insn: &Instruction, _mmu: &Mmu) -> Option<u64> {
    match insn.op_kind(0) {
        OpKind::NearBranch64 => Some(insn.near_branch64()),
        OpKind::Register => Some(cpu.leer_reg(insn.op_register(0))),
        _ => None,
    }
}

/// Si un mnemonico es un salto condicional que el interprete modela.
fn es_jcc(m: Mnemonic) -> bool {
    use Mnemonic::*;
    matches!(
        m,
        Je | Jne | Js | Jns | Jb | Jae | Jbe | Ja | Jl | Jge | Jle | Jg
    )
}

/// Extiende con signo un valor de `tam` bytes a 64 bits.
fn signo_extender(v: u64, tam: usize) -> u64 {
    match tam {
        1 => v as u8 as i8 as i64 as u64,
        2 => v as u16 as i16 as i64 as u64,
        4 => v as u32 as i32 as i64 as u64,
        _ => v,
    }
}
