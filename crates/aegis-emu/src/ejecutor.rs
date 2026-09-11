//! El ejecutor: interpreta las instrucciones decodificadas sobre la CPU y la
//! memoria virtuales.
//!
//! Es donde se cierra la seguridad del micro-sandbox: cada instruccion del
//! binario desconocido se ejecuta AQUI, sobre estado virtual, con un presupuesto
//! que garantiza la terminacion. Las llamadas al sistema no se realizan: se
//! interceptan y se anotan como eventos. Y cuando el flujo salta a codigo que se
//! escribio durante la propia emulacion —un empaquetador desplegando su carga—,
//! se emite un evento de desempaquetado y la region queda disponible para
//! volcarla.

use crate::cpu::{bit_signo, mascara, Cpu, RSP};
use crate::decodificador::{decodificar, Cond, Mem, Op, Operando};
use crate::memoria::Memoria;
use crate::syscalls::{self, EventoComportamiento};
use crate::taint::{DeteccionDop, DetectorDop, EstadoTaint, UMBRAL_DOP_BYTES};
use crate::EmuError;

/// El ejecutor: CPU + memoria + la traza de comportamiento observada.
#[derive(Debug)]
pub struct Ejecutor {
    /// La CPU emulada.
    pub cpu: Cpu,
    /// La memoria emulada.
    pub mem: Memoria,
    eventos: Vec<EventoComportamiento>,
    instrucciones: u64,
    desempaquetados: Vec<(u64, u64)>,
    terminado: bool,
    /// Bump-allocator para dar a `mmap` una direccion real (asi los
    /// empaquetadores que reservan, escriben y saltan funcionan de verdad en el
    /// sandbox, no solo se observan).
    proxima_reserva: u64,
    /// Estado de contaminacion (taint) del flujo de datos, para detectar DOP.
    taint: EstadoTaint,
    /// Detector de programacion orientada a datos (FASE 63): escrituras masivas
    /// de datos contaminados sobre una estructura del sistema protegida.
    dop: DetectorDop,
    /// Acumulador de contaminacion de la instruccion en curso: el OR del taint de
    /// todos los operandos leidos, que se aplica al operando que se escribe.
    taint_acc: bool,
}

/// Base del espacio que reparte el `mmap` emulado.
const BASE_MMAP: u64 = 0x5000_0000;
/// Tope de tamano de una reserva, para que un `mmap` con una longitud absurda no
/// intente reservar gigas en el sandbox.
const MAX_RESERVA: u64 = 16 * 1024 * 1024;
/// Numero de syscall de `mmap` en x86-64.
const SYS_MMAP: u64 = 9;
/// Numero de syscall de `read` en x86-64: la fuente de datos del atacante.
const SYS_READ: u64 = 0;
/// Tope de bytes que un solo `read` contamina, para que un `count` absurdo no
/// haga crecer el seguimiento sin limite.
const MAX_CONTAMINAR: u64 = 64 * 1024;

impl Ejecutor {
    /// Un ejecutor sobre la CPU y la memoria dadas.
    #[must_use]
    pub fn nuevo(cpu: Cpu, mem: Memoria) -> Self {
        Self {
            cpu,
            mem,
            eventos: Vec::new(),
            instrucciones: 0,
            desempaquetados: Vec::new(),
            terminado: false,
            proxima_reserva: BASE_MMAP,
            taint: EstadoTaint::nuevo(),
            dop: DetectorDop::nuevo(UMBRAL_DOP_BYTES),
            taint_acc: false,
        }
    }

    /// Protege una region `[base, fin)` (una estructura del sistema) para la
    /// deteccion de DOP: una escritura masiva de datos contaminados sobre ella se
    /// declarara como un intento de programacion orientada a datos.
    pub fn proteger_region(&mut self, base: u64, fin: u64, nombre: &'static str) {
        self.dop.proteger(base, fin, nombre);
    }

    /// La deteccion de DOP, si el binario emulado la disparo.
    #[must_use]
    pub fn deteccion_dop(&self) -> Option<DeteccionDop> {
        self.dop.detectado()
    }

    /// Los eventos de comportamiento observados, en orden.
    #[must_use]
    pub fn eventos(&self) -> &[EventoComportamiento] {
        &self.eventos
    }

    /// Cuantas instrucciones se han ejecutado.
    #[must_use]
    pub fn instrucciones(&self) -> u64 {
        self.instrucciones
    }

    /// `true` si el binario termino por si mismo (ejecuto `HLT` o una syscall de
    /// salida).
    #[must_use]
    pub fn termino(&self) -> bool {
        self.terminado
    }

    /// Ejecuta hasta que el binario termine o se agote el presupuesto de `max`
    /// instrucciones.
    ///
    /// # Errores
    /// [`EmuError::PresupuestoAgotado`] si no termina en `max` instrucciones, o
    /// cualquier error de acceso/decodificacion.
    pub fn ejecutar(&mut self, max: u64) -> Result<(), EmuError> {
        while !self.terminado {
            if self.instrucciones >= max {
                return Err(EmuError::PresupuestoAgotado(max));
            }
            self.paso()?;
        }
        Ok(())
    }

    /// Ejecuta una sola instruccion.
    ///
    /// # Errores
    /// Cualquier error de acceso a memoria o de decodificacion.
    pub fn paso(&mut self) -> Result<(), EmuError> {
        let rip = self.cpu.rip;
        // Cada instruccion empieza sin contaminacion acumulada; los `leer_op` la
        // van sumando y el `escribir_op` la aplica al destino.
        self.taint_acc = false;

        // Deteccion de desempaquetado: se va a ejecutar codigo que se escribio en
        // tiempo de ejecucion (self-modifying / carga desplegada por el packer).
        if self.mem.fue_escrito(rip) {
            if let Some((base, fin)) = self.mem.rango_escrito(rip) {
                if !self.desempaquetados.contains(&(base, fin)) {
                    self.desempaquetados.push((base, fin));
                    self.eventos
                        .push(EventoComportamiento::Desempaquetado { base, fin });
                }
            }
        }

        let codigo = self.mem.leer_codigo(rip, 15);
        if codigo.is_empty() {
            return Err(EmuError::DireccionNoMapeada(rip));
        }
        let ins = decodificar(&codigo, rip)?;
        let sig = rip.wrapping_add(ins.longitud as u64);
        let tam = ins.tam;
        let mut nuevo_rip = sig;

        match ins.op {
            Op::Mov => {
                let v = self.leer_op(ins.src, ins.tam_fuente, sig)?;
                self.escribir_op(ins.dst, tam, sig, v)?;
            }
            Op::Movzx => {
                let v = self.leer_op(ins.src, ins.tam_fuente, sig)? & mascara(ins.tam_fuente);
                self.escribir_op(ins.dst, tam, sig, v)?;
            }
            Op::Movsx => {
                let v = self.leer_op(ins.src, ins.tam_fuente, sig)?;
                let s = ext_signo(v, ins.tam_fuente, 8);
                self.escribir_op(ins.dst, tam, sig, s)?;
            }
            Op::Lea => {
                if let Operando::Mem(m) = ins.src {
                    let d = self.dir_efectiva(&m, sig);
                    self.escribir_op(ins.dst, tam, sig, d)?;
                }
            }
            Op::Add
            | Op::Adc
            | Op::Sub
            | Op::Sbb
            | Op::Xor
            | Op::And
            | Op::Or
            | Op::Cmp
            | Op::Test
            | Op::Imul => {
                self.binaria(ins.op, ins.dst, ins.src, tam, sig)?;
            }
            Op::Inc => {
                let a = self.leer_op(ins.dst, tam, sig)?;
                let cf = self.cpu.banderas.cf; // INC conserva el acarreo.
                let r = self.f_suma(a, 1, tam);
                self.cpu.banderas.cf = cf;
                self.escribir_op(ins.dst, tam, sig, r)?;
            }
            Op::Dec => {
                let a = self.leer_op(ins.dst, tam, sig)?;
                let cf = self.cpu.banderas.cf;
                let r = self.f_resta(a, 1, tam);
                self.cpu.banderas.cf = cf;
                self.escribir_op(ins.dst, tam, sig, r)?;
            }
            Op::Neg => {
                let a = self.leer_op(ins.dst, tam, sig)?;
                let r = self.f_resta(0, a, tam);
                self.escribir_op(ins.dst, tam, sig, r)?;
            }
            Op::Not => {
                let a = self.leer_op(ins.dst, tam, sig)?;
                self.escribir_op(ins.dst, tam, sig, !a & mascara(tam))?;
            }
            Op::Shl | Op::Shr | Op::Sar | Op::Rol | Op::Ror => {
                self.desplazar(ins.op, ins.dst, ins.src, tam, sig)?;
            }
            Op::Push => {
                // El decodificador siempre deja el operando de PUSH en `dst`
                // (registro, memoria o inmediato).
                let v = self.leer_op(ins.dst, 8, sig)?;
                self.empujar(v)?;
            }
            Op::Pop => {
                let v = self.sacar()?;
                self.escribir_op(ins.dst, 8, sig, v)?;
            }
            Op::Jmp => {
                nuevo_rip = self.objetivo_salto(ins.dst, sig)?;
            }
            Op::Jcc(c) => {
                if self.condicion(c) {
                    nuevo_rip = self.objetivo_salto(ins.dst, sig)?;
                }
            }
            Op::Call => {
                let destino = self.objetivo_salto(ins.dst, sig)?;
                self.empujar(sig)?;
                nuevo_rip = destino;
            }
            Op::Ret => {
                let ret = self.sacar()?;
                if let Operando::Imm(n) = ins.dst {
                    let sp = self.cpu.leer64(RSP).wrapping_add(n);
                    self.cpu.escribir64(RSP, sp);
                }
                nuevo_rip = ret;
            }
            Op::Loop(cc) => {
                let rcx = self.cpu.leer64(1).wrapping_sub(1);
                self.cpu.escribir64(1, rcx);
                let cond_extra = match cc {
                    None => true,
                    Some(esperado_zf) => self.cpu.banderas.zf == esperado_zf,
                };
                if rcx != 0 && cond_extra {
                    nuevo_rip = self.objetivo_salto(ins.dst, sig)?;
                }
            }
            Op::Nop => {}
            Op::Hlt => self.terminado = true,
            Op::Syscall => {
                let numero = self.cpu.leer64(0); // rax
                let args = [
                    self.cpu.leer64(7),  // rdi
                    self.cpu.leer64(6),  // rsi
                    self.cpu.leer64(2),  // rdx
                    self.cpu.leer64(10), // r10
                    self.cpu.leer64(8),  // r8
                    self.cpu.leer64(9),  // r9
                ];
                let ev = syscalls::clasificar(numero, &args);
                self.registrar_syscall(ev);
                // Un `read` mete en memoria datos que controla el atacante: se
                // contamina el buffer de destino (rsi), la fuente del taint para
                // la deteccion de DOP. El volumen se acota para no crecer sin fin.
                if numero == SYS_READ {
                    let n = args[2].min(MAX_CONTAMINAR);
                    self.taint.contaminar_entrada(args[1], n);
                }
                if numero == SYS_MMAP {
                    let dir = self.reservar(args[1], args[2]);
                    self.cpu.escribir64(0, dir);
                } else {
                    self.cpu.escribir64(0, 0); // retorno benigno para continuar.
                }
            }
            Op::Int(0x80) => {
                let numero = self.cpu.leer(0, 4); // eax
                let ev = syscalls::clasificar_int80(numero);
                self.registrar_syscall(ev);
                self.cpu.escribir(0, 4, 0);
            }
            Op::Int(n) => {
                self.eventos.push(EventoComportamiento::LlamadaSistema {
                    numero: u64::from(n),
                    nombre: "int",
                    categoria: syscalls::Categoria::Otra,
                });
            }
        }

        self.cpu.rip = nuevo_rip;
        self.instrucciones += 1;
        Ok(())
    }

    /// Anota un evento de syscall y, si es de salida, marca la emulacion como
    /// terminada.
    fn registrar_syscall(&mut self, ev: EventoComportamiento) {
        if let EventoComportamiento::LlamadaSistema {
            categoria: syscalls::Categoria::Salida,
            ..
        } = ev
        {
            self.terminado = true;
        }
        self.eventos.push(ev);
    }

    /// La direccion de destino de un salto/llamada: relativa (a la siguiente
    /// instruccion) o el valor de un registro/memoria.
    fn objetivo_salto(&mut self, op: Operando, sig: u64) -> Result<u64, EmuError> {
        match op {
            Operando::Rel(rel) => Ok(sig.wrapping_add(rel as u64)),
            otro => self.leer_op(otro, 8, sig),
        }
    }

    fn condicion(&self, c: Cond) -> bool {
        let b = &self.cpu.banderas;
        match c {
            Cond::O => b.of,
            Cond::No => !b.of,
            Cond::B => b.cf,
            Cond::Ae => !b.cf,
            Cond::E => b.zf,
            Cond::Ne => !b.zf,
            Cond::Be => b.cf || b.zf,
            Cond::A => !b.cf && !b.zf,
            Cond::S => b.sf,
            Cond::Ns => !b.sf,
            Cond::P => b.pf,
            Cond::Np => !b.pf,
            Cond::L => b.sf != b.of,
            Cond::Ge => b.sf == b.of,
            Cond::Le => b.zf || (b.sf != b.of),
            Cond::G => !b.zf && (b.sf == b.of),
        }
    }

    fn empujar(&mut self, valor: u64) -> Result<(), EmuError> {
        let sp = self.cpu.leer64(RSP).wrapping_sub(8);
        self.mem.escribir(sp, valor, 8)?;
        self.cpu.escribir64(RSP, sp);
        Ok(())
    }

    fn sacar(&mut self) -> Result<u64, EmuError> {
        let sp = self.cpu.leer64(RSP);
        let v = self.mem.leer(sp, 8)?;
        self.cpu.escribir64(RSP, sp.wrapping_add(8));
        Ok(v)
    }

    /// Reserva una region para el `mmap` emulado, con los permisos derivados de
    /// `prot`, y devuelve su direccion base (o `-1` si no cabe). Asi un
    /// empaquetador que hace `p = mmap(RWX); escribir en p; saltar a p` funciona
    /// de verdad dentro del sandbox.
    fn reservar(&mut self, longitud: u64, prot: u64) -> u64 {
        let len = longitud.clamp(1, MAX_RESERVA);
        let len = (len + 0xFFF) & !0xFFF; // redondear a pagina.
        let base = self.proxima_reserva;
        let (mut r, w, x) = (prot & 0x1 != 0, prot & 0x2 != 0, prot & 0x4 != 0);
        // PROT_NONE se trata como legible: el interes es observar, no reproducir
        // un fallo de proteccion.
        if !r && !w && !x {
            r = true;
        }
        match self.mem.mapear_vacia(base, len as usize, r || x, w, x) {
            Ok(()) => {
                self.proxima_reserva = base.wrapping_add(len).wrapping_add(0x1000);
                base
            }
            Err(_) => u64::MAX,
        }
    }

    /// Una operacion binaria con banderas.
    fn binaria(
        &mut self,
        op: Op,
        dst: Operando,
        src: Operando,
        tam: u8,
        sig: u64,
    ) -> Result<(), EmuError> {
        let a = self.leer_op(dst, tam, sig)?;
        let b = self.leer_op(src, tam, sig)?;
        let m = mascara(tam);
        let res = match op {
            Op::Add => self.f_suma(a, b, tam),
            Op::Sub => self.f_resta(a, b, tam),
            Op::Cmp => {
                self.f_resta(a, b, tam);
                return Ok(());
            }
            Op::Xor => self.f_logica(a ^ b, tam),
            Op::And => self.f_logica(a & b, tam),
            Op::Or => self.f_logica(a | b, tam),
            Op::Test => {
                self.f_logica(a & b, tam);
                return Ok(());
            }
            Op::Adc => {
                let c = u64::from(self.cpu.banderas.cf);
                let r = (a & m).wrapping_add(b & m).wrapping_add(c) & m;
                self.cpu.banderas.cf =
                    (u128::from(a & m) + u128::from(b & m) + u128::from(c)) > u128::from(m);
                self.cpu.banderas.of = bit_signo(a, tam) == bit_signo(b, tam)
                    && bit_signo(r, tam) != bit_signo(a, tam);
                self.cpu.fijar_pzs(r, tam);
                r
            }
            Op::Sbb => {
                let c = u128::from(self.cpu.banderas.cf);
                let resta = u128::from(b & m) + c;
                self.cpu.banderas.cf = u128::from(a & m) < resta;
                let r = (u128::from(a & m).wrapping_sub(resta) as u64) & m;
                self.cpu.banderas.of = bit_signo(a, tam) != bit_signo(b, tam)
                    && bit_signo(r, tam) != bit_signo(a, tam);
                self.cpu.fijar_pzs(r, tam);
                r
            }
            Op::Imul => {
                let sa = i128::from(ext_signo(a, tam, 8) as i64);
                let sb = i128::from(ext_signo(b, tam, 8) as i64);
                let prod = sa * sb;
                let r = (prod as u64) & m;
                let cabe = i128::from(ext_signo(r, tam, 8) as i64) == prod;
                self.cpu.banderas.cf = !cabe;
                self.cpu.banderas.of = !cabe;
                self.cpu.fijar_pzs(r, tam);
                r
            }
            _ => unreachable!("binaria con op no binaria"),
        };
        self.escribir_op(dst, tam, sig, res)
    }

    /// Un desplazamiento o rotacion.
    fn desplazar(
        &mut self,
        op: Op,
        dst: Operando,
        cuenta: Operando,
        tam: u8,
        sig: u64,
    ) -> Result<(), EmuError> {
        let a = self.leer_op(dst, tam, sig)? & mascara(tam);
        let bits = u32::from(tam) * 8;
        let masc_cnt = if tam == 8 { 0x3F } else { 0x1F };
        let cnt = (self.leer_op(cuenta, 1, sig)? & masc_cnt) as u32;
        if cnt == 0 {
            return Ok(()); // x86: un desplazamiento de 0 no toca las banderas.
        }
        let m = mascara(tam);
        let res = match op {
            Op::Shl => {
                let r = ((u128::from(a) << cnt) as u64) & m;
                self.cpu.banderas.cf = cnt <= bits && (a >> (bits - cnt)) & 1 == 1;
                self.cpu.fijar_pzs(r, tam);
                r
            }
            Op::Shr => {
                let r = if cnt >= 64 { 0 } else { a >> cnt } & m;
                self.cpu.banderas.cf = (a >> (cnt - 1)) & 1 == 1;
                self.cpu.fijar_pzs(r, tam);
                r
            }
            Op::Sar => {
                let s = ext_signo(a, tam, 8) as i64;
                let r = (if cnt >= 64 {
                    (s >> 63) as u64
                } else {
                    (s >> cnt) as u64
                }) & m;
                self.cpu.banderas.cf = (a >> (cnt - 1)) & 1 == 1;
                self.cpu.fijar_pzs(r, tam);
                r
            }
            Op::Rol => {
                let n = cnt % bits;
                let r = if n == 0 {
                    a
                } else {
                    ((a << n) | (a >> (bits - n))) & m
                };
                self.cpu.banderas.cf = r & 1 == 1;
                r
            }
            Op::Ror => {
                let n = cnt % bits;
                let r = if n == 0 {
                    a
                } else {
                    ((a >> n) | (a << (bits - n))) & m
                };
                self.cpu.banderas.cf = bit_signo(r, tam);
                r
            }
            _ => unreachable!("desplazar con op no de desplazamiento"),
        };
        self.escribir_op(dst, tam, sig, res)
    }

    // --- Banderas -----------------------------------------------------------

    fn f_suma(&mut self, a: u64, b: u64, tam: u8) -> u64 {
        let m = mascara(tam);
        let (a, b) = (a & m, b & m);
        let res = a.wrapping_add(b) & m;
        self.cpu.banderas.cf = (u128::from(a) + u128::from(b)) > u128::from(m);
        self.cpu.banderas.of =
            bit_signo(a, tam) == bit_signo(b, tam) && bit_signo(res, tam) != bit_signo(a, tam);
        self.cpu.fijar_pzs(res, tam);
        res
    }

    fn f_resta(&mut self, a: u64, b: u64, tam: u8) -> u64 {
        let m = mascara(tam);
        let (a, b) = (a & m, b & m);
        let res = a.wrapping_sub(b) & m;
        self.cpu.banderas.cf = a < b;
        self.cpu.banderas.of =
            bit_signo(a, tam) != bit_signo(b, tam) && bit_signo(res, tam) != bit_signo(a, tam);
        self.cpu.fijar_pzs(res, tam);
        res
    }

    fn f_logica(&mut self, res: u64, tam: u8) -> u64 {
        let res = res & mascara(tam);
        self.cpu.banderas.cf = false;
        self.cpu.banderas.of = false;
        self.cpu.fijar_pzs(res, tam);
        res
    }

    // --- Operandos ----------------------------------------------------------

    fn dir_efectiva(&self, m: &Mem, sig: u64) -> u64 {
        if m.rip_relativo {
            return sig.wrapping_add(m.desp as u64);
        }
        let mut dir = m.desp as u64;
        if let Some(b) = m.base {
            dir = dir.wrapping_add(self.cpu.leer64(b));
        }
        if let Some(i) = m.indice {
            dir = dir.wrapping_add(self.cpu.leer64(i).wrapping_mul(u64::from(m.escala)));
        }
        dir
    }

    fn leer_op(&mut self, op: Operando, tam: u8, sig: u64) -> Result<u64, EmuError> {
        match op {
            Operando::Reg(i) => {
                if self.taint.reg_contaminado(i) {
                    self.taint_acc = true;
                }
                Ok(self.cpu.leer(i, tam))
            }
            Operando::Reg8Alto(i) => {
                if self.taint.reg_contaminado(i & 0x3) {
                    self.taint_acc = true;
                }
                Ok(self.cpu.leer8_alto(i))
            }
            Operando::Mem(m) => {
                let d = self.dir_efectiva(&m, sig);
                if self.taint.mem_contaminada(d, tam) {
                    self.taint_acc = true;
                }
                self.mem.leer(d, tam as usize)
            }
            Operando::Imm(v) => Ok(v & mascara(tam)),
            Operando::Rel(_) | Operando::Ninguno => Ok(0),
        }
    }

    fn escribir_op(&mut self, op: Operando, tam: u8, sig: u64, val: u64) -> Result<(), EmuError> {
        // La contaminacion acumulada por los `leer_op` de esta instruccion es la
        // que hereda el destino.
        let contaminado = self.taint_acc;
        match op {
            Operando::Reg(i) => {
                self.cpu.escribir(i, tam, val);
                self.taint.marcar_reg(i, contaminado);
                Ok(())
            }
            Operando::Reg8Alto(i) => {
                self.cpu.escribir8_alto(i, val);
                self.taint.marcar_reg(i & 0x3, contaminado);
                Ok(())
            }
            Operando::Mem(m) => {
                let d = self.dir_efectiva(&m, sig);
                self.mem.escribir(d, val, tam as usize)?;
                self.taint.marcar_mem(d, tam, contaminado);
                // El corazon de la deteccion de DOP: datos contaminados escritos,
                // en masa, sobre una estructura del sistema protegida.
                if contaminado {
                    self.dop.observar_escritura_contaminada(d, tam);
                }
                Ok(())
            }
            Operando::Imm(_) | Operando::Rel(_) | Operando::Ninguno => Ok(()),
        }
    }
}

/// Extiende con signo un valor de `desde` bytes a `hasta` bytes.
fn ext_signo(valor: u64, desde: u8, hasta: u8) -> u64 {
    let bits = u32::from(desde) * 8;
    let desplazamiento = 64 - bits;
    let s = ((valor << desplazamiento) as i64) >> desplazamiento;
    (s as u64) & mascara(hasta)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::syscalls::Categoria;

    /// Monta un ejecutor con una region de codigo en 0x1000 (RX) y una pila en
    /// 0x7000 (RW), con rsp apuntando cerca del tope.
    fn con_codigo(codigo: &[u8]) -> Ejecutor {
        let mut mem = Memoria::nueva();
        mem.mapear(0x1000, codigo.to_vec(), true, false, true)
            .unwrap();
        mem.mapear_vacia(0x7000, 0x1000, true, true, false).unwrap();
        let mut cpu = Cpu::nueva();
        cpu.rip = 0x1000;
        cpu.escribir64(RSP, 0x7F00);
        Ejecutor::nuevo(cpu, mem)
    }

    #[test]
    fn suma_en_bucle_con_loop() {
        // xor eax,eax; mov ecx,5; add eax,ecx; loop -4; hlt
        // Suma 5+4+3+2+1 = 15 en eax.
        let codigo = [
            0x31, 0xC0, // xor eax, eax
            0xB9, 0x05, 0x00, 0x00, 0x00, // mov ecx, 5
            0x01, 0xC8, // add eax, ecx
            0xE2, 0xFC, // loop -4 (a add)
            0xF4, // hlt
        ];
        let mut e = con_codigo(&codigo);
        e.ejecutar(1000).unwrap();
        assert!(e.termino());
        assert_eq!(e.cpu.leer(0, 4), 15);
    }

    #[test]
    fn cmp_y_salto_condicional() {
        // mov eax,7; cmp eax,7; jne +5 (saltar el mov); mov ebx,1; hlt; mov ebx,2; hlt
        // Como 7==7, NO salta: ebx=1.
        let codigo = [
            0xB8, 0x07, 0x00, 0x00, 0x00, // mov eax,7      (1000..1004)
            0x83, 0xF8, 0x07, // cmp eax,7             (1005..1007)
            0x75, 0x07, // jne +7 -> 1011              (1008..1009), sig=100A
            0xBB, 0x01, 0x00, 0x00, 0x00, // mov ebx,1  (100A..100E)
            0xF4, // hlt                                (100F)
            0xBB, 0x02, 0x00, 0x00, 0x00, // mov ebx,2  (1010..1014)  <- si saltara
            0xF4, // hlt
        ];
        let mut e = con_codigo(&codigo);
        e.ejecutar(1000).unwrap();
        assert_eq!(e.cpu.leer(3, 4), 1, "7==7 no debe saltar");
    }

    #[test]
    fn push_pop_por_la_pila() {
        // mov rax, 0x1234; push rax; pop rbx; hlt  -> rbx == 0x1234
        let codigo = [
            0x48, 0xC7, 0xC0, 0x34, 0x12, 0x00, 0x00, // mov rax, 0x1234
            0x50, // push rax
            0x5B, // pop rbx
            0xF4, // hlt
        ];
        let mut e = con_codigo(&codigo);
        e.ejecutar(1000).unwrap();
        assert_eq!(e.cpu.leer64(3), 0x1234);
    }

    #[test]
    fn syscall_exit_emite_salida_y_termina() {
        // mov eax,60 (exit); xor edi,edi; syscall
        let codigo = [
            0xB8, 0x3C, 0x00, 0x00, 0x00, // mov eax,60
            0x31, 0xFF, // xor edi,edi
            0x0F, 0x05, // syscall
        ];
        let mut e = con_codigo(&codigo);
        e.ejecutar(1000).unwrap();
        assert!(e.termino());
        assert!(matches!(
            e.eventos().last(),
            Some(EventoComportamiento::LlamadaSistema {
                categoria: Categoria::Salida,
                ..
            })
        ));
    }

    #[test]
    fn bucle_infinito_agota_el_presupuesto() {
        // eb fe = jmp -2 (a si mismo): el emulador NO se cuelga, corta.
        let mut e = con_codigo(&[0xEB, 0xFE]);
        assert_eq!(e.ejecutar(500), Err(EmuError::PresupuestoAgotado(500)));
        assert_eq!(e.instrucciones(), 500);
    }

    /// Monta el escenario del exploit DOP: codigo en 0x1000, un buffer de entrada
    /// en 0x2000, una "estructura del sistema" en 0x9000 y una pila. `con_read`
    /// decide si el binario arranca con la syscall `read` (la fuente del taint).
    fn escenario_dop(codigo: &[u8]) -> Ejecutor {
        let mut mem = Memoria::nueva();
        mem.mapear(0x1000, codigo.to_vec(), true, false, true)
            .unwrap();
        mem.mapear_vacia(0x2000, 0x1000, true, true, false).unwrap(); // buffer de entrada
        mem.mapear_vacia(0x9000, 0x1000, true, true, false).unwrap(); // "estructura del SO"
        mem.mapear_vacia(0x7000, 0x1000, true, true, false).unwrap(); // pila
        let mut cpu = Cpu::nueva();
        cpu.rip = 0x1000;
        cpu.escribir64(RSP, 0x7F00);
        cpu.escribir64(6, 0x2000); // rsi = buffer (destino de read, origen de la copia)
        cpu.escribir64(2, 64); // rdx = count del read
        cpu.escribir64(8, 0x9000); // r8 = destino: la region protegida
        cpu.escribir64(1, 8); // rcx = 8 iteraciones del bucle de copia
        let mut e = Ejecutor::nuevo(cpu, mem);
        e.proteger_region(0x9000, 0x9100, "tabla del sistema");
        e
    }

    #[test]
    fn un_exploit_dop_escribe_datos_del_atacante_sobre_una_estructura_protegida() {
        // read() contamina el buffer, y el bucle copia esos datos contaminados EN
        // MASA sobre la region protegida, byte a byte, SIN ninguna syscall que
        // autorice tocar esa estructura. Eso es DOP.
        //   syscall            ; rax=0 (read), rsi=buf, rdx=64 -> contamina [buf,buf+64)
        // copia:
        //   mov rax, [rsi] ; mov [r8], rax ; add rsi,8 ; add r8,8 ; loop copia ; hlt
        let codigo = [
            0x0F, 0x05, // syscall
            0x48, 0x8B, 0x06, // mov rax, [rsi]
            0x49, 0x89, 0x00, // mov [r8], rax
            0x48, 0x83, 0xC6, 0x08, // add rsi, 8
            0x49, 0x83, 0xC0, 0x08, // add r8, 8
            0xE2, 0xF0, // loop -16 (a la copia, en 0x1002)
            0xF4, // hlt
        ];
        let mut e = escenario_dop(&codigo);
        e.ejecutar(10_000).unwrap();
        let dop = e
            .deteccion_dop()
            .expect("una escritura masiva contaminada sobre la region protegida es DOP");
        assert_eq!(dop.region, "tabla del sistema");
        assert!(dop.bytes >= 64, "al menos 64 bytes contaminados escritos");
    }

    #[test]
    fn la_misma_copia_pero_sin_datos_del_atacante_no_es_dop() {
        // Identico bucle de copia a la region protegida, pero SIN el read: los
        // datos no estan contaminados, asi que escribir la estructura no es un
        // ataque (es codigo legitimo copiando datos limpios). El bucle arranca en
        // 0x1000, asi que el loop vuelve a 0x1000.
        let codigo = [
            0x48, 0x8B, 0x06, // mov rax, [rsi]
            0x49, 0x89, 0x00, // mov [r8], rax
            0x48, 0x83, 0xC6, 0x08, // add rsi, 8
            0x49, 0x83, 0xC0, 0x08, // add r8, 8
            0xE2, 0xF0, // loop -16 (a 0x1000)
            0xF4, // hlt
        ];
        let mut e = escenario_dop(&codigo);
        e.ejecutar(10_000).unwrap();
        assert!(
            e.deteccion_dop().is_none(),
            "copiar datos limpios a la estructura no es DOP"
        );
    }

    #[test]
    fn rol_y_shr_funcionan() {
        // mov al, 0x81; rol al, 1 -> 0x03 (bit alto rota al bajo)
        let codigo = [
            0xB0, 0x81, // mov al, 0x81
            0xC0, 0xC0, 0x01, // rol al, 1
            0xF4, // hlt
        ];
        let mut e = con_codigo(&codigo);
        e.ejecutar(100).unwrap();
        assert_eq!(e.cpu.leer(0, 1), 0x03);
    }
}
