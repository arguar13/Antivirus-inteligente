//! Desensamblado de x86 y x86-64, sobre `iced-x86`.
//!
//! # Por que `iced-x86` y no un decodificador propio
//!
//! Es la decision contraria a la de [`crate::arm64`], y las dos son la misma
//! regla aplicada a dos casos distintos.
//!
//! x86-64 no es una codificacion, es un sedimento: prefijos heredados, REX, VEX,
//! EVEX, opcodes de uno, dos y tres bytes, ModRM, SIB, y una tabla que cambia
//! segun el modo. Escribirlo entero en casa son anos, y un decodificador
//! incompleto **no falla ruidosamente**: lee una instruccion de cinco bytes
//! como una de tres y todo lo que viene detras queda desplazado, produciendo un
//! desensamblado que parece correcto y no lo es. Esa es la peor forma de fallar
//! que puede tener esta pieza.
//!
//! `iced-x86` entra con **cero dependencias transitivas**, es Rust puro, y ya
//! estaba en la linea base del agente —justificado para la reconstruccion de
//! Intel PT en `aegis-ptguard`—. No hay ninguna lectura de la disciplina de
//! dependencias de este proyecto que lo rechace.
//!
//! # Lo que este modulo anade por encima
//!
//! `iced-x86` decodifica. Lo que hace falta aqui es lo de despues: traducir su
//! modelo al modelo comun de [`crate::instruccion`], para que el grafo y las
//! reglas no sepan de que arquitectura vienen. La traduccion no es mecanica en
//! un punto concreto, y esta documentado donde ocurre: `syscall` y `int` llegan
//! de `iced` clasificadas como llamada, y aqui son **frontera con el nucleo**,
//! porque para el grafo de llamadas no son una arista y para las reglas si son
//! un hecho.

use std::cell::RefCell;

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, InstructionInfoFactory,
    InstructionInfoOptions, IntelFormatter, Mnemonic, OpAccess, OpKind, Register,
};

use crate::error::DisasmError;
use crate::instruccion::{Arquitectura, Clase, Flujo, Instruccion, Registros, MAX_INMEDIATOS};
use crate::plazo::Plazo;

thread_local! {
    /// La fabrica de informacion de registros de `iced`, reutilizada.
    ///
    /// `InstructionInfoFactory::new()` reserva dos vectores, y `info()` los
    /// vacia y los rellena sin volver a reservar. Construir una por instruccion
    /// serian dos asignaciones por instruccion en el bucle mas caliente del
    /// crate; construir una por hilo y reutilizarla son dos en total.
    ///
    /// Va en `thread_local` y no dentro de [`Tramo`] porque `info()` necesita
    /// `&mut` y `Tramo` es una vista compartida e inmutable —el grafo la usa
    /// por `&self`—. Meterle una celda mutable obligaria a que toda la cadena
    /// de llamadas fuera `&mut`, para un detalle de rendimiento que no tiene
    /// nada que ver con lo que esa cadena hace.
    ///
    /// El prestamo no se solapa consigo mismo: `registros_de` lo toma, lo usa y
    /// lo suelta sin llamar a nada que vuelva a entrar aqui.
    static INFO: RefCell<InstructionInfoFactory> = RefCell::new(InstructionInfoFactory::new());
}

/// Un tramo de codigo x86 listo para desensamblar.
///
/// Es solo una vista: no copia los bytes ni los modifica. Y no ejecuta nada —lo
/// prohibe la invariante 8 del megaprompt— ni tiene forma de hacerlo, porque no
/// hay en todo el crate un camino que transfiera control a estos bytes.
#[derive(Debug, Clone, Copy)]
pub struct Tramo<'a> {
    bytes: &'a [u8],
    base: u64,
    bitness: u32,
}

impl<'a> Tramo<'a> {
    /// Abre un tramo de codigo cargado en `base`.
    pub fn nuevo(bytes: &'a [u8], base: u64, arq: Arquitectura) -> Result<Tramo<'a>, DisasmError> {
        let bitness = match arq {
            Arquitectura::X86 => 32,
            Arquitectura::X86_64 => 64,
            Arquitectura::Arm64 => {
                return Err(DisasmError::ArquitecturaNoSoportada(
                    "arm64 no se decodifica aqui: ver el modulo arm64".into(),
                ))
            }
        };
        Ok(Tramo {
            bytes,
            base,
            bitness,
        })
    }

    /// Principio del tramo.
    pub fn base(&self) -> u64 {
        self.base
    }

    /// Final del tramo, exclusivo.
    pub fn fin(&self) -> u64 {
        self.base.saturating_add(self.bytes.len() as u64)
    }

    /// Si una direccion cae dentro.
    pub fn contiene(&self, direccion: u64) -> bool {
        direccion >= self.base && direccion < self.fin()
    }

    /// Desplazamiento de una direccion dentro del tramo.
    fn offset(&self, direccion: u64) -> Result<usize, DisasmError> {
        if !self.contiene(direccion) {
            return Err(DisasmError::FueraDelTramo {
                direccion,
                base: self.base,
                fin: self.fin(),
            });
        }
        Ok((direccion - self.base) as usize)
    }

    /// Decodifica la instruccion que empieza en `direccion`.
    pub fn en(&self, direccion: u64) -> Result<Instruccion, DisasmError> {
        let off = self.offset(direccion)?;
        let mut d = Decoder::with_ip(self.bitness, self.bytes, self.base, DecoderOptions::NONE);
        d.set_position(off)
            .map_err(|_| DisasmError::NoDecodificable { direccion })?;
        d.set_ip(direccion);
        let i = d.decode();
        if i.is_invalid() || i.len() == 0 {
            return Err(DisasmError::NoDecodificable { direccion });
        }
        Ok(traducir(&i, self.bitness))
    }

    /// Recorrido lineal desde `desde` hasta donde llegue el plazo.
    ///
    /// Es el barrido que alimenta el descubrimiento de funciones. Una direccion
    /// que no decodifica **no detiene el recorrido**: en un binario real hay
    /// datos entre funciones, tablas de saltos y relleno, y pararse en el primer
    /// byte que no sea una instruccion dejaria sin analizar todo lo que viene
    /// detras. Se avanza un byte y se sigue, y el contador de fallos entra en la
    /// cobertura.
    pub fn lineal(&self, desde: u64, plazo: &mut Plazo) -> (Vec<Instruccion>, usize) {
        let mut v = Vec::new();
        let mut fallos = 0usize;
        let mut pc = desde;
        while self.contiene(pc) && plazo.sigue() {
            match self.en(pc) {
                Ok(i) => {
                    // La invariante que impide el cuelgue: si un decodificador
                    // devolviera longitud cero, el cursor no avanzaria nunca.
                    // No deberia pasar con `iced`, y aun asi se comprueba,
                    // porque el coste es una comparacion y lo que evita es que
                    // el agente se quede colgado con un fichero.
                    debug_assert!(i.valida());
                    if !i.valida() {
                        fallos += 1;
                        pc = pc.wrapping_add(1);
                        continue;
                    }
                    pc = i.siguiente();
                    v.push(i);
                }
                Err(_) => {
                    fallos += 1;
                    pc = pc.wrapping_add(1);
                }
            }
        }
        (v, fallos)
    }
}

/// El texto de la instruccion que hay en `direccion`, en sintaxis Intel.
///
/// Se formatea **a la carta** y no se guarda: ver la nota de
/// [`crate::instruccion`]. Lo usan la evidencia de una capacidad —unas decenas
/// de instrucciones— y las pruebas que cotejan contra `objdump`.
pub fn texto_en(bytes: &[u8], base: u64, direccion: u64, arq: Arquitectura) -> Option<String> {
    let t = Tramo::nuevo(bytes, base, arq).ok()?;
    let off = t.offset(direccion).ok()?;
    let mut d = Decoder::with_ip(t.bitness, bytes, base, DecoderOptions::NONE);
    d.set_position(off).ok()?;
    d.set_ip(direccion);
    let i = d.decode();
    if i.is_invalid() {
        return None;
    }
    let mut f = IntelFormatter::new();
    let mut s = String::new();
    f.format(&i, &mut s);
    Some(s)
}

/// Traduce una instruccion de `iced` al modelo comun.
fn traducir(i: &iced_x86::Instruction, bitness: u32) -> Instruccion {
    let clase = clasificar(i.mnemonic());
    let flujo = flujo_de(i, clase);
    let regs = registros_de(i, bitness);
    // Las dos constantes se anulan si los registros no respaldan lo que
    // afirman. Un `mov al, 1` lleva un inmediato y NO define `RAX`; dejar ahi el
    // valor obligaria a quien lo consuma a acordarse de mirar `regs` antes de
    // usarlo, y el dia que a alguien se le olvide, el analisis resolvera una
    // llamada indirecta hacia una direccion inventada. La invariante se guarda
    // en el dato, no en la disciplina de quien lo lee.
    let valor_definido = valor_definido_de(i).filter(|_| regs.definidos != 0);
    let copia_de = copia_de_de(i).filter(|_| regs.definidos != 0);
    let delta = delta_de(i).filter(|_| match regs.unico_escrito() {
        Some(r) => regs.lee(r),
        None => false,
    });
    Instruccion {
        direccion: i.ip(),
        longitud: i.len() as u8,
        clase,
        flujo,
        inmediatos: inmediatos_de(i),
        lee_memoria: toca_memoria(i),
        // Aproximacion deliberada y acotada: en x86 el operando destino es el
        // primero. Una escritura a memoria es entonces un primer operando de
        // tipo memoria. Es exacto para todo lo que las reglas miran —`mov
        // [x], y`, `stos`, `push`— y se queda corto en casos raros de varios
        // operandos de memoria. Se prefiere quedarse corto: una regla que no
        // dispara se nota, y una que dispara de mas enteria el informe.
        escribe_memoria: i.op_count() > 0 && i.op0_kind() == OpKind::Memory,
        regs,
        valor_definido,
        copia_de,
        delta,
        destino_reg: destino_reg_de(i, flujo),
    }
}

/// El registro del que sale el destino de una transferencia indirecta.
///
/// Solo lo hay cuando el destino esta **en un registro**: un `call [rip+0x2f10]`
/// lo tiene en memoria y aqui devuelve `None`, que es la respuesta correcta
/// —ese destino no se resuelve desensamblando, se resuelve mirando lo que hay
/// en esa posicion, y eso lo hace el resolvedor de importaciones con la tabla
/// del contenedor, no el analisis de constantes.
fn destino_reg_de(i: &iced_x86::Instruction, flujo: Flujo) -> Option<u8> {
    if !flujo.indirecta() {
        return None;
    }
    if i.op_count() == 0 || i.op0_kind() != OpKind::Register {
        return None;
    }
    numero_de_registro(i.op0_register())
}

/// El numero comun de un registro general de x86, o `None` si no lo es.
///
/// La numeracion es la de `iced` dentro del bloque de 64 bits (`RAX`=0 … `R15`
/// =15), y se llega a ella desde cualquier anchura normalizando primero al
/// registro completo. Asi `AL`, `AX`, `EAX` y `RAX` dan todos el mismo numero,
/// que es lo que permite que el analisis de constantes siga el rastro cuando el
/// compilador mezcla anchuras —que es lo normal.
fn numero_de_registro(r: Register) -> Option<u8> {
    let completo = r.full_register();
    if !completo.is_gpr64() {
        return None;
    }
    Some((completo as u32 - Register::RAX as u32) as u8)
}

/// Los registros generales que la instruccion modifica, segun `iced`.
///
/// # Por que no se deduce del primer operando
///
/// Porque el primer operando no es el conjunto de escritura. `xchg rax, rbx`
/// escribe dos registros y solo nombra uno como primero; `mul rbx` escribe `RAX`
/// y `RDX` sin nombrar ninguno de los dos; `cpuid` escribe cuatro y no tiene
/// operandos; y una `call` deja indefinidos todos los registros volatiles de la
/// convencion de llamada. Una deduccion por operandos se queda corta justo en
/// esos casos, y quedarse corto aqui significa que el analisis conserva un valor
/// que el programa ya piso —y acaba resolviendo un `call rax` hacia una
/// direccion a la que nadie llama.
///
/// `iced` lleva la tabla de uso de registros del conjunto de instrucciones
/// entero, implicitos incluidos. Se usa esa.
///
/// # La excepcion de la llamada
///
/// La tabla de `iced` describe la instruccion, no la funcion que hay al otro
/// lado: para una `call`, `used_registers` trae `RSP` y `RIP`, no los registros
/// que el callee vaya a pisar. Como el analisis no sabe que hace el callee, una
/// llamada invalida **todos** los registros generales. Es la suposicion segura:
/// puede costar una resolucion, nunca puede inventarla.
fn registros_de(i: &iced_x86::Instruction, bitness: u32) -> Registros {
    let mut r = Registros::nada();
    INFO.with(|f| {
        let mut f = f.borrow_mut();
        let info = f.info_options(i, InstructionInfoOptions::NO_MEMORY_USAGE);
        for u in info.used_registers() {
            let Some(n) = numero_de_registro(u.register()) else {
                continue;
            };
            if matches!(
                u.access(),
                OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite
            ) {
                r.anota_leido(n);
            }
            if !matches!(
                u.access(),
                OpAccess::Write
                    | OpAccess::CondWrite
                    | OpAccess::ReadWrite
                    | OpAccess::ReadCondWrite
            ) {
                continue;
            }
            // Solo una escritura incondicional y de anchura suficiente DEFINE el
            // registro. `cmovz rax, rbx` puede no ocurrir, y `mov al, 1` deja
            // intactos 56 bits: en los dos casos el valor anterior deja de ser
            // fiable pero el nuevo tampoco lo es.
            if u.access() == OpAccess::Write && define_entero(u.register(), bitness) {
                r.anota_definido(n);
            } else {
                r.anota_escrito(n);
            }
        }
    });
    if matches!(
        i.flow_control(),
        FlowControl::Call | FlowControl::IndirectCall | FlowControl::Interrupt
    ) {
        r.escritos = u32::MAX;
        r.definidos = 0;
    }
    r
}

/// El valor exacto que la instruccion deja en el registro que define.
///
/// Son las tres formas en que x86 pone una constante en un registro sin depender
/// de nada anterior:
///
/// - `mov reg, imm`, que es la evidente;
/// - `lea reg, [rip+d]`, que es como el codigo independiente de posicion —todo
///   el codigo moderno— se calcula una direccion, y donde `iced` ya devuelve la
///   direccion absoluta resuelta;
/// - `xor reg, reg` (y `sub reg, reg`), el cero idiomatico, que un analisis que
///   no lo reconozca lee como «valor desconocido» y pierde el rastro.
fn valor_definido_de(i: &iced_x86::Instruction) -> Option<u64> {
    if i.op_count() < 2 || i.op0_kind() != OpKind::Register {
        return None;
    }
    match i.mnemonic() {
        Mnemonic::Mov => match i.op1_kind() {
            OpKind::Immediate8
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64 => Some(i.immediate(1)),
            _ => None,
        },
        Mnemonic::Lea if i.is_ip_rel_memory_operand() => Some(i.ip_rel_memory_address()),
        // `xor eax, eax` y `sub eax, eax` valen cero pase lo que pase. Se exige
        // que los dos operandos sean el MISMO registro: `xor eax, ebx` no.
        Mnemonic::Xor | Mnemonic::Sub
            if i.op1_kind() == OpKind::Register && i.op0_register() == i.op1_register() =>
        {
            Some(0)
        }
        _ => None,
    }
}

/// El registro cuyo valor pasa tal cual al registro que se define.
///
/// Solo el `mov` puro entre dos registros. `movsxd rax, ebx` **no** vale: extiende
/// el signo, asi que el valor de `RAX` no es el de `RBX` en cuanto el bit alto de
/// `EBX` este puesto, y dar por igual lo que no lo es es como se resuelve una
/// llamada hacia una direccion equivocada.
fn copia_de_de(i: &iced_x86::Instruction) -> Option<u8> {
    if i.mnemonic() != Mnemonic::Mov || i.op_count() < 2 {
        return None;
    }
    if i.op0_kind() != OpKind::Register || i.op1_kind() != OpKind::Register {
        return None;
    }
    numero_de_registro(i.op1_register())
}

/// La constante que la instruccion suma al registro que lee y escribe.
///
/// Es la otra mitad de la formacion de direcciones en dos pasos. Se exige que el
/// primer operando sea registro y el segundo inmediato: `add rax, rbx` no suma
/// una constante, suma algo que el analisis no conoce, y confundirlos daria un
/// valor inventado.
///
/// La resta lleva el signo cambiado —es lo mismo con otro nombre—, y el
/// `wrapping_neg` sobre `i64` es exacto para cualquier inmediato de x86, que
/// nunca pasa de 64 bits con signo.
fn delta_de(i: &iced_x86::Instruction) -> Option<i64> {
    if i.op_count() < 2 || i.op0_kind() != OpKind::Register {
        return None;
    }
    let inmediato = matches!(
        i.op1_kind(),
        OpKind::Immediate8
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
    );
    match i.mnemonic() {
        Mnemonic::Add if inmediato => Some(i.immediate(1) as i64),
        Mnemonic::Sub if inmediato => Some((i.immediate(1) as i64).wrapping_neg()),
        // `lea rax, [rax+8]` es una suma con otro nombre, y el compilador la usa
        // precisamente para sumar sin tocar las banderas. Solo cuenta si la base
        // es el mismo registro que el destino y no hay indice.
        Mnemonic::Lea
            if i.memory_base() == i.op0_register()
                && i.memory_index() == Register::None
                && !i.is_ip_rel_memory_operand() =>
        {
            Some(i.memory_displacement64() as i64)
        }
        _ => None,
    }
}

/// Si escribir `r` deja definido su registro completo.
///
/// En 64 bits, escribir un registro de 32 bits extiende con ceros la parte alta
/// —`mov eax, 1` deja `RAX` valiendo exactamente 1—, asi que cuenta como
/// definicion entera. Escribir `AL` o `AX` no: conservan bits anteriores. En 32
/// bits, el registro de 32 bits ya es el completo.
fn define_entero(r: Register, bitness: u32) -> bool {
    match r.size() {
        8 => true,
        4 => bitness >= 32,
        _ => false,
    }
}

/// Si alguno de los operandos es memoria.
fn toca_memoria(i: &iced_x86::Instruction) -> bool {
    (0..i.op_count()).any(|n| i.op_kind(n) == OpKind::Memory)
}

/// Las constantes inmediatas que lleva la instruccion, acotadas.
fn inmediatos_de(i: &iced_x86::Instruction) -> Vec<u64> {
    let mut v = Vec::new();
    for n in 0..i.op_count() {
        if v.len() >= MAX_INMEDIATOS {
            break;
        }
        let k = i.op_kind(n);
        let es_inmediato = matches!(
            k,
            OpKind::Immediate8
                | OpKind::Immediate8_2nd
                | OpKind::Immediate16
                | OpKind::Immediate32
                | OpKind::Immediate64
                | OpKind::Immediate8to16
                | OpKind::Immediate8to32
                | OpKind::Immediate8to64
                | OpKind::Immediate32to64
        );
        if es_inmediato {
            v.push(i.immediate(n));
        }
    }
    // El desplazamiento de memoria tambien es una constante que el binario
    // lleva escrita, y hay reglas que la miran —un acceso a un desplazamiento
    // fijo de la PEB, por ejemplo—. Se anade solo si queda sitio y si no es
    // cero, porque el cero es el desplazamiento por defecto de cualquier
    // `[reg]` y saturaria de ruido el analisis de constantes.
    if v.len() < MAX_INMEDIATOS && toca_memoria(i) && i.memory_displacement64() != 0 {
        v.push(i.memory_displacement64());
    }
    v
}

/// Traduce el control de flujo de `iced` al del modelo comun.
fn flujo_de(i: &iced_x86::Instruction, clase: Clase) -> Flujo {
    // Esto va ANTES de mirar `flow_control`, y es la unica parte de la
    // traduccion que no es mecanica. `iced` clasifica `syscall`, `sysenter` e
    // `int n` dentro del control de flujo de llamada, que es correcto para un
    // emulador y equivocado para un grafo de llamadas: no son una arista a otra
    // funcion del binario, son el borde del programa. Para las reglas, en
    // cambio, son un hecho de primera.
    if clase == Clase::Syscall {
        return Flujo::Frontera;
    }
    match i.flow_control() {
        FlowControl::Next | FlowControl::XbeginXabortXend => Flujo::Secuencial,
        FlowControl::UnconditionalBranch => Flujo::SaltoIncondicional {
            destino: destino_cercano(i),
        },
        FlowControl::IndirectBranch => Flujo::SaltoIncondicional { destino: None },
        FlowControl::ConditionalBranch => match destino_cercano(i) {
            Some(d) => Flujo::SaltoCondicional { destino: d },
            // Un salto condicional sin destino calculable no existe en x86, pero
            // si `iced` devolviera uno, tratarlo como secuencial seria inventar
            // una arista que no esta. Se cuenta como indirecto.
            None => Flujo::SaltoIncondicional { destino: None },
        },
        FlowControl::Return => Flujo::Retorno,
        FlowControl::Call => Flujo::Llamada {
            destino: destino_cercano(i),
        },
        FlowControl::IndirectCall => Flujo::Llamada { destino: None },
        FlowControl::Interrupt => Flujo::Frontera,
        FlowControl::Exception => Flujo::Parada,
    }
}

/// El destino de una rama cercana, si el operando lo lleva.
fn destino_cercano(i: &iced_x86::Instruction) -> Option<u64> {
    match i.op0_kind() {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            Some(i.near_branch_target())
        }
        _ => None,
    }
}

/// De que clase es un mnemonico.
///
/// La lista no pretende clasificar el conjunto de instrucciones de x86: cubre lo
/// que las reglas de capacidades preguntan. Lo demas cae en [`Clase::Otra`], que
/// es una respuesta correcta y no un hueco.
fn clasificar(m: Mnemonic) -> Clase {
    use Mnemonic as M;
    match m {
        M::Mov | M::Movzx | M::Movsx | M::Movsxd | M::Cmove | M::Cmovne => Clase::Mov,
        M::Lea => Clase::Direccion,
        M::Push | M::Pushfq | M::Pushfd | M::Pusha | M::Pushad => Clase::Push,
        M::Pop | M::Popfq | M::Popfd | M::Popa | M::Popad => Clase::Pop,
        M::Add
        | M::Sub
        | M::Adc
        | M::Sbb
        | M::Inc
        | M::Dec
        | M::Neg
        | M::Imul
        | M::Mul
        | M::Idiv
        | M::Div
        | M::Xadd => Clase::Aritmetica,
        M::And | M::Or | M::Xor | M::Not => Clase::Logica,
        M::Shl | M::Shr | M::Sar | M::Rol | M::Ror | M::Rcl | M::Rcr | M::Shld | M::Shrd => {
            Clase::Desplazamiento
        }
        M::Cmp | M::Test => Clase::Comparacion,
        M::Jmp => Clase::Salto,
        M::Call => Clase::Llamada,
        M::Ret | M::Retf => Clase::Retorno,
        M::Syscall | M::Sysenter | M::Int | M::Int3 | M::Int1 => Clase::Syscall,
        M::Hlt | M::Ud0 | M::Ud1 | M::Ud2 => Clase::Parada,
        M::Nop => Clase::Nop,
        // Las instrucciones de cifrado del procesador. Es una de las evidencias
        // mas limpias que hay: no existe una lectura benigna alternativa de un
        // `aesenc`.
        M::Aesenc
        | M::Aesenclast
        | M::Aesdec
        | M::Aesdeclast
        | M::Aesimc
        | M::Aeskeygenassist
        | M::Sha1rnds4
        | M::Sha1nexte
        | M::Sha1msg1
        | M::Sha1msg2
        | M::Sha256rnds2
        | M::Sha256msg1
        | M::Sha256msg2
        | M::Pclmulqdq => Clase::Cripto,
        // Operaciones sobre cadenas. Se dejan fuera `Movsd` y `Cmpsd` a
        // proposito: en x86 ese mnemonico designa tambien una instruccion SSE
        // sobre flotantes, y clasificar un calculo en coma flotante como copia
        // de memoria le daria a una regla una evidencia falsa.
        M::Movsb
        | M::Movsw
        | M::Movsq
        | M::Stosb
        | M::Stosw
        | M::Stosd
        | M::Stosq
        | M::Lodsb
        | M::Lodsw
        | M::Lodsd
        | M::Lodsq
        | M::Scasb
        | M::Scasw
        | M::Scasd
        | M::Scasq
        | M::Cmpsb
        | M::Cmpsw
        | M::Cmpsq => Clase::Cadena,
        _ if es_salto_condicional(m) => Clase::Salto,
        _ => Clase::Otra,
    }
}

/// Si el mnemonico es uno de los saltos condicionales.
///
/// Son treinta y dos mnemonicos distintos —`je`, `jne`, `jbe`...— y enumerarlos
/// uno a uno en el `match` principal lo haria ilegible sin ganar nada.
fn es_salto_condicional(m: Mnemonic) -> bool {
    use Mnemonic as M;
    matches!(
        m,
        M::Ja
            | M::Jae
            | M::Jb
            | M::Jbe
            | M::Je
            | M::Jg
            | M::Jge
            | M::Jl
            | M::Jle
            | M::Jne
            | M::Jno
            | M::Jnp
            | M::Jns
            | M::Jo
            | M::Jp
            | M::Js
            | M::Jcxz
            | M::Jecxz
            | M::Jrcxz
            | M::Loop
            | M::Loope
            | M::Loopne
    )
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// `xor eax, eax` / `ret`, ensamblado a mano.
    const XOR_RET: &[u8] = &[0x31, 0xC0, 0xC3];

    #[test]
    fn se_decodifica_codigo_maquina_real() {
        let t = Tramo::nuevo(XOR_RET, 0x1000, Arquitectura::X86_64).unwrap();
        let i = t.en(0x1000).unwrap();
        assert_eq!(i.longitud, 2);
        assert_eq!(i.clase, Clase::Logica, "xor es logica");
        assert_eq!(i.flujo, Flujo::Secuencial);

        let r = t.en(0x1002).unwrap();
        assert_eq!(r.clase, Clase::Retorno);
        assert_eq!(r.flujo, Flujo::Retorno);
        assert!(r.flujo.termina_bloque());
    }

    #[test]
    fn el_texto_se_formatea_a_la_carta_y_coincide_con_lo_esperado() {
        let s = texto_en(XOR_RET, 0x1000, 0x1000, Arquitectura::X86_64).unwrap();
        assert_eq!(s, "xor eax,eax", "sintaxis Intel");
    }

    #[test]
    fn un_syscall_es_frontera_y_no_una_llamada() {
        // La unica parte no mecanica de la traduccion. `iced` lo clasifica como
        // llamada, que es correcto para un emulador y equivocado para un grafo
        // de llamadas: no es una arista a otra funcion, es el borde del
        // programa. Si esto se rompiera, el grafo de llamadas de cualquier
        // binario de Linux se llenaria de aristas a ninguna parte.
        let t = Tramo::nuevo(&[0x0F, 0x05], 0x2000, Arquitectura::X86_64).unwrap();
        let i = t.en(0x2000).unwrap();
        assert_eq!(i.clase, Clase::Syscall);
        assert_eq!(i.flujo, Flujo::Frontera);
        assert!(!i.flujo.termina_bloque(), "syscall vuelve");
        assert_eq!(i.flujo.destino(), None);
    }

    #[test]
    fn una_llamada_cercana_trae_su_destino() {
        // `call +0` desde 0x1000: destino 0x1005.
        let t = Tramo::nuevo(
            &[0xE8, 0x00, 0x00, 0x00, 0x00],
            0x1000,
            Arquitectura::X86_64,
        )
        .unwrap();
        let i = t.en(0x1000).unwrap();
        assert_eq!(i.clase, Clase::Llamada);
        assert_eq!(
            i.flujo,
            Flujo::Llamada {
                destino: Some(0x1005)
            }
        );
        assert!(!i.flujo.indirecta());
    }

    #[test]
    fn una_llamada_indirecta_se_declara_sin_destino() {
        // `call rax` — el destino se calcula en ejecucion. Es el limite duro del
        // analisis estatico, y se declara en vez de adivinarse.
        let t = Tramo::nuevo(&[0xFF, 0xD0], 0x1000, Arquitectura::X86_64).unwrap();
        let i = t.en(0x1000).unwrap();
        assert_eq!(i.flujo, Flujo::Llamada { destino: None });
        assert!(i.flujo.indirecta());
    }

    #[test]
    fn un_salto_condicional_trae_su_destino_y_el_otro_camino_es_la_siguiente() {
        // `jne +2` desde 0x1000: salta a 0x1004, o sigue en 0x1002.
        let t = Tramo::nuevo(&[0x75, 0x02, 0x90, 0x90], 0x1000, Arquitectura::X86_64).unwrap();
        let i = t.en(0x1000).unwrap();
        assert_eq!(i.clase, Clase::Salto);
        assert_eq!(i.flujo, Flujo::SaltoCondicional { destino: 0x1004 });
        assert_eq!(i.siguiente(), 0x1002);
    }

    #[test]
    fn las_instrucciones_aes_del_procesador_tienen_clase_propia() {
        // `aesenc xmm0, xmm1` — no hay lectura benigna alternativa de esto.
        let t = Tramo::nuevo(
            &[0x66, 0x0F, 0x38, 0xDC, 0xC1],
            0x1000,
            Arquitectura::X86_64,
        )
        .unwrap();
        let i = t.en(0x1000).unwrap();
        assert_eq!(i.clase, Clase::Cripto);
    }

    #[test]
    fn un_inmediato_se_recoge_para_el_analisis_de_constantes() {
        // `mov eax, 0xDEADBEEF`
        let t = Tramo::nuevo(
            &[0xB8, 0xEF, 0xBE, 0xAD, 0xDE],
            0x1000,
            Arquitectura::X86_64,
        )
        .unwrap();
        let i = t.en(0x1000).unwrap();
        assert!(
            i.inmediatos.contains(&0xDEAD_BEEF),
            "inmediatos: {:x?}",
            i.inmediatos
        );
    }

    #[test]
    fn los_inmediatos_estan_acotados() {
        // La cota que impide que un fichero construido para eso haga crecer la
        // memoria por instruccion.
        let t = Tramo::nuevo(XOR_RET, 0x1000, Arquitectura::X86_64).unwrap();
        let i = t.en(0x1000).unwrap();
        assert!(i.inmediatos.len() <= MAX_INMEDIATOS);
        assert!(i.valida());
    }

    #[test]
    fn el_recorrido_lineal_no_se_para_en_los_bytes_que_no_son_codigo() {
        // Entre funciones hay datos. Pararse en el primer byte que no decodifica
        // dejaria sin analizar todo lo que venga detras, que es donde suele
        // estar lo interesante.
        let mut bytes = vec![0x31, 0xC0, 0xC3]; // xor eax,eax; ret
        bytes.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]); // basura
        bytes.extend_from_slice(&[0x90, 0xC3]); // nop; ret
        let t = Tramo::nuevo(&bytes, 0x1000, Arquitectura::X86_64).unwrap();
        let mut p = Plazo::default();
        let (v, _fallos) = t.lineal(0x1000, &mut p);
        assert!(
            v.iter().any(|i| i.clase == Clase::Nop),
            "el nop de despues de la basura tiene que aparecer: {:?}",
            v.iter().map(|i| i.clase).collect::<Vec<_>>()
        );
    }

    #[test]
    fn una_direccion_fuera_del_tramo_se_rechaza_diciendo_los_limites() {
        let t = Tramo::nuevo(XOR_RET, 0x1000, Arquitectura::X86_64).unwrap();
        let e = t.en(0x9999).unwrap_err();
        assert!(
            matches!(
                e,
                DisasmError::FueraDelTramo {
                    base: 0x1000,
                    fin: 0x1003,
                    ..
                }
            ),
            "{e}"
        );
    }

    #[test]
    fn arm64_no_se_decodifica_por_aqui() {
        // Devolver un error en vez de intentarlo: decodificar A64 con un
        // decodificador de x86 produce instrucciones con sentido aparente, que
        // es la peor forma de fallar que tiene esta pieza.
        assert!(Tramo::nuevo(XOR_RET, 0, Arquitectura::Arm64).is_err());
    }

    #[test]
    fn x86_de_32_bits_se_decodifica_distinto_que_de_64() {
        // El mismo byte significa cosas distintas segun el modo, y confundirlos
        // desplaza todo el desensamblado sin que nada lo indique. `0x40` es
        // `inc eax` en 32 bits y un prefijo REX en 64.
        let bytes = &[0x40, 0x90];
        let t32 = Tramo::nuevo(bytes, 0, Arquitectura::X86).unwrap();
        let t64 = Tramo::nuevo(bytes, 0, Arquitectura::X86_64).unwrap();
        assert_eq!(t32.en(0).unwrap().longitud, 1, "inc eax");
        assert_eq!(t64.en(0).unwrap().longitud, 2, "REX + nop, xchg r8d,eax");
    }

    /// El numero comun de `RAX`, para leer las pruebas sin contar bits.
    const RAX: u8 = 0;
    const RCX: u8 = 1;
    const RBX: u8 = 3;

    #[test]
    fn un_mov_de_64_bits_define_el_registro_entero() {
        // `mov rax, 0x401000` — la forma directa de poner una constante.
        let bytes = &[0x48, 0xC7, 0xC0, 0x00, 0x10, 0x40, 0x00];
        let t = Tramo::nuevo(bytes, 0, Arquitectura::X86_64).unwrap();
        let i = t.en(0).unwrap();
        assert!(i.regs.define(RAX));
        assert_eq!(i.valor_definido, Some(0x0040_1000));
        assert_eq!(i.delta, None);
    }

    #[test]
    fn un_mov_de_32_bits_tambien_define_el_registro_entero_porque_extiende_con_ceros() {
        // `mov eax, 0x401000`. En 64 bits una escritura de 32 pone a cero la
        // parte alta, asi que `RAX` queda valiendo exactamente el inmediato. Si
        // esto se tratara como definicion parcial, se perderia la forma MAS
        // comun de cargar una constante en codigo de 64 bits.
        let bytes = &[0xB8, 0x00, 0x10, 0x40, 0x00];
        let t = Tramo::nuevo(bytes, 0, Arquitectura::X86_64).unwrap();
        let i = t.en(0).unwrap();
        assert!(i.regs.define(RAX), "eax define RAX entero");
        assert_eq!(i.valor_definido, Some(0x0040_1000));
    }

    #[test]
    fn un_mov_a_un_subregistro_de_8_bits_no_define_nada() {
        // `mov al, 1`. Es la trampa del modelo: hay un inmediato y hay una
        // escritura, y aun asi `RAX` NO vale 1 —conserva 56 bits—. Un analisis
        // que apuntara aqui `RAX = 1` resolveria un `call rax` posterior hacia
        // una direccion a la que el programa no llama: una arista inventada.
        let bytes = &[0xB0, 0x01];
        let t = Tramo::nuevo(bytes, 0, Arquitectura::X86_64).unwrap();
        let i = t.en(0).unwrap();
        assert!(i.regs.escribe(RAX), "invalida lo que se supiera de RAX");
        assert!(!i.regs.define(RAX), "pero no lo define");
        assert_eq!(i.valor_definido, None, "y por tanto no aporta valor");
    }

    #[test]
    fn un_lea_relativo_al_pc_define_la_direccion_ya_resuelta() {
        // `lea rax, [rip+0x10]` en 0x1000: la instruccion mide 7 bytes, asi que
        // el destino es 0x1007 + 0x10. Es como todo el codigo independiente de
        // posicion —o sea, todo el codigo moderno— se calcula una direccion.
        let bytes = &[0x48, 0x8D, 0x05, 0x10, 0x00, 0x00, 0x00];
        let t = Tramo::nuevo(bytes, 0x1000, Arquitectura::X86_64).unwrap();
        let i = t.en(0x1000).unwrap();
        assert!(i.regs.define(RAX));
        assert_eq!(i.valor_definido, Some(0x1017));
    }

    #[test]
    fn un_xor_de_un_registro_consigo_mismo_define_cero() {
        // El cero idiomatico. Un analisis que no lo reconozca pierde el rastro
        // justo donde el compilador es mas predecible.
        let t = Tramo::nuevo(XOR_RET, 0x1000, Arquitectura::X86_64).unwrap();
        let i = t.en(0x1000).unwrap();
        assert!(i.regs.define(RAX));
        assert_eq!(i.valor_definido, Some(0));
    }

    #[test]
    fn un_xor_de_dos_registros_distintos_no_define_nada() {
        // `xor eax, ebx`: el valor depende de los dos, y no se conoce ninguno.
        let bytes = &[0x31, 0xD8];
        let t = Tramo::nuevo(bytes, 0, Arquitectura::X86_64).unwrap();
        let i = t.en(0).unwrap();
        assert!(i.regs.escribe(RAX));
        assert_eq!(i.valor_definido, None);
    }

    #[test]
    fn un_add_con_inmediato_aporta_su_delta_con_signo() {
        // `add rax, 0x18` y `sub rax, 0x18`: la segunda mitad de una direccion
        // formada en dos pasos. La resta es la misma suma con el signo cambiado.
        let t = Tramo::nuevo(&[0x48, 0x83, 0xC0, 0x18], 0, Arquitectura::X86_64).unwrap();
        assert_eq!(t.en(0).unwrap().delta, Some(0x18));
        let t = Tramo::nuevo(&[0x48, 0x83, 0xE8, 0x18], 0, Arquitectura::X86_64).unwrap();
        assert_eq!(t.en(0).unwrap().delta, Some(-0x18));
    }

    #[test]
    fn un_add_entre_registros_no_aporta_delta() {
        // `add rax, rbx` suma algo que el analisis no conoce. Tratarlo como una
        // suma de constante daria un valor inventado.
        let t = Tramo::nuevo(&[0x48, 0x01, 0xD8], 0, Arquitectura::X86_64).unwrap();
        let i = t.en(0).unwrap();
        assert_eq!(i.delta, None);
        assert!(i.regs.escribe(RAX));
        assert!(i.regs.lee(RBX));
    }

    #[test]
    fn una_llamada_invalida_todos_los_registros_generales() {
        // `call 0x1234`. La tabla de `iced` describe la instruccion —que escribe
        // RSP y RIP—, no la funcion que hay al otro lado. Como el analisis no ha
        // mirado al callee, no puede sostener NINGUN valor a traves de la
        // llamada. Si lo sostuviera, el primer `call rax` despues de una llamada
        // a una funcion que use RAX saldria resuelto hacia una direccion falsa.
        let t = Tramo::nuevo(&[0xE8, 0x00, 0x00, 0x00, 0x00], 0, Arquitectura::X86_64).unwrap();
        let i = t.en(0).unwrap();
        assert_eq!(i.regs.escritos, u32::MAX, "una llamada lo pisa todo");
        assert_eq!(i.regs.definidos, 0);
    }

    #[test]
    fn una_multiplicacion_invalida_rdx_aunque_no_lo_nombre() {
        // `mul rbx` escribe RAX y RDX, y solo nombra RBX. Es el caso que hunde a
        // cualquier deduccion por operandos: el registro pisado no aparece en la
        // instruccion. Se resuelve leyendo la tabla de uso de registros de
        // `iced` en vez de mirar el primer operando.
        let t = Tramo::nuevo(&[0x48, 0xF7, 0xE3], 0, Arquitectura::X86_64).unwrap();
        let i = t.en(0).unwrap();
        const RDX: u8 = 2;
        assert!(i.regs.escribe(RAX), "mul escribe RAX");
        assert!(i.regs.escribe(RDX), "y RDX, sin nombrarlo");
        assert!(i.regs.lee(RBX));
    }

    #[test]
    fn un_xchg_invalida_los_dos_registros() {
        // `xchg rax, rcx`: dos destinos en una instruccion de dos operandos.
        let t = Tramo::nuevo(&[0x48, 0x91], 0, Arquitectura::X86_64).unwrap();
        let i = t.en(0).unwrap();
        assert!(i.regs.escribe(RAX));
        assert!(i.regs.escribe(RCX));
        assert_eq!(i.regs.unico_escrito(), None, "dos escritos no son uno");
    }

    #[test]
    fn una_comparacion_no_define_aunque_escriba_banderas() {
        // `cmp rax, 5`. Las banderas no son un registro general, asi que para
        // este analisis la comparacion no toca nada — y lo que se supiera de RAX
        // sigue valiendo. Perder eso costaria casi todas las resoluciones, que
        // suelen venir despues de una comparacion.
        let t = Tramo::nuevo(&[0x48, 0x83, 0xF8, 0x05], 0, Arquitectura::X86_64).unwrap();
        let i = t.en(0).unwrap();
        assert!(!i.regs.escribe(RAX), "cmp no escribe su primer operando");
        assert!(i.regs.lee(RAX));
    }

    #[test]
    fn una_llamada_indirecta_por_registro_dice_de_que_registro_sale() {
        // `call rax`. Es lo que cierra el circulo con el analisis de constantes.
        let t = Tramo::nuevo(&[0xFF, 0xD0], 0, Arquitectura::X86_64).unwrap();
        let i = t.en(0).unwrap();
        assert!(i.flujo.indirecta());
        assert_eq!(i.destino_reg, Some(RAX));
    }

    #[test]
    fn una_llamada_indirecta_por_memoria_no_dice_ningun_registro() {
        // `call [rip+0x2f10]`: el destino esta en memoria, no en un registro. La
        // respuesta honesta es que este analisis no lo resuelve — lo resuelve la
        // tabla de importaciones del contenedor, que es otra cosa.
        let t = Tramo::nuevo(
            &[0xFF, 0x15, 0x10, 0x2F, 0x00, 0x00],
            0,
            Arquitectura::X86_64,
        )
        .unwrap();
        let i = t.en(0).unwrap();
        assert!(i.flujo.indirecta());
        assert_eq!(i.destino_reg, None);
    }

    #[test]
    fn los_subregistros_se_normalizan_al_mismo_numero() {
        // `mov al, 1` y `mov rax, 1` hablan del mismo registro. Sin normalizar,
        // el analisis creeria que son dos y conservaria un valor ya pisado.
        let a = Tramo::nuevo(&[0xB0, 0x01], 0, Arquitectura::X86_64)
            .unwrap()
            .en(0)
            .unwrap();
        let b = Tramo::nuevo(
            &[0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00],
            0,
            Arquitectura::X86_64,
        )
        .unwrap()
        .en(0)
        .unwrap();
        assert_eq!(a.regs.unico_escrito(), b.regs.unico_escrito());
    }

    #[test]
    fn lo_definido_es_siempre_parte_de_lo_escrito() {
        // La invariante del tipo, comprobada sobre codigo real y variado en vez
        // de sobre un caso construido.
        for bytes in [
            &[0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00][..],
            &[0x31, 0xC0][..],
            &[0x48, 0xF7, 0xE3][..],
            &[0xE8, 0x00, 0x00, 0x00, 0x00][..],
            &[0x0F, 0x05][..],
            &[0xCD, 0x80][..],
        ] {
            let i = Tramo::nuevo(bytes, 0, Arquitectura::X86_64)
                .unwrap()
                .en(0)
                .unwrap();
            assert!(i.regs.coherente(), "{bytes:02x?} rompe la invariante");
        }
    }
}
