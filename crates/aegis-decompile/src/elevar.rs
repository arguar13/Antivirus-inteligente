//! Elevacion semantica de x86-64 a la IR en forma SSA.
//!
//! # Que abre esta capa, y por que aqui
//!
//! El modelo de instruccion de `aegis-disasm` guarda la CLASE y las mascaras de
//! registros —lo que el motor de capacidades necesita—, no la semantica de
//! operandos. Para elevar `add eax, [rbp-8]` a algo recompilable hace falta saber
//! el operando exacto. Esta capa consume el GRAFO de `aegis-disasm` (los limites
//! de bloque y las direcciones que ya localizo) y re-decodifica cada instruccion
//! con el mismo `iced-x86` que usa el desensamblador, para sacar esa semantica.
//! No se reconstruye el grafo —eso seria rodearlo—; se abre la unica pieza que
//! faltaba.
//!
//! # SSA en el sitio: construccion de Braun
//!
//! La forma SSA se construye con el algoritmo de Braun et al. («Simple and
//! Efficient Construction of SSA»), que coloca los fi bajo demanda usando los
//! PREDECESORES del CFG —que `aegis-disasm` ya expone— sin calcular fronteras de
//! dominancia por separado. Cada registro general es una «variable»; leerla en un
//! bloque devuelve su ultima definicion, y si viene de varios predecesores, un fi.
//!
//! # Robustez
//!
//! Come el mismo tipo de entrada hostil que el desensamblador. Nada de lo que hace
//! entra en panico ni reserva sin cota: los bloques y las instrucciones vienen
//! acotados del CFG, y una instruccion que no se sabe elevar se marca como no
//! elevada (cuenta en la calidad) en vez de adivinarse.

use std::collections::BTreeMap;

use aegis_disasm::cfg::Cfg;
use aegis_disasm::instruccion::Arquitectura;
use iced_x86::{Decoder, DecoderOptions, Instruction as IcedInsn, OpKind, Register};

use crate::calidad::Calidad;
use crate::ir::{
    Ancho, BloqueId, BloqueIr, Fi, FuncionIr, OpBin, OpCmp, OpUn, Operacion, Operando, Sentencia,
    Terminador, ValId,
};
use crate::tipos::Tipo;

/// El resultado de elevar una funcion: la IR y lo que costo.
pub struct Elevacion {
    /// La funcion en IR.
    pub funcion: FuncionIr,
    /// La calidad de esta elevacion.
    pub calidad: Calidad,
}

/// Numero de registros generales que se siguen como variables SSA (RAX..R15).
///
/// Las banderas no son una variable SSA mas: se siguen aparte, por bloque, como el
/// par que comparo la ultima instruccion que las fijo (ver [`Constructor::banderas`]).
const REGISTROS: usize = 16;

/// Cuantas variables sigue el constructor SSA por bloque.
const VARIABLES: usize = REGISTROS;

/// La condicion que unas banderas representan: el operador y sus dos operandos,
/// guardados como el valor de la «variable banderas».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Banderas {
    izq: Operando,
    der: Operando,
}

/// El estado de construccion SSA de una funcion (algoritmo de Braun).
struct Constructor<'a> {
    cfg: &'a Cfg,
    codigo: &'a [u8],
    base: u64,
    /// La funcion que se esta construyendo.
    funcion: FuncionIr,
    /// Definicion actual de cada variable en cada bloque: `[bloque][var] -> valor`.
    def: BTreeMap<u64, [Option<Operando>; VARIABLES]>,
    /// Banderas actuales por bloque (la condicion comparada mas reciente).
    banderas: BTreeMap<u64, Option<Banderas>>,
    /// Bloques ya sellados (todos sus predecesores conocidos).
    sellados: std::collections::BTreeSet<u64>,
    /// Contador de valores SSA.
    siguiente_val: u32,
    /// Sentencias acumuladas por bloque, en orden.
    sentencias: BTreeMap<u64, Vec<Sentencia>>,
    /// Terminador de cada bloque.
    terminadores: BTreeMap<u64, Terminador>,
    /// Cuenta de calidad.
    calidad: Calidad,
}

impl<'a> Constructor<'a> {
    fn nuevo(cfg: &'a Cfg, codigo: &'a [u8], base: u64, entrada: u64) -> Self {
        Constructor {
            cfg,
            codigo,
            base,
            funcion: FuncionIr::nueva(entrada),
            def: BTreeMap::new(),
            banderas: BTreeMap::new(),
            sellados: std::collections::BTreeSet::new(),
            siguiente_val: 0,
            sentencias: BTreeMap::new(),
            terminadores: BTreeMap::new(),
            calidad: Calidad::default(),
        }
    }

    fn nuevo_valor(&mut self) -> ValId {
        let v = ValId(self.siguiente_val);
        self.siguiente_val += 1;
        v
    }

    /// Escribe la definicion de una variable en un bloque.
    fn escribir(&mut self, var: usize, bloque: u64, valor: Operando) {
        self.def.entry(bloque).or_insert([None; VARIABLES])[var] = Some(valor);
    }

    /// Lee una variable en un bloque; si no esta definida aqui, la busca en los
    /// predecesores, colocando un fi si hace falta.
    fn leer(&mut self, var: usize, bloque: u64) -> Operando {
        if let Some(arr) = self.def.get(&bloque) {
            if let Some(v) = arr[var] {
                return v;
            }
        }
        self.leer_recursivo(var, bloque)
    }

    fn leer_recursivo(&mut self, var: usize, bloque: u64) -> Operando {
        let preds: Vec<u64> = self
            .cfg
            .bloque(bloque)
            .map(|b| b.predecesores.clone())
            .unwrap_or_default();
        let valor = if preds.is_empty() {
            // Sin predecesores: es la entrada de la funcion. Un registro de
            // argumento de la convencion System V leido antes de definirse es un
            // ARGUMENTO; cualquier otro registro leido sin definir es indefinido
            // (no cero: «no se»). Reconocer los argumentos es lo que permite emitir
            // una funcion recompilable y comprobar su equivalencia.
            match arg_de_registro(var) {
                Some(n) => {
                    let val = self.nuevo_valor();
                    self.sentencias.entry(bloque).or_default().insert(
                        0,
                        Sentencia::Definir {
                            destino: val,
                            ancho: Ancho::B64,
                            tipo: Tipo::Desconocido,
                            op: Operacion::Argumento(n),
                            origen: vec![self.funcion.entrada],
                        },
                    );
                    Operando::Val(val)
                }
                None => Operando::Indefinido,
            }
        } else if preds.len() == 1 {
            self.leer(var, preds[0])
        } else {
            // Varios predecesores: un fi. Para romper ciclos, se define primero un
            // valor nuevo y luego se rellenan sus fuentes.
            let val = self.nuevo_valor();
            self.escribir(var, bloque, Operando::Val(val));
            let mut fuentes = BTreeMap::new();
            for p in preds {
                let o = self.leer(var, p);
                fuentes.insert(BloqueId(p), o);
            }
            // El fi se emite como una sentencia al principio del bloque.
            self.sentencias.entry(bloque).or_default().insert(
                0,
                Sentencia::Definir {
                    destino: val,
                    ancho: Ancho::B64,
                    tipo: Tipo::Desconocido,
                    op: Operacion::Fi(Fi { fuentes }),
                    origen: vec![bloque],
                },
            );
            return Operando::Val(val);
        };
        self.escribir(var, bloque, valor);
        valor
    }

    /// Define una sentencia de calculo y devuelve su valor.
    fn definir(&mut self, bloque: u64, ancho: Ancho, op: Operacion, origen: u64) -> Operando {
        let val = self.nuevo_valor();
        self.sentencias
            .entry(bloque)
            .or_default()
            .push(Sentencia::Definir {
                destino: val,
                ancho,
                tipo: Tipo::Desconocido,
                op,
                origen: vec![origen],
            });
        Operando::Val(val)
    }
}

/// El ancho de un registro de iced.
fn ancho_reg(r: Register) -> Ancho {
    match r.size() {
        1 => Ancho::B8,
        2 => Ancho::B16,
        4 => Ancho::B32,
        8 => Ancho::B64,
        16 => Ancho::B128,
        _ => Ancho::B64,
    }
}

/// El numero de variable (0..15) del registro general de 64 bits que contiene a
/// `r`, o `None` si no es un registro general (vectorial, de segmento, IP...).
fn var_de(r: Register) -> Option<usize> {
    let g = r.full_register(); // normaliza AL/AX/EAX -> RAX
    let idx = match g {
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
    };
    Some(idx)
}

/// La posicion de argumento de la convencion System V AMD64 de un numero de
/// registro general, si es uno de los seis que pasan enteros o punteros.
///
/// RDI, RSI, RDX, RCX, R8, R9 -> argumentos 0..5. Es la convencion de Linux y
/// macOS; la de Windows (RCX, RDX, R8, R9) se anade cuando el decompilador soporte
/// el objeto PE, y hasta entonces se declara.
fn arg_de_registro(var: usize) -> Option<u32> {
    match var {
        7 => Some(0), // RDI
        6 => Some(1), // RSI
        2 => Some(2), // RDX
        1 => Some(3), // RCX
        8 => Some(4), // R8
        9 => Some(5), // R9
        _ => None,
    }
}

/// Eleva una funcion entera del CFG a la IR.
///
/// Solo x86-64 por ahora; otras arquitecturas devuelven una elevacion vacia con su
/// calidad a cero, que es honesto: no se elevo nada.
#[must_use]
pub fn elevar_funcion(
    cfg: &Cfg,
    arq: Arquitectura,
    codigo: &[u8],
    base: u64,
    entrada: u64,
) -> Elevacion {
    if arq != Arquitectura::X86_64 {
        return Elevacion {
            funcion: FuncionIr::nueva(entrada),
            calidad: Calidad::default(),
        };
    }
    let mut c = Constructor::nuevo(cfg, codigo, base, entrada);

    // Los bloques que pertenecen a esta funcion: los alcanzables desde la entrada
    // por sucesores, sin cruzar a otra funcion (las llamadas no son sucesores en
    // este CFG, asi que el recorrido se queda en la funcion).
    let bloques = bloques_de_funcion(cfg, entrada);

    for &dir in &bloques {
        c.terminadores.insert(dir, Terminador::Inalcanzable);
        c.sentencias.entry(dir).or_default();
    }
    for &dir in &bloques {
        elevar_bloque(&mut c, dir);
    }
    // Sellar todos los bloques: ya se conocen todos los predecesores.
    for &dir in &bloques {
        c.sellados.insert(dir);
    }

    // Montar la funcion IR.
    for &dir in &bloques {
        let sentencias = c.sentencias.remove(&dir).unwrap_or_default();
        let terminador = c
            .terminadores
            .remove(&dir)
            .unwrap_or(Terminador::Inalcanzable);
        c.funcion.bloques.insert(
            BloqueId(dir),
            BloqueIr {
                id: BloqueId(dir),
                sentencias,
                terminador,
            },
        );
    }
    c.funcion.valores = c.siguiente_val;
    Elevacion {
        funcion: c.funcion,
        calidad: c.calidad,
    }
}

/// Los bloques alcanzables desde la entrada de la funcion por sucesores.
fn bloques_de_funcion(cfg: &Cfg, entrada: u64) -> Vec<u64> {
    let mut vistos = std::collections::BTreeSet::new();
    let mut pila = vec![entrada];
    while let Some(d) = pila.pop() {
        if !vistos.insert(d) {
            continue;
        }
        if let Some(b) = cfg.bloque(d) {
            for &s in &b.sucesores {
                if !vistos.contains(&s) {
                    pila.push(s);
                }
            }
        }
    }
    vistos.into_iter().collect()
}

/// Decodifica una instruccion de iced en una direccion absoluta.
fn decodificar(codigo: &[u8], base: u64, dir: u64) -> Option<IcedInsn> {
    let off = dir.checked_sub(base)? as usize;
    if off >= codigo.len() {
        return None;
    }
    let mut dec = Decoder::with_ip(64, &codigo[off..], dir, DecoderOptions::NONE);
    if !dec.can_decode() {
        return None;
    }
    let insn = dec.decode();
    if insn.is_invalid() {
        None
    } else {
        Some(insn)
    }
}

/// Eleva las instrucciones de un bloque y fija su terminador.
fn elevar_bloque(c: &mut Constructor, dir: u64) {
    let Some(bloque) = c.cfg.bloque(dir) else {
        return;
    };
    let sucesores = bloque.sucesores.clone();
    // Se recorren las instrucciones por su direccion, re-decodificando con iced.
    let direcciones: Vec<u64> = bloque.instrucciones.iter().map(|i| i.direccion).collect();
    for ip in direcciones {
        c.calidad.instrucciones_totales += 1;
        let Some(insn) = decodificar(c.codigo, c.base, ip) else {
            continue;
        };
        if elevar_instruccion(c, dir, &insn, &sucesores) {
            c.calidad.instrucciones_elevadas += 1;
        }
    }
}

/// El operando de origen de una operacion de iced en la posicion `i`, leyendo el
/// estado SSA actual. Devuelve `(operando, ancho)`.
fn leer_operando(c: &mut Constructor, bloque: u64, insn: &IcedInsn, i: u32) -> (Operando, Ancho) {
    match insn.op_kind(i) {
        OpKind::Register => {
            let r = insn.op_register(i);
            let ancho = ancho_reg(r);
            match var_de(r) {
                Some(v) => (c.leer(v, bloque), ancho),
                None => (Operando::Indefinido, ancho),
            }
        }
        OpKind::Immediate8 | OpKind::Immediate8_2nd => (
            Operando::Const(u64::from(insn.immediate8()), Ancho::B8),
            Ancho::B8,
        ),
        OpKind::Immediate16 => (
            Operando::Const(u64::from(insn.immediate16()), Ancho::B16),
            Ancho::B16,
        ),
        OpKind::Immediate32 => (
            Operando::Const(u64::from(insn.immediate32()), Ancho::B32),
            Ancho::B32,
        ),
        OpKind::Immediate64 => (Operando::Const(insn.immediate64(), Ancho::B64), Ancho::B64),
        OpKind::Immediate8to16 => (
            Operando::Const(insn.immediate8to16() as u64, Ancho::B16),
            Ancho::B16,
        ),
        OpKind::Immediate8to32 => (
            Operando::Const(insn.immediate8to32() as u64, Ancho::B32),
            Ancho::B32,
        ),
        OpKind::Immediate8to64 => (
            Operando::Const(insn.immediate8to64() as u64, Ancho::B64),
            Ancho::B64,
        ),
        OpKind::Immediate32to64 => (
            Operando::Const(insn.immediate32to64() as u64, Ancho::B64),
            Ancho::B64,
        ),
        OpKind::Memory => {
            let dir = direccion_de_memoria(c, bloque, insn);
            let ancho = Ancho::de_bytes(insn.memory_size().size() as u32).unwrap_or(Ancho::B64);
            let val = c.definir(bloque, ancho, Operacion::Cargar { dir, ancho }, insn.ip());
            (val, ancho)
        }
        _ => (Operando::Indefinido, Ancho::B64),
    }
}

/// Reconstruye la direccion de un operando de memoria como un valor SSA:
/// `base + index*scale + disp`.
fn direccion_de_memoria(c: &mut Constructor, bloque: u64, insn: &IcedInsn) -> Operando {
    let mut acc: Option<Operando> = None;
    // base
    let base = insn.memory_base();
    if base != Register::None {
        if let Some(v) = var_de(base) {
            acc = Some(c.leer(v, bloque));
        }
    }
    // index*scale
    let index = insn.memory_index();
    if index != Register::None {
        if let Some(v) = var_de(index) {
            let iv = c.leer(v, bloque);
            let escala = u64::from(insn.memory_index_scale());
            let idx = if escala > 1 {
                c.definir(
                    bloque,
                    Ancho::B64,
                    Operacion::Bin {
                        op: OpBin::Multiplicar,
                        a: iv,
                        b: Operando::Const(escala, Ancho::B64),
                    },
                    insn.ip(),
                )
            } else {
                iv
            };
            acc = Some(match acc {
                Some(a) => c.definir(
                    bloque,
                    Ancho::B64,
                    Operacion::Bin {
                        op: OpBin::Sumar,
                        a,
                        b: idx,
                    },
                    insn.ip(),
                ),
                None => idx,
            });
        }
    }
    // disp
    let disp = insn.memory_displacement64();
    if disp != 0 || acc.is_none() {
        let d = Operando::Const(disp, Ancho::B64);
        acc = Some(match acc {
            Some(a) => c.definir(
                bloque,
                Ancho::B64,
                Operacion::Bin {
                    op: OpBin::Sumar,
                    a,
                    b: d,
                },
                insn.ip(),
            ),
            None => d,
        });
    }
    acc.unwrap_or(Operando::Indefinido)
}

/// Escribe el resultado de una operacion en el operando destino `i` (registro o
/// memoria).
fn escribir_destino(
    c: &mut Constructor,
    bloque: u64,
    insn: &IcedInsn,
    valor: Operando,
    ancho: Ancho,
) {
    match insn.op_kind(0) {
        OpKind::Register => {
            let r = insn.op_register(0);
            if let Some(v) = var_de(r) {
                c.escribir(v, bloque, valor);
            }
        }
        OpKind::Memory => {
            let dir = direccion_de_memoria(c, bloque, insn);
            c.sentencias
                .entry(bloque)
                .or_default()
                .push(Sentencia::Almacenar {
                    dir,
                    valor,
                    ancho,
                    origen: vec![insn.ip()],
                });
        }
        _ => {}
    }
    let _ = i_para_destino(insn);
}

/// El indice del operando destino en iced es 0 para las instrucciones de dos
/// operandos que escriben el primero. Esta funcion documenta esa suposicion y deja
/// sitio para las que no la cumplan.
fn i_para_destino(_insn: &IcedInsn) -> u32 {
    0
}

/// Eleva una sola instruccion. Devuelve si se elevo (para la calidad).
fn elevar_instruccion(
    c: &mut Constructor,
    bloque: u64,
    insn: &IcedInsn,
    sucesores: &[u64],
) -> bool {
    match insn.mnemonic() {
        iced_x86::Mnemonic::Mov => {
            let (fuente, ancho) = leer_operando(c, bloque, insn, 1);
            let val = c.definir(bloque, ancho, Operacion::Copiar(fuente), insn.ip());
            escribir_destino(c, bloque, insn, val, ancho);
            true
        }
        iced_x86::Mnemonic::Movzx => {
            let (fuente, sa) = leer_operando(c, bloque, insn, 1);
            let da = ancho_reg(insn.op_register(0));
            let val = c.definir(
                bloque,
                da,
                Operacion::Un {
                    op: OpUn::ExtenderU(sa),
                    a: fuente,
                },
                insn.ip(),
            );
            escribir_destino(c, bloque, insn, val, da);
            true
        }
        iced_x86::Mnemonic::Movsx | iced_x86::Mnemonic::Movsxd => {
            let (fuente, sa) = leer_operando(c, bloque, insn, 1);
            let da = ancho_reg(insn.op_register(0));
            let val = c.definir(
                bloque,
                da,
                Operacion::Un {
                    op: OpUn::ExtenderS(sa),
                    a: fuente,
                },
                insn.ip(),
            );
            escribir_destino(c, bloque, insn, val, da);
            true
        }
        iced_x86::Mnemonic::Lea => {
            let dir = direccion_de_memoria(c, bloque, insn);
            let da = ancho_reg(insn.op_register(0));
            let val = c.definir(bloque, da, Operacion::Copiar(dir), insn.ip());
            escribir_destino(c, bloque, insn, val, da);
            true
        }
        iced_x86::Mnemonic::Add => bin_op(c, bloque, insn, OpBin::Sumar),
        iced_x86::Mnemonic::Sub => bin_op(c, bloque, insn, OpBin::Restar),
        iced_x86::Mnemonic::And => bin_op(c, bloque, insn, OpBin::Y),
        iced_x86::Mnemonic::Or => bin_op(c, bloque, insn, OpBin::O),
        iced_x86::Mnemonic::Xor => bin_op(c, bloque, insn, OpBin::Xor),
        iced_x86::Mnemonic::Shl => bin_op(c, bloque, insn, OpBin::DesplazarIzq),
        iced_x86::Mnemonic::Shr => bin_op(c, bloque, insn, OpBin::DesplazarDerL),
        iced_x86::Mnemonic::Sar => bin_op(c, bloque, insn, OpBin::DesplazarDerA),
        iced_x86::Mnemonic::Imul if insn.op_count() == 2 => {
            bin_op(c, bloque, insn, OpBin::Multiplicar)
        }
        iced_x86::Mnemonic::Neg => {
            let (a, ancho) = leer_operando(c, bloque, insn, 0);
            let val = c.definir(
                bloque,
                ancho,
                Operacion::Un { op: OpUn::Negar, a },
                insn.ip(),
            );
            escribir_destino(c, bloque, insn, val, ancho);
            true
        }
        iced_x86::Mnemonic::Not => {
            let (a, ancho) = leer_operando(c, bloque, insn, 0);
            let val = c.definir(bloque, ancho, Operacion::Un { op: OpUn::No, a }, insn.ip());
            escribir_destino(c, bloque, insn, val, ancho);
            true
        }
        iced_x86::Mnemonic::Cmp | iced_x86::Mnemonic::Test => {
            let (a, _) = leer_operando(c, bloque, insn, 0);
            let (b, _) = leer_operando(c, bloque, insn, 1);
            // Para `test`, la condicion es sobre `a & b`; para `cmp`, sobre `a - b`.
            // Se guardan los operandos y el jcc siguiente elige el operador.
            c.banderas.insert(bloque, Some(Banderas { izq: a, der: b }));
            true
        }
        iced_x86::Mnemonic::Push
        | iced_x86::Mnemonic::Pop
        | iced_x86::Mnemonic::Nop
        | iced_x86::Mnemonic::Leave
        | iced_x86::Mnemonic::Endbr64
        | iced_x86::Mnemonic::Endbr32 => {
            // Efectos de pila y no-ops: no aportan a la reconstruccion de
            // expresiones enteras del subconjunto, y se cuentan como elevados
            // (se entendieron) sin emitir nada.
            true
        }
        iced_x86::Mnemonic::Ret => {
            let ret = c.leer(0, bloque); // RAX es el valor de retorno por convencion
            c.terminadores
                .insert(bloque, Terminador::Retornar(Some(ret)));
            true
        }
        iced_x86::Mnemonic::Jmp => {
            match insn.op_kind(0) {
                OpKind::NearBranch64 => {
                    c.terminadores
                        .insert(bloque, Terminador::Ir(BloqueId(insn.near_branch64())));
                }
                _ => {
                    c.terminadores.insert(bloque, Terminador::Indirecto);
                }
            }
            true
        }
        iced_x86::Mnemonic::Call => {
            let (destino, nombre) = match insn.op_kind(0) {
                OpKind::NearBranch64 => (Operando::Const(insn.near_branch64(), Ancho::B64), None),
                _ => (Operando::Indefinido, None),
            };
            let ret = c.nuevo_valor();
            c.sentencias
                .entry(bloque)
                .or_default()
                .push(Sentencia::Llamada {
                    destino,
                    nombre,
                    argumentos: Vec::new(),
                    retorno: Some(ret),
                    origen: vec![insn.ip()],
                });
            // El resultado queda en RAX.
            c.escribir(0, bloque, Operando::Val(ret));
            let def = Sentencia::Definir {
                destino: ret,
                ancho: Ancho::B64,
                tipo: Tipo::Desconocido,
                op: Operacion::ResultadoLlamada,
                origen: vec![insn.ip()],
            };
            // El Definir del resultado va justo despues de la llamada.
            c.sentencias.entry(bloque).or_default().push(def);
            true
        }
        m if es_salto_condicional(m) => {
            let destino_si = if insn.op_kind(0) == OpKind::NearBranch64 {
                insn.near_branch64()
            } else {
                c.terminadores.insert(bloque, Terminador::Indirecto);
                return true;
            };
            // El sucesor que NO es el destino del salto es la caida.
            let no = sucesores
                .iter()
                .copied()
                .find(|&s| s != destino_si)
                .unwrap_or(destino_si);
            let cond = condicion_de(c, bloque, m);
            c.terminadores.insert(
                bloque,
                Terminador::Rama {
                    cond,
                    si: BloqueId(destino_si),
                    no: BloqueId(no),
                },
            );
            true
        }
        _ => {
            // No se sabe elevar: se deja el registro destino, si lo hay, como
            // indefinido para no arrastrar un valor viejo que ya no vale.
            if insn.op_count() > 0 && insn.op_kind(0) == OpKind::Register {
                if let Some(v) = var_de(insn.op_register(0)) {
                    c.escribir(v, bloque, Operando::Indefinido);
                }
            }
            false
        }
    }
}

/// Eleva una operacion binaria `dst = dst OP src`.
fn bin_op(c: &mut Constructor, bloque: u64, insn: &IcedInsn, op: OpBin) -> bool {
    let (a, ancho) = leer_operando(c, bloque, insn, 0);
    let (b, _) = leer_operando(c, bloque, insn, 1);
    let val = c.definir(bloque, ancho, Operacion::Bin { op, a, b }, insn.ip());
    escribir_destino(c, bloque, insn, val, ancho);
    true
}

/// Si un mnemonico es un salto condicional.
fn es_salto_condicional(m: iced_x86::Mnemonic) -> bool {
    use iced_x86::Mnemonic::*;
    matches!(
        m,
        Je | Jne
            | Jb
            | Jae
            | Jbe
            | Ja
            | Jl
            | Jge
            | Jle
            | Jg
            | Js
            | Jns
            | Jp
            | Jnp
            | Jo
            | Jno
            | Jcxz
            | Jecxz
            | Jrcxz
    )
}

/// La condicion de un salto condicional, a partir de las banderas guardadas por la
/// ultima comparacion del bloque.
fn condicion_de(c: &mut Constructor, bloque: u64, m: iced_x86::Mnemonic) -> Operando {
    use iced_x86::Mnemonic::*;
    let Some(Some(b)) = c.banderas.get(&bloque).copied() else {
        return Operando::Indefinido;
    };
    let (op, invertir) = match m {
        Je => (OpCmp::Igual, false),
        Jne => (OpCmp::Distinto, false),
        Jb => (OpCmp::MenorU, false),
        Jae => (OpCmp::MenorU, true),
        Jbe => (OpCmp::MenorIgualU, false),
        Ja => (OpCmp::MenorIgualU, true),
        Jl => (OpCmp::MenorS, false),
        Jge => (OpCmp::MenorS, true),
        Jle => (OpCmp::MenorIgualS, false),
        Jg => (OpCmp::MenorIgualS, true),
        _ => return Operando::Indefinido,
    };
    let cmp = c.definir(
        bloque,
        Ancho::B8,
        Operacion::Comparar {
            op,
            a: b.izq,
            b: b.der,
        },
        bloque,
    );
    if invertir {
        c.definir(
            bloque,
            Ancho::B8,
            Operacion::Un {
                op: OpUn::No,
                a: cmp,
            },
            bloque,
        )
    } else {
        cmp
    }
}
