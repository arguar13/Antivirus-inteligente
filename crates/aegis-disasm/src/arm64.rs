//! Decodificador de A64 (ARM64), escrito en casa.
//!
//! # Por que en casa, cuando x86 se decodifica con una biblioteca
//!
//! Son la misma regla aplicada a dos casos muy distintos, y conviene dejar
//! escrito el razonamiento porque desde fuera parece una incoherencia.
//!
//! `iced-x86` entra con **cero** dependencias transitivas y ya estaba aprobado en
//! la linea base del agente. El candidato equivalente para ARM64, `yaxpeax-arm`,
//! arrastra ocho crates —`yaxpeax-arch`, `bitvec`, `funty`, `radium`, `tap`,
//! `wyz`, `num-traits`, `autocfg`—. Este proyecto rechazo libp2p por su arbol y
//! justifica una por una sus treinta y nueve dependencias directas; aceptar ocho
//! mas por A64 seria incoherente con eso.
//!
//! Y el trabajo no es comparable. x86-64 es un sedimento de treinta anos:
//! prefijos heredados, REX, VEX, EVEX, opcodes de uno a tres bytes, ModRM, SIB,
//! y longitud variable —de la que se deriva que un error de un byte desplaza
//! todo lo que viene detras y produce un desensamblado que parece correcto—.
//! A64 es **ancho fijo de 32 bits**, sin prefijos, con los campos en posiciones
//! constantes. Eso cambia dos cosas:
//!
//! 1. La decodificacion se reduce a mascaras y desplazamientos sobre un `u32`.
//! 2. **No existe el fallo por desalineamiento**: la siguiente instruccion esta
//!    cuatro bytes mas alla, se haya entendido esta o no. Un opcode que este
//!    modulo no conozca sale como [`Clase::Otra`] y el recorrido sigue intacto,
//!    donde en x86 el mismo desconocimiento corrompe todo lo siguiente.
//!
//! Esa segunda propiedad es la que hace defendible escribirlo: el coste de no
//! cubrir una instruccion es que esa instruccion no aporta a las reglas, y no
//! que el analisis entero quede mal.
//!
//! # Que se decodifica
//!
//! Todo lo que el grafo y las reglas necesitan:
//!
//! - **Flujo**: `B`, `BL`, `B.cond`, `CBZ`/`CBNZ`, `TBZ`/`TBNZ`, `BR`, `BLR`,
//!   `RET`, `ERET`.
//! - **Frontera con el nucleo**: `SVC`, `HVC`, `SMC`.
//! - **Parada**: `BRK`, `HLT`, `UDF`.
//! - **Constantes**: `MOVZ`, `MOVN`, `MOVK`, `ADR`, `ADRP`, `ADD`/`SUB`
//!   inmediato — que es de donde salen las direcciones y los valores que miran
//!   las reglas.
//! - **Clases**: aritmetica, logica, desplazamiento, comparacion, carga y
//!   almacenamiento, y las de cifrado (`AESE`, `AESD`, `SHA256H`...).
//!
//! Lo que no esta cae en [`Clase::Otra`] con su longitud correcta de cuatro
//! bytes, que es la respuesta honesta.

use crate::error::DisasmError;
use crate::instruccion::{Arquitectura, Clase, Flujo, Instruccion, Registros};
use crate::plazo::Plazo;

/// Toda instruccion de A64 mide esto.
pub const ANCHO: u64 = 4;

/// Un tramo de codigo A64 listo para desensamblar.
#[derive(Debug, Clone, Copy)]
pub struct Tramo<'a> {
    bytes: &'a [u8],
    base: u64,
}

impl<'a> Tramo<'a> {
    /// Abre un tramo de codigo A64 cargado en `base`.
    pub fn nuevo(bytes: &'a [u8], base: u64, arq: Arquitectura) -> Result<Tramo<'a>, DisasmError> {
        if arq != Arquitectura::Arm64 {
            return Err(DisasmError::ArquitecturaNoSoportada(format!(
                "{} no se decodifica aqui: ver el modulo x86",
                arq.nombre()
            )));
        }
        Ok(Tramo { bytes, base })
    }

    /// Principio del tramo.
    pub fn base(&self) -> u64 {
        self.base
    }

    /// Final del tramo, exclusivo.
    pub fn fin(&self) -> u64 {
        self.base.saturating_add(self.bytes.len() as u64)
    }

    /// Si una direccion cae dentro y deja sitio para una instruccion entera.
    pub fn contiene(&self, direccion: u64) -> bool {
        direccion >= self.base && direccion.saturating_add(ANCHO) <= self.fin()
    }

    /// La palabra de 32 bits que hay en `direccion`.
    fn palabra(&self, direccion: u64) -> Result<u32, DisasmError> {
        if !self.contiene(direccion) {
            return Err(DisasmError::FueraDelTramo {
                direccion,
                base: self.base,
                fin: self.fin(),
            });
        }
        let o = (direccion - self.base) as usize;
        Ok(u32::from_le_bytes([
            self.bytes[o],
            self.bytes[o + 1],
            self.bytes[o + 2],
            self.bytes[o + 3],
        ]))
    }

    /// Decodifica la instruccion que hay en `direccion`.
    ///
    /// A64 exige alineamiento a cuatro bytes. Una direccion desalineada no es
    /// una instruccion y se rechaza en vez de leerse a caballo de dos, que
    /// produciria una instruccion inventada.
    pub fn en(&self, direccion: u64) -> Result<Instruccion, DisasmError> {
        if direccion % ANCHO != 0 {
            return Err(DisasmError::NoDecodificable { direccion });
        }
        let w = self.palabra(direccion)?;
        Ok(decodificar(w, direccion))
    }

    /// Recorrido lineal desde `desde` hasta donde llegue el plazo.
    ///
    /// A diferencia del de x86, aqui no hay contador de fallos que devolver:
    /// toda palabra de cuatro bytes se decodifica, aunque sea a
    /// [`Clase::Otra`]. Es la consecuencia directa del ancho fijo.
    pub fn lineal(&self, desde: u64, plazo: &mut Plazo) -> Vec<Instruccion> {
        let mut v = Vec::new();
        let mut pc = desde - (desde % ANCHO);
        while self.contiene(pc) && plazo.sigue() {
            match self.en(pc) {
                Ok(i) => v.push(i),
                Err(_) => break,
            }
            pc += ANCHO;
        }
        v
    }
}

/// El texto de la instruccion que hay en `direccion`.
///
/// Se formatea a la carta, igual que en x86. Lo que este modulo no conoce sale
/// como su palabra en hexadecimal: es lo unico honesto que se puede escribir de
/// una instruccion que no se ha identificado, y deja a quien lea el informe la
/// posibilidad de buscarla.
pub fn texto_en(bytes: &[u8], base: u64, direccion: u64) -> Option<String> {
    let t = Tramo::nuevo(bytes, base, Arquitectura::Arm64).ok()?;
    let w = t.palabra(direccion).ok()?;
    Some(texto_de(w, direccion))
}

/// Extiende el signo de un campo de `bits` bits.
fn sext(v: u64, bits: u32) -> i64 {
    let desplazamiento = 64 - bits;
    ((v << desplazamiento) as i64) >> desplazamiento
}

/// Suma un desplazamiento con signo a una direccion, sin desbordar.
fn relativo(pc: u64, delta: i64) -> u64 {
    pc.wrapping_add(delta as u64)
}

/// Decodifica una palabra de A64.
pub fn decodificar(w: u32, pc: u64) -> Instruccion {
    let a = analizar(w, pc);
    Instruccion {
        direccion: pc,
        longitud: ANCHO as u8,
        clase: a.clase,
        flujo: a.flujo,
        inmediatos: a.inmediatos,
        lee_memoria: es_carga(w),
        escribe_memoria: es_almacenamiento(w),
        regs: a.regs,
        // A64 no tiene segmentos.
        segmento: None,
        valor_definido: a.valor_definido,
        copia_de: a.copia_de,
        delta: a.delta,
        destino_reg: a.destino_reg,
    }
}

/// Lo que sale de mirar una palabra de A64.
///
/// Es una estructura y no una tupla porque son seis campos y cuatro de ellos son
/// opcionales: una tupla de seis en cuarenta sitios de retorno es un sitio donde
/// dos campos se cambian de orden sin que el compilador diga nada.
struct Analisis {
    clase: Clase,
    flujo: Flujo,
    inmediatos: Vec<u64>,
    regs: Registros,
    valor_definido: Option<u64>,
    copia_de: Option<u8>,
    delta: Option<i64>,
    destino_reg: Option<u8>,
}

impl Analisis {
    /// Una instruccion de la que solo se sabe la clase y el flujo.
    fn nueva(clase: Clase, flujo: Flujo) -> Analisis {
        Analisis {
            clase,
            flujo,
            inmediatos: Vec::new(),
            regs: Registros::nada(),
            valor_definido: None,
            copia_de: None,
            delta: None,
            destino_reg: None,
        }
    }

    /// Una instruccion cuyos efectos sobre los registros este decodificador NO
    /// ha determinado.
    ///
    /// **Invalida todos los registros generales**, y esa es la unica respuesta
    /// segura. Una instruccion que el decodificador no entiende puede escribir
    /// cualquier registro; decir que no escribe ninguno dejaria vivo en el
    /// analisis un valor que el programa ya piso, y ese valor acabaria
    /// resolviendo un `blr x16` hacia una direccion a la que nadie salta. Perder
    /// resoluciones por no entender una instruccion es aceptable; inventarlas,
    /// no.
    fn opaca(clase: Clase, flujo: Flujo) -> Analisis {
        let mut a = Analisis::nueva(clase, flujo);
        a.regs.escritos = u32::MAX;
        a
    }

    /// Las constantes que la instruccion lleva escritas.
    fn con(mut self, inmediatos: Vec<u64>) -> Analisis {
        self.inmediatos = inmediatos;
        self
    }

    /// Anota un registro leido, si es uno de los seguidos.
    fn lee(mut self, reg: u32) -> Analisis {
        if let Some(n) = reg_seguido(reg) {
            self.regs.anota_leido(n);
        }
        self
    }

    /// Anota un registro escrito con valor desconocido.
    fn escribe(mut self, reg: u32) -> Analisis {
        if let Some(n) = reg_seguido(reg) {
            self.regs.anota_escrito(n);
        }
        self
    }

    /// Anota un registro que queda definido con un valor exacto.
    fn define(mut self, reg: u32, valor: u64) -> Analisis {
        if let Some(n) = reg_seguido(reg) {
            self.regs.anota_definido(n);
            self.valor_definido = Some(valor);
        }
        self
    }

    /// Anota que el registro `destino` pasa a valer lo que vale `origen`.
    fn copia(mut self, destino: u32, origen: u32) -> Analisis {
        match (reg_seguido(destino), reg_seguido(origen)) {
            (Some(d), Some(o)) => {
                self.regs.anota_leido(o);
                self.regs.anota_definido(d);
                self.copia_de = Some(o);
            }
            // Copiar DESDE `XZR` es poner el registro a cero, que si es un valor
            // conocido. Es como A64 escribe `mov x0, #0` la mitad de las veces.
            (Some(d), None) => {
                self.regs.anota_definido(d);
                self.valor_definido = Some(0);
            }
            // Copiar HACIA `XZR` es tirar el valor: no hay efecto que seguir.
            (None, _) => {}
        }
        self
    }

    /// Anota que la instruccion suma una constante al registro que lee y
    /// escribe.
    fn suma(mut self, reg: u32, delta: i64) -> Analisis {
        if let Some(n) = reg_seguido(reg) {
            self.regs.anota_leido(n);
            self.regs.anota_escrito(n);
            self.delta = Some(delta);
        }
        self
    }

    /// Anota de que registro sale el destino de una transferencia indirecta.
    fn destino(mut self, reg: u32) -> Analisis {
        self.destino_reg = reg_seguido(reg);
        self
    }

    /// Marca la instruccion como una llamada: el callee pisa lo que quiera.
    ///
    /// La tabla de esta funcion describe la instruccion, no la funcion que hay
    /// al otro lado. `BL` escribe `X30` y nada mas *como instruccion*; lo que
    /// pase despues depende de un codigo que el analisis no ha mirado. Se
    /// invalidan todos los registros por la misma razon que en
    /// [`Analisis::opaca`].
    fn llama(mut self) -> Analisis {
        self.regs.escritos = u32::MAX;
        self.regs.definidos = 0;
        self.valor_definido = None;
        self.copia_de = None;
        self.delta = None;
        self
    }
}

/// Numero comun del registro general `n` de A64, o `None` si no se sigue.
///
/// El 31 **no se sigue**, y no es un descuido. En A64 ese numero no nombra un
/// registro: segun la instruccion es `XZR` —el registro cero, cuyas escrituras
/// se descartan y cuyas lecturas dan cero— o es `SP`. Seguirlo como si fuera un
/// registro mas haria que un `subs xzr, x0, x1` —que es como se escribe un
/// `cmp`— pareciera definir un registro, y que un `cmp` invalidara valores que
/// no toca. Fuera de la mascara no estorba, y no se pierde nada: nadie salta a
/// traves de `XZR`.
fn reg_seguido(n: u32) -> Option<u8> {
    if n < 31 {
        Some(n as u8)
    } else {
        None
    }
}

/// Campo `Rd`/`Rt` de A64: bits 4..0.
fn rd(w: u32) -> u32 {
    w & 0x1F
}

/// Campo `Rn` de A64: bits 9..5.
fn rn(w: u32) -> u32 {
    (w >> 5) & 0x1F
}

/// Campo `Rm` de A64: bits 20..16.
fn rm(w: u32) -> u32 {
    (w >> 16) & 0x1F
}

/// Campo `Rt2` de A64 en los pares (`LDP`/`STP`): bits 14..10.
fn rt2(w: u32) -> u32 {
    (w >> 10) & 0x1F
}

/// El nucleo de la decodificacion: clase, flujo, constantes y registros.
fn analizar(w: u32, pc: u64) -> Analisis {
    // --- Ramas con inmediato -------------------------------------------------
    // B:  0b000101 imm26        BL: 0b100101 imm26
    if w >> 26 == 0b000101 {
        let d = relativo(pc, sext(u64::from(w & 0x03FF_FFFF), 26) * 4);
        return Analisis::nueva(Clase::Salto, Flujo::SaltoIncondicional { destino: Some(d) })
            .con(vec![d]);
    }
    if w >> 26 == 0b100101 {
        let d = relativo(pc, sext(u64::from(w & 0x03FF_FFFF), 26) * 4);
        return Analisis::nueva(Clase::Llamada, Flujo::Llamada { destino: Some(d) })
            .con(vec![d])
            .llama();
    }
    // B.cond: 0b01010100 imm19 0 cond
    if w >> 24 == 0b0101_0100 && (w & 0x10) == 0 {
        let imm19 = u64::from((w >> 5) & 0x7_FFFF);
        let d = relativo(pc, sext(imm19, 19) * 4);
        return Analisis::nueva(Clase::Salto, Flujo::SaltoCondicional { destino: d }).con(vec![d]);
    }
    // CBZ/CBNZ: sf 011010 op imm19 Rt
    if (w >> 25) & 0x3F == 0b011010 {
        let imm19 = u64::from((w >> 5) & 0x7_FFFF);
        let d = relativo(pc, sext(imm19, 19) * 4);
        return Analisis::nueva(Clase::Salto, Flujo::SaltoCondicional { destino: d })
            .con(vec![d])
            .lee(rd(w));
    }
    // TBZ/TBNZ: b5 011011 op b40 imm14 Rt
    if (w >> 25) & 0x3F == 0b011011 {
        let imm14 = u64::from((w >> 5) & 0x3FFF);
        let d = relativo(pc, sext(imm14, 14) * 4);
        return Analisis::nueva(Clase::Salto, Flujo::SaltoCondicional { destino: d })
            .con(vec![d])
            .lee(rd(w));
    }

    // --- Ramas por registro --------------------------------------------------
    // El destino esta en un registro. Aqui se declara indirecto en vez de
    // adivinarse, y se anota DE QUE registro sale: es lo que permite al analisis
    // de constantes resolverlo mas adelante, cuando pueda, sin que este modulo
    // tenga que suponer nada.
    const MASCARA_RAMA_REG: u32 = 0xFFFF_FC1F;
    match w & MASCARA_RAMA_REG {
        0xD61F_0000 => {
            return Analisis::nueva(Clase::Salto, Flujo::SaltoIncondicional { destino: None })
                .lee(rn(w))
                .destino(rn(w))
        }
        0xD63F_0000 => {
            return Analisis::nueva(Clase::Llamada, Flujo::Llamada { destino: None })
                .lee(rn(w))
                .destino(rn(w))
                .llama()
        }
        0xD65F_0000 => return Analisis::nueva(Clase::Retorno, Flujo::Retorno).lee(rn(w)),
        _ => {}
    }
    if w == 0xD69F_03E0 {
        return Analisis::nueva(Clase::Retorno, Flujo::Retorno);
    }

    // --- Frontera con el nucleo y paradas ------------------------------------
    // SVC/HVC/SMC: 11010100 000 imm16 000 LL, con LL = 01/10/11
    if w & 0xFFE0_0000 == 0xD400_0000 {
        let imm16 = u64::from((w >> 5) & 0xFFFF);
        return match w & 0x1F {
            // Cruzar al nucleo invalida los registros por la misma razon que una
            // llamada: lo que hay al otro lado no lo ha mirado este analisis.
            1..=3 => Analisis::nueva(Clase::Syscall, Flujo::Frontera)
                .con(vec![imm16])
                .llama(),
            _ => Analisis::opaca(Clase::Otra, Flujo::Secuencial).con(vec![imm16]),
        };
    }
    // BRK: 11010100 001 imm16 00000   HLT: 11010100 010 imm16 00000
    if w & 0xFFE0_001F == 0xD420_0000 || w & 0xFFE0_001F == 0xD440_0000 {
        let imm16 = u64::from((w >> 5) & 0xFFFF);
        return Analisis::nueva(Clase::Parada, Flujo::Parada).con(vec![imm16]);
    }
    // UDF: los 16 bits altos a cero.
    if w >> 16 == 0 {
        return Analisis::nueva(Clase::Parada, Flujo::Parada);
    }
    if w == 0xD503_201F {
        return Analisis::nueva(Clase::Nop, Flujo::Secuencial);
    }

    // --- Constantes: de donde salen las direcciones y los valores ------------
    // MOVN/MOVZ/MOVK: sf opc 100101 hw imm16 Rd
    //
    // Las tres se codifican igual y hacen cosas distintas, y tratarlas igual es
    // un error con consecuencias: `movn` deja el complemento del inmediato, no
    // el inmediato.
    if (w >> 23) & 0x3F == 0b100101 {
        let imm16 = u64::from((w >> 5) & 0xFFFF);
        let hw = u64::from((w >> 21) & 0x3);
        // El inmediato, ya colocado en su mitad: un `movz x0, #0x1234, lsl #16`
        // no aporta 0x1234, aporta 0x12340000.
        let colocado = imm16 << (hw * 16);
        let ancho = if w >> 31 == 1 { 64 } else { 32 };
        let mascara = if ancho == 64 { u64::MAX } else { 0xFFFF_FFFF };
        let a = Analisis::nueva(Clase::Mov, Flujo::Secuencial).con(vec![colocado, imm16]);
        return match (w >> 29) & 0x3 {
            // MOVZ: el registro queda valiendo exactamente el inmediato
            // colocado, con el resto a cero.
            0b10 => a.define(rd(w), colocado & mascara),
            // MOVN: queda valiendo el COMPLEMENTO. Un analisis que apuntara aqui
            // el inmediato sin complementar estaria dando un valor falso, y ese
            // valor acabaria en un `blr` resuelto hacia una direccion que el
            // programa no usa.
            0b00 => a.define(rd(w), (!colocado) & mascara),
            // MOVK: inserta 16 bits y CONSERVA el resto. No define nada por si
            // sola —depende del valor anterior, que esta instruccion no lleva—,
            // asi que solo invalida. La consecuencia esta declarada en la
            // documentacion del modulo: una direccion formada con `movz`+`movk`
            // no se resuelve, y sale contada como transferencia indirecta.
            0b11 => a.escribe(rd(w)),
            // 0b01 no esta asignado en A64. No se sabe que hace, luego invalida
            // todo.
            _ => Analisis::opaca(Clase::Otra, Flujo::Secuencial).con(vec![colocado, imm16]),
        };
    }
    // ADR / ADRP: op immlo 10000 immhi Rd
    if (w >> 24) & 0x1F == 0b10000 {
        let immlo = u64::from((w >> 29) & 0x3);
        let immhi = u64::from((w >> 5) & 0x7_FFFF);
        let imm = (immhi << 2) | immlo;
        let destino = if w >> 31 == 1 {
            // ADRP: pagina de 4 KiB, relativa a la pagina del PC.
            let pagina = pc & !0xFFF;
            relativo(pagina, sext(imm, 21) * 4096)
        } else {
            relativo(pc, sext(imm, 21))
        };
        return Analisis::nueva(Clase::Direccion, Flujo::Secuencial)
            .con(vec![destino])
            .define(rd(w), destino);
    }
    // ADD/SUB inmediato: sf op S 10001 sh imm12 Rn Rd
    if (w >> 23) & 0x3F == 0b100010 {
        let imm12 = u64::from((w >> 10) & 0xFFF);
        let sh = (w >> 22) & 1;
        let valor = if sh == 1 { imm12 << 12 } else { imm12 };
        let resta = (w >> 30) & 1 == 1;
        let marca = (w >> 29) & 1 == 1;
        // `SUBS`/`ADDS` con destino XZR es un `CMP`/`CMN`: no escribe registro,
        // solo banderas.
        if marca && rd(w) == 31 {
            return Analisis::nueva(Clase::Comparacion, Flujo::Secuencial)
                .con(vec![valor])
                .lee(rn(w));
        }
        let a = Analisis::nueva(Clase::Aritmetica, Flujo::Secuencial).con(vec![valor]);
        // La segunda mitad de `adrp`+`add`, que es como A64 forma una direccion.
        // Solo se puede sumar si el registro que se lee es el mismo que se
        // escribe; si no, el resultado no tiene nada que ver con lo que hubiera
        // en el destino.
        if rn(w) == rd(w) {
            let d = valor as i64;
            return a.suma(rd(w), if resta { d.wrapping_neg() } else { d });
        }
        return a.lee(rn(w)).escribe(rd(w));
    }
    // Logicas con inmediato: sf opc 100100 N immr imms Rn Rd
    if (w >> 23) & 0x3F == 0b100100 {
        // `ANDS` con destino XZR es un `TST`: no escribe registro.
        if (w >> 29) & 0x3 == 0b11 && rd(w) == 31 {
            return Analisis::nueva(Clase::Comparacion, Flujo::Secuencial).lee(rn(w));
        }
        return Analisis::nueva(Clase::Logica, Flujo::Secuencial)
            .lee(rn(w))
            .escribe(rd(w));
    }

    // --- Cifrado del procesador ---------------------------------------------
    // Escriben registros vectoriales, que no se siguen: no invalidan nada
    // general, y eso es exacto, no una aproximacion.
    // AESE/AESD/AESMC/AESIMC: 0100 1110 0010 1000 010x xx10 ....
    if w & 0xFFFF_F000 == 0x4E28_4000 {
        return Analisis::nueva(Clase::Cripto, Flujo::Secuencial);
    }
    // SHA1/SHA256: 0101 1110 000. .... 0... ....
    if w & 0xFF00_0000 == 0x5E00_0000 && (w & 0x00F0_0000) == 0 {
        return Analisis::nueva(Clase::Cripto, Flujo::Secuencial);
    }

    // --- Copia entre registros ----------------------------------------------
    // En A64 `mov Xd, Xm` no existe como instruccion: es `ORR Xd, XZR, Xm` sin
    // desplazamiento. Se reconoce aqui porque seguir un valor cuando cambia de
    // registro es la diferencia entre resolver una llamada y perderla, y mover
    // el valor de registro es de las ofuscaciones mas baratas que hay —ademas de
    // algo que el compilador hace por su cuenta todo el rato.
    //
    // La mascara deja libres el bit de anchura y el campo `Rm`, y exige lo que
    // hace que sea una copia limpia: sin desplazamiento, sin negacion y con
    // `Rn` = `XZR`.
    if w & 0x7FE0_FFE0 == 0x2A00_03E0 {
        return Analisis::nueva(Clase::Mov, Flujo::Secuencial).copia(rd(w), rm(w));
    }

    // --- Clases generales, por el grupo mayor de la codificacion -------------
    // Los bits 28..25 dicen a que familia pertenece la instruccion. Es la tabla
    // de primer nivel de A64.
    //
    // De aqui en adelante no se ha identificado la instruccion concreta, solo su
    // familia, y por eso los registros se marcan por **exceso**: se da por
    // escrito todo campo de destino que la familia pueda tener. Un exceso cuesta
    // una resolucion perdida; un defecto cuesta una arista inventada.
    let grupo = (w >> 25) & 0xF;
    match grupo {
        // Datos con inmediato: escribe Rd, lee Rn.
        0b1000 | 0b1001 => Analisis::nueva(Clase::Aritmetica, Flujo::Secuencial)
            .lee(rn(w))
            .escribe(rd(w)),
        // Datos con registros: escribe Rd, lee Rn y Rm.
        0b0101 | 0b1101 => registros_de_datos(w),
        // Cargas y almacenamientos.
        0b0100 | 0b0110 | 0b1100 | 0b1110 => carga_o_almacenamiento(w),
        // Coma flotante y SIMD. La inmensa mayoria escribe registros
        // vectoriales, que no se siguen, pero unas cuantas escriben uno general
        // —`FMOV Xd, Dn`, `UMOV Wd, Vn.B[i]`, `FCVTZS Xd, Dn`— y distinguirlas
        // exige bajar a la tabla de segundo nivel de A64 entera. Se marca Rd por
        // exceso: la unica consecuencia es que una constante que viviera en ese
        // registro deja de seguirse a partir de aqui, y eso cuesta una
        // resolucion, no una invencion.
        0b0111 | 0b1111 => Analisis::nueva(Clase::Otra, Flujo::Secuencial).escribe(rd(w)),
        // Familia no reconocida: no se sabe que escribe, luego invalida todo.
        _ => Analisis::opaca(Clase::Otra, Flujo::Secuencial),
    }
}

/// Efectos sobre los registros de una carga o un almacenamiento.
///
/// # Por que se baja a distinguir las formas
///
/// Porque la alternativa —marcar como escritos todos los campos que alguna forma
/// usa como destino— pisaria un registro en **cada** acceso a memoria, y los
/// accesos a memoria estan por todas partes. Una direccion formada con
/// `adrp`+`add` no sobreviviria al primer `ldr` de la funcion aunque el `ldr` no
/// la toque, y el analisis dejaria de resolver casi nada.
///
/// Las tres cosas que hay que distinguir son pocas y estan en bits fijos: si hay
/// un segundo registro transferido (`LDP`/`STP`), si la forma actualiza el
/// registro base (pre e posindexadas), y si es una exclusiva —que deja el
/// resultado de la operacion en un tercer registro.
fn carga_o_almacenamiento(w: u32) -> Analisis {
    // `Rt` es destino en una carga y fuente en un almacenamiento. Marcarlo
    // escrito en los dos casos sobra en el segundo y no falta en el primero, y
    // distinguirlos no aporta: el valor cargado de memoria no se conoce igual.
    let familia = (w >> 27) & 0b111;
    let mut a = Analisis::nueva(Clase::Mov, Flujo::Secuencial).escribe(rd(w));
    // La forma literal —`ldr x0, etiqueta`— no tiene registro base: esos bits
    // son parte del desplazamiento. Marcarlo leido seria describir un registro
    // que la instruccion no nombra.
    if familia != 0b011 {
        a = a.lee(rn(w));
    }
    match familia {
        // Par de registros: hay un `Rt2`, y los bits 24..23 dicen la forma —01
        // posindexada y 11 preindexada actualizan la base.
        0b101 => {
            a = a.escribe(rt2(w));
            if matches!((w >> 23) & 0b11, 0b01 | 0b11) {
                a = a.escribe(rn(w));
            }
        }
        // Registro suelto. El bit 24 a uno es la forma con desplazamiento sin
        // signo, que no actualiza la base; con el bit 24 a cero, los bits 11..10
        // distinguen posindexada (01) y preindexada (11) de las que no
        // actualizan.
        0b111 => {
            if (w >> 24) & 1 == 0 {
                if matches!((w >> 10) & 0b11, 0b01 | 0b11) {
                    a = a.escribe(rn(w));
                } else if (w >> 21) & 1 == 1 {
                    // Forma con registro de indice: ahi `Rm` si es un registro.
                    a = a.lee(rm(w));
                }
            }
        }
        // Exclusivas y con orden (`STXR`, `LDXR`, `STLXR`, `LDAR`). Un `STXR`
        // deja el resultado de la operacion en `Rs`, que ocupa el campo de `Rm`:
        // es el destino que menos se parece a un destino de toda la familia, y
        // olvidarlo dejaria vivo un valor ya pisado.
        0b001 => {
            a = a.escribe(rm(w));
        }
        _ => {}
    }
    a
}

/// Afina clase y registros dentro del grupo de datos con registros.
fn registros_de_datos(w: u32) -> Analisis {
    let clase = clase_de_registro(w);
    let a = Analisis::nueva(clase, Flujo::Secuencial)
        .lee(rn(w))
        .lee(rm(w));
    // Una comparacion no escribe registro: `clase_de_registro` ya la ha
    // identificado como tal mirando que el destino sea XZR.
    if clase == Clase::Comparacion {
        return a;
    }
    a.escribe(rd(w))
}

/// Afina la clase dentro del grupo de datos con registros.
fn clase_de_registro(w: u32) -> Clase {
    // Logicas con registro: sf opc 01010 shift N Rm imm6 Rn Rd
    if (w >> 24) & 0x1F == 0b01010 {
        return Clase::Logica;
    }
    // Suma/resta con registro: sf op S 01011 ...
    if (w >> 24) & 0x1F == 0b01011 {
        // `SUBS` con destino XZR es un `CMP`: la comparacion que toda regla
        // sobre condiciones mira. Rd = 31 y S = 1.
        let s = (w >> 29) & 1;
        let rd = w & 0x1F;
        if s == 1 && rd == 31 {
            return Clase::Comparacion;
        }
        return Clase::Aritmetica;
    }
    // Desplazamientos variables: sf 0 0 11010110 Rm 0010xx Rn Rd
    if w & 0x7FE0_F000 == 0x1AC0_2000 {
        return Clase::Desplazamiento;
    }
    Clase::Otra
}

/// Si la instruccion carga de memoria.
fn es_carga(w: u32) -> bool {
    // Grupo de cargas y almacenamientos, con el bit de direccion a 1 (carga).
    let grupo = (w >> 25) & 0xF;
    matches!(grupo, 0b0100 | 0b0110 | 0b1100 | 0b1110) && (w >> 22) & 1 == 1
}

/// Si la instruccion escribe en memoria.
fn es_almacenamiento(w: u32) -> bool {
    let grupo = (w >> 25) & 0xF;
    matches!(grupo, 0b0100 | 0b0110 | 0b1100 | 0b1110) && (w >> 22) & 1 == 0
}

/// Texto de una palabra de A64.
fn texto_de(w: u32, pc: u64) -> String {
    let i = decodificar(w, pc);
    match (i.clase, i.flujo) {
        (_, Flujo::SaltoIncondicional { destino: Some(d) }) => format!("b {d:#x}"),
        (_, Flujo::SaltoIncondicional { destino: None }) => "br <registro>".into(),
        (_, Flujo::SaltoCondicional { destino }) => format!("b.<cond> {destino:#x}"),
        (_, Flujo::Llamada { destino: Some(d) }) => format!("bl {d:#x}"),
        (_, Flujo::Llamada { destino: None }) => "blr <registro>".into(),
        (_, Flujo::Retorno) => "ret".into(),
        (Clase::Syscall, _) => format!("svc #{}", i.inmediatos.first().copied().unwrap_or(0)),
        (Clase::Parada, _) => "brk".into(),
        (Clase::Nop, _) => "nop".into(),
        (Clase::Cripto, _) => "<cifrado del procesador>".into(),
        // Lo que este modulo no identifica sale como su palabra. Es lo unico
        // honesto que se puede escribir, y deja buscarla a quien lea el informe.
        _ => format!("<a64 {w:#010x}>"),
    }
}

#[cfg(test)]
// Los literales binarios de estas pruebas se agrupan por los CAMPOS de la
// instruccion —`sf`, `opc`, `hw`, `imm16`, `Rd`— y no en grupos de igual tamano.
// Esa agrupacion es lo que permite cotejarlos a ojo contra el manual de ARM, que
// es como se comprueba que una prueba de decodificacion dice lo que cree decir.
// Uniformarlos para contentar al lint destruiria esa informacion y dejaria unas
// constantes que nadie puede verificar.
#[allow(clippy::unusual_byte_groupings)]
mod pruebas {
    use super::*;

    /// Decodifica una palabra en la direccion dada.
    fn dec(w: u32, pc: u64) -> Instruccion {
        decodificar(w, pc)
    }

    #[test]
    fn toda_instruccion_mide_cuatro_bytes_y_eso_hace_imposible_el_cuelgue() {
        // La propiedad que hace defendible escribir este decodificador en casa:
        // la siguiente instruccion esta cuatro bytes mas alla, se haya entendido
        // esta o no. En x86 un opcode desconocido desplaza todo lo que viene
        // detras; aqui no puede.
        for w in [
            0xD503_201F,
            0x1400_0001,
            0xFFFF_FFFF,
            0x0000_0000,
            0xDEAD_BEEF,
        ] {
            let i = dec(w, 0x1000);
            assert_eq!(i.longitud, 4, "palabra {w:#x}");
            assert!(i.valida());
            assert_eq!(i.siguiente(), 0x1004);
        }
    }

    #[test]
    fn un_salto_incondicional_trae_su_destino() {
        // `b .+4` = 0x14000001 en 0x1000 -> 0x1004.
        let i = dec(0x1400_0001, 0x1000);
        assert_eq!(i.clase, Clase::Salto);
        assert_eq!(
            i.flujo,
            Flujo::SaltoIncondicional {
                destino: Some(0x1004)
            }
        );
    }

    #[test]
    fn un_salto_hacia_atras_se_calcula_con_signo() {
        // `b .-4` = 0x17FFFFFF en 0x1000 -> 0x0FFC. Si el desplazamiento se
        // leyera sin signo, el destino saldria a 256 MiB de distancia y el grafo
        // de cualquier bucle quedaria roto.
        let i = dec(0x17FF_FFFF, 0x1000);
        assert_eq!(
            i.flujo,
            Flujo::SaltoIncondicional {
                destino: Some(0x0FFC)
            }
        );
    }

    #[test]
    fn una_llamada_con_inmediato_es_una_arista_del_grafo() {
        // `bl .+8` = 0x94000002 en 0x2000 -> 0x2008.
        let i = dec(0x9400_0002, 0x2000);
        assert_eq!(i.clase, Clase::Llamada);
        assert_eq!(
            i.flujo,
            Flujo::Llamada {
                destino: Some(0x2008)
            }
        );
        assert!(!i.flujo.indirecta());
    }

    #[test]
    fn ret_br_y_blr_se_distinguen() {
        // Los tres comparten los bits altos y significan cosas muy distintas
        // para el grafo: uno vuelve, otro salta a donde no se sabe y el tercero
        // llama a donde no se sabe.
        assert_eq!(dec(0xD65F_03C0, 0).flujo, Flujo::Retorno);
        assert_eq!(
            dec(0xD61F_0000, 0).flujo,
            Flujo::SaltoIncondicional { destino: None }
        );
        assert_eq!(dec(0xD63F_0000, 0).flujo, Flujo::Llamada { destino: None });
        assert!(dec(0xD61F_0000, 0).flujo.indirecta());
    }

    #[test]
    fn svc_es_frontera_con_el_nucleo_y_no_termina_el_bloque() {
        // `svc #0` = 0xD4000001.
        let i = dec(0xD400_0001, 0x1000);
        assert_eq!(i.clase, Clase::Syscall);
        assert_eq!(i.flujo, Flujo::Frontera);
        assert!(!i.flujo.termina_bloque());
    }

    #[test]
    fn brk_es_una_parada() {
        // `brk #0` = 0xD4200000.
        let i = dec(0xD420_0000, 0);
        assert_eq!(i.clase, Clase::Parada);
        assert!(i.flujo.termina_bloque());
    }

    #[test]
    fn nop_se_reconoce() {
        assert_eq!(dec(0xD503_201F, 0).clase, Clase::Nop);
    }

    #[test]
    fn movz_aporta_el_valor_ya_colocado_en_su_mitad() {
        // `movz x0, #0x1234, lsl #16` no aporta 0x1234 al analisis de
        // constantes: aporta 0x12340000. Quedarse con el inmediato crudo daria
        // una constante que el programa nunca tiene.
        // sf=1 opc=10 100101 hw=01 imm16=0x1234 Rd=0
        let w: u32 = 0b1_10_100101_01_0001001000110100_00000;
        let i = dec(w, 0);
        assert_eq!(i.clase, Clase::Mov);
        assert!(
            i.inmediatos.contains(&0x1234_0000),
            "inmediatos: {:x?}",
            i.inmediatos
        );
    }

    #[test]
    fn adrp_se_calcula_sobre_la_pagina_y_no_sobre_el_pc() {
        // `adrp x0, #0` desde 0x1234 tiene que dar 0x1000, no 0x1234. Es como
        // se forman las direcciones de datos en todo binario de ARM64: fallar
        // aqui desplaza cada cadena y cada tabla que el analisis resuelva.
        // op=1 immlo=00 10000 immhi=0 Rd=0
        let w: u32 = 0b1_00_10000_0000000000000000000_00000;
        let i = dec(w, 0x1234);
        assert_eq!(i.clase, Clase::Direccion);
        assert_eq!(i.inmediatos.first().copied(), Some(0x1000));
    }

    #[test]
    fn una_direccion_desalineada_se_rechaza() {
        // A64 exige alineamiento a cuatro. Leer a caballo de dos instrucciones
        // produciria una instruccion inventada con sentido aparente.
        let bytes = [0x1F, 0x20, 0x03, 0xD5, 0x1F, 0x20, 0x03, 0xD5];
        let t = Tramo::nuevo(&bytes, 0x1000, Arquitectura::Arm64).unwrap();
        assert!(t.en(0x1000).is_ok());
        assert!(matches!(
            t.en(0x1001).unwrap_err(),
            DisasmError::NoDecodificable { .. }
        ));
    }

    #[test]
    fn una_palabra_incompleta_al_final_del_tramo_no_se_lee() {
        // Tres bytes no son una instruccion. Leerlos rellenando con ceros daria
        // una instruccion que no esta en el fichero.
        let bytes = [0x1F, 0x20, 0x03];
        let t = Tramo::nuevo(&bytes, 0x1000, Arquitectura::Arm64).unwrap();
        assert!(t.en(0x1000).is_err());
    }

    #[test]
    fn el_recorrido_lineal_cubre_el_tramo_entero() {
        let mut bytes = Vec::new();
        for _ in 0..16 {
            bytes.extend_from_slice(&0xD503_201Fu32.to_le_bytes());
        }
        let t = Tramo::nuevo(&bytes, 0x1000, Arquitectura::Arm64).unwrap();
        let mut p = Plazo::default();
        let v = t.lineal(0x1000, &mut p);
        assert_eq!(v.len(), 16);
        assert!(v.iter().all(|i| i.clase == Clase::Nop));
    }

    #[test]
    fn x86_no_se_decodifica_por_aqui() {
        assert!(Tramo::nuevo(&[0x90], 0, Arquitectura::X86_64).is_err());
    }

    #[test]
    fn lo_que_no_se_identifica_sale_con_su_palabra_en_el_texto() {
        // Es lo unico honesto que se puede escribir de una instruccion no
        // identificada, y deja buscarla a quien lea el informe.
        let bytes = 0x4E20_1C00u32.to_le_bytes();
        let s = texto_en(&bytes, 0x1000, 0x1000).unwrap();
        assert!(s.contains("a64"), "{s}");
        assert!(s.contains("0x4e201c00"), "{s}");
    }

    #[test]
    fn un_cmp_se_distingue_de_una_resta() {
        // `subs xzr, x0, x1` ES un `cmp`, y toda regla que mire condiciones lo
        // busca por ahi. sf=1 op=1 S=1 01011 shift=00 0 Rm=1 imm6=0 Rn=0 Rd=31
        let w: u32 = 0b1_1_1_01011_00_0_00001_000000_00000_11111;
        assert_eq!(dec(w, 0).clase, Clase::Comparacion);
    }

    // --- Efectos sobre los registros ---------------------------------------
    //
    // Todas las palabras de estas pruebas salen del ensamblador de LLVM
    // (`clang --target=aarch64-linux-gnu`), no de deducirlas a mano del manual.
    // Es la misma disciplina que en x86, donde se cotejan contra `objdump`: una
    // constante inventada por quien escribe la prueba comprueba que el codigo
    // hace lo que su autor creia, no lo que la arquitectura dice.

    #[test]
    fn un_movz_define_el_registro_con_el_inmediato_ya_colocado() {
        // `movz x16, #0x1234, lsl #16` = d2a24690. No aporta 0x1234: aporta
        // 0x12340000.
        let i = dec(0xd2a2_4690, 0);
        assert!(i.regs.define(16));
        assert_eq!(i.valor_definido, Some(0x1234_0000));
    }

    #[test]
    fn un_movn_define_el_complemento_y_no_el_inmediato() {
        // `movn x1, #0x10` = 92800201. El ensamblador lo escribe `mov x1, #-0x11`
        // porque el registro queda valiendo el COMPLEMENTO del inmediato.
        // Apuntar aqui 0x10 —que es lo que la instruccion lleva escrito— seria
        // dar por cierto un valor que el registro no tiene, y ese valor acabaria
        // resolviendo un `blr` hacia una direccion que el programa no usa.
        let i = dec(0x9280_0201, 0);
        assert!(i.regs.define(1));
        assert_eq!(i.valor_definido, Some(0xFFFF_FFFF_FFFF_FFEF));
    }

    #[test]
    fn un_movn_de_32_bits_no_desborda_a_la_parte_alta() {
        // `movn w2, #0x10` = 12800202. La forma de 32 bits deja la parte alta a
        // cero, asi que el valor es 0xFFFFFFEF y no 0xFFFFFFFFFFFFFFEF. Es la
        // misma instruccion con el bit `sf` cambiado y un valor cuatro mil
        // millones de veces distinto.
        let i = dec(0x1280_0202, 0);
        assert!(i.regs.define(2));
        assert_eq!(i.valor_definido, Some(0xFFFF_FFEF));
    }

    #[test]
    fn un_movk_invalida_pero_no_define() {
        // `movk x16, #0x5678` = f28acf10. Inserta 16 bits y conserva el resto,
        // asi que el valor depende de lo que hubiera antes —que esta
        // instruccion no lleva—. Se declara lo que es: el registro cambia y no
        // se sabe a que. La consecuencia esta escrita en la cabecera del modulo.
        let i = dec(0xf28a_cf10, 0);
        assert!(i.regs.escribe(16));
        assert!(!i.regs.define(16));
        assert_eq!(i.valor_definido, None);
    }

    #[test]
    fn un_adrp_seguido_de_add_forma_una_direccion_en_dos_pasos() {
        // `adrp x8, .` = 90000008 en 0x10, y `add x8, x8, #0x18` = 91006108.
        // Es COMO A64 forma una direccion, y por eso el modelo tiene que poder
        // expresar las dos mitades.
        let a = dec(0x9000_0008, 0x10);
        assert!(a.regs.define(8));
        assert_eq!(a.valor_definido, Some(0), "la pagina de 0x10 es 0");

        let b = dec(0x9100_6108, 0x14);
        assert_eq!(b.delta, Some(0x18));
        assert!(b.regs.lee(8), "lee el mismo registro que escribe");
        assert!(b.regs.escribe(8));
        assert_eq!(b.regs.unico_escrito(), Some(8));
    }

    #[test]
    fn una_resta_inmediata_aporta_su_delta_negativo() {
        // `sub x9, x9, #0x18` = d1006129. Es la misma suma con el signo
        // cambiado, y guardarlo sin signo obligaria a distinguir suma de resta
        // por la clase —que no las distingue— o por el texto, que no se guarda.
        let i = dec(0xd100_6129, 0);
        assert_eq!(i.delta, Some(-0x18));
    }

    #[test]
    fn una_suma_entre_registros_distintos_no_aporta_delta() {
        // `add x10, x11, #0x18` = 9100616a. El resultado no tiene nada que ver
        // con lo que hubiera en x10; tratarlo como un desplazamiento de x10
        // daria una direccion inventada.
        let i = dec(0x9100_616a, 0);
        assert_eq!(i.delta, None);
        assert!(i.regs.lee(11));
        assert!(i.regs.escribe(10));
        assert!(!i.regs.define(10));
    }

    #[test]
    fn una_rama_por_registro_dice_de_que_registro_sale() {
        // `blr x16` = d63f0200 y `br x17` = d61f0220.
        let l = dec(0xd63f_0200, 0);
        assert!(l.flujo.indirecta());
        assert_eq!(l.destino_reg, Some(16));
        let s = dec(0xd61f_0220, 0);
        assert!(s.flujo.indirecta());
        assert_eq!(s.destino_reg, Some(17));
    }

    #[test]
    fn una_llamada_invalida_todos_los_registros() {
        // `bl .` = 94000000 y `blr x16` = d63f0200. La tabla de este modulo
        // describe la instruccion, no la funcion que hay al otro lado: como el
        // analisis no ha mirado al callee, no puede sostener ningun valor a
        // traves de la llamada.
        for w in [0x9400_0000u32, 0xd63f_0200] {
            let i = dec(w, 0);
            assert_eq!(i.regs.escritos, u32::MAX, "{w:#010x} deberia pisarlo todo");
            assert_eq!(i.regs.definidos, 0);
        }
    }

    #[test]
    fn cruzar_al_nucleo_tambien_invalida_todos_los_registros() {
        // `svc #0` = d4000001. Lo que hay al otro lado tampoco lo ha mirado el
        // analisis, y ademas devuelve resultados en registros.
        let i = dec(0xd400_0001, 0);
        assert_eq!(i.clase, Clase::Syscall);
        assert_eq!(i.regs.escritos, u32::MAX);
    }

    #[test]
    fn una_comparacion_no_escribe_ningun_registro() {
        // `cmp x0, #5` = f100141f y `tst x0, #0xff` = f2401c1f. Las dos se
        // codifican como una operacion con destino XZR, y XZR no es un registro
        // que se siga: sus escrituras se descartan. Si se siguiera, cada `cmp`
        // invalidaria un registro que no toca —y hay un `cmp` antes de casi
        // cada salto.
        for w in [0xf100_141fu32, 0xf240_1c1f] {
            let i = dec(w, 0);
            assert_eq!(i.clase, Clase::Comparacion, "{w:#010x}");
            assert_eq!(i.regs.escritos, 0, "{w:#010x} no escribe registro alguno");
            assert!(i.regs.lee(0));
        }
    }

    #[test]
    fn una_multiplicacion_escribe_su_destino_y_lee_sus_dos_fuentes() {
        // `mul x0, x1, x2` = 9b027c20.
        let i = dec(0x9b02_7c20, 0);
        assert!(i.regs.escribe(0));
        assert!(i.regs.lee(1));
        assert!(i.regs.lee(2));
    }

    #[test]
    fn una_carga_con_desplazamiento_no_toca_el_registro_base() {
        // `ldr x0, [x8, #8]` = f9400500. Es la distincion que hace util al
        // analisis: si toda carga pisara su base, una direccion formada con
        // `adrp`+`add` no sobreviviria al primer `ldr` de la funcion, y los
        // `ldr` estan por todas partes.
        let i = dec(0xf940_0500, 0);
        assert!(i.regs.escribe(0), "carga en x0");
        assert!(!i.regs.escribe(8), "x8 sigue valiendo lo que valia");
        assert!(i.regs.lee(8));
    }

    #[test]
    fn una_carga_indexada_si_actualiza_el_registro_base() {
        // `ldr x0, [x8], #8` = f8408500 (posindexada) y `ldr x0, [x8, #8]!` =
        // f8408d00 (preindexada). Las dos dejan x8 valiendo otra cosa, y
        // callarlo dejaria vivo en el analisis un valor ya pisado.
        for w in [0xf840_8500u32, 0xf840_8d00] {
            let i = dec(w, 0);
            assert!(i.regs.escribe(0), "{w:#010x}");
            assert!(i.regs.escribe(8), "{w:#010x} actualiza la base");
        }
    }

    #[test]
    fn un_par_con_actualizacion_escribe_los_dos_registros_transferidos() {
        // `stp x29, x30, [sp, #-16]!` = a9bf7bfd y `ldp x29, x30, [sp], #16` =
        // a8c17bfd: el prologo y el epilogo de casi toda funcion de A64.
        for w in [0xa9bf_7bfdu32, 0xa8c1_7bfd] {
            let i = dec(w, 0);
            assert!(i.regs.escribe(29), "{w:#010x}");
            assert!(i.regs.escribe(30), "{w:#010x} tambien el segundo");
        }
    }

    #[test]
    fn un_almacenamiento_exclusivo_escribe_su_registro_de_resultado() {
        // `stxr w9, x0, [x8]` = c8097d00. El destino real —w9, el registro de
        // estado— ocupa el campo donde otras formas llevan un indice, que es el
        // sitio donde menos se parece a un destino. Olvidarlo dejaria vivo un
        // valor ya pisado.
        let i = dec(0xc809_7d00, 0);
        assert!(i.regs.escribe(9), "el resultado de la exclusiva va a w9");
        assert!(i.regs.lee(8));
    }

    #[test]
    fn una_instruccion_de_cifrado_no_invalida_ningun_registro_general() {
        // `aese v0.16b, v1.16b` = 4e284820. Escribe un registro vectorial, y los
        // vectoriales no se siguen: aqui la respuesta exacta y la conservadora
        // coinciden.
        let i = dec(0x4e28_4820, 0);
        assert_eq!(i.clase, Clase::Cripto);
        assert_eq!(i.regs.escritos, 0);
    }

    #[test]
    fn el_registro_31_no_se_sigue_nunca() {
        // En A64 el 31 no nombra un registro: segun la instruccion es XZR —cuyas
        // escrituras se descartan— o SP. Seguirlo haria que un `cmp` pareciera
        // definir un registro.
        assert_eq!(reg_seguido(31), None);
        assert_eq!(reg_seguido(30), Some(30));
        // `stp x29, x30, [sp, #-16]!`: la base es SP y no entra en la mascara.
        let i = dec(0xa9bf_7bfd, 0);
        assert!(!i.regs.escribe(31));
    }

    #[test]
    fn una_palabra_que_este_decodificador_no_entiende_invalida_todo() {
        // Es la regla que sostiene todo lo demas. Una instruccion cuya familia
        // no se reconoce puede escribir cualquier registro; decir que no escribe
        // ninguno dejaria vivo un valor que el programa ya piso. Perder
        // resoluciones por no entender una instruccion es aceptable;
        // inventarlas, no.
        let a = Analisis::opaca(Clase::Otra, Flujo::Secuencial);
        assert_eq!(a.regs.escritos, u32::MAX);
        assert_eq!(a.regs.definidos, 0);
    }

    #[test]
    fn lo_definido_es_siempre_parte_de_lo_escrito() {
        // La invariante del tipo, sobre todas las palabras reales de estas
        // pruebas y sobre un barrido de palabras arbitrarias.
        let reales = [
            0xd2a2_4690u32,
            0x9280_0201,
            0xf28a_cf10,
            0x9000_0008,
            0x9100_6108,
            0xd100_6129,
            0xd63f_0200,
            0xd65f_03c0,
            0xd400_0001,
            0xf100_141f,
            0x9b02_7c20,
            0xf940_0500,
            0xa9bf_7bfd,
            0xc809_7d00,
            0x4e28_4820,
        ];
        for w in reales {
            assert!(dec(w, 0x1000).regs.coherente(), "{w:#010x}");
        }
        let mut x = 0x2545_F491_4F6C_DD1Du64;
        for _ in 0..20_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let i = dec(x as u32, 0x1000);
            assert!(i.regs.coherente(), "{:#010x}", x as u32);
            assert!(i.valor_definido.is_none() || i.regs.definidos != 0);
        }
    }
}
