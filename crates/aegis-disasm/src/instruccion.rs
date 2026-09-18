//! El modelo comun de instruccion: lo que x86 y ARM64 tienen que producir igual.
//!
//! # Por que hay un modelo comun y no dos analisis
//!
//! El grafo de flujo, el grafo de llamadas y las reglas de capacidades no
//! deberian saber de que arquitectura viene lo que miran. Si lo supieran, cada
//! regla habria que escribirla dos veces y las dos versiones divergirian: la de
//! x86 se corregiria y la de ARM64 no, porque el malware que se analiza a diario
//! es de x86.
//!
//! Este modulo define el minimo comun que las tres piezas necesitan, y nada mas.
//!
//! # Por que NO se guarda el texto de cada instruccion
//!
//! Es la decision de diseno con mas consecuencias del modulo. Guardar el
//! mnemonico y la instruccion formateada por cada instruccion decodificada son
//! dos asignaciones de memoria por instruccion: en un binario de cien mil
//! instrucciones, doscientas mil asignaciones pequenas para un texto que **casi
//! nunca se lee**. Solo se lee el de las instrucciones que acaban siendo
//! evidencia, que son unas decenas.
//!
//! Asi que aqui se guarda lo que el ANALISIS necesita —donde esta, cuanto mide,
//! como afecta al flujo, que constantes lleva y de que clase es— y el texto se
//! formatea **a la carta** con [`crate::x86::texto_en`] o
//! [`crate::arm64::texto_en`], para la evidencia y para las pruebas.
//!
//! El efecto medible: un analisis acotado en tiempo no se queda sin memoria
//! antes de quedarse sin tiempo, que es la forma tipica de que una cota de
//! tiempo no sirva de nada.

/// Arquitectura de la que se decodifica.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Arquitectura {
    /// x86 de 32 bits.
    X86,
    /// x86-64.
    X86_64,
    /// ARM64 (AArch64, conjunto A64).
    Arm64,
}

impl Arquitectura {
    /// Nombre legible.
    pub fn nombre(&self) -> &'static str {
        match self {
            Arquitectura::X86 => "x86",
            Arquitectura::X86_64 => "x86-64",
            Arquitectura::Arm64 => "arm64",
        }
    }

    /// Anchura del puntero en bits.
    pub fn bits(&self) -> u32 {
        match self {
            Arquitectura::X86 => 32,
            Arquitectura::X86_64 | Arquitectura::Arm64 => 64,
        }
    }
}

/// Como afecta una instruccion al control de flujo.
///
/// Es lo unico que el constructor del grafo necesita saber, y por eso esta
/// separado de la clase: dos instrucciones de clases distintas —un `jmp` y un
/// `ret`— terminan un bloque igual, y dos de la misma clase —un `jmp` directo y
/// uno indirecto— lo terminan de forma muy distinta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flujo {
    /// Sigue con la siguiente.
    Secuencial,
    /// Salta siempre.
    ///
    /// `destino` es `None` cuando el salto es **indirecto** —a un registro o a
    /// memoria—. Esa distincion es el limite duro de todo desensamblado
    /// estatico: sin ejecutar, el destino solo se conoce si se puede deducir, y
    /// [`crate::cfg`] lo intenta con las tablas de saltos.
    SaltoIncondicional {
        /// A donde, si se sabe.
        destino: Option<u64>,
    },
    /// Salta si se cumple la condicion; si no, sigue con la siguiente.
    SaltoCondicional {
        /// A donde salta si se cumple.
        destino: u64,
    },
    /// Llama a una subrutina y vuelve.
    Llamada {
        /// A donde, si se sabe. `None` si es indirecta.
        destino: Option<u64>,
    },
    /// Vuelve de una subrutina.
    Retorno,
    /// Cruza a modo nucleo: `syscall`, `int`, `sysenter`, `svc`.
    ///
    /// No termina el bloque —la ejecucion vuelve a la siguiente instruccion—
    /// pero es un hecho que las reglas miran, y por eso tiene su propia
    /// variante en vez de contarse como secuencial.
    Frontera,
    /// Para la ejecucion: `hlt`, `ud2`, `brk`.
    Parada,
}

impl Flujo {
    /// Si la instruccion termina un bloque basico.
    ///
    /// La frontera con el nucleo NO lo termina: `syscall` vuelve. Contarla como
    /// terminadora partiria cada funcion que haga una llamada al sistema en
    /// tantos bloques como llamadas, y el grafo dejaria de decir nada sobre su
    /// forma — que es justo lo que las reglas de capacidades miran.
    pub fn termina_bloque(&self) -> bool {
        matches!(
            self,
            Flujo::SaltoIncondicional { .. }
                | Flujo::SaltoCondicional { .. }
                | Flujo::Retorno
                | Flujo::Parada
        )
    }

    /// El destino conocido, si lo hay.
    pub fn destino(&self) -> Option<u64> {
        match self {
            Flujo::SaltoIncondicional { destino } | Flujo::Llamada { destino } => *destino,
            Flujo::SaltoCondicional { destino } => Some(*destino),
            _ => None,
        }
    }

    /// Si es una transferencia de control cuyo destino NO se conoce.
    ///
    /// Es la medida honesta de lo que el analisis estatico no alcanza, y entra
    /// en la cobertura que se declara al final.
    pub fn indirecta(&self) -> bool {
        matches!(
            self,
            Flujo::SaltoIncondicional { destino: None } | Flujo::Llamada { destino: None }
        )
    }
}

/// De que clase es una instruccion, a efectos de las reglas de capacidades.
///
/// No es una taxonomia del conjunto de instrucciones: es la lista de lo que las
/// reglas preguntan. Una clase que ninguna regla mire no aporta nada y si cuesta
/// mantenerla sincronizada entre dos arquitecturas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Clase {
    /// Movimiento de datos.
    Mov,
    /// Calculo de direccion sin acceso (`lea`, `adrp`).
    Direccion,
    /// Apilar.
    Push,
    /// Desapilar.
    Pop,
    /// Suma, resta, multiplicacion, division.
    Aritmetica,
    /// `and`, `or`, `xor`, `not`.
    Logica,
    /// Desplazamientos y rotaciones.
    Desplazamiento,
    /// `cmp`, `test`.
    Comparacion,
    /// Salto, condicional o no.
    Salto,
    /// Llamada.
    Llamada,
    /// Retorno.
    Retorno,
    /// Frontera con el nucleo.
    Syscall,
    /// Parada.
    Parada,
    /// Sin efecto.
    Nop,
    /// Instruccion de cifrado del procesador (`aesenc`, `sha256rnds2`,
    /// `pclmulqdq`).
    ///
    /// Tiene clase propia porque es una de las evidencias mas limpias que
    /// existen: un binario que usa las instrucciones AES del procesador esta
    /// cifrando, y no hay lectura benigna alternativa de esa instruccion.
    Cripto,
    /// Operacion sobre cadenas (`movs`, `stos`, `rep`).
    Cadena,
    /// Cualquier otra.
    Otra,
}

/// Una instruccion decodificada, en lo que el analisis necesita de ella.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruccion {
    /// Donde empieza.
    pub direccion: u64,
    /// Cuantos bytes ocupa.
    ///
    /// Es `u8` porque ninguna instruccion de ninguna de las tres arquitecturas
    /// pasa de 15 bytes. Un decodificador que devolviera cero aqui dejaria el
    /// recorrido sin avanzar, y por eso [`Instruccion::valida`] lo comprueba.
    pub longitud: u8,
    /// De que clase es.
    pub clase: Clase,
    /// Como afecta al flujo.
    pub flujo: Flujo,
    /// Las constantes que lleva dentro, acotadas.
    ///
    /// Son la materia prima del analisis de constantes que resuelve llamadas
    /// indirectas, y de las reglas que identifican algoritmos por sus constantes
    /// magicas. Se acotan a cuatro porque ninguna instruccion real lleva mas, y
    /// dejarlo sin acotar seria una via de agotamiento de memoria por un fichero
    /// construido para eso.
    pub inmediatos: Vec<u64>,
    /// Si toca memoria para leer.
    pub lee_memoria: bool,
    /// Si toca memoria para escribir.
    pub escribe_memoria: bool,
    /// Que registros generales lee y escribe. Ver [`Registros`].
    pub regs: Registros,
    /// El valor exacto que la instruccion deja en el registro que define.
    ///
    /// Solo lo hay cuando el valor **no depende de nada anterior**: un
    /// `mov rax, 0x401000`, un `lea rax, [rip+0x2f10]` —donde ya viene resuelto
    /// a direccion absoluta—, un `movz x16, #0x1234, lsl #16`, un `adrp x8,
    /// pagina`.
    ///
    /// Va aparte de [`Instruccion::inmediatos`] porque son dos cosas distintas:
    /// `inmediatos` es «las constantes que esta instruccion lleva escritas», que
    /// es lo que miran las reglas que buscan constantes magicas, y esto es «el
    /// valor que este registro pasa a tener», que es lo que necesita el analisis
    /// que resuelve llamadas indirectas. Confundirlas obligaria al analisis a
    /// adivinar cual de los inmediatos es el valor, y a acertar por convenio.
    pub valor_definido: Option<u64>,
    /// El registro cuyo valor pasa TAL CUAL al registro que la instruccion
    /// define.
    ///
    /// Es un `mov rax, rbx`, y es la tercera forma de que un registro tenga un
    /// valor conocido: heredarlo de otro. Sin esto, el analisis pierde el rastro
    /// en cuanto el valor cambia de registro —que es una de las ofuscaciones mas
    /// baratas que existen, y que ademas el compilador hace por su cuenta.
    ///
    /// Va aparte de [`Instruccion::valor_definido`] porque no es un valor: es una
    /// referencia a otro registro, y solo significa algo mirando el estado del
    /// analisis en ese punto.
    pub copia_de: Option<u8>,
    /// La constante que la instruccion SUMA al registro que lee y escribe.
    ///
    /// Es la otra mitad de la formacion de direcciones en dos pasos: `adrp x8,
    /// pagina` define, y `add x8, x8, #resto` desplaza. Lleva signo porque un
    /// `sub` es exactamente lo mismo con el signo cambiado, y guardarlo sin
    /// signo obligaria a distinguir suma de resta por la clase —que no las
    /// distingue— o por el texto —que no se guarda.
    ///
    /// Solo vale cuando el registro que se lee es el mismo que se escribe, y eso
    /// se comprueba con [`Registros`], no se supone.
    pub delta: Option<i64>,
    /// Registro del que la instruccion toma su DESTINO, en una transferencia
    /// indirecta.
    ///
    /// Es el numero de registro de [`Registros`], para que un `call rax` y un
    /// `mov eax, ...` previo hablen del mismo registro. Con esto y con
    /// [`Instruccion::regs`] se cierra el circulo: el analisis de constantes
    /// puede decir a donde va un `call rax`.
    ///
    /// Es `None` cuando la transferencia es indirecta **a traves de memoria**
    /// (`call [rip+0x2f10]`, `jmp [rbx+8]`). Ese caso no se resuelve aqui y se
    /// declara como indirecto no resuelto, que es la verdad: el destino esta en
    /// una posicion de memoria cuyo contenido el analisis estatico no conoce.
    pub destino_reg: Option<u8>,
}

/// Los registros generales que una instruccion lee y escribe.
///
/// # Por que mascaras y no un numero de registro
///
/// El analisis de constantes hace dos cosas distintas con una escritura:
/// **invalidar** lo que sabia del registro, y **establecer** un valor nuevo.
/// Confundirlas es un error con consecuencias opuestas, y guardar un solo
/// registro no permite ni lo uno ni lo otro.
///
/// **Un registro no basta.** `xchg rax, rbx` escribe dos; `mul rbx` escribe
/// `RAX` y `RDX` sin nombrarlos; `cpuid` escribe cuatro; y una `call` deja en
/// estado indefinido todos los registros volatiles de la convencion de llamada.
/// Si el modelo solo guarda uno, el resto conserva en el analisis un valor que
/// el programa ya piso. Y un valor que el analisis cree cierto y no lo es acaba
/// en un `call rax` resuelto hacia una direccion **a la que el programa nunca
/// llama**: una arista inventada en el grafo. Eso no es un analisis incompleto,
/// es un analisis que miente, y es peor que dejar la llamada sin resolver.
///
/// **Normalizar a secas tampoco basta.** Para invalidar hay que subir al
/// registro completo: si se aprendio `RAX = 0x401000` y despues viene
/// `mov al, 1`, ya no se sabe cuanto vale `RAX`. Pero para *establecer*, esa
/// misma normalizacion es falsa: `mov al, 1` no deja `RAX` valiendo 1, deja sus
/// 56 bits altos como estaban.
///
/// De ahi las dos mascaras de escritura: [`Registros::escritos`] es «esto ya no
/// vale lo que valia» y [`Registros::definidos`] es «esto vale exactamente lo
/// que se acaba de escribir». La segunda es siempre un subconjunto de la
/// primera.
///
/// # Por que tambien se guarda lo que se lee
///
/// Porque la forma habitual de formar una direccion no cabe en una sola
/// instruccion. En A64 es `adrp x8, pagina` seguido de `add x8, x8, #resto`, y
/// en x86 aparece el equivalente con `lea`/`add`. La segunda instruccion no
/// define nada por si sola: define «lo que hubiera en `x8`, mas una constante».
/// Para poder sumar ahi hace falta saber que esa instruccion **lee el mismo
/// registro que escribe**, y sin [`Registros::leidos`] no se puede distinguir de
/// un `add x8, x9, #resto`, que no tiene nada que ver con el valor anterior de
/// `x8`. Sin esa distincion, o se pierden todas las direcciones formadas en dos
/// pasos, o se inventan.
///
/// # Numeracion
///
/// El numero de registro es **local a la arquitectura** —0..=15 son `RAX`..`R15`
/// en x86-64, 0..=30 son `X0`..`X30` en A64— y eso vale porque una funcion
/// entera viene de un solo decodificador. Solo se representan registros
/// generales: no hay transferencia de control a traves de un registro vectorial
/// en ninguna de las tres arquitecturas, asi que para lo que estas mascaras
/// sirven, los generales son el conjunto completo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Registros {
    /// Registros que la instruccion lee.
    pub leidos: u32,
    /// Registros que la instruccion modifica de cualquier forma.
    ///
    /// Es deliberadamente **generoso**: incluye escrituras parciales,
    /// condicionales e implicitas. Sobrar aqui cuesta una llamada indirecta sin
    /// resolver; faltar cuesta una arista inventada.
    pub escritos: u32,
    /// Subconjunto de [`Registros::escritos`] que queda COMPLETAMENTE definido.
    ///
    /// Cierto para un `mov rax, imm` y tambien para un `mov eax, imm` en 64
    /// bits, porque una escritura de 32 bits extiende con ceros la parte alta.
    /// Falso para `mov al, 1` y `mov ax, 1`, que conservan bits anteriores, y
    /// falso para toda escritura condicional (`cmovz`), que puede no ocurrir.
    pub definidos: u32,
}

/// Cuantos registros generales caben en una mascara de [`Registros`].
pub const MAX_REGISTROS: u8 = 32;

impl Registros {
    /// Una instruccion que no toca ningun registro general.
    pub const fn nada() -> Registros {
        Registros {
            leidos: 0,
            escritos: 0,
            definidos: 0,
        }
    }

    /// Anota que `reg` se lee.
    ///
    /// Un numero de registro fuera de la mascara se ignora en silencio y eso es
    /// correcto: significa que no es un registro general, y los no generales no
    /// participan en este analisis.
    pub fn anota_leido(&mut self, reg: u8) {
        if reg < MAX_REGISTROS {
            self.leidos |= 1 << reg;
        }
    }

    /// Anota que `reg` queda modificado, sin quedar definido por completo.
    pub fn anota_escrito(&mut self, reg: u8) {
        if reg < MAX_REGISTROS {
            self.escritos |= 1 << reg;
        }
    }

    /// Anota que `reg` queda completamente definido —y por tanto, modificado.
    pub fn anota_definido(&mut self, reg: u8) {
        if reg < MAX_REGISTROS {
            self.escritos |= 1 << reg;
            self.definidos |= 1 << reg;
        }
    }

    /// Si `reg` se lee.
    pub fn lee(&self, reg: u8) -> bool {
        reg < MAX_REGISTROS && self.leidos & (1 << reg) != 0
    }

    /// Si `reg` queda modificado.
    pub fn escribe(&self, reg: u8) -> bool {
        reg < MAX_REGISTROS && self.escritos & (1 << reg) != 0
    }

    /// Si `reg` queda completamente definido.
    pub fn define(&self, reg: u8) -> bool {
        reg < MAX_REGISTROS && self.definidos & (1 << reg) != 0
    }

    /// El unico registro que la instruccion escribe, si escribe exactamente uno.
    ///
    /// Lo pide el analisis de constantes: una instruccion que escribe dos
    /// registros no se puede seguir con un solo valor, y una que no escribe
    /// ninguno no aporta nada.
    pub fn unico_escrito(&self) -> Option<u8> {
        if self.escritos.count_ones() != 1 {
            return None;
        }
        Some(self.escritos.trailing_zeros() as u8)
    }

    /// Si no toca ningun registro general.
    pub fn vacia(&self) -> bool {
        self.leidos == 0 && self.escritos == 0
    }

    /// La invariante del tipo: lo definido es siempre parte de lo escrito.
    ///
    /// Si dejara de cumplirse, habria un registro «definido» que el analisis no
    /// invalidaria al reescribirlo, que es justo el fallo que este tipo existe
    /// para impedir.
    pub fn coherente(&self) -> bool {
        self.definidos & !self.escritos == 0
    }
}

/// Maximo de inmediatos que se guardan por instruccion.
pub const MAX_INMEDIATOS: usize = 4;

impl Instruccion {
    /// Donde empieza la siguiente instruccion.
    pub fn siguiente(&self) -> u64 {
        self.direccion.wrapping_add(u64::from(self.longitud))
    }

    /// Comprueba la invariante que sostiene todo recorrido.
    ///
    /// Una longitud de cero deja el bucle del desensamblador sin avanzar, y eso
    /// con un fichero hostil es un cuelgue. Ningun decodificador de este crate
    /// puede devolver una instruccion que no la cumpla, y las pruebas de entrada
    /// hostil lo comprueban sobre bytes arbitrarios.
    pub fn valida(&self) -> bool {
        self.longitud > 0 && self.longitud <= 15 && self.inmediatos.len() <= MAX_INMEDIATOS
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn la_frontera_con_el_nucleo_no_termina_un_bloque() {
        // Si lo terminara, una funcion con diez llamadas al sistema saldria
        // partida en once bloques y el grafo dejaria de decir nada sobre su
        // forma, que es lo que miran las reglas de capacidades.
        assert!(!Flujo::Frontera.termina_bloque());
        assert!(!Flujo::Secuencial.termina_bloque());
        assert!(!Flujo::Llamada { destino: Some(8) }.termina_bloque());
    }

    #[test]
    fn los_saltos_y_el_retorno_si_terminan_un_bloque() {
        assert!(Flujo::SaltoIncondicional { destino: Some(8) }.termina_bloque());
        assert!(Flujo::SaltoIncondicional { destino: None }.termina_bloque());
        assert!(Flujo::SaltoCondicional { destino: 8 }.termina_bloque());
        assert!(Flujo::Retorno.termina_bloque());
        assert!(Flujo::Parada.termina_bloque());
    }

    #[test]
    fn una_transferencia_sin_destino_conocido_se_declara_indirecta() {
        // Es la medida honesta de lo que el analisis estatico no alcanza, y
        // entra en la cobertura declarada.
        assert!(Flujo::SaltoIncondicional { destino: None }.indirecta());
        assert!(Flujo::Llamada { destino: None }.indirecta());
        assert!(!Flujo::SaltoIncondicional { destino: Some(1) }.indirecta());
        assert!(!Flujo::SaltoCondicional { destino: 1 }.indirecta());
        assert!(!Flujo::Retorno.indirecta());
    }

    #[test]
    fn una_instruccion_de_longitud_cero_no_es_valida() {
        // El caso que cuelga el desensamblador: el cursor no avanza nunca.
        let i = Instruccion {
            direccion: 0x1000,
            longitud: 0,
            clase: Clase::Nop,
            flujo: Flujo::Secuencial,
            inmediatos: vec![],
            lee_memoria: false,
            escribe_memoria: false,
            regs: Registros::nada(),
            valor_definido: None,
            copia_de: None,
            delta: None,
            destino_reg: None,
        };
        assert!(!i.valida());
    }

    #[test]
    fn una_instruccion_mas_larga_que_el_maximo_de_x86_no_es_valida() {
        let i = Instruccion {
            direccion: 0x1000,
            longitud: 16,
            clase: Clase::Otra,
            flujo: Flujo::Secuencial,
            inmediatos: vec![],
            lee_memoria: false,
            escribe_memoria: false,
            regs: Registros::nada(),
            valor_definido: None,
            copia_de: None,
            delta: None,
            destino_reg: None,
        };
        assert!(!i.valida(), "ninguna instruccion x86 pasa de 15 bytes");
    }

    #[test]
    fn la_siguiente_direccion_no_desborda() {
        // Una instruccion al final del espacio de direcciones no puede hacer
        // entrar en panico al recorrido.
        let i = Instruccion {
            direccion: u64::MAX,
            longitud: 4,
            clase: Clase::Nop,
            flujo: Flujo::Secuencial,
            inmediatos: vec![],
            lee_memoria: false,
            escribe_memoria: false,
            regs: Registros::nada(),
            valor_definido: None,
            copia_de: None,
            delta: None,
            destino_reg: None,
        };
        assert_eq!(i.siguiente(), 3, "da la vuelta en vez de entrar en panico");
    }

    #[test]
    fn cada_arquitectura_declara_su_anchura() {
        assert_eq!(Arquitectura::X86.bits(), 32);
        assert_eq!(Arquitectura::X86_64.bits(), 64);
        assert_eq!(Arquitectura::Arm64.bits(), 64);
    }
}
