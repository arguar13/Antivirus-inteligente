//! # `aegis-emu` — Micro-sandbox de emulacion x86-64 (FASE 56)
//!
//! ## El problema: el analisis estatico se rinde ante el ofuscamiento
//!
//! El malware moderno casi nunca lleva su codigo en claro. Un empaquetador
//! —UPX mutado, un cifrador a medida— guarda el codigo real comprimido o cifrado
//! y lleva un pequeno descompresor que, al ejecutarse, lo despliega en memoria y
//! salta a el. Una firma sobre el fichero de disco no ve nada, porque el codigo
//! que busca todavia no existe: esta cifrado.
//!
//! La FASE 27 (`aegis-unpacker`) ya lo resuelve **ejecutando** el binario bajo
//! `ptrace`, confinado. Esta fase aporta la via COMPLEMENTARIA y mas segura:
//! **emular** el binario en una CPU virtual, de modo que ni una sola instruccion
//! del codigo desconocido toca el procesador real. El descompresor se ejecuta
//! *dentro del emulador*; sus escrituras caen en memoria virtual; sus llamadas al
//! sistema se **interceptan** en vez de realizarse. Asi se puede desplegar y
//! observar un binario hostil sin ningun riesgo para el host.
//!
//! ## Por que un emulador propio y no `unicorn-engine`
//!
//! El megaprompt sugeria un binding a `unicorn-engine`. Se descarto **a
//! proposito**: unicorn es un emulador en C de decenas de miles de lineas
//! (derivado de QEMU). Meterlo en el arbol de dependencias del agente —la pieza
//! que defiende el endpoint— seria anadir una superficie de ataque nativa enorme
//! dentro de nuestra propia defensa, justo lo que la disciplina del proyecto
//! prohibe. Se elige un emulador **propio, en Rust puro**, con dos consecuencias
//! honestas:
//!
//! 1. Lo que soporta se prueba de verdad contra **codigo maquina x86-64 real**
//!    (stubs ensamblados a mano en las pruebas), cero mocks.
//! 2. Lo que NO soporta se rechaza **RUIDOSAMENTE**
//!    ([`EmuError::InstruccionNoSoportada`]): el emulador nunca finge haber
//!    ejecutado algo que no entiende. El subconjunto de instrucciones cubierto
//!    esta documentado en [`decodificador`]; es el que usan los descompresores y
//!    el shellcode, no el x86 entero.
//!
//! ## Las piezas
//!
//! - [`cpu`]: registros x86-64, puntero de instruccion y banderas.
//! - [`memoria`]: el espacio de direcciones virtual, con seguimiento de las
//!   escrituras (la clave para detectar el desempaquetado: ejecutar codigo en
//!   una region que se escribio en tiempo de ejecucion).
//! - [`decodificador`]: decodifica una instruccion (prefijos REX, ModRM, SIB,
//!   desplazamiento e inmediato) del subconjunto soportado.
//! - [`ejecutor`]: ejecuta la instruccion sobre la CPU y la memoria, con un
//!   presupuesto de instrucciones que garantiza que la emulacion termina.
//! - [`syscalls`]: traduce el numero de syscall de Linux x86-64 a un evento de
//!   comportamiento observable.
//! - [`heuristica`]: a partir de la secuencia de eventos, decide si el binario es
//!   benigno o cae en un patron malicioso (auto-inyeccion, C2, ransomware...).
//!   Es la parte que puede estar mal de forma peligrosa, y se prueba con casos
//!   decisivos.

#![forbid(unsafe_code)]

pub mod cpu;
pub mod decodificador;
pub mod ejecutor;
pub mod heuristica;
pub mod memoria;
pub mod syscalls;
pub mod taint;

use cpu::{Cpu, RSP};
use ejecutor::Ejecutor;
use memoria::Memoria;
use thiserror::Error;

pub use heuristica::{ClaseComportamiento, Severidad, Veredicto};
pub use syscalls::{Categoria, EventoComportamiento};
pub use taint::{DeteccionDop, RegionProtegida};

/// El micro-sandbox de emulacion: se le da un blob de codigo desconocido y
/// devuelve un informe de lo que hace, sin que ninguna de sus instrucciones haya
/// tocado el host.
///
/// El blob se carga en una region ejecutable Y escribible (para que un
/// empaquetador que se descifra a si mismo funcione), con una pila propia. El
/// `mmap` emulado reparte regiones reales, asi que los empaquetadores que
/// reservan-escriben-saltan tambien se despliegan de verdad.
#[derive(Debug, Clone, Copy)]
pub struct AegisSandbox {
    /// Presupuesto de instrucciones (defensa contra el que no termina).
    pub presupuesto: u64,
    /// Direccion donde se carga el codigo.
    pub base_codigo: u64,
    /// Direccion base de la pila.
    pub base_pila: u64,
}

impl Default for AegisSandbox {
    fn default() -> Self {
        Self {
            // 200k instrucciones: mas que de sobra para desplegar un packer, y
            // en la practica se resuelve en microsegundos (muy por debajo de los
            // 100 ms del presupuesto de la fase).
            presupuesto: 200_000,
            base_codigo: 0x0040_0000,
            base_pila: 0x7fff_0000,
        }
    }
}

/// El informe que devuelve el sandbox tras analizar un binario.
#[derive(Debug, Clone)]
pub struct InformeSandbox {
    /// El veredicto de la heuristica.
    pub veredicto: Veredicto,
    /// La traza de eventos observados, en orden.
    pub eventos: Vec<EventoComportamiento>,
    /// La carga desempaquetada, si el binario se desplego a si mismo: son los
    /// bytes de la ultima region que escribio y ejecuto, listos para pasar al
    /// motor YARA (que ahora SI ve el codigo real).
    pub desempaquetado: Option<Vec<u8>>,
    /// Instrucciones ejecutadas.
    pub instrucciones: u64,
    /// `true` si el binario termino por si mismo.
    pub termino: bool,
    /// Si la emulacion se detuvo por un error (p. ej. una instruccion fuera del
    /// subconjunto soportado), su descripcion. NO es un fallo del sandbox: es la
    /// honestidad de declarar que no se pudo seguir emulando, con la traza
    /// obtenida hasta ese punto intacta.
    pub error: Option<String>,
    /// Si el binario intento una programacion orientada a datos (DOP): escribio,
    /// en masa, datos contaminados (derivados de un `read`) sobre una region del
    /// sistema protegida. `None` si no se declaro ninguna region protegida o no
    /// se disparo la deteccion.
    pub dop: Option<DeteccionDop>,
}

impl AegisSandbox {
    /// Un sandbox con la configuracion por defecto.
    #[must_use]
    pub fn nuevo() -> Self {
        Self::default()
    }

    /// Analiza un blob de codigo x86-64 (el punto de entrada del binario
    /// desconocido, o el shellcode extraido) y devuelve el informe.
    #[must_use]
    pub fn analizar(&self, codigo: &[u8]) -> InformeSandbox {
        self.analizar_protegido(codigo, &[])
    }

    /// Como [`AegisSandbox::analizar`], pero declarando regiones del sistema
    /// PROTEGIDAS (estructuras que ningun codigo legitimo reescribe con datos
    /// crudos del exterior). Si el binario escribe, en masa, datos contaminados
    /// —derivados de un `read`— sobre una de ellas, el informe lo marca como un
    /// intento de programacion orientada a datos ([`InformeSandbox::dop`]).
    #[must_use]
    pub fn analizar_protegido(
        &self,
        codigo: &[u8],
        regiones: &[RegionProtegida],
    ) -> InformeSandbox {
        let mut mem = Memoria::nueva();
        let tam_cod = ((codigo.len() + 0xFFF) & !0xFFF).max(0x1000);
        let mut bytes = codigo.to_vec();
        bytes.resize(tam_cod, 0);
        // El codigo va en una region R-W-X: un empaquetador que se descifra a si
        // mismo escribe sobre su propio codigo, y al re-ejecutarlo se detecta el
        // desempaquetado.
        mem.mapear(self.base_codigo, bytes, true, true, true)
            .expect("mapear la region de codigo");
        mem.mapear_vacia(self.base_pila, 0x1_0000, true, true, false)
            .expect("mapear la pila");

        let mut cpu = Cpu::nueva();
        cpu.rip = self.base_codigo;
        cpu.escribir64(RSP, self.base_pila + 0x8000);

        let mut e = Ejecutor::nuevo(cpu, mem);
        for r in regiones {
            e.proteger_region(r.base, r.fin, r.nombre);
        }
        let error = match e.ejecutar(self.presupuesto) {
            Ok(()) => None,
            Err(err) => Some(err.to_string()),
        };

        let eventos = e.eventos().to_vec();
        // La carga desempaquetada es la ultima region escrita-y-ejecutada.
        let desempaquetado = eventos.iter().rev().find_map(|ev| match ev {
            EventoComportamiento::Desempaquetado { base, fin } => {
                e.mem.leer_bytes(*base, (*fin - *base) as usize).ok()
            }
            EventoComportamiento::LlamadaSistema { .. } => None,
        });

        let veredicto = heuristica::evaluar(&eventos);
        let dop = e.deteccion_dop();
        InformeSandbox {
            veredicto,
            eventos,
            desempaquetado,
            instrucciones: e.instrucciones(),
            termino: e.termino(),
            error,
            dop,
        }
    }
}

/// Error del micro-sandbox de emulacion. Todas las variantes fallan de forma
/// ruidosa: una emulacion que no puede continuar de forma fiel se DETIENE y lo
/// dice, nunca sigue adivinando.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EmuError {
    /// Se accedio a una direccion que no cae en ninguna region mapeada.
    #[error("acceso a direccion no mapeada: {0:#x}")]
    DireccionNoMapeada(u64),

    /// Lectura sobre una region sin permiso de lectura.
    #[error("lectura sin permiso en {0:#x}")]
    SinPermisoLectura(u64),

    /// Escritura sobre una region sin permiso de escritura.
    #[error("escritura sin permiso en {0:#x}")]
    SinPermisoEscritura(u64),

    /// Se intento mapear una region que solapa con otra ya existente.
    #[error("la region en {0:#x} solapa con otra ya mapeada")]
    RegionSolapada(u64),

    /// El decodificador encontro un opcode fuera del subconjunto soportado. Se
    /// nombra el opcode y donde estaba: el emulador NO finge ejecutarlo.
    #[error("instruccion no soportada en {direccion:#x}: opcode {opcode}")]
    InstruccionNoSoportada {
        /// Direccion de la instruccion.
        direccion: u64,
        /// Descripcion del opcode (bytes en hexadecimal).
        opcode: String,
    },

    /// El decodificador encontro un prefijo que no soporta.
    #[error("prefijo no soportado en {direccion:#x}: {prefijo:#x}")]
    PrefijoNoSoportado {
        /// Direccion de la instruccion.
        direccion: u64,
        /// Byte de prefijo.
        prefijo: u8,
    },

    /// Se agoto el presupuesto de instrucciones sin que el binario terminase.
    /// No es un fallo del emulador: es su defensa contra un binario que no para
    /// (un bucle infinito de un empaquetador defectuoso o deliberado).
    #[error("presupuesto de {0} instrucciones agotado")]
    PresupuestoAgotado(u64),

    /// La instruccion pedia mas bytes de los que quedan en la region de codigo.
    #[error("fin de codigo inesperado al decodificar en {0:#x}")]
    CodigoTruncado(u64),
}
