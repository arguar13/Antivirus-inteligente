//! Deteccion y bloqueo de depuradores.
//!
//! # Por que un EDR se defiende de los depuradores
//!
//! El malware que se topa con un producto de seguridad tiene dos opciones:
//! evadirlo o desactivarlo. Desactivarlo empieza por entenderlo, y entenderlo
//! empieza por adjuntar un depurador al agente para ver que detecta y como. Un
//! agente que se deja depurar entrega su logica de deteccion al atacante.
//!
//! No es infalible y no pretende serlo: un analista con un kernel modificado o
//! un depurador que intercepte `ptrace` lo sortea. El objetivo es el mismo que
//! el del cifrado de cadenas: subir el coste, quedarse fuera del alcance del
//! atacante oportunista y del script que automatiza el analisis.
//!
//! # Los dos mecanismos, y por que hacen falta los dos
//!
//! En Linux un proceso solo puede tener UN trazador a la vez. De ahi salen las
//! dos comprobaciones, que se complementan:
//!
//! 1. **`TracerPid` de `/proc/self/status`.** Si ya hay un depurador adjunto,
//!    ese campo trae su PID. Es una lectura, no cambia nada, y detecta al
//!    depurador que arranco el proceso bajo su control.
//! 2. **`ptrace(PTRACE_TRACEME)`.** El proceso se declara trazado por su padre.
//!    Si ya habia un trazador, la llamada FALLA, lo que delata al depurador. Y
//!    si no lo habia, ocupa el unico hueco de trazador que existe, con lo que un
//!    depurador que intente adjuntarse DESPUES se encontrara el sitio tomado.
//!    Una sola llamada detecta al que ya estaba y bloquea al que vendria.

use std::sync::atomic::{AtomicU8, Ordering};

/// Resultado de comprobar la presencia de un depurador.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebuggerCheck {
    /// No se detecto ningun trazador.
    Clear,
    /// Hay un trazador adjunto; se incluye su PID cuando se conoce.
    Detected {
        /// PID del trazador, o 0 si se supo de su existencia sin el PID.
        tracer_pid: i32,
    },
}

impl DebuggerCheck {
    /// Indica si hay un depurador presente.
    pub fn is_detected(self) -> bool {
        matches!(self, DebuggerCheck::Detected { .. })
    }
}

/// Lee el campo `TracerPid` de un contenido con el formato de
/// `/proc/self/status`.
///
/// Se separa del acceso al fichero para poder probar el analisis con entradas
/// controladas: el caso de "hay trazador" no se puede provocar comodamente en
/// una prueba, pero si se puede comprobar que el analizador lo reconoce.
pub fn parse_tracer_pid(status: &str) -> Option<i32> {
    for linea in status.lines() {
        if let Some(resto) = linea.strip_prefix("TracerPid:") {
            return resto.trim().parse::<i32>().ok();
        }
    }
    None
}

/// Comprueba `/proc/self/status` en busca de un trazador.
pub fn tracer_from_proc() -> DebuggerCheck {
    match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => match parse_tracer_pid(&s) {
            Some(pid) if pid != 0 => DebuggerCheck::Detected { tracer_pid: pid },
            _ => DebuggerCheck::Clear,
        },
        // Sin /proc no se puede afirmar nada; se declara despejado en vez de
        // suponer lo peor y cerrar el agente en un sistema sin procfs.
        Err(_) => DebuggerCheck::Clear,
    }
}

/// Intenta reclamar el papel de trazador con `PTRACE_TRACEME`.
///
/// Devuelve `Detected` si la llamada falla, lo que significa que ya habia un
/// trazador. Si tiene exito, ademas de no detectar nada, deja el hueco de
/// trazador ocupado para que un depurador posterior no pueda adjuntarse.
///
/// Solo debe llamarse UNA vez y de forma temprana: un segundo `TRACEME` no
/// aporta nada, y llamarlo tras haber lanzado hilos que a su vez usen `ptrace`
/// complica el arbol de trazado sin beneficio.
pub fn claim_traceme() -> DebuggerCheck {
    // SAFETY: `ptrace` es una llamada al sistema sin efectos sobre la memoria
    // de este proceso; PTRACE_TRACEME ignora los otros tres argumentos.
    let r = unsafe {
        libc::ptrace(
            libc::PTRACE_TRACEME,
            0,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if r == -1 {
        DebuggerCheck::Detected { tracer_pid: 0 }
    } else {
        DebuggerCheck::Clear
    }
}

/// Estado del enforcement, para no actuar dos veces.
static ESTADO: AtomicU8 = AtomicU8::new(0);
const NO_INICIADO: u8 = 0;
const ACTIVO: u8 = 1;

/// Politica ante la deteccion de un depurador.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Cerrar el proceso de inmediato.
    ///
    /// Es la respuesta de produccion: si alguien esta depurando el agente, la
    /// integridad de la deteccion ya no se puede garantizar, y seguir corriendo
    /// solo le da mas tiempo al analista.
    Terminate,
    /// Solo informar, sin cerrar.
    ///
    /// Para las pruebas y para un modo de diagnostico en el que un desarrollador
    /// autorizado necesita adjuntar un depurador sin que el proceso se suicide.
    ReportOnly,
}

/// Resultado de aplicar la politica de anti-depuracion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Enforcement {
    /// Lo que vio la comprobacion de `/proc`.
    pub proc_check: DebuggerCheck,
    /// Lo que vio `PTRACE_TRACEME`.
    pub traceme_check: DebuggerCheck,
    /// Si se detecto un depurador por cualquiera de las dos vias.
    pub detected: bool,
}

impl Enforcement {
    /// Combina las dos comprobaciones.
    fn from(proc_check: DebuggerCheck, traceme_check: DebuggerCheck) -> Enforcement {
        Enforcement {
            proc_check,
            traceme_check,
            detected: proc_check.is_detected() || traceme_check.is_detected(),
        }
    }
}

/// Comprueba la presencia de un depurador SIN reclamar el trazador ni cerrar el
/// proceso. Es la via segura para las pruebas y el diagnostico.
pub fn detect() -> Enforcement {
    Enforcement::from(tracer_from_proc(), DebuggerCheck::Clear)
}

/// Aplica la anti-depuracion segun la politica.
///
/// Con [`Policy::Terminate`], si detecta un depurador cierra el proceso con
/// `_exit` y un codigo distinto de cero, sin desenredar la pila: un `panic`
/// ordenado le daria al analista el mensaje y el rastro, que es justo lo que se
/// le quiere negar.
///
/// Es idempotente: solo la primera llamada reclama el trazador.
pub fn enforce(policy: Policy) -> Enforcement {
    let primera = ESTADO
        .compare_exchange(NO_INICIADO, ACTIVO, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok();

    let proc_check = tracer_from_proc();
    let traceme_check = if primera {
        claim_traceme()
    } else {
        DebuggerCheck::Clear
    };
    let resultado = Enforcement::from(proc_check, traceme_check);

    if resultado.detected && policy == Policy::Terminate {
        // SAFETY: `_exit` no vuelve; termina el proceso sin ejecutar
        // destructores ni descargar la memoria, que es lo que se quiere.
        unsafe { libc::_exit(57) };
    }
    resultado
}
