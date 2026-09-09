//! Contador de la PMU: la via barata y siempre activa, cuando el hardware la da.
//!
//! # Que aporta la PMU a la deteccion de syscalls directas
//!
//! Trazar con `ptrace` es exacto pero caro: para el proceso en cada syscall. En
//! produccion, sobre una flota, no se puede trazar todo. La PMU
//! (Performance Monitoring Unit) del procesador cuenta eventos en hardware sin
//! parar nada; con muestreo (PEBS) puede ademas capturar el puntero de
//! instruccion de esos eventos casi gratis. Es la version escalable de lo que
//! el trazador hace caro: un cribado continuo que decide a QUE proceso vale la
//! pena mirar de cerca.
//!
//! # Honestidad sobre el hardware
//!
//! Muchas maquinas virtuales —esta, un microVM de Firecracker, entre ellas— no
//! exponen PMU al huesped: `perf_event_open` con `PERF_TYPE_HARDWARE` devuelve
//! `ENOENT`. Eso NO es un fallo del producto ni se disimula: se reporta como
//! "no aplicable", igual que la ausencia de TPM en el escaner de firmware. La
//! deteccion no depende de la PMU —la hace el trazador con verificacion
//! cruzada—; la PMU solo la abarata donde existe.

use std::os::fd::OwnedFd;

use crate::perf::{
    leer_contador, perf_event_open, perf_ioctl, PerfEventAttr, PERF_COUNT_HW_INSTRUCTIONS,
    PERF_EVENT_IOC_DISABLE, PERF_EVENT_IOC_ENABLE, PERF_EVENT_IOC_RESET, PERF_TYPE_HARDWARE,
};

/// Disponibilidad de la PMU de hardware en esta maquina.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SoportePmu {
    /// La PMU responde: se pudo abrir un contador de hardware.
    Disponible,
    /// La PMU no esta expuesta (tipico de maquinas virtuales).
    NoDisponible(String),
}

impl SoportePmu {
    /// `true` si hay PMU utilizable.
    pub fn hay(&self) -> bool {
        matches!(self, SoportePmu::Disponible)
    }
}

/// Contador de hardware abierto sobre el hilo llamante.
///
/// Cierra el evento al soltarse (el descriptor es propietario).
pub struct ContadorHardware {
    fd: OwnedFd,
}

impl ContadorHardware {
    /// Abre un contador de instrucciones de usuario sobre el hilo actual.
    ///
    /// Devuelve `Err` con el `errno` real si la PMU no esta: el llamante lo
    /// traduce a `SoportePmu::NoDisponible` sin inventarse nada.
    pub fn instrucciones() -> Result<ContadorHardware, std::io::Error> {
        let mut attr = PerfEventAttr::nueva(PERF_TYPE_HARDWARE);
        attr.config = PERF_COUNT_HW_INSTRUCTIONS;
        let fd = perf_event_open(&attr, 0, -1, -1, 0)?;
        Ok(ContadorHardware { fd })
    }

    /// Pone el contador a cero y lo arranca.
    pub fn arrancar(&self) -> Result<(), std::io::Error> {
        perf_ioctl(&self.fd, PERF_EVENT_IOC_RESET)?;
        perf_ioctl(&self.fd, PERF_EVENT_IOC_ENABLE)
    }

    /// Detiene el contador.
    pub fn detener(&self) -> Result<(), std::io::Error> {
        perf_ioctl(&self.fd, PERF_EVENT_IOC_DISABLE)
    }

    /// Lee el valor actual del contador.
    pub fn leer(&self) -> Result<u64, std::io::Error> {
        leer_contador(&self.fd)
    }
}

/// Sondea si esta maquina expone PMU de hardware.
///
/// Intenta abrir un contador de instrucciones y lo cierra de inmediato. No
/// deja nada montado; es una pregunta, no un compromiso.
pub fn sondear_pmu() -> SoportePmu {
    match ContadorHardware::instrucciones() {
        Ok(_contador) => SoportePmu::Disponible,
        Err(e) => SoportePmu::NoDisponible(motivo(&e)),
    }
}

/// Traduce el `errno` de `perf_event_open` a una causa legible.
fn motivo(e: &std::io::Error) -> String {
    match e.raw_os_error() {
        Some(libc::ENOENT) => {
            "la PMU no esta expuesta a esta maquina (tipico de un microVM)".into()
        }
        Some(libc::EACCES) | Some(libc::EPERM) => {
            "sin permiso para perf_event_open (revisar perf_event_paranoid o CAP_PERFMON)".into()
        }
        Some(libc::ENOSYS) => "el kernel no tiene perf_event_open".into(),
        _ => format!("perf_event_open fallo: {e}"),
    }
}
