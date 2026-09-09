//! Puntos de ruptura por hardware sobre los registros de depuracion (DRx).
//!
//! # Que son y por que sirven aqui
//!
//! El procesador tiene cuatro registros de depuracion (DR0..DR3 en x86-64) que
//! disparan una excepcion cuando la CPU EJECUTA una direccion concreta, sin
//! modificar ni un byte del codigo vigilado. Son invisibles para el proceso
//! observado: no puede detectarlos leyendose a si mismo, como si haria con un
//! `int3` inyectado. El kernel los expone via `perf_event_open` con
//! `PERF_TYPE_BREAKPOINT`.
//!
//! # El papel en la deteccion de syscalls directas
//!
//! El trampolin de syscall legitimo de `libc` esta en una direccion conocida.
//! Un vigilante de ejecucion sobre esa direccion cuenta, en hardware, cuantas
//! veces se paso REALMENTE por la puerta sancionada. Si el proceso hace mas
//! syscalls de las que cuenta la puerta —lo dice el trazador o la PMU—, esas de
//! mas entraron al kernel por otro sitio: son directas. Es la contraparte
//! hardware de la verificacion cruzada.
//!
//! A diferencia de la PMU, los registros de depuracion SI estan disponibles en
//! esta maquina: este modulo se ejercita de verdad contra el hardware.

use std::os::fd::OwnedFd;

use crate::perf::{
    leer_contador, perf_event_open, perf_ioctl, PerfEventAttr, HW_BREAKPOINT_LEN_8,
    HW_BREAKPOINT_X, PERF_EVENT_IOC_ENABLE, PERF_EVENT_IOC_RESET, PERF_TYPE_BREAKPOINT,
};

/// Disponibilidad de los registros de depuracion en esta maquina.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SoporteDrx {
    /// Se pudo armar un punto de ruptura de ejecucion por hardware.
    Disponible,
    /// El hardware o el kernel no lo permiten aqui.
    NoDisponible(String),
}

impl SoporteDrx {
    /// `true` si hay registros de depuracion utilizables.
    pub fn hay(&self) -> bool {
        matches!(self, SoporteDrx::Disponible)
    }
}

/// Vigilante de ejecucion sobre una direccion, respaldado por un registro DRx.
///
/// Cuenta, en hardware, cada ejecucion de la direccion vigilada. Se libera el
/// registro al soltarse.
pub struct VigilanteEjecucion {
    fd: OwnedFd,
    direccion: u64,
}

impl VigilanteEjecucion {
    /// Arma un punto de ruptura de ejecucion sobre `direccion` en `pid`.
    ///
    /// `pid == 0` vigila el propio hilo llamante. El contador arranca a cero y
    /// ya habilitado; a partir de aqui cada ejecucion de la direccion lo
    /// incrementa.
    pub fn armar(direccion: u64, pid: libc::pid_t) -> Result<VigilanteEjecucion, std::io::Error> {
        let mut attr = PerfEventAttr::nueva(PERF_TYPE_BREAKPOINT);
        attr.bp_type = HW_BREAKPOINT_X;
        attr.bp_addr = direccion;
        attr.bp_len = HW_BREAKPOINT_LEN_8;
        let fd = perf_event_open(&attr, pid, -1, -1, 0)?;
        perf_ioctl(&fd, PERF_EVENT_IOC_RESET)?;
        perf_ioctl(&fd, PERF_EVENT_IOC_ENABLE)?;
        Ok(VigilanteEjecucion { fd, direccion })
    }

    /// Direccion vigilada.
    pub fn direccion(&self) -> u64 {
        self.direccion
    }

    /// Numero de veces que la direccion se ha ejecutado desde que se armo.
    pub fn disparos(&self) -> Result<u64, std::io::Error> {
        leer_contador(&self.fd)
    }
}

/// Sondea si esta maquina permite puntos de ruptura por hardware.
///
/// Arma un vigilante sobre la propia funcion de sondeo y lo suelta. Es una
/// pregunta al kernel; no deja el registro ocupado.
pub fn sondear_drx() -> SoporteDrx {
    // Una direccion de codigo cualquiera de este proceso sirve para la prueba
    // de armado; se usa la de esta misma funcion.
    let addr = sondear_drx as *const () as u64;
    match VigilanteEjecucion::armar(addr, 0) {
        Ok(_v) => SoporteDrx::Disponible,
        Err(e) => SoporteDrx::NoDisponible(motivo(&e)),
    }
}

/// Traduce el `errno` a una causa legible.
fn motivo(e: &std::io::Error) -> String {
    match e.raw_os_error() {
        Some(libc::EACCES) | Some(libc::EPERM) => {
            "sin permiso para armar el punto de ruptura (perf_event_paranoid/CAP_PERFMON)".into()
        }
        Some(libc::ENOSPC) => "no quedan registros de depuracion libres".into(),
        Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP) => {
            "el kernel o el hardware no soportan puntos de ruptura por perf".into()
        }
        _ => format!("perf_event_open(BREAKPOINT) fallo: {e}"),
    }
}
