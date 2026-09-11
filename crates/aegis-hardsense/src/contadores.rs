//! Los contadores de la PMU en vivo: la fuente real de [`MuestraPmu`], cuando el
//! hardware la da.
//!
//! # Honestidad sobre el hardware (el muro)
//!
//! Muchas maquinas virtuales —esta, entre ellas— no exponen PMU al huesped:
//! `perf_event_open` con `PERF_TYPE_HARDWARE` devuelve `ENOENT`. Eso NO es un
//! fallo del producto ni se disimula: se reporta como [`SoporteHpc::NoDisponible`],
//! igual que hace [`aegis-syscallguard`](https://docs.rs/aegis-syscallguard) con
//! su PMU. La DECISION —la heuristica de [`crate::heuristica`]— no necesita la
//! PMU: opera sobre numeros y se prueba entera. Los contadores solo la alimentan
//! donde el hardware existe.

use std::os::fd::OwnedFd;

use crate::heuristica::MuestraPmu;
use crate::perf::{
    leer_contador, perf_event_open, perf_ioctl, PerfEventAttr, PERF_COUNT_HW_BRANCH_INSTRUCTIONS,
    PERF_COUNT_HW_BRANCH_MISSES, PERF_COUNT_HW_CACHE_MISSES, PERF_COUNT_HW_CPU_CYCLES,
    PERF_COUNT_HW_INSTRUCTIONS, PERF_EVENT_IOC_ENABLE, PERF_EVENT_IOC_RESET,
};

/// Disponibilidad de la PMU de hardware en esta maquina.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SoporteHpc {
    /// La PMU responde: se pudo abrir un contador de hardware.
    Disponible,
    /// La PMU no esta expuesta (tipico de una maquina virtual), con el motivo.
    NoDisponible(String),
}

impl SoporteHpc {
    /// `true` si hay PMU utilizable.
    #[must_use]
    pub fn hay(&self) -> bool {
        matches!(self, SoporteHpc::Disponible)
    }
}

/// El grupo de contadores de hardware que alimenta a [`MuestraPmu`]: ciclos,
/// instrucciones, fallos de cache (LLC), saltos y fallos de prediccion de saltos,
/// medidos sobre el hilo llamante.
///
/// Cierra todos los eventos al soltarse (los descriptores son propietarios).
pub struct ContadoresHpc {
    ciclos: OwnedFd,
    instrucciones: OwnedFd,
    fallos_cache: OwnedFd,
    ramas: OwnedFd,
    fallos_rama: OwnedFd,
    previo: [u64; 5],
}

impl ContadoresHpc {
    /// Abre los cinco contadores de hardware sobre el hilo actual, a cero y
    /// parados.
    ///
    /// # Errores
    /// El `errno` de `perf_event_open` (p. ej. `ENOENT` sin PMU). El llamante lo
    /// traduce a [`SoporteHpc::NoDisponible`] sin inventarse nada.
    pub fn abrir() -> Result<ContadoresHpc, std::io::Error> {
        let abrir_uno = |evento: u64| {
            let attr = PerfEventAttr::contador_hw(evento);
            perf_event_open(&attr, 0, -1, -1, 0)
        };
        Ok(ContadoresHpc {
            ciclos: abrir_uno(PERF_COUNT_HW_CPU_CYCLES)?,
            instrucciones: abrir_uno(PERF_COUNT_HW_INSTRUCTIONS)?,
            fallos_cache: abrir_uno(PERF_COUNT_HW_CACHE_MISSES)?,
            ramas: abrir_uno(PERF_COUNT_HW_BRANCH_INSTRUCTIONS)?,
            fallos_rama: abrir_uno(PERF_COUNT_HW_BRANCH_MISSES)?,
            previo: [0; 5],
        })
    }

    /// Pone los contadores a cero y los arranca.
    ///
    /// # Errores
    /// El `errno` de la `ioctl` si el kernel la rechaza.
    pub fn arrancar(&mut self) -> Result<(), std::io::Error> {
        for fd in self.descriptores() {
            perf_ioctl(fd, PERF_EVENT_IOC_RESET)?;
            perf_ioctl(fd, PERF_EVENT_IOC_ENABLE)?;
        }
        self.previo = [0; 5];
        Ok(())
    }

    /// Lee los contadores y devuelve la [`MuestraPmu`] de la ventana desde la
    /// lectura anterior (o desde `arrancar`).
    ///
    /// # Errores
    /// El `errno` de `read` si el kernel lo rechaza.
    pub fn leer_muestra(&mut self) -> Result<MuestraPmu, std::io::Error> {
        let actual = [
            leer_contador(&self.ciclos)?,
            leer_contador(&self.instrucciones)?,
            leer_contador(&self.fallos_cache)?,
            leer_contador(&self.ramas)?,
            leer_contador(&self.fallos_rama)?,
        ];
        // Diferencias respecto a la lectura previa (los contadores son
        // acumulativos). `saturating_sub` protege ante cualquier reinicio.
        let d: Vec<u64> = actual
            .iter()
            .zip(self.previo.iter())
            .map(|(a, p)| a.saturating_sub(*p))
            .collect();
        self.previo = actual;
        Ok(MuestraPmu {
            ciclos: d[0],
            instrucciones: d[1],
            fallos_cache: d[2],
            ramas: d[3],
            fallos_rama: d[4],
        })
    }

    fn descriptores(&self) -> [&OwnedFd; 5] {
        [
            &self.ciclos,
            &self.instrucciones,
            &self.fallos_cache,
            &self.ramas,
            &self.fallos_rama,
        ]
    }
}

/// Sondea si esta maquina expone PMU de hardware, intentando abrir (y cerrar de
/// inmediato) un contador de instrucciones. No deja nada montado.
#[must_use]
pub fn sondear_hpc() -> SoporteHpc {
    let attr = PerfEventAttr::contador_hw(PERF_COUNT_HW_INSTRUCTIONS);
    match perf_event_open(&attr, 0, -1, -1, 0) {
        Ok(_fd) => SoporteHpc::Disponible,
        Err(e) => SoporteHpc::NoDisponible(motivo(&e)),
    }
}

/// Traduce el `errno` de `perf_event_open` a una causa legible.
fn motivo(e: &std::io::Error) -> String {
    match e.raw_os_error() {
        Some(libc::ENOENT) => {
            "la PMU no esta expuesta a esta maquina (tipico de un microVM)".into()
        }
        Some(libc::EACCES | libc::EPERM) => {
            "sin permiso para perf_event_open (revisar perf_event_paranoid o CAP_PERFMON)".into()
        }
        Some(libc::ENOSYS) => "el kernel no tiene perf_event_open".into(),
        _ => format!("perf_event_open fallo: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn el_sondeo_no_entra_en_panico_y_es_honesto() {
        // En una maquina sin PMU (el CI), tiene que devolver NoDisponible con un
        // motivo, nunca colgarse ni fingir que la hay.
        match sondear_hpc() {
            SoporteHpc::Disponible => {
                println!("PMU: disponible en esta maquina; se ejercita el grupo completo");
                // Donde la haya, se puede abrir el grupo completo.
                let mut c = ContadoresHpc::abrir().expect("si hay PMU, el grupo abre");
                c.arrancar().expect("arranca");
                let _ = c.leer_muestra().expect("lee una muestra");
            }
            SoporteHpc::NoDisponible(motivo) => {
                println!("PMU: NO disponible aqui ({motivo}); la captura en vivo no se ejercita");
                assert!(
                    !motivo.is_empty(),
                    "un no-disponible siempre explica por que"
                );
            }
        }
    }
}
