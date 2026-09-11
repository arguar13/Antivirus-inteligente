//! Reporte honesto de si esta maquina puede capturar Intel PT.
//!
//! Igual que `aegis-syscallguard` (FASE 33) reporta si el PMU esta disponible,
//! aqui se reporta si la CPU tiene Intel PT y si el sistema deja abrir
//! `perf_event`. Una maquina sin `intel_pt` no es un fallo: es `NoAplicable`. El
//! consumidor decide que hacer, pero nunca se le miente diciendo que se esta
//! trazando cuando no se puede.

use std::path::Path;

/// El estado de soporte de Intel PT en esta maquina.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SoportePt {
    /// La CPU tiene `intel_pt` y `perf_event_paranoid` permite abrir la traza.
    Disponible,
    /// La capacidad no existe o no se puede usar aqui; NO es un fallo. Lleva el
    /// motivo para que el operador sepa por que no hay trazado.
    NoAplicable(String),
}

impl SoportePt {
    /// Detecta el soporte leyendo `/proc/cpuinfo` y `perf_event_paranoid`. Es la
    /// misma comprobacion que hace la fontaneria antes de intentar capturar.
    pub fn detectar() -> SoportePt {
        if !cpu_tiene_intel_pt() {
            return SoportePt::NoAplicable(
                "la CPU no expone el flag intel_pt (frecuente en VMs)".to_string(),
            );
        }
        match paranoid() {
            Some(p) if p > 1 => SoportePt::NoAplicable(format!(
                "perf_event_paranoid={p} no permite abrir Intel PT sin privilegios"
            )),
            _ => SoportePt::Disponible,
        }
    }

    /// `true` si se puede capturar de verdad.
    pub fn disponible(&self) -> bool {
        matches!(self, SoportePt::Disponible)
    }
}

/// `true` si `/proc/cpuinfo` anuncia `intel_pt` en los flags.
pub fn cpu_tiene_intel_pt() -> bool {
    std::fs::read_to_string("/proc/cpuinfo")
        .map(|s| {
            s.lines()
                .filter(|l| l.starts_with("flags"))
                .any(|l| l.split_whitespace().any(|f| f == "intel_pt"))
        })
        .unwrap_or(false)
}

/// El valor de `perf_event_paranoid`, o `None` si no se puede leer.
pub fn paranoid() -> Option<i32> {
    let p = Path::new("/proc/sys/kernel/perf_event_paranoid");
    std::fs::read_to_string(p).ok()?.trim().parse().ok()
}
