//! Informe combinado de evasion.
//!
//! # Por que se suman y no se decide con una sola
//!
//! Cada senal por separado tiene una explicacion benigna que la hace inutil
//! como veredicto: la memoria anonima ejecutable la produce cualquier JIT, la
//! divergencia con el disco la producen las reubicaciones, y una diferencia en
//! un prologo la produce un parche de compatibilidad. Lo que no tiene
//! explicacion benigna es la coincidencia: un proceso con codigo que no viene
//! de ningun fichero, cuyo texto no coincide con su imagen y cuyos stubs de
//! syscall estan saltando a otro sitio no es un runtime.

use crate::hollow::{HollowReport, HollowVerdict};
use crate::hooks::HookReport;
use crate::inject::InjectionReport;

/// Gravedad del informe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EvasionSeverity {
    /// Nada que reportar.
    Clean,
    /// Merece registro, no accion.
    Low,
    /// Merece analisis.
    Medium,
    /// Merece contencion.
    High,
}

/// Una senal presente en el informe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvasionSignal {
    /// Descripcion corta.
    pub what: String,
    /// Puntuacion que aporta.
    pub score: u32,
}

/// Informe combinado de un proceso.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EvasionReport {
    /// PID analizado.
    pub pid: i32,
    /// Codigo sin fichero detras.
    pub injection: InjectionReport,
    /// Divergencia entre memoria y disco.
    pub hollow: HollowReport,
    /// Prologos alterados.
    pub hooks: HookReport,
}

impl EvasionReport {
    /// Puntuacion combinada.
    pub fn score(&self) -> u32 {
        self.injection
            .score()
            .saturating_add(self.hollow.score())
            .saturating_add(self.hooks.score())
    }

    /// Senales presentes, de mayor a menor peso.
    pub fn signals(&self) -> Vec<EvasionSignal> {
        let mut v = Vec::new();
        if self.injection.score() > 0 {
            v.push(EvasionSignal {
                what: format!(
                    "{} region(es) ejecutable(s) sin fichero detras",
                    self.injection.findings.len()
                ),
                score: self.injection.score(),
            });
        }
        match self.hollow.verdict() {
            HollowVerdict::Hollowed => v.push(EvasionSignal {
                what: "el codigo en memoria no es el del fichero".into(),
                score: self.hollow.score(),
            }),
            HollowVerdict::Patched => v.push(EvasionSignal {
                what: "codigo parcheado en memoria".into(),
                score: self.hollow.score(),
            }),
            HollowVerdict::Intact => {}
        }
        if self.hooks.hooked() > 0 {
            v.push(EvasionSignal {
                what: format!(
                    "{} stub(s) de syscall saltando a otro sitio",
                    self.hooks.hooked()
                ),
                score: self.hooks.score(),
            });
        }
        v.sort_by(|a, b| b.score.cmp(&a.score));
        v
    }

    /// Gravedad.
    ///
    /// Un vaciado de proceso es grave por si solo; el resto exige acumulacion.
    pub fn severity(&self) -> EvasionSeverity {
        if self.hollow.verdict() == HollowVerdict::Hollowed {
            return EvasionSeverity::High;
        }
        match self.score() {
            0..=9 => EvasionSeverity::Clean,
            10..=39 => EvasionSeverity::Low,
            40..=79 => EvasionSeverity::Medium,
            _ => EvasionSeverity::High,
        }
    }
}

/// Analiza un proceso vivo con las tres comprobaciones.
///
/// # Coste
///
/// Domina la comparacion con el disco: unos pocos MB por proceso, acotados por
/// [`crate::hollow::BYTES_POR_REGION`]. Por eso esto NO corre en el bucle de
/// eventos: se ejecuta bajo demanda, cuando otra señal ya ha señalado al
/// proceso, o en un barrido periodico de baja prioridad.
pub fn analyze_process(pid: i32) -> Result<EvasionReport, crate::EvasionError> {
    let regiones = aegis_scan::memory::regions_of(pid)
        .map_err(|e| crate::EvasionError::Maps { pid, detail: e })?;

    let injection = crate::inject::scan_injection(&regiones);
    let hollow = crate::hollow::compare_process(pid, &regiones)?;
    let hooks = analizar_hooks(pid, &regiones);

    Ok(EvasionReport {
        pid,
        injection,
        hollow,
        hooks,
    })
}

/// Base de carga de cada objeto mapeado en el proceso.
///
/// La base NO es la direccion mas baja del mapeo: es esa direccion menos el
/// `p_vaddr` del primer segmento cargable. Confundirlas funciona por casualidad
/// en los objetos cuyo primer segmento empieza en cero y falla en el resto, que
/// es la clase de error que solo aparece en produccion.
fn base_de_carga(regiones: &[aegis_scan::memory::MemoryRegion]) -> Vec<(String, u64)> {
    use std::collections::HashMap;
    let mut minimos: HashMap<String, u64> = HashMap::new();
    for r in regiones {
        let Some(p) = &r.path else { continue };
        if !p.starts_with('/') || p.ends_with(" (deleted)") {
            continue;
        }
        minimos
            .entry(p.clone())
            .and_modify(|v| *v = (*v).min(r.start))
            .or_insert(r.start);
    }
    let mut v: Vec<(String, u64)> = minimos.into_iter().collect();
    v.sort();
    v
}

fn analizar_hooks(
    pid: i32,
    regiones: &[aegis_scan::memory::MemoryRegion],
) -> crate::hooks::HookReport {
    use std::collections::HashMap;

    let mut cache: HashMap<String, Vec<u8>> = HashMap::new();
    let mut simbolos = Vec::new();

    for (ruta, inicio) in base_de_carga(regiones) {
        let Ok(datos) = std::fs::read(&ruta) else {
            continue;
        };
        let Ok(elf) = goblin::elf::Elf::parse(&datos) else {
            continue;
        };
        let primer_vaddr = elf
            .program_headers
            .iter()
            .filter(|p| p.p_type == goblin::elf::program_header::PT_LOAD)
            .map(|p| p.p_vaddr)
            .min()
            .unwrap_or(0);
        let base = inicio.saturating_sub(primer_vaddr);

        if let Ok(mut s) =
            crate::hooks::resolver_simbolos(&ruta, &datos, base, crate::hooks::SIMBOLOS_VIGILADOS)
        {
            simbolos.append(&mut s);
        }
        cache.insert(ruta, datos);
    }

    crate::hooks::scan_hooks(
        &simbolos,
        |addr, n| aegis_scan::memory::read_memory(pid, addr, n).ok(),
        |lib| cache.get(lib).cloned(),
    )
}
