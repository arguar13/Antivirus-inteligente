//! Volcado de memoria en vivo de un proceso sospechoso.
//!
//! # Por que "en vivo" y no congelando el proceso
//!
//! La forma clasica de volcar la memoria de un proceso es pararlo con `ptrace`,
//! leerla y reanudarlo. Contra un proceso malicioso eso es contraproducente: el
//! paron es observable (el malware puede detectar que lo estan trazando y
//! borrarse o cambiar de comportamiento), y ademas congela un proceso que quiza
//! sea legitimo y este dando servicio.
//!
//! `process_vm_readv` lee la memoria de otro proceso SIN pararlo ni adjuntarse:
//! una sola llamada al sistema copia de su espacio al nuestro. La foto no es
//! perfectamente coherente —el proceso sigue corriendo y puede cambiar la
//! memoria mientras se lee—, pero para buscar patrones de exploit e inyecciones
//! esa incoherencia es irrelevante, y a cambio no se altera el objetivo.
//!
//! Se apoya en `aegis_scan::memory`, que ya encapsula `process_vm_readv` y el
//! parseo de `/proc/<pid>/maps`.

use aegis_scan::memory::{self, MemoryRegion};

/// Error al volcar memoria.
#[derive(Debug, thiserror::Error)]
pub enum DumpError {
    /// No se pudo leer el mapa de memoria del proceso.
    #[error("no se pudo leer el mapa de memoria de {pid}: {detail}")]
    Maps {
        /// PID.
        pid: i32,
        /// Causa.
        detail: std::io::Error,
    },
}

/// Una region volcada con su contenido.
#[derive(Debug, Clone)]
pub struct RegionDump {
    /// Metadatos de la region.
    pub region: MemoryRegion,
    /// Bytes leidos (puede ser mas corto que la region si se acoto o si parte
    /// no era legible).
    pub bytes: Vec<u8>,
    /// Cierto si la region no se pudo leer entera.
    pub partial: bool,
}

/// Politica de volcado: que regiones y cuanto de cada una.
#[derive(Debug, Clone)]
pub struct DumpPolicy {
    /// Volcar regiones ejecutables (codigo, incluido el inyectado).
    pub include_exec: bool,
    /// Volcar regiones escribibles no ejecutables (monton, pila, datos).
    pub include_writable: bool,
    /// Bytes maximos por region.
    pub max_region_bytes: usize,
    /// Bytes maximos en total.
    pub max_total_bytes: usize,
}

impl Default for DumpPolicy {
    fn default() -> Self {
        Self {
            include_exec: true,
            include_writable: true,
            // 2 MB por region y 64 MB en total: suficiente para el analisis de
            // patrones sin arriesgar la memoria del propio agente ante un
            // proceso enorme.
            max_region_bytes: 2 * 1024 * 1024,
            max_total_bytes: 64 * 1024 * 1024,
        }
    }
}

impl DumpPolicy {
    /// Indica si una region entra en la politica.
    fn acepta(&self, r: &MemoryRegion) -> bool {
        if !r.is_readable() {
            return false;
        }
        (self.include_exec && r.perms.exec) || (self.include_writable && r.perms.write)
    }
}

/// Volcado de memoria de un proceso.
#[derive(Debug, Clone, Default)]
pub struct MemoryDump {
    /// Regiones volcadas.
    pub regions: Vec<RegionDump>,
    /// Bytes totales leidos.
    pub total_bytes: usize,
    /// Regiones que la politica acepto pero no se pudieron leer.
    pub skipped: usize,
}

impl MemoryDump {
    /// Volca la memoria de un proceso vivo segun la politica, sin pararlo.
    pub fn capture(pid: i32, policy: &DumpPolicy) -> Result<MemoryDump, DumpError> {
        let regiones = memory::regions_of(pid).map_err(|e| DumpError::Maps { pid, detail: e })?;
        let mut dump = MemoryDump::default();

        for r in regiones {
            if !policy.acepta(&r) {
                continue;
            }
            if dump.total_bytes >= policy.max_total_bytes {
                dump.skipped += 1;
                continue;
            }
            let largo = (r.len() as usize)
                .min(policy.max_region_bytes)
                .min(policy.max_total_bytes - dump.total_bytes);
            match memory::read_memory(pid, r.start, largo) {
                Ok(bytes) => {
                    let parcial = bytes.len() < r.len() as usize;
                    dump.total_bytes += bytes.len();
                    dump.regions.push(RegionDump {
                        region: r,
                        bytes,
                        partial: parcial,
                    });
                }
                Err(_) => dump.skipped += 1,
            }
        }
        Ok(dump)
    }

    /// Regiones ejecutables del volcado, que son las que interesan al analisis
    /// de codigo inyectado.
    pub fn executable_regions(&self) -> impl Iterator<Item = &RegionDump> {
        self.regions.iter().filter(|d| d.region.perms.exec)
    }

    /// Regiones escribibles del volcado (pila, monton), donde viven los datos de
    /// exploit.
    pub fn writable_regions(&self) -> impl Iterator<Item = &RegionDump> {
        self.regions
            .iter()
            .filter(|d| d.region.perms.write && !d.region.perms.exec)
    }
}
