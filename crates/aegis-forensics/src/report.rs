//! Informe forense combinado de un proceso.

use aegis_scan::memory::MemoryRegion;

use crate::dump::MemoryDump;
use crate::exploit::{self, PatternFinding, VtableFinding};

/// Gravedad del hallazgo forense.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ForensicSeverity {
    /// Nada relevante.
    Clean,
    /// Indicios que merecen registro.
    Suspicious,
    /// Patron de exploit claro.
    Malicious,
}

/// Informe forense de un proceso.
#[derive(Debug, Clone, Default)]
pub struct ForensicReport {
    /// PID analizado.
    pub pid: i32,
    /// Vtables secuestradas encontradas en regiones de datos.
    pub hooked_vtables: Vec<VtableFinding>,
    /// Gadgets de stack pivot encontrados en regiones de codigo.
    pub pivots: Vec<PatternFinding>,
    /// Firmas de shellcode encontradas en regiones de datos.
    pub shellcode: Vec<PatternFinding>,
    /// Bytes analizados.
    pub bytes_analyzed: usize,
}

impl ForensicReport {
    /// Analiza un volcado de memoria ya capturado.
    ///
    /// Separar el analisis de la captura permite probarlo con volcados
    /// sinteticos, y en produccion analizar sin volver a leer la memoria.
    pub fn analyze(pid: i32, dump: &MemoryDump, regiones: &[MemoryRegion]) -> ForensicReport {
        let mut informe = ForensicReport {
            pid,
            ..Default::default()
        };

        // Vtables y shellcode se buscan en las regiones de DATOS (escribibles),
        // donde el atacante coloca sus estructuras y su carga.
        for d in dump.writable_regions() {
            informe.bytes_analyzed += d.bytes.len();
            informe
                .hooked_vtables
                .extend(exploit::scan_vtables(&d.bytes, regiones));
            informe.shellcode.extend(exploit::scan_shellcode(&d.bytes));
        }

        // Los gadgets de pivote se buscan en las regiones de CODIGO,
        // especialmente en las inyectadas.
        for d in dump.executable_regions() {
            informe.bytes_analyzed += d.bytes.len();
            informe.pivots.extend(exploit::scan_pivots(&d.bytes));
        }

        informe
    }

    /// Gravedad global.
    ///
    /// Una vtable secuestrada es concluyente: no hay motivo legitimo para que
    /// una llamada virtual salte a codigo anonimo. El shellcode en la pila y los
    /// gadgets de pivote acompanan pero no bastan solos, porque un tobogan de NOP
    /// o una secuencia de bytes puede aparecer por casualidad en datos.
    pub fn severity(&self) -> ForensicSeverity {
        if !self.hooked_vtables.is_empty() {
            return ForensicSeverity::Malicious;
        }
        // Shellcode en datos MAS un gadget de pivote es la combinacion de un
        // exploit real; por separado, sospechoso.
        let hay_shellcode = !self.shellcode.is_empty();
        let hay_pivote = !self.pivots.is_empty();
        if hay_shellcode && hay_pivote {
            ForensicSeverity::Malicious
        } else if hay_shellcode || hay_pivote {
            ForensicSeverity::Suspicious
        } else {
            ForensicSeverity::Clean
        }
    }

    /// Captura la memoria del proceso y la analiza en un solo paso.
    pub fn capture_and_analyze(
        pid: i32,
        policy: &crate::dump::DumpPolicy,
    ) -> Result<ForensicReport, crate::dump::DumpError> {
        let regiones = aegis_scan::memory::regions_of(pid)
            .map_err(|e| crate::dump::DumpError::Maps { pid, detail: e })?;
        let dump = MemoryDump::capture(pid, policy)?;
        Ok(ForensicReport::analyze(pid, &dump, &regiones))
    }
}
