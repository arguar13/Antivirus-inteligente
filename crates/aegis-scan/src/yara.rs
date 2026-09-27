//! Motor de firmas, sobre el motor de patrones PROPIO (FASE 101).
//!
//! # De yara-x a motor propio
//!
//! Este componente usaba `yara-x` —la reescritura en Rust de VirusTotal—. Desde la
//! FASE 101 usa [`aegis_patron`], el motor de patrones propio: coste acotado por
//! tipo, tri-estado, determinista y SIN RETROCESO. La razon no es estetica: un
//! producto no puede superar a su propia dependencia, y cada fallo de esa
//! dependencia era un fallo del agente en el camino que come entrada hostil. El
//! motor propio lee la MISMA sintaxis YARA que las reglas ya escritas —la paridad
//! con yara-x sobre el conjunto base se comprueba en `aegis-patron`—, pero con
//! semantica nueva y sin superficie de terceros.
//!
//! # Concurrencia
//!
//! El motor compilado es inmutable y se comparte con [`ArcSwap`]. La recarga en
//! caliente cambia el puntero de forma atomica: los escaneos en curso terminan con
//! el conjunto antiguo y los nuevos toman el nuevo, sin ventana sin reglas y sin un
//! `Mutex` global que serialice bajo carga.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use aegis_patron::{Motor, Severidad};
use arc_swap::ArcSwap;

use crate::memory::{self, MemoryRegion, MemoryScanPolicy};

/// Gravedad declarada por una regla en su metadato `severity`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Informativa.
    Info,
    /// Baja.
    Low,
    /// Media.
    Medium,
    /// Alta.
    High,
    /// Critica.
    Critical,
}

impl Severity {
    /// Analiza el metadato `severity`.
    ///
    /// Lo desconocido se trata como media, no como baja: infravalorar por no
    /// saber es como algo real acaba ignorado.
    #[must_use]
    pub fn parse(s: &str) -> Severity {
        Severity::from(Severidad::parsear(s))
    }

    /// Etiqueta legible.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Severity::Critical => "CRITICA",
            Severity::High => "ALTA",
            Severity::Medium => "MEDIA",
            Severity::Low => "BAJA",
            Severity::Info => "INFO",
        }
    }
}

impl From<Severidad> for Severity {
    fn from(s: Severidad) -> Severity {
        match s {
            Severidad::Info => Severity::Info,
            Severidad::Baja => Severity::Low,
            Severidad::Media => Severity::Medium,
            Severidad::Alta => Severity::High,
            Severidad::Critica => Severity::Critical,
        }
    }
}

/// Una coincidencia de regla.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    /// Identificador de la regla.
    pub rule: String,
    /// Espacio de nombres.
    pub namespace: String,
    /// Gravedad declarada.
    pub severity: Severity,
    /// Descripcion declarada.
    pub description: String,
    /// Tecnica MITRE ATT&CK, si la regla la declara.
    pub technique: Option<String>,
    /// Desplazamientos donde coincidio, dentro del buffer escaneado.
    pub offsets: Vec<u64>,
}

/// Error del motor.
#[derive(Debug, thiserror::Error)]
pub enum YaraError {
    /// El conjunto de reglas no compila.
    #[error("las reglas no compilan: {0}")]
    Compile(String),

    /// El conjunto base compilo con un numero de reglas distinto del esperado.
    ///
    /// Se comprueba porque un conjunto recortado en silencio deja al agente
    /// arrancando con menos reglas de las que cree tener.
    #[error("el conjunto base compilo {found} reglas y se esperaban {expected}")]
    RuleCountMismatch {
        /// Reglas compiladas.
        found: usize,
        /// Reglas esperadas.
        expected: usize,
    },

    /// Error al escanear.
    #[error("error al escanear: {0}")]
    Scan(String),

    /// Error de entrada/salida.
    #[error("error de E/S en {path}: {source}")]
    Io {
        /// Ruta implicada.
        path: String,
        /// Causa.
        source: std::io::Error,
    },

    /// Error al leer memoria de otro proceso.
    #[error(transparent)]
    Memory(#[from] memory::ReadError),
}

/// Motor de firmas.
pub struct YaraEngine {
    motor: ArcSwap<Motor>,
    rule_count: AtomicUsize,
}

impl std::fmt::Debug for YaraEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("YaraEngine")
            .field("rules", &self.rule_count())
            .finish()
    }
}

/// Compila un conjunto de fuentes YARA en un motor.
///
/// Las reglas de todas las fuentes se combinan en un solo motor bajo el espacio de
/// nombres por defecto, como hacia el compilador anterior.
///
/// # Errores
/// [`YaraError::Compile`] si alguna fuente no compila o no se puede acotar,
/// nombrando la regla y la parte que falla.
pub fn compile_sources(fuentes: &[&str]) -> Result<(Motor, usize), YaraError> {
    let mut reglas = Vec::new();
    for (i, src) in fuentes.iter().enumerate() {
        let r = aegis_patron::compilar(src, "default")
            .map_err(|e| YaraError::Compile(format!("fuente {i}: {e}")))?;
        reglas.extend(r);
    }
    let motor = Motor::desde_reglas(reglas);
    let n = motor.reglas();
    Ok((motor, n))
}

impl YaraEngine {
    /// Crea un motor con el conjunto base empotrado.
    ///
    /// Verifica que el numero de reglas compiladas es el esperado.
    ///
    /// # Errores
    /// [`YaraError`] si el conjunto no compila o su numero de reglas no cuadra.
    pub fn with_base_rules() -> Result<YaraEngine, YaraError> {
        let (motor, n) = compile_sources(&[crate::rules::BASE_RULES])?;
        if n != crate::rules::BASE_RULE_COUNT {
            return Err(YaraError::RuleCountMismatch {
                found: n,
                expected: crate::rules::BASE_RULE_COUNT,
            });
        }
        Ok(YaraEngine {
            motor: ArcSwap::from_pointee(motor),
            rule_count: AtomicUsize::new(n),
        })
    }

    /// Crea un motor a partir de fuentes arbitrarias.
    ///
    /// # Errores
    /// [`YaraError::Compile`] si alguna fuente no compila.
    pub fn from_sources(fuentes: &[&str]) -> Result<YaraEngine, YaraError> {
        let (motor, n) = compile_sources(fuentes)?;
        Ok(YaraEngine {
            motor: ArcSwap::from_pointee(motor),
            rule_count: AtomicUsize::new(n),
        })
    }

    /// Numero de reglas residentes.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rule_count.load(Ordering::Relaxed)
    }

    /// Sustituye el conjunto de reglas sin detener los escaneos en curso.
    ///
    /// # Errores
    /// [`YaraError::Compile`] si las fuentes nuevas no compilan; el conjunto
    /// anterior se conserva intacto.
    pub fn reload(&self, fuentes: &[&str]) -> Result<usize, YaraError> {
        let (motor, n) = compile_sources(fuentes)?;
        self.motor.store(Arc::new(motor));
        self.rule_count.store(n, Ordering::Relaxed);
        Ok(n)
    }

    /// Escanea un buffer en memoria.
    ///
    /// # Errores
    /// No falla por el escaneo en si —el motor no tiene modos de fallo de
    /// ejecucion—; el tipo se conserva por compatibilidad con los consumidores.
    pub fn scan_bytes(&self, datos: &[u8]) -> Result<Vec<Detection>, YaraError> {
        let motor = self.motor.load();
        let resultado = motor.escanear(datos);
        Ok(resultado
            .detecciones
            .into_iter()
            .map(|d| detection_desde(d, 0))
            .collect())
    }

    /// Escanea un fichero del disco.
    ///
    /// # Errores
    /// [`YaraError::Io`] si el fichero no se puede leer.
    pub fn scan_file(&self, ruta: &std::path::Path) -> Result<Vec<Detection>, YaraError> {
        let datos = std::fs::read(ruta).map_err(|e| YaraError::Io {
            path: ruta.display().to_string(),
            source: e,
        })?;
        self.scan_bytes(&datos)
    }

    /// Escanea la memoria de un proceso vivo.
    ///
    /// Recorre las regiones que la politica acepta, en orden de valor de
    /// deteccion, leyendolas por trozos con solape. El solape no es opcional: sin
    /// el, un patron que cruce la frontera de dos trozos no se detecta jamas.
    ///
    /// # Errores
    /// [`YaraError::Io`] si no se puede enumerar la memoria del proceso.
    pub fn scan_process(
        &self,
        pid: i32,
        politica: &MemoryScanPolicy,
    ) -> Result<ProcessScanReport, YaraError> {
        let mut regiones = memory::regions_of(pid).map_err(|e| YaraError::Io {
            path: format!("/proc/{pid}/maps"),
            source: e,
        })?;
        memory::prioritize(&mut regiones);

        let mut informe = ProcessScanReport {
            pid,
            regions_total: regiones.len(),
            ..Default::default()
        };

        let motor = self.motor.load();
        let mut presupuesto = politica.max_total_bytes;

        for region in regiones {
            if !politica.accepts(&region) {
                informe.regions_skipped += 1;
                continue;
            }
            if presupuesto == 0 {
                informe.regions_over_budget += 1;
                continue;
            }

            for (addr, pedir_max) in memory::chunk_ranges(
                region.start,
                region.end,
                politica.chunk_bytes,
                politica.overlap_bytes,
            ) {
                if presupuesto == 0 {
                    informe.regions_over_budget += 1;
                    break;
                }
                let pedir = (pedir_max as u64).min(presupuesto) as usize;

                let datos = match memory::read_memory(pid, addr, pedir) {
                    Ok(d) => d,
                    Err(memory::ReadError::NoSuchProcess(_)) => {
                        // El proceso murio a mitad del barrido. Es la condicion
                        // normal en un sistema vivo, no un error del escaner.
                        informe.process_vanished = true;
                        return Ok(informe);
                    }
                    Err(_) => {
                        // Una region puede desasignarse entre enumerarla y leerla.
                        informe.regions_unreadable += 1;
                        break;
                    }
                };
                if datos.is_empty() {
                    break;
                }

                presupuesto = presupuesto.saturating_sub(datos.len() as u64);
                informe.bytes_scanned += datos.len() as u64;
                informe.regions_scanned_chunks += 1;

                for d in motor.escanear(&datos).detecciones {
                    let mut det = detection_desde(d, addr);
                    det.offsets.dedup();
                    informe.detections.push(MemoryDetection {
                        detection: det,
                        region: region.clone(),
                    });
                }
            }
            informe.regions_scanned += 1;
        }

        Ok(informe)
    }
}

/// Coincidencia localizada en la memoria de un proceso.
#[derive(Debug, Clone)]
pub struct MemoryDetection {
    /// Coincidencia, con desplazamientos ya convertidos a direcciones virtuales.
    pub detection: Detection,
    /// Region donde se encontro.
    pub region: MemoryRegion,
}

/// Resultado de escanear un proceso.
#[derive(Debug, Clone, Default)]
pub struct ProcessScanReport {
    /// PID escaneado.
    pub pid: i32,
    /// Regiones enumeradas.
    pub regions_total: usize,
    /// Regiones efectivamente escaneadas.
    pub regions_scanned: usize,
    /// Trozos leidos.
    pub regions_scanned_chunks: usize,
    /// Regiones descartadas por politica.
    pub regions_skipped: usize,
    /// Regiones que no se pudieron leer.
    pub regions_unreadable: usize,
    /// Regiones no escaneadas por agotarse el presupuesto.
    ///
    /// Distinto de cero significa cobertura incompleta: no se puede afirmar que el
    /// proceso este limpio.
    pub regions_over_budget: usize,
    /// Bytes leidos.
    pub bytes_scanned: u64,
    /// El proceso desaparecio durante el barrido.
    pub process_vanished: bool,
    /// Coincidencias.
    pub detections: Vec<MemoryDetection>,
}

impl ProcessScanReport {
    /// Indica si el barrido cubrio todo lo que la politica aceptaba.
    ///
    /// Un informe sin detecciones pero con cobertura incompleta NO significa que el
    /// proceso este limpio, y confundir ambas cosas es como un escaner acaba dando
    /// falsa tranquilidad.
    #[must_use]
    pub fn complete(&self) -> bool {
        self.regions_over_budget == 0 && self.regions_unreadable == 0 && !self.process_vanished
    }

    /// Gravedad maxima encontrada.
    #[must_use]
    pub fn max_severity(&self) -> Option<Severity> {
        self.detections.iter().map(|d| d.detection.severity).max()
    }
}

/// Construye una [`Detection`] a partir de una deteccion del motor propio.
///
/// `base` es la direccion virtual del inicio del buffer escaneado, de modo que los
/// desplazamientos del escaner se convierten en direcciones reales del proceso.
fn detection_desde(d: aegis_patron::Deteccion, base: u64) -> Detection {
    let mut offsets: Vec<u64> = d.offsets.iter().map(|o| base + o).collect();
    offsets.sort_unstable();
    Detection {
        rule: d.regla,
        namespace: d.namespace,
        severity: Severity::from(d.severidad),
        description: d.descripcion,
        technique: d.tecnica,
        offsets,
    }
}
