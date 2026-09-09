//! Motor de firmas YARA-X.
//!
//! Se usa **YARA-X** y no libyara: es la reescritura en Rust de VirusTotal, sin
//! `unsafe` analizando entrada hostil. En un componente cuyo trabajo consiste
//! precisamente en procesar ficheros y memoria que controla un atacante, eso no
//! es una preferencia estetica.
//!
//! # Concurrencia
//!
//! Las reglas compiladas son inmutables y se comparten con [`ArcSwap`]. El
//! error a evitar es un `Mutex<Rules>` global: convertiria el motor en monohilo
//! justo bajo carga, que es cuando mas falta hace el paralelismo. Cada hilo
//! construye su propio `Scanner`, que es barato; el estado caro esta en las
//! reglas compartidas.
//!
//! La recarga en caliente cambia el puntero de forma atomica. Los escaneos ya
//! en curso terminan con el conjunto antiguo y los nuevos toman el nuevo:
//! ninguno se interrumpe y no hay ventana en la que no haya reglas.

use std::sync::Arc;

use arc_swap::ArcSwap;
use yara_x::{Compiler, Rules, Scanner};

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
    pub fn parse(s: &str) -> Severity {
        match s.trim().to_ascii_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "low" => Severity::Low,
            "info" | "none" => Severity::Info,
            _ => Severity::Medium,
        }
    }

    /// Etiqueta legible.
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
    rules: ArcSwap<Rules>,
    rule_count: std::sync::atomic::AtomicUsize,
}

impl std::fmt::Debug for YaraEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("YaraEngine")
            .field("rules", &self.rule_count())
            .finish()
    }
}

/// Compila un conjunto de fuentes YARA.
pub fn compile_sources(fuentes: &[&str]) -> Result<(Rules, usize), YaraError> {
    let mut c = Compiler::new();
    for (i, src) in fuentes.iter().enumerate() {
        c.add_source(*src)
            .map_err(|e| YaraError::Compile(format!("fuente {i}: {e}")))?;
    }
    // Los errores se acumulan en el compilador ademas de devolverse: se
    // comprueban explicitamente para no construir un conjunto a medias.
    if !c.errors().is_empty() {
        let msgs: Vec<String> = c.errors().iter().map(|e| e.to_string()).collect();
        return Err(YaraError::Compile(msgs.join("; ")));
    }
    let rules = c.build();
    let n = count_rules(&rules);
    Ok((rules, n))
}

/// Cuenta las reglas de un conjunto compilado.
///
/// `Rules` no expone iterador, asi que se escanea un buffer VACIO y se suman
/// las reglas coincidentes y las no coincidentes: toda regla del conjunto cae
/// necesariamente en uno de los dos grupos. Es barato (el buffer no tiene
/// bytes que recorrer) y da el numero real de reglas cargadas, que es
/// justamente lo que hay que verificar al arrancar.
fn count_rules(rules: &Rules) -> usize {
    let mut scanner = Scanner::new(rules);
    match scanner.scan(&[]) {
        Ok(r) => r.matching_rules().count() + r.non_matching_rules().count(),
        Err(_) => 0,
    }
}

impl YaraEngine {
    /// Crea un motor con el conjunto base empotrado.
    ///
    /// Verifica que el numero de reglas compiladas es el esperado.
    pub fn with_base_rules() -> Result<YaraEngine, YaraError> {
        let (rules, n) = compile_sources(&[crate::rules::BASE_RULES])?;
        if n != crate::rules::BASE_RULE_COUNT {
            return Err(YaraError::RuleCountMismatch {
                found: n,
                expected: crate::rules::BASE_RULE_COUNT,
            });
        }
        Ok(YaraEngine {
            rules: ArcSwap::from_pointee(rules),
            rule_count: std::sync::atomic::AtomicUsize::new(n),
        })
    }

    /// Crea un motor a partir de fuentes arbitrarias.
    pub fn from_sources(fuentes: &[&str]) -> Result<YaraEngine, YaraError> {
        let (rules, n) = compile_sources(fuentes)?;
        Ok(YaraEngine {
            rules: ArcSwap::from_pointee(rules),
            rule_count: std::sync::atomic::AtomicUsize::new(n),
        })
    }

    /// Numero de reglas residentes.
    pub fn rule_count(&self) -> usize {
        self.rule_count.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Sustituye el conjunto de reglas sin detener los escaneos en curso.
    ///
    /// Compilar tarda cientos de milisegundos; el intercambio es un almacen
    /// atomico. Los escaneos que ya tomaron el conjunto anterior terminan con
    /// el, y no existe ningun instante sin reglas cargadas.
    pub fn reload(&self, fuentes: &[&str]) -> Result<usize, YaraError> {
        let (rules, n) = compile_sources(fuentes)?;
        self.rules.store(Arc::new(rules));
        self.rule_count
            .store(n, std::sync::atomic::Ordering::Relaxed);
        Ok(n)
    }

    /// Escanea un buffer en memoria.
    pub fn scan_bytes(&self, datos: &[u8]) -> Result<Vec<Detection>, YaraError> {
        let reglas = self.rules.load();
        let mut scanner = Scanner::new(&reglas);
        let resultados = scanner
            .scan(datos)
            .map_err(|e| YaraError::Scan(e.to_string()))?;

        let mut salida = Vec::new();
        for r in resultados.matching_rules() {
            salida.push(detection_from(&r, 0));
        }
        Ok(salida)
    }

    /// Escanea un fichero del disco.
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
    /// deteccion, leyendolas por trozos con solape. El solape no es opcional:
    /// sin el, un patron que cruce la frontera de dos trozos no se detecta
    /// jamas, y el fallo solo se manifiesta con ciertos tamanos de patron y de
    /// region, que es lo que lo hace tan dificil de notar.
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

        let reglas = self.rules.load();
        let mut scanner = Scanner::new(&reglas);
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
                        // Una region puede desasignarse entre enumerarla y
                        // leerla. Se cuenta y se sigue con la siguiente.
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

                let resultados = scanner
                    .scan(&datos)
                    .map_err(|e| YaraError::Scan(e.to_string()))?;
                for r in resultados.matching_rules() {
                    let mut d = detection_from(&r, addr);
                    d.offsets.dedup();
                    informe.detections.push(MemoryDetection {
                        detection: d,
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
    /// Distinto de cero significa cobertura incompleta: no se puede afirmar que
    /// el proceso este limpio.
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
    /// Un informe sin detecciones pero con cobertura incompleta NO significa
    /// que el proceso este limpio, y confundir ambas cosas es como un escaner
    /// acaba dando falsa tranquilidad.
    pub fn complete(&self) -> bool {
        self.regions_over_budget == 0 && self.regions_unreadable == 0 && !self.process_vanished
    }

    /// Gravedad maxima encontrada.
    pub fn max_severity(&self) -> Option<Severity> {
        self.detections.iter().map(|d| d.detection.severity).max()
    }
}

/// Construye una [`Detection`] a partir de una regla coincidente.
///
/// `base` es la direccion virtual del inicio del buffer escaneado, de modo que
/// los desplazamientos del escaner se convierten en direcciones reales del
/// proceso. Sin esa conversion, un informe de memoria da offsets relativos a un
/// trozo que ya no existe y son inservibles para el analista.
fn detection_from(r: &yara_x::Rule<'_, '_>, base: u64) -> Detection {
    let mut severity = Severity::Medium;
    let mut description = String::new();
    let mut technique = None;

    for (clave, valor) in r.metadata() {
        let texto = match valor {
            yara_x::MetaValue::String(s) => s.to_string(),
            yara_x::MetaValue::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
            yara_x::MetaValue::Integer(i) => i.to_string(),
            yara_x::MetaValue::Float(f) => f.to_string(),
            yara_x::MetaValue::Bool(b) => b.to_string(),
        };
        match clave {
            "severity" => severity = Severity::parse(&texto),
            "description" => description = texto,
            "technique" => technique = Some(texto),
            _ => {}
        }
    }

    let mut offsets = Vec::new();
    for patron in r.patterns() {
        for m in patron.matches() {
            offsets.push(base + m.range().start as u64);
        }
    }
    offsets.sort_unstable();

    Detection {
        rule: r.identifier().to_string(),
        namespace: r.namespace().to_string(),
        severity,
        description,
        technique,
        offsets,
    }
}
