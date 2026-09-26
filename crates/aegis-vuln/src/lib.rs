//! # aegis-vuln
//!
//! Escaner de postura y vulnerabilidades del host.
//!
//! Responde a dos preguntas distintas que suelen confundirse:
//!
//! - **Vulnerabilidades**: tengo instalado software con fallos conocidos. Se
//!   responde cruzando el inventario de paquetes contra un feed de CVE.
//! - **Postura**: tengo el sistema mal configurado. Es la via de compromiso mas
//!   comun y **ningun feed de vulnerabilidades la detecta**: un `/etc/shadow`
//!   legible por todos no aparece en ningun CVE y entrega la maquina entera.
//!
//! Ambos escaneos toman una raiz del sistema de ficheros como parametro, de
//! modo que se ejercitan contra arboles sinteticos sin tocar la maquina real.

// SEGURIDAD DE MEMORIA IMPUESTA POR EL COMPILADOR (FASE 80).
//
// Este crate no necesita `unsafe`, asi que lo prohibe. No es una declaracion de
// intenciones: `forbid` no se puede levantar desde dentro ni con un `allow`, asi
// que el dia que alguien optimice un bucle con un puntero crudo, no compila.
//
// La invariante del producto no admite tercera opcion: todo crate del agente O
// declara esto, O esta en `tools/lineabase-unsafe.txt` con su razon escrita. Un
// crate que se cuele sin ninguna de las dos hace fallar
// `tools/verificar-invariantes.sh`.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod cve;
pub mod inventory;
pub mod posture;
pub mod version;

use std::path::Path;

pub use cve::{CveFeed, CveRecord, FeedError, Severity};
pub use inventory::{Inventory, Package, PackageSource, SystemInfo};
pub use version::Version;

/// Naturaleza de un hallazgo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    /// Software con una vulnerabilidad conocida.
    Vulnerability,
    /// Permisos o propiedad de fichero incorrectos.
    Permissions,
    /// Configuracion del sistema por debajo de la linea base.
    Hardening,
    /// Superficie de red expuesta.
    Network,
    /// Problema en las cuentas de usuario.
    Accounts,
    /// Mecanismo de persistencia sospechoso.
    Persistence,
}

impl Category {
    /// Etiqueta legible.
    pub fn label(self) -> &'static str {
        match self {
            Category::Vulnerability => "VULNERABILIDAD",
            Category::Permissions => "PERMISOS",
            Category::Hardening => "FORTIFICACION",
            Category::Network => "RED",
            Category::Accounts => "CUENTAS",
            Category::Persistence => "PERSISTENCIA",
        }
    }
}

/// Un hallazgo del escaneo.
///
/// Siempre lleva `evidence` y `remediation`. Un informe de seguridad sin
/// evidencia no se puede verificar, y sin remediacion no se puede accionar:
/// las dos cosas convierten el informe en ruido que se archiva sin leer.
#[derive(Debug, Clone)]
pub struct Finding {
    /// Identificador estable del hallazgo.
    pub id: String,
    /// Naturaleza.
    pub category: Category,
    /// Gravedad.
    pub severity: Severity,
    /// Titulo en una linea.
    pub title: String,
    /// Que se observo exactamente.
    pub evidence: String,
    /// Que hacer al respecto.
    pub remediation: String,
}

/// Resultado completo de un escaneo.
#[derive(Debug)]
pub struct ScanReport {
    /// Inventario recogido.
    pub inventory: Inventory,
    /// Hallazgos, ordenados de mayor a menor gravedad.
    pub findings: Vec<Finding>,
    /// Registros del feed que se cargaron.
    pub feed_records: usize,
}

impl ScanReport {
    /// Cuenta los hallazgos de una gravedad dada.
    pub fn count(&self, sev: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == sev).count()
    }

    /// Indica si hay algun hallazgo de gravedad alta o critica.
    pub fn has_actionable(&self) -> bool {
        self.findings.iter().any(|f| f.severity >= Severity::High)
    }
}

/// Escaner del host.
#[derive(Debug, Default)]
pub struct Scanner {
    feed: CveFeed,
}

impl Scanner {
    /// Crea un escaner sin feed de CVE: solo hara comprobaciones de postura.
    pub fn new() -> Self {
        Self::default()
    }

    /// Crea un escaner con un feed ya analizado.
    pub fn with_feed(feed: CveFeed) -> Self {
        Self { feed }
    }

    /// Carga el feed desde un fichero.
    pub fn load_feed(&mut self, ruta: &Path) -> Result<usize, ScanError> {
        let texto = std::fs::read_to_string(ruta).map_err(|e| ScanError::FeedIo {
            path: ruta.display().to_string(),
            source: e,
        })?;
        self.feed = CveFeed::parse(&texto)?;
        Ok(self.feed.len())
    }

    /// Ejecuta el escaneo completo tomando `root` como raiz.
    pub fn scan(&self, root: &Path) -> ScanReport {
        let inventory = Inventory::collect(root);

        let mut findings = posture::scan(root);
        findings.extend(self.match_cves(&inventory));

        // Orden estable y por gravedad descendente: un informe cuyo orden
        // cambia entre ejecuciones es imposible de comparar con el anterior.
        findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.category.label().cmp(b.category.label()))
                .then_with(|| a.id.cmp(&b.id))
        });

        ScanReport {
            inventory,
            findings,
            feed_records: self.feed.len(),
        }
    }

    /// Cruza el inventario contra el feed.
    ///
    /// # Por el nombre binario Y por el fuente
    ///
    /// Los avisos de las distribuciones se publican por paquete FUENTE: el fallo
    /// de OpenSSL esta en `openssl`, y lo que carga cada proceso es la biblioteca
    /// del paquete binario `libssl3`. Cruzar solo por el nombre instalado no veia
    /// la vulnerabilidad en una maquina con la biblioteca y sin la herramienta de
    /// linea de ordenes —que es la maquina normal—, y no decia nada.
    ///
    /// Cada paquete se cruza por los dos nombres, cada uno con SU version: la
    /// binaria para las entradas escritas con el nombre binario y la fuente para
    /// las del fuente. Un registro que aparezca por los dos caminos cuenta una
    /// vez.
    fn match_cves(&self, inv: &Inventory) -> Vec<Finding> {
        let mut out = Vec::new();
        for paquete in inv.packages.values() {
            let nombre = &paquete.name;
            let mut vistos: Vec<&str> = Vec::new();
            let por_binario = self
                .feed
                .for_package(nombre)
                .iter()
                .map(|r| (r, &paquete.version));
            let del_fuente = if paquete.source_name() == nombre.as_str() {
                &[][..]
            } else {
                self.feed.for_package(paquete.source_name())
            };
            let por_fuente = del_fuente.iter().map(|r| (r, paquete.source_version()));
            for (registro, version) in por_binario.chain(por_fuente) {
                if vistos.contains(&registro.id.as_str()) || !registro.affects(version) {
                    continue;
                }
                vistos.push(&registro.id);
                // Si el registro llego por el nombre fuente, el rango es de la
                // version fuente, y la evidencia tiene que decir cual se comparo.
                let via = if registro.package == *nombre {
                    String::new()
                } else {
                    format!(" (paquete fuente {} {version})", registro.package)
                };
                let arreglo = match &registro.fixed {
                    Some(v) => format!(
                        "Actualizar {nombre} (fuente {}) a {v} o superior",
                        paquete.source_name()
                    ),
                    None => format!(
                        "No hay correccion publicada para {nombre}. Aplicar mitigaciones \
                         o retirar el paquete si no es imprescindible."
                    ),
                };
                out.push(Finding {
                    id: registro.id.clone(),
                    category: Category::Vulnerability,
                    severity: registro.severity,
                    title: format!("{} afecta a {} {}", registro.id, nombre, paquete.version),
                    evidence: format!(
                        "instalada {}{via}; rango afectado: {} .. {} (CVSS {:.1}) - {}",
                        paquete.version,
                        registro
                            .introduced
                            .as_ref()
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| "cualquiera".into()),
                        registro
                            .fixed
                            .as_ref()
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| "sin correccion".into()),
                        registro.cvss,
                        registro.summary
                    ),
                    remediation: arreglo,
                });
            }
        }
        out
    }
}

/// Error del escaneo.
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    /// No se pudo leer el fichero del feed.
    #[error("no se pudo leer el feed en {path}: {source}")]
    FeedIo {
        /// Ruta del feed.
        path: String,
        /// Causa.
        source: std::io::Error,
    },
    /// El feed tiene un error de formato.
    #[error("el feed tiene un error de formato: {0}")]
    Feed(#[from] FeedError),
}
