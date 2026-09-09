//! Feed local de vulnerabilidades y motor de correspondencia.
//!
//! # Formato del feed
//!
//! Texto delimitado por barras verticales, un registro por linea:
//!
//! ```text
//! CVE-2024-3094|xz-utils|5.6.0|5.6.2|critical|10.0|Puerta trasera en la fase de build
//! ```
//!
//! Campos: `id | paquete | introducida | corregida | severidad | cvss | resumen`.
//! `introducida` vacio significa "todas las versiones anteriores a la
//! correccion"; `corregida` vacio significa "sin correccion publicada".
//!
//! Se elige un formato de linea y no JSON deliberadamente. El feed es un dato
//! que se actualiza a diario en una maquina que este producto protege, y esta
//! forma tiene tres propiedades que importan mas que la comodidad: se analiza
//! sin ninguna dependencia externa, lo que evita meter un analizador de JSON en
//! la superficie de ataque de un componente de seguridad; produce diffs
//! legibles en control de versiones, de modo que un cambio en el feed se puede
//! revisar linea a linea; y es trivial de firmar y verificar. La conversion
//! desde OSV o NVD la hace una herramienta aparte, fuera del host.

use std::collections::HashMap;

use crate::version::Version;

/// Gravedad de una vulnerabilidad.
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
    /// Analiza una gravedad. Lo desconocido se trata como media, no como baja:
    /// infravalorar por no saber es el error que hace que algo real se ignore.
    pub fn parse(s: &str) -> Severity {
        match s.trim().to_ascii_lowercase().as_str() {
            "critical" | "critica" => Severity::Critical,
            "high" | "alta" => Severity::High,
            "medium" | "media" | "moderate" => Severity::Medium,
            "low" | "baja" => Severity::Low,
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

/// Un registro del feed.
#[derive(Debug, Clone)]
pub struct CveRecord {
    /// Identificador, normalmente `CVE-AAAA-NNNN`.
    pub id: String,
    /// Paquete afectado.
    pub package: String,
    /// Primera version afectada. `None` = todas las anteriores a `fixed`.
    pub introduced: Option<Version>,
    /// Primera version corregida. `None` = sin correccion publicada.
    pub fixed: Option<Version>,
    /// Gravedad.
    pub severity: Severity,
    /// Puntuacion CVSS base.
    pub cvss: f32,
    /// Resumen.
    pub summary: String,
}

impl CveRecord {
    /// Indica si `instalada` cae dentro del rango afectado.
    ///
    /// Semantica de rango de OSV: `introduced <= instalada < fixed`. Dos
    /// detalles que hay que hacer bien:
    ///
    /// 1. El limite superior es ABIERTO. Si se tratara como cerrado, la version
    ///    que corrige el fallo se reportaria como vulnerable y el operador
    ///    aprenderia a ignorar el informe.
    /// 2. Se compara contra la version EFECTIVA del contenido, resolviendo la
    ///    convencion `+really` de Debian y Ubuntu. Sin eso, un paquete
    ///    deliberadamente revertido como `xz-utils 5.6.1+really5.4.5` se
    ///    reporta como afectado por la puerta trasera que precisamente esa
    ///    reversion elimina.
    pub fn affects(&self, instalada: &Version) -> bool {
        let efectiva = instalada.effective();
        if let Some(intro) = &self.introduced {
            if efectiva < *intro {
                return false;
            }
        }
        match &self.fixed {
            Some(fix) => efectiva < *fix,
            None => true,
        }
    }
}

/// Error al analizar el feed.
#[derive(Debug, thiserror::Error)]
pub enum FeedError {
    /// Una linea no tiene el numero de campos esperado.
    #[error("linea {line}: se esperaban 7 campos separados por '|', hay {found}")]
    FieldCount {
        /// Numero de linea, empezando en 1.
        line: usize,
        /// Campos encontrados.
        found: usize,
    },
    /// Un campo obligatorio esta vacio.
    #[error("linea {line}: el campo '{field}' no puede estar vacio")]
    EmptyField {
        /// Numero de linea.
        line: usize,
        /// Nombre del campo.
        field: &'static str,
    },
    /// La puntuacion CVSS no es un numero valido.
    #[error("linea {line}: CVSS '{value}' no es un numero entre 0.0 y 10.0")]
    BadCvss {
        /// Numero de linea.
        line: usize,
        /// Valor encontrado.
        value: String,
    },
}

/// Feed de vulnerabilidades indexado por paquete.
#[derive(Debug, Default)]
pub struct CveFeed {
    por_paquete: HashMap<String, Vec<CveRecord>>,
    total: usize,
}

impl CveFeed {
    /// Analiza un feed en el formato descrito en el modulo.
    ///
    /// Se detiene en el primer error en vez de saltarse la linea mala. Un feed
    /// parcialmente cargado produce un informe que dice "sin vulnerabilidades"
    /// por una razon equivocada, y eso es peor que no ejecutar el escaneo.
    pub fn parse(texto: &str) -> Result<CveFeed, FeedError> {
        let mut feed = CveFeed::default();

        for (i, linea) in texto.lines().enumerate() {
            let n = i + 1;
            let linea = linea.trim();
            if linea.is_empty() || linea.starts_with('#') {
                continue;
            }

            let campos: Vec<&str> = linea.split('|').collect();
            if campos.len() != 7 {
                return Err(FeedError::FieldCount {
                    line: n,
                    found: campos.len(),
                });
            }

            let id = campos[0].trim();
            let paquete = campos[1].trim();
            if id.is_empty() {
                return Err(FeedError::EmptyField {
                    line: n,
                    field: "id",
                });
            }
            if paquete.is_empty() {
                return Err(FeedError::EmptyField {
                    line: n,
                    field: "paquete",
                });
            }

            let cvss_txt = campos[5].trim();
            let cvss = cvss_txt.parse::<f32>().map_err(|_| FeedError::BadCvss {
                line: n,
                value: cvss_txt.to_string(),
            })?;
            if !(0.0..=10.0).contains(&cvss) {
                return Err(FeedError::BadCvss {
                    line: n,
                    value: cvss_txt.to_string(),
                });
            }

            let vacio_a_none = |s: &str| {
                let s = s.trim();
                if s.is_empty() {
                    None
                } else {
                    Some(Version::parse(s))
                }
            };

            let registro = CveRecord {
                id: id.to_string(),
                package: paquete.to_string(),
                introduced: vacio_a_none(campos[2]),
                fixed: vacio_a_none(campos[3]),
                severity: Severity::parse(campos[4]),
                cvss,
                summary: campos[6].trim().to_string(),
            };

            feed.total += 1;
            feed.por_paquete
                .entry(registro.package.clone())
                .or_default()
                .push(registro);
        }

        Ok(feed)
    }

    /// Numero de registros cargados.
    pub fn len(&self) -> usize {
        self.total
    }

    /// Indica si el feed esta vacio.
    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    /// Registros que afectan a un paquete concreto.
    pub fn for_package(&self, nombre: &str) -> &[CveRecord] {
        self.por_paquete.get(nombre).map(|v| &v[..]).unwrap_or(&[])
    }

    /// Numero de paquetes distintos cubiertos por el feed.
    pub fn covered_packages(&self) -> usize {
        self.por_paquete.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FEED: &str = "\
# comentario que se ignora
CVE-2024-3094|xz-utils|5.6.0|5.6.2|critical|10.0|Puerta trasera en la fase de build
CVE-2021-4034|policykit-1||0.105-31ubuntu0.2|high|7.8|Escalada local via pkexec
CVE-2099-0001|sinparche|1.0||medium|5.0|Sin correccion publicada
";

    #[test]
    fn el_feed_se_analiza() {
        let f = CveFeed::parse(FEED).expect("feed valido");
        assert_eq!(f.len(), 3);
        assert_eq!(f.covered_packages(), 3);
        assert_eq!(f.for_package("xz-utils").len(), 1);
        assert_eq!(f.for_package("inexistente").len(), 0);
    }

    #[test]
    fn el_limite_superior_del_rango_es_abierto() {
        let f = CveFeed::parse(FEED).unwrap();
        let r = &f.for_package("xz-utils")[0];

        assert!(
            r.affects(&Version::parse("5.6.0")),
            "la version introducida SI esta afectada"
        );
        assert!(r.affects(&Version::parse("5.6.1")));
        // Si el limite superior se tratara como cerrado, la version que corrige
        // el fallo se reportaria como vulnerable y el operador aprenderia a
        // ignorar el informe.
        assert!(
            !r.affects(&Version::parse("5.6.2")),
            "la version corregida NO"
        );
        assert!(!r.affects(&Version::parse("5.6.3")));
        assert!(
            !r.affects(&Version::parse("5.4.0")),
            "anterior a la introduccion"
        );
    }

    #[test]
    fn sin_version_introducida_afecta_a_todo_lo_anterior_a_la_correccion() {
        let f = CveFeed::parse(FEED).unwrap();
        let r = &f.for_package("policykit-1")[0];
        assert!(r.affects(&Version::parse("0.105-31ubuntu0.1")));
        assert!(r.affects(&Version::parse("0.1")));
        assert!(!r.affects(&Version::parse("0.105-31ubuntu0.2")));
    }

    #[test]
    fn sin_correccion_afecta_a_todo_desde_la_introduccion() {
        let f = CveFeed::parse(FEED).unwrap();
        let r = &f.for_package("sinparche")[0];
        assert!(!r.affects(&Version::parse("0.9")));
        assert!(r.affects(&Version::parse("1.0")));
        assert!(r.affects(&Version::parse("99.0")));
    }

    #[test]
    fn el_feed_se_rechaza_entero_ante_una_linea_mala() {
        // Un feed cargado a medias produce un informe que dice "sin
        // vulnerabilidades" por la razon equivocada.
        let malo = "CVE-1|pkg|1.0|2.0|high\n";
        assert!(matches!(
            CveFeed::parse(malo),
            Err(FeedError::FieldCount { line: 1, found: 5 })
        ));

        let sin_id = "|pkg|1.0|2.0|high|7.0|resumen\n";
        assert!(matches!(
            CveFeed::parse(sin_id),
            Err(FeedError::EmptyField {
                line: 1,
                field: "id"
            })
        ));

        let cvss_malo = "CVE-1|pkg|1.0|2.0|high|once|resumen\n";
        assert!(matches!(
            CveFeed::parse(cvss_malo),
            Err(FeedError::BadCvss { line: 1, .. })
        ));

        let cvss_fuera = "CVE-1|pkg|1.0|2.0|high|11.5|resumen\n";
        assert!(matches!(
            CveFeed::parse(cvss_fuera),
            Err(FeedError::BadCvss { line: 1, .. })
        ));
    }

    #[test]
    fn un_paquete_revertido_con_really_no_se_reporta() {
        let f = CveFeed::parse(FEED).unwrap();
        let r = &f.for_package("xz-utils")[0];

        // Este es el paquete que Ubuntu publico para REVERTIR la puerta
        // trasera. Su numero cae dentro del rango [5.6.0, 5.6.2) pero su
        // contenido es 5.4.5. Reportarlo seria un falso positivo sobre un CVE
        // de CVSS 10.0, justo el hallazgo que el operador mira primero.
        assert!(!r.affects(&Version::parse("5.6.1+really5.4.5-1ubuntu0.2")));
        // La version realmente vulnerable si se reporta.
        assert!(r.affects(&Version::parse("5.6.1-1")));
    }

    #[test]
    fn una_gravedad_desconocida_no_se_infravalora() {
        // Tratarla como baja haria que algo real se ignorara.
        assert_eq!(Severity::parse("weird"), Severity::Medium);
        assert_eq!(Severity::parse("CRITICAL"), Severity::Critical);
    }

    #[test]
    fn las_gravedades_se_ordenan() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Low > Severity::Info);
    }
}
