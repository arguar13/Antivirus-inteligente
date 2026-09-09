//! Ficheros senuelo.
//!
//! # Por que son la unica senal concluyente por si sola
//!
//! Todas las demas heuristicas de este motor son probabilisticas: alta entropia
//! tambien la produce un compresor, velocidad tambien la produce una copia de
//! seguridad, dispersion tambien la produce un indexador. Hay que combinarlas y
//! aun asi queda margen de error.
//!
//! Un senuelo no. **Nadie sabe que existe.** No aparece en ningun indice, no lo
//! referencia ninguna aplicacion, ningun usuario lo abrio jamas. Un proceso que
//! lo abre para escritura solo puede haber llegado ahi recorriendo el directorio
//! y modificando todo lo que encuentra, que es exactamente lo que hace un
//! cifrador y no hace nada mas.
//!
//! # Como se disenan para que funcionen
//!
//! Tres decisiones, todas contra el comportamiento real de los cifradores:
//!
//! - **Nombre que ordena pronto.** Muchos cifradores recorren los directorios
//!   en orden alfabetico. Un senuelo que empieza por un digito se encuentra
//!   entre los primeros, y cada fichero de ventaja son documentos del usuario
//!   que no se pierden.
//! - **Contenido plausible y extension corriente.** Los cifradores filtran por
//!   extension y algunos comprueban que el fichero no este ya cifrado. Un
//!   senuelo de ceros con extension rara se salta.
//! - **Visible, no oculto.** Es tentador esconderlos, pero muchas familias
//!   omiten los ficheros ocultos precisamente para no tocar configuracion del
//!   sistema. Un senuelo oculto no lo ve el atacante y tampoco el usuario, con
//!   lo que solo pierde su utilidad.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Error al desplegar o verificar senuelos.
#[derive(Debug, thiserror::Error)]
pub enum HoneypotError {
    /// Error de entrada/salida.
    #[error("error de E/S en {path}: {source}")]
    Io {
        /// Ruta implicada.
        path: String,
        /// Causa.
        source: std::io::Error,
    },
}

fn io_err(p: &Path, e: std::io::Error) -> HoneypotError {
    HoneypotError::Io {
        path: p.display().to_string(),
        source: e,
    }
}

/// Indica si un fallo al sembrar es esperable y debe omitirse en silencio.
///
/// Un directorio de usuario sin permiso de escritura, montado en solo lectura o
/// que desaparecio entre el `is_dir` y el `create` son situaciones corrientes en
/// cualquier equipo real. Cualquier otra cosa (disco lleno, error de E/S del
/// dispositivo) indica un problema del sistema que el agente debe conocer.
fn es_omitible(e: &std::io::Error) -> bool {
    // EROFS se comprueba por codigo crudo y no por `ErrorKind`: la variante
    // `ReadOnlyFilesystem` no se estabilizo hasta 1.83 y el MSRV del proyecto es
    // 1.82.
    const EROFS: i32 = 30;
    matches!(
        e.kind(),
        std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::NotFound
    ) || e.raw_os_error() == Some(EROFS)
}

/// Un fichero senuelo desplegado.
#[derive(Debug, Clone)]
pub struct Canary {
    /// Ruta absoluta.
    pub path: PathBuf,
    /// Tamano en bytes.
    pub size: u64,
    /// Suma de comprobacion del contenido original.
    ///
    /// Permite detectar que fue modificado aunque el evento en tiempo real se
    /// haya perdido: si el ring se lleno durante el pico, el barrido periodico
    /// lo descubre igual.
    pub checksum: u64,
}

/// Configuracion del despliegue.
#[derive(Debug, Clone)]
pub struct HoneypotConfig {
    /// Directorios donde sembrar.
    pub directories: Vec<PathBuf>,
    /// Senuelos por directorio.
    pub per_directory: usize,
}

impl Default for HoneypotConfig {
    fn default() -> Self {
        Self {
            directories: directorios_por_defecto(),
            // Mas de uno por directorio: un cifrador puede saltarse un fichero
            // concreto por tamano o por error, y varios reducen esa
            // probabilidad casi a cero sin coste apreciable.
            per_directory: 3,
        }
    }
}

/// Directorios de documentos donde tiene sentido sembrar.
pub fn directorios_por_defecto() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Ok(home) = std::env::var("HOME") {
        let h = PathBuf::from(home);
        for sub in [
            "Documents",
            "Documentos",
            "Desktop",
            "Escritorio",
            "Pictures",
            "Imagenes",
        ] {
            let d = h.join(sub);
            if d.is_dir() {
                v.push(d);
            }
        }
        if v.is_empty() && h.is_dir() {
            v.push(h);
        }
    }
    for d in ["/srv", "/var/www"] {
        let p = PathBuf::from(d);
        if p.is_dir() {
            v.push(p);
        }
    }
    v
}

/// Plantillas de senuelo: nombre y contenido plausible.
///
/// Los nombres empiezan por digito para ordenar pronto en un recorrido
/// alfabetico, y usan extensiones corrientes para que un cifrador que filtre por
/// extension los incluya.
const PLANTILLAS: &[(&str, &str)] = &[
    (
        "0001-copia-de-seguridad.docx",
        "Informe trimestral\n\nResumen de actividad del periodo. Ver anexos.\n",
    ),
    (
        "0002-contactos.xlsx",
        "nombre,telefono,correo\nEjemplo,600000000,ejemplo@ejemplo.org\n",
    ),
    (
        "0003-notas-personales.pdf",
        "%PDF-1.4\nNotas de la reunion del lunes. Pendiente revisar presupuesto.\n",
    ),
    (
        "0004-fotos-familia.jpg",
        "album de fotos, referencia interna 2024-03\n",
    ),
    (
        "0005-declaracion.odt",
        "Documento de trabajo. No distribuir.\n",
    ),
];

/// Suma de comprobacion FNV-1a de 64 bits.
fn checksum(datos: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in datos {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x1000_0000_01b3);
    }
    h
}

/// Conjunto de senuelos desplegados.
#[derive(Debug, Default)]
pub struct HoneypotSet {
    canarios: HashMap<PathBuf, Canary>,
}

impl HoneypotSet {
    /// Despliega los senuelos segun la configuracion.
    ///
    /// Los directorios que no existen o no se pueden escribir se omiten sin
    /// error: sembrar es una mejora oportunista, y fallar el arranque del agente
    /// porque un directorio de usuario no existe seria desproporcionado.
    pub fn deploy(config: &HoneypotConfig) -> Result<HoneypotSet, HoneypotError> {
        let mut set = HoneypotSet::default();
        for dir in &config.directories {
            if !dir.is_dir() {
                continue;
            }
            for (nombre, contenido) in PLANTILLAS.iter().take(config.per_directory) {
                let ruta = dir.join(nombre);
                // Si ya existe con nuestro contenido, se reutiliza; si existe
                // con OTRO contenido, no se pisa: podria ser un fichero real
                // del usuario que casualmente se llama igual.
                if let Ok(actual) = std::fs::read(&ruta) {
                    if checksum(&actual) == checksum(contenido.as_bytes()) {
                        set.canarios.insert(
                            ruta.clone(),
                            Canary {
                                path: ruta,
                                size: actual.len() as u64,
                                checksum: checksum(&actual),
                            },
                        );
                    }
                    continue;
                }
                match std::fs::File::create(&ruta).and_then(|mut f| {
                    f.write_all(contenido.as_bytes())?;
                    f.sync_all()
                }) {
                    Ok(()) => {
                        set.canarios.insert(
                            ruta.clone(),
                            Canary {
                                path: ruta,
                                size: contenido.len() as u64,
                                checksum: checksum(contenido.as_bytes()),
                            },
                        );
                    }
                    // Se distingue entre "aqui no puedo sembrar" y "el sistema
                    // de ficheros esta roto". Lo primero es corriente y se
                    // omite; lo segundo se propaga, porque tragarselo dejaria
                    // al agente creyendo que tiene senuelos desplegados cuando
                    // en realidad no protegen nada.
                    Err(e) => {
                        // Si `create` funciono y fallo `write_all`, queda un
                        // fichero vacio o a medias en la carpeta del usuario.
                        // No sirve de senuelo (su contenido no es el que se
                        // vigila) y es basura visible, asi que se retira.
                        let _ = std::fs::remove_file(&ruta);
                        if es_omitible(&e) {
                            continue;
                        }
                        return Err(io_err(&ruta, e));
                    }
                }
            }
        }
        Ok(set)
    }

    /// Construye un conjunto sobre rutas ya existentes, sin crear nada.
    pub fn from_paths<I: IntoIterator<Item = PathBuf>>(rutas: I) -> HoneypotSet {
        let mut set = HoneypotSet::default();
        for r in rutas {
            let datos = std::fs::read(&r).unwrap_or_default();
            set.canarios.insert(
                r.clone(),
                Canary {
                    size: datos.len() as u64,
                    checksum: checksum(&datos),
                    path: r,
                },
            );
        }
        set
    }

    /// Numero de senuelos desplegados.
    pub fn len(&self) -> usize {
        self.canarios.len()
    }

    /// Indica si no hay ninguno.
    pub fn is_empty(&self) -> bool {
        self.canarios.is_empty()
    }

    /// Rutas de los senuelos.
    pub fn paths(&self) -> impl Iterator<Item = &Path> {
        self.canarios.keys().map(|p| p.as_path())
    }

    /// Indica si una ruta corresponde a un senuelo.
    ///
    /// Es la consulta de la ruta caliente: se hace por cada apertura con
    /// intencion de escritura, asi que tiene que ser una busqueda en tabla y no
    /// un recorrido.
    pub fn is_canary(&self, ruta: &Path) -> bool {
        self.canarios.contains_key(ruta)
    }

    /// Igual que [`HoneypotSet::is_canary`] sobre una ruta en texto.
    pub fn is_canary_str(&self, ruta: &str) -> bool {
        self.canarios.contains_key(Path::new(ruta))
    }

    /// Comprueba en disco cuales han sido modificados o eliminados.
    ///
    /// Existe porque el evento en tiempo real puede perderse: si el ring se
    /// lleno durante el pico de actividad, esta comprobacion lo descubre igual.
    /// Un producto que solo detecta por evento se queda ciego justo cuando mas
    /// eventos hay.
    pub fn verify(&self) -> Vec<TamperedCanary> {
        let mut salida = Vec::new();
        for (ruta, c) in &self.canarios {
            match std::fs::read(ruta) {
                Ok(datos) => {
                    let ck = checksum(&datos);
                    if ck != c.checksum {
                        salida.push(TamperedCanary {
                            path: ruta.clone(),
                            reason: TamperReason::Modified {
                                expected_size: c.size,
                                found_size: datos.len() as u64,
                            },
                        });
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    salida.push(TamperedCanary {
                        path: ruta.clone(),
                        reason: TamperReason::Deleted,
                    });
                }
                Err(_) => salida.push(TamperedCanary {
                    path: ruta.clone(),
                    reason: TamperReason::Unreadable,
                }),
            }
        }
        salida.sort_by(|a, b| a.path.cmp(&b.path));
        salida
    }

    /// Elimina los senuelos del disco.
    pub fn cleanup(&self) {
        for r in self.canarios.keys() {
            let _ = std::fs::remove_file(r);
        }
    }
}

/// Motivo por el que un senuelo se considera manipulado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TamperReason {
    /// El contenido cambio.
    Modified {
        /// Tamano original.
        expected_size: u64,
        /// Tamano encontrado.
        found_size: u64,
    },
    /// Desaparecio.
    Deleted,
    /// Existe pero no se puede leer.
    ///
    /// Es lo que ocurre cuando un cifrador le cambia los permisos.
    Unreadable,
}

/// Senuelo manipulado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TamperedCanary {
    /// Ruta.
    pub path: PathBuf,
    /// Motivo.
    pub reason: TamperReason,
}
