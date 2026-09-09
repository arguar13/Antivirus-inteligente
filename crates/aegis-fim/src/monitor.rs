//! El monitor de integridad: une la linea base, inotify y el rehasheo.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::baseline::{Baseline, IntegrityChange};
use crate::watch::{ChangeKind, WatchError, Watcher};

/// Configuracion del monitor.
#[derive(Debug, Clone)]
pub struct FimConfig {
    /// Directorios criticos a vigilar.
    pub directories: Vec<PathBuf>,
    /// Ficheros concretos a incluir en la linea base (ademas de los de los
    /// directorios).
    pub files: Vec<PathBuf>,
}

impl Default for FimConfig {
    fn default() -> Self {
        Self {
            directories: rutas_criticas_por_defecto(),
            files: Vec::new(),
        }
    }
}

/// Directorios de sistema donde vive la persistencia y que merece vigilar.
pub fn rutas_criticas_por_defecto() -> Vec<PathBuf> {
    [
        "/etc",
        "/boot",
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/etc/cron.d",
    ]
    .iter()
    .map(PathBuf::from)
    .filter(|p| p.is_dir())
    .collect()
}

/// Monitor de integridad de ficheros.
#[derive(Debug)]
pub struct FimMonitor {
    baseline: Baseline,
    watcher: Watcher,
    /// Ficheros de la linea base, para el barrido de respaldo.
    vigilados: Vec<PathBuf>,
}

impl FimMonitor {
    /// Construye el monitor: hashea la linea base y arranca inotify sobre los
    /// directorios.
    ///
    /// La linea base se calcula ANTES de empezar a vigilar, de forma que
    /// represente el estado en el arranque del monitor. Un fichero que cambie
    /// entre el hasheo y la instalacion del watch se coge en el primer barrido.
    pub fn start(config: &FimConfig) -> Result<FimMonitor, WatchError> {
        let vigilados = Self::enumerar(config);
        let baseline = Baseline::build(&vigilados);

        let mut watcher = Watcher::new()?;
        for dir in &config.directories {
            // Un directorio que no existe se omite, no aborta el monitor: cada
            // distribucion tiene sus rutas.
            let _ = watcher.watch_dir(dir);
        }
        Ok(FimMonitor {
            baseline,
            watcher,
            vigilados,
        })
    }

    /// Construye un monitor sobre ficheros ya enumerados, con una linea base
    /// dada. Util para pruebas y para reanudar con una base guardada.
    pub fn with_baseline(
        directories: &[PathBuf],
        baseline: Baseline,
        vigilados: Vec<PathBuf>,
    ) -> Result<FimMonitor, WatchError> {
        let mut watcher = Watcher::new()?;
        for dir in directories {
            let _ = watcher.watch_dir(dir);
        }
        Ok(FimMonitor {
            baseline,
            watcher,
            vigilados,
        })
    }

    fn enumerar(config: &FimConfig) -> Vec<PathBuf> {
        let mut set: HashSet<PathBuf> = config.files.iter().cloned().collect();
        for dir in &config.directories {
            if let Ok(rd) = std::fs::read_dir(dir) {
                for e in rd.flatten() {
                    let p = e.path();
                    if p.is_file() {
                        set.insert(p);
                    }
                }
            }
        }
        let mut v: Vec<PathBuf> = set.into_iter().collect();
        v.sort();
        v
    }

    /// Linea base actual.
    pub fn baseline(&self) -> &Baseline {
        &self.baseline
    }

    /// Ficheros vigilados.
    pub fn watched_files(&self) -> &[PathBuf] {
        &self.vigilados
    }

    /// Directorios vigilados por inotify.
    pub fn watched_dirs(&self) -> usize {
        self.watcher.watched()
    }

    /// Espera hasta `timeout_ms` a eventos de inotify y devuelve los cambios de
    /// integridad que impliquen. Cada evento rehashea SOLO el fichero afectado.
    ///
    /// Es la ruta caliente: reacciona en milisegundos y no toca mas que el
    /// fichero que el kernel senalo.
    pub fn poll(&self, timeout_ms: i32) -> Result<Vec<IntegrityChange>, WatchError> {
        let eventos = self.watcher.poll_timeout(timeout_ms)?;
        let mut cambios = Vec::new();
        let mut vistos: HashSet<PathBuf> = HashSet::new();
        for ev in eventos {
            // Un mismo fichero puede generar varios eventos en una rafaga; se
            // rehashea una sola vez.
            if !vistos.insert(ev.path.clone()) {
                continue;
            }
            // Solo interesan los ficheros de la linea base o nuevos ficheros en
            // los directorios vigilados; un evento de borrado se comprueba igual.
            let cambio = match ev.kind {
                ChangeKind::Deleted | ChangeKind::MovedOut => {
                    self.baseline
                        .get(&ev.path)
                        .map(|was| IntegrityChange::Removed {
                            path: ev.path.clone(),
                            was: *was,
                        })
                }
                _ => self.baseline.check_path(&ev.path),
            };
            if let Some(c) = cambio {
                cambios.push(c);
            }
        }
        Ok(cambios)
    }

    /// Barrido completo de respaldo, por si se perdio algun evento de inotify.
    pub fn full_scan(&self) -> Vec<IntegrityChange> {
        self.baseline.full_scan(&self.vigilados)
    }

    /// Marca el estado actual de un fichero como el nuevo conocido-bueno, tras
    /// una actualizacion legitima.
    pub fn accept_current(&mut self, ruta: &Path) -> std::io::Result<()> {
        let h = crate::hash::hash_file(ruta)?;
        self.baseline.set(ruta.to_path_buf(), h);
        Ok(())
    }
}
