//! Estado conocido-bueno de los ficheros vigilados.
//!
//! El FIM compara el estado actual contra una linea base: los hashes que los
//! ficheros criticos tenian cuando se sabia que el sistema estaba integro. Una
//! divergencia es una modificacion no autorizada.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::hash::{self, Blake3};

/// Un cambio detectado respecto a la linea base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityChange {
    /// Un fichero vigilado cambio de contenido.
    Modified {
        /// Ruta.
        path: PathBuf,
        /// Hash que tenia.
        was: Blake3,
        /// Hash que tiene.
        now: Blake3,
    },
    /// Aparecio un fichero que no estaba en la linea base.
    Added {
        /// Ruta.
        path: PathBuf,
        /// Hash actual.
        now: Blake3,
    },
    /// Desaparecio un fichero que estaba en la linea base.
    Removed {
        /// Ruta.
        path: PathBuf,
        /// Hash que tenia.
        was: Blake3,
    },
}

impl IntegrityChange {
    /// Ruta afectada.
    pub fn path(&self) -> &Path {
        match self {
            IntegrityChange::Modified { path, .. }
            | IntegrityChange::Added { path, .. }
            | IntegrityChange::Removed { path, .. } => path,
        }
    }
}

/// Linea base de integridad: ruta -> hash conocido-bueno.
#[derive(Debug, Clone, Default)]
pub struct Baseline {
    hashes: BTreeMap<PathBuf, Blake3>,
}

impl Baseline {
    /// Linea base vacia.
    pub fn new() -> Baseline {
        Baseline::default()
    }

    /// Construye la linea base hasheando una lista de ficheros en paralelo.
    ///
    /// Los ficheros que no se pueden leer se omiten: un fichero de sistema que
    /// no existe en esta distribucion no es un problema de integridad.
    pub fn build(rutas: &[PathBuf]) -> Baseline {
        let mut b = Baseline::new();
        for (ruta, h) in hash::hash_files_concurrent(rutas, 0) {
            if let Ok(hash) = h {
                b.hashes.insert(ruta, hash);
            }
        }
        b
    }

    /// Numero de ficheros en la linea base.
    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    /// Indica si esta vacia.
    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    /// Hash conocido de un fichero, si esta en la linea base.
    pub fn get(&self, ruta: &Path) -> Option<&Blake3> {
        self.hashes.get(ruta)
    }

    /// Registra o actualiza el hash de un fichero (tras una actualizacion
    /// legitima, por ejemplo).
    pub fn set(&mut self, ruta: PathBuf, hash: Blake3) {
        self.hashes.insert(ruta, hash);
    }

    /// Comprueba UN fichero contra la linea base rehasheandolo del disco.
    ///
    /// Es la ruta caliente: se llama cuando inotify avisa de que un fichero
    /// concreto cambio, y solo rehashea ese, no toda la lista.
    pub fn check_path(&self, ruta: &Path) -> Option<IntegrityChange> {
        let conocido = self.hashes.get(ruta).copied();
        let actual = hash::hash_file(ruta).ok();
        match (conocido, actual) {
            (Some(was), Some(now)) if was != now => Some(IntegrityChange::Modified {
                path: ruta.to_path_buf(),
                was,
                now,
            }),
            (Some(_), Some(_)) => None, // intacto
            (Some(was), None) => Some(IntegrityChange::Removed {
                path: ruta.to_path_buf(),
                was,
            }),
            (None, Some(now)) => Some(IntegrityChange::Added {
                path: ruta.to_path_buf(),
                now,
            }),
            (None, None) => None,
        }
    }

    /// Barrido completo: rehashea todos los ficheros conocidos y busca los que
    /// hayan cambiado o desaparecido, mas los ficheros nuevos en `presentes`.
    ///
    /// Es la comprobacion de respaldo del sondeo por eventos: si un evento de
    /// inotify se perdio (cola desbordada), el barrido peridico lo descubre.
    pub fn full_scan(&self, presentes: &[PathBuf]) -> Vec<IntegrityChange> {
        let mut cambios = Vec::new();
        // Modificados y borrados.
        for (ruta, was) in &self.hashes {
            match hash::hash_file(ruta) {
                Ok(now) if now != *was => cambios.push(IntegrityChange::Modified {
                    path: ruta.clone(),
                    was: *was,
                    now,
                }),
                Ok(_) => {}
                Err(_) => cambios.push(IntegrityChange::Removed {
                    path: ruta.clone(),
                    was: *was,
                }),
            }
        }
        // Anadidos.
        for ruta in presentes {
            if !self.hashes.contains_key(ruta) {
                if let Ok(now) = hash::hash_file(ruta) {
                    cambios.push(IntegrityChange::Added {
                        path: ruta.clone(),
                        now,
                    });
                }
            }
        }
        cambios
    }
}
