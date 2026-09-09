//! Aplicacion atomica de actualizaciones con rollback.
//!
//! # Las dos garantias
//!
//! 1. **Nada se aplica sin firma valida.** La verificacion Ed25519 ocurre ANTES
//!    de tocar el fichero en produccion. Un artefacto que no verifica no llega
//!    ni a escribirse en su sitio.
//! 2. **Aplicar es todo o nada, y siempre hay marcha atras.** El artefacto nuevo
//!    se escribe en un fichero de ensayo en el MISMO directorio (para que el
//!    renombrado sea atomico), la version anterior se preserva, y solo entonces
//!    se cambia el fichero vivo con un `rename`, que es atomico en POSIX: en
//!    ningun instante hay un fichero a medio escribir en la ruta de produccion.
//!    Si la version nueva falla, [`Updater::rollback`] restaura la anterior con
//!    otro `rename` atomico.
//!
//! # Por que el respaldo va en el mismo directorio
//!
//! El `rename` solo es atomico dentro de un mismo sistema de ficheros. Guardar
//! el respaldo en `/var/backups` de otra particion haria que restaurarlo fuese
//! una copia no atomica, con una ventana en la que no hay binario. El respaldo
//! vive junto al fichero vivo, como `<nombre>.prev`, y restaurarlo es atomico.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::artifact::Artifact;
use crate::signature::{SignatureError, UpdateKey};

/// Error del proceso de actualizacion.
#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    /// La firma del artefacto no es valida.
    #[error("verificacion de firma fallida: {0}")]
    Signature(#[from] SignatureError),
    /// Error de entrada/salida al escribir, renombrar o restaurar.
    #[error("error de E/S aplicando la actualizacion: {0}")]
    Io(#[from] std::io::Error),
    /// La comprobacion de salud posterior fallo y se restauro la version previa.
    #[error("la version nueva no paso la comprobacion de salud; se restauro la anterior")]
    HealthCheckFailed,
    /// No hay version previa que restaurar.
    #[error("no hay respaldo que restaurar para {0}")]
    NoBackup(String),
}

/// Resultado de aplicar una actualizacion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// Se aplico y quedo activa.
    Applied {
        /// Version aplicada.
        version: String,
    },
    /// Se aplico, fallo la salud y se restauro la anterior.
    RolledBack {
        /// Version que se intento y se descarto.
        rejected: String,
    },
}

/// Comprobacion de salud de una version recien aplicada.
///
/// Es un rasgo para poder decidir la salud sin acoplar el actualizador a como se
/// arranca el agente: en produccion arranca el binario nuevo con un
/// `--self-check` y mira que salga 0; en las pruebas es una funcion.
pub trait HealthCheck {
    /// Devuelve `true` si la version en `path` esta sana.
    fn is_healthy(&self, path: &Path) -> bool;
}

impl<F: Fn(&Path) -> bool> HealthCheck for F {
    fn is_healthy(&self, path: &Path) -> bool {
        self(path)
    }
}

/// Actualizador ligado a un directorio de instalacion y una clave.
#[derive(Debug, Clone)]
pub struct Updater {
    install_dir: PathBuf,
    key: UpdateKey,
}

impl Updater {
    /// Crea un actualizador que instala en `install_dir` y verifica con `key`.
    pub fn new(install_dir: impl AsRef<Path>, key: UpdateKey) -> Updater {
        Updater {
            install_dir: install_dir.as_ref().to_path_buf(),
            key,
        }
    }

    fn live_path(&self, name: &str) -> PathBuf {
        self.install_dir.join(name)
    }
    fn prev_path(&self, name: &str) -> PathBuf {
        self.install_dir.join(format!("{name}.prev"))
    }
    fn staging_path(&self, name: &str) -> PathBuf {
        self.install_dir.join(format!("{name}.staging"))
    }

    /// Verifica la firma del artefacto sin aplicarlo.
    pub fn verify(&self, artifact: &Artifact) -> Result<(), UpdateError> {
        self.key.verify(&artifact.bytes, &artifact.signature)?;
        Ok(())
    }

    /// Aplica un artefacto de forma atomica, tras verificar su firma.
    ///
    /// No hace comprobacion de salud: la version nueva queda activa. Para
    /// aplicar con red de seguridad, usar [`Updater::apply_checked`].
    pub fn apply(&self, artifact: &Artifact) -> Result<ApplyOutcome, UpdateError> {
        // 1. Firma ANTES de tocar nada.
        self.verify(artifact)?;
        std::fs::create_dir_all(&self.install_dir)?;

        // 2. Se escribe en un fichero de ensayo en el mismo directorio y se
        //    fuerza a disco, para que el renombrado posterior sea atomico y no
        //    quede un fichero a medias si se corta la corriente ahora.
        let staging = self.staging_path(&artifact.name);
        {
            let mut f = std::fs::File::create(&staging)?;
            f.write_all(&artifact.bytes)?;
            f.sync_all()?;
        }
        // Se conservan los permisos ejecutables para un binario.
        Self::copiar_permisos(&self.live_path(&artifact.name), &staging);

        // 3. Se preserva la version viva actual como respaldo (renombrado
        //    atomico dentro del directorio).
        let live = self.live_path(&artifact.name);
        if live.exists() {
            std::fs::rename(&live, self.prev_path(&artifact.name))?;
        }

        // 4. Se activa la nueva version con un renombrado atomico.
        std::fs::rename(&staging, &live)?;

        Ok(ApplyOutcome::Applied {
            version: artifact.version.clone(),
        })
    }

    /// Aplica un artefacto y comprueba su salud; si falla, restaura la anterior.
    ///
    /// Es el camino de produccion para el binario del agente y el driver: una
    /// version que no arranca o que se cae al iniciar se revierte sola, sin
    /// dejar la maquina sin proteccion.
    pub fn apply_checked<H: HealthCheck>(
        &self,
        artifact: &Artifact,
        health: &H,
    ) -> Result<ApplyOutcome, UpdateError> {
        self.apply(artifact)?;
        let live = self.live_path(&artifact.name);
        if health.is_healthy(&live) {
            Ok(ApplyOutcome::Applied {
                version: artifact.version.clone(),
            })
        } else {
            self.rollback(&artifact.name)?;
            Ok(ApplyOutcome::RolledBack {
                rejected: artifact.version.clone(),
            })
        }
    }

    /// Restaura la version previa de un artefacto.
    ///
    /// La version que falla se descarta (se aparta como `.failed` para el
    /// analisis forense, no se borra en silencio) y la previa vuelve a su sitio
    /// con un renombrado atomico.
    pub fn rollback(&self, name: &str) -> Result<(), UpdateError> {
        let prev = self.prev_path(name);
        if !prev.exists() {
            return Err(UpdateError::NoBackup(name.to_string()));
        }
        let live = self.live_path(name);
        if live.exists() {
            // Se aparta la version defectuosa en vez de borrarla: sirve para
            // saber por que fallo.
            let failed = self.install_dir.join(format!("{name}.failed"));
            let _ = std::fs::remove_file(&failed);
            std::fs::rename(&live, &failed)?;
        }
        std::fs::rename(&prev, &live)?;
        Ok(())
    }

    /// Indica si hay una version previa disponible para restaurar.
    pub fn has_backup(&self, name: &str) -> bool {
        self.prev_path(name).exists()
    }

    fn copiar_permisos(origen: &Path, destino: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(origen) {
                let modo = meta.permissions().mode();
                let _ = std::fs::set_permissions(destino, std::fs::Permissions::from_mode(modo));
            }
        }
        let _ = (origen, destino);
    }
}
