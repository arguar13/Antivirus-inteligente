//! Sembrado de honey-files: credenciales senuelo en el sistema de ficheros.
//!
//! Un atacante que entra husmea en los sitios de siempre: `~/.ssh/`, `~/.pgpass`,
//! ficheros `credentials.xml` de despliegue. Un honey-file es una credencial
//! senuelo puesta justo ahi. Escribirla es E/S de ficheros normal —esto no es
//! gated—; lo que si necesita el kernel es DETECTAR su apertura en tiempo real
//! (fanotify), que vive aparte.

use crate::credformat::{render, Artefacto};
use crate::token::{Atribucion, Marcador};
use std::path::{Path, PathBuf};

/// Un honey-file sembrado.
#[derive(Debug, Clone)]
pub struct HoneyFile {
    /// Donde quedo.
    pub ruta: PathBuf,
    /// El marcador embebido en su contenido.
    pub marcador: Marcador,
    /// A quien esta atado.
    pub atribucion: Atribucion,
}

/// Un fallo al sembrar.
#[derive(Debug, thiserror::Error)]
pub enum HoneyfileError {
    /// No se pudo escribir el fichero senuelo.
    #[error("sembrando el honey-file: {0}")]
    Io(#[from] std::io::Error),
}

/// Siembra un honey-file: renderiza el artefacto con su marcador y lo escribe en
/// `ruta`. Devuelve el `HoneyFile` para registrarlo.
pub fn sembrar(
    ruta: &Path,
    art: Artefacto,
    marcador: Marcador,
    atribucion: Atribucion,
) -> Result<HoneyFile, HoneyfileError> {
    let contenido = render(art, &marcador);
    std::fs::write(ruta, contenido)?;
    Ok(HoneyFile {
        ruta: ruta.to_path_buf(),
        marcador,
        atribucion,
    })
}
