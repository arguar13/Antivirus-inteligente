//! Modelo e interfaz de vigilancia del sistema de ficheros.
//!
//! El modelo es deliberadamente pobre: ruta y tipo de cambio. Las tres
//! plataformas entregan mas cosas —inotify da la cookie de renombrado, ETW da
//! el proceso que escribio, FSEvents da un identificador de evento—, pero solo
//! lo que las tres dan de forma fiable puede formar parte de la interfaz comun.
//! Lo demas se obtiene por el backend concreto cuando hace falta, no fingiendo
//! que existe en todas partes.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::ScalError;
use crate::platform::Platform;

/// Tipo de cambio observado sobre una ruta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileAction {
    /// Se creo la entrada.
    Created,
    /// Cambio el contenido.
    Modified,
    /// Cambiaron atributos, permisos o propietario.
    Attributes,
    /// Se borro la entrada.
    Deleted,
    /// Se movio DENTRO del directorio vigilado.
    MovedIn,
    /// Se movio FUERA del directorio vigilado.
    MovedOut,
}

impl FileAction {
    /// Indica si el cambio puede alterar el contenido del fichero.
    ///
    /// Es lo que decide si hay que rehashear: un cambio de permisos altera la
    /// linea base pero no el hash, y rehashear por el es gasto inutil sobre
    /// ficheros que pueden ser grandes.
    pub fn touches_content(self) -> bool {
        matches!(
            self,
            FileAction::Created | FileAction::Modified | FileAction::MovedIn
        )
    }

    /// Indica si el cambio hace desaparecer la entrada de la ruta vigilada.
    pub fn removes_entry(self) -> bool {
        matches!(self, FileAction::Deleted | FileAction::MovedOut)
    }
}

/// Un cambio observado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEvent {
    /// Ruta completa afectada.
    pub path: PathBuf,
    /// Tipo de cambio.
    pub kind: FileAction,
}

/// Vigilante del sistema de ficheros.
///
/// La vigilancia es por DIRECTORIO, no por fichero suelto, en las tres
/// plataformas. Vigilar un fichero concreto parece mas preciso y es justo lo
/// contrario: la forma habitual de sustituir un fichero de sistema es escribir
/// uno nuevo al lado y renombrarlo encima, y una vigilancia anclada al inodo
/// viejo no ve nada.
pub trait FileSystemMonitor {
    /// Plataforma que implementa este vigilante.
    fn platform(&self) -> Platform;

    /// Empieza a vigilar un directorio.
    fn watch(&mut self, dir: &Path) -> Result<(), ScalError>;

    /// Numero de directorios vigilados.
    fn watched(&self) -> usize;

    /// Entrega los cambios pendientes, esperando como mucho `timeout`.
    fn poll(&mut self, timeout: Duration) -> Result<Vec<FileEvent>, ScalError>;
}
