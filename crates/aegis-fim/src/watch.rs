//! Vigilancia de cambios mediante inotify.
//!
//! La implementacion vive en `aegis-scal`, la capa de abstraccion del sistema:
//! inotify es una interfaz de Linux, y el FIM tiene que poder correr sobre
//! `ReadDirectoryChangesW` en Windows y `FSEvents` en macOS sin reescribir la
//! linea base ni el hasheo. Lo que queda aqui son los nombres con los que el
//! resto del FIM ya la usaba.

pub use aegis_scal::fsmon::{FileAction as ChangeKind, FileEvent as ChangeEvent};

#[cfg(target_os = "linux")]
pub use aegis_scal::linux::fsmon::{InotifyMonitor as Watcher, WatchError};
