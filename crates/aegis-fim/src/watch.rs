//! Vigilancia de cambios mediante inotify (Linux).
//!
//! # Por que inotify y no sondeo
//!
//! Detectar una modificacion releyendo todos los ficheros cada pocos segundos
//! es caro y lento: caro porque hashea todo constantemente, lento porque entre
//! sondeos hay una ventana ciega. inotify avisa al KERNEL de cada cambio y el
//! agente reacciona en milisegundos, hasheando solo el fichero que cambio.
//!
//! Se usa la API cruda por `libc` en vez de una caja externa: son cuatro
//! llamadas al sistema (`inotify_init1`, `inotify_add_watch`, `read`, `close`) y
//! un parseo de estructura de tamano variable, y mantenerlo aqui deja la
//! superficie de kernel que toca el FIM en un unico fichero auditable, sin
//! arrastrar una dependencia.

use std::collections::HashMap;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};

/// Error del vigilante.
#[derive(Debug, thiserror::Error)]
pub enum WatchError {
    /// No se pudo inicializar inotify.
    #[error("inotify_init fallo: {0}")]
    Init(std::io::Error),
    /// No se pudo vigilar una ruta.
    #[error("no se pudo vigilar {path}: {detail}")]
    AddWatch {
        /// Ruta.
        path: String,
        /// Causa.
        detail: std::io::Error,
    },
    /// Error leyendo eventos.
    #[error("error leyendo eventos de inotify: {0}")]
    Read(std::io::Error),
}

/// Tipo de cambio observado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    /// Se creo un fichero.
    Created,
    /// Se modifico el contenido.
    Modified,
    /// Cambiaron atributos o permisos.
    Attributes,
    /// Se borro.
    Deleted,
    /// Se movio a la carpeta vigilada.
    MovedIn,
    /// Se movio fuera.
    MovedOut,
}

/// Un cambio observado en una ruta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeEvent {
    /// Ruta completa afectada.
    pub path: PathBuf,
    /// Tipo de cambio.
    pub kind: ChangeKind,
}

/// Mascara de eventos que interesan a la integridad.
const MASK: u32 = libc::IN_MODIFY
    | libc::IN_CREATE
    | libc::IN_DELETE
    | libc::IN_ATTRIB
    | libc::IN_MOVED_TO
    | libc::IN_MOVED_FROM
    | libc::IN_CLOSE_WRITE;

/// Vigilante de integridad basado en inotify.
#[derive(Debug)]
pub struct Watcher {
    fd: RawFd,
    /// wd -> directorio vigilado, para reconstruir rutas completas.
    watches: HashMap<i32, PathBuf>,
}

impl Watcher {
    /// Crea un vigilante. El descriptor es no bloqueante para poder sondear con
    /// plazo y atender la senal de parada del agente.
    pub fn new() -> Result<Watcher, WatchError> {
        // SAFETY: inotify_init1 no toca memoria del proceso; devuelve un fd o -1.
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if fd < 0 {
            return Err(WatchError::Init(std::io::Error::last_os_error()));
        }
        Ok(Watcher {
            fd,
            watches: HashMap::new(),
        })
    }

    /// Empieza a vigilar un directorio.
    pub fn watch_dir(&mut self, dir: &Path) -> Result<(), WatchError> {
        let c = std::ffi::CString::new(dir.as_os_str().as_bytes()).map_err(|_| {
            WatchError::AddWatch {
                path: dir.display().to_string(),
                detail: std::io::Error::new(std::io::ErrorKind::InvalidInput, "ruta con NUL"),
            }
        })?;
        // SAFETY: fd valido, puntero a CString valida mientras dure la llamada.
        let wd = unsafe { libc::inotify_add_watch(self.fd, c.as_ptr(), MASK) };
        if wd < 0 {
            return Err(WatchError::AddWatch {
                path: dir.display().to_string(),
                detail: std::io::Error::last_os_error(),
            });
        }
        self.watches.insert(wd, dir.to_path_buf());
        Ok(())
    }

    /// Numero de directorios vigilados.
    pub fn watched(&self) -> usize {
        self.watches.len()
    }

    /// Lee los eventos disponibles sin bloquear. Devuelve vacio si no hay
    /// ninguno en este instante.
    pub fn poll(&self) -> Result<Vec<ChangeEvent>, WatchError> {
        let mut buf = [0u8; 8192];
        // SAFETY: se lee en un buffer de pila de tamano conocido sobre un fd
        // valido; el retorno es el numero de bytes o -1.
        let n = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(Vec::new());
            }
            return Err(WatchError::Read(e));
        }
        Ok(self.parse_events(&buf[..n as usize]))
    }

    /// Espera hasta `timeout_ms` a que haya eventos, y los devuelve.
    pub fn poll_timeout(&self, timeout_ms: i32) -> Result<Vec<ChangeEvent>, WatchError> {
        let mut pfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: un unico pollfd valido.
        let r = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if r <= 0 {
            return Ok(Vec::new());
        }
        self.poll()
    }

    fn parse_events(&self, mut datos: &[u8]) -> Vec<ChangeEvent> {
        let mut salida = Vec::new();
        let cabecera = std::mem::size_of::<libc::inotify_event>();
        while datos.len() >= cabecera {
            // SAFETY: hay al menos `cabecera` bytes; se lee sin alinear.
            let ev: libc::inotify_event =
                unsafe { std::ptr::read_unaligned(datos.as_ptr() as *const libc::inotify_event) };
            let len = ev.len as usize;
            if datos.len() < cabecera + len {
                break;
            }
            let nombre_bytes = &datos[cabecera..cabecera + len];
            // El nombre viene terminado en NUL y rellenado; se corta en el NUL.
            let nombre = nombre_bytes.split(|b| *b == 0).next().unwrap_or(&[]);

            if let Some(dir) = self.watches.get(&ev.wd) {
                let ruta = if nombre.is_empty() {
                    dir.clone()
                } else {
                    dir.join(std::ffi::OsStr::from_bytes(nombre))
                };
                for kind in Self::clasificar(ev.mask) {
                    salida.push(ChangeEvent {
                        path: ruta.clone(),
                        kind,
                    });
                }
            }
            datos = &datos[cabecera + len..];
        }
        salida
    }

    fn clasificar(mask: u32) -> Vec<ChangeKind> {
        let mut v = Vec::new();
        // IN_CLOSE_WRITE y IN_MODIFY se tratan como modificacion; CLOSE_WRITE es
        // la senal fiable de "termino de escribir", que es cuando merece la pena
        // rehashear.
        if mask & (libc::IN_MODIFY | libc::IN_CLOSE_WRITE) != 0 {
            v.push(ChangeKind::Modified);
        }
        if mask & libc::IN_CREATE != 0 {
            v.push(ChangeKind::Created);
        }
        if mask & libc::IN_DELETE != 0 {
            v.push(ChangeKind::Deleted);
        }
        if mask & libc::IN_ATTRIB != 0 {
            v.push(ChangeKind::Attributes);
        }
        if mask & libc::IN_MOVED_TO != 0 {
            v.push(ChangeKind::MovedIn);
        }
        if mask & libc::IN_MOVED_FROM != 0 {
            v.push(ChangeKind::MovedOut);
        }
        v
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        // SAFETY: fd valido abierto por este tipo; se cierra una sola vez.
        unsafe { libc::close(self.fd) };
    }
}
