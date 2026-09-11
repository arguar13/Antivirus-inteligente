//! Captura CoW en vivo con fanotify. GATED tras la feature `fanotify`.
//!
//! # Por que esto no se compila ni se prueba en el CI de este proyecto
//!
//! Interceptar la escritura ANTES de que ocurra —para leer el contenido
//! original y guardar la copia-sombra— necesita `fanotify` con permiso de
//! bloqueo (`FAN_CLASS_PRE_CONTENT` / `FAN_OPEN_PERM`), que exige
//! `CAP_SYS_ADMIN` y un kernel reciente. Este entorno de integracion no lo
//! garantiza, asi que la captura vive tras la feature `fanotify` y el CI declara
//! si se ejercio, en vez de fingir.
//!
//! La DECISION —que copiar y cuando (`journal`), como cifrar la copia
//! (`shadowstore`), como revertir (`revert`)— si es portable y se prueba con
//! datos reales en cada `make ci`. Esto de aqui es la tuberia que conecta el
//! kernel con esa decision: se valida ejecutandola en una maquina con permisos,
//! no en una prueba unitaria.
//!
//! # El punto delicado: leer el original ANTES de dejar escribir
//!
//! Con `FAN_CLASS_PRE_CONTENT` el evento llega mientras la operacion esta
//! SUSPENDIDA, esperando un veredicto (`FAN_ALLOW`/`FAN_DENY`). Esa es la unica
//! ventana en la que el fichero sigue teniendo su contenido original: se lee
//! aqui, se pasa al `journal`, y solo entonces se permite la escritura. Un
//! milisegundo despues, el original ya no existe.

use std::os::unix::io::RawFd;

/// Un fallo al montar o usar la captura fanotify.
#[derive(Debug, thiserror::Error)]
pub enum CapturaError {
    /// `fanotify_init`/`fanotify_mark` fallaron (tipicamente falta
    /// `CAP_SYS_ADMIN`).
    #[error("fanotify: {0}")]
    Fanotify(#[from] std::io::Error),
    /// La ruta contenia un byte nulo y no se pudo pasar a la syscall.
    #[error("la ruta a vigilar no es valida")]
    RutaInvalida,
}

/// Un vigilante fanotify montado sobre un punto de montaje.
pub struct Vigilante {
    fd: RawFd,
}

impl Vigilante {
    /// Monta la captura en modo contenido-previo sobre el punto de montaje que
    /// contiene `ruta`. Requiere `CAP_SYS_ADMIN`.
    pub fn montar(ruta: &str) -> Result<Vigilante, CapturaError> {
        // SAFETY: fanotify_init es una syscall sin efectos sobre memoria de
        // Rust; se comprueba el retorno y el fd crudo se envuelve en el acto.
        let fd = unsafe {
            libc::fanotify_init(
                libc::FAN_CLASS_PRE_CONTENT | libc::FAN_CLOEXEC | libc::FAN_NONBLOCK,
                (libc::O_RDONLY | libc::O_LARGEFILE) as u32,
            )
        };
        if fd < 0 {
            return Err(CapturaError::Fanotify(std::io::Error::last_os_error()));
        }

        let cruta = std::ffi::CString::new(ruta).map_err(|_| CapturaError::RutaInvalida)?;
        // SAFETY: `fd` es un descriptor valido recien creado; `cruta` vive hasta
        // el final de la funcion y aporta un puntero C valido y terminado en
        // nulo. Se interceptan las aperturas para escritura en todo el montaje.
        let rc = unsafe {
            libc::fanotify_mark(
                fd,
                libc::FAN_MARK_ADD | libc::FAN_MARK_MOUNT,
                libc::FAN_OPEN_PERM,
                libc::AT_FDCWD,
                cruta.as_ptr(),
            )
        };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            // SAFETY: se cierra el fd que se acaba de abrir; no se vuelve a usar.
            unsafe {
                libc::close(fd);
            }
            return Err(CapturaError::Fanotify(e));
        }

        Ok(Vigilante { fd })
    }

    /// El descriptor fanotify, para integrarlo en un bucle de eventos (epoll).
    pub fn fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for Vigilante {
    fn drop(&mut self) {
        // SAFETY: `fd` es propiedad de este Vigilante y se cierra una sola vez.
        unsafe {
            libc::close(self.fd);
        }
    }
}
