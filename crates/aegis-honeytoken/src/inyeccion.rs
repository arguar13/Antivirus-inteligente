//! Fontaneria de inyeccion en memoria ajena. GATED tras la feature `inyeccion`.
//!
//! # Por que no se compila ni se prueba en el CI de este proyecto
//!
//! Colocar el honey-token en la memoria de un proceso VIVO (un `ssh-agent`, un
//! `gpg-agent`, o LSASS en Windows) necesita `process_vm_writev` con privilegios
//! sobre el objetivo. Ejercerlo exige un proceso victima real y permisos que este
//! entorno de CI no da, asi que vive tras la feature `inyeccion` y el CI declara
//! que no se ejercio.
//!
//! El NUCLEO —acunar el marcador, renderizar la credencial, PLANIFICAR donde
//! escribir leyendo `/proc/<pid>/maps` real, y decidir el disparo— si se prueba
//! en cada `make ci`. Esto de aqui es la escritura final: se valida sobre un
//! proceso real, no en una prueba unitaria.

use std::io;

/// Un fallo al inyectar.
#[derive(Debug, thiserror::Error)]
pub enum InyeccionError {
    /// `process_vm_writev` fallo (tipicamente falta de privilegios sobre el
    /// objetivo, o la region ya no es valida).
    #[error("process_vm_writev: {0}")]
    Io(#[from] io::Error),
    /// No se escribieron todos los bytes del token.
    #[error("escritura parcial: {escritos} de {pedidos} bytes")]
    Parcial {
        /// Bytes escritos.
        escritos: usize,
        /// Bytes que se pidio escribir.
        pedidos: usize,
    },
}

/// Escribe `datos` en la direccion `destino` del espacio de memoria del proceso
/// `pid`. Es la colocacion del honey-token en la region que planifico
/// [`crate::memtoken`].
pub fn escribir_en(pid: i32, destino: u64, datos: &[u8]) -> Result<(), InyeccionError> {
    let local = libc::iovec {
        iov_base: datos.as_ptr() as *mut libc::c_void,
        iov_len: datos.len(),
    };
    let remoto = libc::iovec {
        iov_base: destino as *mut libc::c_void,
        iov_len: datos.len(),
    };
    // SAFETY: process_vm_writev es la syscall; `local` apunta a `datos` (valido
    // durante la llamada) y `remoto` describe la direccion destino ya planificada
    // sobre una region escribible del proceso `pid`. Se comprueba el retorno.
    let n = unsafe { libc::process_vm_writev(pid, &local, 1, &remoto, 1, 0) };
    if n < 0 {
        return Err(InyeccionError::Io(io::Error::last_os_error()));
    }
    if n as usize != datos.len() {
        return Err(InyeccionError::Parcial {
            escritos: n as usize,
            pedidos: datos.len(),
        });
    }
    Ok(())
}
