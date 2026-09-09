//! Lectura de memoria de procesos vivos en Linux.
//!
//! # Como se lee
//!
//! Se usa `process_vm_readv` y no `/proc/<pid>/mem`. Ambos funcionan, pero el
//! primero evita abrir y posicionar un descriptor sobre un fichero disperso de
//! 128 TiB, hace la copia en una sola llamada y no deja un descriptor abierto
//! contra un proceso que puede morir a mitad. La llamada falla limpiamente con
//! `ESRCH` si el proceso desaparece, que es la condicion normal, no un error.

use std::path::Path;

use crate::error::ScalError;
use crate::memory::{MemoryInspector, MemoryRegion, Perms};
use crate::platform::Platform;

/// Analiza el contenido de `/proc/<pid>/maps`.
///
/// Formato por linea:
/// `7f8b4c000000-7f8b4c021000 r-xp 00000000 08:01 1234  /usr/lib/libc.so.6`
///
/// La ruta puede contener espacios, asi que se toma como el resto de la linea
/// desde el sexto campo y no se trocea.
pub fn parse_maps(texto: &str) -> Vec<MemoryRegion> {
    let mut salida = Vec::new();
    for linea in texto.lines() {
        let mut it = linea
            .splitn(6, char::is_whitespace)
            .filter(|s| !s.is_empty());
        let Some(rango) = it.next() else { continue };
        let Some((ini, fin)) = rango.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (u64::from_str_radix(ini, 16), u64::from_str_radix(fin, 16))
        else {
            continue;
        };
        let perms = Perms::parse(it.next().unwrap_or(""));
        let offset = it
            .next()
            .and_then(|s| u64::from_str_radix(s, 16).ok())
            .unwrap_or(0);
        let _dev = it.next();
        let inode = it.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
        let path = it
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);

        salida.push(MemoryRegion {
            start,
            end,
            perms,
            offset,
            inode,
            path,
        });
    }
    salida
}

/// Enumera las regiones de un proceso.
pub fn regions_of(pid: i32) -> Result<Vec<MemoryRegion>, std::io::Error> {
    let ruta = format!("/proc/{pid}/maps");
    let texto = std::fs::read_to_string(&ruta)?;
    Ok(parse_maps(&texto))
}

/// Error al leer memoria ajena.
#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    /// El proceso ya no existe.
    #[error("el proceso {0} ya no existe")]
    NoSuchProcess(i32),
    /// Sin permisos para leer su memoria.
    #[error("sin permisos para leer la memoria del proceso {0}; hace falta CAP_SYS_PTRACE")]
    PermissionDenied(i32),
    /// La region no es legible en este momento.
    ///
    /// Ocurre de forma normal: el proceso puede desasignar una region entre
    /// enumerarla y leerla.
    #[error("la region {start:#x}..{end:#x} del proceso {pid} no se pudo leer: {errno}")]
    RegionUnreadable {
        /// PID.
        pid: i32,
        /// Inicio de la region.
        start: u64,
        /// Final de la region.
        end: u64,
        /// Codigo de error.
        errno: i32,
    },
}

/// Lee `len` bytes desde `addr` en el espacio de direcciones de `pid`.
///
/// Devuelve los bytes efectivamente leidos, que pueden ser menos de los
/// pedidos si la region se redujo entre la enumeracion y la lectura.
pub fn read_memory(pid: i32, addr: u64, len: usize) -> Result<Vec<u8>, ReadError> {
    if len == 0 {
        return Ok(Vec::new());
    }
    let mut buf = vec![0u8; len];

    let local = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: len,
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: len,
    };

    // SAFETY: `local` apunta a `buf`, que esta vivo y tiene `len` bytes. La
    // syscall solo escribe en el buffer local; `remote` es una direccion del
    // OTRO proceso y el kernel la valida por su cuenta, devolviendo EFAULT si
    // no es legible en lugar de tocar memoria de este proceso.
    let leidos = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };

    if leidos < 0 {
        let e = std::io::Error::last_os_error();
        return Err(match e.raw_os_error() {
            Some(libc::ESRCH) => ReadError::NoSuchProcess(pid),
            Some(libc::EPERM) => ReadError::PermissionDenied(pid),
            otro => ReadError::RegionUnreadable {
                pid,
                start: addr,
                end: addr + len as u64,
                errno: otro.unwrap_or(-1),
            },
        });
    }

    buf.truncate(leidos as usize);
    Ok(buf)
}

/// Indica si un PID corresponde a un hilo de kernel, que no tiene memoria de
/// usuario que escanear.
pub fn is_kernel_thread(pid: i32) -> bool {
    // Un hilo de kernel tiene `/proc/<pid>/maps` vacio. Comprobarlo asi evita
    // depender de leer `stat` y funciona aunque falte permiso sobre `exe`.
    match std::fs::metadata(Path::new(&format!("/proc/{pid}/maps"))) {
        Ok(_) => std::fs::read_to_string(format!("/proc/{pid}/maps"))
            .map(|s| s.trim().is_empty())
            .unwrap_or(false),
        Err(_) => false,
    }
}

/// Lector de memoria de Linux, sobre `procfs` y `process_vm_readv`.
///
/// No guarda estado: cada consulta relee el mapa. Cachear el mapa de un proceso
/// vivo seria mas rapido y estaria mal, porque una region inyectada aparece
/// justo entre dos lecturas y es exactamente la que hay que ver.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcMemoryInspector;

impl ProcMemoryInspector {
    /// Crea el lector.
    pub const fn new() -> ProcMemoryInspector {
        ProcMemoryInspector
    }
}

impl MemoryInspector for ProcMemoryInspector {
    fn platform(&self) -> Platform {
        Platform::Linux
    }

    fn regions(&self, pid: u32) -> Result<Vec<MemoryRegion>, ScalError> {
        match regions_of(pid as i32) {
            Ok(r) => Ok(r),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(ScalError::NoSuchProcess(pid))
            }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                Err(ScalError::PermissionDenied {
                    op: "leer /proc/<pid>/maps",
                    needs: "CAP_SYS_PTRACE o ser el mismo usuario",
                })
            }
            Err(source) => Err(ScalError::Os {
                op: "leer /proc/<pid>/maps",
                source,
            }),
        }
    }

    fn read(&self, pid: u32, addr: u64, len: usize) -> Result<Vec<u8>, ScalError> {
        match read_memory(pid as i32, addr, len) {
            Ok(b) => Ok(b),
            Err(ReadError::NoSuchProcess(_)) => Err(ScalError::NoSuchProcess(pid)),
            Err(ReadError::PermissionDenied(_)) => Err(ScalError::PermissionDenied {
                op: "process_vm_readv",
                needs: "CAP_SYS_PTRACE",
            }),
            Err(ReadError::RegionUnreadable { errno, .. }) => Err(ScalError::Os {
                op: "process_vm_readv",
                source: std::io::Error::from_raw_os_error(errno),
            }),
        }
    }
}

/// Comprobacion de que `Perms` cubre lo que `procfs` puede emitir.
///
/// `procfs` escribe siempre cuatro caracteres, y el cuarto solo puede ser `p`
/// (privada) o `s` (compartida). Si alguna vez apareciera un quinto estado, el
/// analizador lo tomaria como "no privada" en silencio; esta prueba deja
/// constancia de la suposicion.
#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn los_permisos_de_procfs_se_analizan_completos() {
        assert_eq!(
            Perms::parse("rwxp"),
            Perms {
                read: true,
                write: true,
                exec: true,
                private: true
            }
        );
        assert!(!Perms::parse("rw-s").private);
        assert_eq!(Perms::parse(""), Perms::default());
    }
}
