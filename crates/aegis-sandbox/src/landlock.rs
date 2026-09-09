//! Restriccion de acceso al sistema de ficheros y a la red con Landlock.
//!
//! # Que aporta sobre seccomp
//!
//! seccomp filtra por NUMERO de llamada; no puede mirar una ruta, porque el
//! argumento es un puntero a memoria del proceso y el filtro corre en el kernel
//! sin poder desreferenciarlo con seguridad —y aunque pudiera, entre la
//! comprobacion y el uso la ruta puede cambiar—. Landlock resuelve exactamente
//! eso: aplica la restriccion en el VFS, sobre el objeto ya resuelto, asi que no
//! hay carrera posible entre comprobar y usar.
//!
//! Sin Landlock, "que este binario no lea `/etc/shadow`" no es expresable; con
//! el, es una regla.
//!
//! # Negociacion de version
//!
//! Landlock evoluciona por versiones de ABI y cada una anade derechos nuevos.
//! Pedir un derecho que el kernel no conoce devuelve `EINVAL` y **el sandbox no
//! se aplica en absoluto**, que es el peor resultado posible: el proceso acaba
//! sin restringir creyendo que lo esta. Por eso [`Abi::supported_fs`] recorta la
//! mascara a lo que el kernel de esta maquina admite, y lo que no se puede
//! aplicar se reporta.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{FromRawFd, OwnedFd, RawFd};
use std::path::Path;

use crate::error::SandboxError;

// Los numeros de estas llamadas son los mismos en x86-64 y aarch64: se anadieron
// cuando el proceso de asignacion ya era comun a todas las arquitecturas.
const NR_CREATE_RULESET: libc::c_long = 444;
const NR_ADD_RULE: libc::c_long = 445;
const NR_RESTRICT_SELF: libc::c_long = 446;

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;
const LANDLOCK_RULE_PATH_BENEATH: libc::c_ulong = 1;
const LANDLOCK_RULE_NET_PORT: libc::c_ulong = 2;

// --- Derechos sobre el sistema de ficheros ---------------------------------
/// Ejecutar un fichero.
pub const FS_EXECUTE: u64 = 1 << 0;
/// Abrir un fichero para escritura.
pub const FS_WRITE_FILE: u64 = 1 << 1;
/// Abrir un fichero para lectura.
pub const FS_READ_FILE: u64 = 1 << 2;
/// Listar un directorio.
pub const FS_READ_DIR: u64 = 1 << 3;
/// Borrar un directorio.
pub const FS_REMOVE_DIR: u64 = 1 << 4;
/// Borrar un fichero.
pub const FS_REMOVE_FILE: u64 = 1 << 5;
/// Crear un dispositivo de caracteres.
pub const FS_MAKE_CHAR: u64 = 1 << 6;
/// Crear un directorio.
pub const FS_MAKE_DIR: u64 = 1 << 7;
/// Crear un fichero regular.
pub const FS_MAKE_REG: u64 = 1 << 8;
/// Crear un socket de dominio Unix.
pub const FS_MAKE_SOCK: u64 = 1 << 9;
/// Crear una tuberia con nombre.
pub const FS_MAKE_FIFO: u64 = 1 << 10;
/// Crear un dispositivo de bloques.
pub const FS_MAKE_BLOCK: u64 = 1 << 11;
/// Crear un enlace simbolico.
pub const FS_MAKE_SYM: u64 = 1 << 12;
/// Reubicar ficheros entre directorios (ABI 2).
pub const FS_REFER: u64 = 1 << 13;
/// Truncar un fichero (ABI 3).
pub const FS_TRUNCATE: u64 = 1 << 14;
/// `ioctl` sobre ficheros de dispositivo (ABI 5).
pub const FS_IOCTL_DEV: u64 = 1 << 15;

// --- Derechos sobre la red (ABI 4) -----------------------------------------
/// Escuchar en un puerto TCP.
pub const NET_BIND_TCP: u64 = 1 << 0;
/// Conectar a un puerto TCP.
pub const NET_CONNECT_TCP: u64 = 1 << 1;

/// Derechos de solo lectura y ejecucion.
pub const LECTURA: u64 = FS_EXECUTE | FS_READ_FILE | FS_READ_DIR;

/// Derechos de escritura, incluida la creacion y el borrado.
pub const ESCRITURA: u64 = FS_WRITE_FILE
    | FS_REMOVE_DIR
    | FS_REMOVE_FILE
    | FS_MAKE_CHAR
    | FS_MAKE_DIR
    | FS_MAKE_REG
    | FS_MAKE_SOCK
    | FS_MAKE_FIFO
    | FS_MAKE_BLOCK
    | FS_MAKE_SYM
    | FS_REFER
    | FS_TRUNCATE;

/// Version de ABI de Landlock que ofrece este kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Abi(pub u32);

impl Abi {
    /// Consulta la version al kernel.
    ///
    /// Devuelve `None` si Landlock no esta disponible, que en un kernel sin
    /// `CONFIG_SECURITY_LANDLOCK` se manifiesta como `ENOSYS`.
    pub fn detect() -> Option<Abi> {
        // SAFETY: con el indicador de version, la llamada no lee el puntero de
        // atributos; solo devuelve el numero de ABI.
        let v = unsafe {
            libc::syscall(
                NR_CREATE_RULESET,
                std::ptr::null::<u8>(),
                0usize,
                LANDLOCK_CREATE_RULESET_VERSION as libc::c_ulong,
            )
        };
        if v <= 0 {
            None
        } else {
            Some(Abi(v as u32))
        }
    }

    /// Mascara de derechos de fichero que esta ABI conoce.
    ///
    /// Pedir un bit que el kernel no conoce hace fallar la creacion entera del
    /// conjunto de reglas, y el proceso se quedaria SIN restringir.
    pub fn supported_fs(self) -> u64 {
        let mut m = FS_EXECUTE
            | FS_WRITE_FILE
            | FS_READ_FILE
            | FS_READ_DIR
            | FS_REMOVE_DIR
            | FS_REMOVE_FILE
            | FS_MAKE_CHAR
            | FS_MAKE_DIR
            | FS_MAKE_REG
            | FS_MAKE_SOCK
            | FS_MAKE_FIFO
            | FS_MAKE_BLOCK
            | FS_MAKE_SYM;
        if self.0 >= 2 {
            m |= FS_REFER;
        }
        if self.0 >= 3 {
            m |= FS_TRUNCATE;
        }
        if self.0 >= 5 {
            m |= FS_IOCTL_DEV;
        }
        m
    }

    /// Indica si esta ABI puede restringir la red.
    pub fn supports_net(self) -> bool {
        self.0 >= 4
    }

    /// Tamano de `struct landlock_ruleset_attr` que este kernel espera.
    ///
    /// El kernel valida el tamano contra la version que implementa: pasar la
    /// estructura completa a un kernel antiguo devuelve `E2BIG`.
    fn attr_size(self) -> usize {
        if self.0 >= 6 {
            24 // + scoped
        } else if self.0 >= 4 {
            16 // + handled_access_net
        } else {
            8 // solo handled_access_fs
        }
    }
}

/// Espejo de `struct landlock_ruleset_attr`.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

/// Espejo de `struct landlock_path_beneath_attr`, que es EMPAQUETADA.
///
/// Sin `packed`, el compilador anade cuatro bytes de relleno tras `parent_fd` y
/// el kernel recibe una estructura de 16 bytes donde espera 12: `EINVAL`.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// Espejo de `struct landlock_net_port_attr`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct NetPortAttr {
    allowed_access: u64,
    port: u64,
}

/// Un conjunto de reglas de Landlock a medio construir.
///
/// Se construye ANTES de bifurcar y se aplica despues: el descriptor sobrevive
/// al `fork`, y asi el hijo solo tiene que hacer una llamada al sistema, sin
/// reservar memoria ni abrir ficheros en un contexto donde no es seguro.
#[derive(Debug)]
pub struct Ruleset {
    fd: OwnedFd,
    abi: Abi,
}

impl Ruleset {
    /// Crea un conjunto que gobierna los derechos indicados.
    ///
    /// Todo derecho gobernado queda PROHIBIDO salvo donde una regla lo permita
    /// explicitamente: Landlock es una lista blanca, que es lo que se quiere
    /// para un binario en el que no se confia.
    pub fn new(abi: Abi, handled_fs: u64, handled_net: u64) -> Result<Ruleset, SandboxError> {
        let attr = RulesetAttr {
            handled_access_fs: handled_fs & abi.supported_fs(),
            handled_access_net: if abi.supports_net() { handled_net } else { 0 },
            scoped: 0,
        };
        // SAFETY: se pasa el tamano que corresponde a la ABI detectada, y la
        // estructura tiene al menos esos bytes.
        let fd = unsafe {
            libc::syscall(
                NR_CREATE_RULESET,
                &attr as *const RulesetAttr,
                abi.attr_size(),
                0usize,
            )
        };
        if fd < 0 {
            return Err(SandboxError::Landlock {
                op: "landlock_create_ruleset",
                source: std::io::Error::last_os_error(),
            });
        }
        // SAFETY: `fd` es un descriptor recien creado y valido del que este
        // tipo pasa a ser el unico duenno.
        Ok(Ruleset {
            fd: unsafe { OwnedFd::from_raw_fd(fd as RawFd) },
            abi,
        })
    }

    /// Version de ABI con la que se creo.
    pub fn abi(&self) -> Abi {
        self.abi
    }

    /// Descriptor en crudo, para aplicarlo tras un `fork`.
    pub fn raw_fd(&self) -> RawFd {
        use std::os::unix::io::AsRawFd;
        self.fd.as_raw_fd()
    }

    /// Permite `derechos` sobre `ruta` y todo lo que cuelgue de ella.
    pub fn allow_path(&self, ruta: &Path, derechos: u64) -> Result<(), SandboxError> {
        let c = CString::new(ruta.as_os_str().as_bytes()).map_err(|_| SandboxError::Path {
            path: ruta.display().to_string(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidInput, "ruta con NUL"),
        })?;
        // O_PATH abre el objeto SIN abrirlo para E/S: no dispara los permisos
        // de lectura ni bloquea nada, que es justo lo que hace falta para
        // nombrar un directorio en una regla.
        // SAFETY: `c` vive durante la llamada; `open` no toca mas memoria.
        let dirfd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if dirfd < 0 {
            return Err(SandboxError::Path {
                path: ruta.display().to_string(),
                source: std::io::Error::last_os_error(),
            });
        }
        // SAFETY: descriptor recien abierto y valido.
        let guard = unsafe { OwnedFd::from_raw_fd(dirfd) };

        let attr = PathBeneathAttr {
            allowed_access: derechos & self.abi.supported_fs(),
            parent_fd: dirfd,
        };
        // SAFETY: la estructura esta empaquetada y su tamano es el que espera
        // el kernel; `guard` mantiene vivo el descriptor durante la llamada.
        let r = unsafe {
            libc::syscall(
                NR_ADD_RULE,
                self.raw_fd(),
                LANDLOCK_RULE_PATH_BENEATH,
                &attr as *const PathBeneathAttr,
                0usize,
            )
        };
        drop(guard);
        if r != 0 {
            return Err(SandboxError::Landlock {
                op: "landlock_add_rule(PATH_BENEATH)",
                source: std::io::Error::last_os_error(),
            });
        }
        Ok(())
    }

    /// Permite un puerto TCP concreto. Requiere ABI 4.
    pub fn allow_port(&self, puerto: u16, derechos: u64) -> Result<(), SandboxError> {
        if !self.abi.supports_net() {
            return Err(SandboxError::LandlockAbiTooOld {
                actual: self.abi.0,
                needs: "restriccion de red",
                required: 4,
            });
        }
        let attr = NetPortAttr {
            allowed_access: derechos,
            port: puerto as u64,
        };
        // SAFETY: estructura de tamano fijo conocido por el kernel desde ABI 4.
        let r = unsafe {
            libc::syscall(
                NR_ADD_RULE,
                self.raw_fd(),
                LANDLOCK_RULE_NET_PORT,
                &attr as *const NetPortAttr,
                0usize,
            )
        };
        if r != 0 {
            return Err(SandboxError::Landlock {
                op: "landlock_add_rule(NET_PORT)",
                source: std::io::Error::last_os_error(),
            });
        }
        Ok(())
    }
}

/// Aplica un conjunto de reglas al proceso actual. **Irreversible.**
///
/// # Seguridad en contexto de senal
///
/// Es una sola llamada al sistema sobre un descriptor ya abierto: se puede
/// llamar entre `fork` y `exec`.
///
/// Exige `PR_SET_NO_NEW_PRIVS`, que [`crate::seccomp::install`] ya deja puesto;
/// si se aplica Landlock sin seccomp, hay que ponerlo aqui.
pub fn restrict_self(fd: RawFd) -> Result<(), SandboxError> {
    // SAFETY: `prctl` con esta opcion no toca memoria del proceso.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(SandboxError::NoNewPrivs(std::io::Error::last_os_error()));
    }
    // SAFETY: `fd` es un conjunto de reglas valido; la llamada no lee memoria
    // del proceso.
    let r = unsafe { libc::syscall(NR_RESTRICT_SELF, fd, 0usize) };
    if r != 0 {
        return Err(SandboxError::Landlock {
            op: "landlock_restrict_self",
            source: std::io::Error::last_os_error(),
        });
    }
    Ok(())
}

/// Indica si este kernel admite Landlock.
pub fn available() -> bool {
    Abi::detect().is_some()
}
