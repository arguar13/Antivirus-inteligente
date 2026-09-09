//! Modelo del espacio de direcciones de un proceso e interfaz para leerlo.
//!
//! El modelo —region, permisos, clase— es el mismo en los tres sistemas: un
//! rango, unos permisos y un fichero detras o nada. Lo que cambia es como se
//! obtiene: `/proc/<pid>/maps` y `process_vm_readv` en Linux, `VirtualQueryEx`
//! y `ReadProcessMemory` en Windows, `mach_vm_region` y `mach_vm_read` en
//! macOS. Esa frontera es la que separa este modulo del backend, y es la razon
//! de que el analisis de inyeccion y de exploits se escriba una sola vez.
//!
//! # Que NO se lee
//!
//! Leer todo el espacio de direcciones de un proceso es a la vez inviable y
//! contraproducente:
//!
//! - `[vvar]`, `[vsyscall]` y las asignaciones de dispositivo devuelven `EIO`
//!   o cuelgan la lectura; hay que saltarlas por nombre.
//! - Las regiones respaldadas por fichero y no escribibles son una copia de
//!   algo que ya esta en disco: escanearlas en cada proceso significa releer
//!   `libc` cientos de veces por barrido.
//! - Una region de 40 GiB de un proceso de base de datos agota la memoria del
//!   agente antes de aportar nada.
//!
//! Lo que si importa es la memoria ANONIMA: es donde vive el codigo que no
//! tiene fichero detras, los buffers descifrados y las cargas utiles
//! inyectadas.

use crate::error::ScalError;
use crate::platform::Platform;

/// Permisos de una region de memoria.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Perms {
    /// Lectura.
    pub read: bool,
    /// Escritura.
    pub write: bool,
    /// Ejecucion.
    pub exec: bool,
    /// Privada (copy-on-write) frente a compartida.
    pub private: bool,
}

impl Perms {
    /// Analiza el campo de permisos de `/proc/<pid>/maps` (`rwxp`).
    pub fn parse(s: &str) -> Perms {
        let b = s.as_bytes();
        Perms {
            read: b.first() == Some(&b'r'),
            write: b.get(1) == Some(&b'w'),
            exec: b.get(2) == Some(&b'x'),
            private: b.get(3) == Some(&b'p'),
        }
    }

    /// Lectura, escritura y ejecucion simultaneas.
    ///
    /// Casi ningun compilador produce esto. Lo producen los packers, los JIT y
    /// el shellcode que se descomprime a si mismo.
    pub fn is_rwx(self) -> bool {
        self.read && self.write && self.exec
    }
}

/// Clasificacion de una region segun su origen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionClass {
    /// Memoria anonima y ejecutable: codigo sin fichero que lo respalde.
    ///
    /// Es la senal de mayor valor del modulo. El codigo legitimo se ejecuta
    /// desde imagenes mapeadas; aqui solo aparecen los JIT y el shellcode.
    AnonymousExec,
    /// Memoria anonima escribible: monton, pila, buffers.
    AnonymousData,
    /// Region respaldada por un fichero y ejecutable.
    FileExec,
    /// Region respaldada por un fichero, sin ejecucion.
    FileData,
    /// Region especial del kernel: `[vvar]`, `[vsyscall]`, `[vdso]`.
    Kernel,
    /// Asignacion de dispositivo.
    Device,
}

/// Una region del espacio de direcciones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryRegion {
    /// Direccion inicial.
    pub start: u64,
    /// Direccion final, exclusiva.
    pub end: u64,
    /// Permisos.
    pub perms: Perms,
    /// Desplazamiento dentro del fichero respaldado.
    pub offset: u64,
    /// Inodo del fichero respaldado, 0 si es anonima.
    pub inode: u64,
    /// Ruta del fichero o etiqueta especial (`[heap]`, `[stack]`, ...).
    pub path: Option<String>,
}

impl MemoryRegion {
    /// Tamano en bytes.
    pub fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Indica si la region esta vacia.
    pub fn is_empty(&self) -> bool {
        self.end <= self.start
    }

    /// Clasifica la region.
    pub fn class(&self) -> RegionClass {
        if let Some(p) = &self.path {
            if p.starts_with('[') {
                // [heap] y [stack] son anonimas pese a llevar etiqueta: no hay
                // fichero detras, solo un nombre que pone el kernel.
                return match p.as_str() {
                    "[heap]" | "[stack]" => {
                        if self.perms.exec {
                            RegionClass::AnonymousExec
                        } else {
                            RegionClass::AnonymousData
                        }
                    }
                    _ => RegionClass::Kernel,
                };
            }
            if p.starts_with("/dev/") {
                return RegionClass::Device;
            }
            return if self.perms.exec {
                RegionClass::FileExec
            } else {
                RegionClass::FileData
            };
        }
        if self.perms.exec {
            RegionClass::AnonymousExec
        } else {
            RegionClass::AnonymousData
        }
    }

    /// Indica si es seguro intentar leerla.
    ///
    /// `[vvar]` y `[vsyscall]` no se pueden leer con `process_vm_readv`; las
    /// asignaciones de dispositivo pueden bloquear la llamada indefinidamente
    /// o tener efectos secundarios en el hardware.
    pub fn is_readable(&self) -> bool {
        if !self.perms.read {
            return false;
        }
        !matches!(self.class(), RegionClass::Kernel | RegionClass::Device)
    }
}

/// Lector del espacio de direcciones de otro proceso.
///
/// Todas las operaciones son SIN parar al objetivo. Un `ptrace`-stop, o su
/// equivalente en las otras plataformas, es observable por el propio proceso
/// —que es como el malware detecta que lo estan mirando— y ademas congela algo
/// que puede ser perfectamente legitimo.
pub trait MemoryInspector {
    /// Plataforma que implementa este lector.
    fn platform(&self) -> Platform;

    /// Enumera las regiones del espacio de direcciones de `pid`.
    fn regions(&self, pid: u32) -> Result<Vec<MemoryRegion>, ScalError>;

    /// Lee `len` bytes desde `addr` en el espacio de direcciones de `pid`.
    ///
    /// Puede devolver MENOS bytes de los pedidos si la region se redujo entre
    /// enumerarla y leerla; eso es normal, no un error.
    fn read(&self, pid: u32, addr: u64, len: usize) -> Result<Vec<u8>, ScalError>;

    /// Regiones ejecutables sin fichero detras.
    ///
    /// Es la consulta de mayor valor de deteccion del rasgo, y por eso esta en
    /// la interfaz en vez de dejarla al llamante: el codigo legitimo se ejecuta
    /// desde imagenes mapeadas, y lo que aparece aqui son los JIT y el codigo
    /// inyectado.
    fn executable_anonymous(&self, pid: u32) -> Result<Vec<MemoryRegion>, ScalError> {
        Ok(self
            .regions(pid)?
            .into_iter()
            .filter(|r| r.class() == RegionClass::AnonymousExec)
            .collect())
    }
}
