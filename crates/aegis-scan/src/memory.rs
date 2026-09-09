//! Lectura de memoria de procesos vivos.
//!
//! Escanear ficheros solo ve lo que el atacante dejo en disco. El malware
//! moderno no deja nada: se descomprime en memoria, se inyecta en un proceso
//! legitimo o se ejecuta desde un buffer que nunca toco el sistema de ficheros.
//! Este modulo es lo que permite mirar ahi.
//!
//! # Como se lee
//!
//! Se usa `process_vm_readv` y no `/proc/<pid>/mem`. Ambos funcionan, pero el
//! primero evita abrir y posicionar un descriptor sobre un fichero disperso de
//! 128 TiB, hace la copia en una sola llamada y no deja un descriptor abierto
//! contra un proceso que puede morir a mitad. La llamada falla limpiamente con
//! `ESRCH` si el proceso desaparece, que es la condicion normal, no un error.
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

use std::path::Path;

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

/// Politica de barrido de memoria.
#[derive(Debug, Clone, Copy)]
pub struct MemoryScanPolicy {
    /// Tamano maximo de una region que se acepta escanear.
    ///
    /// Una region de decenas de gigabytes de un proceso de base de datos agota
    /// la memoria del agente sin aportar deteccion.
    pub max_region_bytes: u64,
    /// Presupuesto total por proceso.
    pub max_total_bytes: u64,
    /// Tamano de cada lectura.
    pub chunk_bytes: usize,
    /// Solape entre trozos consecutivos.
    ///
    /// Sin solape, un patron que cruce la frontera de dos trozos no se detecta
    /// nunca. Es el fallo mas facil de cometer en un escaner por trozos y el
    /// mas dificil de notar, porque solo se manifiesta con ciertos tamanos.
    pub overlap_bytes: usize,
    /// Escanear tambien las regiones respaldadas por fichero.
    ///
    /// Desactivado por defecto: son una copia de algo que ya esta en disco, y
    /// activarlo significa releer `libc` una vez por proceso en cada barrido.
    pub include_file_backed: bool,
}

impl Default for MemoryScanPolicy {
    fn default() -> Self {
        Self {
            max_region_bytes: 256 * 1024 * 1024,
            max_total_bytes: 1024 * 1024 * 1024,
            chunk_bytes: 8 * 1024 * 1024,
            // 64 KiB cubre con holgura cualquier patron YARA razonable.
            overlap_bytes: 64 * 1024,
            include_file_backed: false,
        }
    }
}

impl MemoryScanPolicy {
    /// Indica si una region entra en el barrido segun esta politica.
    pub fn accepts(&self, r: &MemoryRegion) -> bool {
        if !r.is_readable() || r.is_empty() {
            return false;
        }
        if r.len() > self.max_region_bytes {
            return false;
        }
        match r.class() {
            RegionClass::AnonymousExec | RegionClass::AnonymousData => true,
            RegionClass::FileExec | RegionClass::FileData => self.include_file_backed,
            RegionClass::Kernel | RegionClass::Device => false,
        }
    }
}

/// Ordena las regiones por valor de deteccion, de mayor a menor.
///
/// El barrido tiene un presupuesto: si se agota, es preferible haberlo gastado
/// en la memoria anonima ejecutable, donde vive el codigo sin fichero, que en
/// el monton de un navegador.
pub fn prioritize(regiones: &mut [MemoryRegion]) {
    regiones.sort_by_key(|r| match r.class() {
        RegionClass::AnonymousExec if r.perms.is_rwx() => 0,
        RegionClass::AnonymousExec => 1,
        RegionClass::AnonymousData if r.perms.write => 2,
        RegionClass::AnonymousData => 3,
        RegionClass::FileExec => 4,
        RegionClass::FileData => 5,
        RegionClass::Kernel | RegionClass::Device => 6,
    });
}

/// Calcula los trozos con solape que cubren `[start, end)`.
///
/// Devuelve pares `(direccion, longitud)`. Dos propiedades que el llamante
/// necesita y que se verifican en las pruebas:
///
/// 1. **Cobertura completa**: todo byte del rango aparece en algun trozo.
/// 2. **Solape efectivo**: dos trozos consecutivos comparten `overlap` bytes,
///    de modo que un patron a caballo entre ambos aparece entero en al menos
///    uno.
///
/// La segunda es el fallo mas facil de cometer en un escaner por trozos y el
/// mas dificil de notar: solo se manifiesta con ciertas combinaciones de tamano
/// de patron, tamano de trozo y posicion, y cuando lo hace el escaner
/// simplemente no encuentra algo que estaba ahi.
pub fn chunk_ranges(start: u64, end: u64, chunk: usize, overlap: usize) -> Vec<(u64, usize)> {
    let mut salida = Vec::new();
    if end <= start || chunk == 0 {
        return salida;
    }
    // El solape se acota a la MITAD del trozo, no a `chunk - 1`.
    //
    // Con el limite ingenuo, una politica mal configurada (solape 500 sobre
    // trozos de 100) hace que el cursor avance un solo byte por lectura: el
    // bucle termina, pero un barrido de 100 MB pasaria a ser 100 millones de
    // lecturas y contra un proceso real seria indistinguible de un cuelgue.
    //
    // Acotar a la mitad garantiza que el avance nunca baja de `chunk / 2`, con
    // lo que el numero de trozos queda acotado por `2 * rango / chunk` sea cual
    // sea el solape pedido. Y es lo semanticamente correcto: si hace falta un
    // solape mayor que medio trozo, el trozo es demasiado pequeno para los
    // patrones que se buscan, y la respuesta es no arrastrarse.
    let paso = chunk as u64;
    let solape = (overlap as u64).min(paso / 2).min(paso.saturating_sub(1));

    let mut pos = start;
    loop {
        let restante = end - pos;
        let len = restante.min(paso);
        salida.push((pos, len as usize));
        if len >= restante {
            break;
        }
        pos += len - solape;
    }
    salida
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
