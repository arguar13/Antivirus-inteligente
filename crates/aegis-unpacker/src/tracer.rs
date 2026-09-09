//! Ejecucion controlada del binario y deteccion del OEP con `ptrace`.
//!
//! # La estrategia
//!
//! Un empaquetador arranca, descomprime o descifra el codigo real en una region
//! de memoria que crea al vuelo, y salta a el —el OEP—. No se puede saber donde
//! esta el OEP de antemano, asi que se observa el efecto: el proceso empieza a
//! ejecutar codigo en una region ejecutable que NO existia al arrancar.
//!
//! El bucle:
//!
//! 1. Lanza el binario con `PTRACE_TRACEME` y para en el primer `exec`.
//! 2. Toma el mapa de regiones ejecutables de arranque (`/proc/<pid>/maps`): las
//!    de confianza.
//! 3. Avanza de SYSCALL en syscall (`PTRACE_SYSCALL`), no instruccion a
//!    instruccion: recorrer un descompresor paso a paso serian millones de
//!    paradas. Intercepta `mmap`/`mprotect` que crean o promueven regiones a
//!    ejecutables y las anota como nuevas.
//! 4. En cada parada de syscall comprueba el puntero de instruccion. Cuando cae
//!    dentro de una region NUEVA, el codigo desempaquetado ya se esta
//!    ejecutando: es el OEP. Se congela ahi.
//!
//! # Por que "primera syscall desde el codigo nuevo" y no el salto exacto
//!
//! Atrapar la instruccion EXACTA del salto al OEP exigiria un breakpoint
//! hardware o ejecutar paso a paso, y ninguna de las dos escala a un
//! descompresor real. La primera syscall que el codigo desempaquetado ejecuta
//! —y todo payload hace alguna: pide memoria, abre un fichero, se conecta— cae
//! con el puntero de instruccion ya dentro de la region nueva, a poca distancia
//! del OEP. Para volcar y escanear con YARA, esa distancia es irrelevante: el
//! codigo real ya esta entero en memoria.
//!
//! # Contencion
//!
//! El binario se ejecuta bajo un sandbox de llamadas al sistema
//! ([`crate::confinamiento`]) que le corta la red, el control de otros procesos
//! y la superficie de kernel ANTES del primer `exec`. Desempaquetar es ejecutar
//! codigo posiblemente malicioso; hacerlo sin contencion seria detonar la
//! muestra.

use std::os::unix::process::CommandExt;
use std::process::Command;

use crate::error::UnpackError;
use crate::region::{MapaEjecutable, Rango};

/// Numero de syscall de `mmap` en x86-64.
#[cfg(target_arch = "x86_64")]
const SYS_MMAP: u64 = 9;
/// Numero de syscall de `mprotect` en x86-64.
#[cfg(target_arch = "x86_64")]
const SYS_MPROTECT: u64 = 10;
/// Numero de syscall de `mmap` en aarch64.
#[cfg(target_arch = "aarch64")]
const SYS_MMAP: u64 = 222;
/// Numero de syscall de `mprotect` en aarch64.
#[cfg(target_arch = "aarch64")]
const SYS_MPROTECT: u64 = 226;

/// `PROT_EXEC`.
const PROT_EXEC: u64 = 0x4;
/// `MAP_ANONYMOUS`: memoria sin fichero detras.
const MAP_ANONYMOUS: u64 = 0x20;

/// Configuracion del trazado.
#[derive(Debug, Clone)]
pub struct TraceConfig {
    /// Paradas de syscall maximas antes de rendirse.
    ///
    /// Acota el trabajo: un binario que no se autoextrae nunca alcanzaria el
    /// OEP, y el desempaquetador no puede quedarse ejecutandolo para siempre.
    pub max_paradas: u64,
    /// Si es cierto, se aplica el sandbox de llamadas al sistema antes del exec.
    pub confinar: bool,
}

impl Default for TraceConfig {
    fn default() -> Self {
        Self {
            max_paradas: 200_000,
            confinar: true,
        }
    }
}

/// Resultado de un desempaquetado con exito.
#[derive(Debug, Clone)]
pub struct OepAlcanzado {
    /// PID del proceso trazado (ya terminado al devolver esto).
    pub pid: i32,
    /// Region nueva donde se detecto la ejecucion del codigo desempaquetado.
    pub region: Rango,
    /// Puntero de instruccion en el momento de la deteccion.
    pub rip: u64,
    /// Todas las regiones ejecutables nuevas observadas.
    pub regiones_nuevas: Vec<Rango>,
    /// Paradas de syscall consumidas.
    pub paradas: u64,
}

/// Lanza `programa` bajo traza y devuelve el estado al alcanzar el OEP.
///
/// El volcado de la region no se hace aqui: este modulo solo LOCALIZA el codigo
/// desempaquetado. Leerlo es cosa de [`crate::dump`], que corre mientras el
/// proceso sigue detenido en el OEP.
pub fn ejecutar_hasta_oep(
    programa: &std::path::Path,
    args: &[String],
    config: &TraceConfig,
) -> Result<OepAlcanzado, UnpackError> {
    let mut cmd = Command::new(programa);
    cmd.args(args);

    // Antes del exec, en el hijo: reclamar el trazador y confinar.
    let confinar = config.confinar;
    // SAFETY: el cierre solo llama a funciones seguras en contexto posterior al
    // fork y anterior al exec: `ptrace(TRACEME)` y, si procede, la instalacion
    // del sandbox de llamadas, que no reserva memoria.
    unsafe {
        cmd.pre_exec(move || {
            // SAFETY: TRACEME no toca memoria; pide al kernel que este proceso
            // sea trazado por su padre.
            if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if confinar {
                crate::confinamiento::aplicar_pre_exec()
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
            }
            Ok(())
        });
    }

    let hijo = cmd.spawn().map_err(UnpackError::Spawn)?;
    let pid = hijo.id() as i32;
    // El objeto `Child` no debe recolectar al proceso: lo gestiona el trazador
    // con waitpid. Se filtra a proposito.
    std::mem::forget(hijo);

    match bucle_de_traza(pid, config) {
        Ok(oep) => {
            // EXITO: el proceso queda VIVO y DETENIDO en el OEP para que el
            // llamante pueda volcar su memoria. Es su responsabilidad llamar a
            // [`matar_proceso`] despues; [`crate::desempaquetar`] lo hace.
            Ok(oep)
        }
        Err(e) => {
            // En cualquier error, el proceso no puede quedar vivo: es codigo
            // posiblemente malicioso.
            matar_proceso(pid);
            Err(e)
        }
    }
}

/// Mata y recolecta un proceso trazado.
///
/// Se llama tras volcar su memoria. Un proceso trazado no muere solo al recibir
/// SIGKILL si esta detenido: hay que reanudarlo, pero SIGKILL no se puede
/// bloquear ni ignorar, asi que `kill` seguido de `waitpid` lo termina y lo
/// recolecta sin dejar un zombi.
pub fn matar_proceso(pid: i32) {
    // SAFETY: llamadas al sistema con un PID que este modulo creo.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        let mut st = 0;
        libc::waitpid(pid, &mut st, 0);
    }
}

/// El bucle de trazado propiamente dicho.
fn bucle_de_traza(pid: i32, config: &TraceConfig) -> Result<OepAlcanzado, UnpackError> {
    // Primera parada: el `exec` ya ocurrio y el proceso esta detenido.
    let mut st = 0;
    // SAFETY: se espera al hijo trazado recien creado.
    if unsafe { libc::waitpid(pid, &mut st, 0) } == -1 {
        return Err(UnpackError::Ptrace {
            op: "waitpid inicial",
            source: std::io::Error::last_os_error(),
        });
    }
    if libc_wifexited(st) {
        return Err(UnpackError::ProcesoTermino(Some(libc_wexitstatus(st))));
    }

    // Con TRACESYSGOOD, las paradas de syscall se distinguen (bit 0x80 en la
    // senal) de las senales de verdad. Sin esto no se puede separar un
    // `SIGTRAP` de syscall de uno real.
    ptrace(
        libc::PTRACE_SETOPTIONS,
        pid,
        0,
        libc::PTRACE_O_TRACESYSGOOD as libc::c_ulong,
    )?;

    // Mapa de regiones ejecutables de arranque, tomado ahora.
    let mut mapa = MapaEjecutable::con_arranque(regiones_ejecutables(pid));

    let mut en_entrada = true; // alterna entrada/salida de cada syscall
    let mut ultima_syscall = 0u64;
    let mut paradas = 0u64;

    loop {
        if paradas >= config.max_paradas {
            return Err(UnpackError::OepNoAlcanzado(paradas));
        }
        // Avanzar hasta la siguiente entrada/salida de syscall.
        ptrace(libc::PTRACE_SYSCALL, pid, 0, 0)?;
        // SAFETY: espera al hijo trazado.
        if unsafe { libc::waitpid(pid, &mut st, 0) } == -1 {
            return Err(UnpackError::Ptrace {
                op: "waitpid",
                source: std::io::Error::last_os_error(),
            });
        }
        if libc_wifexited(st) {
            return Err(UnpackError::ProcesoTermino(Some(libc_wexitstatus(st))));
        }
        if libc_wifsignaled(st) {
            return Err(UnpackError::ProcesoTermino(None));
        }
        // Solo interesan las paradas de syscall (SIGTRAP | 0x80). Una parada por
        // una senal REAL (un SIGSEGV del propio codigo, por ejemplo) se reinyecta
        // para que el proceso la reciba, en vez de tragarsela: tragarsela
        // cambiaria el comportamiento del binario que se analiza.
        if !es_parada_de_syscall(st) {
            let sig = (st >> 8) & 0xff;
            let reinyectar = if sig == libc::SIGTRAP {
                0
            } else {
                sig as libc::c_ulong
            };
            ptrace(libc::PTRACE_SYSCALL, pid, 0, reinyectar)?;
            // SAFETY: espera al hijo trazado.
            if unsafe { libc::waitpid(pid, &mut st, 0) } == -1 {
                return Err(UnpackError::Ptrace {
                    op: "waitpid tras senal",
                    source: std::io::Error::last_os_error(),
                });
            }
            if libc_wifexited(st) {
                return Err(UnpackError::ProcesoTermino(Some(libc_wexitstatus(st))));
            }
            continue;
        }
        paradas += 1;

        let regs = leer_registros(pid)?;
        let rip = regs.rip();

        if en_entrada {
            // Entrada de syscall: se anota cual es para inspeccionar su salida.
            ultima_syscall = regs.syscall_nr();
        } else {
            // Salida de syscall: si fue un mmap/mprotect que produjo una region
            // ejecutable, se registra como nueva.
            if let Some(r) = region_ejecutable_de(pid, ultima_syscall, &regs) {
                mapa.anadir_nueva(r);
            }
        }
        en_entrada = !en_entrada;

        // La comprobacion del OEP: ¿el puntero de instruccion cae en una region
        // NUEVA? Se hace en cada parada, entrada o salida, porque la primera
        // syscall del codigo desempaquetado puede pillarse en cualquiera de las
        // dos.
        if let Some(region) = mapa.region_nueva_de(rip) {
            return Ok(OepAlcanzado {
                pid,
                region,
                rip,
                regiones_nuevas: mapa.nuevas().to_vec(),
                paradas,
            });
        }
    }
}

/// Devuelve la region ejecutable ANONIMA que produjo una syscall, si la produjo.
///
/// El filtro de anonimato es lo que separa el codigo desempaquetado del ruido:
/// el enlazador dinamico mapea `libc` y las demas bibliotecas con `PROT_EXEC`,
/// pero desde FICHERO. El empaquetador despliega su codigo en memoria ANONIMA
/// —no hay fichero del que venga, lo genero el propio proceso—. Sin este filtro,
/// la primera syscall de `libc` se confunde con el OEP.
fn region_ejecutable_de(pid: i32, syscall: u64, regs: &Regs) -> Option<Rango> {
    match syscall {
        SYS_MMAP => {
            // mmap(addr, len, prot, flags, fd, offset).
            let prot = regs.arg(2);
            let flags = regs.arg(3);
            if prot & PROT_EXEC == 0 || flags & MAP_ANONYMOUS == 0 {
                return None;
            }
            let addr = regs.retorno();
            let len = regs.arg(1);
            // Un mmap fallido devuelve MAP_FAILED (-1 sin signo).
            if addr == u64::MAX || len == 0 {
                return None;
            }
            Some(Rango {
                inicio: addr,
                fin: addr.saturating_add(len),
            })
        }
        SYS_MPROTECT => {
            // mprotect(addr, len, prot). Interesa una promocion a ejecutable de
            // una region ANONIMA: el patron RW -> RX del empaquetador que
            // escribe su codigo y luego lo hace ejecutable. Una region con
            // fichero detras (una biblioteca ajustando permisos) no lo es.
            let prot = regs.arg(2);
            if prot & PROT_EXEC == 0 || regs.retorno() != 0 {
                return None;
            }
            let addr = regs.arg(0);
            let len = regs.arg(1);
            if !es_anonima(pid, addr) {
                return None;
            }
            Some(Rango {
                inicio: addr,
                fin: addr.saturating_add(len),
            })
        }
        _ => None,
    }
}

/// Indica si la region que contiene `addr` es anonima (sin fichero detras).
///
/// Se consulta `/proc/<pid>/maps` del proceso trazado, que esta detenido, asi
/// que el mapa no cambia bajo los pies de la lectura.
fn es_anonima(pid: i32, addr: u64) -> bool {
    let Ok(regiones) = aegis_scal::linux::memory::regions_of(pid) else {
        return false;
    };
    regiones
        .iter()
        .find(|r| addr >= r.start && addr < r.end)
        .map(|r| r.path.is_none() || r.path.as_deref().is_some_and(|p| p.starts_with('[')))
        .unwrap_or(false)
}

/// Lee las regiones ejecutables actuales de `/proc/<pid>/maps`.
fn regiones_ejecutables(pid: i32) -> Vec<Rango> {
    let Ok(regiones) = aegis_scal::linux::memory::regions_of(pid) else {
        return Vec::new();
    };
    regiones
        .into_iter()
        .filter(|r| r.perms.exec)
        .map(|r| Rango {
            inicio: r.start,
            fin: r.end,
        })
        .collect()
}

// ------------------------------------------------------------------------
// Envoltorios finos de ptrace y de los registros, por arquitectura
// ------------------------------------------------------------------------

fn ptrace(
    req: libc::c_uint,
    pid: i32,
    addr: libc::c_ulong,
    data: libc::c_ulong,
) -> Result<libc::c_long, UnpackError> {
    // SAFETY: llamada directa a ptrace con un PID trazado por este proceso.
    let r = unsafe { libc::ptrace(req, pid, addr, data) };
    if r == -1 {
        // ptrace devuelve -1 tambien en exito para algunas peticiones, pero no
        // para las que usa este modulo (SETOPTIONS, SYSCALL, GETREGS con
        // PTRACE_GETREGS via addr/data son 0 en exito).
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(0) {
            return Err(UnpackError::Ptrace {
                op: "ptrace",
                source: e,
            });
        }
    }
    Ok(r)
}

/// Registros relevantes del proceso trazado, abstraidos de la arquitectura.
struct Regs {
    inner: libc::user_regs_struct,
}

#[cfg(target_arch = "x86_64")]
impl Regs {
    fn rip(&self) -> u64 {
        self.inner.rip
    }
    fn syscall_nr(&self) -> u64 {
        self.inner.orig_rax
    }
    fn retorno(&self) -> u64 {
        self.inner.rax
    }
    fn arg(&self, i: usize) -> u64 {
        match i {
            0 => self.inner.rdi,
            1 => self.inner.rsi,
            2 => self.inner.rdx,
            3 => self.inner.r10,
            4 => self.inner.r8,
            _ => self.inner.r9,
        }
    }
}

#[cfg(target_arch = "aarch64")]
impl Regs {
    fn rip(&self) -> u64 {
        self.inner.pc
    }
    fn syscall_nr(&self) -> u64 {
        self.inner.regs[8]
    }
    fn retorno(&self) -> u64 {
        self.inner.regs[0]
    }
    fn arg(&self, i: usize) -> u64 {
        self.inner.regs[i.min(5)]
    }
}

#[cfg(target_arch = "x86_64")]
fn leer_registros(pid: i32) -> Result<Regs, UnpackError> {
    let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    // SAFETY: PTRACE_GETREGS escribe en `regs`, que tiene el tamano correcto.
    let r = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGS,
            pid,
            0,
            &mut regs as *mut _ as libc::c_ulong,
        )
    };
    if r == -1 {
        return Err(UnpackError::Ptrace {
            op: "PTRACE_GETREGS",
            source: std::io::Error::last_os_error(),
        });
    }
    Ok(Regs { inner: regs })
}

#[cfg(target_arch = "aarch64")]
fn leer_registros(pid: i32) -> Result<Regs, UnpackError> {
    let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: &mut regs as *mut _ as *mut libc::c_void,
        iov_len: std::mem::size_of::<libc::user_regs_struct>(),
    };
    // NT_PRSTATUS = 1. En aarch64 los registros se leen con GETREGSET.
    const NT_PRSTATUS: libc::c_ulong = 1;
    // SAFETY: GETREGSET escribe en `regs` a traves de `iov`.
    let r = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGSET,
            pid,
            NT_PRSTATUS,
            &mut iov as *mut _ as libc::c_ulong,
        )
    };
    if r == -1 {
        return Err(UnpackError::Ptrace {
            op: "PTRACE_GETREGSET",
            source: std::io::Error::last_os_error(),
        });
    }
    Ok(Regs { inner: regs })
}

// --- Macros de estado de waitpid, que libc no expone como funciones ---

fn libc_wifexited(st: i32) -> bool {
    (st & 0x7f) == 0
}
fn libc_wexitstatus(st: i32) -> i32 {
    (st >> 8) & 0xff
}
/// Detenido por un trazador o una senal de parada. El valor 0x7f en el byte
/// bajo es el marcador de STOPPED, no de terminado: confundirlos hace creer que
/// el proceso murio cuando solo esta parado a la espera de que el trazador lo
/// reanude.
fn libc_wifstopped(st: i32) -> bool {
    (st & 0xff) == 0x7f
}
/// Terminado por una senal: ni salio limpio ni esta detenido.
fn libc_wifsignaled(st: i32) -> bool {
    !libc_wifexited(st) && !libc_wifstopped(st)
}
fn es_parada_de_syscall(st: i32) -> bool {
    libc_wifstopped(st) && ((st >> 8) & 0xff) == (libc::SIGTRAP | 0x80)
}
