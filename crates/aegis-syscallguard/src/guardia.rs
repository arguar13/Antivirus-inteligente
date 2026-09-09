//! El trazador: captura el origen de cada syscall y lo verifica cruzado.
//!
//! # El bucle
//!
//! 1. Lanza el binario con `PTRACE_TRACEME`; para en el primer `exec`.
//! 2. Avanza de syscall en syscall (`PTRACE_SYSCALL`).
//! 3. En cada ENTRADA de syscall, pide al kernel `PTRACE_GET_SYSCALL_INFO`: el
//!    numero de syscall y el puntero de instruccion desde el que se llamo —el
//!    que el hardware capturo—.
//! 4. Cruza ese puntero con el mapa de memoria del proceso ([`crate::origen`])
//!    para saber de donde salio la syscall.
//! 5. Verifica que el kernel no miente: lee los bytes reales en
//!    `ip - opcode` y comprueba que ahi hay de verdad una instruccion
//!    `syscall`. Si no, la propia info de syscall es sospechosa.
//!
//! # Contencion
//!
//! Este modulo OBSERVA; no aisla. Perfilar una muestra desconocida es ejecutar
//! codigo posiblemente malicioso, y eso se hace dentro del sandbox del producto
//! (`aegis-sandbox`, `aegis-unpacker`), que corta red y superficie de kernel
//! antes del `exec`. Aqui el binario perfilado es un objetivo controlado: una
//! muestra ya confinada, o un proceso propio bajo analisis.

use std::os::unix::process::CommandExt;
use std::process::Command;

use crate::abi::{
    PtraceSyscallInfo, OP_ENTRY, PTRACE_GET_SYSCALL_INFO, RETROCESO_OPCODE, SYSCALL_OPCODE,
};
use crate::error::SyscallGuardError;
use crate::origen::{clasificar, OrigenSyscall};
use crate::report::{AnomaliaSyscall, ConteoOrigen, InformeSyscall};

/// Configuracion del perfilado.
#[derive(Debug, Clone)]
pub struct ConfigPerfilado {
    /// Paradas de syscall maximas antes de terminar el perfilado.
    ///
    /// Acota el trabajo: un proceso de vida larga tiene syscalls sin fin, y el
    /// analisis no puede seguirlo para siempre.
    pub max_paradas: u64,
    /// Tope de anomalias registradas, para no crecer sin limite si una muestra
    /// hace millones de syscalls directas.
    pub max_anomalias: usize,
}

impl Default for ConfigPerfilado {
    fn default() -> Self {
        ConfigPerfilado {
            max_paradas: 500_000,
            max_anomalias: 1024,
        }
    }
}

/// Guardia de syscalls: perfila el origen de las syscalls de un proceso.
#[derive(Debug, Clone, Default)]
pub struct SyscallGuard {
    config: ConfigPerfilado,
}

impl SyscallGuard {
    /// Guardia con la configuracion por defecto.
    pub fn nuevo() -> SyscallGuard {
        SyscallGuard::default()
    }

    /// Guardia con una configuracion concreta.
    pub fn con_config(config: ConfigPerfilado) -> SyscallGuard {
        SyscallGuard { config }
    }

    /// Lanza `programa` bajo traza y perfila el origen de sus syscalls.
    pub fn perfilar_comando(
        &self,
        programa: &std::path::Path,
        args: &[String],
    ) -> Result<InformeSyscall, SyscallGuardError> {
        let mut cmd = Command::new(programa);
        cmd.args(args);
        // SAFETY: el cierre solo llama a `ptrace(TRACEME)`, que no toca memoria;
        // se ejecuta en el hijo, tras el `fork` y antes del `exec`.
        unsafe {
            cmd.pre_exec(|| {
                if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let hijo = cmd.spawn().map_err(SyscallGuardError::Spawn)?;
        let pid = hijo.id() as i32;
        // El trazador gestiona el ciclo de vida con waitpid; que el `Child` no
        // recolecte al proceso.
        std::mem::forget(hijo);

        let resultado = self.bucle(pid);
        // Pase lo que pase, no dejar vivo un proceso que puede ser una muestra.
        matar_proceso(pid);
        resultado
    }

    /// El bucle de trazado.
    fn bucle(&self, pid: i32) -> Result<InformeSyscall, SyscallGuardError> {
        let mut st = 0;
        // SAFETY: se espera al hijo trazado recien creado.
        if unsafe { libc::waitpid(pid, &mut st, 0) } == -1 {
            return Err(SyscallGuardError::Ptrace {
                op: "waitpid inicial",
                source: std::io::Error::last_os_error(),
            });
        }
        if wifexited(st) {
            return Err(SyscallGuardError::ProcesoTermino(Some(wexitstatus(st))));
        }

        // TRACESYSGOOD marca las paradas de syscall con el bit 0x80, para
        // separarlas de las senales reales.
        ptrace_simple(
            libc::PTRACE_SETOPTIONS,
            pid,
            0,
            libc::PTRACE_O_TRACESYSGOOD as libc::c_ulong,
        )?;

        let mut conteos = ConteoOrigen::default();
        let mut anomalias: Vec<AnomaliaSyscall> = Vec::new();
        let mut paradas = 0u64;
        // Cache del mapa de memoria: se relee solo cuando un puntero no cae en
        // ninguna region conocida (una region nueva de mmap/mprotect).
        let mut regiones = leer_regiones(pid);

        loop {
            if paradas >= self.config.max_paradas {
                break;
            }
            ptrace_simple(libc::PTRACE_SYSCALL, pid, 0, 0)?;
            // SAFETY: espera al hijo trazado.
            if unsafe { libc::waitpid(pid, &mut st, 0) } == -1 {
                return Err(SyscallGuardError::Ptrace {
                    op: "waitpid",
                    source: std::io::Error::last_os_error(),
                });
            }
            if wifexited(st) || wifsignaled(st) {
                break;
            }
            if !es_parada_de_syscall(st) {
                // Senal real: reinyectarla para no alterar el comportamiento del
                // proceso (un SIGTRAP de traza se traga con 0).
                let sig = (st >> 8) & 0xff;
                let reinyectar = if sig == libc::SIGTRAP {
                    0
                } else {
                    sig as libc::c_ulong
                };
                ptrace_simple(libc::PTRACE_SYSCALL, pid, 0, reinyectar)?;
                if unsafe { libc::waitpid(pid, &mut st, 0) } == -1 {
                    return Err(SyscallGuardError::Ptrace {
                        op: "waitpid tras senal",
                        source: std::io::Error::last_os_error(),
                    });
                }
                if wifexited(st) || wifsignaled(st) {
                    break;
                }
                continue;
            }

            let Some(info) = get_syscall_info(pid) else {
                continue;
            };
            // Solo la ENTRADA: cada syscall genera entrada y salida; contar las
            // dos duplicaria todo.
            if info.op != OP_ENTRY {
                continue;
            }
            paradas += 1;

            let ip = info.instruction_pointer;
            let mut origen = clasificar(ip, &regiones);
            // Un puntero que no cae en ninguna region conocida puede ser una
            // region nueva (JIT, codigo desempaquetado): releer el mapa una vez
            // y reclasificar antes de darlo por imposible.
            if origen == OrigenSyscall::Desconocido {
                regiones = leer_regiones(pid);
                origen = clasificar(ip, &regiones);
            }
            conteos.anotar(origen);

            if origen.es_evasion() && anomalias.len() < self.config.max_anomalias {
                let opcode_confirmado = confirmar_opcode(pid, ip);
                anomalias.push(AnomaliaSyscall {
                    nr: info.nr,
                    ip,
                    origen,
                    opcode_confirmado,
                });
            }
        }

        Ok(InformeSyscall {
            pid,
            paradas,
            conteos,
            anomalias,
        })
    }
}

/// Lee el puntero de instruccion y comprueba que en `ip - opcode` hay de verdad
/// una instruccion `syscall`. Es el cruce que descubre una info de syscall
/// falseada: el kernel dijo "syscall aqui", la memoria dice otra cosa.
fn confirmar_opcode(pid: i32, ip: u64) -> bool {
    if ip < RETROCESO_OPCODE {
        return false;
    }
    match aegis_scal::linux::memory::read_memory(pid, ip - RETROCESO_OPCODE, SYSCALL_OPCODE.len()) {
        Ok(bytes) => bytes == SYSCALL_OPCODE,
        Err(_) => false,
    }
}

/// Lee las regiones de memoria del proceso; vacio si no se puede.
fn leer_regiones(pid: i32) -> Vec<aegis_scal::memory::MemoryRegion> {
    aegis_scal::linux::memory::regions_of(pid).unwrap_or_default()
}

/// Pide `PTRACE_GET_SYSCALL_INFO`; `None` si el kernel no lo ofrece o falla.
fn get_syscall_info(pid: i32) -> Option<PtraceSyscallInfo> {
    let mut info = PtraceSyscallInfo::cero();
    // SAFETY: `addr` es el tamano del buffer y `data` apunta a `info`, que tiene
    // ese tamano. El kernel solo escribe hasta `addr` bytes en el.
    let r = unsafe {
        libc::ptrace(
            PTRACE_GET_SYSCALL_INFO,
            pid,
            core::mem::size_of::<PtraceSyscallInfo>() as libc::c_ulong,
            &mut info as *mut PtraceSyscallInfo,
        )
    };
    if r > 0 {
        Some(info)
    } else {
        None
    }
}

/// Mata y recolecta un proceso trazado, sin dejar zombi.
pub fn matar_proceso(pid: i32) {
    // SAFETY: senal y espera sobre un PID que este modulo creo.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
        let mut st = 0;
        libc::waitpid(pid, &mut st, 0);
    }
}

/// `ptrace` para peticiones que devuelven 0 en exito (SETOPTIONS, SYSCALL).
fn ptrace_simple(
    req: libc::c_uint,
    pid: i32,
    addr: libc::c_ulong,
    data: libc::c_ulong,
) -> Result<(), SyscallGuardError> {
    // SAFETY: peticion de ptrace sobre un PID trazado por este proceso.
    let r = unsafe { libc::ptrace(req, pid, addr, data) };
    if r == -1 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(0) {
            return Err(SyscallGuardError::Ptrace {
                op: "ptrace",
                source: e,
            });
        }
    }
    Ok(())
}

// --- Macros de estado de waitpid ---

fn wifexited(st: i32) -> bool {
    (st & 0x7f) == 0
}
fn wexitstatus(st: i32) -> i32 {
    (st >> 8) & 0xff
}
fn wifstopped(st: i32) -> bool {
    (st & 0xff) == 0x7f
}
fn wifsignaled(st: i32) -> bool {
    !wifexited(st) && !wifstopped(st)
}
fn es_parada_de_syscall(st: i32) -> bool {
    wifstopped(st) && ((st >> 8) & 0xff) == (libc::SIGTRAP | 0x80)
}
