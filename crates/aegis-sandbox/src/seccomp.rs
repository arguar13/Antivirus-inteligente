//! Construccion e instalacion de filtros seccomp-BPF.
//!
//! # Las dos trampas de un filtro de seccomp
//!
//! 1. **No comprobar la arquitectura.** Los numeros de llamada dependen de la
//!    ABI. En x86-64 el mismo proceso puede invocar la ABI de 32 bits o la x32,
//!    donde los numeros son OTROS: el filtro que bloquea `ptrace` (101) en
//!    x86-64 deja pasar `ptrace` (26) en i386. Un filtro que no empieza
//!    comprobando `arch` no bloquea nada que le importe a un atacante. Este
//!    empieza por ahi, y ademas rechaza el bit de x32.
//! 2. **Reservar memoria despues del `fork`.** El filtro se instala en el hijo,
//!    entre `fork` y `exec`, donde solo se pueden usar funciones seguras en
//!    contexto de senal. Reservar memoria ahi puede bloquearse para siempre si
//!    otro hilo tenia el bloqueo del asignador en el momento del `fork`. Por eso
//!    el programa se COMPILA antes de bifurcar y en el hijo solo se ejecutan
//!    llamadas al sistema.

use crate::error::SandboxError;
use crate::syscalls::Syscall;

/// Instruccion BPF clasica, espejo de `struct sock_filter`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockFilter {
    /// Codigo de operacion.
    pub code: u16,
    /// Salto si la comparacion es cierta.
    pub jt: u8,
    /// Salto si es falsa.
    pub jf: u8,
    /// Operando.
    pub k: u32,
}

/// Programa BPF, espejo de `struct sock_fprog`.
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

// --- Codigos de operacion de BPF clasico -----------------------------------
const BPF_LD: u16 = 0x00;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JEQ: u16 = 0x10;
const BPF_JGE: u16 = 0x30;
const BPF_K: u16 = 0x00;

// --- Desplazamientos dentro de `struct seccomp_data` -----------------------
/// Numero de llamada.
const OFF_NR: u32 = 0;
/// Arquitectura de la ABI usada para la llamada.
const OFF_ARCH: u32 = 4;

// --- Valores de retorno de seccomp -----------------------------------------
/// Mata el PROCESO entero, no solo el hilo.
///
/// Matar solo el hilo dejaria el resto del proceso vivo y en un estado
/// arbitrario, que es peor que cualquiera de los dos extremos.
pub const RET_KILL_PROCESS: u32 = 0x8000_0000;
/// Devuelve un errno sin ejecutar la llamada.
pub const RET_ERRNO: u32 = 0x0005_0000;
/// Permite la llamada.
pub const RET_ALLOW: u32 = 0x7fff_0000;

/// Bit que marca la ABI x32 en x86-64.
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// Arquitectura esperada, en la codificacion de `AUDIT_ARCH_*`.
#[cfg(target_arch = "x86_64")]
pub const AUDIT_ARCH: u32 = 0xc000_003e; // AUDIT_ARCH_X86_64
/// Arquitectura esperada, en la codificacion de `AUDIT_ARCH_*`.
#[cfg(target_arch = "aarch64")]
pub const AUDIT_ARCH: u32 = 0xc000_00b7; // AUDIT_ARCH_AARCH64

/// Que hacer con una llamada denegada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeniedAction {
    /// Devolver un errno. El proceso sigue vivo y puede manejarlo.
    ///
    /// Es lo adecuado para software legitimo al que se le recorta la
    /// superficie: un programa que recibe `EPERM` de `socket` normalmente
    /// informa y sigue, mientras que matarlo produce un fallo incomprensible.
    Errno(i32),
    /// Matar el proceso con `SIGSYS`.
    ///
    /// Es lo adecuado para binarios en los que no se confia: si intenta algo
    /// que la politica prohibe, no hay conversacion posible, y ademas la muerte
    /// por `SIGSYS` queda registrada de forma inconfundible.
    Kill,
}

impl DeniedAction {
    fn ret(self) -> u32 {
        match self {
            // El errno va en los 16 bits bajos del valor de retorno.
            DeniedAction::Errno(e) => RET_ERRNO | (e as u32 & 0xffff),
            DeniedAction::Kill => RET_KILL_PROCESS,
        }
    }
}

fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

/// Compila el programa BPF que deniega `denegadas`.
///
/// La estructura es siempre la misma y el orden importa:
///
/// 1. Comprobar la arquitectura. Si no es la esperada, matar: una llamada
///    desde otra ABI trae numeros que esta tabla no describe.
/// 2. Rechazar el bit de x32 por el mismo motivo.
/// 3. Comparar el numero contra cada llamada denegada.
/// 4. Permitir todo lo demas.
///
/// Es una lista blanca de comportamiento sobre una lista negra de llamadas, y
/// eso es deliberado: una lista blanca de LLAMADAS rompe cualquier programa no
/// escrito para ella —una version distinta de `libc` usa otras—, y un sandbox
/// que rompe el software legitimo se desactiva a la semana.
pub fn compile(denegadas: &[Syscall], accion: DeniedAction) -> Vec<SockFilter> {
    let mut p = Vec::with_capacity(denegadas.len() * 2 + 8);

    // 1. arch == AUDIT_ARCH ?
    p.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARCH));
    p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH, 1, 0));
    p.push(stmt(BPF_RET | BPF_K, RET_KILL_PROCESS));

    // 2. nr < X32_SYSCALL_BIT ?
    p.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_NR));
    p.push(jump(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 1));
    p.push(stmt(BPF_RET | BPF_K, RET_KILL_PROCESS));

    // 3. Las denegadas, ordenadas y sin repetir para que el programa sea
    //    identico ante la misma politica, venga en el orden que venga.
    let mut numeros: Vec<u32> = denegadas.iter().map(|s| s.number()).collect();
    numeros.sort_unstable();
    numeros.dedup();
    for nr in numeros {
        p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1));
        p.push(stmt(BPF_RET | BPF_K, accion.ret()));
    }

    // 4. Todo lo demas pasa.
    p.push(stmt(BPF_RET | BPF_K, RET_ALLOW));
    p
}

/// Numero de la llamada `seccomp`.
#[cfg(target_arch = "x86_64")]
const NR_SECCOMP: libc::c_long = 317;
/// Numero de la llamada `seccomp`.
#[cfg(target_arch = "aarch64")]
const NR_SECCOMP: libc::c_long = 277;

const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;

/// Instala un programa ya compilado en el hilo actual. **Irreversible.**
///
/// # Seguridad en contexto de senal
///
/// Solo hace dos llamadas al sistema y no reserva memoria, asi que se puede
/// llamar entre `fork` y `exec`. Esa propiedad es la razon de que la funcion
/// reciba el programa ya compilado en vez de compilarlo aqui.
///
/// # Errores
///
/// `EINVAL` suele significar que el kernel no tiene `CONFIG_SECCOMP_FILTER`;
/// `EACCES`, que falta `PR_SET_NO_NEW_PRIVS`, que esta funcion pone antes.
pub fn install(programa: &[SockFilter]) -> Result<(), SandboxError> {
    if programa.is_empty() {
        return Err(SandboxError::EmptyFilter);
    }
    if programa.len() > u16::MAX as usize {
        return Err(SandboxError::FilterTooLong(programa.len()));
    }

    // Sin `no_new_privs`, instalar un filtro exige CAP_SYS_ADMIN, y ademas un
    // binario `setuid` dentro del sandbox podria recuperar privilegios.
    // SAFETY: `prctl` con esta opcion no toca memoria del proceso.
    let r = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if r != 0 {
        return Err(SandboxError::NoNewPrivs(std::io::Error::last_os_error()));
    }

    let prog = SockFprog {
        len: programa.len() as u16,
        filter: programa.as_ptr(),
    };

    // SAFETY: `prog` apunta a `programa`, que sigue vivo durante la llamada. El
    // kernel copia el programa a su propio espacio antes de volver.
    let r = unsafe {
        libc::syscall(
            NR_SECCOMP,
            SECCOMP_SET_MODE_FILTER,
            0 as libc::c_ulong,
            &prog as *const SockFprog,
        )
    };
    if r != 0 {
        return Err(SandboxError::Seccomp(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Indica si el kernel admite filtros de seccomp.
///
/// Se comprueba con `prctl(PR_GET_SECCOMP)`, que es inocuo: no cambia nada y
/// devuelve el modo actual. Sin `CONFIG_SECCOMP` responde `ENOSYS`.
pub fn available() -> bool {
    // SAFETY: consulta pura, no modifica el estado del proceso.
    unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) >= 0 }
}
