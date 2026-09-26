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

// ─── Lista blanca aprendida (FASE 93) ─────────────────────────────────────────
//
// La politica escrita a mano de arriba es una LISTA NEGRA a proposito: una lista
// blanca de llamadas rompe cualquier programa no escrito para ella. Un perfil
// APRENDIDO es la excepcion que confirma la regla: la lista sale de lo que ese
// programa hizo de verdad, se ensaya antes en modo permisivo, y si aun asi rompe
// algo se retira solo (`aegis-confinar`). Con esas tres cosas, la lista blanca
// deja de ser fragil y pasa a ser lo que es: la superficie mas pequena posible.

/// Suspende la llamada y se la entrega al supervisor por el descriptor de
/// escucha (`SECCOMP_RET_USER_NOTIF`).
pub const RET_USER_NOTIF: u32 = 0x7fc0_0000;
/// Permite la llamada y la registra en el log de auditoria del kernel.
pub const RET_LOG: u32 = 0x7ffc_0000;

/// El descriptor en el que el hijo supervisado deja su escucha para que el
/// padre la recoja con `pidfd_getfd`.
///
/// Un numero alto y fijo: la escucha nace en el primer descriptor libre, que el
/// padre no puede conocer, y el filtro necesita un numero concreto para dejar
/// pasar SOLO ese `dup3` sin tener que dejar pasar todos.
pub const FD_ESCUCHA: u32 = 907;

/// Numero de `dup3` en x86-64.
#[cfg(target_arch = "x86_64")]
pub const NR_DUP3: u32 = 292;
/// Numero de `dup3` en aarch64.
#[cfg(target_arch = "aarch64")]
pub const NR_DUP3: u32 = 24;

/// Numero de `socket` en esta arquitectura.
#[must_use]
pub fn nr_socket() -> u32 {
    Syscall::Socket.number()
}

/// Que hacer con una llamada que el perfil no contiene.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resto {
    /// Devolver un errno (modo obligatorio): el programa lo ve y puede seguir.
    Errno(i32),
    /// Entregarsela al supervisor (modos de aprendizaje y permisivo).
    Notificar,
}

impl Resto {
    fn ret(self) -> u32 {
        match self {
            Resto::Errno(e) => RET_ERRNO | (e as u32 & 0xffff),
            Resto::Notificar => RET_USER_NOTIF,
        }
    }
}

/// Una lista blanca de llamadas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListaBlanca<'a> {
    /// Numeros de llamada permitidos.
    pub permitidas: &'a [u32],
    /// Si `socket` esta permitida, las familias (`AF_*`) con las que se permite.
    /// `None` la permite con cualquiera.
    pub dominios_socket: Option<&'a [u32]>,
    /// Que hacer con lo demas.
    pub resto: Resto,
    /// Dejar pasar el `dup3` que coloca la escucha en [`FD_ESCUCHA`]. Solo para
    /// los hijos supervisados.
    pub pasaje_de_escucha: bool,
}

/// Desplazamiento de `args[0]` (32 bits bajos) en `struct seccomp_data`.
const OFF_ARG0: u32 = 16;
/// Desplazamiento de `args[1]` (32 bits bajos).
const OFF_ARG1: u32 = 24;

/// Compila una lista blanca.
///
/// Estructura, y el orden importa:
///
/// 1. Arquitectura y bit de x32, igual que la lista negra: otra ABI trae numeros
///    que esta tabla no describe.
/// 2. El `dup3` de la escucha, si procede, comprobando que el DESTINO sea
///    [`FD_ESCUCHA`]: un `dup3` cualquiera del programa sigue pasando por el
///    perfil como todo lo demas.
/// 3. `socket` con su familia: el argumento es un entero y el filtro lo puede
///    mirar sin carrera (no es un puntero).
/// 4. Cada llamada permitida.
/// 5. Lo demas, a `resto`.
///
/// Cada comparacion salta como mucho unas pocas instrucciones, asi que el
/// programa crece linealmente y ningun salto de 8 bits se queda corto, tenga el
/// perfil las llamadas que tenga.
#[must_use]
pub fn compile_lista_blanca(l: &ListaBlanca<'_>) -> Vec<SockFilter> {
    let mut p = Vec::with_capacity(l.permitidas.len() * 2 + 32);
    let resto = l.resto.ret();

    p.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARCH));
    p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH, 1, 0));
    p.push(stmt(BPF_RET | BPF_K, RET_KILL_PROCESS));
    p.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_NR));
    p.push(jump(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 1));
    p.push(stmt(BPF_RET | BPF_K, RET_KILL_PROCESS));

    if l.pasaje_de_escucha {
        // nr == dup3 ? -> args[1] == FD_ESCUCHA ? -> ALLOW ; si no, se recarga nr.
        p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, NR_DUP3, 0, 3));
        p.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARG1));
        p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, FD_ESCUCHA, 0, 1));
        p.push(stmt(BPF_RET | BPF_K, RET_ALLOW));
        p.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_NR));
    }

    let mut numeros: Vec<u32> = l.permitidas.to_vec();
    numeros.sort_unstable();
    numeros.dedup();
    let nr_sock = nr_socket();

    if let (true, Some(dominios)) = (numeros.contains(&nr_sock), l.dominios_socket) {
        let mut dom: Vec<u32> = dominios.to_vec();
        dom.sort_unstable();
        dom.dedup();
        // Bloque: LD arg0; por dominio (JEQ, RET ALLOW); RET resto.
        let largo = 1 + 2 * dom.len() + 1;
        p.push(jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            nr_sock,
            0,
            u8::try_from(largo).unwrap_or(u8::MAX),
        ));
        p.push(stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARG0));
        for d in dom {
            p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, d, 0, 1));
            p.push(stmt(BPF_RET | BPF_K, RET_ALLOW));
        }
        p.push(stmt(BPF_RET | BPF_K, resto));
        // `socket` ya esta resuelta: no vuelve a aparecer en la lista general.
        numeros.retain(|n| *n != nr_sock);
    }

    for nr in numeros {
        p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1));
        p.push(stmt(BPF_RET | BPF_K, RET_ALLOW));
    }
    p.push(stmt(BPF_RET | BPF_K, resto));
    p
}

/// Interpreta un programa BPF clasico sobre una llamada, como lo haria el
/// kernel. Sirve para PROBAR un filtro sin instalarlo: instalar es
/// irreversible, y una prueba que confina al propio proceso de pruebas no puede
/// seguir comprobando nada despues.
///
/// Solo entiende las instrucciones que emite este modulo; cualquier otra
/// devuelve `None`, que es un fallo de la prueba y no un permiso.
#[must_use]
pub fn evaluar(programa: &[SockFilter], nr: u32, arch: u32, args: [u64; 6]) -> Option<u32> {
    let palabra = |off: u32| -> Option<u32> {
        match off {
            OFF_NR => Some(nr),
            OFF_ARCH => Some(arch),
            o if (16..64).contains(&o) && o % 4 == 0 => {
                let i = ((o - 16) / 8) as usize;
                let alta = (o - 16) % 8 == 4;
                Some(if alta {
                    (args[i] >> 32) as u32
                } else {
                    args[i] as u32
                })
            }
            _ => None,
        }
    };
    let mut acc = 0u32;
    let mut pc = 0usize;
    // Un programa de seccomp no tiene saltos hacia atras: como mucho una pasada.
    for _ in 0..=programa.len() {
        let i = programa.get(pc)?;
        match i.code {
            c if c == BPF_LD | BPF_W | BPF_ABS => {
                acc = palabra(i.k)?;
                pc += 1;
            }
            c if c == BPF_JMP | BPF_JEQ | BPF_K => {
                pc += 1 + usize::from(if acc == i.k { i.jt } else { i.jf });
            }
            c if c == BPF_JMP | BPF_JGE | BPF_K => {
                pc += 1 + usize::from(if acc >= i.k { i.jt } else { i.jf });
            }
            c if c == BPF_RET | BPF_K => return Some(i.k),
            _ => return None,
        }
    }
    None
}

/// Instala un filtro que devuelve una escucha de notificaciones.
///
/// # Seguridad en contexto de senal
///
/// Igual que [`install`]: dos llamadas al sistema y nada mas, para poder usarse
/// entre `fork` y `exec`.
///
/// # Errores
/// El `errno` del kernel.
pub fn install_con_escucha(programa: &[SockFilter]) -> Result<std::os::fd::RawFd, SandboxError> {
    if programa.is_empty() {
        return Err(SandboxError::EmptyFilter);
    }
    if programa.len() > u16::MAX as usize {
        return Err(SandboxError::FilterTooLong(programa.len()));
    }
    // SAFETY: `prctl` con esta opcion no toca memoria del proceso.
    let r = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if r != 0 {
        return Err(SandboxError::NoNewPrivs(std::io::Error::last_os_error()));
    }
    let prog = SockFprog {
        len: programa.len() as u16,
        filter: programa.as_ptr(),
    };
    const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;
    // SAFETY: `prog` apunta a `programa`, vivo durante la llamada; el kernel lo
    // copia antes de volver y devuelve un descriptor nuevo o -1.
    let r = unsafe {
        libc::syscall(
            NR_SECCOMP,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &prog as *const SockFprog,
        )
    };
    if r < 0 {
        return Err(SandboxError::Seccomp(std::io::Error::last_os_error()));
    }
    Ok(r as std::os::fd::RawFd)
}

#[cfg(test)]
mod pruebas_lista_blanca {
    use super::*;

    const LEER: u32 = 0;
    const ESCRIBIR: u32 = 1;

    fn ev(p: &[SockFilter], nr: u32, a0: u64, a1: u64) -> u32 {
        evaluar(p, nr, AUDIT_ARCH, [a0, a1, 0, 0, 0, 0]).expect("programa interpretable")
    }

    #[test]
    fn lo_aprendido_pasa_y_lo_demas_va_al_resto() {
        let permitidas = [LEER, ESCRIBIR];
        let p = compile_lista_blanca(&ListaBlanca {
            permitidas: &permitidas,
            dominios_socket: None,
            resto: Resto::Errno(libc::EPERM),
            pasaje_de_escucha: false,
        });
        assert_eq!(ev(&p, LEER, 0, 0), RET_ALLOW);
        assert_eq!(ev(&p, ESCRIBIR, 0, 0), RET_ALLOW);
        assert_eq!(
            ev(&p, Syscall::Ptrace.number(), 0, 0),
            RET_ERRNO | libc::EPERM as u32
        );
        // Otra arquitectura: se mata, venga lo que venga.
        assert_eq!(
            evaluar(&p, LEER, 0x4000_0003, [0; 6]),
            Some(RET_KILL_PROCESS)
        );
        // El bit de x32: tambien.
        assert_eq!(ev(&p, LEER | 0x4000_0000, 0, 0), RET_KILL_PROCESS);
    }

    /// `socket` solo con las familias aprendidas: el dominio es un entero y el
    /// filtro lo puede mirar sin carrera.
    #[test]
    fn socket_solo_pasa_con_las_familias_aprendidas() {
        let permitidas = [LEER, nr_socket()];
        let p = compile_lista_blanca(&ListaBlanca {
            permitidas: &permitidas,
            dominios_socket: Some(&[libc::AF_UNIX as u32]),
            resto: Resto::Notificar,
            pasaje_de_escucha: false,
        });
        assert_eq!(ev(&p, nr_socket(), libc::AF_UNIX as u64, 1), RET_ALLOW);
        assert_eq!(ev(&p, nr_socket(), libc::AF_INET as u64, 1), RET_USER_NOTIF);
        assert_eq!(
            ev(&p, LEER, 0, 0),
            RET_ALLOW,
            "el bloque de socket no se come lo de detras"
        );
        assert_eq!(ev(&p, ESCRIBIR, 0, 0), RET_USER_NOTIF);
    }

    /// El `dup3` de la escucha pasa SOLO si el destino es el descriptor fijo: un
    /// `dup3` cualquiera del programa sigue sujeto al perfil.
    #[test]
    fn el_pasaje_de_escucha_solo_deja_pasar_su_dup3() {
        let p = compile_lista_blanca(&ListaBlanca {
            permitidas: &[],
            dominios_socket: None,
            resto: Resto::Notificar,
            pasaje_de_escucha: true,
        });
        assert_eq!(ev(&p, NR_DUP3, 3, u64::from(FD_ESCUCHA)), RET_ALLOW);
        assert_eq!(ev(&p, NR_DUP3, 3, 1), RET_USER_NOTIF);
        assert_eq!(ev(&p, LEER, 0, u64::from(FD_ESCUCHA)), RET_USER_NOTIF);
    }

    #[test]
    fn un_perfil_de_cuatrocientas_llamadas_compila_sin_saltos_cortos() {
        let todas: Vec<u32> = (0..400).collect();
        let p = compile_lista_blanca(&ListaBlanca {
            permitidas: &todas,
            dominios_socket: Some(&[1, 2, 10, 16]),
            resto: Resto::Errno(libc::EPERM),
            pasaje_de_escucha: true,
        });
        assert!(
            p.len() < 4096,
            "el kernel no acepta programas de mas de 4096"
        );
        for nr in [0u32, 150, 399] {
            assert_eq!(ev(&p, nr, 0, 0), RET_ALLOW, "{nr}");
        }
        assert_eq!(ev(&p, 450, 0, 0), RET_ERRNO | libc::EPERM as u32);
        assert_eq!(ev(&p, nr_socket(), 2, 0), RET_ALLOW);
        assert_eq!(ev(&p, nr_socket(), 17, 0), RET_ERRNO | libc::EPERM as u32);
    }

    #[test]
    fn el_interprete_coincide_con_la_lista_negra_de_siempre() {
        let p = compile(&[Syscall::Ptrace], DeniedAction::Kill);
        assert_eq!(ev(&p, Syscall::Ptrace.number(), 0, 0), RET_KILL_PROCESS);
        assert_eq!(ev(&p, LEER, 0, 0), RET_ALLOW);
    }
}
