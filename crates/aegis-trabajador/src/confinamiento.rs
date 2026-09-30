//! El confinamiento que el trabajador se aplica a si mismo al arrancar, ANTES de
//! leer un solo byte de su entrada.
//!
//! # Las capas, en este orden, y por que en este orden
//!
//! | # | Capa | Que quita | Necesita |
//! |---|---|---|---|
//! | 1 | Limites (`setrlimit`) | volcados de memoria, escribir ficheros, abrir mas de un puñado de descriptores, crear procesos | nada |
//! | 2 | Red (`unshare(CLONE_NEWNET)`) | toda la red: un espacio de nombres propio sin interfaces | `CAP_SYS_ADMIN`: va antes de soltar privilegios |
//! | 3 | Identidad (`setresuid`/`setresgid` a un uid propio) | los privilegios de root y todas las capacidades | ser root: va antes de seccomp |
//! | 4 | Landlock sin reglas | TODO el sistema de ficheros (y la red TCP, si el kernel lo sabe hacer) | `no_new_privs` |
//! | 5 | seccomp en lista blanca | toda llamada que no sea leer, escribir, memoria y reloj | ir el ultimo: las capas anteriores usan llamadas que este filtro prohibe |
//!
//! El techo de memoria y de CPU (cgroup) y el plazo por peticion los pone el
//! AGENTE desde fuera: un proceso comprometido no puede quitarselos.
//!
//! # Nada falla en silencio
//!
//! Cada capa devuelve lo que consiguio. El trabajador lo cuenta en su saludo y
//! el agente lo publica al arrancar. Si la red, la identidad o seccomp no se
//! pueden aplicar, el trabajador NO sirve peticiones (ver
//! [`Aplicado::suficiente`]): un parser de bytes hostiles con red y como root es
//! exactamente lo que esta fase existe para impedir.

use std::fmt;

/// El uid propio del trabajador, si nadie dice otro.
///
/// Un uid que ningun paquete de las distribuciones de la matriz asigna. El
/// empaquetado (FASE 3) creara el usuario `aegis-trabajador` con este uid; hasta
/// entonces se usa el numero, que es lo unico que el kernel mira.
pub const UID_POR_DEFECTO: u32 = 64_701;

/// Lo que consiguio cada capa.
#[derive(Debug, Clone)]
pub struct Aplicado {
    /// Limites de recursos.
    pub limites: Result<(), String>,
    /// Espacio de nombres de red propio.
    pub red: Result<(), String>,
    /// Identidad propia sin privilegios.
    pub identidad: Result<u32, String>,
    /// Landlock: version de ABI aplicada.
    pub landlock: Result<u32, String>,
    /// seccomp: llamadas permitidas.
    pub seccomp: Result<usize, String>,
}

impl Aplicado {
    /// Si el confinamiento basta para servir peticiones.
    ///
    /// Red, identidad y seccomp son obligatorias. Landlock es defensa en
    /// profundidad (el trabajador ya no puede abrir ficheros: seccomp no le deja
    /// llamar a `openat`), asi que su falta se declara pero no para el servicio.
    #[must_use]
    pub fn suficiente(&self) -> bool {
        self.red.is_ok() && self.identidad.is_ok() && self.seccomp.is_ok()
    }
}

impl fmt::Display for Aplicado {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn capa(r: &Result<impl fmt::Display, String>) -> String {
            match r {
                Ok(v) => format!("si ({v})"),
                Err(m) => format!("NO ({m})"),
            }
        }
        write!(
            f,
            "limites={} red-cortada={} uid-propio={} landlock={} seccomp={}",
            match &self.limites {
                Ok(()) => "si".to_string(),
                Err(m) => format!("NO ({m})"),
            },
            match &self.red {
                Ok(()) => "si".to_string(),
                Err(m) => format!("NO ({m})"),
            },
            capa(&self.identidad),
            capa(&self.landlock),
            capa(&self.seccomp),
        )
    }
}

fn error_os(que: &str) -> String {
    format!("{que}: {}", std::io::Error::last_os_error())
}

fn limites() -> Result<(), String> {
    // (recurso, tope). Sin volcados: un volcado del trabajador contendria el
    // fichero que analizaba. Sin escribir ficheros. Un puñado de descriptores:
    // los tres estandar y poco mas. Ningun proceso nuevo.
    //
    // Macro y no tabla: el tipo del recurso no es el mismo en todas las libc
    // (`__rlimit_resource_t` en glibc, `c_int` en musl), y cada constante ya
    // trae el de la que se enlaza.
    macro_rules! tope {
        ($recurso:expr, $valor:expr) => {{
            let l = libc::rlimit {
                rlim_cur: $valor,
                rlim_max: $valor,
            };
            // SAFETY: `setrlimit` solo lee la estructura, que vive en esta pila.
            if unsafe { libc::setrlimit($recurso, &l) } != 0 {
                return Err(error_os(concat!("setrlimit ", stringify!($recurso))));
            }
        }};
    }
    tope!(libc::RLIMIT_CORE, 0);
    tope!(libc::RLIMIT_FSIZE, 0);
    tope!(libc::RLIMIT_NOFILE, 8);
    tope!(libc::RLIMIT_NPROC, 0);
    Ok(())
}

fn red() -> Result<(), String> {
    // SAFETY: `unshare` no toca memoria del proceso. Con CLONE_NEWNET el proceso
    // pasa a un espacio de nombres de red nuevo, que nace sin interfaces (ni
    // siquiera el lazo local levantado): no hay a donde conectar.
    if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
        return Err(error_os("unshare(CLONE_NEWNET)"));
    }
    Ok(())
}

fn identidad(uid: u32) -> Result<u32, String> {
    // SAFETY: las tres llamadas solo reciben enteros (y un puntero nulo con
    // longitud cero en `setgroups`). El orden importa: grupos y gid primero,
    // porque tras soltar el uid ya no se tendria permiso para cambiarlos.
    unsafe {
        if libc::setgroups(0, std::ptr::null()) != 0 {
            return Err(error_os("setgroups"));
        }
        if libc::setresgid(uid, uid, uid) != 0 {
            return Err(error_os("setresgid"));
        }
        if libc::setresuid(uid, uid, uid) != 0 {
            return Err(error_os("setresuid"));
        }
    }
    // Con los tres uid distintos de cero y sin `keepcaps`, el kernel vacia las
    // capacidades efectivas y permitidas. Se comprueba en vez de suponerlo.
    let estado = std::fs::read_to_string("/proc/self/status").map_err(|e| e.to_string())?;
    let eff = estado
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .map(str::trim)
        .ok_or("sin CapEff en /proc/self/status")?;
    if u64::from_str_radix(eff, 16).map_err(|e| e.to_string())? != 0 {
        return Err(format!("quedan capacidades efectivas: {eff}"));
    }
    Ok(uid)
}

fn landlock() -> Result<u32, String> {
    use aegis_sandbox::landlock::{restrict_self, Abi, Ruleset, NET_BIND_TCP, NET_CONNECT_TCP};
    let abi = Abi::detect().ok_or("el kernel no tiene Landlock")?;
    // Todas las operaciones de fichero que esta ABI sabe restringir, y NINGUNA
    // regla que las permita: el trabajador no puede abrir nada.
    let reglas = Ruleset::new(abi, abi.supported_fs(), NET_BIND_TCP | NET_CONNECT_TCP)
        .map_err(|e| e.to_string())?;
    restrict_self(reglas.raw_fd()).map_err(|e| e.to_string())?;
    Ok(abi.0)
}

/// Las llamadas que el trabajador necesita, y ninguna mas.
///
/// Leer peticiones y escribir informes por los descriptores que ya tiene
/// abiertos, pedir y soltar memoria, el reloj (el plazo del desensamblador),
/// aleatoriedad (las tablas hash de la biblioteca estandar) y lo que usa el
/// propio proceso para morir (`abort` tras un panico: se envia SIGABRT a si
/// mismo). Ni `openat`, ni `execve`, ni `socket`, ni `ptrace`, ni `clone`.
fn permitidas() -> Vec<u32> {
    let mut v: Vec<libc::c_long> = vec![
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_close,
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_mprotect,
        libc::SYS_madvise,
        libc::SYS_brk,
        libc::SYS_futex,
        libc::SYS_clock_gettime,
        libc::SYS_getrandom,
        libc::SYS_sched_yield,
        libc::SYS_rt_sigreturn,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigaction,
        libc::SYS_sigaltstack,
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_tgkill,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ];
    v.sort_unstable();
    v.dedup();
    v.into_iter().map(|n| n as u32).collect()
}

fn seccomp() -> Result<usize, String> {
    use aegis_sandbox::seccomp::{compile_lista_blanca, install, ListaBlanca, Resto};
    let lista = permitidas();
    let programa = compile_lista_blanca(&ListaBlanca {
        permitidas: &lista,
        dominios_socket: Some(&[]),
        resto: Resto::Errno(libc::EPERM),
        pasaje_de_escucha: false,
    });
    install(&programa).map_err(|e| e.to_string())?;
    Ok(lista.len())
}

/// Aplica todas las capas en su orden. **Irreversible.**
///
/// Cada capa se intenta aunque falle la anterior: el informe tiene que decir
/// que falta, no solo lo primero que falto.
#[must_use]
pub fn confinar(uid: u32) -> Aplicado {
    let limites = limites();
    let red = red();
    let identidad = identidad(uid);
    let landlock = landlock();
    let seccomp = seccomp();
    Aplicado {
        limites,
        red,
        identidad,
        landlock,
        seccomp,
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn la_lista_no_permite_nada_con_que_escapar() {
        let p = permitidas();
        for prohibida in [
            libc::SYS_openat,
            libc::SYS_execve,
            libc::SYS_socket,
            libc::SYS_ptrace,
            libc::SYS_clone,
            libc::SYS_connect,
            libc::SYS_bpf,
            libc::SYS_process_vm_writev,
        ] {
            assert!(!p.contains(&(prohibida as u32)), "{prohibida} permitida");
        }
    }

    #[test]
    fn sin_red_ni_identidad_ni_seccomp_no_se_sirve() {
        let bien = Aplicado {
            limites: Ok(()),
            red: Ok(()),
            identidad: Ok(UID_POR_DEFECTO),
            landlock: Err("sin landlock".into()),
            seccomp: Ok(22),
        };
        assert!(bien.suficiente());
        let mut sin_red = bien.clone();
        sin_red.red = Err("EPERM".into());
        assert!(!sin_red.suficiente());
        let mut sin_uid = bien.clone();
        sin_uid.identidad = Err("EPERM".into());
        assert!(!sin_uid.suficiente());
        let mut sin_seccomp = bien;
        sin_seccomp.seccomp = Err("ENOSYS".into());
        assert!(!sin_seccomp.suficiente());
    }
}
