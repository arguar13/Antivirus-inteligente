//! Contencion del proceso que se desempaqueta.
//!
//! Desempaquetar es EJECUTAR codigo posiblemente malicioso. Hacerlo sin
//! contencion es detonar la muestra. Antes del `exec`, en el proceso hijo, se
//! instala un filtro de llamadas al sistema que le quita lo que un binario
//! bajo analisis no tiene por que hacer: hablar por la red, tocar otros
//! procesos, cargar codigo en el kernel o cambiar de privilegios.
//!
//! Se usa seccomp directamente y no el crate `aegis-sandbox` para no crear una
//! dependencia circular —el sandbox podria querer desempaquetar algo el dia de
//! manana— y porque aqui hace falta una version minima que corra en el estrecho
//! contexto posterior al `fork`: sin reservar memoria, con el programa BPF ya
//! compilado.
//!
//! Deliberadamente se deja pasar `mmap` y `mprotect`: son justo las llamadas que
//! el empaquetador usa para desplegar su codigo, y el tracer las necesita para
//! detectar el OEP. Lo que se corta es la capacidad de HACER DANO desde ese
//! codigo, no la de desplegarlo.

/// Numero de la syscall `seccomp`.
#[cfg(target_arch = "x86_64")]
const NR_SECCOMP: libc::c_long = 317;
/// Numero de la syscall `seccomp`.
#[cfg(target_arch = "aarch64")]
const NR_SECCOMP: libc::c_long = 277;

const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xc000_00b7;

/// Llamadas prohibidas al proceso desempaquetado, por numero en x86-64.
#[cfg(target_arch = "x86_64")]
const PROHIBIDAS: &[u32] = &[
    41,  // socket
    42,  // connect
    49,  // bind
    43,  // accept
    101, // ptrace
    310, // process_vm_readv
    311, // process_vm_writev
    105, // setuid
    106, // setgid
    321, // bpf
    165, // mount
    166, // umount2
    272, // unshare
    308, // setns
    246, // kexec_load
    175, // init_module
    313, // finit_module
];
/// Llamadas prohibidas, por numero en aarch64.
#[cfg(target_arch = "aarch64")]
const PROHIBIDAS: &[u32] = &[
    198, // socket
    203, // connect
    200, // bind
    202, // accept
    117, // ptrace
    270, // process_vm_readv
    271, // process_vm_writev
    146, // setuid
    144, // setgid
    280, // bpf
    40,  // mount
    39,  // umount2
    97,  // unshare
    268, // setns
    104, // kexec_load
    105, // init_module
    273, // finit_module
];

#[repr(C)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

/// Aplica el sandbox al proceso actual, entre `fork` y `exec`.
///
/// # Seguridad en contexto de senal
///
/// El programa BPF se construye en un array de pila de tamano fijo, sin
/// reservar memoria del monton: se puede llamar en el contexto posterior al
/// fork, donde reservar podria bloquearse para siempre.
pub fn aplicar_pre_exec() -> Result<(), std::io::Error> {
    // no_new_privs: sin el, instalar un filtro exige CAP_SYS_ADMIN, y un binario
    // setuid dentro del sandbox podria recuperar privilegios.
    // SAFETY: prctl con esta opcion no toca memoria del proceso.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }

    // Programa BPF en la pila. Estructura: comprobar arquitectura, cargar el
    // numero de syscall, comparar contra cada prohibida (ERRNO EPERM), y
    // permitir el resto. Capacidad para 8 + 2*PROHIBIDAS instrucciones.
    let mut prog: [SockFilter; 8 + 2 * PROHIBIDAS.len()] = std::array::from_fn(|_| SockFilter {
        code: 0,
        jt: 0,
        jf: 0,
        k: 0,
    });
    let mut n = 0usize;
    let push = |c: u16, jt: u8, jf: u8, k: u32, prog: &mut [SockFilter], n: &mut usize| {
        prog[*n] = SockFilter { code: c, jt, jf, k };
        *n += 1;
    };

    // BPF_LD|BPF_W|BPF_ABS de offset 4 = arch
    push(0x20, 0, 0, 4, &mut prog, &mut n);
    // if arch == AUDIT_ARCH skip 1 else kill
    push(0x15, 1, 0, AUDIT_ARCH, &mut prog, &mut n);
    push(0x06, 0, 0, SECCOMP_RET_KILL_PROCESS, &mut prog, &mut n);
    // BPF_LD|BPF_W|BPF_ABS de offset 0 = nr
    push(0x20, 0, 0, 0, &mut prog, &mut n);
    // rechazar el bit de x32 (nr >= 0x40000000 -> kill)
    push(0x35, 0, 1, 0x4000_0000, &mut prog, &mut n);
    push(0x06, 0, 0, SECCOMP_RET_KILL_PROCESS, &mut prog, &mut n);
    // por cada prohibida: if nr == p -> ERRNO
    let mut prohibidas = PROHIBIDAS.to_vec();
    prohibidas.sort_unstable();
    for p in prohibidas {
        push(0x15, 0, 1, p, &mut prog, &mut n);
        push(
            0x06,
            0,
            0,
            SECCOMP_RET_ERRNO | (libc::EPERM as u32 & 0xffff),
            &mut prog,
            &mut n,
        );
    }
    // permitir el resto
    push(0x06, 0, 0, SECCOMP_RET_ALLOW, &mut prog, &mut n);

    let fprog = SockFprog {
        len: n as u16,
        filter: prog.as_ptr(),
    };
    // SAFETY: `fprog` apunta a `prog`, vivo durante la llamada; el kernel copia
    // el programa a su espacio.
    let r = unsafe {
        libc::syscall(
            NR_SECCOMP,
            SECCOMP_SET_MODE_FILTER,
            0 as libc::c_ulong,
            &fprog as *const SockFprog,
        )
    };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Indica si seccomp esta disponible en esta maquina.
pub fn seccomp_disponible() -> bool {
    // SAFETY: consulta pura del modo seccomp actual.
    unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) >= 0 }
}
