//! Prueba de integracion del guardia contra un binario REAL de syscall directa.
//!
//! Se compila el vector `fixtures/syscall_stub.c` —que hace una syscall via
//! libc y otra directa desde memoria anonima— y se traza con el guardia. El
//! guardia tiene que ver: la de libc como legitima y la directa como evasion,
//! con el opcode `syscall` confirmado en la memoria del proceso.
//!
//! No hay nada simulado: es la tecnica de evasion ejecutada contra el kernel
//! real, cazada por el trazador real.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

use aegis_syscallguard::{EstadoSyscall, OrigenSyscall, SyscallGuard};

/// Numero de syscall de `getpid`, la que ejecuta el codigo directo del stub.
#[cfg(target_arch = "x86_64")]
const NR_GETPID: u64 = 39;
#[cfg(target_arch = "aarch64")]
const NR_GETPID: u64 = 172;

static CONTADOR: AtomicU32 = AtomicU32::new(0);

/// Compila el stub a un binario temporal unico. `None` si no hay compilador.
fn compilar_stub() -> Option<PathBuf> {
    let dir = env!("CARGO_MANIFEST_DIR");
    let fuente = format!("{dir}/tests/fixtures/syscall_stub.c");
    let n = CONTADOR.fetch_add(1, Ordering::Relaxed);
    let bin = std::env::temp_dir().join(format!("aegis_syscall_stub_{}_{n}", std::process::id()));
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".into());
    let salida = Command::new(&cc)
        .args(["-O2", "-o"])
        .arg(&bin)
        .arg(&fuente)
        .output()
        .ok()?;
    if !salida.status.success() {
        eprintln!(
            "no se pudo compilar el stub: {}",
            String::from_utf8_lossy(&salida.stderr)
        );
        return None;
    }
    Some(bin)
}

#[test]
fn el_guardia_caza_la_syscall_directa_y_respeta_la_de_libc() {
    let Some(stub) = compilar_stub() else {
        eprintln!("OMITIDA: no hay compilador de C para construir el vector");
        return;
    };

    let guardia = SyscallGuard::nuevo();
    let informe = guardia
        .perfilar_comando(&stub, &[])
        .expect("el perfilado debe completar sobre un binario que arranca y sale");
    let _ = std::fs::remove_file(&stub);

    eprintln!(
        "conteos: libc={} vdso={} estatico={} anonima={} desconocido={} (paradas={})",
        informe.conteos.libc,
        informe.conteos.vdso,
        informe.conteos.binario_estatico,
        informe.conteos.memoria_anonima,
        informe.conteos.desconocido,
        informe.paradas
    );

    // La syscall via libc (el write, y las de arranque de glibc) se cuentan
    // como legitimas.
    assert!(
        informe.conteos.libc > 0,
        "las syscalls de libc deben contarse como legitimas"
    );

    // La syscall directa desde memoria anonima: exactamente una, la del
    // shellcode del stub.
    assert_eq!(
        informe.conteos.memoria_anonima, 1,
        "debe cazarse una y solo una syscall directa desde memoria anonima"
    );
    assert_eq!(
        informe.estado(),
        EstadoSyscall::Evasion,
        "una syscall directa es veredicto de evasion"
    );

    // La anomalia es la que esperamos: getpid, desde anon, con el opcode
    // `syscall` confirmado en la memoria del proceso (el kernel no mintio).
    let anon: Vec<_> = informe
        .anomalias
        .iter()
        .filter(|a| a.origen == OrigenSyscall::MemoriaAnonima)
        .collect();
    assert_eq!(anon.len(), 1, "una anomalia de memoria anonima");
    assert_eq!(
        anon[0].nr, NR_GETPID,
        "la syscall directa del stub es getpid"
    );
    assert!(
        anon[0].opcode_confirmado,
        "en ip-opcode debe haber de verdad una instruccion syscall: la cruz kernel/memoria cuadra"
    );
}

#[test]
fn un_binario_normal_no_dispara_evasion() {
    // /bin/true no hace syscalls directas: todas pasan por libc/ld o el vdso.
    let guardia = SyscallGuard::nuevo();
    let informe = match guardia.perfilar_comando(std::path::Path::new("/bin/true"), &[]) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("OMITIDA: no se pudo trazar /bin/true: {e}");
            return;
        }
    };
    assert_eq!(
        informe.conteos.memoria_anonima, 0,
        "/bin/true no ejecuta syscalls desde memoria anonima"
    );
    assert_eq!(
        informe.conteos.desconocido, 0,
        "/bin/true no debe producir syscalls de origen imposible"
    );
    assert_ne!(
        informe.estado(),
        EstadoSyscall::Evasion,
        "un binario normal no es evasion"
    );
}
