//! Intento de fuga de un proceso confinado, para la simulacion de Red Team.
//!
//! El programa se confina a si mismo con la politica de binario no confiable y
//! acto seguido intenta, una por una, las cosas que esa politica prohibe. No
//! comprueba que la funcion "no devuelva error": ejecuta las llamadas al sistema
//! de verdad y mira que responde el kernel.
//!
//! - `--errno`: politica que devuelve `EPERM`. Sale con 0 si TODAS las fugas
//!   fueron bloqueadas, y con 1 si alguna funciono.
//! - `--kill`: politica que mata. El proceso no deberia llegar a imprimir nada
//!   tras el primer intento: quien lo lanza comprueba que murio por `SIGSYS`.

use aegis_sandbox::{CompiledSandbox, DeniedAction, FsPolicy, SandboxPolicy};

/// Ejecuta una fuga y devuelve `Ok(())` si el kernel la bloqueo con `EPERM`.
fn intento(nombre: &str, r: i64) -> Result<(), String> {
    if r >= 0 {
        return Err(format!("{nombre}: LA FUGA FUNCIONO"));
    }
    // SAFETY: lee el errno del hilo actual.
    let e = unsafe { *libc::__errno_location() };
    if e == libc::EPERM {
        println!("    bloqueada: {nombre}");
        Ok(())
    } else {
        Err(format!(
            "{nombre}: fallo con errno {e}, que no es EPERM; el filtro no la corto"
        ))
    }
}

fn main() -> std::process::ExitCode {
    let matar = std::env::args().any(|a| a == "--kill");

    let mut p = SandboxPolicy::untrusted_binary();
    // El aislamiento de rutas se ejercita en las pruebas del crate; aqui se
    // mide la capa de llamadas al sistema, que es la que existe en todo kernel.
    p.fs = FsPolicy::default();
    if !matar {
        p.denied_action = DeniedAction::Errno(libc::EPERM);
    }

    let compilado = match CompiledSandbox::compile(&p) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("no se pudo compilar el sandbox: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let resumen = match compilado.apply() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("no se pudo aplicar el sandbox: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    println!(
        "confinado: {} llamadas bloqueadas, landlock={:?}",
        resumen.blocked_syscalls, resumen.landlock_abi
    );

    let mut destino = [0u8; 8];
    let local = libc::iovec {
        iov_base: destino.as_mut_ptr() as *mut libc::c_void,
        iov_len: destino.len(),
    };
    let remoto = libc::iovec {
        iov_base: std::ptr::null_mut(),
        iov_len: destino.len(),
    };

    // SAFETY: todas usan argumentos validos; los PID -1 no existen, de modo que
    // sin sandbox fallarian con ESRCH y no con EPERM, y la diferencia es
    // precisamente lo que se esta midiendo.
    let fugas: Vec<(&str, i64)> = unsafe {
        vec![
            (
                "abrir un socket (salida a la red)",
                libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) as i64,
            ),
            (
                "trazar otro proceso (ptrace)",
                libc::ptrace(
                    libc::PTRACE_PEEKUSER,
                    -1,
                    std::ptr::null_mut::<libc::c_void>(),
                    0,
                ) as i64,
            ),
            (
                "leer memoria ajena (process_vm_readv)",
                libc::process_vm_readv(-1, &local, 1, &remoto, 1, 0) as i64,
            ),
            (
                "escribir memoria ajena (process_vm_writev)",
                libc::process_vm_writev(-1, &local, 1, &remoto, 1, 0) as i64,
            ),
            (
                "cargar un programa eBPF (bpf)",
                libc::syscall(libc::SYS_bpf, 5, std::ptr::null::<u8>(), 0usize),
            ),
            (
                "recuperar privilegios (setuid)",
                libc::syscall(libc::SYS_setuid, 0) as i64,
            ),
            (
                "crear un espacio de nombres (unshare)",
                libc::syscall(libc::SYS_unshare, libc::CLONE_NEWNS) as i64,
            ),
        ]
    };

    // Con la politica de matar, el proceso no llega vivo hasta aqui.
    if matar {
        eprintln!("BRECHA: la politica de matar dejo sobrevivir al proceso");
        return std::process::ExitCode::FAILURE;
    }

    let mut brechas = Vec::new();
    for (nombre, r) in fugas {
        if let Err(e) = intento(nombre, r) {
            brechas.push(e);
        }
    }

    if brechas.is_empty() {
        println!("ninguna fuga funciono");
        std::process::ExitCode::SUCCESS
    } else {
        for b in &brechas {
            eprintln!("BRECHA: {b}");
        }
        std::process::ExitCode::FAILURE
    }
}
