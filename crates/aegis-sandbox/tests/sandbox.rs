//! Pruebas del sandbox.
//!
//! El aislamiento se prueba EJERCIENDOLO: se bifurca un hijo, se le aplica el
//! sandbox y se le hace intentar exactamente lo que la politica prohibe. El
//! resultado se lee del codigo de salida, porque un hijo con seccomp puesto no
//! puede reservar memoria ni imprimir con seguridad.
//!
//! Probar un sandbox comprobando que la funcion "no devuelve error" no prueba
//! nada: un filtro con los numeros equivocados tambien se instala sin error.

use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use aegis_prueba::{omitir, Requisito};
use aegis_sandbox::policy::FsPolicy;
use aegis_sandbox::sandbox::CompiledSandbox;
use aegis_sandbox::seccomp::{self, DeniedAction, RET_ALLOW, RET_KILL_PROCESS};
use aegis_sandbox::syscalls::Syscall;
use aegis_sandbox::{SandboxPolicy, Support};

// --- Codigos de salida del hijo -------------------------------------------
/// La llamada funciono.
const PERMITIDA: i32 = 10;
/// La llamada devolvio EPERM: el filtro la corto.
const DENEGADA_EPERM: i32 = 11;
/// La llamada devolvio EACCES: Landlock la corto.
const DENEGADA_EACCES: i32 = 12;
/// La llamada fallo por otro motivo (el normal cuando no hay sandbox).
const OTRO_ERROR: i32 = 13;
/// No se pudo aplicar el sandbox.
const SIN_SANDBOX: i32 = 90;

/// Lo que un hijo hace tras entrar en el sandbox.
#[derive(Clone, Copy)]
enum Accion {
    /// Abrir un socket TCP.
    Socket,
    /// Leer la memoria de otro proceso.
    LeerMemoriaAjena,
    /// Trazar otro proceso.
    Trazar,
    /// Abrir un fichero.
    Abrir(&'static str),
    /// Abrir un fichero PARA ESCRIBIR.
    ///
    /// Es una accion propia y no un parametro de la anterior porque lo que
    /// distingue a las dos es exactamente lo que Landlock separa: el derecho de
    /// leer y el de escribir son bits distintos, y una regla puede conceder uno
    /// sin el otro.
    AbrirParaEscribir(&'static str),
    /// Nada: solo comprobar que el proceso sigue funcionando.
    Vivir,
}

/// Ejecuta `accion` en un hijo con el sandbox aplicado y devuelve su salida.
///
/// El sandbox se compila ANTES de bifurcar: compilarlo en el hijo reservaria
/// memoria despues del `fork`, que es justo lo que no se puede hacer.
fn en_hijo(policy: &SandboxPolicy, accion: Accion) -> std::process::ExitStatus {
    let compilado = CompiledSandbox::compile(policy).expect("la politica compila");

    // SAFETY: el hijo solo hace llamadas al sistema y termina con `_exit`, sin
    // desenrollar la pila ni volver al arnes de pruebas.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork fallo");
    if pid == 0 {
        let codigo = if compilado.apply().is_err() {
            SIN_SANDBOX
        } else {
            ejecutar(accion)
        };
        // SAFETY: `_exit` no ejecuta destructores ni vacia buffers, que es lo
        // correcto en un hijo que comparte los del padre.
        unsafe { libc::_exit(codigo) };
    }

    let mut estado: libc::c_int = 0;
    // SAFETY: se espera al hijo recien creado con un entero valido de salida.
    let r = unsafe { libc::waitpid(pid, &mut estado, 0) };
    assert_eq!(r, pid, "waitpid fallo");
    std::process::ExitStatus::from_raw(estado)
}

/// Ejecuta la accion. Todo con `libc` en crudo: sin reservar memoria.
fn ejecutar(accion: Accion) -> i32 {
    let r: i64 = match accion {
        // SAFETY: cada llamada usa argumentos validos y no toca memoria propia.
        Accion::Socket => unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) as i64 },
        Accion::LeerMemoriaAjena => {
            let mut destino = [0u8; 8];
            let local = libc::iovec {
                iov_base: destino.as_mut_ptr() as *mut libc::c_void,
                iov_len: destino.len(),
            };
            let remoto = libc::iovec {
                iov_base: std::ptr::null_mut(),
                iov_len: destino.len(),
            };
            // PID -1 no existe: sin sandbox esto da ESRCH, con sandbox EPERM.
            // Asi se distingue "lo corto el filtro" de "fallo por su cuenta".
            // SAFETY: el buffer local esta vivo; el kernel valida el remoto.
            unsafe { libc::process_vm_readv(-1, &local, 1, &remoto, 1, 0) as i64 }
        }
        // SAFETY: PID -1 no existe; sin sandbox da ESRCH.
        Accion::Trazar => unsafe {
            libc::ptrace(
                libc::PTRACE_PEEKUSER,
                -1,
                std::ptr::null_mut::<libc::c_void>(),
                0,
            ) as i64
        },
        // SAFETY: la ruta es una cadena literal terminada en NUL.
        Accion::Abrir(ruta) => unsafe {
            libc::open(ruta.as_ptr() as *const libc::c_char, libc::O_RDONLY) as i64
        },
        // SAFETY: igual que la anterior, con la intencion de escribir.
        Accion::AbrirParaEscribir(ruta) => unsafe {
            libc::open(ruta.as_ptr() as *const libc::c_char, libc::O_WRONLY) as i64
        },
        // SAFETY: consulta pura.
        Accion::Vivir => unsafe { libc::getpid() as i64 },
    };

    if r >= 0 {
        return PERMITIDA;
    }
    // SAFETY: lee el errno del hilo actual.
    match unsafe { *libc::__errno_location() } {
        libc::EPERM => DENEGADA_EPERM,
        libc::EACCES => DENEGADA_EACCES,
        _ => OTRO_ERROR,
    }
}

fn politica_errno(nombre: &'static str) -> SandboxPolicy {
    SandboxPolicy {
        denied_action: DeniedAction::Errno(libc::EPERM),
        ..{
            let mut p = SandboxPolicy::untrusted_binary();
            p.name = nombre;
            p.fs = FsPolicy::default();
            p
        }
    }
}

// ---------------------------------------------------------------------------
// Compilacion del filtro
// ---------------------------------------------------------------------------

#[test]
fn el_filtro_comprueba_la_arquitectura_antes_que_nada() {
    // Es la trampa numero uno de seccomp: los numeros de llamada dependen de la
    // ABI, asi que un filtro que no empieza comprobando `arch` bloquea `ptrace`
    // (101) en x86-64 y deja pasar `ptrace` (26) invocado desde la ABI de 32
    // bits. No bloquea nada que le importe a un atacante.
    let p = seccomp::compile(&[Syscall::Ptrace], DeniedAction::Errno(libc::EPERM));
    assert_eq!(p[0].k, 4, "la primera instruccion carga el campo `arch`");
    assert_eq!(p[1].k, seccomp::AUDIT_ARCH);
    assert_eq!(p[2].k, RET_KILL_PROCESS, "otra arquitectura se mata");
    assert_eq!(p[3].k, 0, "despues se carga el numero de llamada");
    assert_eq!(
        p[4].k, 0x4000_0000,
        "y se rechaza el bit de x32, que trae otra tabla de numeros"
    );
    assert_eq!(p[5].k, RET_KILL_PROCESS);
    assert_eq!(
        p.last().unwrap().k,
        RET_ALLOW,
        "lo que no esta denegado, pasa"
    );
}

#[test]
fn el_filtro_es_identico_ante_la_misma_politica() {
    // Si dependiera del orden de la lista, dos agentes con la misma politica
    // tendrian filtros distintos y no habria forma de auditarlos comparandolos.
    let a = seccomp::compile(
        &[Syscall::Ptrace, Syscall::Socket, Syscall::Bpf],
        DeniedAction::Kill,
    );
    let b = seccomp::compile(
        &[
            Syscall::Bpf,
            Syscall::Ptrace,
            Syscall::Socket,
            Syscall::Ptrace,
        ],
        DeniedAction::Kill,
    );
    assert_eq!(a, b, "mismo conjunto, mismo programa");
}

#[test]
fn la_politica_de_binario_no_confiable_cubre_lo_que_dice_cubrir() {
    let p = SandboxPolicy::untrusted_binary();
    let d = p.denied_syscalls();
    for obligatoria in [
        Syscall::Socket,
        Syscall::Connect,
        Syscall::Ptrace,
        Syscall::ProcessVmWritev,
        Syscall::KexecLoad,
        Syscall::InitModule,
        Syscall::Bpf,
        Syscall::Setuid,
        Syscall::Unshare,
    ] {
        assert!(d.contains(&obligatoria), "falta {obligatoria:?}");
    }
    assert_eq!(p.denied_action, DeniedAction::Kill);
    // `/tmp` no puede estar entre las rutas permitidas: es donde acaba todo lo
    // que se descarga, y un binario sospechoso que pueda escribir ahi deja su
    // segunda etapa.
    for r in p.fs.read_only.iter().chain(p.fs.read_write.iter()) {
        assert!(
            !r.starts_with("/tmp") && !r.starts_with("/var/tmp") && !r.starts_with("/dev/shm"),
            "un directorio escribible por cualquiera no puede estar en la lista: {r:?}"
        );
    }
    assert!(p.fs.read_write.is_empty(), "no se le permite escribir nada");
}

// ---------------------------------------------------------------------------
// Aplicacion real
// ---------------------------------------------------------------------------

#[test]
fn un_proceso_confinado_no_puede_abrir_un_socket() {
    let p = politica_errno("sin-red");
    assert_eq!(
        en_hijo(&p, Accion::Socket).code(),
        Some(DENEGADA_EPERM),
        "la politica prohibe la red"
    );
    // Y el control: sin sandbox, el mismo hijo abre el socket sin problema, asi
    // que lo que se midio es el efecto del filtro y no una limitacion del
    // entorno de pruebas.
    let libre = SandboxPolicy::named("libre");
    assert_eq!(en_hijo(&libre, Accion::Socket).code(), Some(PERMITIDA));
}

#[test]
fn un_proceso_confinado_no_puede_tocar_otros_procesos() {
    let p = politica_errno("sin-procesos");
    assert_eq!(
        en_hijo(&p, Accion::LeerMemoriaAjena).code(),
        Some(DENEGADA_EPERM)
    );
    assert_eq!(en_hijo(&p, Accion::Trazar).code(), Some(DENEGADA_EPERM));

    // Sin sandbox, las mismas llamadas fallan por OTRO motivo (el proceso -1 no
    // existe), no por EPERM: es lo que demuestra que el EPERM viene del filtro.
    let libre = SandboxPolicy::named("libre");
    assert_eq!(
        en_hijo(&libre, Accion::LeerMemoriaAjena).code(),
        Some(OTRO_ERROR)
    );
    assert_eq!(en_hijo(&libre, Accion::Trazar).code(), Some(OTRO_ERROR));
}

#[test]
fn el_proceso_confinado_sigue_funcionando_para_todo_lo_demas() {
    // Un sandbox que rompe el software legitimo se desactiva a la semana de
    // desplegarlo. Lo que no esta denegado tiene que seguir funcionando.
    let p = politica_errno("sin-red");
    assert_eq!(en_hijo(&p, Accion::Vivir).code(), Some(PERMITIDA));
}

#[test]
fn la_politica_de_matar_mata_de_verdad_y_con_sigsys() {
    // Para un binario en el que no se confia no hay conversacion posible: si
    // intenta lo que la politica prohibe, muere. Y muere con SIGSYS, que deja
    // constancia inconfundible de que lo mato el sandbox y no un fallo suyo.
    let mut p = SandboxPolicy::untrusted_binary();
    p.fs = FsPolicy::default(); // el aislamiento de rutas se prueba aparte
    let estado = en_hijo(&p, Accion::Socket);
    assert_eq!(
        estado.signal(),
        Some(libc::SIGSYS),
        "tenia que morir por SIGSYS, salio {estado:?}"
    );
    assert_eq!(estado.code(), None);

    // Y lo que no esta prohibido no lo mata.
    assert_eq!(en_hijo(&p, Accion::Vivir).code(), Some(PERMITIDA));
}

#[test]
fn un_comando_nace_ya_confinado() {
    // El sandbox se aplica entre `fork` y `exec`, de modo que no existe ni un
    // instante en el que el binario corra sin restringir.
    let p = politica_errno("comando");
    let compilado = Arc::new(CompiledSandbox::compile(&p).unwrap());

    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", "exit 7"]);
    compilado.confine(&mut cmd);
    let estado = cmd.status().expect("el comando arranca dentro del sandbox");
    assert_eq!(
        estado.code(),
        Some(7),
        "un programa normal tiene que ejecutarse igual"
    );
}

// ---------------------------------------------------------------------------
// Landlock
// ---------------------------------------------------------------------------

#[test]
fn landlock_niega_el_sistema_de_ficheros_de_raiz() {
    let soporte = Support::detect();
    let Some(abi) = soporte.landlock_abi else {
        // No se falla: este kernel no tiene CONFIG_SECURITY_LANDLOCK. Se avisa
        // en vez de callar, porque la diferencia entre "probado" y "omitido"
        // tiene que verse en la salida del CI.
        omitir(
            "este kernel no admite Landlock; la restriccion por rutas \
             no se puede ejercer aqui. seccomp SI se probo.",
            Requisito::Landlock,
        );
        assert!(soporte.seccomp, "al menos seccomp tiene que estar");
        return;
    };
    eprintln!("Landlock ABI {abi} disponible: se ejerce la restriccion por rutas");

    let lab = std::env::temp_dir().join(format!("aegis-sb-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&lab);

    let mut p = politica_errno("solo-el-laboratorio");
    p.fs = FsPolicy {
        // Solo lo imprescindible para que el proceso pueda ejecutarse, y el
        // laboratorio. Nada mas: ni `/etc`, ni `/root`, ni `/`.
        read_only: FsPolicy::base_del_sistema(),
        read_write: vec![lab.clone()],
    };

    // `/etc/shadow` esta fuera de la lista blanca: Landlock lo corta en el VFS,
    // no por permisos de Unix —esta prueba corre como root, que los ignora—.
    let estado = en_hijo(&p, Accion::Abrir("/etc/shadow\0"));
    assert_eq!(
        estado.code(),
        Some(DENEGADA_EACCES),
        "la raiz del sistema de ficheros tiene que quedar fuera de alcance"
    );

    // Y lo que si esta permitido sigue funcionando.
    assert_eq!(
        en_hijo(&p, Accion::Abrir("/bin/sh\0")).code(),
        Some(PERMITIDA),
        "sin poder leer sus propias bibliotecas, el proceso no arrancaria"
    );

    let _ = std::fs::remove_dir_all(&lab);
}

#[test]
fn el_resumen_dice_lo_que_de_verdad_se_aplico() {
    // Callarse que falta una capa seria lo peligroso: quien despliega creeria
    // tener una proteccion que no tiene.
    let p = SandboxPolicy::untrusted_binary();
    let c = CompiledSandbox::compile(&p).unwrap();
    let r = c.summary();

    assert_eq!(r.blocked_syscalls, p.denied_syscalls().len());
    assert!(r.blocked_syscalls > 20, "la politica bloquea de verdad");

    let soporte = Support::detect();
    assert_eq!(r.landlock_abi, soporte.landlock_abi);
    if soporte.landlock_abi.is_some() {
        assert!(r.allowed_paths > 0);
    } else {
        assert_eq!(r.allowed_paths, 0);
        assert!(!soporte.can_restrict_paths());
    }
    // El programa BPF es auditable desde fuera.
    assert_eq!(c.program().last().unwrap().k, RET_ALLOW);
}

#[test]
fn las_rutas_base_existen_de_verdad() {
    // Una regla de Landlock sobre una ruta inexistente hace fallar la
    // construccion entera del sandbox, y el proceso acabaria SIN restringir.
    let base = FsPolicy::base_del_sistema();
    assert!(!base.is_empty(), "alguna ruta del sistema tiene que haber");
    for r in &base {
        assert!(PathBuf::from(r).exists(), "{r:?} no existe");
    }
}

// ---------------------------------------------------------------------------
// Reglas sobre objetos que no son directorios
// ---------------------------------------------------------------------------
//
// El kernel rechaza con EINVAL una regla PATH_BENEATH sobre un no-directorio
// que pida derechos de directorio —listar, crear, borrar, reubicar—, y ese
// rechazo se lleva por delante la construccion ENTERA del sandbox: el binario
// acaba corriendo sin confinar. Es el peor fallo que este crate puede tener,
// porque no se nota: no hay excepcion, hay un proceso suelto.
//
// No es un caso rebuscado. `FsPolicy::base_del_sistema()` nombra
// `/etc/ld.so.cache`, que es un fichero regular, y cualquier politica razonable
// nombra `/dev/null`, que es un dispositivo de caracteres.

/// Un conjunto de reglas para probar, o `None` si aqui no hay Landlock.
fn conjunto_de_pruebas() -> Option<aegis_sandbox::landlock::Ruleset> {
    let abi = aegis_sandbox::landlock::Abi::detect()?;
    Some(
        aegis_sandbox::landlock::Ruleset::new(abi, abi.supported_fs(), 0)
            .expect("el conjunto de reglas se crea con la mascara que el propio kernel declara"),
    )
}

#[test]
fn una_regla_sobre_un_fichero_regular_no_tumba_el_sandbox() {
    let Some(rs) = conjunto_de_pruebas() else {
        omitir("este kernel no trae Landlock", Requisito::Landlock);
        return;
    };
    let fichero = std::env::temp_dir().join("aegis-landlock-fichero-regular");
    std::fs::write(&fichero, b"x").expect("se puede escribir en el directorio temporal");

    let aplicada = rs
        .allow_path(&fichero, aegis_sandbox::landlock::LECTURA)
        .expect("LECTURA sobre un fichero regular tiene que aceptarse, recortada");
    assert!(
        aplicada,
        "quedaban derechos que conceder —leer y ejecutar—, asi que la regla existe"
    );
    let _ = std::fs::remove_file(&fichero);
}

#[test]
fn una_regla_sobre_un_dispositivo_de_caracteres_no_tumba_el_sandbox() {
    let Some(rs) = conjunto_de_pruebas() else {
        omitir("este kernel no trae Landlock", Requisito::Landlock);
        return;
    };
    let dev = PathBuf::from("/dev/null");
    if !dev.exists() {
        omitir("esta maquina no tiene /dev/null", Requisito::Entorno);
        return;
    }
    // Lectura Y escritura: la mascara mas ancha que la politica llega a pedir,
    // y la que mas derechos de directorio arrastra.
    let derechos = aegis_sandbox::landlock::LECTURA | aegis_sandbox::landlock::ESCRITURA;
    assert!(
        rs.allow_path(&dev, derechos)
            .expect("un dispositivo de caracteres acepta la parte de la mascara que le toca"),
        "leer, escribir y truncar si valen sobre un dispositivo"
    );
}

#[test]
fn una_ruta_sin_ningun_derecho_aplicable_se_declara_en_vez_de_contarse() {
    let Some(rs) = conjunto_de_pruebas() else {
        omitir("este kernel no trae Landlock", Requisito::Landlock);
        return;
    };
    let fichero = std::env::temp_dir().join("aegis-landlock-sin-derechos");
    std::fs::write(&fichero, b"x").expect("se puede escribir en el directorio temporal");

    // «Crear un directorio dentro» no significa nada sobre un fichero regular.
    // La respuesta correcta no es un error —la politica no es incoherente, solo
    // inaplicable ahi— ni un exito silencioso, sino decir que no hubo regla.
    let aplicada = rs
        .allow_path(&fichero, aegis_sandbox::landlock::FS_MAKE_DIR)
        .expect("pedir un derecho inaplicable no es un fallo del sandbox");
    assert!(
        !aplicada,
        "sin ningun derecho que conceder no hay regla, y la ruta sigue prohibida"
    );
    let _ = std::fs::remove_file(&fichero);
}

#[test]
fn una_politica_sin_rutas_no_prohibe_el_sistema_de_ficheros_entero() {
    // Landlock es una LISTA BLANCA: gobernar los derechos de fichero sin anadir
    // ni una regla que los conceda prohibe el arbol completo, y el proceso no
    // llega a ejecutarse —`execve` devuelve EACCES antes de su primera
    // instruccion—. Es la forma exacta de `agent_helper`, que prohibe la red y
    // no dice nada de rutas: sin esta comprobacion, todo proceso auxiliar del
    // agente muere al arrancar en cuanto el kernel trae Landlock.
    let p = SandboxPolicy::agent_helper();
    assert!(p.fs.is_empty(), "esta politica no nombra ninguna ruta");
    assert!(p.deny_network, "y si prohibe la red, que es lo que la crea");

    if let Some(abi) = aegis_sandbox::landlock::Abi::detect() {
        assert_eq!(
            p.handled_fs(abi),
            0,
            "sin rutas no se gobierna ni un derecho de fichero"
        );
    }

    let compilado = Arc::new(CompiledSandbox::compile(&p).expect("la politica compila"));
    assert_eq!(compilado.summary().allowed_paths, 0);

    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", "exit 9"]);
    compilado.confine(&mut cmd);
    let estado = cmd
        .status()
        .expect("un auxiliar del agente tiene que poder arrancar");
    assert_eq!(estado.code(), Some(9), "y ejecutarse con normalidad");
}

#[test]
fn el_resumen_distingue_las_rutas_con_regla_de_las_que_no_la_tienen() {
    let soporte = Support::detect();
    if soporte.landlock_abi.is_none() {
        omitir("este kernel no trae Landlock", Requisito::Landlock);
        return;
    }
    let fichero = std::env::temp_dir().join("aegis-landlock-resumen");
    std::fs::write(&fichero, b"x").expect("se puede escribir en el directorio temporal");

    let mut p = SandboxPolicy::untrusted_binary();
    // Un directorio, que recibe la mascara entera, y un fichero suelto al que
    // solo le corresponde parte de ella.
    p.fs.read_write = vec![std::env::temp_dir(), fichero.clone()];
    let c = CompiledSandbox::compile(&p).expect("la politica se compila con un fichero dentro");
    let r = c.summary();

    assert_eq!(
        r.allowed_paths,
        p.fs.read_only.len() + p.fs.read_write.len(),
        "todas las rutas de esta politica admiten al menos un derecho"
    );
    assert_eq!(r.skipped_paths, 0, "y por tanto ninguna se queda sin regla");
    let _ = std::fs::remove_file(&fichero);
}

#[test]
fn un_fichero_de_solo_lectura_sigue_siendo_de_solo_lectura() {
    // La comprobacion que de verdad importa: recortar la mascara para que el
    // kernel acepte la regla NO puede acabar concediendo de mas. Un fichero en
    // `read_only` tiene que poder leerse y NO poder escribirse, y se comprueba
    // ejerciendolo dentro del sandbox, no leyendo la mascara.
    let soporte = Support::detect();
    if !soporte.can_restrict_paths() {
        omitir("este kernel no trae Landlock", Requisito::Landlock);
        return;
    }
    let fichero = std::env::temp_dir().join("aegis-landlock-solo-lectura");
    std::fs::write(&fichero, b"x").expect("se puede escribir en el directorio temporal");

    let mut p = SandboxPolicy::untrusted_binary();
    p.fs.read_only = FsPolicy::base_del_sistema();
    p.fs.read_only.push(fichero.clone());
    p.fs.read_write = Vec::new();

    let ruta: &'static str = Box::leak(format!("{}\0", fichero.display()).into_boxed_str());
    assert_eq!(
        en_hijo(&p, Accion::Abrir(ruta)).code(),
        Some(PERMITIDA),
        "una ruta de solo lectura se tiene que poder leer"
    );
    assert_eq!(
        en_hijo(&p, Accion::AbrirParaEscribir(ruta)).code(),
        Some(DENEGADA_EACCES),
        "y el recorte de la mascara no puede haber concedido la escritura"
    );
    let _ = std::fs::remove_file(&fichero);
}

#[test]
fn una_politica_de_solo_red_compila_aunque_la_abi_no_gobierne_la_red() {
    // `agent_helper` prohibe la red y no dice nada de rutas. En un kernel con
    // Landlock ABI 3 —el de WSL2, y el de cualquier kernel anterior a 6.7— la red
    // no se puede gobernar con Landlock, y sin rutas tampoco hay nada de fichero
    // que gobernar.
    //
    // Antes se creaba el conjunto de reglas igualmente, con los dos campos a
    // cero, y el kernel lo rechazaba con ENOMSG: la compilacion entera fallaba
    // por una politica que seccomp aplica perfectamente. Ahora no se crea un
    // conjunto que no gobierna nada.
    let p = SandboxPolicy::agent_helper();
    assert!(
        p.fs.is_empty(),
        "la premisa de esta prueba es que no hay rutas"
    );
    assert!(p.deny_network, "y que se pide prohibir la red");

    let c = CompiledSandbox::compile(&p)
        .expect("una politica de solo red tiene que compilar en cualquier ABI");

    // Y lo que importa de verdad: la red sigue prohibida por seccomp, que es
    // quien la cubre cuando Landlock no llega.
    let resumen = c.summary();
    assert!(
        resumen.blocked_syscalls > 0,
        "sin Landlock de red, seccomp tiene que seguir bloqueando llamadas"
    );

    // El proceso confinado sigue vivo: un conjunto de reglas vacio habria hecho
    // fallar la aplicacion entera.
    assert_eq!(
        en_hijo(&p, Accion::Vivir).code(),
        Some(PERMITIDA),
        "el proceso tiene que nacer confinado y seguir funcionando"
    );
}
