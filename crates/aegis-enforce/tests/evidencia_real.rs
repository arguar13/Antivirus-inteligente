//! Disponible frente a aplicado, contra el kernel de verdad (hallazgo H-28).
//!
//! La prueba arranca un HIJO real —este mismo ejecutable de pruebas, limitado a
//! `testigo_confinado_solo_como_hijo`— que se pone un dominio Landlock y un
//! filtro seccomp en su hilo, avisa y se queda esperando. Mientras espera, el
//! padre mide:
//!
//! - sin testigos, seccomp y Landlock salen DISPONIBLES: el kernel los ofrece y
//!   nada medido los usa;
//! - con el hijo como testigo, salen con su evidencia, leida de
//!   `/proc/<tid>/status` y no de ninguna configuracion;
//! - con el propio proceso de la prueba, que no se ha confinado, no hay
//!   evidencia aunque el kernel los ofrezca;
//! - BPF LSM no sale en ningun caso con evidencia: nadie ha enganchado nada.
//!
//! El hijo se confina en su HILO (libtest corre cada prueba en uno) y avisa con
//! su tid: seccomp y Landlock se ponen por hilo, y `/proc/<tid>/status` describe
//! ese hilo. No necesita root: los dos se ponen tras `PR_SET_NO_NEW_PRIVS`.

#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use aegis_enforce::{Capacidad, Estado, Postura, Testigo};

/// Con esta variable, la prueba del hijo se confina; sin ella no hace nada.
const VAR_TESTIGO: &str = "AEGIS_ENFORCE_TESTIGO";
/// Prefijo de la linea con la que el hijo avisa de que ya esta confinado.
const MARCA: &str = "AEGIS-TESTIGO";
/// Nombre de la prueba que hace de hijo.
const HIJO: &str = "testigo_confinado_solo_como_hijo";
/// Lo que el padre espera la marca del hijo. Pasado el plazo, mata al hijo y
/// falla: una prueba colgada no puede dejar colgada la tanda entera.
const PLAZO_MARCA: Duration = Duration::from_secs(60);

/// El lado del hijo. En una ejecucion normal no hace nada: solo actua cuando la
/// arranca la otra prueba con [`VAR_TESTIGO`].
#[test]
fn testigo_confinado_solo_como_hijo() {
    if std::env::var_os(VAR_TESTIGO).is_none() {
        return;
    }
    use aegis_sandbox::landlock::{restrict_self, Abi, Ruleset};
    use aegis_sandbox::seccomp::{compile, install, DeniedAction};
    use aegis_sandbox::Syscall;

    // El tid se lee ANTES de confinarse: despues, Landlock no deja abrir nada.
    let tid: u32 = std::fs::read_link("/proc/thread-self")
        .ok()
        .and_then(|p| p.file_name()?.to_str()?.parse().ok())
        .expect("el tid de este hilo, desde /proc/thread-self");

    // Todo el sistema de ficheros gobernado y ninguna regla: lo que hace el
    // trabajador confinado. Si el kernel no trae Landlock, se dice con ABI 0.
    let landlock = match Abi::detect() {
        Some(abi) => {
            let reglas = Ruleset::new(abi, abi.supported_fs(), 0).expect("conjunto Landlock");
            restrict_self(reglas.raw_fd()).expect("landlock_restrict_self");
            abi.0
        }
        None => 0,
    };
    // Lo que se mide es que el filtro este puesto, no lo que niega: basta con
    // uno minimo. EPERM es 1.
    install(&compile(&[Syscall::Ptrace], DeniedAction::Errno(1))).expect("filtro seccomp");

    println!("{MARCA} tid={tid} landlock={landlock}");
    let _ = std::io::stdout().flush();
    // Se queda confinado hasta que el padre cierre la entrada.
    let mut resto = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut resto);
}

/// Lee la linea del hijo: `(tid, abi de Landlock o 0)`.
///
/// La marca se busca en cualquier punto de la linea, no solo al principio:
/// libtest escribe `test <nombre> ... ` SIN salto de linea antes de correr la
/// prueba, asi que lo que imprime el hijo queda detras, en esa misma linea.
fn leer_marca(lector: &mut impl BufRead) -> Option<(u32, u32)> {
    let mut linea = String::new();
    loop {
        linea.clear();
        if lector.read_line(&mut linea).ok()? == 0 {
            return None;
        }
        let Some((_, resto)) = linea.trim().split_once(MARCA) else {
            continue;
        };
        let mut tid = None;
        let mut abi = None;
        for par in resto.split_whitespace() {
            match par.split_once('=') {
                Some(("tid", v)) => tid = v.parse().ok(),
                Some(("landlock", v)) => abi = v.parse().ok(),
                _ => {}
            }
        }
        return Some((tid?, abi?));
    }
}

#[test]
fn aplica_solo_con_un_testigo_medido_y_disponible_sin_el() {
    let soporte = aegis_sandbox::Support::detect();
    if !soporte.seccomp {
        // make ci exige el kernel (AEGIS_EXIGIR=...,kernel): alli esto falla.
        aegis_prueba::omitir(
            "este kernel no admite seccomp: la prueba no puede ejercer nada",
            aegis_prueba::Requisito::Seccomp,
        );
        return;
    }

    let exe = std::env::current_exe().expect("ruta de este ejecutable de pruebas");
    let mut hijo = Command::new(exe)
        .args(["--exact", HIJO, "--nocapture", "--test-threads=1"])
        .env(VAR_TESTIGO, "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("arranca el hijo testigo");
    // La marca se lee en otro hilo y con plazo: si no llega, se mata al hijo
    // (su salida se cierra y el hilo lector termina) en vez de esperar siempre.
    let salida_hijo = hijo.stdout.take().expect("salida del hijo");
    let (tx, rx) = mpsc::channel();
    let lectora = std::thread::spawn(move || {
        let mut lector = BufReader::new(salida_hijo);
        let marca = leer_marca(&mut lector);
        let _ = tx.send(marca);
        lector
    });
    let marca = match rx.recv_timeout(PLAZO_MARCA) {
        Ok(marca) => marca,
        Err(_) => {
            let _ = hijo.kill();
            None
        }
    };
    let mut lector = lectora.join().expect("hilo lector de la salida del hijo");

    // Todo se mide MIENTRAS el hijo sigue confinado y esperando.
    let (sin, con, yo) = match marca {
        Some((tid, abi)) => {
            let mut testigo = Testigo::proceso(tid);
            if abi > 0 {
                testigo = testigo.con_landlock(abi);
            }
            (
                Some(Postura::medida()),
                Some(Postura::medida_con(&[testigo])),
                Some(Postura::medida_con(&[Testigo::proceso(std::process::id())])),
            )
        }
        None => (None, None, None),
    };

    // Se suelta al hijo antes de comprobar nada: una asercion que falle no
    // puede dejarlo esperando.
    drop(hijo.stdin.take());
    let mut resto = String::new();
    let _ = lector.read_to_string(&mut resto);
    let salida = hijo.wait().expect("estado de salida del hijo");

    let (tid, abi) = marca.unwrap_or_else(|| panic!("el hijo no llego a confinarse: {resto}"));
    let (sin, con, yo) = (sin.unwrap(), con.unwrap(), yo.unwrap());
    assert!(salida.success(), "el hijo termino mal: {salida:?}\n{resto}");

    // 1. Sin testigos: el kernel lo ofrece y nada medido lo usa.
    let e = &sin.capacidades[&Capacidad::Seccomp];
    assert!(
        matches!(e, Estado::Disponible { .. }),
        "seccomp sin testigos: {e:?}"
    );
    assert!(!sin.puede_aplicar_algo(), "{:?}", sin.capacidades);

    // 2. Con el hijo confinado: evidencia, y de ESE hilo.
    match &con.capacidades[&Capacidad::Seccomp] {
        Estado::Aplica { evidencia } => assert_eq!(evidencia.pid(), tid, "{evidencia}"),
        otro => panic!("el hijo tiene un filtro seccomp puesto y no se midio: {otro:?}"),
    }
    assert!(con.puede_aplicar_algo());
    assert!(con.como_describirse().starts_with("aplicando"));

    // 3. El proceso de la prueba no se ha confinado: aunque el kernel lo ofrezca
    //    (y aunque herede algun filtro de quien lo arranco), no hay evidencia.
    let e = &yo.capacidades[&Capacidad::Seccomp];
    assert!(
        !e.aplica(),
        "la prueba no se confino y sale con evidencia: {e:?}"
    );

    // 4. Nadie engancho un programa BPF LSM.
    for p in [&sin, &con, &yo] {
        let e = &p.capacidades[&Capacidad::BpfLsm];
        assert!(!e.aplica(), "BPF LSM sin programa enganchado: {e:?}");
    }

    // 5. Landlock, al final: es la mitad que un kernel sin Landlock no puede
    //    ejercer, y una omision termina la prueba. make ci exige el kernel
    //    (AEGIS_EXIGIR=...,kernel), asi que alli su falta es un fallo.
    if abi == 0 {
        aegis_prueba::omitir(
            "este kernel no trae Landlock: la mitad de Landlock no se ejerce",
            aegis_prueba::Requisito::Landlock,
        );
        return;
    }
    let e = &sin.capacidades[&Capacidad::Landlock];
    assert!(
        matches!(e, Estado::Disponible { .. }),
        "Landlock sin testigos: {e:?}"
    );
    match &con.capacidades[&Capacidad::Landlock] {
        Estado::Aplica { evidencia } => assert_eq!(evidencia.pid(), tid, "{evidencia}"),
        otro => panic!("el hijo declara Landlock ABI {abi} y no se corroboro: {otro:?}"),
    }
    let e = &yo.capacidades[&Capacidad::Landlock];
    assert!(
        !e.aplica(),
        "la prueba no declaro ningun dominio Landlock y sale con evidencia: {e:?}"
    );
}
