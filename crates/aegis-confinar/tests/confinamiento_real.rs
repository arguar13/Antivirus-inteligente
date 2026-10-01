//! El ciclo entero contra el kernel real: aprender, ensayar, imponer, retirarse.
//!
//! Se usa un programa de C propio (`tests/fixtures/confinado_stub.c`) con modos
//! que hacen cosas conocidas, compilado en la propia prueba: asi se sabe
//! exactamente que deberia aprenderse y que deberia bloquearse, y el resultado no
//! depende de lo que haga la version de `ls` que tenga la maquina.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use aegis_confinar::despliegue::{Aviso, PoliticaReversion};
use aegis_confinar::observacion::Acceso;
use aegis_confinar::supervision::{self, Desviacion};
use aegis_confinar::{
    ActivosProtegidos, Confirmacion, Despliegue, Estado, ObjetivoConfinable, Rechazo,
};
use aegis_prueba::{omitir, Requisito};
use aegis_sandbox::supervisor::Fin;
use aegis_sandbox::syscalls;

const VENTANA: Duration = Duration::from_secs(30);

/// Compila el programa de prueba una vez por proceso de pruebas.
fn stub() -> Option<PathBuf> {
    static RUTA: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    RUTA.get_or_init(|| {
        let fuente = PathBuf::from(raiz_crate()).join("tests/fixtures/confinado_stub.c");
        let dir = std::env::temp_dir().join(format!("aegis-confinar-{}", std::process::id()));
        std::fs::create_dir_all(&dir).ok()?;
        let bin = dir.join("confinado_stub");
        let cc = std::env::var("CC").unwrap_or_else(|_| "cc".into());
        let ok = Command::new(&cc)
            .args(["-O1", "-o"])
            .arg(&bin)
            .arg(&fuente)
            .status()
            .ok()?
            .success();
        ok.then_some(bin)
    })
    .clone()
}

fn objetivo() -> Option<ObjetivoConfinable> {
    let Some(b) = stub() else {
        omitir(
            "no hay compilador de C (o no compila) para el programa de prueba",
            Requisito::Herramienta("cc"),
        );
        return None;
    };
    Some(ObjetivoConfinable::nuevo(&b, &ActivosProtegidos::default()).expect("confinable"))
}

fn args(m: &str) -> Vec<String> {
    vec![m.to_string()]
}

fn texto(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn conf() -> Confirmacion {
    Confirmacion::nueva("prueba", "ensayo permisivo limpio", 1).expect("valida")
}

fn hay_etc_hostname() -> bool {
    std::fs::read("/etc/hostname").is_ok_and(|b| !b.is_empty())
}

/// APRENDER sobre un proceso real: lo aprendido cubre lo que el programa hizo, el
/// programa hizo lo mismo que sin supervision, y dos aprendizajes dan lo mismo.
#[test]
fn se_aprende_el_perfil_de_un_programa_real_sin_cambiar_lo_que_hace() {
    let Some(o) = objetivo() else { return };
    if !hay_etc_hostname() {
        omitir(
            "/etc/hostname no existe o esta vacio aqui",
            Requisito::Entorno,
        );
        return;
    }
    let a = supervision::aprender(&o, &args("normal"), VENTANA).expect("aprender");
    assert_eq!(a.fin, Some(Fin::Codigo(0)), "{}", texto(&a.salida));
    assert!(texto(&a.salida).contains("hostname=ok"));
    for n in ["execve", "openat", "read", "write", "exit_group"] {
        let nr = syscalls::numero(n).expect(n);
        assert!(a.perfil.llamadas.contains(&nr), "{n} tiene que aprenderse");
    }
    let socket = syscalls::numero("socket").expect("socket");
    assert!(
        !a.perfil.llamadas.contains(&socket),
        "el modo normal no abre sockets"
    );
    assert!(a.perfil.lecturas.contains(Path::new("/etc/hostname")));
    eprintln!(
        "aprendido en {:?}: {} llamadas vistas, {} distintas de {}\n{}",
        a.duracion,
        a.llamadas_vistas,
        a.perfil.llamadas.len(),
        syscalls::todas().len(),
        a.perfil.texto()
    );
    let b = supervision::aprender(&o, &args("normal"), VENTANA).expect("aprender");
    assert_eq!(
        a.perfil.llamadas, b.perfil.llamadas,
        "el mismo programa aprende lo mismo"
    );
}

/// ENSAYAR en permisivo: el programa hace cosas nuevas, NO se bloquea ninguna, y
/// cada una queda anotada.
#[test]
fn el_ensayo_permisivo_no_bloquea_nada_y_anota_lo_que_habria_bloqueado() {
    let Some(o) = objetivo() else { return };
    if !hay_etc_hostname() {
        omitir(
            "/etc/hostname no existe o esta vacio aqui",
            Requisito::Entorno,
        );
        return;
    }
    let p = supervision::aprender(&o, &args("normal"), VENTANA)
        .expect("aprender")
        .perfil;
    let e = supervision::ensayar(&o, &p, &args("desviado"), VENTANA).expect("ensayar");
    let sal = texto(&e.salida);
    assert_eq!(e.fin, Some(Fin::Codigo(0)), "{sal}");
    assert!(
        sal.contains("socket=ok"),
        "permisivo: el socket se abre de verdad: {sal}"
    );
    assert!(
        sal.contains("passwd=ok"),
        "permisivo: /etc/passwd se lee de verdad: {sal}"
    );
    assert!(
        e.habria_bloqueado
            .contains(&Desviacion::Llamada("socket".into())),
        "{:?}",
        e.habria_bloqueado
    );
    assert!(
        e.habria_bloqueado.contains(&Desviacion::Fichero(
            PathBuf::from("/etc/passwd"),
            Acceso::Lectura
        )),
        "{:?}",
        e.habria_bloqueado
    );
    // Y el mismo programa haciendo lo que se aprendio: ensayo limpio.
    let limpio = supervision::ensayar(&o, &p, &args("normal"), VENTANA).expect("ensayar");
    assert!(
        limpio.habria_bloqueado.is_empty(),
        "{:?}",
        limpio.habria_bloqueado
    );
}

/// IMPONER: lo aprendido sigue funcionando; lo que no se aprendio lo bloquea el
/// KERNEL —seccomp el socket, Landlock el fichero—.
#[test]
fn el_perfil_impuesto_deja_funcionar_lo_aprendido_y_el_kernel_bloquea_lo_demas() {
    let Some(o) = objetivo() else { return };
    if !hay_etc_hostname() {
        omitir(
            "/etc/hostname no existe o esta vacio aqui",
            Requisito::Entorno,
        );
        return;
    }
    let p = supervision::aprender(&o, &args("normal"), VENTANA)
        .expect("aprender")
        .perfil;
    let (fin, sal) =
        supervision::ejecutar_obligatorio(&o, &p, &conf(), &args("normal")).expect("obligatorio");
    assert_eq!(
        fin,
        Fin::Codigo(0),
        "el perfil aprendido no puede romper el programa: {}",
        texto(&sal)
    );
    assert!(texto(&sal).contains("hostname=ok"));

    let (fin, sal) =
        supervision::ejecutar_obligatorio(&o, &p, &conf(), &args("desviado")).expect("obligatorio");
    let sal = texto(&sal);
    eprintln!("desviado bajo el perfil: {fin:?}\n{sal}");
    assert!(
        sal.contains("socket=Operation not permitted"),
        "seccomp: {sal}"
    );
    assert!(
        sal.contains("passwd=Permission denied"),
        "Landlock (si el kernel lo tiene): {sal}"
    );
}

/// CAPACIDADES: un proceso de root que no usa ninguna capacidad deducible
/// arranca solo con las implicitas.
#[test]
fn el_perfil_impuesto_quita_las_capacidades_que_no_se_usaron() {
    let Some(o) = objetivo() else { return };
    if !hay_etc_hostname() {
        omitir(
            "/etc/hostname no existe o esta vacio aqui",
            Requisito::Entorno,
        );
        return;
    }
    let p = supervision::aprender(&o, &args("caps"), VENTANA)
        .expect("aprender")
        .perfil;
    if !p.root {
        omitir(
            "las pruebas no corren como root: sin privilegio no hay capacidades que quitar",
            Requisito::Root,
        );
        return;
    }
    let (fin, sal) =
        supervision::ejecutar_obligatorio(&o, &p, &conf(), &args("caps")).expect("obligatorio");
    let sal = texto(&sal);
    assert_eq!(fin, Fin::Codigo(0), "{sal}");
    let linea = sal
        .lines()
        .find(|l| l.starts_with("CapEff:"))
        .expect("CapEff");
    let efectivas = u64::from_str_radix(linea["CapEff:".len()..].trim(), 16).expect("hex");
    eprintln!(
        "CapEff bajo el perfil: {efectivas:#x} (retenidas {:#x})",
        p.capacidades_retenidas()
    );
    assert_eq!(
        efectivas,
        p.capacidades_retenidas(),
        "solo quedan las retenidas"
    );
    assert_eq!(efectivas & (1 << 21), 0, "CAP_SYS_ADMIN fuera");
}

/// REVERSION AUTOMATICA con un perfil deliberadamente malo: se le quita `openat`
/// y el programa falla al leer; a los tres fallos el perfil se retira solo y el
/// siguiente arranque, sin perfil, funciona.
#[test]
fn un_perfil_malo_se_retira_solo_y_el_programa_vuelve_a_funcionar() {
    let Some(o) = objetivo() else { return };
    if !hay_etc_hostname() {
        omitir(
            "/etc/hostname no existe o esta vacio aqui",
            Requisito::Entorno,
        );
        return;
    }
    let mut p = supervision::aprender(&o, &args("normal"), VENTANA)
        .expect("aprender")
        .perfil;
    p.llamadas
        .remove(&syscalls::numero("openat").expect("openat"));
    let mut d = Despliegue::nuevo(PoliticaReversion::default());
    d.aprendido(p);
    d.ensayado(0);
    d.imponer(conf()).expect("imponer");

    let mut aviso = None;
    let mut ahora = 0u64;
    while d.impone() {
        let perfil = d.perfil().expect("perfil").clone();
        let (fin, sal) =
            supervision::ejecutar_obligatorio(&o, &perfil, &conf(), &args("normal")).expect("run");
        assert!(
            !fin.limpio(),
            "con el perfil roto el programa falla: {}",
            texto(&sal)
        );
        ahora += 1_000_000_000;
        aviso = d.registrar(fin, ahora);
        assert!(ahora < 20_000_000_000, "el perfil no se retiro nunca");
    }
    assert!(matches!(aviso, Some(Aviso::Retirado { .. })), "{aviso:?}");
    assert!(matches!(d.estado(), Estado::Retirado { .. }));
    let (fin, sal) = supervision::ejecutar_libre(&o, &args("normal")).expect("libre");
    assert_eq!(
        fin,
        Fin::Codigo(0),
        "sin perfil el programa vuelve a funcionar: {}",
        texto(&sal)
    );
}

/// AUTOATAQUE: el confinamiento como denegacion de servicio contra el propio
/// producto y contra los activos protegidos. No se puede ni construir el objetivo.
#[test]
fn el_motor_no_puede_confinar_al_agente_ni_a_los_activos_protegidos() {
    let yo = std::env::current_exe().expect("current_exe");
    assert!(matches!(
        ObjetivoConfinable::nuevo(&yo, &ActivosProtegidos::default()),
        Err(Rechazo::AgentePropio(_))
    ));
    // Un binario del producto, se llame como se llame su ruta.
    let dir = std::env::temp_dir().join(format!("aegis-confinar-auto-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let falso_agente = dir.join("aegis-agent");
    std::fs::copy("/bin/true", &falso_agente).expect("copiar");
    assert!(matches!(
        ObjetivoConfinable::nuevo(&falso_agente, &ActivosProtegidos::default()),
        Err(Rechazo::AgentePropio(_))
    ));
    if let Ok(uno) = std::fs::read_link("/proc/1/exe") {
        assert!(ObjetivoConfinable::nuevo(&uno, &ActivosProtegidos::default()).is_err());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// La raiz del crate, leida al ejecutar (ver `crates/aegis-net/build.rs`).
fn raiz_crate() -> String {
    std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").to_string())
}
