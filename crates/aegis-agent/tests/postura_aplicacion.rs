//! La postura de aplicacion que publica el agente, contra el kernel de verdad
//! (H-28).
//!
//! - Sin trabajador: lo que el kernel ofrece sale DISPONIBLE y nada sale con la
//!   etiqueta de aplicado. No necesita root.
//! - Con el trabajador del agente arrancado y confinado de verdad (este mismo
//!   binario con `--trabajador`, como en produccion): seccomp y Landlock salen
//!   aplicados, con la evidencia leida de `/proc/<pid>/status` del trabajador.
//! - Con el trabajador muerto y sin recoger (un zombi que aun conserva en
//!   `/proc` su filtro y su `NoNewPrivs`): nada sale aplicado.
//!
//! Las dos ultimas necesitan root: el trabajador se cambia a un uid propio, se
//! saca de la red y vive en su cgroup. En make ci corren como root y con
//! `AEGIS_EXIGIR=servicios,privilegios,kernel`, asi que no se omiten: una prueba
//! de confinamiento que se salta en silencio es un verde falso.

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use aegis_agent::aplicacion::{lineas, medir};
use aegis_agent::motores::estatico::medir_aplicacion;
use aegis_enforce::{Capacidad, Estado};
use aegis_prueba::{omitir, Requisito};
use aegis_trabajador::{ConfigTrabajador, Trabajador};

fn es_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("Uid:"))
                .map(|l| l.split_whitespace().next() == Some("0"))
        })
        .unwrap_or(false)
}

/// El trabajador de produccion: el binario del agente con `--trabajador`.
/// `None` si hay que omitir (sin root y sin exigencia); falla si se exige.
fn config() -> Option<ConfigTrabajador> {
    if !es_root() {
        omitir(
            "confinar al trabajador necesita root (uid propio, red cortada, cgroup)",
            Requisito::Root,
        );
        return None;
    }
    let mut c = ConfigTrabajador::este_binario().expect("ruta del ejecutable de pruebas");
    // `este_binario` apunta a este ejecutable de pruebas; el trabajador de
    // verdad es el agente. Los argumentos (`--trabajador`) ya son los suyos.
    c.programa = PathBuf::from(env!("CARGO_BIN_EXE_aegis-agent"));
    Some(c)
}

/// La primera letra del `State:` de un proceso (`R`, `S`, `Z`...).
fn estado_de(pid: u32) -> Option<char> {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("State:"))?
        .trim()
        .chars()
        .next()
}

#[test]
fn sin_trabajador_la_postura_sale_disponible_y_nunca_aplicada() {
    let m = medir(None);
    assert!(
        m.postura.aplicando().is_empty(),
        "sin trabajador no hay testigo, y sin testigo no hay evidencia: {:?}",
        m.postura.capacidades
    );
    assert!(m.postura.como_describirse().starts_with("SOLO OBSERVANDO"));
    for (c, requisito) in [
        (Capacidad::Seccomp, Requisito::Seccomp),
        (Capacidad::Landlock, Requisito::Landlock),
    ] {
        match &m.postura.capacidades[&c] {
            Estado::Disponible { .. } => {}
            Estado::Ausente { motivo } => omitir(
                &format!("{}: este kernel no lo ofrece ({motivo})", c.nombre()),
                requisito,
            ),
            otro => panic!(
                "{}: sin trabajador tiene que salir disponible: {otro:?}",
                c.nombre()
            ),
        }
    }
    let l = lineas(&m);
    assert!(l[0].contains("testigo: ninguno"), "{l:?}");
    let disponible = Estado::Disponible {
        motivo: String::new(),
    };
    assert!(
        l.iter().any(|x| x.starts_with(&format!(
            "aplicacion {}: {} (",
            Capacidad::Seccomp.nombre(),
            disponible.etiqueta()
        ))),
        "{l:?}"
    );
}

#[test]
fn con_el_trabajador_vivo_y_confinado_la_postura_lleva_su_evidencia() {
    let Some(c) = config() else { return };
    let t = Trabajador::arrancar(c).expect("el trabajador del agente arranca y se confina");
    let pid = t.pid().expect("un trabajador vivo tiene pid");
    let declarado = t.estado().confinamiento.clone();

    let m = medir_aplicacion(&t);
    assert_eq!(
        m.testigo.map(|x| x.pid),
        Some(pid),
        "el testigo es el trabajador"
    );

    // seccomp: el filtro que el trabajador se puso, leido de SU status.
    let seccomp = &m.postura.capacidades[&Capacidad::Seccomp];
    match seccomp {
        Estado::Aplica { evidencia } => {
            assert_eq!(evidencia.pid(), pid, "{evidencia}");
            assert!(
                evidencia
                    .to_string()
                    .contains(&format!("/proc/{pid}/status")),
                "{evidencia}"
            );
        }
        otro => {
            panic!("el trabajador lleva su filtro seccomp y no se midio: {otro:?}\n{declarado}")
        }
    }

    // Landlock: la ABI que declaro en su saludo, corroborada desde fuera.
    let landlock = &m.postura.capacidades[&Capacidad::Landlock];
    match t.landlock_declarado() {
        Some(abi) => {
            assert_eq!(m.testigo.and_then(|x| x.landlock_declarado), Some(abi));
            match landlock {
                Estado::Aplica { evidencia } => assert_eq!(evidencia.pid(), pid, "{evidencia}"),
                otro => {
                    panic!("el trabajador declara Landlock ABI {abi} y no se corroboro: {otro:?}")
                }
            }
        }
        // El kernel no lo trae: es una omision del entorno, y se dice.
        None if !landlock.disponible() => omitir(
            &format!("este kernel no ofrece Landlock: {}", landlock.detalle()),
            Requisito::Landlock,
        ),
        // El kernel lo trae y el trabajador no lo puso: eso es un fallo del
        // confinamiento, no algo que omitir.
        None => panic!("el kernel ofrece Landlock y el trabajador no lo declara: {declarado}"),
    }

    // Nadie ha enganchado un programa BPF LSM: no puede salir aplicado.
    assert!(!m.postura.capacidades[&Capacidad::BpfLsm].aplica());
    assert!(m.postura.puede_aplicar_algo());
    assert!(m.postura.como_describirse().starts_with("aplicando"));

    // Y el informe lo dice: el testigo con su pid, y cada capa con la etiqueta
    // que le dio aegis-enforce (no una escrita aqui).
    let l = lineas(&m);
    assert!(l[0].contains(&format!("pid {pid}")), "{l:?}");
    assert!(
        l.iter().any(|x| x.starts_with(&format!(
            "aplicacion {}: {} (",
            Capacidad::Seccomp.nombre(),
            seccomp.etiqueta()
        )) && x.contains(&format!("/proc/{pid}/status"))),
        "{l:?}"
    );
}

#[test]
fn un_trabajador_muerto_sin_recoger_no_cuenta_como_testigo() {
    let Some(c) = config() else { return };
    let t = Trabajador::arrancar(c).expect("el trabajador del agente arranca y se confina");
    let pid = t.pid().expect("un trabajador vivo tiene pid");

    // Se le mata desde fuera, sin que el cliente se entere: nadie lo recoge
    // hasta la siguiente peticion, asi que queda zombi, y un zombi conserva en
    // /proc su `Seccomp: 2` y su `NoNewPrivs: 1`.
    match Command::new("kill")
        .args(["-KILL", &pid.to_string()])
        .status()
    {
        Ok(s) if s.success() => {}
        otro => {
            omitir(
                &format!("no se pudo matar al trabajador con kill: {otro:?}"),
                Requisito::Herramienta("kill"),
            );
            return;
        }
    }
    let limite = Instant::now() + Duration::from_secs(5);
    while estado_de(pid) != Some('Z') {
        assert!(
            Instant::now() < limite,
            "el trabajador {pid} no llego a zombi: {:?}",
            estado_de(pid)
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(t.pid(), Some(pid), "el cliente aun no sabe que murio");

    let m = medir_aplicacion(&t);
    for c in [Capacidad::Seccomp, Capacidad::Landlock] {
        let e = &m.postura.capacidades[&c];
        assert!(
            !e.aplica(),
            "{}: un trabajador muerto no impone nada: {e:?}",
            c.nombre()
        );
    }
    assert!(m.postura.como_describirse().starts_with("SOLO OBSERVANDO"));
}
