//! La detonacion entera, contra procesos y sockets de verdad.
//!
//! Lo que se ejercita aqui no es la orquestacion en abstracto: es una muestra
//! escrita en la prueba, con comportamiento conocido, detonada de verdad —con su
//! agente invitado trazandola por `ptrace`, su canal por un socket, su
//! aislamiento por espacios de nombres y su informe montado al final— y se
//! comprueba que lo que hizo aparece.
//!
//! El unico muro es arrancar el hipervisor, que necesita `/dev/kvm`. Todo lo
//! demas ocurre.

use aegis_vmi::modo::Modo;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use aegis_detonate::informe::Veredicto;
use aegis_detonate::{detonar, Frontera, Peticion};

/// Localiza el binario del agente invitado en el arbol de compilacion.
///
/// En produccion vive dentro de la imagen del invitado. Aqui se busca donde lo
/// deja `cargo build -p aegis-invitado`, y si no esta se **omite** la prueba en
/// vez de fingir que paso.
fn agente_invitado() -> Option<PathBuf> {
    let manifiesto = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // server/crates/aegis-detonate -> server/crates -> server -> raiz
    let raiz = manifiesto.parent()?.parent()?.parent()?;
    for perfil in ["debug", "release"] {
        let ruta = raiz.join("target").join(perfil).join("aegis-invitado");
        if ruta.exists() {
            return Some(ruta);
        }
    }
    None
}

fn hay_unshare() -> bool {
    Command::new("unshare")
        .arg("--net")
        .arg("--")
        .arg("/bin/true")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Escribe una muestra de comportamiento conocido y devuelve su ruta.
fn muestra(dir: &Path, nombre: &str, guion: &str) -> PathBuf {
    let ruta = dir.join(nombre);
    std::fs::write(&ruta, guion).unwrap();
    let mut permisos = std::fs::metadata(&ruta).unwrap().permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    {
        use std::os::unix::fs::PermissionsExt;
        permisos.set_mode(0o755);
    }
    std::fs::set_permissions(&ruta, permisos).unwrap();
    ruta
}

fn peticion(dir: &Path, muestra: PathBuf, agente: PathBuf, plazo: Duration) -> Peticion {
    let mut frontera = Frontera::namespaces();
    frontera.limites.plazo = plazo;
    Peticion {
        muestra,
        argumentos: Vec::new(),
        frontera,
        agente_invitado: agente,
        trabajo: dir.join("trabajo"),
        muestra_real: false,
        // Estas pruebas detonan con el agente invitado, que es el camino que ya
        // existia: lo que ejercitan es la frontera y el canal, no el modo.
        modo: Modo::ConAgente,
    }
}

// ---------------------------------------------------------------------------
// Una muestra de comportamiento conocido produce la traza esperada
// ---------------------------------------------------------------------------

#[test]
fn una_muestra_que_cifra_ficheros_aparece_en_el_informe() {
    let (Some(agente), true) = (agente_invitado(), hay_unshare()) else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let victimas = dir.path().join("victima");
    std::fs::create_dir_all(&victimas).unwrap();
    for i in 0..3 {
        std::fs::write(victimas.join(format!("documento{i}.docx")), b"contenido").unwrap();
    }

    // Comportamiento de ransomware, reducido a lo esencial: reescribe los
    // ficheros de la victima con otro nombre, borra los originales y deja una
    // nota. Nada de esto es un truco de prueba: son las tres cosas que hace un
    // cifrador, y son las tres que el informe tiene que ensenar.
    let guion = format!(
        "#!/bin/sh\n\
         for f in {}/documento*.docx; do\n\
         \x20 cat \"$f\" > \"$f.cifrado\"\n\
         \x20 rm -f \"$f\"\n\
         done\n\
         echo 'paga o los pierdes' > {}/RESCATE.txt\n",
        victimas.display(),
        victimas.display()
    );
    let m = muestra(dir.path(), "cifrador.sh", &guion);

    let informe = detonar(&peticion(dir.path(), m, agente, Duration::from_secs(60)))
        .expect("la detonacion tiene que completarse");

    // Lo que hizo aparece. Sin esto, el resto del informe no significa nada.
    let escritos = &informe.comportamiento.escritos;
    assert!(
        escritos.iter().any(|r| r.contains("RESCATE.txt")),
        "no aparece la nota de rescate; escritos: {escritos:?}"
    );
    assert!(
        escritos.iter().any(|r| r.contains(".cifrado")),
        "no aparecen los ficheros cifrados; escritos: {escritos:?}"
    );
    assert!(
        !informe.comportamiento.borrados.is_empty(),
        "no aparece el borrado de los originales"
    );

    // Y el veredicto no es «sin hallazgos», que seria la conclusion equivocada
    // mas cara de todas.
    match informe.veredicto() {
        Veredicto::ConHallazgos { hechos } => assert!(hechos >= 3, "{hechos} hechos"),
        otro => panic!(
            "un cifrador no puede salir como {otro:?}\n{}",
            informe.resumen()
        ),
    }
}

#[test]
fn una_muestra_que_lanza_procesos_los_deja_en_el_informe() {
    let (Some(agente), true) = (agente_invitado(), hay_unshare()) else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    // Lanzar un proceso y morirse es lo primero que hace cualquier malware
    // serio. Si el trazador no siguiera a los hijos, el informe saldria vacio.
    let m = muestra(
        dir.path(),
        "lanzador.sh",
        "#!/bin/sh\n/bin/echo uno > /dev/null\n/bin/echo dos > /dev/null\n",
    );

    let informe = detonar(&peticion(dir.path(), m, agente, Duration::from_secs(60))).unwrap();
    assert!(
        informe.comportamiento.procesos >= 2,
        "solo {} procesos: no se estan siguiendo los hijos",
        informe.comportamiento.procesos
    );
}

// ---------------------------------------------------------------------------
// La frontera
// ---------------------------------------------------------------------------

#[test]
fn una_muestra_que_intenta_salir_a_la_red_no_alcanza_nada() {
    // LA PROPIEDAD QUE DEFINE LA FASE, comprobada y no declarada: se intenta una
    // conexion de verdad a una direccion de verdad desde dentro de la frontera.
    let (Some(agente), true) = (agente_invitado(), hay_unshare()) else {
        return;
    };
    if Command::new("python3")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_err()
    {
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let testigo = dir.path().join("alcanzo.txt");
    let guion = format!(
        "#!/usr/bin/env python3\n\
         import socket\n\
         s = socket.socket(); s.settimeout(3)\n\
         try:\n\
         \x20   s.connect(('1.1.1.1', 80))\n\
         \x20   open({testigo:?}, 'w').write('ALCANZO')\n\
         except Exception:\n\
         \x20   pass\n",
        testigo = testigo.display().to_string()
    );
    let m = muestra(dir.path(), "salidor.py", &guion);

    let _informe = detonar(&peticion(dir.path(), m, agente, Duration::from_secs(60))).unwrap();

    assert!(
        !testigo.exists(),
        "la muestra alcanzo una direccion REAL desde dentro de la frontera"
    );
}

// ---------------------------------------------------------------------------
// Lo que se corta se declara
// ---------------------------------------------------------------------------

#[test]
fn una_muestra_que_no_termina_se_corta_y_el_informe_no_concluye() {
    // «No hizo nada» y «no le dio tiempo» no se pueden escribir igual: alguien
    // desplegaria la muestra creyendo que esta limpia.
    let (Some(agente), true) = (agente_invitado(), hay_unshare()) else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let m = muestra(dir.path(), "eterno.sh", "#!/bin/sh\nsleep 600\n");

    let informe = detonar(&peticion(
        dir.path(),
        m,
        agente,
        Duration::from_millis(1500),
    ))
    .unwrap();

    assert!(
        !informe.final_.tuvo_ocasion(),
        "una muestra cortada no tuvo ocasion: {:?}",
        informe.final_
    );
    match informe.veredicto() {
        Veredicto::NoConcluyente { motivo } => {
            assert!(motivo.contains("NO significa"), "{motivo}");
        }
        otro => panic!("una detonacion cortada no puede concluir {otro:?}"),
    }
}

// ---------------------------------------------------------------------------
// La maquina se destruye siempre
// ---------------------------------------------------------------------------

#[test]
fn no_queda_ningun_proceso_vivo_despues_de_una_detonacion() {
    // Una maquina de detonacion que sobrevive a su detonacion es una maquina
    // infectada corriendo en la infraestructura del que analiza, y ademas
    // invisible porque nadie la esta mirando.
    let (Some(agente), true) = (agente_invitado(), hay_unshare()) else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let testigo = dir.path().join("sobrevivi.txt");
    // La muestra deja un hijo que intenta sobrevivirla: es lo que hace cualquier
    // malware que quiera persistir mas alla de su proceso.
    let guion = format!(
        "#!/bin/sh\n(sleep 30; echo vivo > {}) &\nexit 0\n",
        testigo.display()
    );
    let m = muestra(dir.path(), "persistente.sh", &guion);

    let _ = detonar(&peticion(dir.path(), m, agente, Duration::from_secs(5))).unwrap();

    // Se espera mas de lo que el hijo huerfano tardaria en escribir.
    std::thread::sleep(Duration::from_secs(2));
    assert!(
        !testigo.exists(),
        "un hijo de la muestra sobrevivio a la detonacion"
    );
}

// ---------------------------------------------------------------------------
// El anfitrion no se rompe con lo que el invitado le mande
// ---------------------------------------------------------------------------

#[test]
fn una_traza_manipulada_no_rompe_al_anfitrion() {
    // El canal lo escribe un proceso que la muestra puede haber comprometido. Se
    // le manda basura de verdad por el socket de verdad y el anfitrion tiene que
    // salir de ahi con un informe, no con un panico.
    use aegis_detonate::receptor::{escuchar_unix, Topes};
    use std::io::Write;
    use std::os::unix::net::UnixStream;

    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("canal.sock");
    let s2 = socket.clone();

    let receptor = std::thread::spawn(move || {
        escuchar_unix(&s2, Topes::default(), Duration::from_secs(5)).unwrap()
    });
    for _ in 0..200 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    let mut flujo = UnixStream::connect(&socket).unwrap();
    // Basura de todas las formas que se le ocurren a alguien con intencion.
    let _ = flujo.write_all(b"AEGD");
    let _ = flujo.write_all(&[0xff; 64]);
    let _ = flujo.write_all(b"\x00\x00\x00\x00\x00\x00\x00\x00");
    let _ = flujo.write_all(&vec![0x41u8; 100_000]);
    drop(flujo);

    let recepcion = receptor.join().unwrap();
    assert!(
        !recepcion.completa(),
        "una traza de basura no puede salir como completa"
    );
    assert!(
        !recepcion.anomalias.is_empty(),
        "y tiene que decir que paso"
    );
}

// ---------------------------------------------------------------------------
// Determinismo: se mide, no se afirma
// ---------------------------------------------------------------------------

#[test]
fn dos_detonaciones_de_la_misma_muestra_dan_el_mismo_informe() {
    let (Some(agente), true) = (agente_invitado(), hay_unshare()) else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let salida = dir.path().join("salida");
    std::fs::create_dir_all(&salida).unwrap();
    let guion = format!(
        "#!/bin/sh\n\
         echo uno > {0}/fijo-a.txt\n\
         echo dos > {0}/fijo-b.txt\n",
        salida.display()
    );
    let m = muestra(dir.path(), "determinista.sh", &guion);

    let (a, b, divergencias) = aegis_detonate::detonar_dos_veces(&peticion(
        dir.path(),
        m,
        agente,
        Duration::from_secs(60),
    ))
    .unwrap();

    assert!(
        divergencias.is_empty(),
        "una muestra determinista no puede divergir: {divergencias:?}"
    );
    assert_eq!(
        a.huella(),
        b.huella(),
        "la misma muestra con el mismo comportamiento tiene que dar la misma huella"
    );
}

#[test]
fn una_muestra_que_usa_azar_lo_declara_en_vez_de_fingir_determinismo() {
    // Normalizar el nombre hasta que parezca determinista esconderia justo el
    // comportamiento que interesa.
    let (Some(agente), true) = (agente_invitado(), hay_unshare()) else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let salida = dir.path().join("salida");
    std::fs::create_dir_all(&salida).unwrap();
    let guion = format!(
        "#!/bin/sh\n\
         n=$(od -An -tx4 -N8 /dev/urandom | tr -d ' \\n')\n\
         echo carga > {}/$n.bin\n",
        salida.display()
    );
    let m = muestra(dir.path(), "aleatoria.sh", &guion);

    let (a, _b, divergencias) = aegis_detonate::detonar_dos_veces(&peticion(
        dir.path(),
        m,
        agente,
        Duration::from_secs(60),
    ))
    .unwrap();

    // O bien divergen —y entonces la comparacion lo dice— o bien el informe
    // declara la fuente de indeterminismo. Lo que no puede pasar es que salga
    // como perfectamente reproducible sin mas.
    let declarado = a.indeterminismo.iter().any(|x| x.que.contains("generado"));
    assert!(
        !divergencias.is_empty() || declarado,
        "un nombre al azar tiene que salir en la comparacion o declararse:\n{}\n{:?}",
        a.resumen(),
        a.indeterminismo
    );
}

// ---------------------------------------------------------------------------
// El muro, declarado
// ---------------------------------------------------------------------------

#[test]
fn se_dice_si_este_anfitrion_puede_levantar_maquinas_virtuales() {
    // Degradar en silencio a un aislamiento mas debil es peor que negarse a
    // arrancar: el informe sale igual y nadie sabe con que fuerza estaba
    // encerrada la muestra.
    let hay = aegis_detonate::maquina::hay_virtualizacion();
    assert_eq!(hay, Path::new("/dev/kvm").exists());

    // Y el informe lleva escrito con que fuerza estaba encerrada.
    let f = Frontera::namespaces();
    assert!(
        f.resumen().contains("NO"),
        "la jaula tiene que declarar que no aguanta una elevacion local: {}",
        f.resumen()
    );
}
