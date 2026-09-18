//! Pruebas de la traduccion de telemetria a tecnicas de ATT&CK.
//!
//! La pieza que se prueba aqui no es el motor —eso esta en `aegis-behavior`—
//! sino el CRITERIO de traduccion: que se traduce, que no, y por que. Una
//! traduccion generosa de mas arruina el motor mas rapido que un motor mal
//! calibrado, porque le mete ruido con peso alto.

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Arc;

use aegis_agent::behavior::{tecnicas_de_imagen, BehaviorBridge};
use aegis_agent::graph::ProcKey;
use aegis_agent::triage::TelemetryEvent;
use aegis_behavior::engine::EngineConfig;
use aegis_behavior::score::Action;
use aegis_behavior::technique::Technique;

fn dormilon() -> Child {
    Command::new("/bin/sh")
        .args(["-c", "sleep 300"])
        .spawn()
        .unwrap()
}

/// Directorio de trabajo con copias REALES de un binario, renombradas.
///
/// Hace falta porque la capa de abstraccion resuelve la imagen leyendo
/// `/proc/<pid>/exe`, que es el binario que el kernel ejecuto de verdad. Un
/// guion no valdria: el `exe` de un guion es su interprete. Copiando un binario
/// con el nombre que interesa se consiguen procesos vivos cuya imagen resuelta
/// es la que la prueba necesita, sin simular nada.
///
/// # Por que un INTERPRETE DE ORDENES y ya no `sleep`
///
/// Porque no todo binario funciona bajo otro nombre. Ubuntu 26.04 sustituyo GNU
/// coreutils por uutils (paquete `rust-coreutils`), que es un unico binario
/// MULTI-LLAMADA: mira su `argv[0]` para saber que orden ejecutar. Una copia de
/// `sleep` llamada `nginx` responde «coreutils: unknown program 'nginx'» y muere
/// al instante, asi que no habia proceso vivo ni `exe` que resolver, y la prueba
/// fallaba diciendo que no veia la cadena —un sintoma que no apunta a la causa—.
///
/// Un interprete de ordenes no tiene ese problema por diseño: distinguir el
/// comportamiento por `argv[0]` es justo lo que hace (`sh` frente a `bash`), asi
/// que arranca con el nombre que se le ponga. Es la propiedad que esta prueba
/// necesita, y [`fuente_del_laboratorio`] la COMPRUEBA en vez de suponerla.
struct Lab(PathBuf);

impl Lab {
    fn nuevo(n: &str) -> Lab {
        let p = std::env::temp_dir().join(format!("aegis-beh-{n}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Lab(p)
    }

    /// Lanza una copia del interprete con el nombre indicado y devuelve el hijo.
    ///
    /// Queda bloqueado en `read`, no dormido: su entrada estandar es una tuberia
    /// que este proceso conserva abierta, asi que el hijo espera indefinidamente
    /// y muere solo en cuanto la prueba suelta el [`Child`]. Con `sleep 300` en su
    /// lugar quedarian procesos huerfanos cinco minutos tras cada ejecucion, y
    /// ademas el interprete tendria un hijo que `matar` no alcanza.
    fn lanzar(&self, nombre: &str) -> Child {
        let destino = self.0.join(nombre);
        std::fs::copy(fuente_del_laboratorio(), &destino).unwrap();
        let mut permisos = std::fs::metadata(&destino).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permisos, 0o755);
        std::fs::set_permissions(&destino, permisos).unwrap();
        // `ETXTBSY` es un clasico de Linux al ejecutar algo recien escrito
        // desde un proceso con varios hilos: si otro hilo tiene el fichero
        // abierto para escritura en el instante del `fork`, el descriptor se
        // hereda y el `exec` falla. No es un defecto del codigo bajo prueba, y
        // se resuelve solo en milisegundos.
        for intento in 0..50 {
            match Command::new(&destino)
                .args(["-c", "read x"])
                .stdin(std::process::Stdio::piped())
                .spawn()
            {
                Ok(mut c) => {
                    // Que haya arrancado no basta: un binario multi-llamada acepta
                    // el `spawn` y se muere al mirarse el `argv[0]`. Si eso pasa,
                    // el fallo tiene que salir AQUI y con su causa, no cincuenta
                    // lineas mas abajo como una cadena de ataque que no se ve.
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    match c.try_wait() {
                        Ok(None) => return c,
                        Ok(Some(estado)) => panic!(
                            "la copia de {} llamada «{nombre}» murio al instante ({estado}).\n\
                             Suele significar que la fuente es un binario MULTI-LLAMADA \
                             (mira su argv[0]) y no admite otro nombre.",
                            fuente_del_laboratorio().display()
                        ),
                        Err(e) => panic!("no se pudo comprobar el hijo «{nombre}»: {e}"),
                    }
                }
                Err(e) if e.raw_os_error() == Some(libc_etxtbsy()) && intento < 49 => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(e) => panic!("no se pudo lanzar {}: {e}", destino.display()),
            }
        }
        unreachable!("el bucle sale por return o por panic")
    }

    fn ruta(&self, nombre: &str) -> PathBuf {
        self.0.join(nombre)
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `ETXTBSY`, sin arrastrar `libc` como dependencia de prueba.
fn libc_etxtbsy() -> i32 {
    26
}

/// El binario que se copia bajo otros nombres para poblar el laboratorio.
///
/// Se elige COMPROBANDO la propiedad que hace falta —que arranque y siga vivo
/// bajo un nombre que no es el suyo— en vez de darla por hecha. Es la suposicion
/// que se rompio con el coreutils multi-llamada de Ubuntu 26.04, y comprobarla
/// cuesta un `spawn` una sola vez por ejecucion.
fn fuente_del_laboratorio() -> &'static Path {
    static ELEGIDO: std::sync::OnceLock<&'static Path> = std::sync::OnceLock::new();
    ELEGIDO.get_or_init(|| {
        let candidatos = ["/bin/dash", "/bin/bash", "/bin/sh", "/usr/bin/bash"];
        let mut descartados = Vec::new();
        for c in candidatos {
            let ruta = Path::new(c);
            if !ruta.exists() {
                continue;
            }
            match sirve_con_otro_nombre(ruta) {
                Ok(()) => return ruta,
                Err(motivo) => descartados.push(format!("{c}: {motivo}")),
            }
        }
        panic!(
            "ningun interprete sirve para montar el laboratorio.\n\
             Se necesita un binario que arranque bajo un nombre que no es el suyo \
             y que acepte `-c`.\nDescartados:\n  {}",
            descartados.join("\n  ")
        )
    })
}

/// Comprueba que `fuente` copiada con otro nombre arranca y sigue viva.
///
/// Devuelve el motivo del descarte si no sirve, para que el panico de arriba
/// pueda decir por que se descarto cada candidato en vez de solo que no hubo
/// ninguno.
fn sirve_con_otro_nombre(fuente: &Path) -> Result<(), String> {
    let dir = std::env::temp_dir().join(format!(
        "aegis-beh-sonda-{}-{}",
        std::process::id(),
        fuente.file_name().and_then(|n| n.to_str()).unwrap_or("x")
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    // Un nombre que ninguna orden del sistema tiene, que es justo el caso que
    // rompe a un binario multi-llamada.
    let destino = dir.join("aegis-sonda-de-nombre-ajeno");
    let resultado = (|| -> Result<(), String> {
        std::fs::copy(fuente, &destino).map_err(|e| e.to_string())?;
        let mut permisos = std::fs::metadata(&destino)
            .map_err(|e| e.to_string())?
            .permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut permisos, 0o755);
        std::fs::set_permissions(&destino, permisos).map_err(|e| e.to_string())?;

        let mut hijo = Command::new(&destino)
            .args(["-c", "read x"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| format!("no arranco: {e}"))?;
        std::thread::sleep(std::time::Duration::from_millis(50));
        let vivo = matches!(hijo.try_wait(), Ok(None));
        let _ = hijo.kill();
        let _ = hijo.wait();
        if vivo {
            Ok(())
        } else {
            Err("murio al instante bajo otro nombre (¿binario multi-llamada?)".to_owned())
        }
    })();
    let _ = std::fs::remove_dir_all(&dir);
    resultado
}

fn matar(mut c: Child) {
    let _ = c.kill();
    let _ = c.wait();
}

fn exec(actor: u64, pid: u32, image: &str) -> TelemetryEvent {
    exec_hijo_de(actor, 1, pid, image)
}

fn exec_hijo_de(actor: u64, parent: u64, pid: u32, image: &str) -> TelemetryEvent {
    TelemetryEvent::Exec {
        actor: ProcKey(actor),
        pid,
        parent: ProcKey(parent),
        image: Arc::from(image),
        cmdline: Arc::from(image),
        started_ns: 1,
        ts_ns: 1,
    }
}

#[test]
fn la_imagen_decide_las_tecnicas_de_un_exec() {
    assert_eq!(
        tecnicas_de_imagen("/bin/bash"),
        vec![Technique::CommandInterpreter]
    );
    assert_eq!(
        tecnicas_de_imagen("/usr/bin/curl"),
        vec![Technique::IngressToolTransfer]
    );
    assert_eq!(
        tecnicas_de_imagen("/usr/bin/chmod"),
        vec![Technique::PermissionsModification]
    );
    assert_eq!(
        tecnicas_de_imagen("/usr/bin/crontab"),
        vec![Technique::ScheduledTask]
    );
    // `busybox` es interprete y descargador a la vez: por eso la traduccion
    // devuelve una lista y no una tecnica.
    let bb = tecnicas_de_imagen("/bin/busybox");
    assert!(bb.contains(&Technique::CommandInterpreter));
    // Y un binario cualquiera no implica ninguna tecnica.
    assert!(tecnicas_de_imagen("/usr/bin/ls").is_empty());
    assert!(tecnicas_de_imagen("ls").is_empty());
}

#[test]
fn un_exec_real_queda_anotado_en_el_motor_con_su_tecnica() {
    let mut p = BehaviorBridge::new(EngineConfig::default());
    let hijo = dormilon();
    let pid = hijo.id();

    p.ingest(&exec(0x11, pid, "/bin/sh"), 10);

    let key = p.identidad(ProcKey(0x11)).expect("el actor se resolvio");
    let nodo = p.engine().graph().node(key).expect("esta en el grafo");
    assert!(
        nodo.techniques.contains_key(&Technique::CommandInterpreter),
        "un interprete tiene que quedar anotado como T1059"
    );
    // Y no escala por si solo: es lo que evita alertar por cada `cron`.
    assert_eq!(
        p.engine().assess(key).unwrap().action,
        Action::Observe,
        "un interprete suelto no puede escalar"
    );

    matar(hijo);
}

#[test]
fn escribir_la_memoria_de_otro_proceso_es_inyeccion_y_leerla_no() {
    let mut p = BehaviorBridge::new(EngineConfig::default());
    let atacante = dormilon();
    let victima = dormilon();
    p.ingest(&exec(0x21, atacante.id(), "/tmp/implante"), 10);
    p.ingest(&exec(0x22, victima.id(), "/usr/bin/gnome-calculator"), 11);

    let k_atacante = p.identidad(ProcKey(0x21)).unwrap();
    let k_victima = p.identidad(ProcKey(0x22)).unwrap();

    // Leer memoria ajena lo hacen `gdb` y los perfiladores: traducirlo daria un
    // falso positivo por cada uso de un depurador.
    p.ingest(
        &TelemetryEvent::Ptrace {
            actor: ProcKey(0x21),
            source_pid: atacante.id(),
            target_pid: victima.id(),
            request: 0,
            writes_memory: false,
            ts_ns: 12,
        },
        12,
    );
    assert!(
        !p.engine()
            .graph()
            .node(k_atacante)
            .unwrap()
            .techniques
            .contains_key(&Technique::ProcessInjection),
        "leer memoria ajena no es inyeccion"
    );

    // Escribirla si lo es, y ademas crea la arista causal que explica lo que la
    // victima haga a partir de ahora.
    p.ingest(
        &TelemetryEvent::Ptrace {
            actor: ProcKey(0x21),
            source_pid: atacante.id(),
            target_pid: victima.id(),
            request: 0,
            writes_memory: true,
            ts_ns: 13,
        },
        13,
    );
    assert!(p
        .engine()
        .graph()
        .node(k_atacante)
        .unwrap()
        .techniques
        .contains_key(&Technique::ProcessInjection));
    assert_eq!(
        p.engine().graph().causal_path(k_victima),
        vec![k_atacante, k_victima],
        "la victima cuelga causalmente de quien la inyecto, no de su padre"
    );

    matar(atacante);
    matar(victima);
}

#[test]
fn el_cifrado_solo_entra_cuando_el_motor_de_ransomware_lo_confirma() {
    let mut p = BehaviorBridge::new(EngineConfig::default());
    let hijo = dormilon();
    p.ingest(&exec(0x31, hijo.id(), "/usr/bin/tar"), 10);
    let key = p.identidad(ProcKey(0x31)).unwrap();

    // Una escritura de alta entropia NO basta: guardar un `.tar.gz` la produce.
    p.ingest(
        &TelemetryEvent::FileWriteSample {
            actor: ProcKey(0x31),
            pid: hijo.id(),
            fd: 3,
            bytes: 65_536,
            sample: Arc::from(&[0u8; 0][..]),
            distinct_bytes: 250,
            ts_ns: 11,
        },
        11,
    );
    assert!(
        !p.engine()
            .graph()
            .node(key)
            .unwrap()
            .techniques
            .contains_key(&Technique::DataEncryptedForImpact),
        "una escritura de alta entropia sola no puede valer 60 puntos"
    );

    // Confirmado por el motor de ransomware, si.
    let a = p.on_ransom_confirmed(ProcKey(0x31));
    assert!(a.is_some(), "el cifrado confirmado tiene que actuar");
    assert!(p
        .engine()
        .graph()
        .node(key)
        .unwrap()
        .techniques
        .contains_key(&Technique::DataEncryptedForImpact));

    matar(hijo);
}

#[test]
fn la_red_se_traduce_segun_a_donde_va() {
    // Las imagenes son copias de `sleep` con nombres que NO implican ninguna
    // tecnica por si mismos, para que lo unico que anote el motor sea lo que
    // aporta la conexion.
    let lab = Lab::nuevo("red");
    let mut p = BehaviorBridge::new(EngineConfig::default());
    let a = lab.lanzar("beacon");
    let b = lab.lanzar("scanner");
    let c = lab.lanzar("local");
    let ruta = |n: &str| lab.ruta(n).to_string_lossy().into_owned();
    p.ingest(&exec(0x41, a.id(), &ruta("beacon")), 10);
    p.ingest(&exec(0x42, b.id(), &ruta("scanner")), 10);
    p.ingest(&exec(0x43, c.id(), &ruta("local")), 10);

    let conexion = |actor: u64, pid: u32, dport: u16, privado: bool, loopback: bool| {
        TelemetryEvent::NetConnect {
            actor: ProcKey(actor),
            pid,
            daddr: [0; 16],
            dport,
            family: 2,
            loopback,
            private_dst: privado,
            ts_ns: 11,
        }
    };

    p.ingest(&conexion(0x41, a.id(), 443, false, false), 11);
    p.ingest(&conexion(0x42, b.id(), 445, true, false), 11);
    p.ingest(&conexion(0x43, c.id(), 8080, false, true), 11);

    let t = |actor: u64| {
        let k = p.identidad(ProcKey(actor)).unwrap();
        p.engine()
            .graph()
            .node(k)
            .unwrap()
            .techniques
            .keys()
            .copied()
            .collect::<Vec<_>>()
    };
    assert_eq!(t(0x41), vec![Technique::ApplicationLayerProtocol]);
    assert_eq!(
        t(0x42),
        vec![Technique::RemoteServices],
        "SMB en red interna"
    );
    // El trafico contra la propia maquina no dice nada: cualquier servicio
    // local lo genera constantemente.
    assert!(t(0x43).is_empty(), "loopback no se traduce");

    matar(a);
    matar(b);
    matar(c);
}

#[test]
fn tocar_los_registros_del_sistema_es_borrado_de_rastros() {
    let mut p = BehaviorBridge::new(EngineConfig::default());
    let hijo = dormilon();
    p.ingest(&exec(0x51, hijo.id(), "/bin/mv"), 10);
    let key = p.identidad(ProcKey(0x51)).unwrap();

    p.ingest(
        &TelemetryEvent::FileRename {
            actor: ProcKey(0x51),
            pid: hijo.id(),
            from: Arc::from("/var/log/auth.log"),
            to: Arc::from("/tmp/x"),
            ts_ns: 11,
        },
        11,
    );
    assert!(p
        .engine()
        .graph()
        .node(key)
        .unwrap()
        .techniques
        .contains_key(&Technique::IndicatorRemoval));

    matar(hijo);
}

#[test]
fn un_actor_desconocido_no_rompe_la_ingesta() {
    // Procesos que ya existian antes de arrancar el agente generan eventos cuyo
    // actor el puente nunca vio nacer. Tienen que ignorarse sin panico.
    let mut p = BehaviorBridge::new(EngineConfig::default());
    let salida = p.ingest(
        &TelemetryEvent::NetConnect {
            actor: ProcKey(0xDEAD),
            pid: 4_294_967_290,
            daddr: [0; 16],
            dport: 443,
            family: 2,
            loopback: false,
            private_dst: false,
            ts_ns: 1,
        },
        1,
    );
    assert!(salida.is_empty());
    assert_eq!(p.engine().stats().observaciones, 0);
}

#[test]
fn el_linaje_lo_fija_la_sonda_y_no_el_padre_actual_de_procfs() {
    // Un proceso que se desliga —su padre muere y `init` lo adopta— conserva en
    // el grafo la arista con quien lo lanzo de verdad. Sin esto, desligarse
    // borraria el linaje del incidente, que es justo para lo que se hace.
    let mut p = BehaviorBridge::new(EngineConfig::default());
    let padre = dormilon();
    let hijo = dormilon();
    p.ingest(&exec(0x61, padre.id(), "/bin/sh"), 10);
    p.ingest(&exec_hijo_de(0x62, 0x61, hijo.id(), "/usr/bin/curl"), 11);

    let k_padre = p.identidad(ProcKey(0x61)).unwrap();
    let k_hijo = p.identidad(ProcKey(0x62)).unwrap();
    assert_eq!(
        p.engine().graph().causal_path(k_hijo),
        vec![k_padre, k_hijo],
        "el linaje es el que dijo la sonda, no el que diga procfs ahora"
    );

    matar(padre);
    matar(hijo);
}

#[test]
fn la_cadena_de_ejecucion_remota_llega_al_aislamiento_desde_telemetria_real() {
    // La prueba de extremo a extremo de la fase: procesos REALES cuyo
    // `/proc/<pid>/exe` es el que la cadena necesita, solo eventos de
    // telemetria, ninguna tecnica anotada a mano y ninguna arista puesta a mano.
    let lab = Lab::nuevo("rce");
    let mut p = BehaviorBridge::new(EngineConfig::default());

    let nginx = lab.lanzar("nginx");
    let sh = lab.lanzar("sh");
    let curl = lab.lanzar("curl");
    let chmod = lab.lanzar("chmod");
    let carga = lab.lanzar(".update");

    let ruta = |n: &str| lab.ruta(n).to_string_lossy().into_owned();
    p.ingest(&exec(1, nginx.id(), &ruta("nginx")), 1);
    p.ingest(&exec_hijo_de(2, 1, sh.id(), &ruta("sh")), 2);
    p.ingest(&exec_hijo_de(3, 2, curl.id(), &ruta("curl")), 3);
    p.ingest(&exec_hijo_de(4, 2, chmod.id(), &ruta("chmod")), 4);
    let decisiones = p.ingest(&exec_hijo_de(5, 2, carga.id(), &ruta(".update")), 5);

    let k_carga = p.identidad(ProcKey(5)).unwrap();
    let a = p.engine().assess(k_carga).unwrap();
    assert!(
        a.score.chains.contains(&"web-rce"),
        "la cadena tiene que verse desde telemetria pura: {:?} (imagen resuelta {:?})",
        a.score.chains,
        p.engine().graph().node(k_carga).unwrap().image
    );
    assert_eq!(a.action, Action::Isolate, "puntuo {}", a.score.total);
    assert!(
        decisiones
            .iter()
            .any(|d| d.key == k_carga && d.action == Action::Isolate),
        "el aislamiento tiene que llegar en la propia ingesta: {decisiones:?}"
    );

    for c in [nginx, sh, curl, chmod, carga] {
        matar(c);
    }
}
