//! Pruebas de la capa de abstraccion del sistema.
//!
//! El criterio de estas pruebas es que TODO lo que se pueda comprobar contra el
//! sistema de verdad se comprueba contra el sistema de verdad: procesos que se
//! lanzan y se matan, ficheros que se crean en un directorio vigilado por
//! inotify, memoria propia leida con `process_vm_readv` y, si la maquina lo
//! permite, reglas puestas y quitadas en nftables. Una capa de abstraccion
//! probada solo con valores inventados demuestra que el codigo compila, no que
//! abstrae nada.

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;

use aegis_prueba::{omitir, Requisito};
use aegis_scal::error::ScalError;
use aegis_scal::fsmon::{FileAction, FileSystemMonitor};
use aegis_scal::memory::{MemoryInspector, RegionClass};
use aegis_scal::netfilter::{BlockReason, NetworkFilter};
use aegis_scal::platform::{Platform, Support};
use aegis_scal::process::{ProcessEvent, ProcessKey, ProcessLifecycleProvider, ProcessState};
use aegis_scal::{Capabilities, SystemCore};

// ---------------------------------------------------------------------------
// Utillaje
// ---------------------------------------------------------------------------

struct Lab(PathBuf);
impl Lab {
    fn nuevo(n: &str) -> Lab {
        let p = std::env::temp_dir().join(format!("aegis-scal-{n}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Lab(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for Lab {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Lanza un proceso que se queda dormido, para tenerlo vivo mientras dure la
/// prueba.
fn dormilon() -> Child {
    Command::new("/bin/sh")
        .args(["-c", "sleep 300"])
        .spawn()
        .expect("no se pudo lanzar el proceso de prueba")
}

/// Mata y RECOLECTA un hijo.
///
/// Recolectarlo no es opcional en estas pruebas: un proceso muerto sin
/// recolectar es un zombi, y un zombi conserva su `/proc/<pid>/stat`, con lo que
/// el censo lo sigue viendo vivo. Sin el `wait`, la prueba de deteccion de
/// muertes no fallaria por un defecto del codigo sino por la prueba.
fn matar(mut c: Child) {
    let _ = c.kill();
    let _ = c.wait();
}

// ---------------------------------------------------------------------------
// Analisis de /proc/<pid>/stat
// ---------------------------------------------------------------------------

#[test]
fn el_analizador_de_stat_sobrevive_a_un_nombre_con_parentesis() {
    use aegis_scal::linux::process::parse_stat;

    // Un nombre de ejecutable puede llevar espacios Y parentesis. Trocear la
    // linea desde el principio da un ppid aleatorio, que es el defecto clasico
    // de este analizador.
    let linea = "4242 (mi (raro) proc) S 99 4242 4242 0 -1 4194304 100 0 0 0 \
                 1 2 0 0 20 0 7 0 987654 1234 5678 ...";
    let (estado, ppid, hilos, arranque) = parse_stat(linea).expect("tiene que analizarse");
    assert_eq!(estado, ProcessState::Sleeping);
    assert_eq!(ppid, 99, "el ppid es el campo 4, tras el ULTIMO parentesis");
    assert_eq!(hilos, 7);
    assert_eq!(arranque, 987_654);
}

#[test]
fn el_analizador_de_stat_reconoce_los_estados() {
    use aegis_scal::linux::process::parse_stat;
    let base = |estado: &str| format!("1 (x) {estado} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 0 500 0");
    for (letra, esperado) in [
        ("R", ProcessState::Running),
        ("S", ProcessState::Sleeping),
        ("D", ProcessState::Uninterruptible),
        ("T", ProcessState::Stopped),
        ("Z", ProcessState::Zombie),
        ("X", ProcessState::Other),
    ] {
        let (e, _, _, arranque) = parse_stat(&base(letra)).unwrap();
        assert_eq!(e, esperado, "estado {letra}");
        assert_eq!(arranque, 500);
    }
}

#[test]
fn el_analizador_de_cmdline_trocea_por_nul() {
    use aegis_scal::linux::process::parse_cmdline;
    assert_eq!(
        parse_cmdline(b"/bin/sh\0-c\0echo hola\0"),
        vec!["/bin/sh", "-c", "echo hola"]
    );
    // Un hilo de kernel tiene la linea vacia; un servidor que reescribio su
    // titulo la tiene sin NUL. Ninguno de los dos es un error.
    assert!(parse_cmdline(b"").is_empty());
    assert_eq!(parse_cmdline(b"titulo reescrito"), vec!["titulo reescrito"]);
}

// ---------------------------------------------------------------------------
// Ciclo de vida de procesos sobre procfs
// ---------------------------------------------------------------------------

fn proveedor() -> aegis_scal::linux::process::ProcFsProcesses {
    aegis_scal::linux::process::ProcFsProcesses::con_intervalo(Duration::from_millis(20))
}

#[test]
fn el_censo_ve_este_mismo_proceso() {
    let p = proveedor();
    let yo = std::process::id();
    let info = p.info(yo).expect("el proceso de prueba existe");

    assert_eq!(info.key.pid, yo);
    assert!(info.key.start_stamp > 0, "la marca de arranque es real");
    assert!(
        info.image
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .contains("scal"),
        "la imagen resuelta es el binario de la prueba: {:?}",
        info.image
    );
    assert!(!info.cmdline.is_empty());
    assert!(info.threads >= 1);

    let lista = p.list().unwrap();
    assert!(
        lista.iter().any(|i| i.key.pid == yo),
        "la enumeracion incluye este proceso"
    );
    assert!(lista.len() > 1, "hay mas de un proceso en la maquina");
}

#[test]
fn la_identidad_distingue_un_pid_reciclado() {
    let p = proveedor();
    let yo = std::process::id();
    let real = p.key_of(yo).unwrap();

    assert!(p.is_alive(real), "la identidad real esta viva");
    // Mismo PID, arranque distinto: es OTRO proceso. Si esto diera cierto, el
    // historial de un proceso se heredaria al que reutilice su numero.
    let impostor = ProcessKey::new(yo, real.start_stamp + 1);
    assert!(
        !p.is_alive(impostor),
        "un PID reciclado no es el mismo proceso"
    );
    assert_ne!(real, impostor);
}

#[test]
fn un_proceso_inexistente_da_no_such_process() {
    let p = proveedor();
    // Por encima de cualquier pid_max razonable.
    let e = p.info(4_294_967_290).unwrap_err();
    assert!(matches!(e, ScalError::NoSuchProcess(_)), "llego {e:?}");
    assert!(
        e.is_transient(),
        "que un proceso no exista no aborta un barrido"
    );
}

#[test]
fn los_hijos_directos_se_resuelven() {
    let p = proveedor();
    let hijo = dormilon();
    let pid_hijo = hijo.id();

    let hijos = p.children_of(std::process::id()).unwrap();
    assert!(
        hijos.contains(&pid_hijo),
        "el hijo {pid_hijo} tiene que aparecer entre {hijos:?}"
    );

    matar(hijo);
}

#[test]
fn el_censo_detecta_nacimientos_y_muertes_reales() {
    let mut p = proveedor();

    // Nacimiento: el censo inicial se tomo al construir, asi que este proceso
    // es genuinamente nuevo para el proveedor.
    let hijo = dormilon();
    let pid = hijo.id();

    let mut clave = None;
    for _ in 0..40 {
        for ev in p.poll(Duration::from_millis(100)).unwrap() {
            if let ProcessEvent::Started(info) = &ev {
                if info.key.pid == pid {
                    clave = Some(info.key);
                }
            }
        }
        if clave.is_some() {
            break;
        }
    }
    let clave = clave.expect("el censo tiene que ver nacer al proceso de prueba");

    // Muerte: se mata Y se recolecta, porque un zombi sigue teniendo `stat`.
    matar(hijo);

    let mut visto_muerto = false;
    for _ in 0..40 {
        for ev in p.poll(Duration::from_millis(100)).unwrap() {
            if ev
                == (ProcessEvent::Exited {
                    key: clave,
                    exit_code: None,
                })
            {
                visto_muerto = true;
            }
        }
        if visto_muerto {
            break;
        }
    }
    assert!(visto_muerto, "el censo tiene que ver morir al proceso");
}

#[test]
fn el_primer_censo_no_reporta_lo_que_ya_existia() {
    // Si el censo inicial no se tomara en la construccion, la primera llamada
    // reportaria como recien nacidos los cientos de procesos de la maquina, y
    // un motor conductual escalaria todo el sistema en el arranque.
    let mut p = proveedor();
    assert!(p.censados() > 1, "hay procesos en la maquina");
    let eventos = p.poll(Duration::from_millis(0)).unwrap();
    let nacimientos = eventos
        .iter()
        .filter(|e| matches!(e, ProcessEvent::Started(_)))
        .count();
    assert!(
        nacimientos < p.censados() / 2,
        "el arranque no puede reportar la maquina entera como nueva ({nacimientos} de {})",
        p.censados()
    );
}

#[test]
fn la_reconciliacion_evita_reportar_dos_veces_el_mismo_nacimiento() {
    let mut p = proveedor();
    let hijo = dormilon();
    let pid = hijo.id();
    // Otra fuente (la sonda de eBPF, en produccion) ya vio el nacimiento.
    let clave = p.key_of(pid).unwrap();
    p.reconciliar_alta(clave);

    let eventos = p.poll(Duration::from_millis(0)).unwrap();
    assert!(
        !eventos
            .iter()
            .any(|e| matches!(e, ProcessEvent::Started(i) if i.key == clave)),
        "un nacimiento ya conocido no se puede reportar otra vez"
    );

    matar(hijo);
}

// ---------------------------------------------------------------------------
// Vigilancia del sistema de ficheros
// ---------------------------------------------------------------------------

#[test]
fn inotify_ve_los_cambios_de_verdad() {
    let lab = Lab::nuevo("fs");
    let mut m = aegis_scal::linux::fsmon::InotifyMonitor::new().unwrap();
    m.watch(lab.path()).unwrap();
    assert_eq!(FileSystemMonitor::watched(&m), 1);

    let f = lab.path().join("victima.conf");
    std::fs::write(&f, b"contenido inicial").unwrap();

    let mut vistos = Vec::new();
    for _ in 0..20 {
        vistos.extend(m.poll(Duration::from_millis(200)).unwrap());
        if vistos.iter().any(|e| e.path == f) {
            break;
        }
    }
    assert!(
        vistos
            .iter()
            .any(|e| e.path == f && e.kind == FileAction::Created),
        "crear un fichero tiene que verse: {vistos:?}"
    );

    // Un cambio de contenido tiene que distinguirse de uno de atributos: el
    // primero obliga a rehashear y el segundo no.
    std::fs::write(&f, b"contenido alterado por el atacante").unwrap();
    let mut modificado = false;
    for _ in 0..20 {
        if m.poll(Duration::from_millis(200))
            .unwrap()
            .iter()
            .any(|e| e.path == f && e.kind == FileAction::Modified)
        {
            modificado = true;
            break;
        }
    }
    assert!(modificado, "modificar el contenido tiene que verse");
}

#[test]
fn vigilar_un_directorio_inexistente_da_un_error_util() {
    let mut m = aegis_scal::linux::fsmon::InotifyMonitor::new().unwrap();
    let e = m
        .watch(Path::new("/no/existe/este/directorio/aegis"))
        .unwrap_err();
    assert!(matches!(e, ScalError::BadPath { .. }), "llego {e:?}");
}

#[test]
fn la_clasificacion_de_cambios_dice_cuando_hay_que_rehashear() {
    assert!(FileAction::Modified.touches_content());
    assert!(FileAction::Created.touches_content());
    assert!(FileAction::MovedIn.touches_content());
    // Cambiar permisos altera la linea base pero no el hash: rehashear por eso
    // es gasto puro sobre ficheros que pueden ser enormes.
    assert!(!FileAction::Attributes.touches_content());
    assert!(FileAction::Deleted.removes_entry());
    assert!(FileAction::MovedOut.removes_entry());
    assert!(!FileAction::Modified.removes_entry());
}

// ---------------------------------------------------------------------------
// Lectura de memoria
// ---------------------------------------------------------------------------

#[test]
fn se_lee_la_memoria_propia_y_coincide_byte_a_byte() {
    let insp = aegis_scal::linux::memory::ProcMemoryInspector::new();
    let yo = std::process::id();

    let testigo: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    let addr = testigo.as_ptr() as u64;

    let leido = insp.read(yo, addr, testigo.len()).unwrap();
    assert_eq!(
        leido, testigo,
        "la lectura tiene que ser identica al original"
    );

    let regiones = insp.regions(yo).unwrap();
    assert!(regiones.len() > 3, "un proceso real tiene varias regiones");
    assert!(
        regiones.iter().any(|r| r.start <= addr && addr < r.end),
        "la direccion del testigo cae dentro de alguna region enumerada"
    );
    assert!(
        regiones.iter().any(|r| r.class() == RegionClass::FileExec),
        "el codigo del propio binario esta respaldado por fichero"
    );
    assert_eq!(insp.platform(), Platform::Linux);
}

#[test]
fn leer_un_proceso_que_no_existe_no_es_un_fallo_opaco() {
    let insp = aegis_scal::linux::memory::ProcMemoryInspector::new();
    let e = insp.regions(4_294_967_290).unwrap_err();
    assert!(matches!(e, ScalError::NoSuchProcess(_)), "llego {e:?}");
}

#[test]
fn las_regiones_anonimas_ejecutables_se_aislan() {
    let insp = aegis_scal::linux::memory::ProcMemoryInspector::new();
    let yo = std::process::id();
    let anon = insp.executable_anonymous(yo).unwrap();
    // Este binario no usa JIT, asi que no deberia tener casi nada; lo que
    // importa es que el filtro sea consistente con la clasificacion.
    for r in &anon {
        assert!(r.perms.exec);
        assert_eq!(r.class(), RegionClass::AnonymousExec);
    }
}

// ---------------------------------------------------------------------------
// Filtro de red
// ---------------------------------------------------------------------------

#[test]
fn el_conjunto_de_reglas_no_borra_los_bloqueos_al_reinstalarse() {
    let f = aegis_scal::linux::netfilter::NftablesFilter::dry_run();
    let reglas = f.ruleset();
    // Vaciar las CADENAS antes de reponerlas es lo que hace idempotente la
    // instalacion; vaciar la TABLA borraria los bloqueos vigentes en cada
    // arranque del agente, que es lo que un atacante querria provocar.
    assert!(reglas.contains("flush chain inet aegis_scal ingress"));
    assert!(reglas.contains("flush chain inet aegis_scal egress"));
    assert!(!reglas.contains("flush table"));
    assert!(
        reglas.contains("flags timeout"),
        "la caducidad la lleva el kernel"
    );
    assert!(reglas.contains("ip saddr @blk4 drop"));
    assert!(reglas.contains("ip6 daddr @blk6 drop"));
    // En seco no se promete contencion.
    assert!(!f.available());
}

#[test]
fn se_recuperan_las_direcciones_bloqueadas_de_la_salida_de_nft() {
    use aegis_scal::linux::netfilter::{parse_duracion_nft, parse_elements};

    let salida = "table inet aegis_scal {\n\
                  \tset blk4 {\n\
                  \t\ttype ipv4_addr\n\
                  \t\tflags timeout\n\
                  \t\telements = { 192.0.2.1 timeout 10m expires 9m58s comment \"recon\",\n\
                  \t\t             198.51.100.7 comment \"c2\" }\n\
                  \t}\n\
                  }\n";
    let v = parse_elements(salida, BlockReason::Manual);
    assert_eq!(v.len(), 2);
    assert_eq!(v[0].addr.to_string(), "192.0.2.1");
    assert_eq!(v[0].reason, BlockReason::Reconnaissance);
    // Interesa `timeout` (lo pedido), no `expires` (lo que queda), que cambia
    // en cada lectura y haria inestable cualquier comparacion.
    assert_eq!(v[0].ttl, Some(Duration::from_secs(600)));
    assert_eq!(v[1].addr.to_string(), "198.51.100.7");
    assert_eq!(v[1].reason, BlockReason::CommandAndControl);
    assert_eq!(v[1].ttl, None);

    assert!(parse_elements("set vacio {}", BlockReason::Manual).is_empty());

    assert_eq!(
        parse_duracion_nft("1d2h3m4s"),
        Some(Duration::from_secs(93_784))
    );
    assert_eq!(parse_duracion_nft("600"), Some(Duration::from_secs(600)));
    assert_eq!(parse_duracion_nft("nada"), None);
}

#[test]
fn nftables_bloquea_y_desbloquea_de_verdad() {
    let f = aegis_scal::linux::netfilter::NftablesFilter::new();
    if !f.available() {
        omitir(
            "nftables no esta disponible en esta maquina",
            Requisito::Herramienta("nft"),
        );
        return;
    }
    // Se limpia lo que hubiera antes para no arrastrar estado de otra prueba.
    f.flush().unwrap();

    // TEST-NET-1 y TEST-NET-2 (RFC 5737): documentacion, jamas enrutadas.
    let v4: std::net::IpAddr = "192.0.2.66".parse().unwrap();
    let v6: std::net::IpAddr = "2001:db8::dead".parse().unwrap();

    f.block(
        v4,
        BlockReason::Reconnaissance,
        Some(Duration::from_secs(120)),
    )
    .unwrap();
    f.block(v6, BlockReason::CommandAndControl, None).unwrap();
    // Bloquear dos veces no puede fallar: la respuesta automatica repite.
    f.block(
        v4,
        BlockReason::Reconnaissance,
        Some(Duration::from_secs(120)),
    )
    .unwrap();

    let bloqueadas = f.blocked().unwrap();
    let uno = bloqueadas
        .iter()
        .find(|b| b.addr == v4)
        .expect("la IPv4 tiene que estar bloqueada");
    assert_eq!(uno.reason, BlockReason::Reconnaissance);
    assert_eq!(uno.ttl, Some(Duration::from_secs(120)));
    assert!(
        bloqueadas.iter().any(|b| b.addr == v6),
        "la IPv6 tiene que estar bloqueada"
    );

    f.unblock(v4).unwrap();
    // Desbloquear algo que ya no esta tampoco puede fallar.
    f.unblock(v4).unwrap();
    assert!(!f.blocked().unwrap().iter().any(|b| b.addr == v4));

    f.flush().unwrap();
    assert!(
        f.blocked().unwrap().is_empty(),
        "flush deja el sistema limpio"
    );
    // Y retirar dos veces es idempotente.
    f.flush().unwrap();
}

// ---------------------------------------------------------------------------
// Capacidades y esqueletos de otras plataformas
// ---------------------------------------------------------------------------

#[test]
fn linux_declara_lo_que_de_verdad_puede() {
    let c: Capabilities = aegis_scal::capabilities();
    assert_eq!(c.platform, Platform::Linux);
    assert!(c.complete(), "en Linux no falta ninguna capacidad");
    assert!(c.process_query.is_native());
    assert!(c.memory_inspection.is_native());
    // El censo de `/proc` es correcto pero tiene ventana ciega, y la capa lo
    // dice en vez de venderlo como nativo: una regla que asuma eventos
    // inmediatos tiene que poder enterarse.
    assert!(matches!(c.process_events, Support::Degraded(_)));
    assert!(c.process_events.is_usable());
    assert!(!c.process_events.is_native());
}

#[test]
fn los_esqueletos_de_otras_plataformas_no_fingen_estar_limpios() {
    for (plat, caps) in [
        (
            Platform::Windows,
            aegis_scal::capabilities_of(Platform::Windows),
        ),
        (
            Platform::MacOs,
            aegis_scal::capabilities_of(Platform::MacOs),
        ),
    ] {
        assert_eq!(caps.platform, plat);
        assert!(!caps.complete());
        assert_eq!(caps.missing().len(), 5, "en {plat} falta todo, y se dice");
        for (_, motivo) in caps.missing() {
            assert!(
                motivo.starts_with("falta "),
                "el motivo nombra la interfaz que falta, no dice 'TODO': {motivo}"
            );
        }
    }
}

#[test]
fn un_esqueleto_devuelve_error_y_no_una_lista_vacia() {
    // Una lista vacia se lee como "no hay nada malo en esta maquina". El
    // esqueleto tiene que ser ruidoso.
    let w = aegis_scal::windows::EtwProcesses;
    let e = w.list().unwrap_err();
    assert!(e.is_unsupported(), "llego {e:?}");
    assert!(
        e.to_string().contains("windows"),
        "el error dice en que plataforma: {e}"
    );
    assert!(!w.is_alive(ProcessKey::new(1, 1)));

    let m = aegis_scal::macos::MachMemoryInspector;
    assert!(m.regions(1).unwrap_err().is_unsupported());
    assert_eq!(m.platform(), Platform::MacOs);

    let f = aegis_scal::macos::NetworkExtensionFilter;
    assert!(!f.available());
    assert!(f.blocked().unwrap_err().is_unsupported());

    let mut fs = aegis_scal::windows::DirectoryChangesMonitor;
    assert!(fs.watch(Path::new("/tmp")).unwrap_err().is_unsupported());
    assert_eq!(FileSystemMonitor::watched(&fs), 0);
}

#[test]
fn el_nucleo_del_sistema_se_construye_y_habla_por_los_rasgos() {
    let mut core = SystemCore::host().expect("los backends del anfitrion arrancan");
    assert_eq!(core.capabilities().platform, Platform::HOST);
    assert_eq!(core.processes.platform(), Platform::HOST);
    assert_eq!(core.memory.platform(), Platform::HOST);

    // Se usa SOLO por los rasgos: si esto compilase con algo especifico de
    // Linux, la capa no habria servido para nada.
    let yo = std::process::id();
    let clave = core.processes.key_of(yo).unwrap();
    assert!(core.processes.is_alive(clave));
    assert!(!core.memory.regions(yo).unwrap().is_empty());

    let lab = Lab::nuevo("core");
    core.files.watch(lab.path()).unwrap();
    assert_eq!(core.files.watched(), 1);
    assert!(core.processes.poll(Duration::from_millis(1)).is_ok());
}

#[test]
fn la_plataforma_anfitriona_se_nombra_igual_en_todas_partes() {
    assert_eq!(Platform::HOST.as_str(), "linux");
    assert_eq!(Platform::HOST.to_string(), "linux");
    assert_eq!(aegis_scal::capabilities().platform, Platform::HOST);
}
