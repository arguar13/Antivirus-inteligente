//! Pruebas del puente entre la telemetria de eBPF y la capa de abstraccion.
//!
//! Las de ciclo de vida se hacen con PROCESOS DE VERDAD: se lanza uno, se
//! fabrica el evento de eBPF que la sonda habria emitido por el, y se comprueba
//! que el puente resuelve su identidad contra `procfs` y no la inventa. Con
//! valores inventados de principio a fin, la propiedad que importa —que las dos
//! fuentes converjan en la MISMA identidad— no se estaria probando.

use std::process::{Child, Command};
use std::sync::Arc;
use std::time::Duration;

use aegis_agent::graph::ProcKey;
use aegis_agent::scal::{eventos_de_fichero, EbpfProcessProvider};
use aegis_agent::triage::TelemetryEvent;
use aegis_scal::fsmon::FileAction;
use aegis_scal::process::{ProcessEvent, ProcessLifecycleProvider};

fn dormilon() -> Child {
    Command::new("/bin/sh")
        .args(["-c", "sleep 300"])
        .spawn()
        .unwrap()
}

fn matar(mut c: Child) {
    let _ = c.kill();
    let _ = c.wait();
}

fn exec(actor: u64, pid: u32) -> TelemetryEvent {
    TelemetryEvent::Exec {
        actor: ProcKey(actor),
        pid,
        parent: ProcKey(1),
        image: Arc::from("/bin/sh"),
        cmdline: Arc::from("/bin/sh -c sleep 300"),
        started_ns: 1_000,
        ts_ns: 1_000,
    }
}

#[test]
fn un_exec_de_ebpf_se_convierte_en_un_nacimiento_con_identidad_de_procfs() {
    let mut p = EbpfProcessProvider::new();
    let hijo = dormilon();
    let pid = hijo.id();

    // La identidad que `procfs` considera correcta para ese proceso.
    let esperada = p.key_of(pid).unwrap();

    assert!(p.ingest(&exec(0xAA, pid)), "el exec produce un evento");
    assert_eq!(p.seguidos(), 1);
    assert_eq!(p.perdidos(), 0);

    let eventos = p.poll(Duration::from_millis(0)).unwrap();
    let ProcessEvent::Started(info) = &eventos[0] else {
        panic!("se esperaba un nacimiento, llego {:?}", eventos[0]);
    };
    assert_eq!(
        info.key, esperada,
        "la identidad la fija procfs, no el reloj de la sonda"
    );
    assert_eq!(info.key.pid, pid);
    assert!(info.key.start_stamp > 0);
    // El retrato lo completa procfs con lo que la sonda no trae.
    assert!(info.threads >= 1);
    // Y lo completa con la imagen REAL, no con la que se invoco: `/bin/sh` es
    // un enlace, y `procfs` resuelve el binario al que apunta. Es la propiedad
    // que se quiere —un atacante que ejecute por un enlace no cambia lo que el
    // agente registra— y por eso se compara contra el destino canonico.
    let real = std::fs::canonicalize("/bin/sh").unwrap();
    assert_eq!(info.image.as_deref(), Some(real.as_path()));

    matar(hijo);
}

#[test]
fn el_nacimiento_visto_por_ebpf_no_se_reporta_otra_vez_por_el_censo() {
    let mut p = EbpfProcessProvider::new();
    let hijo = dormilon();
    let pid = hijo.id();

    p.ingest(&exec(0xBB, pid));
    let primeros = p.poll(Duration::from_millis(0)).unwrap();
    assert_eq!(primeros.len(), 1);

    // La segunda vuelta cae al censo. Si el puente no hubiera reconciliado, el
    // censo veria el proceso como nuevo y el motor conductual contaria la misma
    // cadena dos veces.
    let segundos = p.poll(Duration::from_millis(0)).unwrap();
    assert!(
        !segundos
            .iter()
            .any(|e| matches!(e, ProcessEvent::Started(i) if i.key.pid == pid)),
        "el mismo nacimiento no puede llegar dos veces: {segundos:?}"
    );

    matar(hijo);
}

#[test]
fn un_exit_de_ebpf_recupera_la_identidad_del_proceso_ya_desaparecido() {
    let mut p = EbpfProcessProvider::new();
    let hijo = dormilon();
    let pid = hijo.id();
    let esperada = p.key_of(pid).unwrap();

    p.ingest(&exec(0xCC, pid));
    let _ = p.poll(Duration::from_millis(0)).unwrap();

    // El proceso muere de verdad y se recolecta: `/proc/<pid>` ya no existe.
    matar(hijo);
    assert!(p.info(pid).is_err(), "el proceso ya no esta en procfs");

    // Aun asi, el puente sabe de quien era la salida, porque guardo la
    // identidad al nacer. Sin ese mapa, una muerte seria irresoluble.
    assert!(p.ingest(&TelemetryEvent::Exit {
        actor: ProcKey(0xCC),
        ts_ns: 2_000,
    }));
    let eventos = p.poll(Duration::from_millis(0)).unwrap();
    assert!(
        eventos.contains(&ProcessEvent::Exited {
            key: esperada,
            exit_code: None,
        }),
        "la muerte tiene que llegar con la identidad correcta: {eventos:?}"
    );
    assert_eq!(p.seguidos(), 0, "la identidad se libera al morir");
}

#[test]
fn un_exec_de_un_proceso_ya_muerto_se_cuenta_como_perdido_y_no_se_inventa() {
    let mut p = EbpfProcessProvider::new();
    // PID por encima de cualquier pid_max: la sonda pudo emitirlo y el proceso
    // desaparecio antes de que el agente drenara el ring.
    assert!(!p.ingest(&exec(0xDD, 4_294_967_290)));
    assert_eq!(
        p.perdidos(),
        1,
        "se cuenta, no se fabrica una identidad falsa"
    );
    assert_eq!(p.seguidos(), 0);
    assert!(p
        .poll(Duration::from_millis(0))
        .unwrap()
        .iter()
        .all(|e| e.key().pid != 4_294_967_290));
}

#[test]
fn una_salida_sin_nacimiento_conocido_no_inventa_una_muerte() {
    let mut p = EbpfProcessProvider::new();
    // Proceso que ya existia antes de arrancar el agente: nunca se vio nacer.
    assert!(!p.ingest(&TelemetryEvent::Exit {
        actor: ProcKey(0xEE),
        ts_ns: 1,
    }));
}

#[test]
fn el_puente_responde_las_consultas_por_el_rasgo() {
    let p = EbpfProcessProvider::new();
    let yo = std::process::id();
    assert_eq!(p.platform(), aegis_scal::Platform::Linux);
    let clave = p.key_of(yo).unwrap();
    assert!(p.is_alive(clave));
    assert_eq!(p.info(yo).unwrap().key, clave);
    assert!(p.list().unwrap().iter().any(|i| i.key.pid == yo));

    let hijo = dormilon();
    assert!(p.children_of(yo).unwrap().contains(&hijo.id()));
    matar(hijo);
}

#[test]
fn un_renombrado_se_traduce_a_las_dos_mitades_del_movimiento() {
    let ev = TelemetryEvent::FileRename {
        actor: ProcKey(1),
        pid: 10,
        from: Arc::from("/etc/passwd"),
        to: Arc::from("/tmp/passwd.bak"),
        ts_ns: 5,
    };
    let v = eventos_de_fichero(&ev);
    assert_eq!(v.len(), 2, "mover es salir de un sitio Y entrar en otro");
    assert_eq!(v[0].path.to_str(), Some("/etc/passwd"));
    assert_eq!(v[0].kind, FileAction::MovedOut);
    assert_eq!(v[1].path.to_str(), Some("/tmp/passwd.bak"));
    assert_eq!(v[1].kind, FileAction::MovedIn);
}

#[test]
fn una_escritura_se_traduce_y_lo_que_no_es_de_disco_no_se_traduce() {
    let escritura = TelemetryEvent::FileWrite {
        actor: ProcKey(1),
        pid: 10,
        path: Arc::from("/etc/shadow"),
        flags: 0,
        ts_ns: 5,
    };
    let v = eventos_de_fichero(&escritura);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].kind, FileAction::Modified);

    // Una conexion de red no es un cambio de fichero. Forzarla a serlo seria
    // exactamente la traduccion falsa que esta capa evita.
    let conexion = TelemetryEvent::NetConnect {
        actor: ProcKey(1),
        pid: 10,
        daddr: [0; 16],
        dport: 443,
        family: 2,
        loopback: false,
        private_dst: false,
        ts_ns: 6,
    };
    assert!(eventos_de_fichero(&conexion).is_empty());
    assert!(eventos_de_fichero(&exec(1, 1)).is_empty());
}
