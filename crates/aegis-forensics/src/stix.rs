//! Exportacion a STIX 2.1.
//!
//! # Por que STIX y no un formato propio
//!
//! Un informe forense que solo entiende AegisCore obliga al equipo a copiar los
//! indicadores a mano en su plataforma de inteligencia, su SIEM y su EDR de
//! terceros. STIX 2.1 es el formato que todos ellos leen, asi que exportar en el
//! convierte un incidente en algo que se puede buscar en el resto de la flota
//! **el mismo dia**, que es cuando sirve.
//!
//! # Identificadores: por que hay SHA-1 en un producto de seguridad
//!
//! STIX 2.1 exige que los objetos observables (SCO) lleven un UUID de version 5
//! calculado sobre sus propiedades identificativas, y UUIDv5 esta definido sobre
//! SHA-1. No es una eleccion: es lo que hace que dos herramientas distintas que
//! observen el MISMO fichero produzcan el MISMO identificador, que es la base de
//! la deduplicacion entre plataformas.
//!
//! Ese SHA-1 no protege nada y no se usa jamas para integridad —para eso el
//! producto usa SHA-256 y BLAKE3—. Se implementa aqui, en cincuenta lineas
//! auditables, en vez de traer una dependencia para una funcion que solo sirve
//! para nombrar.
//!
//! Los objetos de dominio (SDO) llevan UUIDv4, como manda la especificacion, y
//! por eso el bundle no es reproducible byte a byte: [`to_bundle_with`] permite
//! fijarlos para poder compararlo en las pruebas.

use crate::artifacts::{IncidentArtifacts, ProcessArtifact, SocketArtifact};
use crate::json::{array, Obj};

/// Espacio de nombres para los UUIDv5 de los observables, fijado por STIX 2.1.
pub const NS_SCO: [u8; 16] = [
    0x00, 0xab, 0xed, 0xb4, 0xaa, 0x42, 0x46, 0x6c, 0x9c, 0x01, 0xfe, 0xd2, 0x33, 0x15, 0xa9, 0xb7,
];

// ---------------------------------------------------------------------------
// SHA-1, solo para nombrar
// ---------------------------------------------------------------------------

/// SHA-1 de un mensaje.
///
/// **No es una primitiva de seguridad de este producto.** Existe unicamente
/// porque UUIDv5 —que STIX exige para los observables— esta definido sobre ella.
/// Cualquier uso para integridad o autenticacion seria un defecto.
pub fn sha1(msg: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

    // Relleno: un bit a uno, ceros, y la longitud en bits como big-endian de 64.
    let mut datos = msg.to_vec();
    let bits = (msg.len() as u64) * 8;
    datos.push(0x80);
    while datos.len() % 64 != 56 {
        datos.push(0);
    }
    datos.extend_from_slice(&bits.to_be_bytes());

    for bloque in datos.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, palabra) in bloque.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([palabra[0], palabra[1], palabra[2], palabra[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }

    let mut salida = [0u8; 20];
    for (i, v) in h.iter().enumerate() {
        salida[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    salida
}

/// Formatea 16 bytes como un UUID canonico.
pub fn formato_uuid(b: &[u8; 16]) -> String {
    let h = |r: &[u8]| -> String { r.iter().map(|x| format!("{x:02x}")).collect() };
    format!(
        "{}-{}-{}-{}-{}",
        h(&b[0..4]),
        h(&b[4..6]),
        h(&b[6..8]),
        h(&b[8..10]),
        h(&b[10..16])
    )
}

/// UUID de version 5: SHA-1 del espacio de nombres concatenado con el nombre.
pub fn uuid_v5(namespace: &[u8; 16], nombre: &[u8]) -> String {
    let mut msg = Vec::with_capacity(16 + nombre.len());
    msg.extend_from_slice(namespace);
    msg.extend_from_slice(nombre);
    let d = sha1(&msg);
    let mut u = [0u8; 16];
    u.copy_from_slice(&d[..16]);
    // Version 5 en el nibble alto del byte 6, variante RFC 4122 en el byte 8.
    u[6] = (u[6] & 0x0f) | 0x50;
    u[8] = (u[8] & 0x3f) | 0x80;
    formato_uuid(&u)
}

/// UUID de version 4 a partir de la aleatoriedad del sistema.
///
/// Se pide al kernel y no a un generador propio: los identificadores de un
/// informe que va a cruzar organizaciones no deben ser predecibles, y una
/// secuencia sembrada por el reloj lo seria.
pub fn uuid_v4() -> String {
    let mut b = [0u8; 16];
    llenar_aleatorio(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    formato_uuid(&b)
}

fn llenar_aleatorio(buf: &mut [u8; 16]) {
    // SAFETY: se escribe exactamente en el buffer indicado y con su longitud.
    let n = unsafe {
        libc::getrandom(
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
            0 as libc::c_uint,
        )
    };
    if n == buf.len() as isize {
        return;
    }
    // `getrandom` puede no existir en un kernel antiguo; `/dev/urandom` si.
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(buf);
    }
}

// ---------------------------------------------------------------------------
// Construccion del bundle
// ---------------------------------------------------------------------------

/// Identificador STIX de un observable, a partir de sus propiedades.
fn id_sco(tipo: &str, propiedades: &str) -> String {
    format!("{tipo}--{}", uuid_v5(&NS_SCO, propiedades.as_bytes()))
}

/// Objeto `file` de un binario.
fn objeto_file(p: &ProcessArtifact) -> Option<(String, String)> {
    let ruta = p.image.as_ref()?;
    let nombre = ruta.file_name()?.to_string_lossy().into_owned();
    // Las propiedades identificativas de `file` en STIX 2.1 son los hashes si
    // los hay, y el nombre en su defecto. Con hash, dos agentes distintos que
    // vean el mismo binario producen el mismo identificador.
    let clave = match &p.sha256 {
        Some(h) => format!("{{\"hashes\":{{\"SHA-256\":\"{h}\"}}}}"),
        None => format!("{{\"name\":\"{nombre}\"}}"),
    };
    let id = id_sco("file", &clave);

    let mut o = Obj::new();
    o.str("type", "file").str("id", &id).str("name", &nombre);
    if let Some(h) = &p.sha256 {
        let mut hashes = Obj::new();
        hashes.str("SHA-256", h);
        o.raw("hashes", &hashes.finish());
    }
    o.opt_num("size", p.image_size);
    o.str("x_aegis_path", &ruta.to_string_lossy());
    Some((id, o.finish()))
}

/// Objeto `process`.
fn objeto_process(
    p: &ProcessArtifact,
    file_ref: Option<&str>,
    parent_ref: Option<&str>,
) -> (String, String) {
    // El PID solo no identifica: se recicla. La marca de arranque entra en la
    // clave para que dos procesos distintos con el mismo numero sean dos
    // objetos distintos, que es lo que un informe forense necesita.
    let clave = format!("{{\"pid\":{},\"x_aegis_start\":{}}}", p.pid, p.start_stamp);
    let id = id_sco("process", &clave);

    let mut o = Obj::new();
    o.str("type", "process")
        .str("id", &id)
        .num("pid", p.pid as u64);
    if !p.cmdline.is_empty() {
        o.str("command_line", &p.cmdline.join(" "));
    }
    o.opt_str("image_ref", file_ref)
        .opt_str("parent_ref", parent_ref)
        .num("x_aegis_ppid", p.ppid as u64)
        .num("x_aegis_uid", p.uid as u64)
        .num("x_aegis_start_stamp", p.start_stamp);
    (id, o.finish())
}

/// Objetos de una conexion: las dos direcciones y el trafico.
fn objetos_socket(s: &SocketArtifact) -> Vec<(String, String)> {
    let tipo_dir = |ip: std::net::IpAddr| {
        if ip.is_ipv4() {
            "ipv4-addr"
        } else {
            "ipv6-addr"
        }
    };

    let mut salida = Vec::new();
    let mut refs = Vec::new();
    for ip in [s.local.ip(), s.remote.ip()] {
        let tipo = tipo_dir(ip);
        let clave = format!("{{\"value\":\"{ip}\"}}");
        let id = id_sco(tipo, &clave);
        let mut o = Obj::new();
        o.str("type", tipo)
            .str("id", &id)
            .str("value", &ip.to_string());
        refs.push(id.clone());
        salida.push((id, o.finish()));
    }

    let clave = format!(
        "{{\"dst_port\":{},\"protocols\":[\"{}\"],\"src_port\":{},\"x\":\"{}-{}\"}}",
        s.remote.port(),
        s.proto.transport(),
        s.local.port(),
        s.local.ip(),
        s.remote.ip()
    );
    let id = id_sco("network-traffic", &clave);
    let mut o = Obj::new();
    o.str("type", "network-traffic")
        .str("id", &id)
        .str_array(
            "protocols",
            &[
                s.proto.network().to_string(),
                s.proto.transport().to_string(),
            ],
        )
        .str("src_ref", &refs[0])
        .str("dst_ref", &refs[1])
        .num("src_port", s.local.port() as u64)
        .num("dst_port", s.remote.port() as u64)
        .str("x_aegis_state", s.state)
        .num("x_aegis_pid", s.pid as u64);
    salida.push((id, o.finish()));
    salida
}

/// Serializa los artefactos como un bundle de STIX 2.1.
pub fn to_bundle(a: &IncidentArtifacts) -> String {
    to_bundle_with(a, &mut || uuid_v4())
}

/// Igual que [`to_bundle`], pero con los UUID de los objetos de dominio
/// suministrados por el llamante.
///
/// Existe para que las pruebas puedan comparar el documento entero: los UUIDv4
/// que la especificacion exige para los SDO hacen que dos exportaciones del
/// mismo incidente no sean identicas, y sin poder fijarlos solo se podria
/// comprobar el documento a trozos.
pub fn to_bundle_with(a: &IncidentArtifacts, uuid: &mut dyn FnMut() -> String) -> String {
    let mut objetos: Vec<String> = Vec::new();
    let mut refs: Vec<String> = Vec::new();

    // 1. Ficheros y procesos. Se hace en dos pasadas porque `parent_ref` de un
    //    proceso necesita el identificador del padre, que puede aparecer
    //    despues en la lista.
    let mut id_por_pid: std::collections::HashMap<u32, String> = std::collections::HashMap::new();
    let mut ficheros: std::collections::HashMap<u32, String> = std::collections::HashMap::new();
    let mut vistos: std::collections::HashSet<String> = std::collections::HashSet::new();

    for p in &a.processes {
        if let Some((id, json)) = objeto_file(p) {
            if vistos.insert(id.clone()) {
                objetos.push(json);
                refs.push(id.clone());
            }
            ficheros.insert(p.pid, id);
        }
        let clave = format!("{{\"pid\":{},\"x_aegis_start\":{}}}", p.pid, p.start_stamp);
        id_por_pid.insert(p.pid, id_sco("process", &clave));
    }

    for p in &a.processes {
        let padre = id_por_pid.get(&p.ppid).cloned();
        let (id, json) = objeto_process(
            p,
            ficheros.get(&p.pid).map(|s| s.as_str()),
            padre.as_deref(),
        );
        if vistos.insert(id.clone()) {
            objetos.push(json);
            refs.push(id);
        }
    }

    // 2. Conexiones. Solo las que tienen un extremo remoto real: un socket a la
    //    escucha no aporta infraestructura con la que pivotar.
    for s in a.connected_sockets() {
        for (id, json) in objetos_socket(s) {
            if vistos.insert(id.clone()) {
                objetos.push(json);
                refs.push(id);
            }
        }
    }

    // 3. `observed-data`: el SDO que ata todos los observables al momento en que
    //    se vieron.
    let mut od = Obj::new();
    od.str("type", "observed-data")
        .str("spec_version", "2.1")
        .str("id", &format!("observed-data--{}", uuid()))
        .str("created", &a.collected_at)
        .str("modified", &a.collected_at)
        .str("first_observed", &a.collected_at)
        .str("last_observed", &a.collected_at)
        .num("number_observed", 1)
        .str_array("object_refs", &refs)
        .str("x_aegis_incident", &a.id)
        .str("x_aegis_trigger_source", &a.trigger.source)
        .str("x_aegis_trigger_reason", &a.trigger.reason);
    if !a.gaps.is_empty() {
        // Lo que NO se pudo recoger va en el documento. Un informe que calla sus
        // huecos induce a concluir que algo no ocurrio cuando lo unico cierto
        // es que no se pudo mirar.
        od.str_array("x_aegis_gaps", &a.gaps);
    }
    if !a.memory.findings.is_empty() {
        od.str_array("x_aegis_memory_findings", &a.memory.findings);
    }
    objetos.push(od.finish());

    // 4. `indicator` con el patron y las tecnicas de ATT&CK, si las hay.
    if let Some(ind) = indicador(a, uuid) {
        objetos.push(ind);
    }

    let mut b = Obj::new();
    b.str("type", "bundle")
        .str("id", &format!("bundle--{}", uuid()))
        .raw("objects", &array(&objetos));
    b.finish()
}

/// Indicador buscable a partir del binario del proceso raiz.
///
/// Solo se emite si hay hash: un indicador sin patron util es ruido en la
/// plataforma de inteligencia de quien lo reciba.
fn indicador(a: &IncidentArtifacts, uuid: &mut dyn FnMut() -> String) -> Option<String> {
    let raiz = a.processes.iter().find(|p| p.pid == a.root_pid)?;
    let hash = raiz.sha256.as_ref()?;

    let mut o = Obj::new();
    o.str("type", "indicator")
        .str("spec_version", "2.1")
        .str("id", &format!("indicator--{}", uuid()))
        .str("created", &a.collected_at)
        .str("modified", &a.collected_at)
        .str(
            "name",
            &format!("AegisCore: {} ({})", a.trigger.reason, a.trigger.source),
        )
        .str_array("indicator_types", &["malicious-activity".to_string()])
        .str("pattern_type", "stix")
        .str("pattern", &format!("[file:hashes.'SHA-256' = '{hash}']"))
        .str("valid_from", &a.collected_at);
    if let Some(s) = a.trigger.score {
        o.num("confidence", confianza(s));
    }
    if !a.trigger.techniques.is_empty() {
        let refs: Vec<String> = a
            .trigger
            .techniques
            .iter()
            .map(|t| {
                let mut r = Obj::new();
                r.str("source_name", "mitre-attack")
                    .str("external_id", t)
                    .str("url", &format!("https://attack.mitre.org/techniques/{t}/"));
                r.finish()
            })
            .collect();
        o.raw("external_references", &array(&refs));
    }
    Some(o.finish())
}

/// Traduce la puntuacion del motor a la escala de confianza de STIX.
///
/// STIX la define de 0 a 100 con la misma orientacion, asi que la traduccion es
/// la identidad acotada. Se hace explicita porque las dos escalas podrian
/// divergir, y entonces esta funcion seria el unico sitio que tocar.
pub fn confianza(score: u8) -> u64 {
    score.min(100) as u64
}
