//! Prueba de integracion del desempaquetado dinamico contra un EMPAQUETADOR
//! REAL.
//!
//! No hay simulacion en ninguna parte: se compila un binario cuyo codigo real
//! esta cifrado con XOR en disco, se ejecuta de verdad bajo ptrace, se detecta
//! su OEP observando el efecto real de la descompresion sobre su mapa de
//! memoria, se vuelca la region, y se comprueba con el motor YARA de verdad que
//! una firma que NO aparece en el fichero de disco SI aparece en el volcado. Es
//! exactamente lo que hace un empaquetador real, reducido a lo esencial.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use aegis_scan::yara::YaraEngine;
use aegis_unpacker::{desempaquetar, TraceConfig};

/// La firma que el payload lleva en claro tras descifrarse. En el fichero de
/// disco esta XOR'd y no aparece.
const FIRMA: &[u8] = b"AEGIS_UNPACKED_OK_7F3A";

/// Regla YARA que busca la firma del codigo desempaquetado.
const REGLA: &str = r#"
rule payload_desempaquetado {
    meta:
        description = "codigo que solo aparece tras el desempaquetado en memoria"
        severity = "high"
    strings:
        $firma = "AEGIS_UNPACKED_OK_7F3A"
    condition:
        $firma
}
"#;

/// Compila el empaquetador de prueba desde su fuente a un binario temporal.
///
/// Se compila en la prueba en vez de versionar el binario: un binario en git no
/// es reproducible ni auditable, y la fuente C si.
fn compilar_stub() -> Option<PathBuf> {
    let fuente = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/packer_stub.c");
    // Nombre unico por invocacion: los tests corren en hilos del mismo proceso,
    // asi que un nombre basado solo en el PID los hace chocar y borrarse el
    // fichero unos a otros.
    static N: AtomicU32 = AtomicU32::new(0);
    let salida = std::env::temp_dir().join(format!(
        "aegis-packer-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".into());
    let r = std::process::Command::new(&cc)
        .args(["-O0", "-no-pie", "-o"])
        .arg(&salida)
        .arg(&fuente)
        .output()
        .ok()?;
    if !r.status.success() {
        eprintln!(
            "no se pudo compilar el stub: {}",
            String::from_utf8_lossy(&r.stderr)
        );
        return None;
    }
    Some(salida)
}

#[test]
fn el_desempaquetado_saca_a_la_luz_codigo_que_el_disco_esconde() {
    if !aegis_unpacker::soportado() {
        eprintln!("OMITIDA: sin seccomp no se puede confinar el desempaquetado");
        return;
    }
    let Some(stub) = compilar_stub() else {
        eprintln!("OMITIDA: no hay compilador de C para el empaquetador de prueba");
        return;
    };

    // 1. En DISCO, la firma NO esta: el motor YARA no la ve en los bytes del
    // fichero. Se escanean los BYTES en vez del fichero para escanear
    // exactamente lo mismo que se contrasta con la busqueda directa.
    let motor = YaraEngine::from_sources(&[REGLA]).expect("la regla compila");
    let bytes_disco = std::fs::read(&stub).unwrap();
    let en_disco = motor
        .scan_bytes(&bytes_disco)
        .expect("se pueden escanear los bytes del fichero");
    assert!(
        en_disco.is_empty(),
        "la firma NO debe aparecer en el binario de disco (esta cifrada): {en_disco:?}"
    );
    assert!(
        !bytes_disco.windows(FIRMA.len()).any(|w| w == FIRMA),
        "la firma en claro no puede estar en el fichero"
    );

    // 2. Se desempaqueta: se ejecuta bajo control hasta el OEP y se vuelca.
    let cfg = TraceConfig {
        max_paradas: 100_000,
        confinar: true,
    };
    let u = desempaquetar(&stub, &[], &cfg).expect("el empaquetador de prueba se desempaqueta");

    assert!(
        !u.oep.regiones_nuevas.is_empty(),
        "tiene que haber detectado la region anonima ejecutable del descompresor"
    );
    assert!(
        u.oep.region.contiene(u.oep.rip),
        "el OEP tiene que caer dentro de la region desempaquetada"
    );
    assert!(!u.dump.codigo.is_empty(), "se volco algo");

    // 3. En el VOLCADO, la firma SI esta: YARA la ve donde el disco no la tenia.
    let en_memoria = motor
        .scan_bytes(&u.dump.codigo)
        .expect("se puede escanear el volcado");
    assert!(
        en_memoria
            .iter()
            .any(|d| d.rule == "payload_desempaquetado"),
        "la firma del codigo desempaquetado tiene que aparecer en el volcado: {:?}",
        en_memoria
    );

    let _ = std::fs::remove_file(&stub);
}

#[test]
fn un_binario_que_no_se_autoextrae_no_bloquea_el_desempaquetador() {
    // /bin/true no despliega codigo anonimo ejecutable: el desempaquetador tiene
    // que rendirse limpiamente al agotar su presupuesto o al terminar el
    // proceso, nunca colgarse.
    if !aegis_unpacker::soportado() {
        return;
    }
    let cfg = TraceConfig {
        max_paradas: 20_000,
        confinar: true,
    };
    let r = desempaquetar(std::path::Path::new("/bin/true"), &[], &cfg);
    // /bin/true termina antes de desplegar nada: el resultado es un error
    // limpio (proceso termino, u OEP no alcanzado), jamas un cuelgue ni un
    // panico.
    assert!(
        r.is_err(),
        "/bin/true no despliega codigo: no puede dar un desempaquetado con exito"
    );
}

#[test]
fn el_proceso_desempaquetado_no_queda_vivo() {
    // Desempaquetar ejecuta codigo posiblemente malicioso: no puede quedar ni un
    // proceso vivo despues, pase lo que pase.
    if !aegis_unpacker::soportado() {
        return;
    }
    let Some(stub) = compilar_stub() else {
        return;
    };
    let cfg = TraceConfig::default();
    let u = desempaquetar(&stub, &[], &cfg).expect("se desempaqueta");
    let pid = u.oep.pid;
    // El proceso tiene que estar muerto: kill(pid, 0) devuelve ESRCH.
    // SAFETY: consulta de existencia, no envia senal.
    let vivo = unsafe { libc::kill(pid, 0) } == 0;
    assert!(
        !vivo,
        "el proceso trazado no puede quedar vivo tras desempaquetar"
    );
    let _ = std::fs::remove_file(&stub);
}
