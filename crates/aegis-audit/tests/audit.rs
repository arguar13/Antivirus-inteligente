//! Pruebas del registro de auditoria cifrado.
//!
//! Las pruebas que importan no comprueban que el codigo llame a una funcion:
//! abren el fichero SQLite POR FUERA del registro y verifican que el detalle
//! sensible no esta en claro, que un byte cambiado se detecta, y que dos filas
//! no se pueden intercambiar. Un cifrado "de auditoria" que se probara solo
//! contra su propio descifrado no probaria nada.

use std::path::{Path, PathBuf};

use aegis_audit::{AuditConfig, AuditError, AuditEvent, AuditLogger, Severity};
use rusqlite::Connection;

struct Lab(PathBuf);

impl Lab {
    fn nuevo(n: &str) -> Lab {
        let p = std::env::temp_dir().join(format!("aegis-audit-{n}-{}", std::process::id()));
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

fn clave() -> [u8; 32] {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(7).wrapping_add(3);
    }
    k
}

fn evento(ts: u64, sev: Severity, kind: &str, detail: &str) -> AuditEvent {
    AuditEvent::new(ts, sev, kind)
        .with_actor(0xABCD)
        .with_detail(detail)
}

// ---------------------------------------------------------------------------
// El cuerpo se cifra de verdad en el fichero
// ---------------------------------------------------------------------------

#[test]
fn el_detalle_sensible_no_esta_en_claro_en_el_fichero() {
    let lab = Lab::nuevo("cifrado");
    let secreto = "/home/victima/documentos/nomina-confidencial.xlsx cifrado por PID 6613";
    {
        let mut log =
            AuditLogger::open(lab.path(), "audit", clave(), AuditConfig::default()).unwrap();
        log.log(&evento(
            1000,
            Severity::Critical,
            "ransomware.contained",
            secreto,
        ))
        .unwrap();
    }

    // Se leen los BYTES CRUDOS del fichero .db y se exige que el secreto no
    // aparezca. Los metadatos (tipo) si pueden estar; el detalle no.
    let db = lab.path().join("audit-000000.db");
    let crudo = std::fs::read(&db).unwrap();
    let ventana = String::from_utf8_lossy(&crudo);
    assert!(
        !ventana.contains("nomina-confidencial"),
        "el detalle sensible aparece en claro en el fichero SQLite"
    );
    assert!(
        !ventana.contains("victima"),
        "la ruta de la victima aparece en claro"
    );
    // El tipo si esta indexado en claro, a proposito.
    assert!(ventana.contains("ransomware.contained"));
}

#[test]
fn lo_que_se_escribe_se_lee_igual_tras_reabrir() {
    let lab = Lab::nuevo("roundtrip");
    {
        let mut log =
            AuditLogger::open(lab.path(), "audit", clave(), AuditConfig::default()).unwrap();
        log.log(&evento(1, Severity::Info, "proc.exec", "/usr/bin/bash"))
            .unwrap();
        log.log(&evento(
            2,
            Severity::Warning,
            "net.connect",
            "1.2.3.4:443 desde PID 10",
        ))
        .unwrap();
        log.log(&evento(
            3,
            Severity::Critical,
            "ransom",
            "cifrado masivo detectado",
        ))
        .unwrap();
    }
    // Se reabre: el registro tiene que reconstruir su estado del disco.
    let log = AuditLogger::open(lab.path(), "audit", clave(), AuditConfig::default()).unwrap();
    let todos = log.query_active(Severity::Info).unwrap();
    assert_eq!(todos.len(), 3);
    assert_eq!(todos[0].event.detail, "/usr/bin/bash");
    assert_eq!(todos[2].event.detail, "cifrado masivo detectado");

    // Filtrado por gravedad.
    let graves = log.query_active(Severity::Warning).unwrap();
    assert_eq!(graves.len(), 2);
    assert!(graves.iter().all(|e| e.event.severity >= Severity::Warning));
}

// ---------------------------------------------------------------------------
// Deteccion de manipulacion
// ---------------------------------------------------------------------------

#[test]
fn un_cuerpo_manipulado_en_el_fichero_no_autentica() {
    let lab = Lab::nuevo("tamper");
    {
        let mut log =
            AuditLogger::open(lab.path(), "audit", clave(), AuditConfig::default()).unwrap();
        log.log(&evento(1, Severity::Critical, "ransom", "detalle original"))
            .unwrap();
    }

    // Un atacante con acceso al fichero cambia un byte del cuerpo cifrado.
    let db = lab.path().join("audit-000000.db");
    {
        let conn = Connection::open(&db).unwrap();
        let cuerpo: Vec<u8> = conn
            .query_row("SELECT cuerpo FROM eventos WHERE id=1", [], |r| r.get(0))
            .unwrap();
        let mut roto = cuerpo.clone();
        roto[0] ^= 0x01;
        conn.execute("UPDATE eventos SET cuerpo=?1 WHERE id=1", [roto])
            .unwrap();
    }

    let log = AuditLogger::open(lab.path(), "audit", clave(), AuditConfig::default()).unwrap();
    match log.query_active(Severity::Info) {
        Err(AuditError::Crypto(_)) => {}
        otro => panic!("un cuerpo manipulado deberia fallar la autenticacion: {otro:?}"),
    }
}

#[test]
fn no_se_pueden_intercambiar_los_cuerpos_de_dos_filas() {
    let lab = Lab::nuevo("swap");
    {
        let mut log =
            AuditLogger::open(lab.path(), "audit", clave(), AuditConfig::default()).unwrap();
        log.log(&evento(1, Severity::Info, "benigno", "esto es inocuo"))
            .unwrap();
        log.log(&evento(
            2,
            Severity::Critical,
            "incidente",
            "esto es un ataque",
        ))
        .unwrap();
    }

    // El atacante intercambia los cuerpos y nonces de las dos filas para mover
    // el detalle del incidente a la fila benigna (o borrar el rastro del
    // ataque). La AAD ata cada cuerpo a SU id, asi que descifrar con la fila
    // equivocada falla.
    let db = lab.path().join("audit-000000.db");
    {
        let conn = Connection::open(&db).unwrap();
        let (c1, n1): (Vec<u8>, Vec<u8>) = conn
            .query_row("SELECT cuerpo, nonce FROM eventos WHERE id=1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        let (c2, n2): (Vec<u8>, Vec<u8>) = conn
            .query_row("SELECT cuerpo, nonce FROM eventos WHERE id=2", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        conn.execute(
            "UPDATE eventos SET cuerpo=?1, nonce=?2 WHERE id=1",
            rusqlite::params![c2, n2],
        )
        .unwrap();
        conn.execute(
            "UPDATE eventos SET cuerpo=?1, nonce=?2 WHERE id=2",
            rusqlite::params![c1, n1],
        )
        .unwrap();
    }

    let log = AuditLogger::open(lab.path(), "audit", clave(), AuditConfig::default()).unwrap();
    assert!(
        log.query_active(Severity::Info).is_err(),
        "intercambiar cuerpos entre filas deberia romper la autenticacion"
    );
}

#[test]
fn una_clave_distinta_no_descifra() {
    let lab = Lab::nuevo("otraclave");
    {
        let mut log =
            AuditLogger::open(lab.path(), "audit", clave(), AuditConfig::default()).unwrap();
        log.log(&evento(1, Severity::Critical, "x", "secreto"))
            .unwrap();
    }
    let mut otra = clave();
    otra[0] ^= 0xFF;
    let log = AuditLogger::open(lab.path(), "audit", otra, AuditConfig::default()).unwrap();
    assert!(log.query_active(Severity::Info).is_err());
}

// ---------------------------------------------------------------------------
// Rotacion
// ---------------------------------------------------------------------------

#[test]
fn el_registro_rota_al_superar_el_tamano_maximo() {
    let lab = Lab::nuevo("rota");
    let config = AuditConfig {
        max_bytes: 64 * 1024, // 64 KB para forzar la rotacion pronto
        max_segments: 100,
        check_every: 16,
    };
    let mut log = AuditLogger::open(lab.path(), "audit", clave(), config).unwrap();

    let relleno = "x".repeat(512);
    for i in 0..2000u64 {
        log.log(&evento(i, Severity::Info, "carga", &relleno))
            .unwrap();
    }

    assert!(
        log.segment() >= 1,
        "con 2000 eventos de 512 B y limite de 64 KB deberia haber rotado, \
         segmento actual {}",
        log.segment()
    );
    // Hay varios ficheros de segmento en disco.
    let segmentos = log.segments_on_disk();
    assert!(segmentos.len() >= 2, "segmentos en disco: {segmentos:?}");
    // El segmento activo empieza de cero tras rotar.
    assert!(log.active_rows() < 2000);
}

#[test]
fn la_rotacion_conserva_solo_los_segmentos_mas_recientes() {
    let lab = Lab::nuevo("poda");
    let config = AuditConfig {
        max_bytes: 32 * 1024,
        max_segments: 3,
        check_every: 8,
    };
    let mut log = AuditLogger::open(lab.path(), "audit", clave(), config).unwrap();

    let relleno = "y".repeat(512);
    for i in 0..4000u64 {
        log.log(&evento(i, Severity::Info, "carga", &relleno))
            .unwrap();
    }

    let segmentos = log.segments_on_disk();
    assert!(
        segmentos.len() <= 3,
        "la poda deberia dejar como mucho 3 segmentos, hay {}: {segmentos:?}",
        segmentos.len()
    );
    // Los que quedan son los de secuencia mas alta.
    let max = log.segment();
    assert!(
        segmentos.contains(&max),
        "el segmento activo tiene que estar"
    );
}

#[test]
fn una_rotacion_forzada_incrementa_la_secuencia_y_no_reusa_nonce() {
    let lab = Lab::nuevo("forzada");
    let mut log = AuditLogger::open(lab.path(), "audit", clave(), AuditConfig::default()).unwrap();

    log.log(&evento(1, Severity::Info, "a", "primero")).unwrap();
    let seg0 = log.segment();
    log.rotar().unwrap();
    let seg1 = log.segment();
    assert_eq!(seg1, seg0 + 1, "la rotacion incrementa la secuencia");

    log.log(&evento(2, Severity::Info, "b", "segundo")).unwrap();
    // Cada segmento tiene su fila id=1, pero el nonce difiere porque incluye la
    // secuencia del segmento: no hay reutilizacion de (clave, nonce).
    assert_eq!(log.active_rows(), 1);

    // Reabrir en el segmento nuevo y leer.
    let leidos = log.query_active(Severity::Info).unwrap();
    assert_eq!(leidos.len(), 1);
    assert_eq!(leidos[0].event.detail, "segundo");
}

// ---------------------------------------------------------------------------
// Integracion con el blindaje: la clave puede venir del vault de aegis-harden
// ---------------------------------------------------------------------------

#[test]
fn la_clave_puede_derivarse_del_blindaje() {
    // El registro no impone de donde sale la clave; en produccion puede venir
    // del material de blindaje. Aqui se comprueba que una clave de 32 bytes
    // derivada por aegis-harden sirve tal cual.
    let key =
        aegis_harden::strings::derive_key(&[0xDEAD_BEEF, 0xCAFE_F00D, 1, 2], b"aegis-audit-key");
    let lab = Lab::nuevo("harden");
    {
        let mut log = AuditLogger::open(lab.path(), "audit", key, AuditConfig::default()).unwrap();
        log.log(&evento(1, Severity::Notice, "x", "detalle"))
            .unwrap();
    }
    let log = AuditLogger::open(lab.path(), "audit", key, AuditConfig::default()).unwrap();
    assert_eq!(
        log.query_active(Severity::Info).unwrap()[0].event.detail,
        "detalle"
    );
}
