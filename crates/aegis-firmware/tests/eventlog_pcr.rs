//! Pruebas del analizador del event log y del recalculo de PCRs.
//!
//! Contra VECTORES BINARIOS REALES: cada log se construye byte a byte como lo
//! escribe el firmware. La prueba central es la que da todo su valor al modulo:
//! reproducir un log fiel da exactamente el PCR que el TPM tendria, y reproducir
//! un log MANIPULADO da un PCR distinto, que es como se delata un bootkit.

mod common;
use common::{extend, sha256, LogBuilder};

use aegis_firmware::eventlog::{self, LogError};
use aegis_firmware::pcr;
use aegis_firmware::tcg::{EventType, HashAlg};

#[test]
fn un_log_crypto_agil_se_analiza_con_sus_dos_bancos() {
    let mut b = LogBuilder::crypto_agile_sha1_sha256();
    b.medir(0, EventType::PostCode.as_u32(), b"firmware v1");
    b.medir(4, EventType::EfiBootServicesApplication.as_u32(), b"grub");
    let bytes = b.build();

    let log = eventlog::parse(&bytes).unwrap();
    assert!(log.crypto_agile, "el Spec ID Event lo declara crypto-agil");
    assert_eq!(log.banks, vec![HashAlg::Sha1, HashAlg::Sha256]);
    // 3 eventos: el Spec ID + los dos medidos.
    assert_eq!(log.events.len(), 3);
    assert_eq!(log.events[0].event_type, EventType::NoAction);
    // Cada evento medido lleva los dos digests.
    assert_eq!(log.events[1].digests.len(), 2);
    assert!(log.events[1].digest(HashAlg::Sha256).is_some());
    assert_eq!(
        log.events[2].event_type,
        EventType::EfiBootServicesApplication
    );
}

#[test]
fn reproducir_un_log_fiel_da_el_pcr_correcto() {
    // Se construye el log Y se calcula a mano el PCR esperado con las mismas
    // extensiones. Si el modulo reproduce bien, coinciden.
    let mut b = LogBuilder::crypto_agile_sha1_sha256();
    let (_, m1) = b.medir(
        4,
        EventType::EfiBootServicesApplication.as_u32(),
        b"grub-legitimo",
    );
    let (_, m2) = b.medir(4, EventType::EfiBootServicesApplication.as_u32(), b"kernel");
    let log = eventlog::parse(&b.build()).unwrap();

    // El PCR 4 esperado: cero, extendido con m1 y luego con m2.
    let esperado = extend(extend([0u8; 32], &m1), &m2);

    let banco = pcr::reproducir_sha256(&log);
    assert_eq!(
        banco.get(4).unwrap(),
        &esperado,
        "el PCR 4 reproducido tiene que coincidir con el calculado a mano"
    );
    // Un PCR que nadie extendio se queda a cero.
    assert_eq!(banco.get(10).unwrap(), &[0u8; 32]);
}

#[test]
fn ev_no_action_no_extiende_el_pcr() {
    // Es la trampa mas facil: el primer evento (Spec ID) es EV_NO_ACTION y NO
    // se mide. Si se extendiera, el PCR 0 saldria distinto de cero solo por el.
    let b = LogBuilder::crypto_agile_sha1_sha256();
    let log = eventlog::parse(&b.build()).unwrap();
    let banco = pcr::reproducir_sha256(&log);
    assert_eq!(
        banco.get(0).unwrap(),
        &[0u8; 32],
        "un log con solo EV_NO_ACTION no extiende ningun PCR"
    );
}

#[test]
fn un_log_manipulado_no_reproduce_el_pcr_del_tpm() {
    // El nucleo de la deteccion de bootkits. El firmware midio el grub REAL y
    // extendio su medida en el PCR 4 del TPM. Un bootkit reescribe el event log
    // para que declare la medida del grub LEGITIMO, escondiendo el suyo. Pero el
    // TPM ya tiene el PCR extendido con la medida del grub malicioso, y no se
    // puede cambiar sin la clave. Reproducir el log manipulado NO da ese PCR.
    let medida_real_del_grub_malicioso = sha256(b"grub-con-bootkit");
    // El TPM tiene el PCR 4 extendido con la medida REAL (la maliciosa).
    let tpm_pcr4 = extend([0u8; 32], &medida_real_del_grub_malicioso);
    let mut tpm = pcr::PcrBank::cero(HashAlg::Sha256);
    tpm.valores[4] = tpm_pcr4.to_vec();

    // El log MIENTE: declara la medida del grub legitimo.
    let mut b = LogBuilder::crypto_agile_sha1_sha256();
    let digest_legitimo = sha256(b"grub-legitimo");
    b.medir_con_digest_falso(
        4,
        EventType::EfiBootServicesApplication.as_u32(),
        b"grub-con-bootkit",
        digest_legitimo,
    );
    let log = eventlog::parse(&b.build()).unwrap();

    let reproducido = pcr::reproducir_sha256(&log);
    let m = pcr::contrastar(&reproducido, &tpm, &pcr::PCRS_DE_ARRANQUE);
    assert!(
        m.hay_discrepancia(),
        "el log manipulado no puede reproducir el PCR que el TPM tiene de verdad"
    );
    assert!(
        m.discrepan.contains(&4),
        "la discrepancia esta en el PCR 4, el del gestor de arranque: {m:?}"
    );
}

#[test]
fn una_medida_no_registrada_en_el_log_se_detecta() {
    // El otro modo de compromiso: algo se ejecuto y se midio en el TPM pero NO
    // se registro en el log. La reproduccion deja el PCR a cero mientras el TPM
    // lo tiene con valor.
    let mut tpm = pcr::PcrBank::cero(HashAlg::Sha256);
    tpm.valores[5] = extend([0u8; 32], &sha256(b"driver-oculto")).to_vec();

    let b = LogBuilder::crypto_agile_sha1_sha256(); // log vacio de medidas
    let log = eventlog::parse(&b.build()).unwrap();
    let reproducido = pcr::reproducir_sha256(&log);
    let m = pcr::contrastar(&reproducido, &tpm, &pcr::PCRS_DE_ARRANQUE);
    assert!(m.no_explicados.contains(&5), "PCR 5 no explicado: {m:?}");
    assert!(m.hay_discrepancia());
}

#[test]
fn un_arranque_intacto_no_produce_discrepancia() {
    // El caso limpio, que NO puede dar un falso positivo: el TPM tiene lo mismo
    // que el log reproduce.
    let mut b = LogBuilder::crypto_agile_sha1_sha256();
    let (_, m0) = b.medir(0, EventType::PostCode.as_u32(), b"firmware");
    let (_, m4) = b.medir(4, EventType::EfiBootServicesApplication.as_u32(), b"grub");
    let log = eventlog::parse(&b.build()).unwrap();

    let mut tpm = pcr::PcrBank::cero(HashAlg::Sha256);
    tpm.valores[0] = extend([0u8; 32], &m0).to_vec();
    tpm.valores[4] = extend([0u8; 32], &m4).to_vec();

    let reproducido = pcr::reproducir_sha256(&log);
    let m = pcr::contrastar(&reproducido, &tpm, &pcr::PCRS_DE_ARRANQUE);
    assert!(
        !m.hay_discrepancia(),
        "un arranque intacto no discrepa: {m:?}"
    );
    assert!(m.coinciden.contains(&0) && m.coinciden.contains(&4));
}

// --- Robustez del analizador ante entrada hostil ---

#[test]
fn un_log_truncado_no_desborda() {
    let mut b = LogBuilder::crypto_agile_sha1_sha256();
    b.medir(4, EventType::EfiBootServicesApplication.as_u32(), b"grub");
    let bytes = b.build();
    // Cada truncamiento tiene que fallar limpio, nunca desbordar.
    for corte in 0..bytes.len() {
        let r = eventlog::parse(&bytes[..corte]);
        // O analiza un prefijo valido, o devuelve Truncated: nunca panica.
        assert!(
            r.is_ok() || matches!(r, Err(LogError::Truncated(_)) | Err(LogError::BadSpecId(_)))
        );
    }
}

#[test]
fn un_event_size_desmesurado_se_rechaza() {
    // Un log que declara un evento de gigabytes: el analizador no puede intentar
    // reservarlos.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0u32.to_le_bytes()); // PCR
    bytes.extend_from_slice(&0x0000_0001u32.to_le_bytes()); // EV_POST_CODE (legacy)
    bytes.extend_from_slice(&[0u8; 20]); // digest SHA-1
    bytes.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // EventSize enorme
    let r = eventlog::parse(&bytes);
    assert!(
        matches!(
            r,
            Err(LogError::BadSize { .. }) | Err(LogError::Truncated(_))
        ),
        "un EventSize enorme tiene que rechazarse: {r:?}"
    );
}

#[test]
fn un_log_vacio_es_un_log_vacio_no_un_error() {
    let log = eventlog::parse(&[]).unwrap();
    assert!(log.events.is_empty());
    assert!(!log.crypto_agile);
}
