//! Pruebas del protocolo del TPM 2.0 y del veredicto de firmware.
//!
//! El wire del TPM se comprueba byte a byte contra los valores del estandar
//! —un comando mal formado no da un error claro, el TPM responde otra cosa y el
//! fallo aflora como un PCR equivocado mucho despues—. Y se fija la propiedad
//! que evita el falso positivo universal: en una maquina sin TPM ni UEFI, el
//! veredicto es "no aplicable", jamas "inseguro".

use aegis_firmware::tcg::HashAlg;
use aegis_firmware::tpm::{self, PcrReadResp};

#[test]
fn el_comando_pcr_read_tiene_los_bytes_exactos_del_estandar() {
    // Bytes verificados contra la especificacion TCG (big-endian).
    // PCR0 solo, sha256: 80 01 00 00 00 14 00 00 01 7E 00 00 00 01 00 0B 03 01 00 00
    let cmd = tpm::construir_pcr_read(HashAlg::Sha256, tpm::bitmap_de(&[0]));
    assert_eq!(
        cmd,
        vec![
            0x80, 0x01, // TPM_ST_NO_SESSIONS
            0x00, 0x00, 0x00, 0x14, // commandSize = 20
            0x00, 0x00, 0x01, 0x7E, // TPM_CC_PCR_Read
            0x00, 0x00, 0x00, 0x01, // count = 1
            0x00, 0x0B, // TPM_ALG_SHA256
            0x03, // sizeofSelect = 3
            0x01, 0x00, 0x00, // pcrSelect: solo PCR0
        ]
    );

    // PCR0-7, sha256: ... 03 FF 00 00
    let cmd07 = tpm::construir_pcr_read(HashAlg::Sha256, tpm::bitmap_de(&[0, 1, 2, 3, 4, 5, 6, 7]));
    assert_eq!(&cmd07[17..20], &[0xFF, 0x00, 0x00]);

    // PCR0-23: ... 03 FF FF FF
    let todos: Vec<u32> = (0..24).collect();
    let cmd_all = tpm::construir_pcr_read(HashAlg::Sha256, tpm::bitmap_de(&todos));
    assert_eq!(&cmd_all[17..20], &[0xFF, 0xFF, 0xFF]);

    // El bitmap coloca cada PCR en su bit: PCR8 es el bit 0 del byte 1.
    assert_eq!(tpm::bitmap_de(&[8]), [0x00, 0x01, 0x00]);
    assert_eq!(tpm::bitmap_de(&[23]), [0x00, 0x00, 0x80]);
}

#[test]
fn la_respuesta_pcr_read_se_interpreta_bien() {
    // Se fabrica una respuesta de TPM valida (big-endian) con un digest de
    // PCR0 y se comprueba que se lee.
    let mut resp = Vec::new();
    resp.extend_from_slice(&0x8001u16.to_be_bytes()); // tag
    resp.extend_from_slice(&0u32.to_be_bytes()); // responseSize (no se valida)
    resp.extend_from_slice(&0u32.to_be_bytes()); // TPM_RC_SUCCESS
    resp.extend_from_slice(&5u32.to_be_bytes()); // pcrUpdateCounter
    resp.extend_from_slice(&1u32.to_be_bytes()); // count seleccion
    resp.extend_from_slice(&0x000Bu16.to_be_bytes()); // sha256
    resp.push(3); // sizeofSelect
    resp.extend_from_slice(&[0x01, 0x00, 0x00]); // devolvio PCR0
    resp.extend_from_slice(&1u32.to_be_bytes()); // pcrValues count
    resp.extend_from_slice(&0x0020u16.to_be_bytes()); // digest size = 32
    resp.extend_from_slice(&[0xAB; 32]); // el digest

    let PcrReadResp {
        update_counter,
        devuelto,
        digests,
    } = tpm::parse_pcr_read(&resp).unwrap();
    assert_eq!(update_counter, 5);
    assert_eq!(devuelto, [0x01, 0x00, 0x00]);
    assert_eq!(digests.len(), 1);
    assert_eq!(digests[0], vec![0xAB; 32]);
}

#[test]
fn una_respuesta_con_codigo_de_error_no_se_interpreta_como_datos() {
    let mut resp = Vec::new();
    resp.extend_from_slice(&0x8001u16.to_be_bytes());
    resp.extend_from_slice(&10u32.to_be_bytes());
    resp.extend_from_slice(&0x0000_0101u32.to_be_bytes()); // codigo de error != 0
    let r = tpm::parse_pcr_read(&resp);
    assert!(
        matches!(r, Err(tpm::TpmError::RespuestaTpm(0x101))),
        "{r:?}"
    );
}

#[test]
fn una_respuesta_con_mas_de_ocho_digests_se_rechaza() {
    // El TPM devuelve como mucho 8 por llamada. Una respuesta que declara 24 es
    // malformada; interpretarla leeria basura del buffer.
    let mut resp = Vec::new();
    resp.extend_from_slice(&0x8001u16.to_be_bytes());
    resp.extend_from_slice(&0u32.to_be_bytes());
    resp.extend_from_slice(&0u32.to_be_bytes());
    resp.extend_from_slice(&0u32.to_be_bytes());
    resp.extend_from_slice(&1u32.to_be_bytes());
    resp.extend_from_slice(&0x000Bu16.to_be_bytes());
    resp.push(3);
    resp.extend_from_slice(&[0xFF, 0xFF, 0xFF]);
    resp.extend_from_slice(&24u32.to_be_bytes()); // 24 digests: imposible
    let r = tpm::parse_pcr_read(&resp);
    assert!(
        matches!(r, Err(tpm::TpmError::RespuestaMalformada(_))),
        "{r:?}"
    );
}

#[test]
fn el_pcr_hex_de_sysfs_se_interpreta_en_mayuscula_y_minuscula() {
    let mayus = "AB".repeat(32) + "\n";
    let minus = "ab".repeat(32);
    let a = tpm::parse_pcr_hex(&mayus, HashAlg::Sha256).unwrap();
    let b = tpm::parse_pcr_hex(&minus, HashAlg::Sha256).unwrap();
    assert_eq!(a, vec![0xAB; 32]);
    assert_eq!(b, vec![0xAB; 32]);
    // Longitud equivocada: rechazada, no truncada.
    assert!(tpm::parse_pcr_hex("ABCD", HashAlg::Sha256).is_none());
    // Un valor SHA-1 (40 hex) no cuela como SHA-256.
    assert!(tpm::parse_pcr_hex(&"00".repeat(20), HashAlg::Sha256).is_none());
    assert!(tpm::parse_pcr_hex(&"00".repeat(20), HashAlg::Sha1).is_some());
}

// --- La propiedad que evita el falso positivo universal ---

#[test]
fn en_una_maquina_sin_firmware_el_veredicto_es_no_aplicable_no_inseguro() {
    let soporte = aegis_firmware::FirmwareSupport::detect();
    let r = aegis_firmware::escanear(None);

    // Sea cual sea la maquina, el escaner NUNCA falla y NUNCA reporta un
    // compromiso inventado sobre ausencia de hardware.
    if !soporte.algo_que_verificar() {
        assert!(
            !r.comprometido(),
            "una maquina sin TPM ni UEFI no puede reportarse como comprometida: {:?}",
            r.fallos()
        );
        // Y ninguna comprobacion puede ser un fallo: todas "no aplicable".
        for c in &r.checks {
            assert!(
                !c.estado.es_fallo(),
                "la comprobacion {} no puede fallar sin hardware: {:?}",
                c.nombre,
                c.estado
            );
        }
        // La maquina de integracion es exactamente este caso.
        assert!(!soporte.tpm && !soporte.uefi);
    }
    // Y el escaner produjo las tres comprobaciones esperadas.
    assert_eq!(r.checks.len(), 3);
}

#[test]
fn los_bancos_no_se_inventan_cuando_no_hay_tpm() {
    // NO existe ningun fichero active_banks; sin TPM la lista es vacia, no una
    // suposicion.
    if !tpm::hay_tpm() {
        assert!(tpm::bancos_activos().is_empty());
        assert!(tpm::version_mayor().is_none());
    }
}
