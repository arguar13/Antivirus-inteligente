//! Verificacion de extremo a extremo con firmas REALES.
//!
//! No hay mocks: se generan claves de verdad (Ed25519, ECDSA P-256, RSA-2048),
//! se ensambla un `TPMS_ATTEST` byte a byte segun la spec TPM 2.0, se FIRMA con
//! la clave, y el verificador lo comprueba. Asi se demuestra que aceptara la
//! firma de un TPM real sin tener uno delante. Cada propiedad de seguridad tiene
//! su vector negativo: la prueba de que el verificador RECHAZA lo que debe.

use aegis_attest::attest::{Attest, QuoteInfo, SeleccionPcr};
use aegis_attest::identidad::{AreaPublica, ClavePublicaAk};
use aegis_attest::verificador::{verificar_quote, Entrada, Veredicto};
use aegis_firmware::HashAlg;
use sha2::{Digest, Sha256};

// --- Construccion de un quote autentico byte a byte -------------------------

fn pcrs_de_arranque() -> Vec<(u32, Vec<u8>)> {
    // Ocho PCR con valores distintos y deterministas (no hace falta que sean
    // "reales": lo que se prueba es que la firma los ata y el digest casa).
    (0u32..8)
        .map(|i| {
            let mut h = Sha256::new();
            h.update([i as u8; 4]);
            (i, h.finalize().to_vec())
        })
        .collect()
}

fn digest_pcrs(pcrs: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut orden: Vec<&(u32, Vec<u8>)> = pcrs.iter().collect();
    orden.sort_by_key(|(p, _)| *p);
    let mut h = Sha256::new();
    for (_, v) in orden {
        h.update(v);
    }
    h.finalize().to_vec()
}

/// Ensambla un `TPMS_ATTEST` de tipo quote con el nonce y los PCR dados.
fn construir_attest(qualified_signer: &[u8], nonce: &[u8], pcrs: &[(u32, Vec<u8>)]) -> Attest {
    Attest {
        magic: aegis_attest::attest::TPM_GENERATED_VALUE,
        tipo: aegis_attest::attest::TPM_ST_ATTEST_QUOTE,
        qualified_signer: qualified_signer.to_vec(),
        extra_data: nonce.to_vec(),
        clock: 123_456,
        reset_count: 2,
        restart_count: 0,
        safe: 1,
        firmware_version: 0x2020_0100,
        quote: QuoteInfo {
            selecciones: vec![SeleccionPcr {
                alg: HashAlg::Sha256,
                bitmap: [0xFF, 0x00, 0x00].to_vec(), // PCR 0..7
            }],
            pcr_digest: digest_pcrs(pcrs),
        },
    }
}

// --- Areas publicas TPMT_PUBLIC construidas a mano --------------------------

fn area_rsa(n: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&0x0001u16.to_be_bytes()); // type RSA
    v.extend_from_slice(&0x000Bu16.to_be_bytes()); // nameAlg SHA256
    v.extend_from_slice(&0u32.to_be_bytes()); // objectAttributes
    v.extend_from_slice(&0u16.to_be_bytes()); // authPolicy TPM2B vacio
    v.extend_from_slice(&0x0010u16.to_be_bytes()); // symmetric NULL
    v.extend_from_slice(&0x0010u16.to_be_bytes()); // scheme NULL
    v.extend_from_slice(&2048u16.to_be_bytes()); // keyBits
    v.extend_from_slice(&0u32.to_be_bytes()); // exponent = 0 -> 65537
    v.extend_from_slice(&(n.len() as u16).to_be_bytes()); // unique TPM2B
    v.extend_from_slice(n);
    v
}

fn area_ecc(x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&0x0023u16.to_be_bytes()); // type ECC
    v.extend_from_slice(&0x000Bu16.to_be_bytes()); // nameAlg SHA256
    v.extend_from_slice(&0u32.to_be_bytes());
    v.extend_from_slice(&0u16.to_be_bytes()); // authPolicy
    v.extend_from_slice(&0x0010u16.to_be_bytes()); // symmetric NULL
    v.extend_from_slice(&0x0010u16.to_be_bytes()); // scheme NULL
    v.extend_from_slice(&0x0003u16.to_be_bytes()); // curve NIST P-256
    v.extend_from_slice(&0x0010u16.to_be_bytes()); // kdf NULL
    v.extend_from_slice(&(x.len() as u16).to_be_bytes());
    v.extend_from_slice(x);
    v.extend_from_slice(&(y.len() as u16).to_be_bytes());
    v.extend_from_slice(y);
    v
}

// --- Round-trip del codec ---------------------------------------------------

#[test]
fn el_codec_de_attest_es_una_inversa_exacta() {
    let pcrs = pcrs_de_arranque();
    let attest = construir_attest(b"nombre-ak", &[7u8; 32], &pcrs);
    let bytes = attest.marshal();
    let reparseado = Attest::parse(&bytes).expect("parsea");
    assert_eq!(attest, reparseado, "parse(marshal(x)) tiene que dar x");
    assert_eq!(bytes, reparseado.marshal(), "marshal es estable");
}

#[test]
fn un_tpm2b_que_se_sale_del_buffer_es_error_no_panico() {
    // magic + tipo + un TPM2B que declara 1000 bytes en un buffer minusculo.
    let mut b = Vec::new();
    b.extend_from_slice(&aegis_attest::attest::TPM_GENERATED_VALUE.to_be_bytes());
    b.extend_from_slice(&aegis_attest::attest::TPM_ST_ATTEST_QUOTE.to_be_bytes());
    b.extend_from_slice(&1000u16.to_be_bytes()); // qualifiedSigner enorme
    b.push(0x41);
    assert!(Attest::parse(&b).is_err(), "no debe panicar ni leer fuera");
}

// --- Ed25519 ----------------------------------------------------------------

#[test]
fn quote_ed25519_autentico_se_acepta_y_manipulado_se_rechaza() {
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;

    let sk = SigningKey::generate(&mut OsRng);
    let ak = ClavePublicaAk::Ed25519(sk.verifying_key().to_bytes());

    let pcrs = pcrs_de_arranque();
    let nonce = [0x5Au8; 32];
    let attest = construir_attest(b"ak-ed25519", &nonce, &pcrs);
    let bytes = attest.marshal();
    let firma = sk.sign(&bytes).to_bytes().to_vec();

    let entrada = Entrada {
        attest_firmado: &bytes,
        firma: &firma,
        ak: &ak,
        ak_name_esperado: None,
        nonce_esperado: &nonce,
        pcrs_presentados: &pcrs,
        hash_firma: HashAlg::Sha256,
        dorados: Some(&pcrs),
    };
    assert_eq!(
        verificar_quote(&entrada).unwrap(),
        Veredicto::Valido,
        "un quote autentico y fresco se acepta"
    );

    // Un byte del quote volteado -> la firma ya no verifica.
    let mut manipulado = bytes.clone();
    manipulado[40] ^= 0x01;
    let entrada_mala = Entrada {
        attest_firmado: &manipulado,
        firma: &firma,
        ..leer_entrada(&ak, &nonce, &pcrs)
    };
    assert!(
        verificar_quote(&entrada_mala).unwrap().es_fallo(),
        "un quote con un byte cambiado se rechaza: la firma no cubre esa version"
    );
}

// Construye una Entrada base reutilizable (con firma vacia, que se sobreescribe).
fn leer_entrada<'a>(
    ak: &'a ClavePublicaAk,
    nonce: &'a [u8],
    pcrs: &'a [(u32, Vec<u8>)],
) -> Entrada<'a> {
    Entrada {
        attest_firmado: &[],
        firma: &[],
        ak,
        ak_name_esperado: None,
        nonce_esperado: nonce,
        pcrs_presentados: pcrs,
        hash_firma: HashAlg::Sha256,
        dorados: None,
    }
}

// --- ECDSA P-256, con parseo del area publica y Name ------------------------

#[test]
fn quote_ecdsa_p256_con_area_publica_real() {
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    use rand_core::OsRng;

    let sk = SigningKey::random(&mut OsRng);
    let vk = sk.verifying_key();
    let punto = vk.to_encoded_point(false);
    let x = punto.x().unwrap().to_vec();
    let y = punto.y().unwrap().to_vec();

    // El area publica real se parsea y produce la misma clave y un Name valido.
    let area = area_ecc(&x, &y);
    let ap = AreaPublica::parse(&area).expect("area ECC parsea");
    assert_eq!(
        ap.clave,
        ClavePublicaAk::EcdsaP256 {
            x: x.clone(),
            y: y.clone()
        }
    );
    assert_eq!(ap.name.len(), 2 + 32, "Name = alg(2) || SHA256(32)");

    let pcrs = pcrs_de_arranque();
    let nonce = [0x11u8; 32];
    let attest = construir_attest(&ap.name, &nonce, &pcrs);
    let bytes = attest.marshal();
    let sig: Signature = sk.sign(&bytes);
    let firma = sig.to_bytes().to_vec();

    let entrada = Entrada {
        attest_firmado: &bytes,
        firma: &firma,
        ak: &ap.clave,
        ak_name_esperado: Some(&ap.name),
        nonce_esperado: &nonce,
        pcrs_presentados: &pcrs,
        hash_firma: HashAlg::Sha256,
        dorados: None,
    };
    assert_eq!(verificar_quote(&entrada).unwrap(), Veredicto::Valido);

    // AK equivocada: el Name esperado es otro -> se rechaza aunque la firma sea
    // valida, porque no es la clave matriculada.
    let entrada_otro_name = Entrada {
        ak_name_esperado: Some(b"otro-name-cualquiera"),
        ..Entrada {
            attest_firmado: &bytes,
            firma: &firma,
            ak: &ap.clave,
            ak_name_esperado: None,
            nonce_esperado: &nonce,
            pcrs_presentados: &pcrs,
            hash_firma: HashAlg::Sha256,
            dorados: None,
        }
    };
    assert!(verificar_quote(&entrada_otro_name).unwrap().es_fallo());
}

// --- RSA-2048 y los vectores negativos de contenido -------------------------

#[test]
fn quote_rsa_y_todos_los_rechazos_de_contenido() {
    use rand_core::OsRng;
    use rsa::pkcs1v15::SigningKey;
    use rsa::signature::{SignatureEncoding, Signer};
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;

    let priv_key = RsaPrivateKey::new(&mut OsRng, 2048).expect("genera RSA");
    let pk = priv_key.to_public_key();
    let n = pk.n().to_bytes_be();
    let area = area_rsa(&n);
    let ap = AreaPublica::parse(&area).expect("area RSA parsea");
    let ak = ap.clave.clone();

    let signing = SigningKey::<Sha256>::new(priv_key);

    let pcrs = pcrs_de_arranque();
    let nonce = [0x22u8; 32];

    // Helper: firma un attest dado y verifica con la entrada dada.
    let firmar = |attest: &Attest| -> Vec<u8> { signing.sign(&attest.marshal()).to_vec() };

    // 1. Autentico -> Valido.
    let bueno = construir_attest(&ap.name, &nonce, &pcrs);
    let bytes = bueno.marshal();
    let firma = firmar(&bueno);
    let entrada_ok = Entrada {
        attest_firmado: &bytes,
        firma: &firma,
        ak: &ak,
        ak_name_esperado: Some(&ap.name),
        nonce_esperado: &nonce,
        pcrs_presentados: &pcrs,
        hash_firma: HashAlg::Sha256,
        dorados: Some(&pcrs),
    };
    assert_eq!(verificar_quote(&entrada_ok).unwrap(), Veredicto::Valido);

    // 2. Nonce equivocado (reproduccion de otro desafio).
    let otro_nonce = [0x99u8; 32];
    let entrada_nonce = Entrada {
        nonce_esperado: &otro_nonce,
        ..Entrada {
            attest_firmado: &bytes,
            firma: &firma,
            ak: &ak,
            ak_name_esperado: Some(&ap.name),
            nonce_esperado: &nonce,
            pcrs_presentados: &pcrs,
            hash_firma: HashAlg::Sha256,
            dorados: None,
        }
    };
    assert!(
        verificar_quote(&entrada_nonce).unwrap().es_fallo(),
        "nonce mal -> fallo"
    );

    // 3. PCR presentado alterado: el digest firmado ya no casa.
    let mut pcrs_falsos = pcrs.clone();
    pcrs_falsos[3].1[0] ^= 0xFF;
    let entrada_pcr = Entrada {
        pcrs_presentados: &pcrs_falsos,
        ..Entrada {
            attest_firmado: &bytes,
            firma: &firma,
            ak: &ak,
            ak_name_esperado: Some(&ap.name),
            nonce_esperado: &nonce,
            pcrs_presentados: &pcrs,
            hash_firma: HashAlg::Sha256,
            dorados: None,
        }
    };
    assert!(
        verificar_quote(&entrada_pcr).unwrap().es_fallo(),
        "un PCR alterado no casa con el digest firmado"
    );

    // 4. PCR autentico pero distinto del dorado: el arranque cambio.
    let mut dorados = pcrs.clone();
    dorados[4].1[0] ^= 0x01;
    let entrada_dorado = Entrada {
        dorados: Some(&dorados),
        ..Entrada {
            attest_firmado: &bytes,
            firma: &firma,
            ak: &ak,
            ak_name_esperado: Some(&ap.name),
            nonce_esperado: &nonce,
            pcrs_presentados: &pcrs,
            hash_firma: HashAlg::Sha256,
            dorados: None,
        }
    };
    assert!(
        verificar_quote(&entrada_dorado).unwrap().es_fallo(),
        "PCR autentico que no coincide con el dorado -> fallo (arranque alterado)"
    );
}
