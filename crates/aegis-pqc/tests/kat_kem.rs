//! Known Answer Tests oficiales de FIPS 203 (ML-KEM-768), vectores NIST ACVP.
//!
//! Es el ancla de honestidad del KEM: una implementacion sutilmente mal pasaria
//! un roundtrip casero pero FALLA estos vectores. Se prueban los tres sentidos:
//! generacion de claves, encapsulado y desencapsulado.
#![cfg(feature = "kem")]

use aegis_pqc::kem::{
    desencapsular, encapsular, ClavePublica, ClaveSecreta, ParClaves, TextoCifrado,
    ENCAPS_ALEATORIEDAD_LEN, SEMILLA_LEN,
};

/// Decodifica una cadena hexadecimal a bytes (helper de prueba, sin dependencias).
fn hex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "longitud hex impar");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("digito hex valido"))
        .collect()
}

/// Extrae el array `casos` del fichero de vectores.
fn casos(json: &str) -> Vec<serde_json::Value> {
    let v: serde_json::Value = serde_json::from_str(json).expect("json de vectores valido");
    v["casos"].as_array().expect("campo casos").clone()
}

fn campo(c: &serde_json::Value, k: &str) -> Vec<u8> {
    hex(c[k].as_str().unwrap_or_else(|| panic!("campo {k} ausente")))
}

#[test]
fn kat_keygen_fips203() {
    let cs = casos(include_str!("vectors/kem_keygen.json"));
    assert!(!cs.is_empty());
    for c in cs {
        let d = campo(&c, "d");
        let z = campo(&c, "z");
        // FIPS 203 KeyGen: la semilla es d || z.
        let mut semilla = [0u8; SEMILLA_LEN];
        semilla[..32].copy_from_slice(&d);
        semilla[32..].copy_from_slice(&z);

        let par = ParClaves::generar(&semilla);
        assert_eq!(
            &par.publica.as_bytes()[..],
            &campo(&c, "ek")[..],
            "ek no coincide (tcId {})",
            c["tcId"]
        );
        assert_eq!(
            &par.secreta().as_bytes()[..],
            &campo(&c, "dk")[..],
            "dk no coincide (tcId {})",
            c["tcId"]
        );
    }
}

#[test]
fn kat_encaps_fips203() {
    let cs = casos(include_str!("vectors/kem_encaps.json"));
    assert!(!cs.is_empty());
    for c in cs {
        let pk = ClavePublica::desde_bytes(&campo(&c, "ek")).expect("ek valida");
        let mut m = [0u8; ENCAPS_ALEATORIEDAD_LEN];
        m.copy_from_slice(&campo(&c, "m"));

        let (ct, ss) = encapsular(&pk, &m).expect("encapsular");
        assert_eq!(
            &ct.as_bytes()[..],
            &campo(&c, "c")[..],
            "ciphertext no coincide (tcId {})",
            c["tcId"]
        );
        assert_eq!(
            &ss.as_bytes()[..],
            &campo(&c, "k")[..],
            "secreto no coincide (tcId {})",
            c["tcId"]
        );
    }
}

#[test]
fn kat_decaps_fips203() {
    let cs = casos(include_str!("vectors/kem_decaps.json"));
    assert!(!cs.is_empty());
    for c in cs {
        let sk = ClaveSecreta::desde_bytes(&campo(&c, "dk")).expect("dk valida");
        let ct = TextoCifrado::desde_bytes(&campo(&c, "c")).expect("ct valido");
        let ss = desencapsular(&sk, &ct);
        assert_eq!(
            &ss.as_bytes()[..],
            &campo(&c, "k")[..],
            "secreto desencapsulado no coincide (tcId {})",
            c["tcId"]
        );
    }
}
