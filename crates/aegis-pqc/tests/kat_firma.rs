//! KAT oficial de verificacion de FIPS 204 (ML-DSA-65), vectores NIST ACVP.
//!
//! Es el KAT del **borde de seguridad**: el camino de verificacion es el que
//! protege el firmado de actualizaciones, y estos vectores incluyen los
//! NEGATIVOS del propio NIST (firma con la `z`, la pista o el compromiso
//! alterados, y mensaje alterado). Se ejercita a traves de la API publica
//! [`aegis_pqc::firma`].
#![cfg(feature = "sign")]

use aegis_pqc::firma::{ClaveVerificacion, Firma};

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "longitud hex impar");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("digito hex"))
        .collect()
}

fn casos(json: &str) -> Vec<serde_json::Value> {
    let v: serde_json::Value = serde_json::from_str(json).expect("json de vectores");
    v["casos"].as_array().expect("campo casos").clone()
}

#[test]
fn kat_sigver_fips204_incluye_negativos() {
    let cs = casos(include_str!("vectors/dsa_sigver.json"));
    assert!(!cs.is_empty());

    let mut positivos = 0;
    let mut negativos = 0;

    for c in cs {
        let pk =
            ClaveVerificacion::desde_bytes(&hex(c["pk"].as_str().unwrap())).expect("pk valida");
        let firma =
            Firma::desde_bytes(&hex(c["signature"].as_str().unwrap())).expect("firma valida");
        let msg = hex(c["message"].as_str().unwrap());
        let ctx = hex(c["context"].as_str().unwrap_or(""));
        let esperado = c["testPassed"].as_bool().expect("testPassed");

        let obtenido = pk.verificar(&msg, &ctx, &firma);
        assert_eq!(
            obtenido, esperado,
            "veredicto != esperado (tcId {}, motivo {:?})",
            c["tcId"], c["reason"]
        );

        if esperado {
            positivos += 1;
        } else {
            negativos += 1;
        }
    }

    // La honestidad del KAT exige que haya de los dos: si solo hubiera positivos,
    // un verificador que aceptara TODO pasaria igual.
    assert!(positivos > 0, "debe haber vectores validos");
    assert!(
        negativos > 0,
        "debe haber vectores invalidos (negativos oficiales)"
    );
}
