//! Autoataque: el compilador y el motor, usados contra el producto.
//!
//! Un motor de patrones tiene dos superficies: el COMPILADOR, que lee reglas que
//! quiza escribio un tercero, y el MOTOR, que lee bytes que elige el atacante. Las
//! dos tienen que fallar EN EL INTENTO, no aguantar por suerte.

use aegis_patron::{ErrorCompilacion, Motor};

#[test]
fn una_regla_con_salto_sin_cota_no_compila() {
    // El compilador como superficie: una regla cuyo coste no se puede demostrar se
    // rechaza, y el error dice que parte no se acota.
    let e =
        Motor::compilar("rule M { strings: $s = { 90 [5-] 90 } condition: $s }", "x").unwrap_err();
    assert!(matches!(e, ErrorCompilacion::SinCota { .. }), "{e:?}");
}

#[test]
fn un_salto_gigante_aunque_acotado_tambien_se_rechaza() {
    // `[0-1000000]` tiene cota, pero es una via de agotamiento: se rechaza por
    // superar el maximo demostrable.
    let e = Motor::compilar(
        "rule G { strings: $s = { 90 [0-1000000] 90 } condition: $s }",
        "x",
    )
    .unwrap_err();
    assert!(matches!(e, ErrorCompilacion::SinCota { .. }), "{e:?}");
}

#[test]
fn una_regla_mal_formada_no_hace_panico() {
    // Sintaxis rota por muchos sitios: se devuelve un error, no un panico.
    for mala in [
        "rule",
        "rule {",
        "rule X { strings: $a = condition: $a }",
        "rule X { condition: 5 of }",
        "rule X { strings: $a = { zz } condition: $a }",
        "rule X { strings: $a = \"sin cerrar condition: $a }",
        "}{}{",
        "rule X { condition: $inexistente or or }",
    ] {
        let _ = Motor::compilar(mala, "x"); // no debe entrar en panico
    }
}

#[test]
fn el_motor_no_hace_panico_ni_se_cuelga_con_entradas_hostiles() {
    // El motor como superficie. Se compila un conjunto con muchas cadenas y se le
    // dan entradas adversarias: enormes, repetitivas, y con casi-coincidencias.
    let fuente = r#"
        rule R1 { strings: $a="AAAA" $b="BBBB" condition: $a and $b }
        rule R2 { strings: $a="root" nocase $b="/etc/" condition: $a or $b }
        rule R3 { strings: $s = { 41 ?? 41 [1-3] 42 } condition: $s }
    "#;
    let motor = Motor::compilar(fuente, "x").unwrap();

    // Entrada gigante de un solo byte: el prefiltro no puede reservar por byte.
    let grande = vec![0x41u8; 2_000_000];
    let _ = motor.escanear(&grande);

    // Entrada que casi casa el patron hex una y otra vez.
    let mut casi = Vec::new();
    for _ in 0..100_000 {
        casi.extend_from_slice(&[0x41, 0x00, 0x41, 0x99]);
    }
    let _ = motor.escanear(&casi);

    // Entrada vacia.
    assert!(motor.escanear(&[]).detecciones.is_empty());

    // Barrido pseudoaleatorio: termina siempre.
    let mut x = 0x1234_5678u64;
    for _ in 0..20 {
        let mut d = Vec::with_capacity(8192);
        for _ in 0..8192 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            d.push(x as u8);
        }
        let _ = motor.escanear(&d);
    }
}

#[test]
fn el_escaneo_parcial_de_una_entrada_enorme_lo_declara() {
    // Tri-estado bajo carga: escanear un tope de un buffer grande dice que fue
    // parcial, en vez de devolver «limpio».
    let motor = Motor::compilar(r#"rule R { strings: $a="zzz" condition: $a }"#, "x").unwrap();
    let grande = vec![0u8; 10_000_000];
    let r = motor.escanear_hasta(&grande, 4096);
    assert!(!r.completo);
    assert_eq!(r.bytes_escaneados, 4096);
}
