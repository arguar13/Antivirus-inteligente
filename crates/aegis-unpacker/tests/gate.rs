//! Pruebas del filtro de entropia.
//!
//! Con datos reales: codigo real de baja entropia, ruido criptografico de alta.

use aegis_unpacker::gate::{evaluar, Seccion};

/// Bytes que parecen codigo real: mucha estructura, valores repetidos.
fn codigo_real(n: usize) -> Vec<u8> {
    // Un patron de instrucciones x86 tipicas: muchos 0x00, 0x48, 0x89, 0xE5...
    let patron = [
        0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x10, 0x89, 0x7D, 0xFC, 0x8B, 0x45, 0xFC, 0xC9,
        0xC3, 0x00, 0x00,
    ];
    patron.iter().copied().cycle().take(n).collect()
}

/// Bytes de alta entropia: un flujo pseudoaleatorio determinista (un cifrado
/// real produce esto).
fn ruido(n: usize, semilla: u64) -> Vec<u8> {
    let mut x = semilla;
    (0..n)
        .map(|_| {
            x = x
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (x >> 33) as u8
        })
        .collect()
}

#[test]
fn un_binario_normal_no_se_marca_como_empaquetado() {
    let secciones = vec![
        Seccion {
            nombre: ".text".into(),
            ejecutable: true,
            datos: codigo_real(8192),
        },
        Seccion {
            nombre: ".rodata".into(),
            ejecutable: false,
            datos: b"cadenas de texto legibles y tablas".repeat(50),
        },
    ];
    let v = evaluar(&secciones);
    assert!(
        !v.empaquetado,
        "codigo real no es empaquetado: {}",
        v.motivo
    );
}

#[test]
fn un_binario_con_la_seccion_de_codigo_cifrada_se_marca() {
    // El patron del empaquetador: la seccion EJECUTABLE es de alta entropia
    // porque el codigo real esta comprimido/cifrado dentro.
    let secciones = vec![Seccion {
        nombre: ".text".into(),
        ejecutable: true,
        datos: ruido(16384, 42),
    }];
    let v = evaluar(&secciones);
    assert!(
        v.empaquetado,
        "una seccion de codigo cifrada se marca: {}",
        v.motivo
    );
}

#[test]
fn una_seccion_de_datos_comprimida_no_basta_para_marcar() {
    // Un binario legitimo con recursos comprimidos en una seccion de DATOS pero
    // su codigo en claro en .text NO es un empaquetador.
    let secciones = vec![
        Seccion {
            nombre: ".text".into(),
            ejecutable: true,
            datos: codigo_real(8192),
        },
        Seccion {
            nombre: ".resources".into(),
            ejecutable: false,
            datos: ruido(16384, 7),
        },
    ];
    let v = evaluar(&secciones);
    assert!(
        !v.empaquetado,
        "datos comprimidos con codigo en claro no es empaquetado: {}",
        v.motivo
    );
}

#[test]
fn sin_secciones_ejecutables_no_se_marca() {
    let secciones = vec![Seccion {
        nombre: ".data".into(),
        ejecutable: false,
        datos: ruido(4096, 1),
    }];
    assert!(!evaluar(&secciones).empaquetado);
}
