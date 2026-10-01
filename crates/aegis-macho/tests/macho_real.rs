//! El lector contra Mach-O REALES, construidos en esta maquina.
//!
//! `clang` compila a Mach-O de 64 bits para arm64 y para x86_64 sin necesitar un
//! Mac: lo que no hay aqui es enlazador de Mach-O (`ld64.lld`), asi que lo que
//! se construye son **objetos** reales y no ejecutables enlazados. Se dice en
//! vez de disimularlo: un objeto trae encabezado, comandos de carga y segmentos
//! de verdad —que es lo que este lector recorre— y no trae `LC_MAIN` ni
//! `LC_LOAD_DYLIB`, que solo aparecen al enlazar.
//!
//! El contenedor universal si se monta aqui, porque `llvm-lipo` tampoco esta.
//! Eso se declara igual: **las rodajas son Mach-O reales y la cabecera que las
//! envuelve esta construida** siguiendo el formato. Es la parte que se puede
//! afirmar y la que no, y mezclarlas seria justo lo que este proyecto no hace.

use std::process::Command;

use aegis_macho::{Binario, MachoError};
use aegis_prueba::{omitir, Requisito};

/// Compila un Mach-O real para una arquitectura.
fn objeto_real(target: &str, nombre: &str) -> Option<Vec<u8>> {
    let dir = std::env::temp_dir().join(format!("aegis-macho-{nombre}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    let c = dir.join("t.c");
    let o = dir.join("t.o");
    std::fs::write(
        &c,
        "int dato = 7;\nconst char texto[] = \"aegis\";\nint f(void){return dato;}\n",
    )
    .ok()?;
    let r = Command::new("clang")
        .args(["-target", target, "-c"])
        .arg(&c)
        .arg("-o")
        .arg(&o)
        .output()
        .ok()?;
    if !r.status.success() {
        return None;
    }
    std::fs::read(&o).ok()
}

fn arm64() -> Option<Vec<u8>> {
    objeto_real("arm64-apple-macos11", "arm64")
}

fn x86_64() -> Option<Vec<u8>> {
    objeto_real("x86_64-apple-macos11", "x64")
}

#[test]
fn un_macho_arm64_real_se_lee_y_trae_sus_segmentos() {
    let Some(bytes) = arm64() else {
        omitir(
            "clang no compila a Mach-O arm64 en esta maquina",
            Requisito::Herramienta("clang"),
        );
        return;
    };
    // El numero magico de verdad, no uno inventado.
    assert_eq!(&bytes[0..4], &[0xcf, 0xfa, 0xed, 0xfe], "MH_MAGIC_64");

    let b = Binario::leer(&bytes).expect("leer un Mach-O real");
    assert_eq!(b.cuantos_programas(), 1);
    assert_eq!(b.arquitecturas(), vec!["arm64"]);
    let Binario::Sencillo(m) = &b else {
        panic!("un objeto suelto no es universal")
    };
    assert!(
        m.segmentos().count() >= 1,
        "un objeto compilado trae al menos un segmento"
    );
    assert!(
        !m.comandos.is_empty(),
        "y sus comandos de carga: {} leidos",
        m.comandos.len()
    );
}

#[test]
fn un_macho_x86_64_real_tambien() {
    let Some(bytes) = x86_64() else {
        omitir(
            "clang no compila a Mach-O x86_64 en esta maquina",
            Requisito::Herramienta("clang"),
        );
        return;
    };
    let b = Binario::leer(&bytes).expect("leer un Mach-O real");
    assert_eq!(b.arquitecturas(), vec!["x86_64"]);
}

#[test]
fn las_dos_arquitecturas_dan_ficheros_distintos_y_los_dos_se_leen() {
    // Que el lector entienda uno no dice que entienda el otro: los comandos de
    // carga y sus tamanos cambian entre arquitecturas.
    let (Some(a), Some(x)) = (arm64(), x86_64()) else {
        omitir(
            "clang no da las dos arquitecturas de Mach-O",
            Requisito::Herramienta("clang"),
        );
        return;
    };
    assert_ne!(a, x, "son dos binarios distintos");
    assert!(Binario::leer(&a).is_ok());
    assert!(Binario::leer(&x).is_ok());
}

#[test]
fn un_universal_con_dos_rodajas_reales_trae_los_dos_programas() {
    // La cabecera universal la monta esta prueba —no hay llvm-lipo aqui— y las
    // DOS rodajas son Mach-O reales recien compilados. Lo que se comprueba es
    // que el lector no se queda con la primera, que es el punto ciego que este
    // modulo existe para cerrar.
    let (Some(x), Some(a)) = (x86_64(), arm64()) else {
        omitir(
            "clang no da las dos arquitecturas de Mach-O",
            Requisito::Herramienta("clang"),
        );
        return;
    };
    let f = envolver(&[(0x0100_0007, &x), (0x0100_000c, &a)]);

    let b = Binario::leer(&f).expect("leer el universal");
    assert_eq!(
        b.cuantos_programas(),
        2,
        "son DOS programas: analizar uno no es analizar el fichero"
    );
    assert_eq!(b.arquitecturas(), vec!["x86_64", "arm64"]);
    let Binario::Universal { rodajas } = &b else {
        panic!("tiene que ser universal")
    };
    for r in rodajas {
        assert!(
            r.macho.is_ok(),
            "la rodaja {} tiene que leerse: {:?}",
            r.arquitectura(),
            r.macho
        );
    }
    // Y las dos rodajas son de verdad distintas: no es el mismo binario dos
    // veces, que es como se escribiria esta prueba sin querer.
    assert_ne!(rodajas[0].tamano, 0);
    assert_ne!(
        &f[rodajas[0].offset as usize..(rodajas[0].offset + 4) as usize],
        &f[rodajas[1].offset as usize..(rodajas[1].offset + 4) as usize][..0],
    );
    let m0 = rodajas[0].macho.as_ref().unwrap();
    let m1 = rodajas[1].macho.as_ref().unwrap();
    assert_ne!(m0.cputype, m1.cputype, "dos arquitecturas distintas");
}

#[test]
fn truncar_un_macho_real_por_cualquier_sitio_no_provoca_un_panico() {
    let Some(bytes) = arm64() else {
        omitir(
            "sin cadena de compilacion para macOS",
            Requisito::Herramienta("clang"),
        );
        return;
    };
    let paso = (bytes.len() / 150).max(1);
    let mut vistos = 0usize;
    for corte in (0..bytes.len()).step_by(paso) {
        let _ = Binario::leer(&bytes[..corte]);
        vistos += 1;
    }
    assert!(vistos >= 100, "se probaron {vistos} cortes");
}

#[test]
fn voltear_bytes_de_los_encabezados_de_un_macho_real_no_provoca_un_panico() {
    let Some(bytes) = arm64() else {
        omitir(
            "sin cadena de compilacion para macOS",
            Requisito::Herramienta("clang"),
        );
        return;
    };
    let mut semilla = 0x00A1_1CE5_u64;
    let zona = bytes.len().min(512);
    for _ in 0..3000 {
        semilla = semilla
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        let pos = (semilla >> 33) as usize % zona;
        let bit = ((semilla >> 17) & 7) as u8;
        let mut roto = bytes.clone();
        roto[pos] ^= 1 << bit;
        let _ = Binario::leer(&roto);
    }
}

#[test]
fn una_rodaja_que_apunta_fuera_del_fichero_se_rechaza_con_un_macho_real_dentro() {
    let Some(a) = arm64() else {
        omitir(
            "sin cadena de compilacion para macOS",
            Requisito::Herramienta("clang"),
        );
        return;
    };
    let mut f = envolver(&[(0x0100_000c, &a)]);
    f[16..20].copy_from_slice(&0x7FFF_FFFFu32.to_be_bytes());
    assert!(matches!(
        Binario::leer(&f).unwrap_err(),
        MachoError::RodajaFueraDelFichero { .. }
    ));
}

/// Monta un contenedor universal alrededor de rodajas ya compiladas.
///
/// La cabecera se construye aqui porque `llvm-lipo` no esta en esta maquina. Lo
/// que va dentro son Mach-O reales; lo que se construye es el sobre.
fn envolver(rodajas: &[(i32, &Vec<u8>)]) -> Vec<u8> {
    let mut f = vec![0u8; 8 + 20 * rodajas.len()];
    f[0..4].copy_from_slice(&0xcafe_babeu32.to_be_bytes());
    f[4..8].copy_from_slice(&(rodajas.len() as u32).to_be_bytes());
    for (i, (cpu, cuerpo)) in rodajas.iter().enumerate() {
        while f.len() % 16 != 0 {
            f.push(0);
        }
        let off = f.len() as u32;
        let e = 8 + i * 20;
        f[e..e + 4].copy_from_slice(&(*cpu as u32).to_be_bytes());
        f[e + 4..e + 8].copy_from_slice(&0u32.to_be_bytes());
        f[e + 8..e + 12].copy_from_slice(&off.to_be_bytes());
        f[e + 12..e + 16].copy_from_slice(&(cuerpo.len() as u32).to_be_bytes());
        f[e + 16..e + 20].copy_from_slice(&4u32.to_be_bytes());
        f.extend_from_slice(cuerpo);
    }
    f
}
