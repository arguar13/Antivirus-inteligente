//! El lector contra ejecutables de Windows REALES, construidos aqui.
//!
//! # Por que no hay ficheros de prueba en el repositorio
//!
//! Un `.exe` guardado en `tests/datos/` es una foto: se genero una vez, con un
//! enlazador, y prueba que el lector entiende ESE fichero. Lo que hace falta
//! saber es si entiende los que produce una cadena de compilacion de verdad, que
//! es lo que va a encontrarse en una maquina.
//!
//! Esta maquina de integracion tiene `clang` y `lld-link`, y ya los usa para
//! compilar el driver de Windows desde Linux. Asi que aqui los ejecutables se
//! **construyen en el momento**: un PE32+ real, con su encabezado DOS, su
//! encabezado opcional, su tabla de secciones y su punto de entrada. Y el
//! testigo tampoco es este crate: lo que dice el lector se coteja contra
//! `llvm-readobj`, que es otra implementacion, escrita por otra gente, del mismo
//! formato.
//!
//! Donde no haya cadena de compilacion, las pruebas se **omiten diciendolo**.
//! Una prueba que se salta en silencio es peor que no tenerla.

use std::path::{Path, PathBuf};
use std::process::Command;

use aegis_pe::{huella_authenticode, Formato, Imagen, Informe, PeError};

/// Construye un ejecutable de Windows de verdad y devuelve sus bytes.
///
/// Devuelve `None` si esta maquina no tiene la cadena de compilacion, y quien
/// llama lo dice en voz alta en vez de dar la prueba por pasada.
fn construir_pe(nombre: &str, fuente: &str) -> Option<(Vec<u8>, PathBuf)> {
    for cual in ["clang", "lld-link"] {
        if Command::new(cual).arg("--version").output().is_err() {
            return None;
        }
    }
    let dir = std::env::temp_dir().join(format!("aegis-pe-{nombre}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    let c = dir.join("t.c");
    let obj = dir.join("t.obj");
    let exe = dir.join("t.exe");
    std::fs::write(&c, fuente).ok()?;

    let r = Command::new("clang")
        .args(["--target=x86_64-pc-windows-msvc", "-ffreestanding", "-c"])
        .arg(&c)
        .arg("-o")
        .arg(&obj)
        .output()
        .ok()?;
    if !r.status.success() {
        eprintln!("OMITIDA: clang no pudo compilar para Windows");
        return None;
    }
    let r = Command::new("lld-link")
        .args(["/subsystem:console", "/entry:punto", "/nodefaultlib"])
        .arg(format!("/out:{}", exe.display()))
        .arg(&obj)
        .output()
        .ok()?;
    if !r.status.success() {
        eprintln!("OMITIDA: lld-link no pudo enlazar un PE");
        return None;
    }
    let bytes = std::fs::read(&exe).ok()?;
    Some((bytes, exe))
}

/// Un ejecutable con dos secciones y algo de contenido en cada una.
const FUENTE: &str = r#"
volatile int contador = 7;
const char saludo[] = "aegis";
int punto(void) { return contador + (int)saludo[0]; }
"#;

/// Lo que dice `llvm-readobj` de un fichero, para cotejar.
fn readobj(ruta: &Path) -> Option<String> {
    let r = Command::new("llvm-readobj")
        .arg("--file-headers")
        .arg(ruta)
        .output()
        .ok()?;
    r.status
        .success()
        .then(|| String::from_utf8_lossy(&r.stdout).into_owned())
}

fn campo<'a>(salida: &'a str, clave: &str) -> Option<&'a str> {
    salida
        .lines()
        .find(|l| l.trim_start().starts_with(clave))
        .and_then(|l| l.split(':').nth(1))
        .map(|v| v.trim())
}

// ---------------------------------------------------------------------------
// Contra un PE real, cotejado con otra implementacion
// ---------------------------------------------------------------------------

#[test]
fn un_pe_real_se_lee_y_coincide_con_lo_que_dice_llvm_readobj() {
    let Some((bytes, ruta)) = construir_pe("basico", FUENTE) else {
        eprintln!("OMITIDA: esta maquina no tiene clang/lld-link para Windows");
        return;
    };
    let imagen = Imagen::leer(&bytes).expect("leer un PE real");

    assert_eq!(imagen.formato, Formato::Pe32Mas, "x86_64 es PE32+");
    assert_eq!(imagen.maquina, 0x8664, "IMAGE_FILE_MACHINE_AMD64");
    assert!(
        !imagen.secciones.is_empty(),
        "un ejecutable tiene secciones"
    );
    assert!(
        imagen.punto_de_entrada != 0,
        "el enlazador puso un punto de entrada"
    );
    assert!(
        imagen.seccion_de_rva(imagen.punto_de_entrada).is_some(),
        "y cae dentro de una seccion, que es lo normal en un fichero sano"
    );

    // El testigo independiente.
    let Some(salida) = readobj(&ruta) else {
        eprintln!("(sin llvm-readobj para cotejar; el resto de la prueba ya paso)");
        return;
    };
    let secciones: u16 = campo(&salida, "SectionCount")
        .and_then(|v| v.parse().ok())
        .expect("SectionCount de llvm-readobj");
    assert_eq!(
        imagen.secciones.len() as u16,
        secciones,
        "el numero de secciones tiene que coincidir con el que ve llvm-readobj"
    );
    assert!(
        campo(&salida, "Machine")
            .unwrap_or_default()
            .contains("AMD64"),
        "y la maquina tambien"
    );
}

#[test]
fn las_secciones_de_un_pe_real_caben_dentro_del_fichero() {
    let Some((bytes, _)) = construir_pe("secciones", FUENTE) else {
        eprintln!("OMITIDA: sin cadena de compilacion para Windows");
        return;
    };
    let imagen = Imagen::leer(&bytes).unwrap();
    for s in &imagen.secciones {
        let fin = u64::from(s.offset_bruto) + u64::from(s.tamano_bruto);
        assert!(
            fin <= bytes.len() as u64,
            "la seccion «{}» dice ir hasta {fin} y el fichero mide {}",
            s.nombre,
            bytes.len()
        );
    }
}

// ---------------------------------------------------------------------------
// La huella Authenticode, por sus propiedades
// ---------------------------------------------------------------------------

#[test]
fn cambiar_el_checksum_no_mueve_la_huella_authenticode() {
    // La propiedad que define la huella. Windows recalcula el CheckSum al
    // firmar, asi que si entrara en el calculo ninguna firma cuadraria jamas.
    // Un lector que hashee el fichero entero pasa todas las demas pruebas y
    // falla esta.
    let Some((bytes, _)) = construir_pe("checksum", FUENTE) else {
        eprintln!("OMITIDA: sin cadena de compilacion para Windows");
        return;
    };
    let imagen = Imagen::leer(&bytes).unwrap();
    let antes = huella_authenticode(&imagen, &bytes).unwrap();

    let mut tocado = bytes.clone();
    let off = imagen.offset_checksum as usize;
    tocado[off..off + 4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    let imagen2 = Imagen::leer(&tocado).unwrap();
    let despues = huella_authenticode(&imagen2, &tocado).unwrap();

    assert_eq!(
        antes, despues,
        "el CheckSum esta fuera de la huella a proposito"
    );
    assert_ne!(bytes, tocado, "y de verdad se cambio el fichero");
}

#[test]
fn cambiar_la_entrada_del_directorio_de_seguridad_no_mueve_la_huella() {
    // El otro tramo saltado: apunta a la firma, que todavia no existe cuando se
    // calcula la huella.
    let Some((bytes, _)) = construir_pe("dirseg", FUENTE) else {
        eprintln!("OMITIDA: sin cadena de compilacion para Windows");
        return;
    };
    let imagen = Imagen::leer(&bytes).unwrap();
    let antes = huella_authenticode(&imagen, &bytes).unwrap();

    let mut tocado = bytes.clone();
    let off = imagen.offset_dir_seguridad as usize;
    // Se toca la entrada del directorio SIN declarar una tabla que exista: lo
    // que se comprueba es que esos ocho bytes no entran en la huella.
    tocado[off..off + 8].copy_from_slice(&[0xAA; 8]);
    let despues = huella_authenticode(&imagen, &tocado).unwrap();

    assert_eq!(antes, despues, "esos ocho bytes estan fuera de la huella");
}

#[test]
fn cambiar_un_byte_de_una_seccion_si_mueve_la_huella() {
    // La otra mitad de la propiedad. Sin esta, «saltarse el CheckSum» podria
    // estar implementado como «no hashear nada» y la prueba anterior pasaria.
    let Some((bytes, _)) = construir_pe("seccion", FUENTE) else {
        eprintln!("OMITIDA: sin cadena de compilacion para Windows");
        return;
    };
    let imagen = Imagen::leer(&bytes).unwrap();
    let antes = huella_authenticode(&imagen, &bytes).unwrap();

    let s = imagen
        .secciones
        .iter()
        .find(|s| s.tamano_bruto > 0)
        .expect("alguna seccion con bytes");
    let mut tocado = bytes.clone();
    tocado[s.offset_bruto as usize] ^= 0xFF;
    let despues = huella_authenticode(&imagen, &tocado).unwrap();

    assert_ne!(
        antes, despues,
        "cambiar el codigo tiene que invalidar la firma"
    );
}

#[test]
fn cambiar_un_byte_del_talon_dos_si_mueve_la_huella() {
    // El talon DOS —el «This program cannot be run in DOS mode»— esta antes del
    // CheckSum y dentro de la huella. Es sitio clasico para esconder datos.
    let Some((bytes, _)) = construir_pe("talon", FUENTE) else {
        eprintln!("OMITIDA: sin cadena de compilacion para Windows");
        return;
    };
    let imagen = Imagen::leer(&bytes).unwrap();
    let antes = huella_authenticode(&imagen, &bytes).unwrap();

    let mut tocado = bytes.clone();
    tocado[0x40] ^= 0xFF; // dentro del talon, detras del encabezado DOS
    let despues = huella_authenticode(&imagen, &tocado).unwrap();

    assert_ne!(antes, despues, "el talon DOS entra en la huella");
}

#[test]
fn pegar_datos_al_final_si_mueve_la_huella_cuando_no_hay_firma() {
    // Sin tabla de certificados, todo el overlay entra en la huella. Es lo que
    // impide pegarle una carga a un instalador sin que se note.
    let Some((bytes, _)) = construir_pe("overlay", FUENTE) else {
        eprintln!("OMITIDA: sin cadena de compilacion para Windows");
        return;
    };
    let imagen = Imagen::leer(&bytes).unwrap();
    let antes = huella_authenticode(&imagen, &bytes).unwrap();

    let mut tocado = bytes.clone();
    tocado.extend_from_slice(b"carga pegada detras");
    let despues = huella_authenticode(&imagen, &tocado).unwrap();

    assert_ne!(antes, despues, "lo pegado detras entra en la huella");
}

#[test]
fn la_huella_de_un_mismo_fichero_es_siempre_la_misma() {
    let Some((bytes, _)) = construir_pe("estable", FUENTE) else {
        eprintln!("OMITIDA: sin cadena de compilacion para Windows");
        return;
    };
    let imagen = Imagen::leer(&bytes).unwrap();
    let a = huella_authenticode(&imagen, &bytes).unwrap();
    let b = huella_authenticode(&imagen, &bytes).unwrap();
    assert_eq!(a, b);
}

#[test]
fn la_huella_authenticode_no_es_el_sha256_del_fichero() {
    // Si coincidieran, seria que no se esta saltando nada — y toda la
    // implementacion estaria mal de una forma que ninguna otra prueba ve.
    use sha2::{Digest, Sha256};
    let Some((bytes, _)) = construir_pe("distinta", FUENTE) else {
        eprintln!("OMITIDA: sin cadena de compilacion para Windows");
        return;
    };
    let imagen = Imagen::leer(&bytes).unwrap();
    let authenticode = huella_authenticode(&imagen, &bytes).unwrap();
    let plano: [u8; 32] = Sha256::digest(&bytes).into();
    assert_ne!(
        authenticode, plano,
        "la huella salta tres tramos: no puede coincidir con el hash del fichero"
    );
}

// ---------------------------------------------------------------------------
// Entrada hostil: lo que importa es que NUNCA entre en panico
// ---------------------------------------------------------------------------

#[test]
fn truncar_un_pe_real_por_cualquier_sitio_no_provoca_un_panico() {
    // El agente parsea ficheros que elige el atacante, con `panic = "abort"`.
    // Un panico aqui es el proceso entero muriendose, y un EDR que se mata
    // mandandole un fichero se desinstala solo. Se trunca por cada uno de
    // doscientos puntos y lo unico que se exige es que la respuesta sea `Ok` o
    // un `Err` con nombre.
    let Some((bytes, _)) = construir_pe("truncado", FUENTE) else {
        eprintln!("OMITIDA: sin cadena de compilacion para Windows");
        return;
    };
    let paso = (bytes.len() / 200).max(1);
    let mut errores = 0usize;
    let mut leidos = 0usize;
    for corte in (0..bytes.len()).step_by(paso) {
        match Informe::de(&bytes[..corte]) {
            Ok(_) => leidos += 1,
            Err(_) => errores += 1,
        }
    }
    assert!(errores > 0, "algun corte tiene que quedarse corto");
    assert!(
        errores + leidos >= 100,
        "se probaron {} cortes",
        errores + leidos
    );
}

#[test]
fn voltear_bytes_sueltos_de_un_pe_real_no_provoca_un_panico() {
    // Mutacion dirigida a los encabezados, que es donde estan los
    // desplazamientos que el lector sigue. Generador determinista: una prueba
    // que falla una vez de cada cien y no se puede reproducir no sirve de nada.
    let Some((bytes, _)) = construir_pe("volteado", FUENTE) else {
        eprintln!("OMITIDA: sin cadena de compilacion para Windows");
        return;
    };
    let mut semilla = 0x5EED_1234_u64;
    let zona = bytes.len().min(1024);
    for _ in 0..3000 {
        // Congruencial lineal: reproducible y suficiente para elegir posiciones.
        semilla = semilla
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        let pos = (semilla >> 33) as usize % zona;
        let bit = ((semilla >> 17) & 7) as u8;
        let mut roto = bytes.clone();
        roto[pos] ^= 1 << bit;
        // No se mira el resultado: se mira que haya resultado.
        let _ = Informe::de(&roto);
    }
}

#[test]
fn un_numero_de_secciones_imposible_se_rechaza_sin_reservar_memoria() {
    // `NumberOfSections` a 0xFFFF con un fichero de un kilobyte: un lector que
    // reserve antes de comprobar pide sitio para 65535 secciones por cada
    // fichero que le manden.
    let Some((bytes, _)) = construir_pe("secciones-imposibles", FUENTE) else {
        eprintln!("OMITIDA: sin cadena de compilacion para Windows");
        return;
    };
    let imagen = Imagen::leer(&bytes).unwrap();
    let lfanew = u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]) as usize;
    let mut roto = bytes.clone();
    roto[lfanew + 6..lfanew + 8].copy_from_slice(&0xFFFFu16.to_le_bytes());
    let e = Imagen::leer(&roto).unwrap_err();
    assert!(
        matches!(e, PeError::DemasiadasSecciones(0xFFFF)),
        "tiene que rechazarse por el numero, antes de tocar memoria: {e}"
    );
    assert!(imagen.secciones.len() < 96, "el original es razonable");
}

#[test]
fn un_e_lfanew_que_apunta_fuera_del_fichero_se_rechaza() {
    let Some((bytes, _)) = construir_pe("lfanew", FUENTE) else {
        eprintln!("OMITIDA: sin cadena de compilacion para Windows");
        return;
    };
    let mut roto = bytes.clone();
    roto[0x3C..0x40].copy_from_slice(&0x7FFF_FFFFu32.to_le_bytes());
    let e = Imagen::leer(&roto).unwrap_err();
    assert!(matches!(e, PeError::SeAcabaElFichero { .. }), "{e}");
}

#[test]
fn una_magic_desconocida_en_el_encabezado_opcional_se_rechaza() {
    let Some((bytes, _)) = construir_pe("magic", FUENTE) else {
        eprintln!("OMITIDA: sin cadena de compilacion para Windows");
        return;
    };
    let lfanew = u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]) as usize;
    let mut roto = bytes.clone();
    // El encabezado opcional empieza 24 bytes despues de la firma PE.
    roto[lfanew + 24..lfanew + 26].copy_from_slice(&0x1234u16.to_le_bytes());
    let e = Imagen::leer(&roto).unwrap_err();
    assert!(matches!(e, PeError::MagicDesconocida(0x1234)), "{e}");
}

// ---------------------------------------------------------------------------
// El informe completo
// ---------------------------------------------------------------------------

#[test]
fn el_informe_de_un_pe_real_dice_que_no_lleva_firma_y_lo_dice_como_indicio() {
    let Some((bytes, _)) = construir_pe("informe", FUENTE) else {
        eprintln!("OMITIDA: sin cadena de compilacion para Windows");
        return;
    };
    let informe = Informe::de(&bytes).expect("informe de un PE real");
    assert!(
        !informe.lleva_tabla_de_certificados(),
        "lld-link no firma: este fichero no lleva tabla de certificados"
    );
    assert!(informe.indicios.contains(&aegis_pe::Indicio::SinFirma));
    // Y la frase dice su falso positivo, porque no llevar firma es lo normal.
    let frase = aegis_pe::Indicio::SinFirma.frase();
    assert!(frase.contains("la mayoria"), "{frase}");
}
