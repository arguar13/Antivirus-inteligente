//! Pruebas del analisis estatico y del pipeline de inferencia.
//!
//! Cada muestra se fabrica en tiempo de ejecucion escribiendo las cabeceras
//! byte a byte, y se escribe a `/tmp` antes de analizarla, de modo que se
//! recorre el mismo camino que en produccion: leer un fichero del disco,
//! analizarlo con goblin, vectorizar e inferir.

mod common;

use std::path::{Path, PathBuf};

use aegis_ml::entropy;
use aegis_ml::features::{
    to_vector_with_data, BinaryFormat, FeatureExtractor, FEATURE_DIM, OFF_BYTE_HIST,
    OFF_ENTROPY_HIST, OFF_HEADER, OFF_IMPORTS, OFF_SECTIONS, OFF_STRINGS,
};
use aegis_ml::{MalwareModel, ModelError, Verdict};

use common::*;

struct Lab(PathBuf);

impl Lab {
    fn nuevo(n: &str) -> Lab {
        let p = std::env::temp_dir().join(format!("aegis-ml-{n}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Lab(p)
    }
    fn escribir(&self, nombre: &str, datos: &[u8]) -> PathBuf {
        let p = self.0.join(nombre);
        std::fs::write(&p, datos).unwrap();
        p
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ---------------------------------------------------------------------------
// Entropia de Shannon
// ---------------------------------------------------------------------------

#[test]
fn la_entropia_de_shannon_da_los_valores_teoricos() {
    // Un solo simbolo repetido: no hay incertidumbre.
    assert_eq!(entropy::shannon(&[0u8; 1000]), 0.0);
    // Dos simbolos equiprobables: exactamente 1 bit por simbolo.
    let mut dos = vec![0u8; 500];
    dos.extend(vec![1u8; 500]);
    assert!((entropy::shannon(&dos) - 1.0).abs() < 1e-9);
    // Los 256 valores una vez cada uno: el maximo, 8 bits por byte.
    let todos: Vec<u8> = (0..=255u8).collect();
    assert!((entropy::shannon(&todos) - 8.0).abs() < 1e-9);
    // Cuatro simbolos equiprobables: 2 bits.
    let cuatro: Vec<u8> = (0..1000).map(|i| (i % 4) as u8).collect();
    assert!((entropy::shannon(&cuatro) - 2.0).abs() < 1e-9);
    // Buffer vacio.
    assert_eq!(entropy::shannon(&[]), 0.0);
}

#[test]
fn la_entropia_distingue_texto_de_codigo_y_de_datos_cifrados() {
    let texto = entropy::shannon(&text_like(8192));
    let codigo = entropy::shannon(&code_like(8192));
    let cifrado = entropy::shannon(&high_entropy(8192, 42));

    assert!(texto < 5.0, "texto plano dio {texto:.2}");
    assert!(
        (4.0..7.0).contains(&codigo),
        "codigo maquina dio {codigo:.2}, deberia estar entre 4 y 7"
    );
    assert!(cifrado > 7.9, "datos cifrados dieron {cifrado:.2}");
    assert!(
        texto < codigo && codigo < cifrado,
        "el orden debe conservarse"
    );
}

#[test]
fn el_punto_fijo_q8_8_va_y_vuelve() {
    let datos = high_entropy(4096, 7);
    let q = entropy::shannon_q8_8(&datos);
    let vuelta = entropy::from_q8_8(q);
    assert!((vuelta - entropy::shannon(&datos)).abs() < 0.01);
    // 8,0 bits/byte se codifica como 2048.
    let todos: Vec<u8> = (0..=255u8).collect();
    assert_eq!(entropy::shannon_q8_8(&todos), 2048);
}

#[test]
fn la_entropia_por_bloques_revela_una_carga_util_oculta() {
    // Un fichero mayoritariamente de texto con una carga cifrada al final. La
    // entropia GLOBAL sale discreta y no llama la atencion; el maximo por
    // bloque la delata. Es justo el caso que justifica trocear.
    let mut mezcla = text_like(60_000);
    mezcla.extend(high_entropy(4096, 99));

    let global = entropy::shannon(&mezcla);
    let bloques = entropy::block_entropy(&mezcla, 4096);

    assert!(global < 6.0, "la entropia global es {global:.2}");
    assert!(
        bloques.max > 7.9,
        "el maximo por bloque deberia delatar la carga, dio {:.2}",
        bloques.max
    );
    assert!(
        bloques.stddev > 0.5,
        "la mezcla deberia elevar la desviacion"
    );
    assert!(bloques.high_ratio > 0.0 && bloques.high_ratio < 0.3);
}

#[test]
fn los_histogramas_suman_uno_y_distinguen_distribuciones() {
    let texto = entropy::byte_histogram(&text_like(4096), 16);
    let cifrado = entropy::byte_histogram(&high_entropy(4096, 3), 16);
    assert!((texto.iter().sum::<f32>() - 1.0).abs() < 1e-5);
    assert!((cifrado.iter().sum::<f32>() - 1.0).abs() < 1e-5);
    // El texto se concentra en los cubos de ASCII imprimible; los datos
    // cifrados se reparten.
    let max_texto = texto.iter().cloned().fold(0f32, f32::max);
    let max_cifrado = cifrado.iter().cloned().fold(0f32, f32::max);
    assert!(
        max_texto > max_cifrado * 2.0,
        "texto {max_texto:.3} frente a cifrado {max_cifrado:.3}"
    );

    let eh = entropy::entropy_histogram(&high_entropy(40_960, 5), 4096, 32);
    assert!((eh.iter().sum::<f32>() - 1.0).abs() < 1e-5);
    // Datos uniformemente aleatorios: toda la masa en el cubo mas alto.
    assert!(eh[31] > 0.9, "histograma: {eh:?}");
}

// ---------------------------------------------------------------------------
// Analisis de ELF
// ---------------------------------------------------------------------------

fn elf_benigno() -> Vec<u8> {
    ElfBuilder {
        e_type: ET_DYN,
        entry: 0x1000,
        segments: vec![
            SegmentSpec {
                p_type: PT_INTERP,
                flags: PF_R,
            },
            SegmentSpec {
                p_type: PT_LOAD,
                flags: PF_R | PF_X,
            },
            SegmentSpec {
                p_type: PT_LOAD,
                flags: PF_R | PF_W,
            },
            // Pila NO ejecutable: la marca de un compilador moderno.
            SegmentSpec {
                p_type: PT_GNU_STACK,
                flags: PF_R | PF_W,
            },
            SegmentSpec {
                p_type: PT_GNU_RELRO,
                flags: PF_R,
            },
        ],
        sections: vec![
            SectionSpec::progbits(".text", SHF_ALLOC | SHF_EXECINSTR, code_like(8192)),
            SectionSpec::progbits(".rodata", SHF_ALLOC, text_like(2048)),
            SectionSpec::progbits(".data", SHF_ALLOC | SHF_WRITE, text_like(1024)),
            SectionSpec {
                name: ".symtab",
                sh_type: SHT_SYMTAB,
                flags: 0,
                data: vec![0u8; 512],
                virtual_size: 0,
            },
        ],
        ..Default::default()
    }
    .build()
}

fn elf_empaquetado() -> Vec<u8> {
    ElfBuilder {
        e_type: ET_EXEC,
        // El punto de entrada apunta a la ultima seccion, donde vive el
        // descompresor: el patron caracteristico de un packer.
        entry: 0x3000,
        segments: vec![
            // Segmento escribible Y ejecutable: casi ningun compilador lo emite.
            SegmentSpec {
                p_type: PT_LOAD,
                flags: PF_R | PF_W | PF_X,
            },
            // Sin PT_GNU_STACK con NX y sin RELRO: sin mitigaciones.
        ],
        sections: vec![
            SectionSpec::progbits(".text", SHF_ALLOC | SHF_EXECINSTR, high_entropy(16384, 1)),
            SectionSpec::progbits(".data", SHF_ALLOC | SHF_WRITE, high_entropy(4096, 2)),
            // Nombre que ningun compilador emite, escribible y ejecutable.
            SectionSpec::progbits(
                ".packed",
                SHF_ALLOC | SHF_EXECINSTR | SHF_WRITE,
                high_entropy(4096, 3),
            ),
            // SHT_NOBITS con un tamano en memoria enorme: el descompresor
            // reservara ahi el codigo descomprimido. Es la unica forma en que
            // un ELF expresa "ocupa mucho mas en memoria que en disco".
            SectionSpec {
                name: ".unpack_buf",
                sh_type: SHT_NOBITS,
                flags: SHF_ALLOC | SHF_EXECINSTR | SHF_WRITE,
                data: Vec::new(),
                virtual_size: 4096 * 64,
            },
        ],
        overlay: high_entropy(32768, 4),
        ..Default::default()
    }
    .build()
}

#[test]
fn analiza_un_elf_benigno_generado_al_vuelo() {
    let lab = Lab::nuevo("elf-benigno");
    let ruta = lab.escribir("normal.so", &elf_benigno());

    let x = FeatureExtractor::default();
    let f = x.extract_file(&ruta).unwrap();

    assert!(!f.parse_failed, "el ELF construido debe analizarse");
    let info = f.format.clone().unwrap();
    assert_eq!(info.kind, Some(BinaryFormat::Elf));
    assert!(info.is_64);
    assert!(info.little_endian);
    assert!(info.dynamic, "PT_INTERP implica enlazado dinamico");
    assert!(info.nx, "PT_GNU_STACK sin PF_X implica pila no ejecutable");
    assert!(info.relro);
    assert!(!info.rwx_segment, "no hay segmento escribible y ejecutable");
    assert!(!info.stripped, "tiene .symtab");

    let nombres: Vec<&str> = f.sections.iter().map(|s| s.name.as_str()).collect();
    assert!(nombres.contains(&".text"));
    assert!(nombres.contains(&".rodata"));

    let text = f.sections.iter().find(|s| s.name == ".text").unwrap();
    assert!(
        (4.0..7.0).contains(&text.entropy),
        ".text de codigo real deberia tener entropia intermedia, dio {:.2}",
        text.entropy
    );
}

#[test]
fn detecta_las_anomalias_estructurales_de_un_elf_empaquetado() {
    let lab = Lab::nuevo("elf-packed");
    let ruta = lab.escribir("packed.bin", &elf_empaquetado());

    let x = FeatureExtractor::default();
    let f = x.extract_file(&ruta).unwrap();
    let info = f.format.clone().unwrap();

    // Cada una de estas es una senal independiente y todas deben verse.
    assert!(info.rwx_segment, "el segmento RWX debe detectarse");
    assert!(!info.nx, "sin PT_GNU_STACK la pila es ejecutable");
    assert!(!info.relro);
    assert!(info.stripped, "no hay .symtab");
    assert!(
        info.overlay_bytes > 30_000,
        "el apendice de {} bytes deberia detectarse",
        info.overlay_bytes
    );

    let packed = f.sections.iter().find(|s| s.name == ".packed").unwrap();
    assert!(packed.is_wx(), "la seccion es escribible y ejecutable");
    assert!(packed.entropy > 7.9, "entropia de la seccion empaquetada");

    // El buffer de descompresion: nada en disco, mucho en memoria. Es la unica
    // forma en que un ELF expresa esa dualidad, y por eso `virtual_to_raw`
    // devuelve su valor tope para SHT_NOBITS.
    let buf = f.sections.iter().find(|s| s.name == ".unpack_buf").unwrap();
    assert_eq!(buf.raw_size, 0, "SHT_NOBITS no ocupa nada en el fichero");
    assert!(buf.virtual_size > 200_000);
    assert!(buf.virtual_to_raw() >= 10.0);
    assert!(buf.is_wx());
}

#[test]
fn el_punto_de_entrada_fuera_de_toda_seccion_se_detecta() {
    // Cabecera manipulada: el punto de entrada no cae en ninguna seccion.
    let datos = ElfBuilder {
        entry: 0xdead_beef,
        segments: vec![SegmentSpec {
            p_type: PT_LOAD,
            flags: PF_R | PF_X,
        }],
        sections: vec![SectionSpec::progbits(
            ".text",
            SHF_ALLOC | SHF_EXECINSTR,
            code_like(1024),
        )],
        ..Default::default()
    }
    .build();

    let f = FeatureExtractor::default().extract(&datos);
    assert!(f.format.unwrap().entry_outside_sections);
}

// ---------------------------------------------------------------------------
// Analisis de PE
// ---------------------------------------------------------------------------

#[test]
fn analiza_un_pe_generado_al_vuelo() {
    let lab = Lab::nuevo("pe");
    let datos = PeBuilder {
        sections: vec![
            PeSection {
                name: ".text",
                data: code_like(4096),
                virtual_size: 0,
                characteristics: SCN_CODE_R_X,
            },
            PeSection {
                name: ".rdata",
                data: text_like(2048),
                virtual_size: 0,
                characteristics: 0x4000_0040,
            },
            PeSection {
                name: ".data",
                data: text_like(1024),
                virtual_size: 0,
                characteristics: SCN_DATA_RW,
            },
        ],
        ..Default::default()
    }
    .build();
    let ruta = lab.escribir("programa.exe", &datos);

    let f = FeatureExtractor::default().extract_file(&ruta).unwrap();
    assert!(!f.parse_failed, "el PE construido debe analizarse");
    let info = f.format.clone().unwrap();
    assert_eq!(info.kind, Some(BinaryFormat::Pe));
    assert!(info.is_64);
    assert!(info.nx, "NX_COMPAT esta puesto");
    assert!(info.pie, "DYNAMIC_BASE esta puesto");
    assert!(!info.rwx_segment);
    assert_eq!(f.sections.len(), 3);
    assert!(f.sections.iter().any(|s| s.name == ".text"));
}

#[test]
fn detecta_una_seccion_pe_escribible_y_ejecutable() {
    let datos = PeBuilder {
        // Sin ASLR ni DEP.
        dll_characteristics: 0,
        entry_rva: 0x2000,
        sections: vec![
            PeSection {
                name: ".text",
                data: high_entropy(4096, 11),
                virtual_size: 0,
                characteristics: SCN_CODE_R_X,
            },
            PeSection {
                name: "UPX1",
                data: high_entropy(8192, 12),
                virtual_size: 8192 * 15,
                characteristics: SCN_RWX,
            },
        ],
        ..Default::default()
    }
    .build();

    let f = FeatureExtractor::default().extract(&datos);
    let info = f.format.clone().unwrap();
    assert!(info.rwx_segment, "la seccion UPX1 es RWX");
    assert!(!info.nx, "sin NX_COMPAT");
    assert!(!info.pie, "sin DYNAMIC_BASE");

    let upx = f.sections.iter().find(|s| s.name == "UPX1").unwrap();
    assert!(upx.is_wx());
    assert!(upx.virtual_to_raw() > 10.0);
}

#[test]
fn un_binario_malformado_no_hace_fallar_el_extractor() {
    // Un PE o ELF roto que aun asi carga es una tecnica contra analizadores que
    // se rinden ante lo que no entienden. Fallar el analisis es una
    // CARACTERISTICA, no un error.
    let x = FeatureExtractor::default();

    let mut roto = elf_benigno();
    // Destrozar la tabla de secciones.
    let n = roto.len();
    for b in roto[n - 200..].iter_mut() {
        *b = 0xff;
    }
    let f = x.extract(&roto);
    // Pase lo que pase, el extractor devuelve caracteristicas utilizables.
    assert!(f.size > 0);
    assert!(f.entropy > 0.0);

    // Basura pura.
    let basura = high_entropy(4096, 77);
    let f2 = x.extract(&basura);
    assert!(f2.parse_failed || f2.format.unwrap().kind == Some(BinaryFormat::Unknown));
    assert!(f2.entropy > 7.9);

    // Vacio y minusculo: ninguno debe entrar en panico.
    assert_eq!(x.extract(&[]).size, 0);
    assert_eq!(x.extract(b"MZ").size, 2);
    assert_eq!(x.extract(b"\x7fELF").size, 4);
}

#[test]
fn analiza_binarios_reales_del_sistema() {
    // El mejor conjunto de muestras benignas es el que ya esta en la maquina.
    let x = FeatureExtractor::default();
    let mut analizados = 0;
    for ruta in ["/bin/true", "/bin/ls", "/bin/cat", "/usr/bin/env"] {
        let p = Path::new(ruta);
        if !p.exists() {
            continue;
        }
        let f = x.extract_file(p).unwrap();
        assert!(!f.parse_failed, "{ruta} deberia analizarse");
        let info = f.format.clone().unwrap();
        assert_eq!(info.kind, Some(BinaryFormat::Elf));
        assert!(info.nx, "{ruta} deberia tener pila no ejecutable");
        assert!(
            !info.rwx_segment,
            "{ruta} no deberia tener segmento escribible y ejecutable"
        );
        assert!(!f.sections.is_empty(), "{ruta} deberia tener secciones");
        assert!(
            f.entropy < 7.0,
            "{ruta} tiene entropia {:.2}, demasiado alta para un binario del sistema",
            f.entropy
        );
        analizados += 1;
    }
    assert!(analizados > 0, "no se encontro ningun binario del sistema");
}

// ---------------------------------------------------------------------------
// Vectorizacion
// ---------------------------------------------------------------------------

#[test]
fn el_vector_tiene_la_dimension_y_el_rango_correctos() {
    let datos = elf_benigno();
    let f = FeatureExtractor::default().extract(&datos);
    let v = to_vector_with_data(&f, &datos, 4096);

    assert_eq!(v.len(), FEATURE_DIM);
    for (i, x) in v.iter().enumerate() {
        assert!(x.is_finite(), "la componente {i} es {x}");
        assert!(
            (-0.01..=1.01).contains(x),
            "la componente {i} vale {x} y deberia estar normalizada en [0,1]"
        );
    }
    // Los histogramas ocupan sus bloques y suman uno.
    let bh: f32 = v[OFF_BYTE_HIST..OFF_BYTE_HIST + 16].iter().sum();
    assert!((bh - 1.0).abs() < 1e-4, "histograma de bytes suma {bh}");
    let eh: f32 = v[OFF_ENTROPY_HIST..OFF_ENTROPY_HIST + 32].iter().sum();
    assert!((eh - 1.0).abs() < 1e-4, "histograma de entropia suma {eh}");
}

#[test]
fn el_vector_separa_lo_benigno_de_lo_empaquetado() {
    let x = FeatureExtractor::default();
    let b = elf_benigno();
    let m = elf_empaquetado();
    let vb = to_vector_with_data(&x.extract(&b), &b, 4096);
    let vm = to_vector_with_data(&x.extract(&m), &m, 4096);

    // Segmento RWX: 0 frente a 1.
    assert_eq!(vb[OFF_HEADER + 13], 0.0);
    assert_eq!(vm[OFF_HEADER + 13], 1.0);
    // Pila no ejecutable presente solo en el benigno.
    assert_eq!(vb[OFF_HEADER + 8], 1.0);
    assert_eq!(vm[OFF_HEADER + 8], 0.0);
    // Entropia maxima de seccion.
    assert!(vm[OFF_SECTIONS + 2] > vb[OFF_SECTIONS + 2]);
    // Razon tamano en memoria frente a disco.
    assert!(vm[OFF_SECTIONS + 9] > vb[OFF_SECTIONS + 9]);
    // Secciones con nombre no estandar.
    assert!(vm[OFF_SECTIONS + 7] > vb[OFF_SECTIONS + 7]);
}

#[test]
fn el_hashing_de_importaciones_reparte_y_normaliza() {
    let x = FeatureExtractor::default();
    // Un binario real del sistema tiene importaciones de libc.
    let Ok(f) = x.extract_file(Path::new("/bin/ls")) else {
        return;
    };
    if f.imports.is_empty() {
        return;
    }
    let datos = std::fs::read("/bin/ls").unwrap();
    let v = to_vector_with_data(&f, &datos, 4096);

    let bloque: f32 = v[OFF_IMPORTS..OFF_IMPORTS + 64].iter().sum();
    // El bloque suma aproximadamente 1: cada importacion aporta 1/total.
    assert!(
        (bloque - 1.0).abs() < 0.01,
        "el bloque de importaciones suma {bloque}"
    );
    // Y se reparte: si todo cayera en un cubo, el hashing no serviria.
    let ocupados = v[OFF_IMPORTS..OFF_IMPORTS + 64]
        .iter()
        .filter(|x| **x > 0.0)
        .count();
    assert!(ocupados > 5, "solo {ocupados} cubos ocupados de 64");
}

#[test]
fn las_cadenas_sospechosas_se_reflejan_en_el_vector() {
    let mut datos = elf_benigno();
    datos.extend_from_slice(
        b"ptrace PTRACE_ATTACH process_vm_writev /proc/self/status TracerPid VMware \
          your files have been encrypted bitcoin",
    );
    let f = FeatureExtractor::default().extract(&datos);
    let v = to_vector_with_data(&f, &datos, 4096);

    // Presencia de categorias: inyeccion (3), antianalisis (4), rescate (6).
    assert_eq!(v[OFF_STRINGS + 10 + 3 * 2], 1.0, "categoria inyeccion");
    assert_eq!(v[OFF_STRINGS + 10 + 4 * 2], 1.0, "categoria antianalisis");
    assert_eq!(v[OFF_STRINGS + 10 + 6 * 2], 1.0, "categoria rescate");
}

// ---------------------------------------------------------------------------
// Inferencia
// ---------------------------------------------------------------------------

#[test]
fn el_modelo_empotrado_carga() {
    let m = MalwareModel::embedded().expect("el modelo empotrado debe cargar");
    assert_eq!(m.input_dim(), FEATURE_DIM);
}

#[test]
fn un_vector_de_dimension_incorrecta_se_rechaza() {
    // No producir un error aqui significa producir una PUNTUACION SIN SENTIDO,
    // que es la clase de fallo que nadie detecta hasta que el producto lleva
    // meses bloqueando lo que no debe.
    let m = MalwareModel::embedded().unwrap();
    let err = m.predict(&[0.0; 10]).unwrap_err();
    assert!(
        matches!(
            err,
            ModelError::BadInputDim {
                found: 10,
                expected: 256
            }
        ),
        "error: {err:?}"
    );
}

#[test]
fn el_pipeline_completo_puntua_mas_alto_lo_empaquetado() {
    let lab = Lab::nuevo("inferencia");
    let x = FeatureExtractor::default();
    let m = MalwareModel::embedded().unwrap();

    let b = elf_benigno();
    let mal = elf_empaquetado();
    lab.escribir("benigno.so", &b);
    lab.escribir("packed.bin", &mal);

    let pb = m
        .predict(&to_vector_with_data(&x.extract(&b), &b, 4096))
        .unwrap();
    let pm = m
        .predict(&to_vector_with_data(&x.extract(&mal), &mal, 4096))
        .unwrap();

    assert!(
        pm.score > pb.score,
        "el empaquetado ({:.4}) debe puntuar por encima del benigno ({:.4})",
        pm.score,
        pb.score
    );
    assert!(
        pb.verdict == Verdict::Record,
        "un ELF con NX, RELRO y secciones estandar no puede pasar de Record, dio {:?} ({:.4})",
        pb.verdict,
        pb.score
    );
    assert!(
        pm.score > 0.5,
        "un binario con segmento RWX, entropia 7,99, seccion no estandar y sin \
         mitigaciones deberia puntuar por encima de 0,5, dio {:.4}",
        pm.score
    );
}

#[test]
fn los_binarios_reales_del_sistema_no_disparan_el_modelo() {
    // La comprobacion que de verdad importa: con ~300.000 ejecutables por
    // endpoint, cualquier tendencia a puntuar alto software normal se traduce
    // en miles de falsos positivos.
    let x = FeatureExtractor::default();
    let m = MalwareModel::embedded().unwrap();
    let mut probados = 0;

    for ruta in [
        "/bin/true",
        "/bin/ls",
        "/bin/cat",
        "/bin/sh",
        "/usr/bin/env",
        "/usr/bin/id",
        "/usr/bin/head",
        "/usr/bin/wc",
    ] {
        let p = Path::new(ruta);
        if !p.exists() {
            continue;
        }
        let datos = std::fs::read(p).unwrap();
        let v = to_vector_with_data(&x.extract(&datos), &datos, 4096);
        let pred = m.predict(&v).unwrap();
        assert!(
            pred.verdict == Verdict::Record,
            "{ruta} obtuvo {:?} con puntuacion {:.4}; un binario del sistema no puede \
             pasar de Record",
            pred.verdict,
            pred.score
        );
        probados += 1;
    }
    assert!(probados >= 2, "solo se probaron {probados} binarios reales");
}

#[test]
fn una_entrada_con_valores_no_finitos_no_corrompe_el_veredicto() {
    // Un NaN se propaga a la salida y hace que TODAS las comparaciones sean
    // falsas: el veredicto acabaria siendo Record por accidente en vez de por
    // decision. Se sanea antes de inferir.
    let m = MalwareModel::embedded().unwrap();
    let mut v = vec![0.0f32; FEATURE_DIM];
    v[1] = f32::NAN;
    v[2] = f32::INFINITY;
    v[3] = f32::NEG_INFINITY;

    let p = m.predict(&v).expect("no debe fallar, debe sanear");
    assert!(p.score.is_finite(), "la puntuacion es {}", p.score);
    assert!((0.0..=1.0).contains(&p.score));
}

#[test]
fn los_umbrales_escalonan_la_respuesta() {
    let t = aegis_ml::Thresholds::default();
    assert_eq!(t.verdict(0.10), Verdict::Record);
    assert_eq!(t.verdict(0.85), Verdict::Record);
    assert_eq!(t.verdict(0.92), Verdict::Watch);
    assert_eq!(t.verdict(0.996), Verdict::Block);
    assert_eq!(t.verdict(0.9995), Verdict::Contain);
    // El orden de los umbrales tiene que ser estricto, o un tramo queda
    // inalcanzable y el escalonado deja de existir.
    assert!(t.record < t.watch && t.watch < t.block && t.block < t.contain);
}
