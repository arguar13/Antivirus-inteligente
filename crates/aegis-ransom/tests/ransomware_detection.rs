//! Pruebas del motor anti-ransomware con material real.
//!
//! # Por que estas pruebas escriben ficheros de verdad
//!
//! Inyectar entropias inventadas al motor comprueba la aritmetica y nada mas.
//! La primera version de este modulo pasaba asi todas sus pruebas y era
//! INCAPAZ de detectar nada en produccion: comparaba contra 7,9 bits/byte
//! absolutos, y una muestra de 512 bytes de datos cifrados solo llega a 7,59
//! por el tamano de la muestra. El detector estaba muerto y ninguna prueba con
//! numeros a mano lo habria visto.
//!
//! Por eso aqui el "cifrador" escribe bytes reales en `/tmp`, se leen del
//! disco, y la entropia la calcula el mismo codigo que la calcula en el agente.

use std::path::{Path, PathBuf};

use aegis_ml::entropy;
use aegis_ransom::engine::{ContainmentOutcome, Responder, Signal};
use aegis_ransom::honeypot::{HoneypotConfig, TamperReason};
use aegis_ransom::velocity::{directorio, extension, RATIO_CIFRADO, RATIO_ESTRUCTURADO};
use aegis_ransom::{
    EngineConfig, HoneypotSet, RansomVerdict, RansomwareEngine, VelocityConfig, VelocityTracker,
    WriteObservation,
};

// ---------------------------------------------------------------------------
// Utillaje: laboratorio en disco y generadores de contenido real
// ---------------------------------------------------------------------------

struct Lab(PathBuf);

impl Lab {
    fn nuevo(n: &str) -> Lab {
        let p = std::env::temp_dir().join(format!("aegis-ransom-{n}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Lab(p)
    }
    fn subdir(&self, n: &str) -> PathBuf {
        let d = self.0.join(n);
        std::fs::create_dir_all(&d).unwrap();
        d
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Generador de flujo pseudoaleatorio de calidad criptografica suficiente para
/// que la entropia medida sea indistinguible de la de un cifrador real.
///
/// Es xoshiro256++, no un LCG: un generador congruencial lineal tiene los bits
/// bajos casi periodicos y produce histogramas de bytes sesgados, con lo que la
/// entropia medida se queda corta y la prueba mediria el generador en vez del
/// detector.
struct Flujo {
    s: [u64; 4],
}

impl Flujo {
    fn nuevo(semilla: u64) -> Flujo {
        // SplitMix64 para sembrar, que es lo que recomienda el autor de
        // xoshiro: sembrar los cuatro estados con el mismo valor deja el
        // generador en una region degenerada durante miles de salidas.
        let mut x = semilla.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut sig = || {
            x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = x;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };
        Flujo {
            s: [sig(), sig(), sig(), sig()],
        }
    }

    fn siguiente(&mut self) -> u64 {
        let r = self.s[0]
            .wrapping_add(self.s[3])
            .rotate_left(23)
            .wrapping_add(self.s[0]);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        r
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        while v.len() < n {
            v.extend_from_slice(&self.siguiente().to_le_bytes());
        }
        v.truncate(n);
        v
    }
}

/// Documento de texto plausible: lo que un usuario tiene en su carpeta.
fn documento(n: usize, semilla: u64) -> Vec<u8> {
    const FRASES: &[&str] = &[
        "El informe trimestral recoge la actividad del periodo analizado.\n",
        "Se adjunta el detalle de gastos por departamento y ejercicio.\n",
        "Pendiente de revision por el comite antes de su publicacion.\n",
        "Referencia interna del expediente y anexos correspondientes.\n",
        "Resumen ejecutivo, conclusiones y lineas de trabajo futuras.\n",
    ];
    let mut v = Vec::with_capacity(n);
    let mut i = semilla as usize;
    while v.len() < n {
        v.extend_from_slice(FRASES[i % FRASES.len()].as_bytes());
        i += 1;
    }
    v.truncate(n);
    v
}

/// Cifra un buffer con un flujo, que es exactamente lo que hace un cifrador de
/// ransomware en modo de flujo: XOR del contenido con un keystream.
fn cifrar(claro: &[u8], semilla: u64) -> Vec<u8> {
    let mut f = Flujo::nuevo(semilla);
    let k = f.bytes(claro.len());
    claro.iter().zip(k).map(|(a, b)| a ^ b).collect()
}

/// Longitud de la muestra que entrega el sondeo del kernel.
const MUESTRA: usize = 512;

/// Lee del disco la muestra que veria el sondeo de `write`.
fn muestra_de(p: &Path) -> Vec<u8> {
    let d = std::fs::read(p).unwrap();
    d[..d.len().min(MUESTRA)].to_vec()
}

/// Respondedor que cuenta llamadas en vez de terminar procesos.
#[derive(Debug, Default)]
struct Contador {
    llamadas: std::sync::Mutex<Vec<u32>>,
}

impl Responder for Contador {
    fn contain(&self, pid: u32) -> ContainmentOutcome {
        self.llamadas.lock().unwrap().push(pid);
        ContainmentOutcome::Killed { processes: 1 }
    }
}

#[derive(Debug, Clone)]
struct Espia(std::sync::Arc<Contador>);

impl Responder for Espia {
    fn contain(&self, pid: u32) -> ContainmentOutcome {
        self.0.contain(pid)
    }
}

fn motor_sin_senuelos(cfg: EngineConfig) -> RansomwareEngine {
    RansomwareEngine::new(cfg, HoneypotSet::default())
}

const MS: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// 1. El material de prueba es real: se valida antes de medir nada con el
// ---------------------------------------------------------------------------

/// Sin esto, todo lo demas puede ser un espejismo: si el "cifrado" de la prueba
/// no fuese realmente de alta entropia, las pruebas de deteccion pasarian por
/// el motivo equivocado o fallarian sin culpa del motor.
#[test]
fn el_material_de_prueba_tiene_la_entropia_que_dice_tener() {
    let claro = documento(4096, 1);
    let cifrado = cifrar(&claro, 0xDEAD_BEEF);

    let m_claro = &claro[..MUESTRA];
    let m_cifrado = &cifrado[..MUESTRA];

    let r_claro = entropy::entropia_normalizada(m_claro).unwrap();
    let r_cifrado = entropy::entropia_normalizada(m_cifrado).unwrap();

    assert!(
        r_claro < RATIO_ESTRUCTURADO,
        "el texto plano deberia leerse como estructurado, dio {r_claro:.4} \
         ({:.3} bits/byte)",
        entropy::shannon(m_claro)
    );
    assert!(
        r_cifrado > RATIO_CIFRADO,
        "el flujo cifrado deberia leerse como cifrado, dio {r_cifrado:.4} \
         ({:.3} bits/byte)",
        entropy::shannon(m_cifrado)
    );
}

/// La regresion que motivo todo el cambio de umbral: en bits por byte
/// absolutos, datos cifrados muestreados a 512 bytes NO llegan a 7,9. Un umbral
/// absoluto ahi no lo cruza nada.
#[test]
fn a_512_bytes_ningun_dato_real_alcanza_los_7_9_bits_absolutos() {
    let mut maximo: f64 = 0.0;
    for semilla in 0..200u64 {
        let mut f = Flujo::nuevo(semilla);
        maximo = maximo.max(entropy::shannon(&f.bytes(MUESTRA)));
    }
    assert!(
        maximo < 7.9,
        "si esto falla, el umbral absoluto de 7,9 seria alcanzable a 512 bytes \
         y el cambio a fraccion normalizada dejaria de estar justificado; \
         maximo observado {maximo:.4}"
    );
    // Y sin embargo, normalizado, todos cruzan de sobra.
    let mut f = Flujo::nuevo(99);
    let r = entropy::entropia_normalizada(&f.bytes(MUESTRA)).unwrap();
    assert!(r > RATIO_CIFRADO, "normalizado dio {r:.4}");
}

#[test]
fn la_entropia_maxima_esperada_crece_y_se_satura_en_ocho() {
    let mut previo = 0.0;
    for e in 4..=20u32 {
        let v = entropy::entropia_maxima_esperada(1usize << e);
        assert!(v >= previo, "no monotona en 2^{e}: {v} tras {previo}");
        assert!(
            v <= 8.0 + 1e-9,
            "por encima del maximo teorico en 2^{e}: {v}"
        );
        // Estrictamente creciente mientras no ha saturado.
        if e <= 16 {
            assert!(v > previo, "estancada antes de saturar, en 2^{e}: {v}");
        }
        previo = v;
    }
    assert!((entropy::entropia_maxima_esperada(1 << 20) - 8.0).abs() < 1e-9);
    // Una muestra mas corta que el minimo no se juzga.
    assert!(entropy::entropia_normalizada(&[0u8; 32]).is_none());
    assert!(entropy::entropia_normalizada(&[]).is_none());
}

// ---------------------------------------------------------------------------
// 2. Deteccion de un cifrador real
// ---------------------------------------------------------------------------

/// Un cifrador de verdad: recorre un arbol de documentos, lee cada fichero,
/// escribe la version cifrada y lo renombra con su extension. Las escrituras se
/// leen del disco y se entregan al motor como bytes crudos.
#[test]
fn un_cifrador_real_se_detiene_antes_de_veinte_ficheros() {
    let lab = Lab::nuevo("cifrador");
    let mut victimas = Vec::new();
    for d in ["docs", "fotos", "contabilidad", "personal"] {
        let dir = lab.subdir(d);
        for i in 0..60 {
            let p = dir.join(format!("archivo-{i:03}.docx"));
            std::fs::write(&p, documento(8192, i as u64)).unwrap();
            victimas.push(p);
        }
    }
    victimas.sort();

    let mut motor = motor_sin_senuelos(EngineConfig::default());
    let actor = 0xC1F4;
    let pid = 4242;
    let mut t = 0u64;

    // Fase 1: el proceso se comporta como una aplicacion ofimatica normal.
    // Reescribe unos cuantos documentos con contenido plano. Esto es lo que
    // establece la fase estructurada; sin ella no hay transicion que ver.
    for (i, v) in victimas.iter().take(24).enumerate() {
        std::fs::write(v, documento(8192, 900 + i as u64)).unwrap();
        t += 30 * MS;
        let d = motor.on_write_sample(
            actor,
            pid,
            Some(v.to_str().unwrap()),
            &muestra_de(v),
            8192,
            t,
        );
        assert!(
            !d.as_ref().is_some_and(|d| d.verdict.is_ransomware()),
            "reescribir documentos en texto plano no puede ser ransomware \
             (fichero {i})"
        );
    }

    // Fase 2: empieza a cifrar. Se cuenta cuantos ficheros se pierden hasta que
    // el motor confirma: es el presupuesto de dano del producto.
    let mut cifrados = 0usize;
    let mut confirmado_en = None;
    for (i, v) in victimas.iter().enumerate() {
        let claro = std::fs::read(v).unwrap();
        std::fs::write(v, cifrar(&claro, i as u64)).unwrap();
        cifrados += 1;
        t += 3 * MS;
        let d = motor.on_write_sample(
            actor,
            pid,
            Some(v.to_str().unwrap()),
            &muestra_de(v),
            claro.len() as u64,
            t,
        );
        if d.as_ref().is_some_and(|d| d.verdict.is_ransomware()) {
            confirmado_en = Some((cifrados, d.unwrap()));
            break;
        }
    }

    let (perdidos, deteccion) =
        confirmado_en.expect("el cifrador no fue detectado en 240 ficheros");
    println!("ficheros cifrados antes de confirmar: {perdidos}");
    assert!(
        perdidos <= 20,
        "presupuesto de dano excedido: {perdidos} ficheros cifrados antes de \
         confirmar (limite 20)"
    );
    let senales = deteccion.verdict.signals();
    assert!(
        senales
            .iter()
            .any(|s| matches!(s, Signal::EntropyTransition { .. })),
        "la transicion de entropia deberia estar entre las senales: {senales:?}"
    );
}

/// El falso positivo que haria inutilizable la deteccion: `tar czf` sobre el
/// mismo arbol. Rapido, disperso y de entropia maxima desde el primer byte.
///
/// La diferencia con el cifrador no es ninguna de esas tres cosas: es que un
/// compresor NACE escribiendo ruido y un cifrador CAMBIA.
#[test]
fn un_compresor_rapido_y_disperso_no_se_confirma_como_ransomware() {
    let lab = Lab::nuevo("compresor");
    let mut motor = motor_sin_senuelos(EngineConfig::default());
    let actor = 0xC0DE;
    let mut t = 0u64;

    let mut peor = RansomVerdict::Normal;
    for i in 0..200u64 {
        let dir = lab.subdir(&format!("parte-{}", i % 8));
        let p = dir.join(format!("salida-{i:03}.gz"));
        // Sale comprimido desde la primera escritura: nunca hay fase plana.
        let datos = cifrar(&documento(8192, i), 0xBEEF ^ i);
        std::fs::write(&p, &datos).unwrap();
        t += 2 * MS;
        if let Some(d) = motor.on_write_sample(
            actor,
            7777,
            Some(p.to_str().unwrap()),
            &muestra_de(&p),
            datos.len() as u64,
            t,
        ) {
            assert!(
                !d.verdict.is_ransomware(),
                "un compresor no puede confirmarse como ransomware: {:?}",
                d.verdict
            );
            peor = d.verdict;
        }
    }

    // Se espera que sea SOSPECHOSO: es rapido y disperso, y esconderlo del todo
    // seria mentir sobre lo que el motor ve. Lo que no puede es confirmarse.
    assert!(
        matches!(peor, RansomVerdict::Suspicious { .. }),
        "deberia quedarse en sospechoso, quedo en {peor:?}"
    );
    assert!(
        !peor
            .signals()
            .iter()
            .any(|s| matches!(s, Signal::EntropyTransition { .. })),
        "un compresor no presenta transicion de entropia: {:?}",
        peor.signals()
    );
}

/// El motor de copias de seguridad: lee muchos ficheros, escribe rapido, pero
/// todo dentro de su propio directorio. Sin dispersion no hay confirmacion.
#[test]
fn una_copia_de_seguridad_concentrada_no_se_confirma() {
    let lab = Lab::nuevo("backup");
    let destino = lab.subdir("respaldo");
    let mut motor = motor_sin_senuelos(EngineConfig::default());
    let mut t = 0u64;

    for i in 0..300u64 {
        let p = destino.join(format!("bloque-{i:04}.dat"));
        let datos = cifrar(&documento(8192, i), i);
        std::fs::write(&p, &datos).unwrap();
        t += MS;
        if let Some(d) = motor.on_write_sample(
            0xBACC,
            5555,
            Some(p.to_str().unwrap()),
            &muestra_de(&p),
            datos.len() as u64,
            t,
        ) {
            assert!(
                !d.verdict.is_ransomware(),
                "una copia de seguridad concentrada en un directorio no puede \
                 confirmarse: {:?}",
                d.verdict
            );
        }
    }
    let estado = motor.tracker().state(0xBACC).unwrap();
    assert_eq!(
        estado.distinct_dirs(),
        1,
        "toda la actividad estaba en un solo directorio"
    );
}

// ---------------------------------------------------------------------------
// 3. Escrituras sin muestra: la trampa que fabricaria transiciones falsas
// ---------------------------------------------------------------------------

/// El sondeo del kernel solo muestrea escrituras por encima de un tamano
/// minimo. Si las no muestreadas se anotasen como entropia cero, cualquier
/// proceso que haga muchas escrituras pequenas y luego escriba algo comprimido
/// mostraria una "transicion" que nunca ocurrio.
#[test]
fn las_escrituras_sin_muestra_no_fabrican_una_transicion() {
    let mut motor = motor_sin_senuelos(EngineConfig::default());
    let actor = 0x5A17;
    let mut t = 0u64;

    // 48 escrituras que el kernel no muestreo (buffer vacio).
    for i in 0..48u64 {
        t += MS;
        motor.on_write_sample(actor, 11, Some(&format!("/tmp/x/f{i}")), &[], 100, t);
    }
    // Y ahora 20 escrituras de alta entropia, esta vez con muestra.
    let mut f = Flujo::nuevo(7);
    for i in 0..20u64 {
        t += MS;
        let m = f.bytes(MUESTRA);
        motor.on_write_sample(actor, 11, Some(&format!("/tmp/x/g{i}")), &m, 8192, t);
    }

    let estado = motor.tracker().state(actor).unwrap();
    assert!(
        !estado.entropy_transition(),
        "no hubo fase estructurada observada: anterior={:?} reciente={:?}",
        estado.earlier_entropy(),
        estado.recent_entropy()
    );
    assert_eq!(
        estado.high_entropy_writes(),
        20,
        "las 20 muestreadas si cuentan como alta entropia"
    );
    // Una muestra por debajo del minimo tampoco se juzga.
    t += MS;
    motor.on_write_sample(actor, 11, Some("/tmp/x/corta"), &[0xAB; 16], 16, t);
    assert_eq!(
        motor.tracker().state(actor).unwrap().high_entropy_writes(),
        20
    );
}

// ---------------------------------------------------------------------------
// 4. Senuelos
// ---------------------------------------------------------------------------

#[test]
fn un_senuelo_tocado_confirma_por_si_solo_y_contiene() {
    let lab = Lab::nuevo("senuelo");
    let docs = lab.subdir("Documentos");
    let set = HoneypotSet::deploy(&HoneypotConfig {
        directories: vec![docs.clone()],
        per_directory: 3,
    })
    .unwrap();
    assert_eq!(set.len(), 3, "deberian haberse sembrado tres senuelos");
    for p in set.paths() {
        assert!(p.exists(), "{} no llego al disco", p.display());
    }

    let espia = std::sync::Arc::new(Contador::default());
    let mut motor = RansomwareEngine::new(EngineConfig::default(), set)
        .with_responder(Box::new(Espia(espia.clone())));

    let canario = motor
        .honeypots()
        .paths()
        .next()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    // Un unico evento, sin ningun historial previo: basta.
    let d = motor
        .on_open_for_write(0x_DEC0, 31337, &canario, 1_000)
        .expect("abrir un senuelo para escritura tiene que emitir deteccion");
    assert!(d.verdict.is_ransomware(), "{:?}", d.verdict);
    assert!(matches!(
        d.verdict.signals().first(),
        Some(Signal::HoneypotTouched { .. })
    ));

    assert_eq!(
        motor.contain(&d),
        Some(ContainmentOutcome::Killed { processes: 1 })
    );
    // Deduplicado: el mismo actor no se contiene dos veces aunque siga
    // generando eventos mientras muere.
    assert_eq!(motor.contain(&d), None);
    let d2 = motor
        .on_open_for_write(0x_DEC0, 31337, &canario, 2_000)
        .unwrap();
    assert_eq!(motor.contain(&d2), None);
    assert_eq!(
        espia.llamadas.lock().unwrap().as_slice(),
        &[31337],
        "el respondedor solo debe invocarse una vez por incidente"
    );
}

/// Un senuelo con el nombre de un fichero que ya existe NO se pisa: podria ser
/// un documento real del usuario que casualmente se llama igual.
#[test]
fn el_despliegue_no_pisa_un_fichero_existente_del_usuario() {
    let lab = Lab::nuevo("nopisa");
    let docs = lab.subdir("Documentos");
    let chocante = docs.join("0001-copia-de-seguridad.docx");
    std::fs::write(&chocante, b"documento real del usuario, no tocar").unwrap();

    let set = HoneypotSet::deploy(&HoneypotConfig {
        directories: vec![docs],
        per_directory: 3,
    })
    .unwrap();

    assert_eq!(
        std::fs::read(&chocante).unwrap(),
        b"documento real del usuario, no tocar",
        "el fichero del usuario fue sobrescrito"
    );
    assert!(
        !set.is_canary(&chocante),
        "un fichero ajeno no puede vigilarse como senuelo: al primer guardado \
         del usuario dispararia una contencion"
    );
    assert_eq!(set.len(), 2, "los otros dos si se sembraron");
}

/// El barrido periodico existe porque el evento en tiempo real puede perderse:
/// si el ring se lleno durante el pico, esto descubre el dano igual.
#[test]
fn el_barrido_periodico_descubre_senuelos_manipulados() {
    let lab = Lab::nuevo("barrido");
    let docs = lab.subdir("Documentos");
    let set = HoneypotSet::deploy(&HoneypotConfig {
        directories: vec![docs],
        per_directory: 3,
    })
    .unwrap();
    let rutas: Vec<PathBuf> = set.paths().map(|p| p.to_path_buf()).collect();

    let mut motor = RansomwareEngine::new(EngineConfig::default(), set);
    assert_eq!(motor.maintain(1_000).tampered_canaries, 0, "aun intactos");

    // Un cifrador los reescribe y borra uno.
    std::fs::write(&rutas[0], cifrar(&documento(4096, 1), 5)).unwrap();
    std::fs::remove_file(&rutas[1]).unwrap();

    let informe = motor.maintain(2_000);
    assert_eq!(informe.tampered_canaries, 2, "{:?}", informe.tampered);
    let motivos: Vec<&TamperReason> = informe.tampered.iter().map(|t| &t.reason).collect();
    assert!(
        motivos
            .iter()
            .any(|m| matches!(m, TamperReason::Modified { .. })),
        "{motivos:?}"
    );
    assert!(
        motivos.iter().any(|m| matches!(m, TamperReason::Deleted)),
        "{motivos:?}"
    );
}

#[test]
fn los_senuelos_se_ordenan_pronto_en_un_recorrido_alfabetico() {
    let lab = Lab::nuevo("orden");
    let docs = lab.subdir("Documentos");
    for n in ["Anexo.docx", "balance.xlsx", "Zeta.pdf", "informe.odt"] {
        std::fs::write(docs.join(n), documento(1024, 3)).unwrap();
    }
    let set = HoneypotSet::deploy(&HoneypotConfig {
        directories: vec![docs.clone()],
        per_directory: 3,
    })
    .unwrap();

    let mut entradas: Vec<String> = std::fs::read_dir(&docs)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    entradas.sort();

    // Los tres primeros de un recorrido alfabetico tienen que ser senuelos:
    // cada fichero de ventaja son documentos del usuario que no se pierden.
    for (i, nombre) in entradas.iter().take(3).enumerate() {
        assert!(
            set.is_canary(&docs.join(nombre)),
            "la entrada {i} del recorrido ({nombre}) no es un senuelo"
        );
    }
}

#[test]
fn el_despliegue_omite_lo_que_no_puede_escribir_sin_fallar() {
    // Un directorio que no existe no es un error: sembrar es oportunista.
    let set = HoneypotSet::deploy(&HoneypotConfig {
        directories: vec![PathBuf::from("/no/existe/en/ningun/sitio")],
        per_directory: 3,
    })
    .unwrap();
    assert!(set.is_empty());
    assert_eq!(set.verify().len(), 0);
}

// ---------------------------------------------------------------------------
// 5. Renombrado masivo
// ---------------------------------------------------------------------------

#[test]
fn el_renombrado_masivo_a_extension_nueva_es_una_senal() {
    let mut motor = motor_sin_senuelos(EngineConfig::default());
    let actor: u64 = 0xFEED;
    let mut t = 0u64;
    let mut ultimo = None;

    for i in 0..40u64 {
        t += MS;
        let dir = i % 5;
        ultimo = motor.on_rename(
            actor,
            2020,
            &format!("/home/u/docs{dir}/informe-{i}.docx"),
            &format!("/home/u/docs{dir}/informe-{i}.docx.aegislock"),
            t,
        );
    }

    let v = ultimo.expect("deberia haber emitido veredicto").verdict;
    assert!(v.is_ransomware(), "{v:?}");
    let s = v.signals();
    assert!(
        s.iter().any(|x| matches!(x, Signal::RenameBurst { .. })),
        "{s:?}"
    );
    assert!(
        s.iter()
            .any(|x| matches!(x, Signal::DirectorySpread { .. })),
        "{s:?}"
    );
}

/// Renombrar a una extension que el sistema ya conocia no es senal: si lo
/// fuese, cualquier script que genere `.bak` en masa dispararia el detector.
#[test]
fn el_renombrado_masivo_a_extension_conocida_no_es_rafaga() {
    let mut motor = motor_sin_senuelos(EngineConfig::default());
    let actor: u64 = 0xBA0;
    let mut t = 0u64;
    let mut ultimo = None;

    for i in 0..40u64 {
        t += MS;
        ultimo = motor.on_rename(
            actor,
            2021,
            &format!("/home/u/docs{}/f-{i}.txt", i % 5),
            &format!("/home/u/docs{}/f-{i}.bak", i % 5),
            t,
        );
    }

    let v = ultimo.unwrap().verdict;
    assert!(
        !v.signals()
            .iter()
            .any(|x| matches!(x, Signal::RenameBurst { .. })),
        "'.bak' es una extension corriente y no puede contar como nueva: {:?}",
        v.signals()
    );
    assert!(!v.is_ransomware(), "{v:?}");
}

#[test]
fn una_extension_aprendida_deja_de_ser_nueva() {
    let mut t = VelocityTracker::default();
    t.on_rename(1, "/a/b.docx", "/a/b.parquet", 10);
    assert_eq!(t.new_extensions(1), 1);

    let mut t2 = VelocityTracker::default();
    t2.learn_extension("parquet");
    t2.on_rename(1, "/a/b.docx", "/a/b.parquet", 10);
    assert_eq!(
        t2.new_extensions(1),
        0,
        "tras aprenderla, la primera vez que alguien guarde un .parquet no \
         puede gritar el detector"
    );
}

// ---------------------------------------------------------------------------
// 6. Cotas de recursos y ciclo de vida
// ---------------------------------------------------------------------------

/// Un arbol de compilacion crea miles de procesos. Sin cota dura, el
/// seguimiento crece sin techo y el agente incumple su presupuesto de 50 MB.
#[test]
fn el_seguimiento_esta_acotado_con_miles_de_procesos() {
    let cfg = VelocityConfig {
        max_tracked: 512,
        ..Default::default()
    };
    let mut motor = motor_sin_senuelos(EngineConfig {
        velocity: cfg,
        ..Default::default()
    });

    let mut f = Flujo::nuevo(1);
    let muestra = f.bytes(MUESTRA);
    for i in 0..20_000u64 {
        motor.on_write_sample(
            i,
            i as u32,
            Some(&format!("/tmp/p{i}/salida.bin")),
            &muestra,
            8192,
            i * 1_000,
        );
    }
    assert!(
        motor.tracker().tracked() <= 512,
        "el seguimiento crecio a {} con cota 512",
        motor.tracker().tracked()
    );
}

/// La cota por proceso: un cifrador que toque cien mil ficheros no puede hacer
/// crecer el conjunto de hashes sin limite.
#[test]
fn los_ficheros_por_proceso_estan_acotados() {
    let cfg = VelocityConfig {
        max_files_per_process: 64,
        window_ns: u64::MAX / 4,
        ..Default::default()
    };
    let mut t = VelocityTracker::new(cfg);
    for i in 0..5_000u64 {
        t.on_write(
            1,
            Some(&format!("/home/u/d{}/f{i}.docx", i % 200)),
            WriteObservation {
                entropy_ratio: Some(0.99),
                bytes: 4096,
                ts_ns: i,
            },
        );
    }
    let e = t.state(1).unwrap();
    assert!(e.distinct_files() <= 64, "{}", e.distinct_files());
    assert!(e.distinct_dirs() <= 64, "{}", e.distinct_dirs());
    assert_eq!(e.writes(), 5_000, "las escrituras si se cuentan todas");
}

#[test]
fn los_procesos_inactivos_se_olvidan_y_los_terminados_tambien() {
    let mut motor = motor_sin_senuelos(EngineConfig::default());
    let mut f = Flujo::nuevo(3);
    let m = f.bytes(MUESTRA);
    for i in 0..10u64 {
        motor.on_write_sample(i, i as u32, Some("/tmp/a/b"), &m, 4096, 1_000);
    }
    assert_eq!(motor.tracker().tracked(), 10);

    // Nada ha pasado todavia: la poda solo actua tras 30 ventanas.
    assert_eq!(motor.maintain(1_000_000_000).pruned, 0);
    assert_eq!(motor.maintain(60_000_000_000).pruned, 10);
    assert_eq!(motor.tracker().tracked(), 0);

    motor.on_write_sample(77, 77, Some("/tmp/a/b"), &m, 4096, 60_000_000_000);
    assert_eq!(motor.tracker().tracked(), 1);
    motor.on_exit(77);
    assert_eq!(motor.tracker().tracked(), 0);
}

/// Al rotar la ventana se olvidan los contadores pero NO el historial de
/// entropia: la transicion de texto plano a cifrado puede cruzar el limite, y
/// borrarla ahi seria perder justo la senal que se busca.
#[test]
fn la_rotacion_de_ventana_conserva_el_historial_de_entropia() {
    let cfg = VelocityConfig {
        window_ns: 1_000_000,
        ..Default::default()
    };
    let mut t = VelocityTracker::new(cfg);
    let plano = documento(MUESTRA, 1);
    let r_plano = entropy::entropia_normalizada(&plano).unwrap();
    let mut f = Flujo::nuevo(5);

    for i in 0..40u64 {
        t.on_write(
            1,
            Some("/a/b.docx"),
            WriteObservation {
                entropy_ratio: Some(r_plano),
                bytes: 4096,
                ts_ns: i,
            },
        );
    }
    // Salto muy por encima de la ventana: rota.
    let base = 100_000_000u64;
    for i in 0..16u64 {
        let r = entropy::entropia_normalizada(&f.bytes(MUESTRA)).unwrap();
        t.on_write(
            1,
            Some("/a/b.docx"),
            WriteObservation {
                entropy_ratio: Some(r),
                bytes: 4096,
                ts_ns: base + i,
            },
        );
    }

    let e = t.state(1).unwrap();
    assert_eq!(e.writes(), 16, "los contadores si se reinician al rotar");
    assert!(
        e.entropy_transition(),
        "la transicion tiene que sobrevivir a la rotacion: anterior={:?} \
         reciente={:?}",
        e.earlier_entropy(),
        e.recent_entropy()
    );
}

// ---------------------------------------------------------------------------
// 7. Analisis de rutas
// ---------------------------------------------------------------------------

#[test]
fn el_analisis_de_rutas_cubre_los_casos_raros() {
    assert_eq!(directorio("/home/u/a.txt"), "/home/u");
    assert_eq!(directorio("/a.txt"), "/");
    assert_eq!(directorio("relativo.txt"), ".");
    assert_eq!(directorio("/"), "/");

    assert_eq!(extension("/a/b.docx"), Some("docx"));
    assert_eq!(extension("/a/b.tar.gz"), Some("gz"));
    // Un punto inicial es un fichero oculto, no una extension.
    assert_eq!(extension("/a/.bashrc"), None);
    assert_eq!(extension("/a/sin_extension"), None);
    assert_eq!(extension("/a/b."), None);
    // Una "extension" larguisima es basura, no una extension.
    assert_eq!(extension("/a/b.estoesdemasiadolargoparaser"), None);
    // Un punto en el directorio no cuenta como extension del fichero.
    assert_eq!(extension("/a.b/fichero"), None);
}

// ---------------------------------------------------------------------------
// 8. Contencion
// ---------------------------------------------------------------------------

#[test]
fn sin_contencion_automatica_se_detecta_pero_no_se_actua() {
    let espia = std::sync::Arc::new(Contador::default());
    let cfg = EngineConfig {
        auto_contain: false,
        ..Default::default()
    };
    let lab = Lab::nuevo("noauto");
    let docs = lab.subdir("Documentos");
    let set = HoneypotSet::deploy(&HoneypotConfig {
        directories: vec![docs],
        per_directory: 1,
    })
    .unwrap();
    let canario = set.paths().next().unwrap().to_str().unwrap().to_string();

    let mut motor = RansomwareEngine::new(cfg, set).with_responder(Box::new(Espia(espia.clone())));
    let d = motor.on_open_for_write(1, 999, &canario, 10).unwrap();
    assert!(d.verdict.is_ransomware());
    assert_eq!(motor.contain(&d), Some(ContainmentOutcome::NotAttempted));
    assert!(
        espia.llamadas.lock().unwrap().is_empty(),
        "con auto_contain desactivado no se puede tocar ningun proceso"
    );
}

#[test]
fn un_veredicto_que_no_es_ransomware_nunca_contiene() {
    let espia = std::sync::Arc::new(Contador::default());
    let mut motor =
        motor_sin_senuelos(EngineConfig::default()).with_responder(Box::new(Espia(espia.clone())));

    let mut f = Flujo::nuevo(11);
    let m = f.bytes(MUESTRA);
    let mut visto = false;
    for i in 0..30u64 {
        if let Some(d) = motor.on_write_sample(
            1,
            123,
            Some(&format!("/srv/datos/f{i}.gz")),
            &m,
            8192,
            i * MS,
        ) {
            if !d.verdict.is_ransomware() {
                assert_eq!(motor.contain(&d), None);
                visto = true;
            }
        }
    }
    assert!(
        visto,
        "deberia haberse emitido algun veredicto no confirmado"
    );
    assert!(espia.llamadas.lock().unwrap().is_empty());
    assert_eq!(motor.contained(), 0);
}
