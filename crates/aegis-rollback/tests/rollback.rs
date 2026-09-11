//! Rollback de extremo a extremo con un "ransomware" sintetico REAL.
//!
//! Sin mocks: se crea un documento de verdad en un directorio temporal, un
//! cifrador ChaCha20 real lo sobreescribe subiendo su entropia igual que el
//! ransomware, y el rollback lo restaura byte a byte desde la copia-sombra
//! cifrada. Es la propiedad central de la FASE 50: que lo restaurado sea EL
//! ORIGINAL, no la version cifrada.

use aegis_rollback::journal::{DecisionDiario, Journal};
use aegis_rollback::plan::PlanReversion;
use aegis_rollback::revert::{ejecutar_plan, ReverterFichero};
use aegis_rollback::shadowstore::AlmacenSombra;

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;

/// Un documento de usuario: texto repetitivo, baja entropia.
fn documento() -> Vec<u8> {
    "Informe trimestral de seguridad. ".repeat(400).into_bytes()
}

/// El "ransomware": cifra los bytes in-place con ChaCha20 (entropia alta real).
fn cifrar_como_ransomware(datos: &mut [u8]) {
    let mut c = ChaCha20::new(&[0x42u8; 32].into(), &[0x24u8; 12].into());
    c.apply_keystream(datos);
}

#[test]
fn el_rollback_restaura_el_documento_original_no_el_cifrado() {
    let dir = tempfile::tempdir().unwrap();
    let ruta_doc = dir.path().join("informe.txt");
    let original = documento();
    std::fs::write(&ruta_doc, &original).unwrap();

    let almacen_dir = dir.path().join("sombras");
    let almacen = AlmacenSombra::abrir(&almacen_dir, [0x11u8; 32]).unwrap();
    let mut diario = Journal::new();

    // 1. Llega la escritura de cifrado. Se lee la muestra previa (el documento)
    //    y una muestra de lo que se va a escribir (ya cifrado).
    let previa = std::fs::read(&ruta_doc).unwrap();
    let mut nueva = previa.clone();
    cifrar_como_ransomware(&mut nueva);

    let ruta_bytes = ruta_doc.to_str().unwrap().as_bytes();
    assert_eq!(
        diario.evaluar(ruta_bytes, &previa, &nueva),
        DecisionDiario::Copiar,
        "una escritura que sube la entropia de documento a cifrado dispara la copia"
    );

    // 2. Antes de dejar cifrar, se guarda la copia-sombra del ORIGINAL.
    let sombra = almacen.guardar(ruta_bytes, &previa).unwrap();

    // 3. El ransomware cifra el fichero en disco.
    let mut en_disco = std::fs::read(&ruta_doc).unwrap();
    cifrar_como_ransomware(&mut en_disco);
    std::fs::write(&ruta_doc, &en_disco).unwrap();
    assert_ne!(
        std::fs::read(&ruta_doc).unwrap(),
        original,
        "el fichero quedo cifrado"
    );

    // 4. Se confirma ransomware -> se construye el plan y se revierte.
    let mut plan = PlanReversion::nuevo();
    plan.anadir(sombra, ruta_bytes.to_vec());
    let (restaurados, errores) = ejecutar_plan(&plan, &almacen, &ReverterFichero);
    assert_eq!(restaurados, 1);
    assert!(errores.is_empty(), "no debe haber errores: {errores:?}");

    // 5. LA PROPIEDAD CENTRAL: el fichero en disco vuelve a ser el original.
    assert_eq!(
        std::fs::read(&ruta_doc).unwrap(),
        original,
        "el rollback restauro el documento original, no la basura cifrada"
    );
}

#[test]
fn el_diario_no_pisa_una_copia_buena_en_la_segunda_pasada() {
    let mut diario = Journal::new();
    let doc = documento();
    let mut cifrado = doc.clone();
    cifrar_como_ransomware(&mut cifrado);

    // Primera escritura: documento -> cifrado. Se copia.
    assert_eq!(
        diario.evaluar(b"/u/f", &doc, &cifrado),
        DecisionDiario::Copiar
    );
    // Segunda escritura sobre el MISMO fichero (el ransomware reescribe): la
    // muestra previa ya es cifrada. Sin dedup se guardaria la version cifrada
    // encima de la buena. El diario lo impide.
    let mut recifrado = cifrado.clone();
    cifrar_como_ransomware(&mut recifrado);
    assert_eq!(
        diario.evaluar(b"/u/f", &cifrado, &recifrado),
        DecisionDiario::YaCopiado,
        "la segunda pasada NO debe pisar la copia buena"
    );
}

#[test]
fn sin_incidente_una_escritura_normal_no_se_copia() {
    let mut diario = Journal::new();
    let doc1 = b"texto plano uno dos tres".to_vec();
    let doc2 = b"texto plano cuatro cinco".to_vec();
    // Documento -> documento: no hay firma de cifrado, no se copia.
    assert_eq!(
        diario.evaluar(b"/u/g", &doc1, &doc2),
        DecisionDiario::Ignorar
    );
}

#[test]
fn con_incidente_confirmado_se_preserva_todo_lo_que_toque() {
    let mut diario = Journal::new();
    diario.activar_incidente();
    // Incluso una escritura documento->documento se preserva una vez el detector
    // confirmo el incidente: el proceso es malicioso, cualquier cosa que toque
    // hay que poder deshacerla.
    assert_eq!(
        diario.evaluar(b"/u/h", b"antes", b"despues"),
        DecisionDiario::Copiar
    );
}

#[test]
fn una_copia_sombra_alterada_se_detecta_al_recuperar() {
    let dir = tempfile::tempdir().unwrap();
    let almacen = AlmacenSombra::abrir(dir.path(), [0x33u8; 32]).unwrap();
    let id = almacen
        .guardar(b"/u/secreto", b"contenido original")
        .unwrap();

    // Un atacante altera un byte del blob cifrado en disco.
    let ruta_blob = dir.path().join(id.hex());
    let mut blob = std::fs::read(&ruta_blob).unwrap();
    let n = blob.len();
    blob[n - 1] ^= 0xFF;
    std::fs::write(&ruta_blob, &blob).unwrap();

    // AES-GCM detecta la manipulacion: no devuelve basura, devuelve error.
    assert!(
        almacen.recuperar(id).is_err(),
        "GCM tiene que detectar la copia alterada"
    );
}

#[test]
fn la_copia_sombra_conserva_ruta_y_contenido() {
    let dir = tempfile::tempdir().unwrap();
    let almacen = AlmacenSombra::abrir(dir.path(), [0x55u8; 32]).unwrap();
    let id = almacen.guardar(b"/home/u/doc.txt", b"hola mundo").unwrap();
    let (ruta, contenido) = almacen.recuperar(id).unwrap();
    assert_eq!(ruta, b"/home/u/doc.txt");
    assert_eq!(contenido, b"hola mundo");
}
