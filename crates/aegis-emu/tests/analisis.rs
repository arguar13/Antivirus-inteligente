//! Pruebas de integracion del micro-sandbox contra codigo maquina x86-64 REAL.
//!
//! Cada prueba ensambla a mano un stub —un empaquetador que se auto-descifra,
//! una auto-inyeccion via `mmap` RWX, un binario benigno, un C2— y comprueba que
//! el sandbox lo emula de verdad y lo clasifica bien. Es la honestidad de la
//! fase: no hay mocks, se ejecutan bytes de instruccion autenticos.

use std::time::{Duration, Instant};

use aegis_emu::{AegisSandbox, ClaseComportamiento, EventoComportamiento, Severidad};

/// EL CASO DECISIVO del desempaquetado, calcado del de `aegis-unpacker`: una
/// firma que NO esta en el fichero de disco SI aparece tras desempaquetar.
///
/// El stub descifra (XOR 0x5A) 6 bytes en 0x400040 y salta a ellos. Descifrados
/// son `mov eax, 0xCAFEBABE; hlt`. En el "disco" (el codigo cifrado) el marcador
/// 0xCAFEBABE no se ve; tras emular, el sandbox lo extrae.
#[test]
fn desempaqueta_un_stub_xor_y_extrae_la_carga_real() {
    let mut codigo = vec![0x90u8; 0x1000];
    // Descifrador en 0x400000.
    let descifrador = [
        0x48, 0xBE, 0x40, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rsi, 0x400040
        0xB9, 0x06, 0x00, 0x00, 0x00, // mov ecx, 6
        0x8A, 0x06, // mov al, [rsi]
        0x34, 0x5A, // xor al, 0x5A
        0x88, 0x06, // mov [rsi], al
        0x48, 0xFF, 0xC6, // inc rsi
        0xE2, 0xF5, // loop -11 (al mov al,[rsi])
        0x48, 0xB8, 0x40, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0x400040
        0xFF, 0xE0, // jmp rax
    ];
    codigo[..descifrador.len()].copy_from_slice(&descifrador);
    // Carga cifrada en 0x400040: descifra a  B8 BE BA FE CA F4.
    let cifrada = [0xE2, 0xE4, 0xE0, 0xA4, 0x90, 0xAE];
    codigo[0x40..0x40 + cifrada.len()].copy_from_slice(&cifrada);

    let ini = Instant::now();
    let informe = AegisSandbox::nuevo().analizar(&codigo);
    let transcurrido = ini.elapsed();

    // La firma no estaba en el "disco".
    assert_ne!(&codigo[0x40..0x46], &[0xB8, 0xBE, 0xBA, 0xFE, 0xCA, 0xF4]);
    // Se detecto el desempaquetado.
    assert!(informe
        .eventos
        .iter()
        .any(|e| matches!(e, EventoComportamiento::Desempaquetado { .. })));
    // Y la carga extraida SI la tiene: mov eax, 0xCAFEBABE ; hlt.
    let carga = informe.desempaquetado.expect("debe extraer la carga");
    assert_eq!(carga, vec![0xB8, 0xBE, 0xBA, 0xFE, 0xCA, 0xF4]);
    // La carga se ejecuto de verdad: termino en el HLT descifrado.
    assert!(informe.termino);
    assert_eq!(informe.error, None);
    assert_eq!(
        informe.veredicto.clase,
        ClaseComportamiento::Desempaquetador
    );
    // El presupuesto de la fase: muy por debajo de 100 ms (aqui, microsegundos).
    assert!(
        transcurrido < Duration::from_millis(100),
        "la emulacion tardo {transcurrido:?}"
    );
}

/// Auto-inyeccion: `mmap` de una region RWX, escribir en ella y saltar. El
/// sandbox lo emula de verdad (el `mmap` reparte una direccion usable) y lo marca
/// como critico.
#[test]
fn detecta_autoinyeccion_via_mmap_rwx() {
    let stub = [
        0xB8, 0x09, 0x00, 0x00, 0x00, // mov eax, 9 (mmap)
        0x31, 0xFF, // xor edi, edi (addr = NULL)
        0xBE, 0x00, 0x10, 0x00, 0x00, // mov esi, 0x1000 (len)
        0xBA, 0x07, 0x00, 0x00, 0x00, // mov edx, 7 (PROT_R|W|X)
        0x0F, 0x05, // syscall -> rax = base reservada
        0xC6, 0x00, 0xF4, // mov byte [rax], 0xF4 (escribe un HLT)
        0xFF, 0xE0, // jmp rax (ejecuta la region recien escrita)
    ];
    let informe = AegisSandbox::nuevo().analizar(&stub);

    assert_eq!(informe.veredicto.clase, ClaseComportamiento::AutoInyeccion);
    assert_eq!(informe.veredicto.severidad, Severidad::Critica);
    assert!(informe.veredicto.malicioso);
    assert!(informe.termino);
    // Se vio tanto la memoria ejecutable como el salto a codigo escrito.
    assert!(informe
        .eventos
        .iter()
        .any(|e| matches!(e, EventoComportamiento::Desempaquetado { .. })));
}

/// EL CASO DECISIVO de no marcar de mas: un binario que solo lee y termina es
/// benigno.
#[test]
fn un_binario_que_solo_lee_y_sale_es_benigno() {
    let stub = [
        0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, 0 (read)
        0x0F, 0x05, // syscall
        0xB8, 0x3C, 0x00, 0x00, 0x00, // mov eax, 60 (exit)
        0x31, 0xFF, // xor edi, edi
        0x0F, 0x05, // syscall
    ];
    let informe = AegisSandbox::nuevo().analizar(&stub);
    assert_eq!(informe.veredicto.clase, ClaseComportamiento::Benigno);
    assert!(!informe.veredicto.malicioso);
    assert!(informe.termino);
}

/// Actividad de red: `socket` + `connect` se clasifica como C2.
#[test]
fn detecta_c2_por_actividad_de_red() {
    let stub = [
        0xB8, 0x29, 0x00, 0x00, 0x00, // mov eax, 41 (socket)
        0x0F, 0x05, // syscall
        0xB8, 0x2A, 0x00, 0x00, 0x00, // mov eax, 42 (connect)
        0x0F, 0x05, // syscall
        0xB8, 0x3C, 0x00, 0x00, 0x00, // mov eax, 60 (exit)
        0x31, 0xFF, // xor edi, edi
        0x0F, 0x05, // syscall
    ];
    let informe = AegisSandbox::nuevo().analizar(&stub);
    assert_eq!(informe.veredicto.clase, ClaseComportamiento::C2);
    assert_eq!(informe.veredicto.severidad, Severidad::Alta);
    assert!(informe.veredicto.malicioso);
}

/// Un opcode fuera del subconjunto se declara con honestidad: el informe trae el
/// error, y la traza obtenida hasta ese punto queda intacta (no se finge nada).
#[test]
fn una_instruccion_no_soportada_se_declara_sin_fingir() {
    // f1 (ICEBP) no esta en el subconjunto.
    let stub = [0xF1];
    let informe = AegisSandbox::nuevo().analizar(&stub);
    assert!(informe.error.is_some());
    assert!(informe.error.as_deref().unwrap().contains("no soportada"));
}
