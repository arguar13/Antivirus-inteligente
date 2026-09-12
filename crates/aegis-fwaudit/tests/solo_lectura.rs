//! La garantía de solo lectura, **ejercida contra el kernel**.
//!
//! # Por que esta prueba vive fuera de la biblioteca
//!
//! `aegis-fwaudit` lleva `#![forbid(unsafe_code)]`, y eso es parte de la
//! garantia, no una preferencia de estilo: el crate lee la ROM SPI de la placa
//! base, y una escritura accidental ahi no es un bug, es un **ladrillo** —una ROM
//! mal escrita deja la maquina sin arrancar y no hay recuperacion por software—.
//!
//! Pero para DEMOSTRAR que el kernel rechaza una escritura hace falta intentarla,
//! y eso es `unsafe`. Que la prueba sea externa es exactamente lo correcto: la
//! biblioteca no puede escribir ni queriendo (el compilador se lo impide), y la
//! prueba comprueba que, aunque pudiera, el kernel lo pararia igual.
//!
//! Son dos capas independientes. Una sola no bastaria: `forbid(unsafe_code)` no
//! impide llamar a `File::write`, y `O_RDONLY` no impide un fallo logico en otra
//! parte. Juntas, la escritura es imposible por dos motivos distintos.

use std::os::fd::{AsFd, AsRawFd};
use std::path::PathBuf;

use aegis_fwaudit::solo_lectura::LecturaSolo;

fn fichero_temporal(nombre: &str, contenido: &[u8]) -> PathBuf {
    let ruta =
        std::env::temp_dir().join(format!("aegis-fwaudit-it-{}-{nombre}", std::process::id()));
    std::fs::write(&ruta, contenido).expect("crear el fichero de prueba");
    ruta
}

/// LA GARANTIA. No se comprueba que el codigo «no llame a write»: se comprueba
/// que, aunque llamara, el kernel lo rechaza. Es la diferencia entre una
/// convencion y una garantia.
#[test]
fn el_kernel_rechaza_cualquier_escritura_sobre_un_descriptor_abierto_asi() {
    let ruta = fichero_temporal("rechazo", b"contenido original");
    let lector = LecturaSolo::abrir(&ruta).expect("abrir");

    let datos = b"DESTRUIDO";
    // SEGURIDAD: se escribe sobre un descriptor propio abierto O_RDONLY. La
    // llamada tiene que FALLAR; ese es justo el objeto de la prueba.
    let n = unsafe {
        libc::write(
            lector.as_fd().as_raw_fd(),
            datos.as_ptr().cast::<libc::c_void>(),
            datos.len(),
        )
    };
    let err = std::io::Error::last_os_error();
    assert_eq!(n, -1, "el kernel NO puede permitir escribir aqui");
    assert_eq!(
        err.raw_os_error(),
        Some(libc::EBADF),
        "se esperaba EBADF (descriptor no abierto para escritura), llego {err}"
    );

    // Y el contenido sigue intacto. Es lo que separa un EDR de un ladrillo.
    assert_eq!(
        std::fs::read(&ruta).expect("releer"),
        b"contenido original",
        "el fichero NO puede haber cambiado"
    );
    let _ = std::fs::remove_file(&ruta);
}

/// Truncar tampoco. `ftruncate` es otra via de destruir una ROM, y tambien la
/// para el modo de apertura.
#[test]
fn un_truncado_tambien_se_rechaza() {
    let ruta = fichero_temporal("truncar", &vec![0xAAu8; 4096]);
    let lector = LecturaSolo::abrir(&ruta).expect("abrir");
    // SEGURIDAD: truncar un descriptor propio de solo lectura; tiene que fallar.
    let rc = unsafe { libc::ftruncate(lector.as_fd().as_raw_fd(), 0) };
    assert_eq!(rc, -1, "truncar tampoco puede permitirse");
    assert_eq!(
        std::fs::metadata(&ruta).expect("metadata").len(),
        4096,
        "el fichero conserva su tamano"
    );
    let _ = std::fs::remove_file(&ruta);
}

/// Y `pwrite`, que escribe en un desplazamiento sin mover el cursor: es la via
/// que usaria quien quisiera parchear un sector concreto de la ROM.
#[test]
fn una_escritura_posicional_tampoco_pasa() {
    let ruta = fichero_temporal("pwrite", &vec![0x55u8; 8192]);
    let lector = LecturaSolo::abrir(&ruta).expect("abrir");
    let datos = [0xFFu8; 16];
    // SEGURIDAD: pwrite sobre un descriptor propio de solo lectura.
    let n = unsafe {
        libc::pwrite(
            lector.as_fd().as_raw_fd(),
            datos.as_ptr().cast::<libc::c_void>(),
            datos.len(),
            4096,
        )
    };
    assert_eq!(n, -1, "una escritura posicional tampoco puede permitirse");
    assert!(
        std::fs::read(&ruta)
            .expect("releer")
            .iter()
            .all(|b| *b == 0x55),
        "ni un byte del fichero puede haber cambiado"
    );
    let _ = std::fs::remove_file(&ruta);
}
