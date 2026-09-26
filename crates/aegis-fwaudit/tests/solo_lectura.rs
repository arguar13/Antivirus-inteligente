//! La garantia de solo lectura, **ejercida contra el kernel**.
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

// ─── FASE 92: cada superficie nueva, contra el kernel real ────────────────────
//
// La FASE 92 lleva `LecturaSolo` a sitios mucho mas peligrosos que un fichero:
// la configuracion PCI del chipset, `/proc`, los ficheros de microcodigo del
// fabricante y `/dev/mem`. Se ejerce la garantia en CADA uno.
//
// DOS DECISIONES QUE HACEN SEGURA LA PRUEBA MISMA
//
// 1. Las escrituras son de CERO bytes y el truncado es al tamano ACTUAL. El
//    kernel comprueba el modo del descriptor antes que la longitud
//    (`vfs_write` empieza por `FMODE_WRITE`), asi que el rechazo se demuestra
//    igual. Y si la garantia fallara algun dia, la prueba no podria hacer dano:
//    ni en la memoria fisica, ni en el microcodigo del fabricante.
// 2. Se afirma el errno que el kernel da DE VERDAD, que no es siempre EBADF:
//    `write` da EBADF; `pwrite` da ESPIPE en los ficheros de /proc y sysfs
//    (rechaza la escritura posicional antes de mirar el modo) y EBADF en el
//    resto; `ftruncate` da EINVAL (el kernel exige fichero regular Y abierto
//    para escribir, y agrupa los dos fallos en ese codigo). El enunciado de la
//    fase pedia EBADF en los tres; se comprueba lo que el kernel hace, que es lo
//    unico que se puede comprobar.

/// Lo que devolvio el kernel en cada intento.
struct Rechazo {
    write: i32,
    pwrite: i32,
    ftruncate: i32,
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Intenta escribir por las tres vias sobre el descriptor que da `LecturaSolo`.
/// Devuelve `None` si la superficie no existe en esta maquina.
fn ejercer(ruta: &std::path::Path) -> Option<Rechazo> {
    let lector = LecturaSolo::abrir(ruta).ok()?;
    let fd = lector.as_fd().as_raw_fd();
    let nada = [0u8; 0];
    let tamano = std::fs::metadata(ruta).map(|m| m.len()).unwrap_or(0);
    // SEGURIDAD: escrituras de CERO bytes y truncado al tamano ACTUAL sobre un
    // descriptor propio abierto O_RDONLY; aunque la garantia fallara, no
    // cambiarian nada.
    let w = unsafe { libc::write(fd, nada.as_ptr().cast::<libc::c_void>(), 0) };
    let ew = if w == -1 { errno() } else { 0 };
    let pw = unsafe { libc::pwrite(fd, nada.as_ptr().cast::<libc::c_void>(), 0, 0) };
    let epw = if pw == -1 { errno() } else { 0 };
    let t = unsafe { libc::ftruncate(fd, libc::off_t::try_from(tamano).unwrap_or(0)) };
    let et = if t == -1 { errno() } else { 0 };
    Some(Rechazo {
        write: ew,
        pwrite: epw,
        ftruncate: et,
    })
}

fn nombre_errno(e: i32) -> &'static str {
    match e {
        0 => "PERMITIDO",
        libc::EBADF => "EBADF",
        libc::ESPIPE => "ESPIPE",
        libc::EINVAL => "EINVAL",
        libc::EACCES => "EACCES",
        libc::EPERM => "EPERM",
        _ => "otro",
    }
}

/// El primer fichero de un directorio que cumpla un criterio.
fn primero(dir: &str, sufijo: &str) -> Option<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        // `join("")` anadiria una barra final y la apertura daria ENOTDIR.
        .map(|e| {
            if sufijo.is_empty() {
                e.path()
            } else {
                e.path().join(sufijo)
            }
        })
        .filter(|p| p.exists())
        .collect();
    v.sort();
    v.into_iter().next()
}

/// AUTOATAQUE: la auditoria como via de ladrillo, por cada superficie nueva.
#[test]
fn cada_superficie_nueva_rechaza_la_escritura_en_el_kernel() {
    let superficies: Vec<(&str, Option<PathBuf>)> = vec![
        (
            "configuracion PCI (sysfs)",
            primero("/sys/bus/pci/devices", "config"),
        ),
        (
            "tabla ACPI (DSDT)",
            Some(PathBuf::from("/sys/firmware/acpi/tables/DSDT")),
        ),
        ("/proc/cpuinfo", Some(PathBuf::from("/proc/cpuinfo"))),
        (
            "mitigaciones de CPU (sysfs)",
            primero("/sys/devices/system/cpu/vulnerabilities", ""),
        ),
        (
            "microcodigo del fabricante",
            primero("/lib/firmware/intel-ucode", ""),
        ),
        (
            "variables UEFI (efivarfs)",
            primero("/sys/firmware/efi/efivars", ""),
        ),
        ("memoria fisica (/dev/mem)", Some(PathBuf::from("/dev/mem"))),
        ("MSR de la CPU 0", Some(PathBuf::from("/dev/cpu/0/msr"))),
    ];
    let mut ejercidas = 0;
    for (nombre, ruta) in superficies {
        let Some(ruta) = ruta else {
            eprintln!("  {nombre:<32} NO APLICABLE: no existe en esta maquina");
            continue;
        };
        let Some(r) = ejercer(&ruta) else {
            eprintln!(
                "  {nombre:<32} NO APLICABLE: {} no se puede abrir aqui",
                ruta.display()
            );
            continue;
        };
        eprintln!(
            "  {nombre:<32} write={} pwrite={} ftruncate={}   ({})",
            nombre_errno(r.write),
            nombre_errno(r.pwrite),
            nombre_errno(r.ftruncate),
            ruta.display()
        );
        assert_eq!(r.write, libc::EBADF, "{nombre}: write tiene que dar EBADF");
        assert!(
            r.pwrite == libc::EBADF || r.pwrite == libc::ESPIPE,
            "{nombre}: pwrite tiene que rechazarse (EBADF o ESPIPE), dio {}",
            nombre_errno(r.pwrite)
        );
        assert!(
            r.ftruncate == libc::EINVAL || r.ftruncate == libc::EBADF,
            "{nombre}: ftruncate tiene que rechazarse, dio {}",
            nombre_errno(r.ftruncate)
        );
        ejercidas += 1;
    }
    // Una prueba que no ejerce nada no demuestra nada: en esta maquina hay,
    // como minimo, /proc/cpuinfo, las mitigaciones y la DSDT.
    assert!(ejercidas >= 3, "solo se ejercieron {ejercidas} superficies");
    eprintln!("  superficies ejercidas contra el kernel: {ejercidas}");
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
