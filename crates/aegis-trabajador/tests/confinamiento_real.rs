//! El trabajador confinado contra el kernel de verdad: confinamiento real,
//! panico, bomba de memoria, bucle infinito, relanzamiento y enfriamiento.
//!
//! Necesita root (espacio de nombres de red, cambio de uid, cgroup). En make ci
//! se ejecuta como root con `AEGIS_EXIGIR_ROOT=1`, y entonces NO se salta: una
//! prueba de confinamiento que se omite en silencio es un verde falso.

#![cfg(all(target_os = "linux", feature = "prueba-fallos"))]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use aegis_trabajador::{Analizador, ConfigTrabajador, FalloAnalisis, Trabajador};

fn es_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("Uid:"))
                .map(|l| l.split_whitespace().next() == Some("0"))
        })
        .unwrap_or(false)
}

/// `None` si hay que saltar (sin root y sin exigencia); falla si se exige.
fn config() -> Option<ConfigTrabajador> {
    if !es_root() {
        assert!(
            std::env::var_os("AEGIS_EXIGIR_ROOT").is_none(),
            "AEGIS_EXIGIR_ROOT: la prueba de confinamiento real necesita root"
        );
        eprintln!("SALTADA: el confinamiento real necesita root");
        return None;
    }
    let mut c = ConfigTrabajador::este_binario().expect("ruta del ejecutable");
    c.programa = PathBuf::from(env!("CARGO_BIN_EXE_aegis-trabajador-prueba"));
    c.argumentos = Vec::new();
    c.memoria_max = 96 * 1024 * 1024;
    c.max_muertes = 50;
    Some(c)
}

#[test]
fn se_confina_de_verdad_y_lo_declara() {
    let Some(c) = config() else { return };
    let mut t = Trabajador::arrancar(c).expect("el trabajador arranca y se confina");
    let conf = t.estado().confinamiento.clone();
    for capa in [
        "red-cortada=si",
        "uid-propio=si",
        "seccomp=si",
        "limites=si",
    ] {
        assert!(conf.contains(capa), "falta {capa}: {conf}");
    }
    assert!(
        !t.estado().cgroup.starts_with("SIN"),
        "sin cgroup: {}",
        t.estado().cgroup
    );

    // Desde DENTRO: ni ficheros ni red.
    let i = t
        .analizar(Analizador::PruebaSonda, b"", Duration::from_secs(5))
        .expect("la sonda responde");
    let dice = &i.hallazgos[0].porque;
    assert!(
        !dice.contains("fichero=abrio"),
        "el trabajador leyo un fichero: {dice}"
    );
    assert!(
        !dice.contains("red=abrio"),
        "el trabajador abrio un socket: {dice}"
    );
}

#[test]
fn un_panico_mata_al_trabajador_y_el_siguiente_analisis_lo_relanza() {
    let Some(c) = config() else { return };
    let mut t = Trabajador::arrancar(c).unwrap();
    let r = t.analizar(Analizador::PruebaPanico, b"PANICO", Duration::from_secs(5));
    assert!(matches!(r, Err(FalloAnalisis::Murio(_))), "{r:?}");
    let otro = t.analizar(Analizador::Pe, b"MZ no es un PE", Duration::from_secs(5));
    assert!(
        otro.is_ok(),
        "tras morir, el siguiente analisis relanza: {otro:?}"
    );
    assert_eq!(t.estado().arranques, 2);
    assert_eq!(t.estado().muertes, 1);
}

#[test]
fn la_bomba_de_memoria_la_para_el_techo_del_cgroup() {
    let Some(c) = config() else { return };
    let mut t = Trabajador::arrancar(c).unwrap();
    let r = t.analizar(Analizador::PruebaMemoria, b"", Duration::from_secs(20));
    assert!(matches!(r, Err(FalloAnalisis::Murio(_))), "{r:?}");
    assert_eq!(
        t.estado().muertes_por_memoria,
        1,
        "la muerte la causo el techo de memoria del cgroup: {:?}",
        t.estado().ultima_muerte
    );
}

#[test]
fn el_bucle_infinito_lo_corta_el_plazo() {
    let Some(c) = config() else { return };
    let mut t = Trabajador::arrancar(c).unwrap();
    let inicio = Instant::now();
    let r = t.analizar(Analizador::PruebaBucle, b"", Duration::from_millis(500));
    assert!(matches!(r, Err(FalloAnalisis::Plazo(_))), "{r:?}");
    assert!(inicio.elapsed() < Duration::from_secs(3));
    assert_eq!(t.estado().plazos, 1);
}

#[test]
fn morir_en_bucle_lo_deja_enfriando_y_lo_dice() {
    let Some(mut c) = config() else { return };
    c.max_muertes = 3;
    let mut t = Trabajador::arrancar(c).unwrap();
    for _ in 0..3 {
        let _ = t.analizar(Analizador::PruebaPanico, b"PANICO", Duration::from_secs(5));
    }
    let r = t.analizar(Analizador::Pe, b"MZ", Duration::from_secs(5));
    assert!(
        matches!(&r, Err(FalloAnalisis::NoDisponible(m)) if m.contains("enfriando")),
        "{r:?}"
    );
    assert_eq!(t.estado().enfriamientos, 1);
}

#[test]
fn un_ejecutable_real_se_analiza_confinado() {
    let Some(c) = config() else { return };
    let mut t = Trabajador::arrancar(c).unwrap();
    let bytes = std::fs::read("/bin/ls").expect("/bin/ls");
    for a in aegis_trabajador::para_ejecutable(&bytes) {
        let r = t.analizar(a, &bytes, Duration::from_secs(10));
        assert!(r.is_ok(), "{a:?}: {r:?}");
    }
    assert_eq!(t.estado().muertes, 0);
}
