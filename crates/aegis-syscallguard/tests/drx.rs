//! Prueba de los registros de depuracion (DRx) contra el hardware REAL.
//!
//! A diferencia de la PMU, los registros de depuracion SI estan en esta
//! maquina. Se arma un punto de ruptura de EJECUCION por hardware sobre una
//! funcion conocida, se la llama N veces y se comprueba que el contador de
//! hardware marca exactamente N disparos. Es la instruccion `syscall` de la
//! puerta sancionada, contada por el silicio, sin tocar un solo byte del codigo.

use aegis_syscallguard::drx::{sondear_drx, SoporteDrx, VigilanteEjecucion};

/// Funcion vigilada. `inline(never)` para que tenga una direccion estable y
/// cada llamada ejecute de verdad su primera instruccion.
#[inline(never)]
fn objetivo_vigilado(x: u64) -> u64 {
    std::hint::black_box(x).wrapping_mul(2654435761)
}

#[test]
fn la_sonda_de_drx_es_honesta() {
    match sondear_drx() {
        SoporteDrx::Disponible => eprintln!("DRx disponible: hay registros de depuracion"),
        SoporteDrx::NoDisponible(m) => {
            assert!(!m.is_empty(), "una no-disponibilidad debe explicarse");
            eprintln!("DRx no disponible: {m}");
        }
    }
}

#[test]
fn un_punto_de_ruptura_por_hardware_cuenta_las_ejecuciones() {
    if !sondear_drx().hay() {
        eprintln!("OMITIDA: esta maquina no expone registros de depuracion");
        return;
    }

    let addr = objetivo_vigilado as *const () as u64;
    let vigilante = match VigilanteEjecucion::armar(addr, 0) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("OMITIDA: no se pudo armar el punto de ruptura: {e}");
            return;
        }
    };
    assert_eq!(vigilante.direccion(), addr);

    const N: u64 = 7;
    let mut acc = 0u64;
    for i in 0..N {
        acc = acc.wrapping_add(objetivo_vigilado(i));
    }
    std::hint::black_box(acc);

    let disparos = vigilante
        .disparos()
        .expect("leer los disparos del hardware");
    eprintln!("el hardware conto {disparos} ejecuciones de la direccion vigilada (esperado {N})");
    assert_eq!(
        disparos, N,
        "el hardware debe contar exactamente {N} ejecuciones de la direccion vigilada, conto {disparos}"
    );
}
