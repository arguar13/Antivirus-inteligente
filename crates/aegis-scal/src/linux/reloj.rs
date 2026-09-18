//! Los relojes del sistema, incluido el que no se puede mover.
//!
//! # Por que esto esta en la SCAL y no en quien lo usa
//!
//! `std` da dos relojes: `SystemTime`, que es el de pared y se puede mover, e
//! `Instant`, que es monotono pero se apoya en `CLOCK_MONOTONIC` —que NO cuenta
//! el tiempo suspendido— y no expone su valor, solo diferencias. Para una
//! cronologia forense hace falta un tercero, `CLOCK_BOOTTIME`, y ese solo se
//! alcanza con `clock_gettime`. La regla del producto es que esa llamada vive
//! concentrada aqui, revisada, y que quien la consume —`aegis-custodia`, desde
//! la FASE 82— lo hace con `#![forbid(unsafe_code)]` y sin enterarse.
//!
//! # Los dos relojes, y por que los dos
//!
//! | Reloj | Sabe que dia es | Se puede mover | Cuenta lo suspendido |
//! |---|---|---|---|
//! | `CLOCK_REALTIME` | si | **si**, con `clock_settime` | — |
//! | `CLOCK_BOOTTIME` | no | **no**: no hay llamada para fijarlo | si |
//!
//! El de pared es el unico que puede fechar un hecho, y el unico que un
//! atacante con root puede falsear. El de arranque no sabe que dia es, pero no
//! retrocede nunca, asi que ordena hechos del mismo arranque con independencia
//! de lo que diga el otro. Registrando los dos, una contradiccion entre ellos
//! deja de ser invisible y pasa a ser aritmetica.
//!
//! # Por que BOOTTIME y no MONOTONIC
//!
//! `CLOCK_MONOTONIC` se para mientras la maquina esta suspendida. En un portatil
//! que pasa la noche cerrado, dos hechos separados por diez horas reales
//! aparecerian separados por segundos, y la cronologia quedaria comprimida sin
//! que nada lo indicara. `CLOCK_BOOTTIME` es el mismo reloj contando tambien esa
//! suspension, que es lo que un forense necesita.

/// Segundos desde la epoca Unix, por el reloj de pared (`CLOCK_REALTIME`).
///
/// Es el unico que sabe que dia es, y el unico que se puede mover. Devuelve
/// `None` si el kernel rechaza la llamada, que no deberia ocurrir nunca: no
/// inventa un cero, porque una marca de tiempo inventada en un informe forense
/// es peor que una ausente.
pub fn pared_segundos() -> Option<u64> {
    leer(libc::CLOCK_REALTIME).map(|(s, _)| s)
}

/// Nanosegundos desde el arranque, contando la suspension (`CLOCK_BOOTTIME`).
///
/// No se puede fijar y no retrocede. Solo es comparable con otra lectura **del
/// mismo arranque**: en el siguiente vuelve a contar desde cero.
pub fn arranque_nanos() -> Option<u64> {
    leer(libc::CLOCK_BOOTTIME).map(|(s, ns)| s.saturating_mul(1_000_000_000).saturating_add(ns))
}

/// Lee un reloj POSIX. Devuelve `(segundos, nanosegundos)`.
fn leer(cual: libc::clockid_t) -> Option<(u64, u64)> {
    let mut t = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `clock_gettime` escribe los dos campos del `timespec` que se le
    // pasa y no toca ninguna otra memoria del proceso. El puntero apunta a una
    // variable local viva y en exclusiva durante toda la llamada, y el valor de
    // retorno se comprueba antes de leerla.
    let r = unsafe { libc::clock_gettime(cual, &mut t) };
    if r != 0 {
        return None;
    }
    // Un reloj no devuelve negativos, pero el tipo del sistema es con signo:
    // se acota en vez de convertir a ciegas, que con `as` daria un numero
    // enorme justo en el caso raro.
    if t.tv_sec < 0 || t.tv_nsec < 0 {
        return None;
    }
    Some((t.tv_sec as u64, t.tv_nsec as u64))
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn el_reloj_de_pared_da_una_fecha_plausible() {
        let s = pared_segundos().expect("CLOCK_REALTIME siempre responde");
        // Posterior a 2020 y anterior a 2100: no comprueba la hora, comprueba
        // que se esta leyendo el reloj y no un cero.
        assert!(s > 1_577_836_800, "posterior a 2020: {s}");
        assert!(s < 4_102_444_800, "anterior a 2100: {s}");
    }

    #[test]
    fn el_reloj_de_arranque_avanza_y_no_retrocede() {
        let a = arranque_nanos().expect("CLOCK_BOOTTIME siempre responde");
        let b = arranque_nanos().expect("CLOCK_BOOTTIME siempre responde");
        assert!(b >= a, "el reloj de arranque no retrocede: {a} -> {b}");
    }

    #[test]
    fn el_reloj_de_arranque_mide_una_espera_real() {
        // Que avance NO basta: hay que comprobar que mide tiempo de verdad y no
        // devuelve un contador cualquiera.
        let a = arranque_nanos().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        let b = arranque_nanos().unwrap();
        let delta = b - a;
        assert!(
            delta >= 15_000_000,
            "veinte milisegundos de espera tienen que verse: {delta} ns"
        );
        assert!(
            delta < 5_000_000_000,
            "y no pueden ser cinco segundos: {delta} ns"
        );
    }

    #[test]
    fn los_dos_relojes_son_distintos() {
        // El de arranque cuenta desde el arranque y el de pared desde 1970: si
        // alguien cablea los dos al mismo `clockid`, esto lo detecta.
        let pared_ns = pared_segundos().unwrap().saturating_mul(1_000_000_000);
        let arranque = arranque_nanos().unwrap();
        assert!(
            arranque < pared_ns,
            "el tiempo desde el arranque no puede ser mayor que el transcurrido \
             desde 1970"
        );
    }
}
