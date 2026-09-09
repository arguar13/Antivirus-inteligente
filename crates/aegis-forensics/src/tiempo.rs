//! Marcas de tiempo en el formato que exige STIX.
//!
//! STIX 2.1 obliga a que todo instante sea RFC 3339 en UTC y con precision de
//! milisegundos: `2024-05-17T09:31:04.123Z`. El resto del producto trabaja con
//! el reloj MONOTONO, que es lo correcto para medir intervalos —no salta con
//! NTP— pero no tiene fecha. Para un informe que va a leer un humano o a cruzar
//! otra herramienta hace falta la hora de pared, y este modulo la convierte.
//!
//! Se hace la aritmetica del calendario a mano en vez de traer una dependencia:
//! son treinta lineas de un algoritmo publicado y verificable contra fechas
//! conocidas, y una caja de fechas completa arrastra zonas horarias, localizacion
//! y analisis de formatos que este producto no usa para nada.

/// Convierte segundos desde el epoch de Unix a `YYYY-MM-DDTHH:MM:SS.mmmZ`.
///
/// Solo admite instantes posteriores al epoch: una marca anterior a 1970 en un
/// informe forense es un reloj mal puesto, y emitir una fecha con año negativo
/// produciria un documento que ningun consumidor de STIX acepta.
pub fn rfc3339(epoch_secs: u64, millis: u32) -> String {
    let dias = (epoch_secs / 86_400) as i64;
    let resto = epoch_secs % 86_400;
    let (y, m, d) = civil_desde_dias(dias);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z",
        resto / 3600,
        (resto % 3600) / 60,
        resto % 60,
        millis.min(999)
    )
}

/// Instante actual del reloj de pared en formato STIX.
pub fn ahora() -> String {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => rfc3339(d.as_secs(), d.subsec_millis()),
        // Un reloj anterior a 1970 significa que la maquina no tiene hora. Se
        // emite el epoch, que es una fecha valida y evidentemente falsa, en vez
        // de un documento invalido o un panico en mitad de un incidente.
        Err(_) => rfc3339(0, 0),
    }
}

/// Fecha civil a partir de los dias desde el epoch.
///
/// Algoritmo de Howard Hinnant (`civil_from_days`), que desplaza el origen del
/// calendario a marzo para que el dia bisiesto caiga al final del año y la
/// aritmetica no necesite casos especiales.
pub fn civil_desde_dias(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}
