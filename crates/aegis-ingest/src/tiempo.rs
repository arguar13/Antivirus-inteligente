//! Conversion de fechas a nanosegundos desde la epoca Unix.
//!
//! # Por que esta escrito aqui y no se trae una biblioteca de calendario
//!
//! Porque esto corre en el AGENTE, donde cada dependencia es superficie de
//! ataque y peso en el presupuesto, y porque lo que hace falta es exactamente
//! esto: convertir una fecha civil a un instante. Las bibliotecas de calendario
//! completas traen zonas horarias, formatos de salida y localizacion, y ninguna
//! de las tres cosas se usa en una canalizacion de registros.
//!
//! El algoritmo de [`dias_desde_civil`] es el de Howard Hinnant: aritmetica
//! entera exacta, sin tablas y sin bucles, valida para cualquier ano del
//! calendario gregoriano proleptico. No aproxima.
//!
//! # El ano que el registro no dice
//!
//! RFC 3164 —el syslog viejo, que sigue siendo la mayoria de lo que llega a un
//! puerto 514— **no lleva ano**. Hay que ponerlo, y ponerlo mal tiene una
//! consecuencia concreta: una linea del 31 de diciembre leida el 1 de enero se
//! fecharia con once meses y veintinueve dias de retraso, saldria de cualquier
//! ventana de correlacion, y el incidente de nochevieja no se veria. Ver
//! [`ano_probable`].

/// Nanosegundos en un segundo.
pub const NS: u64 = 1_000_000_000;

/// Segundos en un dia.
const SEGUNDOS_DIA: i64 = 86_400;

/// Desfase entre la epoca de Windows (1601-01-01) y la de Unix, en segundos.
///
/// Lo necesita EVTX, que fecha con `FILETIME`: intervalos de 100 ns desde 1601.
pub const DESFASE_FILETIME_S: i64 = 11_644_473_600;

/// Dias desde 1970-01-01 para una fecha civil.
///
/// Algoritmo de Howard Hinnant (`days_from_civil`): desplaza el origen a marzo
/// para que el dia bisiesto caiga al final del ano y desaparezcan los casos
/// especiales. Exacto para todo el gregoriano proleptico.
#[must_use]
pub fn dias_desde_civil(ano: i64, mes: u32, dia: u32) -> i64 {
    let y = if mes <= 2 { ano - 1 } else { ano };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let anos_de_era = y - era * 400; // [0, 399]
    let m = i64::from(mes);
    let d = i64::from(dia);
    let dia_del_ano = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1; // [0, 365]
    let dia_de_era = anos_de_era * 365 + anos_de_era / 4 - anos_de_era / 100 + dia_del_ano;
    era * 146_097 + dia_de_era - 719_468
}

/// La inversa: fecha civil a partir de los dias desde 1970-01-01.
#[must_use]
pub fn civil_desde_dias(dias: i64) -> (i64, u32, u32) {
    let z = dias + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let dia_de_era = z - era * 146_097; // [0, 146096]
    let anos_de_era =
        (dia_de_era - dia_de_era / 1460 + dia_de_era / 36_524 - dia_de_era / 146_096) / 365;
    let y = anos_de_era + era * 400;
    let dia_del_ano = dia_de_era - (365 * anos_de_era + anos_de_era / 4 - anos_de_era / 100);
    let mp = (5 * dia_del_ano + 2) / 153; // [0, 11]
    let d = dia_del_ano - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let ano = if m <= 2 { y + 1 } else { y };
    (
        ano,
        u32::try_from(m).unwrap_or(1),
        u32::try_from(d).unwrap_or(1),
    )
}

/// Instante en nanosegundos Unix a partir de una fecha civil en UTC.
///
/// Devuelve `None` si la fecha no existe —el 31 de febrero, el mes 13— o si se
/// sale del rango representable. Un registro puede traer cualquier cosa en esos
/// campos, incluido lo que desborde una multiplicacion.
#[must_use]
pub fn instante_utc(
    ano: i64,
    mes: u32,
    dia: u32,
    hora: u32,
    minuto: u32,
    segundo: u32,
    nanos: u32,
) -> Option<u64> {
    if !(1..=12).contains(&mes) || dia == 0 || dia > dias_del_mes(ano, mes) {
        return None;
    }
    // El segundo 60 existe: es el intersticial. Se acepta y se aplasta al 59,
    // porque el tiempo Unix no lo representa y rechazar la linea perderia un
    // registro perfectamente legitimo por un detalle del calendario.
    if hora > 23 || minuto > 59 || segundo > 60 || nanos >= 1_000_000_000 {
        return None;
    }
    let segundo = segundo.min(59);
    let dias = dias_desde_civil(ano, mes, dia);
    let segundos = dias
        .checked_mul(SEGUNDOS_DIA)?
        .checked_add(i64::from(hora) * 3600 + i64::from(minuto) * 60 + i64::from(segundo))?;
    let segundos = u64::try_from(segundos).ok()?;
    segundos.checked_mul(NS)?.checked_add(u64::from(nanos))
}

/// Dias que tiene un mes, teniendo en cuenta los bisiestos.
#[must_use]
pub fn dias_del_mes(ano: i64, mes: u32) -> u32 {
    match mes {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if es_bisiesto(ano) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Regla gregoriana completa, con la excepcion de los seculares.
#[must_use]
pub fn es_bisiesto(ano: i64) -> bool {
    (ano % 4 == 0 && ano % 100 != 0) || ano % 400 == 0
}

/// `FILETIME` de Windows —intervalos de 100 ns desde 1601-01-01— a nanosegundos
/// Unix.
///
/// Devuelve `None` para fechas anteriores a 1970: EVTX de una maquina con el
/// reloj en 1601 es un registro sin hora util, y colarlo como cero lo pondria en
/// el mismo instante que la epoca Unix, que es una fecha con significado.
#[must_use]
pub fn desde_filetime(filetime: u64) -> Option<u64> {
    let cien_ns = i64::try_from(filetime).ok()?;
    let segundos = cien_ns / 10_000_000 - DESFASE_FILETIME_S;
    let resto = u64::try_from(cien_ns % 10_000_000).ok()?;
    let segundos = u64::try_from(segundos).ok()?;
    segundos.checked_mul(NS)?.checked_add(resto * 100)
}

/// Deduce el ano de una fecha que no lo lleva.
///
/// # El caso que casi todo el mundo hace mal
///
/// RFC 3164 no trae ano. Lo obvio es poner el del reloj de quien lee, y funciona
/// once meses y veintinueve dias al ano. El dia que falla —una linea del 31 de
/// diciembre leida el 1 de enero— la fecha sale con un ano de adelanto, el
/// evento cae en el futuro, y cualquier ventana de correlacion lo pierde.
///
/// La regla es: se prueba el ano de lectura; si eso deja la fecha mas de un dia
/// en el futuro, es del ano anterior. Un dia de margen y no cero, porque los
/// relojes de las maquinas que emiten syslog viejo no estan sincronizados y
/// adelantar unos minutos es normal.
///
/// Lo que NO se hace es mirar hacia atras: una linea de hace once meses fechada
/// asi es indistinguible de una de hace un mes, y adivinar produciria un evento
/// con una hora inventada. Se queda en el ano de lectura y el control de
/// verosimilitud del esquema la marcara si no cuadra.
#[must_use]
pub fn ano_probable(mes: u32, dia: u32, ahora_ns: u64) -> i64 {
    let (ano_ahora, _, _) =
        civil_desde_dias(i64::try_from(ahora_ns / NS).unwrap_or(0) / SEGUNDOS_DIA);
    let Some(candidato) = instante_utc(ano_ahora, mes, dia, 0, 0, 0, 0) else {
        return ano_ahora;
    };
    if candidato > ahora_ns.saturating_add(2 * u64::from(SEGUNDOS_DIA.unsigned_abs() as u32) * NS) {
        return ano_ahora - 1;
    }
    ano_ahora
}

/// Analiza una marca de tiempo RFC 3339 y devuelve nanosegundos Unix.
///
/// Acepta lo que RFC 5424 permite: fraccion de segundo de 1 a 6 digitos, `Z` o
/// desplazamiento `±HH:MM`. Rechaza todo lo demas **con nombre** en vez de
/// aceptarlo a medias: una hora analizada mal es peor que una hora ausente,
/// porque la ausente se marca como [`crate::esquema::ConfianzaReloj::DeLlegada`]
/// y la mal analizada se cree.
#[must_use]
pub fn desde_rfc3339(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    // Lo minimo es 1970-01-01T00:00:00Z: veinte bytes.
    if b.len() < 20 {
        return None;
    }
    let ano = numero(&b[0..4])?;
    if b[4] != b'-' {
        return None;
    }
    let mes = numero(&b[5..7])?;
    if b[7] != b'-' {
        return None;
    }
    let dia = numero(&b[8..10])?;
    if b[10] != b'T' && b[10] != b't' && b[10] != b' ' {
        return None;
    }
    let hora = numero(&b[11..13])?;
    if b[13] != b':' {
        return None;
    }
    let minuto = numero(&b[14..16])?;
    if b[16] != b':' {
        return None;
    }
    let segundo = numero(&b[17..19])?;

    let mut i = 19;
    let mut nanos: u64 = 0;
    if b[i] == b'.' || b[i] == b',' {
        i += 1;
        let inicio = i;
        let mut escala = 100_000_000u64;
        while i < b.len() && b[i].is_ascii_digit() {
            // Mas alla del nanosegundo la precision se descarta en vez de
            // desbordar: hay emisores que escriben doce digitos.
            if escala > 0 {
                nanos += u64::from(b[i] - b'0') * escala;
                escala /= 10;
            }
            i += 1;
        }
        if i == inicio {
            return None; // un punto sin digitos detras
        }
    }

    // Zona horaria. Es obligatoria en RFC 3339 y su ausencia NO se interpreta
    // como UTC: un registro sin zona puede venir de cualquier huso, y suponer
    // UTC desplazaria el evento hasta doce horas sin que nadie lo supiera.
    let desplazamiento_s: i64 = match b.get(i)? {
        b'Z' | b'z' => {
            i += 1;
            0
        }
        signo @ (b'+' | b'-') => {
            let signo = if *signo == b'-' { -1 } else { 1 };
            if b.len() < i + 6 || b[i + 3] != b':' {
                return None;
            }
            let hh = i64::from(numero(&b[i + 1..i + 3])?);
            let mm = i64::from(numero(&b[i + 4..i + 6])?);
            if hh > 23 || mm > 59 {
                return None;
            }
            i += 6;
            signo * (hh * 3600 + mm * 60)
        }
        _ => return None,
    };
    if i != b.len() {
        return None; // sobra texto: no se analiza a medias
    }

    let base = instante_utc(
        i64::from(ano),
        u32::from(mes),
        u32::from(dia),
        u32::from(hora),
        u32::from(minuto),
        u32::from(segundo),
        u32::try_from(nanos).ok()?,
    )?;
    // El desplazamiento se RESTA: «12:00+02:00» son las 10:00 UTC.
    let ajuste = desplazamiento_s.checked_mul(i64::try_from(NS).ok()?)?;
    if ajuste >= 0 {
        base.checked_sub(u64::try_from(ajuste).ok()?)
    } else {
        base.checked_add(u64::try_from(-ajuste).ok()?)
    }
}

/// Lee un numero decimal de ancho fijo. Cualquier byte que no sea digito lo
/// invalida entero: no se acepta «2O23» como 23.
fn numero(b: &[u8]) -> Option<u16> {
    let mut n: u16 = 0;
    for c in b {
        if !c.is_ascii_digit() {
            return None;
        }
        n = n.checked_mul(10)?.checked_add(u16::from(c - b'0'))?;
    }
    Some(n)
}

/// Los tres meses en ingles abreviado de RFC 3164, a numero.
#[must_use]
pub fn mes_abreviado(s: &[u8]) -> Option<u32> {
    if s.len() != 3 {
        return None;
    }
    let mut clave = [0u8; 3];
    for (d, o) in clave.iter_mut().zip(s.iter()) {
        *d = o.to_ascii_lowercase();
    }
    Some(match &clave {
        b"jan" => 1,
        b"feb" => 2,
        b"mar" => 3,
        b"apr" => 4,
        b"may" => 5,
        b"jun" => 6,
        b"jul" => 7,
        b"aug" => 8,
        b"sep" => 9,
        b"oct" => 10,
        b"nov" => 11,
        b"dec" => 12,
        _ => return None,
    })
}

#[cfg(test)]
mod pruebas {
    use super::*;

    // --- El calendario, contra fechas conocidas ----------------------------

    #[test]
    fn la_epoca_unix_es_el_dia_cero() {
        assert_eq!(dias_desde_civil(1970, 1, 1), 0);
        assert_eq!(civil_desde_dias(0), (1970, 1, 1));
    }

    #[test]
    fn los_bisiestos_seculares_siguen_la_regla_completa() {
        // 1900 NO fue bisiesto y 2000 SI. Una implementacion que solo mire el
        // multiplo de cuatro se desvia un dia durante un siglo entero.
        assert!(!es_bisiesto(1900));
        assert!(es_bisiesto(2000));
        assert!(es_bisiesto(2024));
        assert!(!es_bisiesto(2023));
        assert_eq!(dias_del_mes(2024, 2), 29);
        assert_eq!(dias_del_mes(2023, 2), 28);
    }

    #[test]
    fn ida_y_vuelta_sobre_cuarenta_anos_de_dias() {
        // Barrido exhaustivo: si hubiera un caso especial mal puesto —el 1 de
        // marzo, el 29 de febrero, el cambio de siglo— saldria aqui.
        for d in -20_000..20_000i64 {
            let (a, m, dd) = civil_desde_dias(d);
            assert_eq!(dias_desde_civil(a, m, dd), d, "dia {d} -> {a}-{m}-{dd}");
        }
    }

    #[test]
    fn una_fecha_que_no_existe_no_se_convierte() {
        // Un registro puede traer cualquier cosa en estos campos.
        assert!(instante_utc(2023, 2, 30, 0, 0, 0, 0).is_none());
        assert!(instante_utc(2023, 13, 1, 0, 0, 0, 0).is_none());
        assert!(instante_utc(2023, 1, 0, 0, 0, 0, 0).is_none());
        assert!(instante_utc(2023, 1, 1, 24, 0, 0, 0).is_none());
        assert!(instante_utc(2023, 2, 29, 0, 0, 0, 0).is_none());
        assert!(instante_utc(2024, 2, 29, 0, 0, 0, 0).is_some());
    }

    #[test]
    fn el_segundo_intersticial_se_acepta_aplastado() {
        // El segundo 60 existe en UTC y el tiempo Unix no lo representa.
        // Rechazar la linea perderia un registro legitimo por un detalle del
        // calendario.
        let a = instante_utc(2016, 12, 31, 23, 59, 60, 0).unwrap();
        let b = instante_utc(2016, 12, 31, 23, 59, 59, 0).unwrap();
        assert_eq!(a, b);
        assert!(instante_utc(2016, 12, 31, 23, 59, 61, 0).is_none());
    }

    // --- RFC 3339, byte a byte ---------------------------------------------

    #[test]
    fn el_ejemplo_del_rfc_5424_se_analiza_exacto() {
        // 2003-10-11T22:14:15.003Z, el ejemplo literal del RFC.
        let t = desde_rfc3339("2003-10-11T22:14:15.003Z").unwrap();
        let esperado = instante_utc(2003, 10, 11, 22, 14, 15, 3_000_000).unwrap();
        assert_eq!(t, esperado);
    }

    #[test]
    fn el_desplazamiento_de_zona_se_resta() {
        // «12:00+02:00» son las 10:00 UTC. Sumarlo en vez de restarlo desplaza
        // el evento cuatro horas en el sentido contrario: el error clasico.
        let con_zona = desde_rfc3339("2023-06-15T12:00:00+02:00").unwrap();
        let en_utc = desde_rfc3339("2023-06-15T10:00:00Z").unwrap();
        assert_eq!(con_zona, en_utc);

        let oeste = desde_rfc3339("2023-06-15T08:00:00-02:00").unwrap();
        assert_eq!(oeste, en_utc);
    }

    #[test]
    fn sin_zona_no_se_supone_utc() {
        // Suponer UTC desplazaria el evento hasta doce horas sin que nadie lo
        // supiera. Mejor sin hora y marcado que con una hora inventada.
        assert!(desde_rfc3339("2023-06-15T12:00:00").is_none());
    }

    #[test]
    fn una_marca_medio_valida_se_rechaza_entera() {
        assert!(desde_rfc3339("2O23-06-15T12:00:00Z").is_none(), "letra O");
        assert!(
            desde_rfc3339("2023-06-15T12:00:00.Z").is_none(),
            "punto solo"
        );
        assert!(desde_rfc3339("2023-06-15T12:00:00Zbasura").is_none());
        assert!(desde_rfc3339("").is_none());
        assert!(desde_rfc3339("2023").is_none());
        assert!(desde_rfc3339("2023-06-15T12:00:00+99:00").is_none());
    }

    #[test]
    fn la_fraccion_larga_no_desborda() {
        // Hay emisores que escriben doce digitos de fraccion.
        let t = desde_rfc3339("2023-06-15T12:00:00.123456789012Z").unwrap();
        let esperado = instante_utc(2023, 6, 15, 12, 0, 0, 123_456_789).unwrap();
        assert_eq!(t, esperado);
    }

    // --- El ano que el registro no dice -------------------------------------

    #[test]
    fn el_31_de_diciembre_leido_el_1_de_enero_es_del_ano_anterior() {
        // EL CASO QUE CASI TODO EL MUNDO HACE MAL. Sin esto, el incidente de
        // nochevieja se fecha con un ano de adelanto, cae en el futuro y
        // cualquier ventana de correlacion lo pierde.
        let uno_de_enero = instante_utc(2024, 1, 1, 3, 0, 0, 0).unwrap();
        assert_eq!(ano_probable(12, 31, uno_de_enero), 2023);
    }

    #[test]
    fn una_fecha_del_mismo_ano_se_queda_en_el_ano_de_lectura() {
        let en_junio = instante_utc(2024, 6, 15, 12, 0, 0, 0).unwrap();
        assert_eq!(ano_probable(6, 15, en_junio), 2024);
        assert_eq!(ano_probable(1, 3, en_junio), 2024, "enero ya paso");
    }

    #[test]
    fn unos_minutos_de_adelanto_no_cambian_el_ano() {
        // Los relojes de las maquinas que emiten syslog viejo no estan
        // sincronizados; adelantar unos minutos es normal y no es diciembre.
        let casi_medianoche = instante_utc(2024, 6, 15, 23, 59, 0, 0).unwrap();
        assert_eq!(ano_probable(6, 16, casi_medianoche), 2024);
    }

    #[test]
    fn el_29_de_febrero_de_un_ano_no_bisiesto_no_rompe_la_deduccion() {
        // instante_utc devuelve None y la funcion tiene que seguir dando un ano.
        let en_2023 = instante_utc(2023, 3, 1, 0, 0, 0, 0).unwrap();
        assert_eq!(ano_probable(2, 29, en_2023), 2023);
    }

    // --- FILETIME ----------------------------------------------------------

    #[test]
    fn el_filetime_de_la_epoca_unix_da_cero() {
        let ft = u64::try_from(DESFASE_FILETIME_S * 10_000_000).unwrap();
        assert_eq!(desde_filetime(ft), Some(0));
    }

    #[test]
    fn un_filetime_anterior_a_1970_no_se_cuela_como_cero() {
        // Colarlo como cero lo pondria en el mismo instante que la epoca Unix,
        // que es una fecha con significado.
        assert!(desde_filetime(0).is_none());
        assert!(desde_filetime(1_000).is_none());
    }

    #[test]
    fn el_filetime_conserva_los_cien_nanosegundos() {
        let ft = u64::try_from(DESFASE_FILETIME_S * 10_000_000 + 1234).unwrap();
        assert_eq!(desde_filetime(ft), Some(123_400));
    }

    // --- Meses -------------------------------------------------------------

    #[test]
    fn los_meses_abreviados_se_leen_sin_importar_la_caja() {
        assert_eq!(mes_abreviado(b"Jan"), Some(1));
        assert_eq!(mes_abreviado(b"DEC"), Some(12));
        assert_eq!(mes_abreviado(b"sep"), Some(9));
        assert_eq!(mes_abreviado(b"xxx"), None);
        assert_eq!(mes_abreviado(b"Ja"), None);
    }
}
