//! El esquema en PostgreSQL y el ciclo de vida de las particiones.
//!
//! # Cuatro tablas particionadas por dia, y la purga es un `DROP`
//!
//! | Tabla | Una fila por | Para que |
//! |---|---|---|
//! | `segmentos` | segmento (hasta [`crate::SEGMENTO_FILAS`] filas de una tabla) | tiempo minimo y maximo, filas, nivel de retencion |
//! | `columnas` | columna de un segmento | los bytes codificados y comprimidos, y el mapa de zona |
//! | `entidades` | entidad presente en un segmento | el indice primario (entidad, tiempo) |
//! | `secundarios` | valor distinto de una columna DECLARADA en un segmento | los indices secundarios, solo los que alguien pidio |
//!
//! Las cuatro se parten por el MISMO dia, de modo que borrar un dia es soltar
//! cuatro particiones: `DROP TABLE`, sin `DELETE` fila a fila, sin vacio que
//! recuperar y sin bloquear lo demas. Es el unico borrado que escala a la
//! retencion de un SIEM.
//!
//! El dia viaja como entero (dias desde 1970) y PostgreSQL lo convierte con
//! `DATE '1970-01-01' + n`: asi no entra ninguna dependencia de fechas.

use sqlx::{PgPool, Postgres, Transaction};

use crate::ErrorAlmacen;

/// Nanosegundos de un dia.
pub const NS_DIA: u64 = 86_400_000_000_000;

/// El dia (desde 1970) de un instante.
#[must_use]
pub fn dia_de(ts_ns: u64) -> i32 {
    i32::try_from(ts_ns / NS_DIA).unwrap_or(i32::MAX)
}

/// Un nombre de esquema de PostgreSQL valido y sin comillas que escapar.
///
/// Los nombres de esquema no se pueden pasar como parametro de una consulta: van
/// en el texto. Por eso solo se admiten letras minusculas, digitos y `_`, y se
/// comprueba aqui, una vez, antes de que ningun texto de SQL los contenga.
///
/// # Errors
///
/// Si el nombre no es valido.
pub fn validar_esquema(s: &str) -> Result<(), ErrorAlmacen> {
    let ok = !s.is_empty()
        && s.len() <= 48
        && s.starts_with(|c: char| c.is_ascii_lowercase())
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    if ok {
        Ok(())
    } else {
        Err(ErrorAlmacen::Configuracion(format!(
            "nombre de esquema no valido: '{s}'"
        )))
    }
}

/// Crea el esquema base si no existe.
///
/// # Errors
///
/// Si PostgreSQL falla.
pub async fn crear(pool: &PgPool, s: &str) -> Result<(), ErrorAlmacen> {
    validar_esquema(s)?;
    let ddl = format!(
        r"
CREATE SCHEMA IF NOT EXISTS {s};
CREATE SEQUENCE IF NOT EXISTS {s}.segmento_id;
CREATE TABLE IF NOT EXISTS {s}.segmentos (
    dia      DATE     NOT NULL,
    id       BIGINT   NOT NULL,
    tabla    TEXT     NOT NULL,
    ts_min   BIGINT   NOT NULL,
    ts_max   BIGINT   NOT NULL,
    filas    INTEGER  NOT NULL,
    PRIMARY KEY (dia, id)
) PARTITION BY RANGE (dia);
CREATE INDEX IF NOT EXISTS segmentos_tabla ON {s}.segmentos (tabla, dia, ts_min);
CREATE TABLE IF NOT EXISTS {s}.columnas (
    dia       DATE     NOT NULL,
    segmento  BIGINT   NOT NULL,
    columna   TEXT     NOT NULL,
    datos     BYTEA    NOT NULL,
    minimo    BIGINT,
    maximo    BIGINT,
    crudos    INTEGER  NOT NULL,
    PRIMARY KEY (dia, segmento, columna)
) PARTITION BY RANGE (dia);
CREATE TABLE IF NOT EXISTS {s}.entidades (
    dia       DATE     NOT NULL,
    entidad   TEXT     NOT NULL,
    tabla     TEXT     NOT NULL,
    segmento  BIGINT   NOT NULL,
    ts_min    BIGINT   NOT NULL,
    ts_max    BIGINT   NOT NULL
) PARTITION BY RANGE (dia);
CREATE INDEX IF NOT EXISTS entidades_primario ON {s}.entidades (entidad, ts_min);
CREATE TABLE IF NOT EXISTS {s}.secundarios (
    dia       DATE     NOT NULL,
    tabla     TEXT     NOT NULL,
    columna   TEXT     NOT NULL,
    valor     TEXT     NOT NULL,
    segmento  BIGINT   NOT NULL
) PARTITION BY RANGE (dia);
CREATE INDEX IF NOT EXISTS secundarios_valor ON {s}.secundarios (tabla, columna, valor);
CREATE TABLE IF NOT EXISTS {s}.declarados (
    tabla    TEXT NOT NULL,
    columna  TEXT NOT NULL,
    PRIMARY KEY (tabla, columna)
);
CREATE TABLE IF NOT EXISTS {s}.particiones (
    dia       DATE     PRIMARY KEY,
    nivel     SMALLINT NOT NULL DEFAULT 0,
    archivo   TEXT
);
"
    );
    sqlx::raw_sql(&ddl).execute(pool).await?;
    Ok(())
}

/// Las tablas particionadas por dia.
pub const PARTIDAS: [&str; 4] = ["segmentos", "columnas", "entidades", "secundarios"];

/// Nombre de la particion de una tabla para un dia.
#[must_use]
pub fn nombre_particion(tabla: &str, dia: i32) -> String {
    format!("{tabla}_d{dia}")
}

/// Crea las particiones de un dia, si faltan, dentro de la transaccion.
///
/// Un cerrojo consultivo por dia serializa la creacion: dos ingestas del mismo
/// dia a la vez no pueden pelearse por crear la misma particion.
///
/// # Errors
///
/// Si PostgreSQL falla.
pub async fn asegurar_dia(
    tx: &mut Transaction<'_, Postgres>,
    s: &str,
    dia: i32,
) -> Result<(), ErrorAlmacen> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1), $2)")
        .bind(s)
        .bind(dia)
        .execute(&mut **tx)
        .await?;
    let nivel: Option<i16> = sqlx::query_scalar(&format!(
        "SELECT nivel FROM {s}.particiones WHERE dia = DATE '1970-01-01' + $1"
    ))
    .bind(dia)
    .fetch_optional(&mut **tx)
    .await?;
    match nivel {
        // Un dia frio ya tiene sus columnas en un fichero: aceptar filas nuevas
        // lo dejaria con datos en dos sitios.
        Some(n) if n >= 2 => {
            return Err(ErrorAlmacen::Filas {
                tabla: String::new(),
                motivo: format!(
                    "llegan filas del {} y ese dia ya esta en el nivel frio: sus columnas estan en un fichero",
                    crate::plan::fecha(dia)
                ),
            })
        }
        Some(_) => return Ok(()),
        None => {}
    }
    for t in PARTIDAS {
        let p = nombre_particion(t, dia);
        let ddl = format!(
            "CREATE TABLE IF NOT EXISTS {s}.{p} PARTITION OF {s}.{t} \
             FOR VALUES FROM (DATE '1970-01-01' + {dia}) TO (DATE '1970-01-01' + {})",
            dia + 1
        );
        sqlx::raw_sql(&ddl).execute(&mut **tx).await?;
    }
    sqlx::query(&format!(
        "INSERT INTO {s}.particiones (dia) VALUES (DATE '1970-01-01' + $1) ON CONFLICT DO NOTHING"
    ))
    .bind(dia)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Los dias con particion, y su nivel de retencion.
///
/// # Errors
///
/// Si PostgreSQL falla.
pub async fn dias(pool: &PgPool, s: &str) -> Result<Vec<(i32, i16, Option<String>)>, ErrorAlmacen> {
    let v: Vec<(i32, i16, Option<String>)> = sqlx::query_as(&format!(
        "SELECT (dia - DATE '1970-01-01')::int, nivel, archivo FROM {s}.particiones ORDER BY dia"
    ))
    .fetch_all(pool)
    .await?;
    Ok(v)
}

/// Suelta las particiones de un dia: la purga.
///
/// `DROP TABLE` de cada particion, no `DELETE`: es instantaneo, no deja filas
/// muertas que el vacio tenga que recoger, y no bloquea los otros dias.
///
/// # Errors
///
/// Si PostgreSQL falla.
pub async fn soltar_dia(pool: &PgPool, s: &str, dia: i32) -> Result<(), ErrorAlmacen> {
    let mut tx = pool.begin().await?;
    for t in PARTIDAS {
        let p = nombre_particion(t, dia);
        sqlx::raw_sql(&format!("DROP TABLE IF EXISTS {s}.{p}"))
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query(&format!(
        "DELETE FROM {s}.particiones WHERE dia = DATE '1970-01-01' + $1"
    ))
    .bind(dia)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Bytes que ocupa cada particion de un dia en disco (tablas e indices).
///
/// # Errors
///
/// Si PostgreSQL falla.
pub async fn bytes_dia(pool: &PgPool, s: &str, dia: i32) -> Result<i64, ErrorAlmacen> {
    let mut total = 0i64;
    for t in PARTIDAS {
        let p = format!("{s}.{}", nombre_particion(t, dia));
        let b: Option<i64> = sqlx::query_scalar("SELECT pg_total_relation_size(to_regclass($1))")
            .bind(&p)
            .fetch_one(pool)
            .await?;
        total += b.unwrap_or(0);
    }
    Ok(total)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn un_nombre_de_esquema_con_comillas_o_espacios_no_llega_al_sql() {
        assert!(validar_esquema("almacen").is_ok());
        assert!(validar_esquema("prueba_42").is_ok());
        for malo in [
            "",
            "Almacen",
            "a;drop",
            "a b",
            "a\"b",
            "1a",
            &"a".repeat(49),
        ] {
            assert!(validar_esquema(malo).is_err(), "{malo}");
        }
    }

    #[test]
    fn el_dia_de_un_instante() {
        assert_eq!(dia_de(0), 0);
        assert_eq!(dia_de(NS_DIA - 1), 0);
        assert_eq!(dia_de(1_788_220_800_000_000_000), 20_697);
    }
}
