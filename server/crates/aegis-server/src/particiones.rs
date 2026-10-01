//! Mantenimiento de las particiones mensuales del plano de control (H-19).
//!
//! # Que se mantiene
//!
//! `alertas` (por `recibido_en`) y `eventos_normalizados` (por `ocurrio_en`)
//! son tablas `PARTITION BY RANGE` con una hija por mes UTC (migracion 0011).
//! Una fila cuyo mes no tiene hija **no se puede insertar**: PostgreSQL la
//! rechaza. Por eso las hijas se crean con [`ADELANTO_MESES`] de adelanto, al
//! arrancar el servidor ([`mantener`], antes de aceptar conexiones) y despues
//! cada [`INTERVALO`] ([`correr`]).
//!
//! # Donde vive la logica
//!
//! En la base, en las funciones de la migracion 0011
//! (`aegis_particion_crear`, `aegis_particiones_asegurar`,
//! `aegis_particiones_purgar`). Aqui solo se llaman. Con varios nodos del plano
//! de control, cada uno llama a las mismas funciones y la base las serializa
//! con un cerrojo consultivo: no hay dos planes calculados en dos memorias.
//!
//! # La purga
//!
//! SOLO si el operador fija una retencion con `AEGIS_RETENCION_MESES` (meses;
//! `0` o sin fijar: no se purga nunca), con `DROP TABLE` de la hija entera.
//! Borrar la evidencia de un cliente es irreversible: no puede ocurrir por un
//! valor por defecto, ni en el primer arranque de una instalacion existente.
//! Nunca `DELETE`. Cada hija soltada queda anotada en la tabla `particiones` con
//! la fecha y el motivo.

use std::time::Duration;

use crate::almacen::Almacen;
use crate::error::{ErrorServidor, Resultado};

/// Una tabla particionada por mes y la columna de tiempo que la corta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TablaMensual {
    /// Nombre de la tabla padre.
    pub nombre: &'static str,
    /// Columna `TIMESTAMPTZ` por la que se particiona.
    pub columna: &'static str,
}

/// Las tablas que mantiene este modulo, las mismas que aceptan las funciones de
/// la migracion 0011.
pub const TABLAS: &[TablaMensual] = &[
    TablaMensual {
        nombre: "alertas",
        columna: "recibido_en",
    },
    TablaMensual {
        nombre: "eventos_normalizados",
        columna: "ocurrio_en",
    },
];

/// Meses por adelantado que tienen que existir ademas del mes en curso.
///
/// Tres: un despliegue puede quedarse un trimestre sin mantenimiento antes de
/// que la ingesta se pare por falta de hija. La migracion 0011 usa el mismo.
pub const ADELANTO_MESES: i32 = 3;

/// Retencion RECOMENDADA, que el operador puede fijar: un año completo mas uno
/// de margen. No se aplica sola.
///
/// Las investigaciones miran atras —el tiempo hasta detectar una intrusion se
/// mide en meses— y purgar justo en el limite deja al analista sin el mes que
/// acaba de necesitar.
pub const RETENCION_RECOMENDADA_MESES: i32 = 13;

/// Variable de entorno que fija la retencion en meses (`0`: no purgar nunca).
pub const VAR_RETENCION: &str = "AEGIS_RETENCION_MESES";

/// Cada cuanto se repite el mantenimiento.
///
/// Una hora: sobra con tres meses de adelanto, y es lo bastante frecuente para
/// que un fallo pasajero (un cerrojo que no se consiguio) se recupere solo.
pub const INTERVALO: Duration = Duration::from_secs(3600);

/// Que hace el mantenimiento.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Politica {
    /// Meses por adelantado que se aseguran, ademas del mes en curso.
    pub adelanto_meses: i32,
    /// Meses de retencion, o `None` para no purgar.
    pub retencion_meses: Option<i32>,
}

impl Politica {
    /// La politica del entorno: [`VAR_RETENCION`] o, si no esta, ninguna purga.
    ///
    /// # Errors
    ///
    /// Si la variable no es un numero de meses. Un valor ilegible NO cae al
    /// defecto: decidir en silencio cuanto tiempo se guarda la evidencia de un
    /// cliente no es algo que se pueda hacer por una errata.
    pub fn desde_entorno() -> Result<Politica, ErrorServidor> {
        Politica::desde_valor(std::env::var(VAR_RETENCION).ok().as_deref())
    }

    /// La politica para un valor dado de [`VAR_RETENCION`] (`None`: no esta).
    ///
    /// # Errors
    ///
    /// Si el valor no es un entero >= 0.
    pub fn desde_valor(valor: Option<&str>) -> Result<Politica, ErrorServidor> {
        let retencion_meses = match valor.map(str::trim) {
            None | Some("") => None,
            Some(v) => match v.parse::<i32>() {
                Ok(0) => None,
                Ok(n) if n > 0 => Some(n),
                _ => {
                    return Err(ErrorServidor::Config(format!(
                        "{VAR_RETENCION} invalida: {v:?} (meses >= 1; 0 = no purgar)"
                    )));
                }
            },
        };
        Ok(Politica {
            adelanto_meses: ADELANTO_MESES,
            retencion_meses,
        })
    }
}

/// Lo que hizo una vuelta de mantenimiento.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Informe {
    /// Hijas creadas.
    pub creadas: i64,
    /// Hijas soltadas por retencion.
    pub purgadas: i64,
}

/// Una vuelta de mantenimiento: asegura las hijas de cada tabla y, si hay
/// retencion, suelta las que la exceden.
///
/// Primero crea y despues purga: la purga nunca toca el mes en curso (la
/// retencion minima es un mes), asi que el orden no puede dejar a la ingesta sin
/// hija.
///
/// # Errors
///
/// Si la base falla o una funcion de la 0011 se niega (por ejemplo, porque no
/// consiguio el cerrojo del padre en su `lock_timeout`).
pub async fn mantener(almacen: &Almacen, politica: Politica) -> Resultado<Informe> {
    let mut informe = Informe::default();
    for tabla in TABLAS {
        let creadas: i32 = sqlx::query_scalar("SELECT aegis_particiones_asegurar($1, $2)")
            .bind(tabla.nombre)
            .bind(politica.adelanto_meses)
            .fetch_one(almacen.pool())
            .await?;
        informe.creadas += i64::from(creadas);

        if let Some(meses) = politica.retencion_meses {
            let purgadas: i32 =
                sqlx::query_scalar("SELECT aegis_particiones_purgar($1, $2, 'retencion')")
                    .bind(tabla.nombre)
                    .bind(meses)
                    .fetch_one(almacen.pool())
                    .await?;
            informe.purgadas += i64::from(purgadas);
        }
    }
    Ok(informe)
}

/// El mantenimiento periodico, para `tokio::spawn`. No termina nunca.
///
/// El arranque ya hizo una vuelta con [`mantener`] (y no arranca si falla); esto
/// repite cada [`INTERVALO`]. Un fallo aqui se registra y se reintenta: el
/// adelanto de [`ADELANTO_MESES`] da margen de sobra antes de que la ingesta lo
/// note.
pub async fn correr(almacen: Almacen, politica: Politica) {
    let mut tic = tokio::time::interval(INTERVALO);
    tic.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // El primer tic es inmediato, y esa vuelta ya la hizo el arranque.
    tic.tick().await;
    loop {
        tic.tick().await;
        match mantener(&almacen, politica).await {
            Ok(i) if i.creadas > 0 || i.purgadas > 0 => tracing::info!(
                creadas = i.creadas,
                purgadas = i.purgadas,
                "particiones mensuales mantenidas"
            ),
            Ok(_) => tracing::debug!("particiones mensuales al dia"),
            Err(e) => tracing::error!(
                error = %e,
                adelanto_meses = politica.adelanto_meses,
                "el mantenimiento de particiones fallo; se reintenta en la siguiente \
                 vuelta, y la ingesta tiene hijas creadas para ese adelanto"
            ),
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn sin_variable_no_se_purga_nada() {
        // Borrar evidencia es irreversible: solo con una retencion explicita.
        let p = Politica::desde_valor(None).unwrap();
        assert_eq!(p.retencion_meses, None);
        assert_eq!(p.adelanto_meses, ADELANTO_MESES);
        assert_eq!(
            Politica::desde_valor(Some("  ")).unwrap().retencion_meses,
            None
        );
        assert_eq!(
            Politica::desde_valor(Some(&RETENCION_RECOMENDADA_MESES.to_string()))
                .unwrap()
                .retencion_meses,
            Some(RETENCION_RECOMENDADA_MESES)
        );
    }

    #[test]
    fn cero_desactiva_la_purga_y_un_numero_la_fija() {
        assert_eq!(
            Politica::desde_valor(Some("0")).unwrap().retencion_meses,
            None
        );
        assert_eq!(
            Politica::desde_valor(Some("24")).unwrap().retencion_meses,
            Some(24)
        );
    }

    #[test]
    fn un_valor_ilegible_es_un_error_y_no_el_defecto() {
        for malo in ["-1", "trece", "13m", "1.5"] {
            assert!(
                Politica::desde_valor(Some(malo)).is_err(),
                "{malo:?} no puede decidir en silencio la retencion"
            );
        }
    }

    #[test]
    fn el_adelanto_de_la_migracion_es_el_mismo() {
        // La 0011 crea el mes en curso y tres de adelanto con
        // `generate_series(0, 3)`. Si esto cambia, cambia tambien alli (en una
        // migracion nueva) o el primer arranque tras migrar crea de mas.
        let migracion = include_str!("../../../migrations/0011_particionado_real.sql");
        assert!(migracion.contains("generate_series(0, 3)"));
        assert_eq!(ADELANTO_MESES, 3);
    }
}
