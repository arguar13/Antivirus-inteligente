//! El particionado de `alertas` y `eventos_normalizados` es REAL (H-19).
//!
//! La migracion 0007 declaro `eventos_normalizados` como particionada y dijo que
//! el arranque del servidor creaba sus particiones. Nadie las creaba: era un
//! padre sin hijas en el que cualquier INSERT habria fallado. Y la tabla que
//! crece de verdad, `alertas`, no estaba particionada.
//!
//! Estas pruebas hablan con un PostgreSQL REAL y fallan si:
//!  - alguna de las dos deja de ser `PARTITION BY RANGE` por su columna de
//!    tiempo, o gana una particion DEFAULT;
//!  - una fila de AHORA —o de cualquiera de los meses de adelanto— no cae en la
//!    hija de su mes (sin hija, PostgreSQL la rechaza; con una DEFAULT caeria
//!    alli, y tambien falla);
//!  - la purga por retencion no suelta la hija entera, toca el mes en curso o no
//!    deja constancia en `particiones`.
//!
//! Todo lo que escribe va en una transaccion que se deshace: la base de pruebas
//! es compartida, y la purga de verdad no se ejecuta nunca sobre ella.
//!
//! Se omite (y se cuenta, via `aegis_prueba`) solo si no hay PostgreSQL. Si hay
//! base y la migracion falla, FALLA: una 0011 rota es justo lo que esto vigila.

mod comun;
use aegis_server::particiones::{
    self, Politica, ADELANTO_MESES, RETENCION_RECOMENDADA_MESES, TABLAS,
};
use comun::almacen_real;
use sqlx::{PgPool, Postgres, Transaction};

/// Las pruebas de este fichero van una detras de otra: la de la purga toma un
/// cerrojo exclusivo sobre `alertas` hasta deshacer su transaccion, y las demas
/// escriben en ella.
static EN_SERIE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Una transaccion con la sesion en UTC, para que los meses que calcula la
/// prueba y los que usan las funciones de la 0011 sean el mismo calendario.
async fn transaccion(pool: &PgPool) -> Transaction<'static, Postgres> {
    let mut tx = pool.begin().await.expect("abrir transaccion");
    sqlx::query("SET LOCAL TIME ZONE 'UTC'")
        .execute(&mut *tx)
        .await
        .expect("zona horaria UTC");
    tx
}

/// Nombre de la hija del mes de `now() + meses` (negativo: hacia atras).
async fn hija_esperada(tx: &mut Transaction<'static, Postgres>, tabla: &str, meses: i32) -> String {
    sqlx::query_scalar(
        "SELECT $1 || '_' || to_char(now() + make_interval(months => $2), 'YYYY_MM')",
    )
    .bind(tabla)
    .bind(meses)
    .fetch_one(&mut **tx)
    .await
    .expect("nombre de la hija esperada")
}

/// Un agente para la clave ajena de `alertas`, dentro de la transaccion.
async fn agente(tx: &mut Transaction<'static, Postgres>) -> String {
    let cn = format!("particionado-{}", uuid::Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO agentes (cn, id_agente, hostname, version_agente) \
         VALUES ($1, 'particionado', 'particionado', '0')",
    )
    .bind(&cn)
    .execute(&mut **tx)
    .await
    .expect("agente de prueba");
    cn
}

/// Inserta una fila con la hora `now() + meses` en la tabla y devuelve la
/// relacion en la que cayo de verdad (`tableoid`), o el error de PostgreSQL.
async fn insertar(
    tx: &mut Transaction<'static, Postgres>,
    tabla: &str,
    meses: i32,
) -> Result<String, sqlx::Error> {
    match tabla {
        "alertas" => {
            let cn = agente(tx).await;
            sqlx::query_scalar(
                "INSERT INTO alertas \
                   (id, cn_agente, severidad, categoria, descripcion, ocurrido_en, recibido_en) \
                 VALUES ($1, $2, 1, 'particionado', 'prueba de particion', now(), \
                         now() + make_interval(months => $3)) \
                 RETURNING tableoid::regclass::text",
            )
            .bind(uuid::Uuid::new_v4())
            .bind(&cn)
            .bind(meses)
            .fetch_one(&mut **tx)
            .await
        }
        "eventos_normalizados" => {
            sqlx::query_scalar(
                "INSERT INTO eventos_normalizados \
                   (id, ancla, esquema, inquilino, anfitrion, productor, ocurrio_en, \
                    observado_en, reloj, clase, resultado, severidad, origen, mensaje) \
                 VALUES ($1, 'prueba', 1, 'prueba', 'prueba', 'prueba', \
                         now() + make_interval(months => $2), now(), 'de-llegada', \
                         'prueba', 'prueba', 'baja', 'prueba', 'prueba de particion') \
                 RETURNING tableoid::regclass::text",
            )
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(meses)
            .fetch_one(&mut **tx)
            .await
        }
        otra => panic!("tabla sin insercion de prueba: {otra}"),
    }
}

#[tokio::test]
async fn las_tablas_que_crecen_estan_particionadas_por_tiempo_y_sin_default() {
    let _serie = EN_SERIE.lock().await;
    let Some(a) = almacen_real(4).await else {
        return;
    };
    let pool = a.pool();

    for t in TABLAS {
        let fila: Option<(String, Option<String>)> = sqlx::query_as(
            "SELECT c.relkind::text, pg_get_partkeydef(c.oid) \
               FROM pg_class c WHERE c.oid = to_regclass($1)",
        )
        .bind(t.nombre)
        .fetch_optional(pool)
        .await
        .expect("catalogo");
        let (relkind, clave) = fila.unwrap_or_else(|| panic!("{} no existe", t.nombre));
        assert_eq!(
            relkind, "p",
            "{} ya no es una tabla particionada (relkind {relkind}): la purga volveria a \
             ser un DELETE masivo",
            t.nombre
        );
        assert_eq!(
            clave.as_deref(),
            Some(format!("RANGE ({})", t.columna).as_str()),
            "{} tiene que particionarse por RANGO de {}",
            t.nombre,
            t.columna
        );

        let defecto: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid \
              WHERE i.inhparent = to_regclass($1) \
                AND pg_get_expr(c.relpartbound, c.oid) = 'DEFAULT'",
        )
        .bind(t.nombre)
        .fetch_one(pool)
        .await
        .expect("particion DEFAULT");
        assert_eq!(
            defecto, 0,
            "{} tiene una particion DEFAULT: se tragaria las filas sin hija y despues \
             impediria crear la hija de ese mes",
            t.nombre
        );
    }
}

#[tokio::test]
async fn hay_hija_para_ahora_y_para_cada_mes_de_adelanto() {
    let _serie = EN_SERIE.lock().await;
    let Some(a) = almacen_real(4).await else {
        return;
    };
    let pool = a.pool();

    // Lo mismo que hace el servidor al arrancar, sin purga: sobre la base de
    // pruebas no se tira nada de verdad.
    let politica = Politica {
        adelanto_meses: ADELANTO_MESES,
        retencion_meses: None,
    };
    particiones::mantener(&a, politica)
        .await
        .expect("el mantenimiento de particiones tiene que poder correr");
    let otra = particiones::mantener(&a, politica)
        .await
        .expect("segunda vuelta");
    assert_eq!(
        otra.creadas, 0,
        "una segunda vuelta seguida no tiene nada que crear"
    );
    assert_eq!(otra.purgadas, 0, "sin retencion no se purga nada");

    for t in TABLAS {
        for meses in 0..=ADELANTO_MESES {
            let mut tx = transaccion(pool).await;
            let esperada = hija_esperada(&mut tx, t.nombre, meses).await;
            let cayo = insertar(&mut tx, t.nombre, meses)
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "una fila de {} con hora now()+{meses} meses no entra: {e}. Sin la hija \
                     {esperada}, la ingesta de ese mes se rechaza",
                        t.nombre
                    )
                });
            assert_eq!(
                cayo, esperada,
                "la fila de {} tenia que caer en la hija de su mes",
                t.nombre
            );
            tx.rollback().await.expect("deshacer");
        }
    }
}

#[tokio::test]
async fn la_retencion_suelta_la_hija_entera_y_no_toca_el_mes_en_curso() {
    let _serie = EN_SERIE.lock().await;
    let Some(a) = almacen_real(4).await else {
        return;
    };
    let pool = a.pool();

    // Una retencion de cero meses soltaria el mes en curso: se rechaza.
    let cero = sqlx::query_scalar::<_, i32>("SELECT aegis_particiones_purgar('alertas', 0)")
        .fetch_one(pool)
        .await;
    assert!(
        cero.is_err(),
        "una retencion de 0 meses tiene que rechazarse"
    );

    particiones::mantener(
        &a,
        Politica {
            adelanto_meses: ADELANTO_MESES,
            retencion_meses: None,
        },
    )
    .await
    .expect("mantenimiento");

    let mut tx = transaccion(pool).await;
    let atras = -(RETENCION_RECOMENDADA_MESES + 2);
    let vieja = hija_esperada(&mut tx, "alertas", atras).await;
    let actual = hija_esperada(&mut tx, "alertas", 0).await;

    // Un mes fuera de la retencion, con una alerta dentro.
    sqlx::query_scalar::<_, bool>(
        "SELECT aegis_particion_crear('alertas', (now() + make_interval(months => $1))::date)",
    )
    .bind(atras)
    .fetch_one(&mut *tx)
    .await
    .expect("crear la hija de un mes viejo");
    let cayo = insertar(&mut tx, "alertas", atras)
        .await
        .expect("alerta vieja");
    assert_eq!(cayo, vieja, "la alerta vieja tenia que caer en su mes");

    let soltadas: i32 =
        sqlx::query_scalar("SELECT aegis_particiones_purgar('alertas', $1, 'prueba H-19')")
            .bind(RETENCION_RECOMENDADA_MESES)
            .fetch_one(&mut *tx)
            .await
            .expect("purgar");
    assert!(
        soltadas >= 1,
        "la purga no solto ninguna hija (esperaba al menos {vieja})"
    );

    let queda_vieja: Option<String> = sqlx::query_scalar("SELECT to_regclass($1)::text")
        .bind(&vieja)
        .fetch_one(&mut *tx)
        .await
        .expect("to_regclass");
    assert_eq!(
        queda_vieja, None,
        "{vieja} tenia que desaparecer con DROP, no vaciarse"
    );

    let queda_actual: Option<String> = sqlx::query_scalar("SELECT to_regclass($1)::text")
        .bind(&actual)
        .fetch_one(&mut *tx)
        .await
        .expect("to_regclass");
    assert_eq!(
        queda_actual.as_deref(),
        Some(actual.as_str()),
        "la purga no puede tocar la hija del mes en curso"
    );

    let constancia: (bool, Option<String>) = sqlx::query_as(
        "SELECT purgada_en IS NOT NULL, motivo_purga FROM particiones \
          WHERE tabla = 'alertas' \
            AND mes = date_trunc('month', now() + make_interval(months => $1))::date",
    )
    .bind(atras)
    .fetch_one(&mut *tx)
    .await
    .expect("la purga tiene que dejar constancia en `particiones`");
    assert!(constancia.0, "el registro no marca {vieja} como purgada");
    assert_eq!(constancia.1.as_deref(), Some("prueba H-19"));

    // Nada de esto se queda: la base de pruebas es compartida.
    tx.rollback().await.expect("deshacer");
}
