//! AegisReal (FASE 111): la escala, MEDIDA de verdad contra PostgreSQL.
//!
//! El benchmark de `fleet-simulator/src/bin/escala.rs` mide cien mil agentes en
//! memoria, en el mismo proceso, sin tocar la base ni la red. Es honesto sobre su
//! muro. Pero la afirmacion que de verdad importa —«cero perdida silenciosa,
//! demostrada contando en los DOS extremos»— no se puede sostener contando en un
//! solo proceso: la garantiza la base de datos, o no se garantiza.
//!
//! Aqui la ingesta pasa por el MISMO camino de persistencia que en produccion
//! (`Almacen::registrar_alerta` -> `INSERT INTO alertas` + `UPDATE agentes` en una
//! transaccion), contra un PostgreSQL REAL, y se cuenta:
//!  1. lo que el simulador ENVIO (extremo emisor),
//!  2. lo que la base GUARDA (`count(*)` de alertas — extremo receptor),
//!  3. el contador propio del servidor (`sum(eventos)` de agentes).
//!
//! Los tres tienen que cuadrar: perdida == 0, demostrada, no prometida.
//!
//! Ademas se mide la latencia de ingesta (p50/p95/p99) y se comprueban dos cosas
//! mas contra la base real: el aislamiento por inquilino (el conteo de uno no
//! incluye al otro) y que la PURGA de la FASE 75 es metadato, no un barrido de
//! filas —`DETACH`+`DROP` de una particion frente a un `DELETE`—, que es lo que
//! hace que la purga no bloquee la ingesta.
//!
//! Se OMITE con honestidad —sin fingir exito— si la maquina no tiene PostgreSQL.
//! El muro real (cien mil conexiones mTLS vivas, discos de produccion) se declara
//! en `tools/verificar-escala-real.sh`.

mod comun;
use aegis_server::almacen::NuevaAlerta;
use chrono::Utc;
use comun::almacen_real;
use sqlx::Row;

/// Las dos pruebas de este fichero se ejecutan UNA DETRAS DE OTRA. La de la purga
/// mide el WAL que escribe cada operacion, y el WAL es de toda la base: la ingesta
/// de la otra prueba, corriendo a la vez, lo contaminaria.
static EN_SERIE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Posicion actual del WAL.
async fn lsn_actual(pool: &sqlx::PgPool) -> String {
    sqlx::query_scalar::<_, String>("SELECT pg_current_wal_lsn()::text")
        .fetch_one(pool)
        .await
        .expect("pg_current_wal_lsn")
}

/// Bytes de WAL escritos desde `lsn`.
async fn wal_desde(pool: &sqlx::PgPool, lsn: &str) -> f64 {
    sqlx::query_scalar::<_, f64>("SELECT pg_wal_lsn_diff(pg_current_wal_lsn(), $1::pg_lsn)::float8")
        .bind(lsn)
        .fetch_one(pool)
        .await
        .expect("pg_wal_lsn_diff")
}

fn sufijo() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

fn nueva_alerta(descripcion: &str) -> NuevaAlerta<'_> {
    NuevaAlerta {
        severidad: 3,
        categoria: "escala-real",
        descripcion,
        tecnica: Some("T1059"),
        tactica: Some("execution"),
        ocurrido_en: Utc::now(),
        detalles: serde_json::json!({"bench": "escala-real"}),
    }
}

/// El percentil `p` (0..=1) de una lista de duraciones en nanosegundos, por rango
/// mas cercano (determinista, sin interpolar).
fn percentil_ns(muestras: &mut [u128], p: f64) -> u128 {
    if muestras.is_empty() {
        return 0;
    }
    muestras.sort_unstable();
    let n = muestras.len();
    let rango = ((p * n as f64).ceil() as usize).clamp(1, n);
    muestras[rango - 1]
}

#[tokio::test]
async fn cero_perdida_contada_en_los_dos_extremos_contra_postgres_real() {
    let _serie = EN_SERIE.lock().await;
    let Some(a) = almacen_real(16).await else {
        return;
    };
    let run = sufijo();
    // Dos inquilinos (flotas) para comprobar de paso el aislamiento.
    let flota_a = format!("flota-a-{run}");
    let flota_b = format!("flota-b-{run}");

    const AGENTES: usize = 20;
    const EVENTOS_POR_AGENTE: usize = 200;
    let mut cns: Vec<String> = Vec::new();
    let mut enviados_a = 0usize;
    let mut enviados_b = 0usize;
    let mut latencias_ns: Vec<u128> = Vec::with_capacity(AGENTES * EVENTOS_POR_AGENTE);

    for i in 0..AGENTES {
        let cn = format!("cn-{run}-{i}");
        let flota = if i % 2 == 0 { &flota_a } else { &flota_b };
        a.enrolar(
            &cn,
            &format!("id-{i}"),
            &format!("host-{i}"),
            "9.9.9",
            b"huella",
            flota,
        )
        .await
        .expect("enrolar agente");
        for j in 0..EVENTOS_POR_AGENTE {
            let d = format!("evento {j} de {cn}");
            let t = std::time::Instant::now();
            a.registrar_alerta(&cn, &nueva_alerta(&d))
                .await
                .expect("registrar alerta");
            latencias_ns.push(t.elapsed().as_nanos());
            if i % 2 == 0 {
                enviados_a += 1;
            } else {
                enviados_b += 1;
            }
        }
        cns.push(cn);
    }
    let enviados = enviados_a + enviados_b;
    assert_eq!(enviados, AGENTES * EVENTOS_POR_AGENTE);

    // Extremo receptor 1: lo que la base GUARDA en alertas, para MIS agentes.
    let guardadas: i64 = sqlx::query("SELECT count(*) FROM alertas WHERE cn_agente = ANY($1)")
        .bind(&cns)
        .fetch_one(a.pool())
        .await
        .expect("contar alertas")
        .get(0);

    // Extremo receptor 2: el contador propio del servidor (sum de eventos).
    let contados: i64 =
        sqlx::query("SELECT COALESCE(sum(eventos),0)::bigint FROM agentes WHERE cn = ANY($1)")
            .bind(&cns)
            .fetch_one(a.pool())
            .await
            .expect("sumar eventos")
            .get(0);

    // LA PROPIEDAD: perdida CERO, demostrada contando en los dos extremos.
    assert_eq!(
        guardadas, enviados as i64,
        "perdida en alertas: envie {enviados}, hay {guardadas}"
    );
    assert_eq!(
        contados, enviados as i64,
        "el contador del servidor no cuadra"
    );

    // Latencia de ingesta, publicada.
    let p50 = percentil_ns(&mut latencias_ns, 0.50) / 1000;
    let p95 = percentil_ns(&mut latencias_ns, 0.95) / 1000;
    let p99 = percentil_ns(&mut latencias_ns, 0.99) / 1000;
    eprintln!("ingesta real: {enviados} eventos, latencia p50={p50}us p95={p95}us p99={p99}us");

    // Aislamiento por inquilino: el conteo de una flota NO incluye a la otra.
    let en_a: i64 = sqlx::query(
        "SELECT count(*) FROM alertas al JOIN agentes ag ON al.cn_agente = ag.cn WHERE ag.id_flota = $1",
    )
    .bind(&flota_a)
    .fetch_one(a.pool())
    .await
    .expect("contar flota a")
    .get(0);
    assert_eq!(en_a, enviados_a as i64, "el inquilino A ve solo lo suyo");
    assert!(
        enviados_b > 0 && en_a < enviados as i64,
        "y no lo del inquilino B"
    );

    // Limpieza de MIS filas (otras pruebas comparten la base).
    let _ = sqlx::query("DELETE FROM alertas WHERE cn_agente = ANY($1)")
        .bind(&cns)
        .execute(a.pool())
        .await;
    let _ = sqlx::query("DELETE FROM agentes WHERE cn = ANY($1)")
        .bind(&cns)
        .execute(a.pool())
        .await;
}

#[tokio::test]
async fn la_purga_es_metadato_no_un_barrido_de_filas() {
    let _serie = EN_SERIE.lock().await;
    // La purga de la FASE 75 (aegis-scale::particion::sql_soltar) es
    // DETACH PARTITION + DROP, nunca DELETE. La diferencia importa: DROP de una
    // particion es O(1) en metadato y no toca las filas, asi que no compite con la
    // ingesta; un DELETE recorre y bloquea. Se demuestra contra PostgreSQL REAL en
    // un esquema desechable, a escala pequena —la propiedad no depende del tamano—.
    let Some(a) = almacen_real(16).await else {
        return;
    };
    let esquema = format!("purga_{}", sufijo());
    let pool = a.pool();
    sqlx::query(&format!("CREATE SCHEMA {esquema}"))
        .execute(pool)
        .await
        .expect("crear esquema");

    // Tabla particionada por rango, con dos particiones iguales.
    sqlx::query(&format!(
        "CREATE TABLE {esquema}.eventos (dia int NOT NULL, carga text) PARTITION BY RANGE (dia)"
    ))
    .execute(pool)
    .await
    .expect("tabla particionada");
    for (nombre, desde, hasta) in [("p1", 0, 1000), ("p2", 1000, 2000)] {
        sqlx::query(&format!(
            "CREATE TABLE {esquema}.eventos_{nombre} PARTITION OF {esquema}.eventos \
             FOR VALUES FROM ({desde}) TO ({hasta})"
        ))
        .execute(pool)
        .await
        .expect("crear particion");
    }
    // Llenar las dos particiones con las mismas filas.
    for (part_lo, _) in [(0, "p1"), (1000, "p2")] {
        sqlx::query(&format!(
            "INSERT INTO {esquema}.eventos (dia, carga) \
             SELECT {part_lo} + (g % 1000), repeat('x', 64) FROM generate_series(1, 20000) g"
        ))
        .execute(pool)
        .await
        .expect("llenar particion");
    }

    // Lo que se mide es el WAL que escribe cada operacion, no su tiempo de reloj.
    //
    // POR QUE NO EL TIEMPO. Antes se comparaban dos cronometros de una sola
    // operacion sobre veinte mil filas. El DROP hace fsync del catalogo, y con el
    // disco ocupado —un runner de CI, un disco virtual recien compactado— ese fsync
    // costaba mas que borrar veinte mil filas en memoria: la prueba fallaba sin que
    // la propiedad fuera falsa (FASE 0 del MP-15). El WAL, en cambio, es
    // determinista: un DELETE registra CADA fila que borra; un DETACH+DROP solo
    // cambia el catalogo, sea cual sea el tamano de la particion. Eso ES «purga por
    // metadato, no barrido», dicho sin depender de la carga de la maquina.

    // Purga como la FASE 75: DETACH + DROP de p1. Metadato.
    let antes = lsn_actual(pool).await;
    let t_purga = std::time::Instant::now();
    sqlx::query(&format!(
        "ALTER TABLE {esquema}.eventos DETACH PARTITION {esquema}.eventos_p1"
    ))
    .execute(pool)
    .await
    .expect("detach");
    sqlx::query(&format!("DROP TABLE {esquema}.eventos_p1"))
        .execute(pool)
        .await
        .expect("drop");
    let purga_us = t_purga.elapsed().as_micros();
    let wal_purga = wal_desde(pool, &antes).await;

    // Un DELETE equivalente sobre p2: barrido de filas.
    let antes = lsn_actual(pool).await;
    let t_delete = std::time::Instant::now();
    let borradas = sqlx::query(&format!("DELETE FROM {esquema}.eventos_p2"))
        .execute(pool)
        .await
        .expect("delete")
        .rows_affected();
    let delete_us = t_delete.elapsed().as_micros();
    let wal_delete = wal_desde(pool, &antes).await;

    eprintln!(
        "purga FASE 75: DETACH+DROP {wal_purga} B de WAL ({purga_us}us) vs DELETE de \
         {borradas} filas {wal_delete} B de WAL ({delete_us}us)"
    );
    assert_eq!(borradas, 20000, "el DELETE si recorre las filas");
    // Sobre datos iguales, el barrido escribe en el WAL al menos diez veces lo que
    // la purga por metadato (en la practica, cientos de veces).
    assert!(
        wal_delete >= 10.0 * wal_purga,
        "DETACH+DROP escribio {wal_purga} B de WAL y el DELETE {wal_delete} B: la purga \
         deberia ser metadato, no un barrido de filas"
    );

    sqlx::query(&format!("DROP SCHEMA {esquema} CASCADE"))
        .execute(pool)
        .await
        .expect("limpiar esquema");
}
