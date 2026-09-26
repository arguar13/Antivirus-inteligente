//! AegisStore contra PostgreSQL de verdad.
//!
//! El muro que la FASE 75 declaro —«no se escribe en PostgreSQL»— se derriba
//! aqui: particiones declarativas reales, `DROP` real, indices reales. Cada
//! prueba trabaja en su propio esquema y lo borra al terminar.
//!
//! Sin PostgreSQL, cada prueba se salta y LO DICE (`OMITIDA: ...`).

use aegis_almacen::retencion::Retencion;
use aegis_almacen::{Almacen, ErrorAlmacen, FilaEntrada, Via};
use aegis_entidad::entidad;
use aegis_parser::historico::Ventana;
use aegis_parser::valor::Valor;
use sqlx::postgres::PgPoolOptions;

const NS_DIA: u64 = 86_400_000_000_000;
/// 2026-09-01T00:00:00Z.
const DIA0: u64 = 1_788_220_800_000_000_000;

fn url() -> String {
    std::env::var("AEGIS_TEST_PG_URL")
        .unwrap_or_else(|_| "postgres://postgres@%2Fvar%2Frun%2Fpostgresql/aegis_test".to_string())
}

struct Prueba {
    almacen: Almacen,
    esquema: String,
    dir: std::path::PathBuf,
}

impl Prueba {
    async fn cerrar(self) {
        let _ = sqlx::raw_sql(&format!("DROP SCHEMA IF EXISTS {} CASCADE", self.esquema))
            .execute(self.almacen.pool())
            .await;
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn prueba(nombre: &str, retencion: Retencion) -> Option<Prueba> {
    let pool = match PgPoolOptions::new()
        .max_connections(4)
        .connect(&url())
        .await
    {
        Ok(p) => p,
        Err(e) => {
            eprintln!("OMITIDA: no hay PostgreSQL en {} ({e})", url());
            return None;
        }
    };
    let esquema = format!("alm_{nombre}_{}", std::process::id());
    let _ = sqlx::raw_sql(&format!("DROP SCHEMA IF EXISTS {esquema} CASCADE"))
        .execute(&pool)
        .await;
    let dir = std::env::temp_dir().join(format!("aegis-almacen-{esquema}"));
    let almacen = Almacen::abrir(pool, &esquema, retencion, dir.clone())
        .await
        .expect("abrir");
    Some(Prueba {
        almacen,
        esquema,
        dir,
    })
}

fn maquina() -> aegis_entidad::Eid {
    entidad::maquina("equipo-de-prueba")
}

/// Una fila de `processes` con las columnas que guarda el almacen.
fn proceso(ts: u64, pid: i64, nombre: &str, uid: i64) -> FilaEntrada {
    let e = entidad::proceso(&maquina(), 1, u32::try_from(pid).unwrap(), ts);
    let t = aegis_parser::esquema::historico::tabla("processes").unwrap();
    let valores = aegis_almacen::columnas_guardadas(t)
        .iter()
        .map(|c| match c.nombre {
            "pid" => Valor::Entero(pid),
            "ppid" => Valor::Entero(1),
            "start_ns" => Valor::Entero(i64::try_from(ts).unwrap()),
            "name" => Valor::Texto(nombre.into()),
            "path" => Valor::Texto(format!("/usr/bin/{nombre}")),
            "uid" | "gid" => Valor::Entero(uid),
            // Lo que no se pudo leer en el endpoint llega ausente, y ausente
            // tiene que seguir en el almacen.
            "sha256" if pid % 7 == 0 => Valor::Ausente,
            _ => match c.tipo {
                aegis_parser::esquema::Tipo::Entero => Valor::Entero(0),
                aegis_parser::esquema::Tipo::Real => Valor::Real(0.0),
                aegis_parser::esquema::Tipo::Booleano => Valor::Booleano(false),
                aegis_parser::esquema::Tipo::Texto => Valor::Texto(String::new()),
            },
        })
        .collect();
    FilaEntrada {
        ts_ns: ts,
        entidad: Some(e),
        valores,
    }
}

async fn cargar_diez_dias(a: &Almacen) {
    let mut filas = Vec::new();
    for d in 0..10u64 {
        for i in 0..300i64 {
            let ts = DIA0 + d * NS_DIA + u64::try_from(i).unwrap() * 1_000_000_000;
            let nombre = ["bash", "sshd", "nginx"][usize::try_from(i % 3).unwrap()];
            filas.push(proceso(
                ts,
                i + 100 * i64::try_from(d).unwrap(),
                nombre,
                i % 2,
            ));
        }
    }
    let inf = a.ingerir("processes", filas).await.expect("ingerir");
    assert_eq!(inf.filas, 3000);
    assert_eq!(inf.dias, 10);
    assert!(inf.bytes_comprimidos < inf.bytes_crudos, "{inf:?}");
}

#[tokio::test]
async fn una_consulta_cara_sin_filtro_se_rechaza_con_un_mensaje_util() {
    let Some(p) = prueba("rechazo", Retencion::default()).await else {
        return;
    };
    cargar_diez_dias(&p.almacen).await;
    let ahora = DIA0 + 10 * NS_DIA;
    let e = p
        .almacen
        .consultar("SELECT pid, name FROM processes WHERE uid = 0", ahora)
        .await
        .expect_err("sin acotar, diez dias, se rechaza");
    let ErrorAlmacen::Rechazada(r) = &e else {
        panic!("{e}")
    };
    eprintln!("{e}");
    assert!(r.motivo.contains("10 dias"), "{}", r.motivo);
    assert!(
        r.sugerencia.contains("DURING LAST 7 DAYS"),
        "{}",
        r.sugerencia
    );
    assert_eq!(r.coste.particiones, 10);
    assert_eq!(
        r.coste.segmentos, 0,
        "se rechazo ANTES de preguntar por segmentos"
    );

    // La misma consulta, acotada como sugiere el error, se ejecuta.
    let ok = p
        .almacen
        .consultar(
            "SELECT pid, name FROM processes WHERE uid = 0 DURING LAST 7 DAYS LIMIT 10000",
            ahora,
        )
        .await
        .expect("acotada, cabe");
    assert_eq!(ok.coste.particiones, 7);
    assert_eq!(ok.filas.len(), 7 * 150);
    assert!(ok.filas.iter().all(|f| f.len() == 2));
    p.cerrar().await;
}

#[tokio::test]
async fn solo_se_leen_las_columnas_que_la_consulta_usa() {
    let Some(p) = prueba("columnas", Retencion::default()).await else {
        return;
    };
    cargar_diez_dias(&p.almacen).await;
    let ahora = DIA0 + 10 * NS_DIA;
    let q = "SELECT name FROM processes WHERE uid = 1 DURING LAST 1 DAYS";
    let coste = p.almacen.explicar(q, ahora).await.unwrap();
    assert_eq!(coste.columnas, ["ts", "entity", "name", "uid"]);
    let r = p.almacen.consultar(q, ahora).await.unwrap();
    assert_eq!(r.columnas, ["name"]);
    // Ausente sobrevive: el sha256 de los pid multiplos de 7 no se pudo leer.
    let r = p
        .almacen
        .consultar(
            "SELECT pid, sha256 FROM processes WHERE pid = 7 DURING LAST 30 DAYS",
            ahora,
        )
        .await
        .unwrap();
    assert_eq!(r.filas, vec![vec![Valor::Entero(7), Valor::Ausente]]);
    // Y NOT LIKE sobre un ausente es cierto, como en el endpoint.
    let r = p
        .almacen
        .consultar("SELECT COUNT(*) FROM processes WHERE pid = 7 AND sha256 NOT LIKE 'a%' DURING LAST 30 DAYS", ahora)
        .await
        .unwrap();
    assert_eq!(r.filas, vec![vec![Valor::Entero(1)]]);
    p.cerrar().await;
}

#[tokio::test]
async fn una_consulta_por_entidad_devuelve_todo_lo_suyo_cruzando_subsistemas() {
    let Some(p) = prueba("entidad", Retencion::default()).await else {
        return;
    };
    let a = &p.almacen;
    cargar_diez_dias(a).await;
    let ts = DIA0 + 3 * NS_DIA + 5_000_000_000;
    // El proceso con pid 305 del dia 3 (i = 5, se llama nginx), ya ingerido.
    let f = proceso(ts, 305, "nginx", 1);
    let eid = f.entidad.clone().unwrap();
    // Su veredicto y su caso, en sus tablas.
    a.ingerir(
        "verdicts",
        vec![FilaEntrada {
            ts_ns: ts + 1,
            entidad: Some(eid.clone()),
            valores: vec![
                Valor::Texto("malicioso".into()),
                Valor::Entero(85),
                Valor::Entero(2),
                Valor::Entero(3),
                Valor::Texto("inyecta en sshd y abre un puerto".into()),
            ],
        }],
    )
    .await
    .unwrap();
    a.ingerir(
        "cases",
        vec![FilaEntrada {
            ts_ns: ts + 2,
            entidad: Some(eid.clone()),
            valores: vec![
                Valor::Texto("CASO-42".into()),
                Valor::Texto("abierto".into()),
                Valor::Texto("sshd comprometido".into()),
                Valor::Texto("alta".into()),
            ],
        }],
    )
    .await
    .unwrap();
    let todo = a
        .todo_de(
            &eid,
            Ventana::Ultimos { ns: 30 * NS_DIA },
            DIA0 + 10 * NS_DIA,
        )
        .await
        .unwrap();
    let tablas: Vec<&str> = todo.iter().map(|(t, _)| t.as_str()).collect();
    assert_eq!(tablas, ["cases", "processes", "verdicts"]);
    for (t, r) in &todo {
        assert_eq!(r.filas.len(), 1, "{t}: {r:?}");
        assert!(
            matches!(r.coste.via, Via::Entidad(1)),
            "{t} usa el indice primario"
        );
        assert!(
            r.coste.segmentos <= 1,
            "{t}: {} segmentos",
            r.coste.segmentos
        );
    }
    // Y por el lenguaje, uniendo por entidad con una subconsulta acotada.
    let r = a
        .consultar(
            "SELECT pid, name FROM processes \
             WHERE entity IN (SELECT entity FROM verdicts WHERE result = 'malicioso' LIMIT 100) \
             DURING LAST 30 DAYS",
            DIA0 + 10 * NS_DIA,
        )
        .await
        .unwrap();
    assert_eq!(
        r.filas,
        vec![vec![Valor::Entero(305), Valor::Texto("nginx".into())]]
    );
    assert!(matches!(r.coste.via, Via::Entidad(1)));
    p.cerrar().await;
}

#[tokio::test]
async fn un_indice_secundario_solo_existe_si_se_declara() {
    let Some(p) = prueba("secundario", Retencion::default()).await else {
        return;
    };
    let a = &p.almacen;
    let ahora = DIA0 + 10 * NS_DIA;
    let q = "SELECT pid FROM processes WHERE name = 'nginx' DURING LAST 30 DAYS LIMIT 10000";
    cargar_diez_dias(a).await;
    assert_eq!(a.explicar(q, ahora).await.unwrap().via, Via::Barrido);
    // Declarado, vale para lo que se ingiera desde ahora.
    a.declarar_indice("processes", "name").await.unwrap();
    let mut filas = Vec::new();
    for i in 0..20_000i64 {
        let ts = DIA0 + 9 * NS_DIA + u64::try_from(i).unwrap() * 1_000_000;
        filas.push(proceso(
            ts,
            50_000 + i,
            if i == 12_345 { "raro" } else { "bash" },
            0,
        ));
    }
    a.ingerir("processes", filas).await.unwrap();
    let c = a
        .explicar(
            "SELECT pid FROM processes WHERE name = 'raro' DURING LAST 1 DAYS",
            ahora,
        )
        .await
        .unwrap();
    assert_eq!(
        c.via,
        Via::Secundario {
            columna: "name".into()
        }
    );
    assert_eq!(
        c.segmentos, 1,
        "de los tres segmentos del dia, solo uno tiene 'raro'"
    );
    let r = a
        .consultar(
            "SELECT pid FROM processes WHERE name = 'raro' DURING LAST 1 DAYS",
            ahora,
        )
        .await
        .unwrap();
    assert_eq!(r.filas, vec![vec![Valor::Entero(62_345)]]);
    p.cerrar().await;
}

#[tokio::test]
async fn agregacion_con_cubos_de_tiempo_y_top_por_cuenta() {
    let Some(p) = prueba("agregacion", Retencion::default()).await else {
        return;
    };
    let a = &p.almacen;
    cargar_diez_dias(a).await;
    let ahora = DIA0 + 10 * NS_DIA;
    let r = a
        .consultar(
            "SELECT name, COUNT(*), MAX(pid) FROM processes DURING LAST 2 DAYS GROUP BY name",
            ahora,
        )
        .await
        .unwrap();
    assert_eq!(r.columnas, ["name", "count", "max(pid)"]);
    assert_eq!(r.filas.len(), 3);
    assert!(
        r.filas.iter().all(|f| f[1] == Valor::Entero(200)),
        "{:?}",
        r.filas
    );
    let r = a
        .consultar(
            "SELECT bucket, COUNT(*) FROM processes DURING LAST 3 DAYS GROUP BY EVERY 1 DAYS",
            ahora,
        )
        .await
        .unwrap();
    assert_eq!(r.filas.len(), 3);
    assert_eq!(
        r.filas[0][0],
        Valor::Entero(i64::try_from(DIA0 + 7 * NS_DIA).unwrap())
    );
    assert!(r.filas.iter().all(|f| f[1] == Valor::Entero(300)));
    p.cerrar().await;
}

#[tokio::test]
async fn la_retencion_baja_de_nivel_lee_de_fichero_y_purga_con_drop() {
    let r = Retencion {
        caliente_dias: 2,
        tibio_dias: 4,
        frio_dias: 8,
    };
    let Some(p) = prueba("retencion", r).await else {
        return;
    };
    let a = &p.almacen;
    a.declarar_indice("processes", "name").await.unwrap();
    cargar_diez_dias(a).await;
    let ahora = DIA0 + 10 * NS_DIA;
    let q = "SELECT COUNT(*) FROM processes WHERE name = 'sshd' DURING LAST 30 DAYS";
    let antes = a.consultar(q, ahora).await.unwrap();
    assert_eq!(antes.filas, vec![vec![Valor::Entero(1000)]]);
    let bytes_antes: i64 = a
        .coste_por_nivel()
        .await
        .unwrap()
        .iter()
        .map(|c| c.bytes_base)
        .sum();

    let inf = a.aplicar_retencion(ahora).await.unwrap();
    eprintln!("{inf:?}");
    assert_eq!(inf.purgados.len(), 3, "los dias de 8, 9 y 10 de antiguedad");
    assert_eq!(inf.a_frio.len(), 4);
    assert_eq!(inf.a_tibio.len(), 2);
    let niveles = a.coste_por_nivel().await.unwrap();
    eprintln!("{niveles:?}");
    assert_eq!(
        niveles.iter().map(|c| c.dias).collect::<Vec<_>>(),
        [1, 2, 4]
    );
    assert!(niveles[2].bytes_fichero > 0);
    let bytes_despues: i64 = niveles.iter().map(|c| c.bytes_base).sum();
    assert!(
        bytes_despues < bytes_antes,
        "{bytes_despues} < {bytes_antes}"
    );

    // Purgar es soltar la particion: ya no existe la tabla.
    let dia_purgado = inf.purgados[0];
    let existe: Option<String> = sqlx::query_scalar(&format!(
        "SELECT to_regclass('{}.columnas_d{dia_purgado}')::text",
        p.esquema
    ))
    .fetch_one(a.pool())
    .await
    .unwrap();
    assert_eq!(existe, None);

    // Lo que queda responde igual, lea de PostgreSQL o del fichero frio: 7 dias.
    let despues = a.consultar(q, ahora).await.unwrap();
    assert_eq!(despues.filas, vec![vec![Valor::Entero(700)]]);
    assert_eq!(despues.coste.por_nivel, [1, 2, 4]);

    // Una fila tardia de un dia frio se rechaza con su motivo.
    let tarde = proceso(DIA0 + 3 * NS_DIA + 1, 99_999, "bash", 0);
    let e = a
        .ingerir("processes", vec![tarde])
        .await
        .expect_err("dia frio");
    assert!(e.to_string().contains("nivel frio"), "{e}");
    p.cerrar().await;
}

#[tokio::test]
async fn una_fila_que_no_cuadra_con_su_esquema_se_rechaza_entera() {
    let Some(p) = prueba("esquema", Retencion::default()).await else {
        return;
    };
    let mut f = proceso(DIA0, 1, "bash", 0);
    f.valores[0] = Valor::Texto("no soy un pid".into());
    let e = p
        .almacen
        .ingerir("processes", vec![f])
        .await
        .expect_err("tipo");
    assert!(e.to_string().contains("pid"), "{e}");
    let mut f = proceso(DIA0, 1, "bash", 0);
    f.valores.pop();
    assert!(p.almacen.ingerir("processes", vec![f]).await.is_err());
    p.cerrar().await;
}
