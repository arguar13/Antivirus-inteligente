//! LA MISMA CONSULTA contra el endpoint y contra el historico.
//!
//! Es la promesa que distingue a este almacen: una consulta de AegisQL se
//! escribe una vez y corre contra el vivo y contra el historico. Aqui se
//! comprueba con el ejecutor REAL del endpoint (`aegis-hunt`) sobre una tabla
//! REAL de esta maquina (`users`, de `/etc/passwd`): esas mismas filas se
//! ingieren en el almacen, y cada consulta tiene que devolver lo mismo por los
//! dos caminos —las mismas columnas y las mismas filas—.
//!
//! El endpoint no ordena (el orden lo pone el plano de control al juntar la
//! flota), asi que las filas se comparan como conjunto.

use aegis_almacen::retencion::Retencion;
use aegis_almacen::{Almacen, FilaEntrada};
use aegis_entidad::entidad;
use aegis_estado::{Contexto, Filtro};
use aegis_hunt::ejecutor::Ejecutor;
use aegis_parser::plan::planificar;
use aegis_parser::sintaxis;
use aegis_prueba::{omitir, Requisito};
use sqlx::postgres::PgPoolOptions;

fn url() -> String {
    std::env::var("AEGIS_TEST_PG_URL")
        .unwrap_or_else(|_| "postgres://postgres@%2Fvar%2Frun%2Fpostgresql/aegis_test".to_string())
}

/// Consultas de caza reales sobre `users`, que ejercen cada forma de predicado,
/// las negaciones sobre lo ausente, `*`, `COUNT(*)` y el techo.
const CONSULTAS: &[&str] = &[
    "SELECT username, uid FROM users",
    "SELECT * FROM users",
    "SELECT COUNT(*) FROM users",
    "SELECT username FROM users WHERE uid = 0",
    "SELECT username, shell FROM users WHERE shell LIKE '%sh'",
    "SELECT username FROM users WHERE shell NOT LIKE '%nologin' AND uid >= 1000",
    "SELECT username FROM users WHERE username IN ('root', 'daemon', 'nobody')",
    "SELECT username FROM users WHERE NOT (uid < 1000 OR username = 'nobody')",
    "SELECT username FROM users WHERE can_login",
    "SELECT username FROM users WHERE is_root OR gid = 0",
    "SELECT username, password_state FROM users WHERE password_state != 'bloqueada'",
    "SELECT COUNT(*) FROM users WHERE description NOT IN ('')",
    "SELECT username FROM users WHERE 1000 <= uid",
    "SELECT username FROM users LIMIT 3",
];

#[tokio::test]
async fn cada_consulta_devuelve_lo_mismo_contra_el_endpoint_y_contra_el_historico() {
    let pool = match PgPoolOptions::new()
        .max_connections(2)
        .connect(&url())
        .await
    {
        Ok(p) => p,
        Err(e) => {
            omitir(
                &format!("no hay PostgreSQL en {} ({e})", url()),
                Requisito::Postgresql,
            );
            return;
        }
    };
    let esquema = format!("alm_paridad_{}", std::process::id());
    let _ = sqlx::raw_sql(&format!("DROP SCHEMA IF EXISTS {esquema} CASCADE"))
        .execute(&pool)
        .await;
    let dir = std::env::temp_dir().join(format!("aegis-almacen-{esquema}"));
    let almacen = Almacen::abrir(pool.clone(), &esquema, Retencion::default(), dir.clone())
        .await
        .expect("abrir");

    let ahora = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(0));
    let ctx = Contexto::del_sistema(entidad::maquina("maquina-de-integracion"), 1, ahora);
    let tabla = aegis_estado::tabla_llamada("users").expect("la tabla users existe");
    let filas = tabla
        .leer(&ctx, &Filtro::ninguno())
        .expect("se lee /etc/passwd");
    assert!(filas.filas.len() > 5, "una maquina real tiene cuentas");
    let entrada: Vec<FilaEntrada> = filas
        .filas
        .iter()
        .map(|f| FilaEntrada {
            ts_ns: ahora,
            entidad: f.entidad().cloned(),
            valores: f.valores().to_vec(),
        })
        .collect();
    almacen
        .ingerir("users", entrada)
        .await
        .expect("ingerir las filas reales");

    let ejecutor = Ejecutor::nuevo().con_estado(&ctx);
    for q in CONSULTAS {
        let plan =
            planificar(sintaxis::analizar(q).unwrap_or_else(|e| panic!("{q}: {}", e.dibujar(q))));
        let vivo = ejecutor.ejecutar(&plan);
        assert!(
            vivo.motivo.is_none(),
            "{q}: el endpoint no pudo leer: {:?}",
            vivo.motivo
        );
        let hist = almacen
            .consultar(q, ahora)
            .await
            .unwrap_or_else(|e| panic!("{q}: el historico fallo: {e}"));
        assert_eq!(hist.columnas, vivo.columnas, "{q}: columnas");
        let mut a: Vec<Vec<String>> = vivo.filas.clone();
        let mut b: Vec<Vec<String>> = hist
            .filas
            .iter()
            .map(|f| f.iter().map(aegis_parser::valor::Valor::a_texto).collect())
            .collect();
        a.sort();
        b.sort();
        if q.contains("LIMIT 3") {
            // Con techo y sin orden, cada lado devuelve TRES filas cualesquiera
            // de las que casan: se compara el numero y que sean de verdad filas
            // de la tabla.
            assert_eq!(a.len(), 3, "{q}");
            assert_eq!(b.len(), 3, "{q}");
            assert!(
                vivo.incompleto && hist.truncada,
                "{q}: los dos dicen que habia mas"
            );
        } else {
            assert_eq!(b, a, "{q}: filas distintas");
        }
        eprintln!(
            "{q}\n    -> {} fila(s) iguales por los dos caminos",
            a.len()
        );
    }

    let _ = sqlx::raw_sql(&format!("DROP SCHEMA IF EXISTS {esquema} CASCADE"))
        .execute(&pool)
        .await;
    let _ = std::fs::remove_dir_all(&dir);
}
