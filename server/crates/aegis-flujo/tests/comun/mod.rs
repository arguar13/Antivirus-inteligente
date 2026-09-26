//! Lo comun a las pruebas contra PostgreSQL: un esquema propio por prueba con
//! las migraciones REALES del plano de control, una flota y las firmas.

#![allow(dead_code)]

use aegis_entidad::Eid;
use aegis_flujo::firma::{huella, Firma, DOMINIO};
use aegis_flujo::frenos::CincoFrenos;
use aegis_flujo::pg::PuertosPg;
use aegis_pqc::firma_hibrida::ClaveFirmaHibrida;
use aegis_predict::grafo::Evidencia;
use aegis_predict::ConfigContencion;
use sqlx::postgres::PgPoolOptions;
use sqlx::{Executor, PgPool};

pub fn url() -> String {
    std::env::var("AEGIS_TEST_PG_URL")
        .unwrap_or_else(|_| "postgres://postgres@%2Fvar%2Frun%2Fpostgresql/aegis_test".to_string())
}

/// Un esquema de pruebas con el esquema real del plano de control.
pub struct Base {
    pub pool: PgPool,
    pub esquema: String,
}

impl Base {
    pub async fn abrir(nombre: &str) -> Option<Base> {
        let esquema = format!("flujo_{nombre}_{}", std::process::id());
        let admin = match PgPoolOptions::new()
            .max_connections(1)
            .connect(&url())
            .await
        {
            Ok(p) => p,
            Err(e) => {
                eprintln!("OMITIDA: no hay PostgreSQL en {} ({e})", url());
                return None;
            }
        };
        admin
            .execute(
                format!("DROP SCHEMA IF EXISTS {esquema} CASCADE; CREATE SCHEMA {esquema}")
                    .as_str(),
            )
            .await
            .expect("crear el esquema");
        admin.close().await;
        let e = esquema.clone();
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .after_connect(move |c, _| {
                let e = e.clone();
                Box::pin(async move {
                    c.execute(format!("SET search_path TO {e}").as_str())
                        .await?;
                    Ok(())
                })
            })
            .connect(&url())
            .await
            .expect("conectar");
        // Las MISMAS migraciones que aplica aegis-server al arrancar.
        sqlx::migrate!("../../migrations")
            .run(&pool)
            .await
            .expect("migrar");
        Some(Base { pool, esquema })
    }

    pub async fn cerrar(self) {
        let _ = self
            .pool
            .execute(format!("DROP SCHEMA IF EXISTS {} CASCADE", self.esquema).as_str())
            .await;
        self.pool.close().await;
    }

    /// Enrola `n` maquinas `srv-0000`.. con direccion `10.20.x.y`.
    pub async fn flota(&self, n: usize) {
        let mut cns = Vec::with_capacity(n);
        let mut ips = Vec::with_capacity(n);
        for i in 0..n {
            cns.push(format!("srv-{i:04}"));
            ips.push(format!("10.20.{}.{}", 1 + i / 250, 1 + i % 250));
        }
        sqlx::query(
            r#"INSERT INTO agentes (cn, id_agente, hostname, version_agente, direccion_vista)
               SELECT c, c, c, '1.0', i::inet FROM unnest($1::text[], $2::text[]) AS t(c, i)"#,
        )
        .bind(&cns)
        .bind(&ips)
        .execute(&self.pool)
        .await
        .expect("flota");
    }

    /// Enrola una maquina con una direccion.
    pub async fn maquina(&self, cn: &str, ip: &str) {
        sqlx::query(
            "INSERT INTO agentes (cn, id_agente, hostname, version_agente, direccion_vista) VALUES ($1, $1, $1, '1.0', $2::inet)",
        )
        .bind(cn)
        .bind(ip)
        .execute(&self.pool)
        .await
        .expect("maquina");
    }

    pub fn puertos(&self, ejecucion: &str) -> PuertosPg {
        PuertosPg::nuevo(self.pool.clone(), "flujo:contencion", ejecucion, "acme").unwrap()
    }

    pub async fn contar(&self, sql: &str) -> i64 {
        sqlx::query_scalar(sql)
            .fetch_one(&self.pool)
            .await
            .expect(sql)
    }
}

/// Los frenos de la FASE 69 con evidencia solida y confianza alta: lo unico que
/// puede detener un paso es su radio o un protegido.
pub fn frenos(flota: usize, protegidos: &[Eid]) -> CincoFrenos {
    CincoFrenos {
        config: ConfigContencion::default(),
        flota,
        protegidos: protegidos.iter().cloned().collect(),
        evidencia: Evidencia {
            observaciones: 12,
            observadores: 4,
            antiguedad_seg: 3 * 86_400,
        },
        confianza: 0.95,
    }
}

/// Una persona del SOC que firma aprobaciones.
pub struct Analista {
    pub nombre: &'static str,
    clave: ClaveFirmaHibrida,
}

impl Analista {
    pub fn nuevo(nombre: &'static str) -> Analista {
        Analista {
            nombre,
            clave: ClaveFirmaHibrida::generar_aleatorio().unwrap(),
        }
    }

    /// Firma la ejecucion de `paso` del flujo `flujo` sobre `objetivos`, y la
    /// verifica como lo haria el servidor.
    pub fn aprueba(&self, flujo: &str, paso: &str, objetivos: &[Eid]) -> Firma {
        let h = huella(flujo, paso, objetivos);
        let firma = self.clave.firmar(&h, DOMINIO).unwrap();
        Firma::verificar(
            &self.clave.clave_verificacion(),
            self.nombre,
            flujo,
            paso,
            objetivos,
            &firma,
        )
        .unwrap()
    }
}

pub fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}
