//! Persistencia en PostgreSQL: inventario de flota, alertas y politicas.
//!
//! # Por que consultas en tiempo de ejecucion y no las macros de sqlx
//!
//! `sqlx::query!` comprueba el SQL contra una base de datos VIVA en tiempo de
//! COMPILACION. Es una garantia excelente y un problema operativo: el CI, el
//! empaquetado y cualquier compilacion cruzada pasarian a exigir un PostgreSQL
//! accesible. Aqui se usa la API en tiempo de ejecucion y las consultas se
//! validan con pruebas de integracion contra una base de datos real, que da la
//! misma garantia sin atar la compilacion a la infraestructura.

use chrono::{DateTime, Utc};
use sqlx::postgres::{PgPoolOptions, PgRow};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::error::Resultado;

/// Acceso a la base de datos del plano de control.
#[derive(Clone)]
pub struct Almacen {
    pool: PgPool,
}

/// Estado devuelto al agente tras un latido.
#[derive(Debug, Clone, Copy, Default)]
pub struct EstadoLatido {
    /// Version de politica que el plano de control tiene publicada.
    pub version_politica: i64,
    /// Si hay un comando esperando a este agente.
    pub hay_comando: bool,
}

/// Vista de un agente para el panel.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VistaAgente {
    /// Identidad autenticada por mTLS.
    pub cn: String,
    /// Nombre de maquina declarado.
    pub hostname: String,
    /// Version del agente.
    pub version_agente: String,
    /// Ultimo latido recibido.
    pub ultimo_latido: Option<DateTime<Utc>>,
    /// Si se considera conectado segun el margen de desconexion.
    pub en_linea: bool,
    /// Memoria residente reportada en el ultimo latido.
    pub rss_kb: i64,
    /// Amenazas activas reportadas.
    pub amenazas_activas: i64,
    /// Latidos acumulados.
    pub latidos: i64,
    /// Eventos acumulados.
    pub eventos: i64,
    /// Si el endpoint esta aislado de la red.
    pub aislado: bool,
    /// Version de politica que el agente dice tener aplicada.
    pub version_politica: i64,
}

/// Vista de una alerta para el panel.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VistaAlerta {
    /// Identificador del incidente.
    pub id: Uuid,
    /// Agente que la reporto.
    pub cn_agente: String,
    /// Severidad 0..4.
    pub severidad: i16,
    /// Categoria declarada por el agente.
    pub categoria: String,
    /// Descripcion legible.
    pub descripcion: String,
    /// Tecnica MITRE ATT&CK asignada.
    pub tecnica_mitre: Option<String>,
    /// Tactica MITRE ATT&CK asignada.
    pub tactica_mitre: Option<String>,
    /// Momento en el endpoint.
    pub ocurrido_en: DateTime<Utc>,
    /// Momento de llegada al plano de control.
    pub recibido_en: DateTime<Utc>,
    /// Si ya fue resuelta.
    pub resuelta: bool,
}

/// Resumen agregado para la cabecera del panel.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Resumen {
    /// Agentes enrolados.
    pub agentes_total: i64,
    /// Agentes que han latido dentro del margen.
    pub agentes_en_linea: i64,
    /// Agentes aislados por respuesta.
    pub agentes_aislados: i64,
    /// Alertas sin resolver.
    pub alertas_abiertas: i64,
    /// Alertas criticas sin resolver (severidad >= 3).
    pub alertas_criticas: i64,
    /// Version de politica activa.
    pub version_politica: i64,
}

/// Datos de una alerta a registrar.
///
/// Se agrupan en una estructura en vez de pasarlos sueltos porque, con siete
/// campos, el orden de los argumentos se convierte en una trampa: intercambiar
/// `categoria` y `descripcion` compilaria igual y falsearia todo el historico.
#[derive(Debug, Clone, Copy)]
pub struct NuevaAlerta<'a> {
    /// Severidad ya acotada al rango del esquema (0..4).
    pub severidad: i16,
    /// Categoria declarada por el agente.
    pub categoria: &'a str,
    /// Descripcion legible del hallazgo.
    pub descripcion: &'a str,
    /// Tecnica MITRE ATT&CK asignada, si la categoria tiene mapeo.
    pub tecnica: Option<&'a str>,
    /// Tactica MITRE ATT&CK asignada.
    pub tactica: Option<&'a str>,
    /// Momento en que ocurrio en el endpoint.
    pub ocurrido_en: DateTime<Utc>,
}

/// Comando pendiente de entrega a un agente.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Comando {
    /// Identificador del comando.
    pub id: Uuid,
    /// Accion a ejecutar.
    pub accion: String,
    /// Parametros de la accion.
    pub parametros: serde_json::Value,
}

impl Almacen {
    /// Abre el pool de conexiones.
    ///
    /// El pool es la pieza que decide si el servidor aguanta diez mil agentes o
    /// se atasca: cada latido es una transaccion corta, asi que interesan
    /// muchas conexiones cortas y un tiempo de adquisicion acotado, no
    /// conexiones eternas.
    pub async fn conectar(url: &str, max_conexiones: u32) -> Resultado<Almacen> {
        let pool = PgPoolOptions::new()
            .max_connections(max_conexiones)
            // Una conexion que tarda mas de esto en estar disponible significa
            // que el pool esta saturado: mejor devolver error al agente (que
            // reintentara en el siguiente latido) que acumular espera.
            .acquire_timeout(std::time::Duration::from_secs(5))
            .idle_timeout(std::time::Duration::from_secs(600))
            .connect(url)
            .await?;
        Ok(Almacen { pool })
    }

    /// Referencia al pool, para las pruebas y las metricas.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Aplica las migraciones pendientes.
    pub async fn migrar(&self) -> Resultado<()> {
        sqlx::migrate!("../../migrations")
            .run(&self.pool)
            .await
            .map_err(|e| sqlx::Error::Migrate(Box::new(e)))?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Flota
    // -----------------------------------------------------------------------

    /// Enrola un agente o actualiza su registro si ya existia.
    ///
    /// La clave es el CN del certificado, no lo que el agente declare: un
    /// agente que reaparece con otro hostname sigue siendo el mismo endpoint, y
    /// uno que declara el CN de otro no llega hasta aqui porque el handshake
    /// mTLS lo habria rechazado antes.
    pub async fn enrolar(
        &self,
        cn: &str,
        id_agente: &str,
        hostname: &str,
        version_agente: &str,
        huella_cert: &[u8],
        id_flota: &str,
    ) -> Resultado<()> {
        sqlx::query(
            r#"
            INSERT INTO agentes (cn, id_agente, hostname, version_agente, huella_cert, id_flota)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (cn) DO UPDATE SET
                id_agente      = EXCLUDED.id_agente,
                hostname       = EXCLUDED.hostname,
                version_agente = EXCLUDED.version_agente,
                huella_cert    = EXCLUDED.huella_cert,
                id_flota       = EXCLUDED.id_flota
            "#,
        )
        .bind(cn)
        .bind(id_agente)
        .bind(hostname)
        .bind(version_agente)
        .bind(huella_cert)
        .bind(id_flota)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Registra un latido y devuelve lo que el agente debe saber.
    ///
    /// Se resuelve en UNA consulta: el latido es la operacion mas frecuente del
    /// sistema (una por agente y por intervalo), asi que cada ida y vuelta de
    /// mas se multiplica por el tamano de la flota.
    pub async fn registrar_latido(
        &self,
        cn: &str,
        rss_kb: i64,
        amenazas_activas: i64,
        version_politica_agente: i64,
    ) -> Resultado<EstadoLatido> {
        let fila = sqlx::query(
            r#"
            WITH actualizado AS (
                UPDATE agentes
                   SET ultimo_latido    = now(),
                       latidos          = latidos + 1,
                       rss_kb           = $2,
                       amenazas_activas = $3,
                       version_politica = $4
                 WHERE cn = $1
                RETURNING cn
            )
            SELECT
                COALESCE((SELECT version FROM politicas WHERE activa LIMIT 1), 0) AS version_politica,
                EXISTS (
                    SELECT 1 FROM comandos
                     WHERE cn_agente = $1 AND entregado_en IS NULL
                ) AS hay_comando,
                EXISTS (SELECT 1 FROM actualizado) AS existe
            "#,
        )
        .bind(cn)
        .bind(rss_kb)
        .bind(amenazas_activas)
        .bind(version_politica_agente)
        .fetch_one(&self.pool)
        .await?;

        Ok(EstadoLatido {
            version_politica: fila.try_get("version_politica").unwrap_or(0),
            hay_comando: fila.try_get("hay_comando").unwrap_or(false),
        })
    }

    /// Guarda una alerta y devuelve su identificador de incidente.
    pub async fn registrar_alerta(&self, cn: &str, a: &NuevaAlerta<'_>) -> Resultado<Uuid> {
        let NuevaAlerta {
            severidad,
            categoria,
            descripcion,
            tecnica,
            tactica,
            ocurrido_en,
        } = *a;
        let id = Uuid::new_v4();
        let mut tx = self.pool.begin().await?;

        sqlx::query(
            r#"
            INSERT INTO alertas
                (id, cn_agente, severidad, categoria, descripcion,
                 tecnica_mitre, tactica_mitre, ocurrido_en)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(id)
        .bind(cn)
        .bind(severidad)
        .bind(categoria)
        .bind(descripcion)
        .bind(tecnica)
        .bind(tactica)
        .bind(ocurrido_en)
        .execute(&mut *tx)
        .await?;

        // El contador del agente y la alerta van en la MISMA transaccion: si se
        // guardara la alerta y fallara el contador, el inventario diria que el
        // endpoint no ha reportado nada mientras la alerta existe.
        sqlx::query("UPDATE agentes SET eventos = eventos + 1 WHERE cn = $1")
            .bind(cn)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(id)
    }

    // -----------------------------------------------------------------------
    // Consultas del panel
    // -----------------------------------------------------------------------

    /// Lista los agentes con su estado de conexion.
    pub async fn listar_agentes(
        &self,
        margen_seg: i64,
        limite: i64,
    ) -> Resultado<Vec<VistaAgente>> {
        let filas = sqlx::query(
            r#"
            SELECT cn, hostname, version_agente, ultimo_latido, rss_kb,
                   amenazas_activas, latidos, eventos, aislado, version_politica,
                   (ultimo_latido IS NOT NULL
                    AND ultimo_latido > now() - make_interval(secs => $1::double precision))
                   AS en_linea
              FROM agentes
             ORDER BY ultimo_latido DESC NULLS LAST
             LIMIT $2
            "#,
        )
        .bind(margen_seg as f64)
        .bind(limite)
        .fetch_all(&self.pool)
        .await?;

        Ok(filas.iter().map(fila_a_agente).collect())
    }

    /// Lista las alertas mas recientes.
    pub async fn listar_alertas(
        &self,
        limite: i64,
        solo_abiertas: bool,
    ) -> Resultado<Vec<VistaAlerta>> {
        let sql = if solo_abiertas {
            r#"SELECT id, cn_agente, severidad, categoria, descripcion, tecnica_mitre,
                      tactica_mitre, ocurrido_en, recibido_en, resuelta
                 FROM alertas WHERE NOT resuelta
                ORDER BY severidad DESC, recibido_en DESC LIMIT $1"#
        } else {
            r#"SELECT id, cn_agente, severidad, categoria, descripcion, tecnica_mitre,
                      tactica_mitre, ocurrido_en, recibido_en, resuelta
                 FROM alertas ORDER BY recibido_en DESC LIMIT $1"#
        };
        let filas = sqlx::query(sql).bind(limite).fetch_all(&self.pool).await?;
        Ok(filas.iter().map(fila_a_alerta).collect())
    }

    /// Devuelve un agente por su CN.
    pub async fn obtener_agente(&self, cn: &str, margen_seg: i64) -> Resultado<VistaAgente> {
        let fila = sqlx::query(
            r#"
            SELECT cn, hostname, version_agente, ultimo_latido, rss_kb,
                   amenazas_activas, latidos, eventos, aislado, version_politica,
                   (ultimo_latido IS NOT NULL
                    AND ultimo_latido > now() - make_interval(secs => $2::double precision))
                   AS en_linea
              FROM agentes WHERE cn = $1
            "#,
        )
        .bind(cn)
        .bind(margen_seg as f64)
        .fetch_optional(&self.pool)
        .await?;

        match fila {
            Some(f) => Ok(fila_a_agente(&f)),
            None => Err(crate::error::ErrorServidor::NoEncontrado(format!(
                "el agente {} no esta enrolado",
                cn.chars().take(64).collect::<String>()
            ))),
        }
    }

    /// Resumen agregado de la flota.
    pub async fn resumen(&self, margen_seg: i64) -> Resultado<Resumen> {
        let fila = sqlx::query(
            r#"
            SELECT
              (SELECT count(*) FROM agentes)::bigint AS agentes_total,
              (SELECT count(*) FROM agentes
                WHERE ultimo_latido > now() - make_interval(secs => $1::double precision))::bigint
                AS agentes_en_linea,
              (SELECT count(*) FROM agentes WHERE aislado)::bigint AS agentes_aislados,
              (SELECT count(*) FROM alertas WHERE NOT resuelta)::bigint AS alertas_abiertas,
              (SELECT count(*) FROM alertas WHERE NOT resuelta AND severidad >= 3)::bigint
                AS alertas_criticas,
              COALESCE((SELECT version FROM politicas WHERE activa LIMIT 1), 0) AS version_politica
            "#,
        )
        .bind(margen_seg as f64)
        .fetch_one(&self.pool)
        .await?;

        Ok(Resumen {
            agentes_total: fila.try_get("agentes_total").unwrap_or(0),
            agentes_en_linea: fila.try_get("agentes_en_linea").unwrap_or(0),
            agentes_aislados: fila.try_get("agentes_aislados").unwrap_or(0),
            alertas_abiertas: fila.try_get("alertas_abiertas").unwrap_or(0),
            alertas_criticas: fila.try_get("alertas_criticas").unwrap_or(0),
            version_politica: fila.try_get("version_politica").unwrap_or(0),
        })
    }

    // -----------------------------------------------------------------------
    // Respuesta: comandos y aislamiento
    // -----------------------------------------------------------------------

    /// Encola un comando para un agente.
    pub async fn encolar_comando(
        &self,
        cn: &str,
        accion: &str,
        parametros: serde_json::Value,
        ordenado_por: &str,
    ) -> Resultado<Uuid> {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO comandos (id, cn_agente, accion, parametros, ordenado_por)
               VALUES ($1, $2, $3, $4, $5)"#,
        )
        .bind(id)
        .bind(cn)
        .bind(accion)
        .bind(&parametros)
        .bind(ordenado_por)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    /// Toma el comando pendiente mas antiguo de un agente y lo marca entregado.
    ///
    /// El `FOR UPDATE SKIP LOCKED` es lo que permite que varias instancias del
    /// plano de control atiendan a la misma flota sin entregar el mismo comando
    /// dos veces: la fila que una instancia esta tomando, la otra la salta.
    pub async fn tomar_comando_pendiente(&self, cn: &str) -> Resultado<Option<Comando>> {
        let fila = sqlx::query(
            r#"
            WITH siguiente AS (
                SELECT id FROM comandos
                 WHERE cn_agente = $1 AND entregado_en IS NULL
                 ORDER BY creado_en
                 FOR UPDATE SKIP LOCKED
                 LIMIT 1
            )
            UPDATE comandos c
               SET entregado_en = now()
              FROM siguiente s
             WHERE c.id = s.id
            RETURNING c.id, c.accion, c.parametros
            "#,
        )
        .bind(cn)
        .fetch_optional(&self.pool)
        .await?;

        Ok(fila.map(|f| Comando {
            id: f.get("id"),
            accion: f.get("accion"),
            parametros: f.get("parametros"),
        }))
    }

    /// Marca un endpoint como aislado o lo libera.
    pub async fn fijar_aislamiento(&self, cn: &str, aislado: bool) -> Resultado<bool> {
        let r = sqlx::query(
            r#"UPDATE agentes
                  SET aislado = $2,
                      aislado_en = CASE WHEN $2 THEN now() ELSE NULL END
                WHERE cn = $1"#,
        )
        .bind(cn)
        .bind(aislado)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() > 0)
    }

    /// Publica una politica nueva y la deja como activa.
    pub async fn publicar_politica(
        &self,
        nombre: &str,
        contenido: serde_json::Value,
    ) -> Resultado<i64> {
        let mut tx = self.pool.begin().await?;
        // Desactivar la anterior ANTES de insertar la nueva: el indice unico
        // parcial sobre `activa` rechazaria dos activas a la vez, que es
        // exactamente la garantia que se busca.
        sqlx::query("UPDATE politicas SET activa = FALSE WHERE activa")
            .execute(&mut *tx)
            .await?;
        let fila = sqlx::query(
            r#"INSERT INTO politicas (version, nombre, contenido, activa)
               VALUES ((SELECT COALESCE(max(version), 0) + 1 FROM politicas), $1, $2, TRUE)
               RETURNING version"#,
        )
        .bind(nombre)
        .bind(&contenido)
        .fetch_one(&mut *tx)
        .await?;
        let version: i64 = fila.get("version");
        tx.commit().await?;
        Ok(version)
    }
}

/// Conversion de fila a vista de agente.
fn fila_a_agente(f: &PgRow) -> VistaAgente {
    VistaAgente {
        cn: f.get("cn"),
        hostname: f.get("hostname"),
        version_agente: f.get("version_agente"),
        ultimo_latido: f.try_get("ultimo_latido").ok().flatten(),
        en_linea: f
            .try_get("en_linea")
            .unwrap_or(Some(false))
            .unwrap_or(false),
        rss_kb: f.get("rss_kb"),
        amenazas_activas: f.get("amenazas_activas"),
        latidos: f.get("latidos"),
        eventos: f.get("eventos"),
        aislado: f.get("aislado"),
        version_politica: f.get("version_politica"),
    }
}

/// Conversion de fila a vista de alerta.
fn fila_a_alerta(f: &PgRow) -> VistaAlerta {
    VistaAlerta {
        id: f.get("id"),
        cn_agente: f.get("cn_agente"),
        severidad: f.get("severidad"),
        categoria: f.get("categoria"),
        descripcion: f.get("descripcion"),
        tecnica_mitre: f.try_get("tecnica_mitre").ok().flatten(),
        tactica_mitre: f.try_get("tactica_mitre").ok().flatten(),
        ocurrido_en: f.get("ocurrido_en"),
        recibido_en: f.get("recibido_en"),
        resuelta: f.get("resuelta"),
    }
}
