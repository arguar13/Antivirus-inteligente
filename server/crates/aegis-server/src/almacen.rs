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

    /// Alertas de UN endpoint concreto, de la mas reciente a la mas antigua.
    ///
    /// La consola necesita esto para la vista de detalle: al pinchar un
    /// endpoint hay que poder ver que le ha pasado A EL, no filtrar a ojo un
    /// listado global de toda la flota. En un despliegue de diez mil maquinas,
    /// las alertas de un endpoint concreto no aparecen en las primeras paginas
    /// del listado global salvo que sean las mas graves del momento.
    ///
    /// El indice `idx_alertas_agente (cn_agente, recibido_en DESC)` cubre esta
    /// consulta exactamente, sin ordenacion adicional.
    pub async fn listar_alertas_de_agente(
        &self,
        cn: &str,
        limite: i64,
    ) -> Resultado<Vec<VistaAlerta>> {
        let filas = sqlx::query(
            r#"SELECT id, cn_agente, severidad, categoria, descripcion, tecnica_mitre,
                      tactica_mitre, ocurrido_en, recibido_en, resuelta
                 FROM alertas WHERE cn_agente = $1
                ORDER BY recibido_en DESC LIMIT $2"#,
        )
        .bind(cn)
        .bind(limite)
        .fetch_all(&self.pool)
        .await?;
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

        // Avisar por el canal: sin esto, el comando esperaria al latido del
        // canal de suscripcion (hasta 30 s) o al siguiente latido del agente.
        // Aislar un endpoint comprometido es justo lo que no puede esperar.
        let (version, _) = self
            .politica_activa()
            .await
            .unwrap_or((0, serde_json::Value::Null));
        let _ = sqlx::query("SELECT pg_notify($1, $2)")
            .bind(CANAL_POLITICA)
            .bind(version.to_string())
            .execute(&self.pool)
            .await;

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
        // Una publicacion cada vez (ver CERROJO_PUBLICACION).
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(CERROJO_PUBLICACION)
            .execute(&mut *tx)
            .await?;
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

// ---------------------------------------------------------------------------
// FASE 38: inteligencia STIX, grafos de linaje y motor de reglas
// ---------------------------------------------------------------------------

/// Canal de PostgreSQL por el que se avisa de que hay politica nueva.
///
/// Se usa `NOTIFY` y no un aviso en memoria porque el plano de control se
/// despliega con VARIAS instancias detras de un balanceador: un agente puede
/// tener su canal de suscripcion abierto contra la instancia A mientras el
/// operador publica la regla contra la instancia B. Sin este aviso cruzado, ese
/// endpoint no se enteraria hasta reconectar.
pub const CANAL_POLITICA: &str = "aegis_politica";

/// Cerrojo consultivo que serializa la publicacion de politica.
///
/// POR QUE HACE FALTA
/// ------------------
/// Publicar politica es un ciclo leer-modificar-escribir sobre la tabla:
/// desactivar la vigente, calcular `max(version) + 1` e insertar la nueva. Bajo
/// READ COMMITTED —el aislamiento por defecto de PostgreSQL, y el que usa este
/// servidor— dos transacciones simultaneas no se ven entre si: la segunda se
/// queda esperando en el `UPDATE`, y cuando la primera confirma vuelve a
/// evaluar la condicion sobre la fila ya desactivada, no afecta a ninguna, y
/// tampoco ve todavia la fila recien insertada. Su `INSERT` choca entonces
/// contra el indice unico parcial y contra la clave primaria de version, y la
/// publicacion se PIERDE con un error crudo de base de datos.
///
/// No es un caso de laboratorio: son dos operadores en la consola, o un
/// operador y la automatizacion que recompila reglas tras ingerir inteligencia.
///
/// POR QUE UN CERROJO CONSULTIVO Y NO OTRA COSA
/// -------------------------------------------
/// - Subir a SERIALIZABLE obligaria a reintentar en TODO el servidor, no solo
///   aqui, y a que cada llamador supiera distinguir un fallo reintentable.
/// - `LOCK TABLE politicas IN EXCLUSIVE MODE` sirve, pero es un cerrojo pesado
///   sobre un objeto que ademas leen los latidos de toda la flota.
/// - Un cerrojo consultivo es del ambito del CLUSTER, no del proceso, asi que
///   sigue funcionando con varias instancias del plano de control detras del
///   balanceador; y al ser `_xact_` se libera solo al confirmar o deshacer la
///   transaccion, sin ninguna ruta de fuga.
///
/// El valor son los ocho bytes ASCII de "AEGISPOL": arbitrario, pero
/// reconocible en `pg_locks` cuando alguien diagnostique un bloqueo.
const CERROJO_PUBLICACION: i64 = 0x4145_4749_5350_4F4C;

/// Resultado de ingerir un bundle STIX.
#[derive(Debug, Clone, Default)]
pub struct IngestaStix {
    /// Identificador del bundle almacenado.
    pub id_bundle: String,
    /// Objetos dados de alta o actualizados.
    pub objetos: u64,
    /// Objetos que ya se conocian y han sumado un avistamiento.
    pub reavistados: u64,
}

impl Almacen {
    /// Ingiere un bundle STIX 2.1 completo.
    ///
    /// La deduplicacion es la razon de ser de esta funcion: STIX define los
    /// identificadores para que dos herramientas que observen el MISMO artefacto
    /// produzcan el MISMO id. Aprovecharlo convierte "cien endpoints han visto
    /// este fichero" en un objeto con cien avistamientos en vez de cien objetos
    /// sueltos, que es la diferencia entre ver una campana y ver ruido.
    pub async fn ingerir_stix(
        &self,
        cn: &str,
        bundle_json: &str,
        generado_en: Option<DateTime<Utc>>,
    ) -> Resultado<IngestaStix> {
        let raiz: serde_json::Value = serde_json::from_str(bundle_json).map_err(|e| {
            crate::error::ErrorServidor::Config(format!("bundle STIX ilegible: {e}"))
        })?;

        if raiz.get("type").and_then(|v| v.as_str()) != Some("bundle") {
            return Err(crate::error::ErrorServidor::Config(
                "el documento no declara type=bundle".into(),
            ));
        }

        let id_bundle = raiz
            .get("id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("bundle--{}", Uuid::new_v4()));

        let objetos = raiz
            .get("objects")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let mut tx = self.pool.begin().await?;

        sqlx::query(
            r#"INSERT INTO stix_bundles (id, cn_agente, objetos, generado_en)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (id) DO UPDATE SET recibido_en = now()"#,
        )
        .bind(&id_bundle)
        .bind(cn)
        .bind(objetos.len() as i32)
        .bind(generado_en)
        .execute(&mut *tx)
        .await?;

        let mut nuevos = 0u64;
        let mut reavistados = 0u64;
        for obj in &objetos {
            let (Some(id), Some(tipo)) = (
                obj.get("id").and_then(|v| v.as_str()),
                obj.get("type").and_then(|v| v.as_str()),
            ) else {
                // Un objeto sin id o sin tipo no cumple la especificacion: se
                // descarta ese objeto, no el bundle entero, para no perder los
                // que si son validos.
                continue;
            };

            let fila = sqlx::query(
                r#"
                INSERT INTO stix_objetos (id, tipo, id_bundle, cn_agente, contenido)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (id) DO UPDATE SET
                    avistamientos = stix_objetos.avistamientos + 1,
                    ultima_vez    = now(),
                    contenido     = EXCLUDED.contenido
                RETURNING avistamientos
                "#,
            )
            .bind(id)
            .bind(tipo)
            .bind(&id_bundle)
            .bind(cn)
            .bind(obj)
            .fetch_one(&mut *tx)
            .await?;

            let avistamientos: i32 = fila.get("avistamientos");
            if avistamientos > 1 {
                reavistados += 1;
            } else {
                nuevos += 1;
            }
        }

        tx.commit().await?;
        Ok(IngestaStix {
            id_bundle,
            objetos: nuevos + reavistados,
            reavistados,
        })
    }

    /// Guarda el subgrafo de linaje que rodea a una deteccion.
    pub async fn ingerir_grafo(
        &self,
        cn: &str,
        raiz: i64,
        capturado_en: DateTime<Utc>,
        nodos: &[NodoGrafo],
    ) -> Resultado<(Uuid, u64)> {
        let id = Uuid::new_v4();
        let mut tx = self.pool.begin().await?;

        sqlx::query(
            r#"INSERT INTO grafos (id, cn_agente, raiz, nodos, capturado_en)
               VALUES ($1, $2, $3, $4, $5)"#,
        )
        .bind(id)
        .bind(cn)
        .bind(raiz)
        .bind(nodos.len() as i32)
        .bind(capturado_en)
        .execute(&mut *tx)
        .await?;

        for n in nodos {
            // Un grafo puede traer la misma clave dos veces si el agente la
            // incluyo por dos caminos del linaje: se ignora el duplicado en vez
            // de abortar la ingesta entera por un detalle del emisor.
            sqlx::query(
                r#"INSERT INTO grafo_nodos
                     (id_grafo, clave, pid, padre, creador, profundidad, imagen,
                      cmdline, clase, iniciado_ns, terminado_ns, taints, puntuacion)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
                   ON CONFLICT (id_grafo, clave) DO NOTHING"#,
            )
            .bind(id)
            .bind(n.clave)
            .bind(n.pid)
            .bind(n.padre)
            .bind(n.creador)
            .bind(n.profundidad)
            .bind(&n.imagen)
            .bind(&n.cmdline)
            .bind(n.clase)
            .bind(n.iniciado_ns)
            .bind(n.terminado_ns)
            .bind(n.taints)
            .bind(n.puntuacion)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok((id, nodos.len() as u64))
    }

    // -----------------------------------------------------------------------
    // Reglas globales
    // -----------------------------------------------------------------------

    /// Da de alta una regla ya validada.
    pub async fn crear_regla(
        &self,
        nombre: &str,
        tipo: &str,
        parametros: &serde_json::Value,
        severidad: i16,
        creada_por: &str,
    ) -> Resultado<Uuid> {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO reglas (id, nombre, tipo, parametros, severidad, creada_por)
               VALUES ($1, $2, $3, $4, $5, $6)"#,
        )
        .bind(id)
        .bind(nombre)
        .bind(tipo)
        .bind(parametros)
        .bind(severidad)
        .bind(creada_por)
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    /// Lista las reglas, activas y no activas.
    pub async fn listar_reglas(&self) -> Resultado<Vec<crate::reglas::Regla>> {
        let filas = sqlx::query(
            r#"SELECT id, nombre, tipo, parametros, activa, severidad, creada_por
                 FROM reglas ORDER BY creada_en"#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(filas
            .iter()
            .map(|f| crate::reglas::Regla {
                id: f.get("id"),
                nombre: f.get("nombre"),
                tipo: f.get("tipo"),
                parametros: f.get("parametros"),
                activa: f.get("activa"),
                severidad: f.get("severidad"),
                creada_por: f.get("creada_por"),
            })
            .collect())
    }

    /// Activa o desactiva una regla.
    pub async fn fijar_regla_activa(&self, id: Uuid, activa: bool) -> Resultado<bool> {
        let r = sqlx::query("UPDATE reglas SET activa = $2 WHERE id = $1")
            .bind(id)
            .bind(activa)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    /// Borra una regla.
    pub async fn borrar_regla(&self, id: Uuid) -> Resultado<bool> {
        let r = sqlx::query("DELETE FROM reglas WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected() > 0)
    }

    /// Recompila las reglas activas, publica la politica y AVISA a la flota.
    ///
    /// Las tres cosas van juntas a proposito: publicar sin avisar dejaria a los
    /// endpoints con politica vieja hasta su siguiente reconexion, y avisar sin
    /// publicar les haria pedir una version que no existe.
    pub async fn recompilar_y_publicar(&self, nombre: &str) -> Resultado<i64> {
        let reglas = self.listar_reglas().await?;

        let mut tx = self.pool.begin().await?;
        // El MISMO cerrojo que `publicar_politica`: los dos caminos escriben la
        // misma tabla y compiten entre si, no solo consigo mismos.
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(CERROJO_PUBLICACION)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE politicas SET activa = FALSE WHERE activa")
            .execute(&mut *tx)
            .await?;
        let fila = sqlx::query(
            r#"INSERT INTO politicas (version, nombre, contenido, activa)
               VALUES ((SELECT COALESCE(max(version), 0) + 1 FROM politicas), $1, $2, TRUE)
               RETURNING version"#,
        )
        .bind(nombre)
        .bind(serde_json::Value::Null) // se sustituye abajo con la version ya conocida
        .fetch_one(&mut *tx)
        .await?;
        let version: i64 = fila.get("version");

        // La politica lleva su propia version dentro, asi que se compila una vez
        // conocida y se actualiza la fila en la misma transaccion.
        let contenido = crate::reglas::compilar_politica(version, &reglas);
        sqlx::query("UPDATE politicas SET contenido = $2 WHERE version = $1")
            .bind(version)
            .bind(&contenido)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;

        // El aviso va DESPUES del commit: si fuera dentro y la transaccion se
        // deshiciera, los suscriptores irian a buscar una politica inexistente.
        sqlx::query("SELECT pg_notify($1, $2)")
            .bind(CANAL_POLITICA)
            .bind(version.to_string())
            .execute(&self.pool)
            .await?;

        Ok(version)
    }

    /// Lista los grafos capturados, los mas recientes primero.
    pub async fn listar_grafos(&self, limite: i64) -> Resultado<Vec<VistaGrafo>> {
        let filas = sqlx::query(
            r#"SELECT id, cn_agente, raiz, nodos, capturado_en, recibido_en
                 FROM grafos ORDER BY recibido_en DESC LIMIT $1"#,
        )
        .bind(limite)
        .fetch_all(&self.pool)
        .await?;
        Ok(filas
            .iter()
            .map(|f| VistaGrafo {
                id: f.get("id"),
                cn_agente: f.get("cn_agente"),
                raiz: f.get("raiz"),
                nodos: f.get("nodos"),
                capturado_en: f.get("capturado_en"),
                recibido_en: f.get("recibido_en"),
            })
            .collect())
    }

    /// Devuelve los nodos de un grafo, ordenados por profundidad.
    ///
    /// El orden importa para quien lo dibuja: recorrer de la raiz hacia las
    /// hojas permite colocar cada nodo sabiendo ya donde quedo su padre.
    pub async fn nodos_de_grafo(&self, id: Uuid) -> Resultado<Vec<VistaNodoGrafo>> {
        let filas = sqlx::query(
            r#"SELECT clave, pid, padre, creador, profundidad, imagen, cmdline,
                      clase, iniciado_ns, terminado_ns, taints, puntuacion
                 FROM grafo_nodos WHERE id_grafo = $1
                ORDER BY profundidad, clave"#,
        )
        .bind(id)
        .fetch_all(&self.pool)
        .await?;

        if filas.is_empty() {
            return Err(crate::error::ErrorServidor::NoEncontrado(format!(
                "no hay grafo con identificador {id}"
            )));
        }

        Ok(filas
            .iter()
            .map(|f| VistaNodoGrafo {
                clave: f.get("clave"),
                pid: f.get("pid"),
                padre: f.get("padre"),
                creador: f.get("creador"),
                profundidad: f.get("profundidad"),
                imagen: f.get("imagen"),
                cmdline: f.get("cmdline"),
                clase: f.get("clase"),
                iniciado_ns: f.get("iniciado_ns"),
                terminado_ns: f.try_get("terminado_ns").ok().flatten(),
                taints: f.get("taints"),
                puntuacion: f.get("puntuacion"),
            })
            .collect())
    }

    /// Lista los objetos STIX ingeridos, los mas avistados primero.
    ///
    /// El orden no es capricho: un indicador visto una vez es una anecdota; uno
    /// visto en cincuenta endpoints es una campana en curso, y es lo que el
    /// analista tiene que mirar antes.
    pub async fn listar_objetos_stix(&self, limite: i64) -> Resultado<Vec<VistaObjetoStix>> {
        let filas = sqlx::query(
            r#"SELECT id, tipo, cn_agente, contenido, avistamientos, primera_vez, ultima_vez
                 FROM stix_objetos
                ORDER BY avistamientos DESC, ultima_vez DESC
                LIMIT $1"#,
        )
        .bind(limite)
        .fetch_all(&self.pool)
        .await?;

        Ok(filas
            .iter()
            .map(|f| VistaObjetoStix {
                id: f.get("id"),
                tipo: f.get("tipo"),
                cn_agente: f.try_get("cn_agente").ok().flatten(),
                contenido: f.get("contenido"),
                avistamientos: f.get("avistamientos"),
                primera_vez: f.get("primera_vez"),
                ultima_vez: f.get("ultima_vez"),
            })
            .collect())
    }

    /// Devuelve la politica activa: su version y su contenido.
    pub async fn politica_activa(&self) -> Resultado<(i64, serde_json::Value)> {
        let fila = sqlx::query("SELECT version, contenido FROM politicas WHERE activa LIMIT 1")
            .fetch_optional(&self.pool)
            .await?;
        Ok(match fila {
            Some(f) => (f.get("version"), f.get("contenido")),
            None => (0, serde_json::Value::Null),
        })
    }
}

/// Vista de un grafo capturado.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VistaGrafo {
    /// Identificador.
    pub id: Uuid,
    /// Agente que lo capturo.
    pub cn_agente: String,
    /// Clave del nodo que disparo la captura.
    pub raiz: i64,
    /// Numero de nodos.
    pub nodos: i32,
    /// Momento de captura en el endpoint.
    pub capturado_en: DateTime<Utc>,
    /// Momento de llegada.
    pub recibido_en: DateTime<Utc>,
}

/// Vista de un nodo del grafo para dibujar el arbol.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VistaNodoGrafo {
    /// Identidad estable del proceso.
    pub clave: i64,
    /// PID observado.
    pub pid: i64,
    /// Clave del padre.
    pub padre: i64,
    /// Clave del creador.
    pub creador: i64,
    /// Profundidad en el linaje.
    pub profundidad: i32,
    /// Ruta de la imagen.
    pub imagen: String,
    /// Linea de comandos.
    pub cmdline: String,
    /// Clase de imagen.
    pub clase: i32,
    /// Arranque en nanosegundos.
    pub iniciado_ns: i64,
    /// Salida, si termino.
    pub terminado_ns: Option<i64>,
    /// Marcas de contaminacion.
    pub taints: i64,
    /// Puntuacion de comportamiento.
    pub puntuacion: i32,
}

/// Vista de un objeto STIX para el panel.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VistaObjetoStix {
    /// Identificador STIX.
    pub id: String,
    /// Tipo de objeto (indicator, process, file...).
    pub tipo: String,
    /// Agente que lo reporto por ultima vez.
    pub cn_agente: Option<String>,
    /// Objeto completo tal y como llego.
    pub contenido: serde_json::Value,
    /// Cuantas veces se ha visto en la flota.
    pub avistamientos: i32,
    /// Primer avistamiento.
    pub primera_vez: DateTime<Utc>,
    /// Ultimo avistamiento.
    pub ultima_vez: DateTime<Utc>,
}

/// Un nodo de linaje listo para persistir.
#[derive(Debug, Clone, Default)]
pub struct NodoGrafo {
    /// Identidad estable del proceso.
    pub clave: i64,
    /// PID observado.
    pub pid: i64,
    /// Clave del padre.
    pub padre: i64,
    /// Clave del creador.
    pub creador: i64,
    /// Profundidad en el linaje.
    pub profundidad: i32,
    /// Ruta de la imagen.
    pub imagen: String,
    /// Linea de comandos.
    pub cmdline: String,
    /// Clase de imagen.
    pub clase: i32,
    /// Arranque en nanosegundos.
    pub iniciado_ns: i64,
    /// Salida en nanosegundos, si termino.
    pub terminado_ns: Option<i64>,
    /// Marcas de contaminacion.
    pub taints: i64,
    /// Puntuacion de comportamiento.
    pub puntuacion: i32,
}

// ---------------------------------------------------------------------------
// FASE 43: cacerias distribuidas AegisQL
// ---------------------------------------------------------------------------

/// Canal de PostgreSQL por el que se avisa de que hay caceria nueva.
///
/// Se usa el mismo mecanismo que la politica y por el mismo motivo: el plano de
/// control se despliega con varias instancias detras de un balanceador, y los
/// agentes estan repartidos entre todas. La caceria la recibe una instancia; el
/// aviso tiene que llegar a las demas o solo respondera una fraccion de la
/// flota, y el analista no tendra forma de saber cual.
pub const CANAL_CAZA: &str = "aegis_caza";

/// Cuanto tiempo sigue una caceria abierta entregandose a los que reconecten.
///
/// POR QUE UNA CACERIA CADUCA
/// --------------------------
/// Una caceria abierta le corresponde a todo endpoint que no la haya
/// contestado, incluidos los que estaban apagados. Sin caducidad, esa lista
/// crece para siempre: un portatil que vuelve de vacaciones recibiria de golpe
/// TODAS las cacerias que se lanzaron mientras no estaba, una detras de otra,
/// antes de poder recibir su politica. Con suficientes cacerias acumuladas, un
/// endpoint que reconecta no llega nunca a ponerse al dia.
///
/// Y las respuestas tardias tampoco sirven de mucho: una caceria pregunta por
/// el estado de una maquina AHORA. La respuesta de un endpoint que la contesta
/// una semana despues describe una maquina distinta de la que se pregunto.
///
/// Veinticuatro horas cubre con holgura el caso real —un endpoint apagado
/// durante la noche o un fin de semana— sin dejar que la cola crezca sin fin.
pub const VENTANA_ENTREGA_CAZA_HORAS: i64 = 24;

/// Una caceria, tal y como la ve la consola.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VistaCaza {
    /// Identificador.
    pub id: Uuid,
    /// Texto exacto que escribio el analista.
    pub consulta: String,
    /// Tabla sobre la que se consulta.
    pub tabla: String,
    /// Columnas devueltas, en orden.
    pub columnas: Vec<String>,
    /// Operador que la ordeno.
    pub lanzada_por: String,
    /// Momento de lanzamiento.
    pub lanzada_en: chrono::DateTime<chrono::Utc>,
    /// Momento de cierre, si ya se cerro.
    pub cerrada_en: Option<chrono::DateTime<chrono::Utc>>,
    /// Agentes en linea cuando se lanzo: el denominador de la cobertura.
    pub objetivo: i64,
}

/// Resumen agregado de una caceria.
///
/// Es lo que responde la pregunta que de verdad hace un analista: no "dame las
/// filas" sino "que parte de mi flota contesto, cuantos encontraron algo, y de
/// que no me puedo fiar".
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ResumenCaza {
    /// Endpoints que han respondido.
    pub respondieron: i64,
    /// Endpoints con al menos una coincidencia.
    pub con_hallazgos: i64,
    /// Suma de coincidencias en toda la flota.
    pub coincidencias: i64,
    /// Suma de filas examinadas.
    pub examinadas: i64,
    /// Suma de valores que no se pudieron obtener.
    pub inaccesibles: i64,
    /// Endpoints que agotaron su presupuesto de tiempo.
    pub agotados: i64,
    /// Endpoints que informaron de un error.
    pub con_error: i64,
    /// Milisegundos del endpoint mas lento.
    pub peor_ms: i64,
}

/// Respuesta de un endpoint concreto.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VistaRespuestaCaza {
    /// Endpoint que respondio.
    pub cn_agente: String,
    /// Filas devueltas.
    pub filas: serde_json::Value,
    /// Filas que pasaron el filtro en ese endpoint.
    pub coincidencias: i64,
    /// Filas examinadas.
    pub examinadas: i64,
    /// Valores inaccesibles.
    pub inaccesibles: i64,
    /// Si el resultado se recorto.
    pub incompleto: bool,
    /// Si se agoto el presupuesto.
    pub agotado: bool,
    /// Milisegundos empleados.
    pub duracion_ms: i64,
    /// Error informado por el endpoint.
    pub error: String,
    /// Momento de llegada.
    pub recibida_en: chrono::DateTime<chrono::Utc>,
}

impl Almacen {
    /// Registra una caceria y avisa a las demas instancias.
    pub async fn lanzar_caza(
        &self,
        consulta: &str,
        tabla: &str,
        columnas: &[String],
        lanzada_por: &str,
        margen_seg: i64,
    ) -> Resultado<Uuid> {
        let id = Uuid::new_v4();

        // El denominador se captura AHORA. Contar los agentes en linea al leer
        // el resultado daria una cobertura que cambia sola: un endpoint que se
        // apago despues de responder haria bajar el porcentaje sin que nadie
        // hubiera dejado de contestar.
        let objetivo: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM agentes
              WHERE ultimo_latido IS NOT NULL
                AND ultimo_latido > now() - make_interval(secs => $1::double precision)",
        )
        .bind(margen_seg as f64)
        .fetch_one(&self.pool)
        .await?;

        sqlx::query(
            r#"INSERT INTO cacerias (id, consulta, tabla, columnas, lanzada_por, objetivo)
               VALUES ($1, $2, $3, $4, $5, $6)"#,
        )
        .bind(id)
        .bind(consulta)
        .bind(tabla)
        .bind(columnas)
        .bind(lanzada_por)
        .bind(objetivo)
        .execute(&self.pool)
        .await?;

        // El aviso va DESPUES de confirmar la insercion: avisar antes dejaria a
        // las otras instancias buscando una caceria que aun no existe.
        sqlx::query("SELECT pg_notify($1, $2)")
            .bind(CANAL_CAZA)
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;

        Ok(id)
    }

    /// Caceria abierta que ESTE agente todavia no ha contestado.
    ///
    /// Que la condicion sea "no ha contestado" y no "es posterior a su ultima
    /// conexion" es lo que hace que un endpoint apagado reciba la caceria al
    /// volver, y que uno que ya respondio no la repita en bucle. La consulta
    /// cae sobre la clave primaria de `caza_respuestas`.
    pub async fn caza_pendiente_para(&self, cn: &str) -> Resultado<Option<(Uuid, String)>> {
        let fila = sqlx::query(
            r#"SELECT c.id, c.consulta
                 FROM cacerias c
                WHERE c.cerrada_en IS NULL
                  AND c.lanzada_en > now() - make_interval(hours => $2::int)
                  AND NOT EXISTS (
                      SELECT 1 FROM caza_respuestas r
                       WHERE r.caza_id = c.id AND r.cn_agente = $1)
                ORDER BY c.lanzada_en DESC
                LIMIT 1"#,
        )
        .bind(cn)
        .bind(VENTANA_ENTREGA_CAZA_HORAS as i32)
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.map(|f| (f.get("id"), f.get("consulta"))))
    }

    /// Guarda la respuesta de un endpoint.
    ///
    /// Es idempotente por la clave primaria (caza_id, cn_agente): un agente que
    /// pierde la conexion justo despues de responder y reintenta SUSTITUYE su
    /// respuesta en vez de duplicarla. Sin eso, un endpoint con mala red
    /// inflaria el recuento y el analista veria una amenaza mas extendida de lo
    /// que esta.
    #[allow(clippy::too_many_arguments)]
    pub async fn guardar_respuesta_caza(
        &self,
        caza_id: Uuid,
        cn: &str,
        filas: &serde_json::Value,
        coincidencias: i64,
        examinadas: i64,
        inaccesibles: i64,
        incompleto: bool,
        agotado: bool,
        duracion_ms: i64,
        error: &str,
    ) -> Resultado<()> {
        sqlx::query(
            r#"INSERT INTO caza_respuestas
                   (caza_id, cn_agente, filas, coincidencias, examinadas,
                    inaccesibles, incompleto, agotado, duracion_ms, error)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
               ON CONFLICT (caza_id, cn_agente) DO UPDATE SET
                   filas = EXCLUDED.filas,
                   coincidencias = EXCLUDED.coincidencias,
                   examinadas = EXCLUDED.examinadas,
                   inaccesibles = EXCLUDED.inaccesibles,
                   incompleto = EXCLUDED.incompleto,
                   agotado = EXCLUDED.agotado,
                   duracion_ms = EXCLUDED.duracion_ms,
                   error = EXCLUDED.error,
                   recibida_en = now()"#,
        )
        .bind(caza_id)
        .bind(cn)
        .bind(filas)
        .bind(coincidencias)
        .bind(examinadas)
        .bind(inaccesibles)
        .bind(incompleto)
        .bind(agotado)
        .bind(duracion_ms)
        .bind(error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Una caceria por su identificador.
    pub async fn obtener_caza(&self, id: Uuid) -> Resultado<Option<VistaCaza>> {
        let fila = sqlx::query(
            r#"SELECT id, consulta, tabla, columnas, lanzada_por, lanzada_en,
                      cerrada_en, objetivo
                 FROM cacerias WHERE id = $1"#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.map(|f| VistaCaza {
            id: f.get("id"),
            consulta: f.get("consulta"),
            tabla: f.get("tabla"),
            columnas: f.get("columnas"),
            lanzada_por: f.get("lanzada_por"),
            lanzada_en: f.get("lanzada_en"),
            cerrada_en: f.try_get("cerrada_en").ok().flatten(),
            objetivo: f.get("objetivo"),
        }))
    }

    /// Cacerias recientes.
    pub async fn listar_cacerias(&self, limite: i64) -> Resultado<Vec<VistaCaza>> {
        let filas = sqlx::query(
            r#"SELECT id, consulta, tabla, columnas, lanzada_por, lanzada_en,
                      cerrada_en, objetivo
                 FROM cacerias ORDER BY lanzada_en DESC LIMIT $1"#,
        )
        .bind(limite)
        .fetch_all(&self.pool)
        .await?;
        Ok(filas
            .iter()
            .map(|f| VistaCaza {
                id: f.get("id"),
                consulta: f.get("consulta"),
                tabla: f.get("tabla"),
                columnas: f.get("columnas"),
                lanzada_por: f.get("lanzada_por"),
                lanzada_en: f.get("lanzada_en"),
                cerrada_en: f.try_get("cerrada_en").ok().flatten(),
                objetivo: f.get("objetivo"),
            })
            .collect())
    }

    /// Agrega las respuestas de una caceria.
    ///
    /// La agregacion la hace PostgreSQL y no el servidor: traerse diez mil
    /// respuestas a memoria para sumarlas seria mover megabytes por la red en
    /// cada refresco del panel, cuando lo que el analista mira son ocho
    /// numeros.
    pub async fn resumen_caza(&self, id: Uuid) -> Resultado<ResumenCaza> {
        let f = sqlx::query(
            r#"SELECT
                   count(*)                                         AS respondieron,
                   count(*) FILTER (WHERE coincidencias > 0)         AS con_hallazgos,
                   -- `sum()` sobre BIGINT devuelve NUMERIC en PostgreSQL, no
                   -- BIGINT: es asi para que la suma de una columna de 64 bits
                   -- no pueda desbordar. Sin el cast explicito, leer la
                   -- columna como i64 revienta en tiempo de EJECUCION, que es
                   -- justo donde no se quiere descubrir un error de tipos.
                   COALESCE(sum(coincidencias), 0)::bigint           AS coincidencias,
                   COALESCE(sum(examinadas), 0)::bigint              AS examinadas,
                   COALESCE(sum(inaccesibles), 0)::bigint            AS inaccesibles,
                   count(*) FILTER (WHERE agotado)                   AS agotados,
                   count(*) FILTER (WHERE error <> '')               AS con_error,
                   COALESCE(max(duracion_ms), 0)                     AS peor_ms
                 FROM caza_respuestas WHERE caza_id = $1"#,
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await?;
        Ok(ResumenCaza {
            respondieron: f.get("respondieron"),
            con_hallazgos: f.get("con_hallazgos"),
            coincidencias: f.get("coincidencias"),
            examinadas: f.get("examinadas"),
            inaccesibles: f.get("inaccesibles"),
            agotados: f.get("agotados"),
            con_error: f.get("con_error"),
            peor_ms: f.get("peor_ms"),
        })
    }

    /// Respuestas de una caceria, primero las que encontraron algo.
    pub async fn respuestas_caza(
        &self,
        id: Uuid,
        limite: i64,
    ) -> Resultado<Vec<VistaRespuestaCaza>> {
        let filas = sqlx::query(
            r#"SELECT cn_agente, filas, coincidencias, examinadas, inaccesibles,
                      incompleto, agotado, duracion_ms, error, recibida_en
                 FROM caza_respuestas
                WHERE caza_id = $1
                ORDER BY coincidencias DESC, recibida_en DESC
                LIMIT $2"#,
        )
        .bind(id)
        .bind(limite)
        .fetch_all(&self.pool)
        .await?;
        Ok(filas
            .iter()
            .map(|f| VistaRespuestaCaza {
                cn_agente: f.get("cn_agente"),
                filas: f.get("filas"),
                coincidencias: f.get("coincidencias"),
                examinadas: f.get("examinadas"),
                inaccesibles: f.get("inaccesibles"),
                incompleto: f.get("incompleto"),
                agotado: f.get("agotado"),
                duracion_ms: f.get("duracion_ms"),
                error: f.get("error"),
                recibida_en: f.get("recibida_en"),
            })
            .collect())
    }

    /// Cierra una caceria: deja de entregarse a los agentes que reconecten.
    pub async fn cerrar_caza(&self, id: Uuid) -> Resultado<bool> {
        let r = sqlx::query(
            "UPDATE cacerias SET cerrada_en = now() WHERE id = $1 AND cerrada_en IS NULL",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(r.rows_affected() > 0)
    }
}

// ---------------------------------------------------------------------------
// FASE 44: cuarentena de enjambre (micro-segmentacion Zero-Trust)
// ---------------------------------------------------------------------------

/// Canal de PostgreSQL por el que se avisa de un cambio en la cuarentena.
pub const CANAL_CUARENTENA: &str = "aegis_cuarentena";

/// Una direccion en cuarentena, tal y como la ve la consola.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VistaCuarentena {
    /// Direccion aislada por toda la flota.
    pub direccion: std::net::IpAddr,
    /// Endpoint por cuya causa se ordeno, si lo hay.
    pub cn_origen: Option<String>,
    /// Por que.
    pub motivo: String,
    /// Quien la ordeno.
    pub ordenada_por: String,
    /// Cuando.
    pub ordenada_en: chrono::DateTime<chrono::Utc>,
    /// Cuando caduca sola, si caduca.
    pub expira_en: Option<chrono::DateTime<chrono::Utc>>,
}

impl Almacen {
    /// Pone una direccion en cuarentena en toda la flota.
    ///
    /// Es idempotente: volver a ordenarla sobre una direccion ya aislada
    /// actualiza el motivo y la caducidad en vez de fallar. Durante un
    /// incidente, la misma orden puede llegar por dos caminos —la deteccion
    /// automatica y el operador— con segundos de diferencia, y que la segunda
    /// falle no ayuda a nadie.
    pub async fn poner_en_cuarentena(
        &self,
        direccion: std::net::IpAddr,
        cn_origen: Option<&str>,
        motivo: &str,
        ordenada_por: &str,
        duracion_horas: Option<i64>,
    ) -> Resultado<()> {
        sqlx::query(
            r#"INSERT INTO cuarentena
                   (direccion, cn_origen, motivo, ordenada_por, expira_en,
                    levantada_en, levantada_por)
               VALUES ($1, $2, $3, $4,
                       CASE WHEN $5::bigint IS NULL THEN NULL
                            ELSE now() + make_interval(hours => $5::int) END,
                       NULL, NULL)
               ON CONFLICT (direccion) DO UPDATE SET
                   cn_origen     = EXCLUDED.cn_origen,
                   motivo        = EXCLUDED.motivo,
                   ordenada_por  = EXCLUDED.ordenada_por,
                   ordenada_en   = now(),
                   expira_en     = EXCLUDED.expira_en,
                   -- Reordenarla la REACTIVA: si estaba levantada y vuelve a
                   -- hacer falta, la orden nueva manda.
                   levantada_en  = NULL,
                   levantada_por = NULL"#,
        )
        .bind(direccion)
        .bind(cn_origen)
        .bind(motivo)
        .bind(ordenada_por)
        .bind(duracion_horas)
        .execute(&self.pool)
        .await?;

        self.avisar_cuarentena().await
    }

    /// Levanta una cuarentena.
    pub async fn levantar_cuarentena(
        &self,
        direccion: std::net::IpAddr,
        por: &str,
    ) -> Resultado<bool> {
        let r = sqlx::query(
            r#"UPDATE cuarentena
                  SET levantada_en = now(), levantada_por = $2
                WHERE direccion = $1 AND levantada_en IS NULL"#,
        )
        .bind(direccion)
        .bind(por)
        .execute(&self.pool)
        .await?;

        if r.rows_affected() > 0 {
            self.avisar_cuarentena().await?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Avisa a las demas instancias de que la cuarentena cambio.
    async fn avisar_cuarentena(&self) -> Resultado<()> {
        sqlx::query("SELECT pg_notify($1, '')")
            .bind(CANAL_CUARENTENA)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Direcciones en cuarentena AHORA MISMO.
    ///
    /// La caducidad se aplica en la consulta y no con una tarea de limpieza: una
    /// cuarentena caducada tiene que dejar de aplicarse en el instante exacto en
    /// que caduca, no cuando a un recolector le toque pasar. Si dependiera de
    /// una tarea, un fallo de esa tarea dejaria a una maquina sin red durante
    /// horas despues de que su cuarentena hubiera expirado.
    pub async fn cuarentena_vigente(&self) -> Resultado<Vec<VistaCuarentena>> {
        let filas = sqlx::query(
            r#"SELECT direccion, cn_origen, motivo, ordenada_por, ordenada_en, expira_en
                 FROM cuarentena
                WHERE levantada_en IS NULL
                  AND (expira_en IS NULL OR expira_en > now())
                ORDER BY ordenada_en DESC"#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(filas
            .iter()
            .map(|f| VistaCuarentena {
                direccion: f.get("direccion"),
                cn_origen: f.try_get("cn_origen").ok().flatten(),
                motivo: f.get("motivo"),
                ordenada_por: f.get("ordenada_por"),
                ordenada_en: f.get("ordenada_en"),
                expira_en: f.try_get("expira_en").ok().flatten(),
            })
            .collect())
    }

    /// Cuarentena que se le entrega a UN agente.
    ///
    /// Se le quita SU PROPIA direccion. Un endpoint que se bloquea a si mismo
    /// se queda sin plano de control —deja de poder recibir la orden de que la
    /// cuarentena se levanto—, y a partir de ahi solo se recupera yendo
    /// fisicamente a la maquina. El aislamiento del endpoint comprometido es
    /// otra cosa distinta y tiene su propio mecanismo (`aislar`), que
    /// deliberadamente deja abierto el canal con el plano de control.
    pub async fn cuarentena_para(&self, cn: &str) -> Resultado<Vec<std::net::IpAddr>> {
        let filas = sqlx::query(
            r#"SELECT c.direccion
                 FROM cuarentena c
                WHERE c.levantada_en IS NULL
                  AND (c.expira_en IS NULL OR c.expira_en > now())
                  AND c.direccion IS DISTINCT FROM
                      (SELECT a.direccion_vista FROM agentes a WHERE a.cn = $1)
                ORDER BY c.direccion"#,
        )
        .bind(cn)
        .fetch_all(&self.pool)
        .await?;
        Ok(filas.iter().map(|f| f.get("direccion")).collect())
    }

    /// Registra la direccion desde la que se conecto un agente.
    ///
    /// Solo escribe si CAMBIO. Un agente abre una conexion por cada llamada, y
    /// escribir en la tabla de inventario en cada una convertiria el latido de
    /// diez mil endpoints en diez mil escrituras por ciclo, para guardar
    /// siempre el mismo valor.
    pub async fn registrar_direccion(
        &self,
        cn: &str,
        direccion: std::net::IpAddr,
    ) -> Resultado<()> {
        sqlx::query(
            r#"UPDATE agentes
                  SET direccion_vista = $2, direccion_vista_en = now()
                WHERE cn = $1
                  AND (direccion_vista IS DISTINCT FROM $2)"#,
        )
        .bind(cn)
        .bind(direccion)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Direccion observada de un agente, si se conoce.
    pub async fn direccion_de(&self, cn: &str) -> Resultado<Option<std::net::IpAddr>> {
        let f = sqlx::query("SELECT direccion_vista FROM agentes WHERE cn = $1")
            .bind(cn)
            .fetch_optional(&self.pool)
            .await?;
        Ok(f.and_then(|f| f.try_get("direccion_vista").ok().flatten()))
    }
}
