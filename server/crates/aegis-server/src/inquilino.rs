//! Consultas acotadas a UN inquilino (H-03, FASE 6.2 del MP-16).
//!
//! Son las versiones por inquilino de las consultas del panel que
//! `crate::autorizacion` clasifica como [`Alcance::Inquilino`]: el inquilino
//! llega de la sesion, nunca de la peticion, y va en el `WHERE` de la propia
//! consulta. No se filtra despues en memoria: un `LIMIT` aplicado antes de
//! filtrar devolveria menos filas de las pedidas, y un agregado (el resumen)
//! filtrado despues seguiria contando a los demas clientes.
//!
//! El inquilino de un agente es `agentes.id_flota`, que el enrolamiento deriva
//! del CN autenticado (`crate::autorizacion::inquilino_de_cn`). Lo que cuelga
//! de un agente (alertas, respuestas de caza) se acota por su `cn_agente`.
//!
//! [`Alcance::Inquilino`]: crate::autorizacion::Alcance::Inquilino

use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::almacen::{
    ResumenCaza, VistaAgente, VistaAlerta, VistaCaza, VistaRespuestaCaza, CANAL_CAZA,
};
use crate::error::Resultado;

/// Resumen para la cabecera del panel, de un inquilino.
pub async fn resumen(
    pool: &PgPool,
    inquilino: &str,
    margen_seg: i64,
) -> Resultado<crate::almacen::Resumen> {
    let f = sqlx::query(
        r#"
        SELECT
          (SELECT count(*) FROM agentes WHERE id_flota = $2)::bigint AS agentes_total,
          (SELECT count(*) FROM agentes WHERE id_flota = $2
            AND ultimo_latido > now() - make_interval(secs => $1::double precision))::bigint
            AS agentes_en_linea,
          (SELECT count(*) FROM agentes WHERE id_flota = $2 AND aislado)::bigint
            AS agentes_aislados,
          (SELECT count(*) FROM alertas al JOIN agentes a ON a.cn = al.cn_agente
            WHERE a.id_flota = $2 AND NOT al.resuelta)::bigint AS alertas_abiertas,
          (SELECT count(*) FROM alertas al JOIN agentes a ON a.cn = al.cn_agente
            WHERE a.id_flota = $2 AND NOT al.resuelta AND al.severidad >= 3)::bigint
            AS alertas_criticas,
          COALESCE((SELECT version FROM politicas WHERE activa LIMIT 1), 0) AS version_politica
        "#,
    )
    .bind(margen_seg as f64)
    .bind(inquilino)
    .fetch_one(pool)
    .await?;
    Ok(crate::almacen::Resumen {
        agentes_total: f.try_get("agentes_total").unwrap_or(0),
        agentes_en_linea: f.try_get("agentes_en_linea").unwrap_or(0),
        agentes_aislados: f.try_get("agentes_aislados").unwrap_or(0),
        alertas_abiertas: f.try_get("alertas_abiertas").unwrap_or(0),
        alertas_criticas: f.try_get("alertas_criticas").unwrap_or(0),
        version_politica: f.try_get("version_politica").unwrap_or(0),
    })
}

/// Agentes de un inquilino.
pub async fn listar_agentes(
    pool: &PgPool,
    inquilino: &str,
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
         WHERE id_flota = $3
         ORDER BY ultimo_latido DESC NULLS LAST
         LIMIT $2
        "#,
    )
    .bind(margen_seg as f64)
    .bind(limite)
    .bind(inquilino)
    .fetch_all(pool)
    .await?;
    Ok(filas
        .iter()
        .map(|f| VistaAgente {
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
        })
        .collect())
}

/// Alertas de los agentes de un inquilino.
pub async fn listar_alertas(
    pool: &PgPool,
    inquilino: &str,
    limite: i64,
    solo_abiertas: bool,
) -> Resultado<Vec<VistaAlerta>> {
    let sql = if solo_abiertas {
        r#"SELECT al.id, al.cn_agente, al.severidad, al.categoria, al.descripcion,
                  al.tecnica_mitre, al.tactica_mitre, al.ocurrido_en, al.recibido_en,
                  al.resuelta
             FROM alertas al JOIN agentes a ON a.cn = al.cn_agente
            WHERE a.id_flota = $2 AND NOT al.resuelta
            ORDER BY al.severidad DESC, al.recibido_en DESC LIMIT $1"#
    } else {
        r#"SELECT al.id, al.cn_agente, al.severidad, al.categoria, al.descripcion,
                  al.tecnica_mitre, al.tactica_mitre, al.ocurrido_en, al.recibido_en,
                  al.resuelta
             FROM alertas al JOIN agentes a ON a.cn = al.cn_agente
            WHERE a.id_flota = $2
            ORDER BY al.recibido_en DESC LIMIT $1"#
    };
    let filas = sqlx::query(sql)
        .bind(limite)
        .bind(inquilino)
        .fetch_all(pool)
        .await?;
    Ok(filas
        .iter()
        .map(|f| VistaAlerta {
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
        })
        .collect())
}

/// Inquilino de un caso, si existe.
pub async fn propietario_caso(pool: &PgPool, id: &str) -> Resultado<Option<String>> {
    Ok(
        sqlx::query_scalar::<_, String>("SELECT inquilino FROM casos WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await?,
    )
}

/// Inquilino de una caza, si existe y lo tiene. Las cazas de antes de esta
/// fase no tienen inquilino: no son de nadie y no las ve ningun cliente.
pub async fn propietario_caza(pool: &PgPool, id: Uuid) -> Resultado<Option<String>> {
    let v: Option<Option<String>> =
        sqlx::query_scalar("SELECT inquilino FROM cacerias WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await?;
    Ok(v.flatten())
}

/// Cazas abiertas de un inquilino, para el tope de simultaneas.
pub async fn cazas_abiertas(pool: &PgPool, inquilino: &str) -> Resultado<i64> {
    Ok(sqlx::query_scalar(
        "SELECT count(*) FROM cacerias WHERE inquilino = $1 AND cerrada_en IS NULL",
    )
    .bind(inquilino)
    .fetch_one(pool)
    .await?)
}

/// Registra una caza DE UN INQUILINO y avisa a las demas instancias.
///
/// Diferencias con `Almacen::lanzar_caza`, que queda para las cazas de
/// plataforma y las pruebas del transporte:
///
/// - el denominador (`objetivo`) son los agentes EN LINEA DEL INQUILINO: contar
///   la flota entera le diria a un cliente cuantas maquinas tienen los demas;
/// - `cacerias.inquilino` queda fijado, y `Almacen::caza_pendiente_para` solo
///   entrega la caza a los agentes de ese inquilino.
#[allow(clippy::too_many_arguments)]
pub async fn lanzar_caza(
    pool: &PgPool,
    inquilino: &str,
    consulta: &str,
    tabla: &str,
    columnas: &[String],
    lanzada_por: &str,
    margen_seg: i64,
) -> Resultado<Uuid> {
    let id = Uuid::new_v4();
    let objetivo: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM agentes
          WHERE id_flota = $2
            AND ultimo_latido IS NOT NULL
            AND ultimo_latido > now() - make_interval(secs => $1::double precision)",
    )
    .bind(margen_seg as f64)
    .bind(inquilino)
    .fetch_one(pool)
    .await?;
    sqlx::query(
        r#"INSERT INTO cacerias (id, consulta, tabla, columnas, lanzada_por, objetivo, inquilino)
           VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
    )
    .bind(id)
    .bind(consulta)
    .bind(tabla)
    .bind(columnas)
    .bind(lanzada_por)
    .bind(objetivo)
    .bind(inquilino)
    .execute(pool)
    .await?;
    sqlx::query("SELECT pg_notify($1, $2)")
        .bind(CANAL_CAZA)
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(id)
}

/// Cazas de un inquilino, las mas recientes primero.
pub async fn listar_cacerias(
    pool: &PgPool,
    inquilino: &str,
    limite: i64,
) -> Resultado<Vec<VistaCaza>> {
    let filas = sqlx::query(
        r#"SELECT id, consulta, tabla, columnas, lanzada_por, lanzada_en,
                  cerrada_en, objetivo
             FROM cacerias WHERE inquilino = $2
            ORDER BY lanzada_en DESC LIMIT $1"#,
    )
    .bind(limite)
    .bind(inquilino)
    .fetch_all(pool)
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

/// Resumen de una caza contando SOLO las respuestas de agentes del inquilino.
///
/// La caza ya es del inquilino (lo comprueba la capa), pero una respuesta la
/// sube un agente con el identificador de caza que el elija: sin este filtro,
/// un agente de otro cliente podria colar filas en la caza de este.
pub async fn resumen_caza(pool: &PgPool, id: Uuid, inquilino: &str) -> Resultado<ResumenCaza> {
    let f = sqlx::query(
        r#"SELECT
               count(*)                                         AS respondieron,
               count(*) FILTER (WHERE r.coincidencias > 0)       AS con_hallazgos,
               COALESCE(sum(r.coincidencias), 0)::bigint         AS coincidencias,
               COALESCE(sum(r.examinadas), 0)::bigint            AS examinadas,
               COALESCE(sum(r.inaccesibles), 0)::bigint          AS inaccesibles,
               count(*) FILTER (WHERE r.agotado)                 AS agotados,
               count(*) FILTER (WHERE r.error <> '')             AS con_error,
               COALESCE(max(r.duracion_ms), 0)                   AS peor_ms
             FROM caza_respuestas r JOIN agentes a ON a.cn = r.cn_agente
            WHERE r.caza_id = $1 AND a.id_flota = $2"#,
    )
    .bind(id)
    .bind(inquilino)
    .fetch_one(pool)
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

/// Respuestas de una caza de agentes del inquilino.
pub async fn respuestas_caza(
    pool: &PgPool,
    id: Uuid,
    inquilino: &str,
    limite: i64,
) -> Resultado<Vec<VistaRespuestaCaza>> {
    let filas = sqlx::query(
        r#"SELECT r.cn_agente, r.filas, r.coincidencias, r.examinadas, r.inaccesibles,
                  r.incompleto, r.agotado, r.duracion_ms, r.error, r.recibida_en
             FROM caza_respuestas r JOIN agentes a ON a.cn = r.cn_agente
            WHERE r.caza_id = $1 AND a.id_flota = $3
            ORDER BY r.coincidencias DESC, r.recibida_en DESC
            LIMIT $2"#,
    )
    .bind(id)
    .bind(limite)
    .bind(inquilino)
    .fetch_all(pool)
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
