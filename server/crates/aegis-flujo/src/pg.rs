//! Los puertos del catalogo sobre el esquema REAL del plano de control.
//!
//! No es un doble de pruebas: son las mismas tablas que usan la consola y la
//! remediacion automatica —`agentes` y `comandos` para aislar, matar y poner
//! en cuarentena; `cuarentena` (FASE 44) para bloquear un indicador; `casos` y
//! su rastro encadenado (FASE 76) para abrir un caso—, mas las de la migracion
//! `0009_flujos.sql` para lo que no vive en un endpoint.
//!
//! # Cada escritura es una transaccion con su lectura de «antes»
//!
//! El estado de antes se lee dentro de la MISMA transaccion que lo cambia, con
//! la fila bloqueada (`FOR UPDATE`). Leerlo fuera dejaria una ventana en la que
//! otro operador aisla la maquina entre la lectura y la escritura, y al revertir
//! el flujo la liberaria —deshaciendo una decision que no era suya—.
//!
//! # Tiempos en microsegundos
//!
//! PostgreSQL guarda `TIMESTAMPTZ` con resolucion de microsegundo. El instante
//! que entra en el resumen de una entrada del rastro de un caso se redondea a
//! microsegundos ANTES de calcularlo; si no, el resumen se calcularia sobre
//! nanosegundos que la base de datos tira, y la cadena fallaria al releerla
//! acusando de manipulacion a una entrada honesta.

use aegis_case::auditoria::{Entrada, GENESIS};
use aegis_case::Accion;
use aegis_entidad::Eid;
use sqlx::{PgPool, Postgres, Row, Transaction};

use crate::catalogo::{
    CasoAbierto, Enriquecimiento, FilaBloqueo, Notificacion, OrdenAgente, PrevioAislamiento,
    PrevioBloqueo, PrevioCuenta, Puertos,
};
use crate::paso::{ErrorPaso, Fut};
use crate::tipos::{LocFichero, LocProceso};

/// Canal por el que el plano de control avisa de un cambio en la cuarentena de
/// red: el mismo que usa `aegis-server`.
pub const CANAL_CUARENTENA: &str = "aegis_cuarentena";

/// Los puertos sobre PostgreSQL, para UNA ejecucion de un flujo.
#[derive(Debug, Clone)]
pub struct PuertosPg {
    pool: PgPool,
    actor: String,
    ejecucion: String,
    inquilino: String,
}

fn fallo(e: sqlx::Error) -> ErrorPaso {
    ErrorPaso::Fallo(format!("base de datos: {e}"))
}

/// Ahora, en microsegundos Unix.
fn ahora_us() -> i64 {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    i64::try_from(d.as_micros()).unwrap_or(i64::MAX)
}

/// Expresion SQL de un instante en microsegundos Unix.
const DE_US: &str = "(TIMESTAMPTZ 'epoch' + ($1::bigint) * INTERVAL '1 microsecond')";

impl PuertosPg {
    /// Los puertos de una ejecucion: `actor` queda en cada fila que se toca,
    /// `ejecucion` hace idempotentes los reintentos, e `inquilino` es el de los
    /// casos que se abran.
    ///
    /// # Errors
    ///
    /// [`ErrorPaso::Entrada`] si el actor o la ejecucion estan vacios: una
    /// accion sobre la flota sin responsable, o sin identidad de ejecucion (que
    /// haria que dos incidentes distintos se tomaran por el mismo reintento), no
    /// se permite.
    pub fn nuevo(
        pool: PgPool,
        actor: &str,
        ejecucion: &str,
        inquilino: &str,
    ) -> Result<PuertosPg, ErrorPaso> {
        if actor.trim().is_empty() || ejecucion.trim().is_empty() || inquilino.trim().is_empty() {
            return Err(ErrorPaso::Entrada(
                "un flujo necesita actor, ejecucion e inquilino no vacios".into(),
            ));
        }
        Ok(PuertosPg {
            pool,
            actor: actor.to_string(),
            ejecucion: ejecucion.to_string(),
            inquilino: inquilino.to_string(),
        })
    }

    /// El pool.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    async fn tx(&self) -> Result<Transaction<'static, Postgres>, ErrorPaso> {
        self.pool.begin().await.map_err(fallo)
    }

    /// Encola una orden a un agente; idempotente por el identificador.
    async fn encolar(
        &self,
        tx: &mut Transaction<'static, Postgres>,
        id: uuid::Uuid,
        cn: &str,
        accion: &str,
        parametros: serde_json::Value,
    ) -> Result<(), ErrorPaso> {
        let existe: Option<bool> = sqlx::query_scalar("SELECT TRUE FROM agentes WHERE cn = $1")
            .bind(cn)
            .fetch_optional(&mut **tx)
            .await
            .map_err(fallo)?;
        if existe.is_none() {
            return Err(ErrorPaso::Entrada(format!(
                "la maquina {cn} no esta en la flota"
            )));
        }
        sqlx::query(
            r#"INSERT INTO comandos (id, cn_agente, accion, parametros, ordenado_por)
               VALUES ($1, $2, $3, $4, $5)
               ON CONFLICT (id) DO NOTHING"#,
        )
        .bind(id)
        .bind(cn)
        .bind(accion)
        .bind(parametros)
        .bind(&self.actor)
        .execute(&mut **tx)
        .await
        .map_err(fallo)?;
        Ok(())
    }

    /// Deshace una orden a un agente: si todavia no la recogio, se retira y
    /// el agente nunca la vera; si ya la recogio, se encola la contraria.
    async fn deshacer_orden(
        &self,
        tx: &mut Transaction<'static, Postgres>,
        cn: &str,
        orden: uuid::Uuid,
        contraria: &str,
        parametros: serde_json::Value,
    ) -> Result<(), ErrorPaso> {
        let retirada = sqlx::query("DELETE FROM comandos WHERE id = $1 AND entregado_en IS NULL")
            .bind(orden)
            .execute(&mut **tx)
            .await
            .map_err(fallo)?
            .rows_affected();
        if retirada == 0 {
            let id = self.id_efecto(contraria, &orden.to_string());
            self.encolar(tx, id, cn, contraria, parametros).await?;
        }
        Ok(())
    }

    async fn anotar_caso(
        tx: &mut Transaction<'static, Postgres>,
        caso: &str,
        actor: &str,
        accion: Accion,
        detalle: &str,
    ) -> Result<(), ErrorPaso> {
        let cabeza = sqlx::query(
            "SELECT secuencia, resumen FROM caso_auditoria WHERE caso = $1 ORDER BY secuencia DESC LIMIT 1",
        )
        .bind(caso)
        .fetch_optional(&mut **tx)
        .await
        .map_err(fallo)?;
        let (secuencia, anterior) = match cabeza {
            Some(f) => (
                f.get::<i64, _>("secuencia") + 1,
                f.get::<String, _>("resumen"),
            ),
            None => (1, GENESIS.to_string()),
        };
        let us = ahora_us();
        let e = Entrada::nueva(
            u64::try_from(secuencia).unwrap_or(1),
            caso,
            actor,
            accion,
            detalle,
            u64::try_from(us).unwrap_or(0) * 1_000,
            anterior,
        );
        sqlx::query(&format!(
            r#"INSERT INTO caso_auditoria
                 (caso, secuencia, actor, accion, detalle, cuando, anterior, resumen)
               VALUES ($2, $3, $4, $5, $6, {DE_US}, $7, $8)"#
        ))
        .bind(us)
        .bind(caso)
        .bind(secuencia)
        .bind(&e.actor)
        .bind(e.accion.nombre())
        .bind(&e.detalle)
        .bind(&e.anterior)
        .bind(&e.resumen)
        .execute(&mut **tx)
        .await
        .map_err(fallo)?;
        Ok(())
    }

    async fn avisar_cuarentena(tx: &mut Transaction<'static, Postgres>) -> Result<(), ErrorPaso> {
        sqlx::query("SELECT pg_notify($1, '')")
            .bind(CANAL_CUARENTENA)
            .execute(&mut **tx)
            .await
            .map_err(fallo)?;
        Ok(())
    }

    fn motivo_bloqueo(&self) -> String {
        format!("flujo de respuesta, ejecucion {}", self.ejecucion)
    }
}

impl Puertos for PuertosPg {
    fn actor(&self) -> &str {
        &self.actor
    }

    fn ejecucion(&self) -> &str {
        &self.ejecucion
    }

    fn aislar<'a>(
        &'a self,
        cn: &'a str,
        orden: uuid::Uuid,
    ) -> Fut<'a, Result<PrevioAislamiento, ErrorPaso>> {
        Box::pin(async move {
            let mut tx = self.tx().await?;
            let aislado: Option<bool> =
                sqlx::query_scalar("SELECT aislado FROM agentes WHERE cn = $1 FOR UPDATE")
                    .bind(cn)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(fallo)?;
            let Some(aislado) = aislado else {
                return Err(ErrorPaso::Entrada(format!(
                    "la maquina {cn} no esta en la flota"
                )));
            };
            // ¿Lo aislo esta misma ejecucion en un intento anterior? Entonces no
            // «ya estaba»: es nuestro, y revertir tiene que liberarla.
            let nuestra: Option<bool> =
                sqlx::query_scalar("SELECT TRUE FROM comandos WHERE id = $1")
                    .bind(orden)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(fallo)?;
            if aislado && nuestra.is_none() {
                tx.commit().await.map_err(fallo)?;
                return Ok(PrevioAislamiento {
                    cn: cn.to_string(),
                    ya_estaba: true,
                    orden: None,
                });
            }
            sqlx::query("UPDATE agentes SET aislado = TRUE, aislado_en = COALESCE(aislado_en, now()) WHERE cn = $1")
                .bind(cn)
                .execute(&mut *tx)
                .await
                .map_err(fallo)?;
            self.encolar(
                &mut tx,
                orden,
                cn,
                "aislar",
                serde_json::json!({"motivo": "flujo de respuesta", "ejecucion": self.ejecucion}),
            )
            .await?;
            tx.commit().await.map_err(fallo)?;
            Ok(PrevioAislamiento {
                cn: cn.to_string(),
                ya_estaba: false,
                orden: Some(orden),
            })
        })
    }

    fn deshacer_aislamiento(&self, previo: PrevioAislamiento) -> Fut<'_, Result<(), ErrorPaso>> {
        Box::pin(async move {
            let (false, Some(orden)) = (previo.ya_estaba, previo.orden) else {
                return Ok(());
            };
            let mut tx = self.tx().await?;
            self.deshacer_orden(
                &mut tx,
                &previo.cn,
                orden,
                "liberar",
                serde_json::json!({"motivo": "reversion de flujo", "ejecucion": self.ejecucion}),
            )
            .await?;
            sqlx::query("UPDATE agentes SET aislado = FALSE, aislado_en = NULL WHERE cn = $1")
                .bind(&previo.cn)
                .execute(&mut *tx)
                .await
                .map_err(fallo)?;
            tx.commit().await.map_err(fallo)
        })
    }

    fn matar<'a>(
        &'a self,
        p: &'a LocProceso,
        orden: uuid::Uuid,
    ) -> Fut<'a, Result<OrdenAgente, ErrorPaso>> {
        Box::pin(async move {
            let mut tx = self.tx().await?;
            // El proceso va identificado entero: un «matar el pid 4242» sin el
            // instante de arranque mataria a quien tenga ese pid cuando llegue
            // la orden, que puede ser otro.
            self.encolar(
                &mut tx,
                orden,
                &p.maquina,
                "matar_proceso",
                serde_json::json!({"boot": p.boot, "pid": p.pid, "arranque_ns": p.arranque_ns}),
            )
            .await?;
            tx.commit().await.map_err(fallo)?;
            Ok(OrdenAgente {
                cn: p.maquina.clone(),
                orden,
            })
        })
    }

    fn cuarentena<'a>(
        &'a self,
        f: &'a LocFichero,
        orden: uuid::Uuid,
    ) -> Fut<'a, Result<OrdenAgente, ErrorPaso>> {
        Box::pin(async move {
            let mut tx = self.tx().await?;
            self.encolar(
                &mut tx,
                orden,
                &f.maquina,
                "cuarentena_fichero",
                serde_json::json!({"ruta": f.ruta}),
            )
            .await?;
            tx.commit().await.map_err(fallo)?;
            Ok(OrdenAgente {
                cn: f.maquina.clone(),
                orden,
            })
        })
    }

    fn restaurar<'a>(
        &'a self,
        f: &'a LocFichero,
        o: OrdenAgente,
    ) -> Fut<'a, Result<(), ErrorPaso>> {
        Box::pin(async move {
            let mut tx = self.tx().await?;
            self.deshacer_orden(
                &mut tx,
                &o.cn,
                o.orden,
                "restaurar_fichero",
                serde_json::json!({"ruta": f.ruta}),
            )
            .await?;
            tx.commit().await.map_err(fallo)
        })
    }

    fn revocar_tickets<'a>(
        &'a self,
        cuenta: &'a str,
        orden: uuid::Uuid,
    ) -> Fut<'a, Result<uuid::Uuid, ErrorPaso>> {
        Box::pin(async move {
            sqlx::query(
                r#"INSERT INTO ordenes_directorio (id, cuenta, accion, ordenada_por)
                   VALUES ($1, $2, 'revocar_tickets', $3)
                   ON CONFLICT (id) DO NOTHING"#,
            )
            .bind(orden)
            .bind(cuenta)
            .bind(&self.actor)
            .execute(&self.pool)
            .await
            .map_err(fallo)?;
            Ok(orden)
        })
    }

    fn deshabilitar<'a>(
        &'a self,
        cuenta: &'a str,
        orden: uuid::Uuid,
    ) -> Fut<'a, Result<PrevioCuenta, ErrorPaso>> {
        Box::pin(async move {
            let mut tx = self.tx().await?;
            let fila = sqlx::query(
                "SELECT orden, rehabilitada_en IS NULL AS vigente FROM cuentas_deshabilitadas WHERE cuenta = $1 FOR UPDATE",
            )
            .bind(cuenta)
            .fetch_optional(&mut *tx)
            .await
            .map_err(fallo)?;
            if let Some(f) = &fila {
                let vigente: bool = f.get("vigente");
                let suya: uuid::Uuid = f.get("orden");
                if vigente {
                    tx.commit().await.map_err(fallo)?;
                    return Ok(PrevioCuenta {
                        cuenta: cuenta.to_string(),
                        // Si la deshabilito ESTA ejecucion en un intento
                        // anterior, es nuestra.
                        ya_estaba: suya != orden,
                    });
                }
            }
            sqlx::query(
                r#"INSERT INTO cuentas_deshabilitadas (cuenta, orden, ordenada_por)
                   VALUES ($1, $2, $3)
                   ON CONFLICT (cuenta) DO UPDATE SET
                       orden = EXCLUDED.orden, ordenada_por = EXCLUDED.ordenada_por,
                       ordenada_en = now(), rehabilitada_en = NULL, rehabilitada_por = NULL"#,
            )
            .bind(cuenta)
            .bind(orden)
            .bind(&self.actor)
            .execute(&mut *tx)
            .await
            .map_err(fallo)?;
            sqlx::query(
                r#"INSERT INTO ordenes_directorio (id, cuenta, accion, ordenada_por)
                   VALUES ($1, $2, 'deshabilitar', $3) ON CONFLICT (id) DO NOTHING"#,
            )
            .bind(orden)
            .bind(cuenta)
            .bind(&self.actor)
            .execute(&mut *tx)
            .await
            .map_err(fallo)?;
            tx.commit().await.map_err(fallo)?;
            Ok(PrevioCuenta {
                cuenta: cuenta.to_string(),
                ya_estaba: false,
            })
        })
    }

    fn rehabilitar(&self, previo: PrevioCuenta) -> Fut<'_, Result<(), ErrorPaso>> {
        Box::pin(async move {
            if previo.ya_estaba {
                return Ok(());
            }
            let mut tx = self.tx().await?;
            let hecho = sqlx::query(
                r#"UPDATE cuentas_deshabilitadas
                      SET rehabilitada_en = now(), rehabilitada_por = $2
                    WHERE cuenta = $1 AND rehabilitada_en IS NULL"#,
            )
            .bind(&previo.cuenta)
            .bind(&self.actor)
            .execute(&mut *tx)
            .await
            .map_err(fallo)?
            .rows_affected();
            if hecho > 0 {
                sqlx::query(
                    r#"INSERT INTO ordenes_directorio (id, cuenta, accion, ordenada_por)
                       VALUES ($1, $2, 'rehabilitar', $3) ON CONFLICT (id) DO NOTHING"#,
                )
                .bind(self.id_efecto("rehabilitar", &previo.cuenta))
                .bind(&previo.cuenta)
                .bind(&self.actor)
                .execute(&mut *tx)
                .await
                .map_err(fallo)?;
            }
            tx.commit().await.map_err(fallo)
        })
    }

    fn maquinas_en(&self, red: ipnet::IpNet) -> Fut<'_, Result<Vec<String>, ErrorPaso>> {
        Box::pin(async move {
            sqlx::query_scalar("SELECT cn FROM agentes WHERE direccion_vista <<= $1 ORDER BY cn")
                .bind(red)
                .fetch_all(&self.pool)
                .await
                .map_err(fallo)
        })
    }

    fn bloquear(&self, red: ipnet::IpNet) -> Fut<'_, Result<PrevioBloqueo, ErrorPaso>> {
        Box::pin(async move {
            let mut tx = self.tx().await?;
            let fila = sqlx::query(
                r#"SELECT cn_origen, motivo, ordenada_por,
                          (extract(epoch FROM ordenada_en) * 1000000)::bigint AS ordenada_us,
                          (extract(epoch FROM expira_en) * 1000000)::bigint AS expira_us,
                          (extract(epoch FROM levantada_en) * 1000000)::bigint AS levantada_us,
                          levantada_por,
                          levantada_en IS NULL AND (expira_en IS NULL OR expira_en > now()) AS vigente
                     FROM cuarentena WHERE direccion = $1 FOR UPDATE"#,
            )
            .bind(red)
            .fetch_optional(&mut *tx)
            .await
            .map_err(fallo)?;
            let motivo = self.motivo_bloqueo();
            let previo = match fila {
                None => PrevioBloqueo::Nuevo(red),
                Some(f) => {
                    let vigente: bool = f.get("vigente");
                    let fila = FilaBloqueo {
                        cn_origen: f.get("cn_origen"),
                        motivo: f.get("motivo"),
                        ordenada_por: f.get("ordenada_por"),
                        ordenada_us: f.get("ordenada_us"),
                        expira_us: f.get("expira_us"),
                        levantada_us: f.get("levantada_us"),
                        levantada_por: f.get("levantada_por"),
                    };
                    if vigente && fila.motivo == motivo {
                        // Un intento anterior de esta misma ejecucion.
                        tx.commit().await.map_err(fallo)?;
                        return Ok(PrevioBloqueo::Nuevo(red));
                    }
                    if vigente {
                        tx.commit().await.map_err(fallo)?;
                        return Ok(PrevioBloqueo::YaVigente(red));
                    }
                    PrevioBloqueo::Levantado { red, fila }
                }
            };
            sqlx::query(
                r#"INSERT INTO cuarentena (direccion, cn_origen, motivo, ordenada_por, expira_en)
                   VALUES ($1, NULL, $2, $3, NULL)
                   ON CONFLICT (direccion) DO UPDATE SET
                       cn_origen = NULL, motivo = EXCLUDED.motivo, ordenada_por = EXCLUDED.ordenada_por,
                       ordenada_en = now(), expira_en = NULL, levantada_en = NULL, levantada_por = NULL"#,
            )
            .bind(red)
            .bind(&motivo)
            .bind(&self.actor)
            .execute(&mut *tx)
            .await
            .map_err(fallo)?;
            Self::avisar_cuarentena(&mut tx).await?;
            tx.commit().await.map_err(fallo)?;
            Ok(previo)
        })
    }

    fn restaurar_bloqueo(&self, previo: PrevioBloqueo) -> Fut<'_, Result<(), ErrorPaso>> {
        Box::pin(async move {
            let mut tx = self.tx().await?;
            match previo {
                PrevioBloqueo::YaVigente(_) => return Ok(()),
                PrevioBloqueo::Nuevo(red) => {
                    // Se levanta marcando, como la consola: queda quien y cuando.
                    sqlx::query(
                        r#"UPDATE cuarentena SET levantada_en = now(), levantada_por = $2
                            WHERE direccion = $1 AND levantada_en IS NULL"#,
                    )
                    .bind(red)
                    .bind(&self.actor)
                    .execute(&mut *tx)
                    .await
                    .map_err(fallo)?;
                }
                PrevioBloqueo::Levantado { red, fila } => {
                    // La fila vuelve a ser EXACTAMENTE la de antes.
                    sqlx::query(
                        r#"UPDATE cuarentena SET
                               cn_origen = $2, motivo = $3, ordenada_por = $4,
                               ordenada_en = TIMESTAMPTZ 'epoch' + $5::bigint * INTERVAL '1 microsecond',
                               expira_en = TIMESTAMPTZ 'epoch' + $6::bigint * INTERVAL '1 microsecond',
                               levantada_en = TIMESTAMPTZ 'epoch' + $7::bigint * INTERVAL '1 microsecond',
                               levantada_por = $8
                             WHERE direccion = $1"#,
                    )
                    .bind(red)
                    .bind(&fila.cn_origen)
                    .bind(&fila.motivo)
                    .bind(&fila.ordenada_por)
                    .bind(fila.ordenada_us)
                    .bind(fila.expira_us)
                    .bind(fila.levantada_us)
                    .bind(&fila.levantada_por)
                    .execute(&mut *tx)
                    .await
                    .map_err(fallo)?;
                }
            }
            Self::avisar_cuarentena(&mut tx).await?;
            tx.commit().await.map_err(fallo)
        })
    }

    fn abrir_caso<'a>(
        &'a self,
        id: &'a str,
        titulo: &'a str,
        severidad: &'a str,
        detalle: &'a str,
        implicados: &'a [Eid],
    ) -> Fut<'a, Result<CasoAbierto, ErrorPaso>> {
        Box::pin(async move {
            let mut tx = self.tx().await?;
            let nuevo = sqlx::query(
                r#"INSERT INTO casos (id, inquilino, titulo, estado, severidad, abierto_en)
                   VALUES ($1, $2, $3, 'nuevo', $4, now())
                   ON CONFLICT (id) DO NOTHING"#,
            )
            .bind(id)
            .bind(&self.inquilino)
            .bind(titulo)
            .bind(severidad)
            .execute(&mut *tx)
            .await
            .map_err(fallo)?
            .rows_affected()
                > 0;
            if nuevo {
                for e in implicados {
                    sqlx::query(
                        "INSERT INTO caso_observables (caso, tipo, valor) VALUES ($1, 'entidad', $2) ON CONFLICT DO NOTHING",
                    )
                    .bind(id)
                    .bind(e.texto())
                    .execute(&mut *tx)
                    .await
                    .map_err(fallo)?;
                }
                Self::anotar_caso(
                    &mut tx,
                    id,
                    &self.actor,
                    Accion::Creado,
                    &format!(
                        "abierto por el flujo de respuesta (ejecucion {}): {detalle}",
                        self.ejecucion
                    ),
                )
                .await?;
            }
            tx.commit().await.map_err(fallo)?;
            Ok(CasoAbierto {
                id: id.to_string(),
                ya_existia: !nuevo,
            })
        })
    }

    fn cerrar_caso_revertido(&self, caso: CasoAbierto) -> Fut<'_, Result<(), ErrorPaso>> {
        Box::pin(async move {
            let mut tx = self.tx().await?;
            let estado: Option<String> =
                sqlx::query_scalar("SELECT estado FROM casos WHERE id = $1 FOR UPDATE")
                    .bind(&caso.id)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(fallo)?;
            // Un caso no se borra —su rastro lo impide, a proposito—: se cierra
            // como no concluyente diciendo por que. Si una persona ya lo cerro,
            // se respeta su veredicto.
            if estado.as_deref().is_some_and(|e| e != "cerrado") {
                let justificacion = format!(
                    "el flujo de respuesta que lo abrio (ejecucion {}) se revirtio",
                    self.ejecucion
                );
                sqlx::query(
                    r#"UPDATE casos SET estado = 'cerrado', veredicto = 'no-concluyente',
                              justificacion_cierre = $2, cerrado_en = now()
                        WHERE id = $1"#,
                )
                .bind(&caso.id)
                .bind(&justificacion)
                .execute(&mut *tx)
                .await
                .map_err(fallo)?;
                Self::anotar_caso(
                    &mut tx,
                    &caso.id,
                    &self.actor,
                    Accion::Cerrado,
                    &justificacion,
                )
                .await?;
            }
            tx.commit().await.map_err(fallo)
        })
    }

    fn enriquecer<'a>(&'a self, sha256: &'a str) -> Fut<'a, Result<Enriquecimiento, ErrorPaso>> {
        Box::pin(async move {
            let sha = sha256.trim().to_ascii_lowercase();
            // Se valida ANTES de usarlo en un LIKE: un «hash» con % o _ seria un
            // patron, no un valor.
            if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(ErrorPaso::Entrada(format!("«{sha256}» no es un SHA-256")));
            }
            let maquinas: Vec<String> = sqlx::query_scalar(
                "SELECT DISTINCT cn_agente FROM alertas WHERE lower(detalles->>'sha256') = $1 ORDER BY cn_agente",
            )
            .bind(&sha)
            .fetch_all(&self.pool)
            .await
            .map_err(fallo)?;
            let alertas: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM alertas WHERE lower(detalles->>'sha256') = $1",
            )
            .bind(&sha)
            .fetch_one(&self.pool)
            .await
            .map_err(fallo)?;
            let inteligencia: Vec<String> = sqlx::query_scalar(
                "SELECT id FROM stix_objetos WHERE lower(contenido::text) LIKE '%' || $1 || '%' ORDER BY id LIMIT 100",
            )
            .bind(&sha)
            .fetch_all(&self.pool)
            .await
            .map_err(fallo)?;
            Ok(Enriquecimiento {
                sha256: sha,
                maquinas,
                alertas,
                inteligencia,
            })
        })
    }

    fn notificar<'a>(
        &'a self,
        id: uuid::Uuid,
        destino: &'a str,
        texto: &'a str,
    ) -> Fut<'a, Result<Notificacion, ErrorPaso>> {
        Box::pin(async move {
            let nueva = sqlx::query(
                r#"INSERT INTO notificaciones (id, destino, texto, creada_por)
                   VALUES ($1, $2, $3, $4) ON CONFLICT (id) DO NOTHING"#,
            )
            .bind(id)
            .bind(destino)
            .bind(texto)
            .bind(&self.actor)
            .execute(&self.pool)
            .await
            .map_err(fallo)?
            .rows_affected()
                > 0;
            Ok(Notificacion {
                id,
                ya_existia: !nueva,
            })
        })
    }

    fn anular_notificacion(&self, n: Notificacion) -> Fut<'_, Result<(), ErrorPaso>> {
        Box::pin(async move {
            let mut tx = self.tx().await?;
            let anulada = sqlx::query(
                r#"UPDATE notificaciones SET anulada_en = now()
                    WHERE id = $1 AND enviada_en IS NULL AND anulada_en IS NULL"#,
            )
            .bind(n.id)
            .execute(&mut *tx)
            .await
            .map_err(fallo)?
            .rows_affected();
            if anulada == 0 {
                // Ya salio: se rectifica, referenciandola.
                sqlx::query(
                    r#"INSERT INTO notificaciones (id, destino, texto, creada_por, rectifica)
                       SELECT $2, destino, 'RECTIFICACION: la respuesta automatica notificada se revirtio', $3, id
                         FROM notificaciones WHERE id = $1 AND enviada_en IS NOT NULL
                       ON CONFLICT (id) DO NOTHING"#,
                )
                .bind(n.id)
                .bind(self.id_efecto("rectificar", &n.id.to_string()))
                .bind(&self.actor)
                .execute(&mut *tx)
                .await
                .map_err(fallo)?;
            }
            tx.commit().await.map_err(fallo)
        })
    }
}
