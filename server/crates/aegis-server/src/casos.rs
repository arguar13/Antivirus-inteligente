//! Persistencia del ciclo de vida del incidente.
//!
//! # Donde encaja
//!
//! [`aegis_case`] tiene la logica entera —fusion, transiciones, cronologia,
//! rastro encadenado, metricas— como funciones puras, sin base de datos y sin
//! red. Este modulo es lo que la pone en PostgreSQL.
//!
//! La separacion no es estetica: permite probar mil alertas de una campana y un
//! rastro manipulado en milisegundos, y deja aqui solo lo que de verdad necesita
//! una base de datos.
//!
//! # La regla de escritura, que es toda la correccion del rastro
//!
//! ```text
//!   1. se calcula la entrada del rastro EN MEMORIA, enganchada a la cabeza
//!   2. se abre una transaccion
//!   3. se escribe el cambio del caso
//!   4. se escribe la entrada del rastro
//!   5. se confirma
//! ```
//!
//! Los pasos 3 y 4 van **en la misma transaccion**, y eso no es negociable: un
//! cambio de caso sin su entrada de rastro es exactamente el agujero que el
//! rastro existe para cerrar, y ocurriria en cada corte de red entre las dos
//! escrituras.
//!
//! Y la cabeza se lee **dentro** de la transaccion, con bloqueo de fila sobre el
//! caso. Sin el bloqueo, dos analistas que actuan a la vez calculan la misma
//! cabeza, escriben dos entradas con la misma `anterior`, y **la cadena se
//! bifurca**: las dos son validas por separado y ninguna incluye a la otra. El
//! indice unico sobre el resumen lo convierte en un error en vez de en una
//! bifurcacion silenciosa, pero el bloqueo es lo que hace que ni siquiera se
//! intente.

use aegis_case::auditoria::{Accion, Entrada, Rastro, Rotura};
use aegis_case::metricas::{self, Resumen};
use aegis_case::modelo::{Alerta, Caso, Estado, Observable, Severidad, Tarea, Veredicto};
use aegis_case::plantillas;
use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};

use crate::almacen::Almacen;
use crate::error::{ErrorServidor, Resultado};

/// Casos que se listan como maximo de una vez.
pub const MAX_LISTADO: i64 = 500;

/// Vista de un caso para el panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VistaCaso {
    /// Identificador.
    pub id: String,
    /// Inquilino.
    pub inquilino: String,
    /// Titulo.
    pub titulo: String,
    /// Estado.
    pub estado: String,
    /// Gravedad.
    pub severidad: String,
    /// Clase de incidente deducida.
    pub clase: String,
    /// Quien lo lleva.
    pub asignado_a: Option<String>,
    /// Cuando empezo lo mas antiguo.
    pub abierto_en: DateTime<Utc>,
    /// Cuando se cerro.
    pub cerrado_en: Option<DateTime<Utc>>,
    /// Con que se cerro.
    pub veredicto: Option<String>,
    /// Alertas fusionadas.
    pub alertas: i64,
    /// Tareas que siguen abiertas.
    pub tareas_abiertas: i64,
    /// Tecnicas de ATT&CK vistas.
    pub tecnicas: Vec<String>,
}

/// Vista de una entrada del rastro.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VistaAuditoria {
    /// Posicion en la cadena.
    pub secuencia: i64,
    /// Quien.
    pub actor: String,
    /// Que.
    pub accion: String,
    /// Detalle.
    pub detalle: String,
    /// Cuando.
    pub cuando: DateTime<Utc>,
    /// Resumen de esta entrada.
    pub resumen: String,
}

/// El veredicto de comprobar un rastro.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Integridad {
    /// Caso.
    pub caso: String,
    /// Entradas del rastro.
    pub entradas: i64,
    /// Si la cadena cuadra.
    pub intacto: bool,
    /// Las roturas, en texto legible.
    ///
    /// Se devuelven **todas**: quien manipula un rastro suele tocar varias cosas,
    /// y parar en la primera esconde el resto.
    pub roturas: Vec<String>,
    /// Hasta donde llega el ultimo anclaje publicado.
    ///
    /// Es la frontera de lo que ya no se puede reescribir sin que se note: por
    /// debajo, inmutable; por encima, detectable.
    pub anclado_hasta: i64,
}

/// El servicio de casos.
pub struct ServicioCasos {
    pool: PgPool,
}

impl ServicioCasos {
    /// Crea el servicio sobre el mismo almacen del resto del plano de control.
    #[must_use]
    pub fn nuevo(almacen: &Almacen) -> ServicioCasos {
        ServicioCasos {
            pool: almacen.pool().clone(),
        }
    }

    /// Abre un caso a partir de una alerta, o la fusiona en uno existente.
    ///
    /// La decision de fusion la toma [`aegis_case::fusion`] sobre los casos
    /// abiertos del inquilino. Se consultan **solo los abiertos y solo los de su
    /// inquilino**: lo primero porque un caso cerrado no absorbe —si lo hiciera,
    /// una alerta nueva entraria en un caso que ya tiene veredicto y nadie
    /// volveria a mirarla—, y lo segundo porque es la invariante de aislamiento.
    pub async fn admitir(&self, alerta: Alerta, actor: &str) -> Resultado<String> {
        let candidatos = self.abiertos_de(&alerta.inquilino).await?;
        let mut f = aegis_case::fusion::Fusionador::nuevo();
        for c in candidatos {
            f.adoptar(c);
        }
        let decision = f.admitir(alerta.clone());
        let caso = &f.casos()[decision.caso];

        let mut tx = self.pool.begin().await?;
        if decision.nuevo {
            let clase = plantillas::clasificar(caso).nombre();
            sqlx::query(
                r#"INSERT INTO casos
                     (id, inquilino, titulo, estado, severidad, clase, abierto_en, tecnicas)
                   VALUES ($1, $2, $3, 'nuevo', $4, $5, $6, $7)
                   ON CONFLICT (id) DO NOTHING"#,
            )
            .bind(&caso.id)
            .bind(&caso.inquilino)
            .bind(&caso.titulo)
            .bind(caso.severidad.nombre())
            .bind(clase)
            .bind(de_ns(caso.abierto_ns))
            .bind(&caso.tecnicas)
            .execute(&mut *tx)
            .await?;
        } else {
            // La gravedad del caso es la MAYOR de sus alertas y nunca baja: un
            // caso que empieza con un hallazgo critico y sigue con cien
            // informativos no se vuelve informativo, aunque el promedio lo diga.
            let clase = plantillas::clasificar(caso).nombre();
            sqlx::query(
                r#"UPDATE casos
                      SET severidad = $2, clase = $3, tecnicas = $4,
                          abierto_en = LEAST(abierto_en, $5)
                    WHERE id = $1"#,
            )
            .bind(&caso.id)
            .bind(caso.severidad.nombre())
            .bind(clase)
            .bind(&caso.tecnicas)
            .bind(de_ns(caso.abierto_ns))
            .execute(&mut *tx)
            .await?;
        }

        sqlx::query(
            r#"INSERT INTO caso_alertas
                 (caso, alerta, motivo, regla, anfitrion, sujeto, tecnica, ocurrio_en)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
               ON CONFLICT (caso, alerta) DO NOTHING"#,
        )
        .bind(&caso.id)
        .bind(&alerta.id)
        .bind(decision.motivo.nombre())
        .bind(&alerta.regla)
        .bind(&alerta.anfitrion)
        .bind(&alerta.sujeto)
        .bind(alerta.tecnica.as_deref())
        .bind(de_ns(alerta.ocurrio_ns))
        .execute(&mut *tx)
        .await?;

        for o in &alerta.observables {
            sqlx::query(
                r#"INSERT INTO caso_observables (caso, tipo, valor) VALUES ($1, $2, $3)
                   ON CONFLICT DO NOTHING"#,
            )
            .bind(&caso.id)
            .bind(o.tipo())
            .bind(o.valor())
            .execute(&mut *tx)
            .await?;
        }

        let accion = if decision.nuevo {
            Accion::Creado
        } else {
            Accion::AlertaFusionada
        };
        let detalle = format!(
            "alerta {} ({}) por {}",
            alerta.id,
            alerta.regla,
            decision.motivo.nombre()
        );
        anotar_en(
            &mut tx,
            &caso.id,
            actor,
            accion,
            &detalle,
            alerta.ocurrio_ns,
        )
        .await?;
        tx.commit().await?;
        Ok(caso.id.clone())
    }

    /// Casos abiertos de un inquilino, con lo que hace falta para fusionar.
    async fn abiertos_de(&self, inquilino: &str) -> Resultado<Vec<Caso>> {
        let filas = sqlx::query(
            r#"SELECT c.id, c.inquilino, c.titulo, c.estado, c.severidad,
                      c.abierto_en, c.tecnicas
                 FROM casos c
                WHERE c.inquilino = $1 AND c.estado <> 'cerrado'
                ORDER BY c.abierto_en DESC LIMIT 200"#,
        )
        .bind(inquilino)
        .fetch_all(&self.pool)
        .await?;

        let mut salida = Vec::with_capacity(filas.len());
        for f in filas {
            let id: String = f.get("id");
            let alertas = sqlx::query(
                r#"SELECT alerta, regla, anfitrion, sujeto, tecnica, ocurrio_en
                     FROM caso_alertas WHERE caso = $1 ORDER BY ocurrio_en"#,
            )
            .bind(&id)
            .fetch_all(&self.pool)
            .await?;
            let Some(primera) = alertas.first() else {
                continue;
            };
            let severidad = severidad_de(&f.get::<String, _>("severidad"));
            let mut caso = Caso::abrir(id.clone(), alerta_de(primera, inquilino, severidad));
            for a in alertas.iter().skip(1) {
                caso.absorber(alerta_de(a, inquilino, severidad));
            }
            caso.estado = estado_de(&f.get::<String, _>("estado"));
            caso.severidad = severidad;
            caso.titulo = f.get("titulo");
            salida.push(caso);
        }
        Ok(salida)
    }

    /// Cambia el estado de un caso, validando la transicion.
    ///
    /// Devuelve el motivo legible cuando la transicion no es valida. Legible
    /// importa: el analista lo va a leer en el panel a las tres de la manana.
    pub async fn pasar_a(&self, caso: &str, nuevo: Estado, actor: &str) -> Resultado<()> {
        let mut tx = self.pool.begin().await?;
        let actual: String =
            sqlx::query_scalar("SELECT estado FROM casos WHERE id = $1 FOR UPDATE")
                .bind(caso)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(|| ErrorServidor::Config(format!("el caso {caso} no existe")))?;
        let actual = estado_de(&actual);
        if !actual.puede_pasar_a(nuevo) {
            return Err(ErrorServidor::Config(format!(
                "un caso {} no puede pasar a {}",
                actual.nombre(),
                nuevo.nombre()
            )));
        }
        if nuevo == Estado::Cerrado {
            return Err(ErrorServidor::Config(
                "para cerrar un caso hay que usar `cerrar`, que exige veredicto".into(),
            ));
        }
        let ahora = Utc::now();
        sqlx::query(
            r#"UPDATE casos
                  SET estado = $2,
                      primer_vistazo_en = CASE WHEN $2 = 'en-curso'
                                               THEN COALESCE(primer_vistazo_en, $3)
                                               ELSE primer_vistazo_en END,
                      contenido_en = CASE WHEN $2 = 'contenido'
                                          THEN COALESCE(contenido_en, $3)
                                          ELSE contenido_en END,
                      cerrado_en = NULL, veredicto = NULL, justificacion_cierre = NULL
                WHERE id = $1"#,
        )
        .bind(caso)
        .bind(nuevo.nombre())
        .bind(ahora)
        .execute(&mut *tx)
        .await?;
        let accion = if actual == Estado::Cerrado {
            Accion::Reabierto
        } else {
            Accion::CambioDeEstado
        };
        let detalle = format!("de {} a {}", actual.nombre(), nuevo.nombre());
        anotar_en(&mut tx, caso, actor, accion, &detalle, a_ns(ahora)).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Cierra un caso con veredicto.
    ///
    /// Con tareas abiertas exige justificacion: no es proceso, es la diferencia
    /// entre «se investigo y no era nada» y «nadie llego a mirarlo», que acaban
    /// igual en el panel y no son lo mismo.
    pub async fn cerrar(
        &self,
        caso: &str,
        veredicto: Veredicto,
        justificacion: Option<String>,
        actor: &str,
    ) -> Resultado<()> {
        let mut tx = self.pool.begin().await?;
        let estado: String =
            sqlx::query_scalar("SELECT estado FROM casos WHERE id = $1 FOR UPDATE")
                .bind(caso)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or_else(|| ErrorServidor::Config(format!("el caso {caso} no existe")))?;
        if estado == "cerrado" {
            return Err(ErrorServidor::Config("el caso ya estaba cerrado".into()));
        }
        let abiertas: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM caso_tareas WHERE caso = $1 AND estado = 'pendiente'",
        )
        .bind(caso)
        .fetch_one(&mut *tx)
        .await?;
        let justificacion = justificacion.filter(|j| !j.trim().is_empty());
        if abiertas > 0 && justificacion.is_none() {
            return Err(ErrorServidor::Config(format!(
                "quedan {abiertas} tarea(s) abierta(s): para cerrar sin hacerlas hay que escribir \
                 por que"
            )));
        }
        let ahora = Utc::now();
        sqlx::query(
            r#"UPDATE casos SET estado = 'cerrado', veredicto = $2,
                                justificacion_cierre = $3, cerrado_en = $4
                WHERE id = $1"#,
        )
        .bind(caso)
        .bind(veredicto.nombre())
        .bind(justificacion.as_deref())
        .bind(ahora)
        .execute(&mut *tx)
        .await?;
        let detalle = match &justificacion {
            Some(j) => format!("{} — {j}", veredicto.nombre()),
            None => veredicto.nombre().to_string(),
        };
        anotar_en(&mut tx, caso, actor, Accion::Cerrado, &detalle, a_ns(ahora)).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Anade una tarea.
    pub async fn anadir_tarea(&self, caso: &str, titulo: &str, actor: &str) -> Resultado<i32> {
        let mut tx = self.pool.begin().await?;
        let siguiente: i32 =
            sqlx::query_scalar("SELECT COALESCE(max(id), 0) + 1 FROM caso_tareas WHERE caso = $1")
                .bind(caso)
                .fetch_one(&mut *tx)
                .await?;
        sqlx::query("INSERT INTO caso_tareas (caso, id, titulo) VALUES ($1, $2, $3)")
            .bind(caso)
            .bind(siguiente)
            .bind(titulo)
            .execute(&mut *tx)
            .await?;
        let ahora = Utc::now();
        anotar_en(
            &mut tx,
            caso,
            actor,
            Accion::TareaCreada,
            &format!("#{siguiente} {titulo}"),
            a_ns(ahora),
        )
        .await?;
        tx.commit().await?;
        Ok(siguiente)
    }

    /// Cierra una tarea.
    pub async fn cerrar_tarea(
        &self,
        caso: &str,
        tarea: i32,
        motivo: Option<String>,
        actor: &str,
    ) -> Resultado<()> {
        let mut tx = self.pool.begin().await?;
        let estado = if motivo.is_some() {
            "descartada"
        } else {
            "hecha"
        };
        let n = sqlx::query(
            r#"UPDATE caso_tareas SET estado = $3, motivo = $4
                WHERE caso = $1 AND id = $2 AND estado = 'pendiente'"#,
        )
        .bind(caso)
        .bind(tarea)
        .bind(estado)
        .bind(motivo.as_deref())
        .execute(&mut *tx)
        .await?;
        if n.rows_affected() == 0 {
            return Err(ErrorServidor::Config(format!(
                "la tarea {tarea} no existe o ya estaba cerrada"
            )));
        }
        let ahora = Utc::now();
        anotar_en(
            &mut tx,
            caso,
            actor,
            Accion::TareaCerrada,
            &format!("#{tarea} {estado}"),
            a_ns(ahora),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Deja constancia de que alguien leyo el caso.
    ///
    /// Se registra porque «quien vio que» es parte de la pregunta que un rastro
    /// tiene que contestar, y porque el acceso a informacion personal se audita
    /// por obligacion en cualquier regimen de proteccion de datos.
    pub async fn consultado(&self, caso: &str, actor: &str) -> Resultado<()> {
        let mut tx = self.pool.begin().await?;
        let ahora = Utc::now();
        anotar_en(&mut tx, caso, actor, Accion::Consultado, "", a_ns(ahora)).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Lista casos.
    pub async fn listar(&self, inquilino: Option<&str>, limite: i64) -> Resultado<Vec<VistaCaso>> {
        let limite = limite.clamp(1, MAX_LISTADO);
        let filas = sqlx::query(
            r#"SELECT c.id, c.inquilino, c.titulo, c.estado, c.severidad, c.clase,
                      c.asignado_a, c.abierto_en, c.cerrado_en, c.veredicto, c.tecnicas,
                      (SELECT count(*) FROM caso_alertas a WHERE a.caso = c.id) AS alertas,
                      (SELECT count(*) FROM caso_tareas t
                        WHERE t.caso = c.id AND t.estado = 'pendiente') AS tareas_abiertas
                 FROM casos c
                WHERE ($1::text IS NULL OR c.inquilino = $1)
                ORDER BY c.abierto_en DESC LIMIT $2"#,
        )
        .bind(inquilino)
        .bind(limite)
        .fetch_all(&self.pool)
        .await?;
        Ok(filas
            .iter()
            .map(|f| VistaCaso {
                id: f.get("id"),
                inquilino: f.get("inquilino"),
                titulo: f.get("titulo"),
                estado: f.get("estado"),
                severidad: f.get("severidad"),
                clase: f.get("clase"),
                asignado_a: f.try_get("asignado_a").ok().flatten(),
                abierto_en: f.get("abierto_en"),
                cerrado_en: f.try_get("cerrado_en").ok().flatten(),
                veredicto: f.try_get("veredicto").ok().flatten(),
                alertas: f.get("alertas"),
                tareas_abiertas: f.get("tareas_abiertas"),
                tecnicas: f.get("tecnicas"),
            })
            .collect())
    }

    /// El rastro de un caso.
    pub async fn rastro(&self, caso: &str) -> Resultado<Vec<VistaAuditoria>> {
        let filas = sqlx::query(
            r#"SELECT secuencia, actor, accion, detalle, cuando, resumen
                 FROM caso_auditoria WHERE caso = $1 ORDER BY secuencia"#,
        )
        .bind(caso)
        .fetch_all(&self.pool)
        .await?;
        Ok(filas
            .iter()
            .map(|f| VistaAuditoria {
                secuencia: f.get("secuencia"),
                actor: f.get("actor"),
                accion: f.get("accion"),
                detalle: f.get("detalle"),
                cuando: f.get("cuando"),
                resumen: f.get("resumen"),
            })
            .collect())
    }

    /// Comprueba la integridad del rastro de un caso.
    ///
    /// Recalcula la cadena entera en memoria y la compara con lo que hay en
    /// disco. Que esto sea una operacion que se pueda pedir desde el panel es
    /// parte del valor: un rastro que solo se comprueba cuando alguien sospecha
    /// es un rastro que nadie comprueba.
    pub async fn verificar(&self, caso: &str) -> Resultado<Integridad> {
        let filas = sqlx::query(
            r#"SELECT secuencia, actor, accion, detalle, cuando, anterior, resumen
                 FROM caso_auditoria WHERE caso = $1 ORDER BY secuencia"#,
        )
        .bind(caso)
        .fetch_all(&self.pool)
        .await?;
        let mut rastro = Rastro::nuevo(caso);
        for f in &filas {
            rastro.cargar(Entrada {
                secuencia: u64::try_from(f.get::<i64, _>("secuencia")).unwrap_or(0),
                caso: caso.to_string(),
                actor: f.get("actor"),
                accion: accion_de(&f.get::<String, _>("accion")),
                detalle: f.get("detalle"),
                cuando_ns: a_ns(f.get::<DateTime<Utc>, _>("cuando")),
                anterior: f.get("anterior"),
                resumen: f.get("resumen"),
            });
        }
        let anclas = sqlx::query("SELECT hasta, resumen FROM caso_anclas WHERE caso = $1")
            .bind(caso)
            .fetch_all(&self.pool)
            .await?;
        let mut anclado_hasta = 0i64;
        for a in &anclas {
            let hasta: i64 = a.get("hasta");
            anclado_hasta = anclado_hasta.max(hasta);
            rastro.cargar_ancla(aegis_case::auditoria::Ancla {
                hasta: u64::try_from(hasta).unwrap_or(0),
                resumen: a.get("resumen"),
                cuando_ns: 0,
            });
        }
        let roturas = rastro.verificar();
        Ok(Integridad {
            caso: caso.to_string(),
            entradas: i64::try_from(filas.len()).unwrap_or(0),
            intacto: roturas.is_empty(),
            roturas: roturas.iter().map(texto_rotura).collect(),
            anclado_hasta,
        })
    }

    /// Publica un anclaje del rastro.
    pub async fn anclar(&self, caso: &str, atestacion: Option<&str>) -> Resultado<i64> {
        let mut tx = self.pool.begin().await?;
        let fila = sqlx::query(
            r#"SELECT secuencia, resumen FROM caso_auditoria
                WHERE caso = $1 ORDER BY secuencia DESC LIMIT 1"#,
        )
        .bind(caso)
        .fetch_optional(&mut *tx)
        .await?;
        let (hasta, resumen) = match fila {
            Some(f) => (f.get::<i64, _>("secuencia"), f.get::<String, _>("resumen")),
            None => (0, aegis_case::auditoria::GENESIS.to_string()),
        };
        sqlx::query(
            r#"INSERT INTO caso_anclas (caso, hasta, resumen, atestacion)
               VALUES ($1, $2, $3, $4)
               ON CONFLICT (caso, hasta) DO UPDATE SET atestacion = EXCLUDED.atestacion"#,
        )
        .bind(caso)
        .bind(hasta)
        .bind(&resumen)
        .bind(atestacion)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(hasta)
    }

    /// Metricas del SOC sobre los casos de un inquilino.
    pub async fn metricas(&self, inquilino: Option<&str>) -> Resultado<Resumen> {
        let casos = self.cargar_para_metricas(inquilino).await?;
        Ok(metricas::calcular(
            &casos,
            &std::collections::BTreeMap::new(),
        ))
    }

    async fn cargar_para_metricas(&self, inquilino: Option<&str>) -> Resultado<Vec<Caso>> {
        let filas = sqlx::query(
            r#"SELECT id, inquilino, titulo, estado, severidad, asignado_a, abierto_en,
                      primer_vistazo_en, contenido_en, cerrado_en, veredicto, tecnicas
                 FROM casos
                WHERE ($1::text IS NULL OR inquilino = $1)
                ORDER BY abierto_en DESC LIMIT 5000"#,
        )
        .bind(inquilino)
        .fetch_all(&self.pool)
        .await?;
        let mut salida = Vec::with_capacity(filas.len());
        for f in filas {
            let id: String = f.get("id");
            let inq: String = f.get("inquilino");
            let severidad = severidad_de(&f.get::<String, _>("severidad"));
            let alertas = sqlx::query(
                r#"SELECT alerta, regla, anfitrion, sujeto, tecnica, ocurrio_en
                     FROM caso_alertas WHERE caso = $1 ORDER BY ocurrio_en"#,
            )
            .bind(&id)
            .fetch_all(&self.pool)
            .await?;
            let Some(primera) = alertas.first() else {
                continue;
            };
            let mut caso = Caso::abrir(id, alerta_de(primera, &inq, severidad));
            for a in alertas.iter().skip(1) {
                caso.absorber(alerta_de(a, &inq, severidad));
            }
            caso.estado = estado_de(&f.get::<String, _>("estado"));
            caso.severidad = severidad;
            caso.asignado_a = f.try_get("asignado_a").ok().flatten();
            caso.abierto_ns = a_ns(f.get::<DateTime<Utc>, _>("abierto_en"));
            caso.primer_vistazo_ns = f
                .try_get::<Option<DateTime<Utc>>, _>("primer_vistazo_en")
                .ok()
                .flatten()
                .map(a_ns);
            caso.contenido_ns = f
                .try_get::<Option<DateTime<Utc>>, _>("contenido_en")
                .ok()
                .flatten()
                .map(a_ns);
            caso.cerrado_ns = f
                .try_get::<Option<DateTime<Utc>>, _>("cerrado_en")
                .ok()
                .flatten()
                .map(a_ns);
            caso.veredicto = f
                .try_get::<Option<String>, _>("veredicto")
                .ok()
                .flatten()
                .map(|v| veredicto_de(&v));
            salida.push(caso);
        }
        Ok(salida)
    }
}

/// Escribe una entrada del rastro dentro de una transaccion ya abierta.
///
/// La cabeza se lee **aqui dentro**, con la fila del caso bloqueada por la
/// operacion que llamo. Sin ese bloqueo, dos analistas que actuan a la vez
/// calculan la misma cabeza y la cadena se bifurca; el indice unico sobre el
/// resumen lo convierte en un error en vez de en una bifurcacion silenciosa.
async fn anotar_en(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    caso: &str,
    actor: &str,
    accion: Accion,
    detalle: &str,
    cuando_ns: u64,
) -> Resultado<()> {
    if actor.trim().is_empty() {
        return Err(ErrorServidor::Config(
            "una entrada de auditoria sin actor no es una entrada de auditoria".into(),
        ));
    }
    let cabeza = sqlx::query(
        r#"SELECT secuencia, resumen FROM caso_auditoria
            WHERE caso = $1 ORDER BY secuencia DESC LIMIT 1"#,
    )
    .bind(caso)
    .fetch_optional(&mut **tx)
    .await?;
    let (secuencia, anterior) = match cabeza {
        Some(f) => (
            f.get::<i64, _>("secuencia") + 1,
            f.get::<String, _>("resumen"),
        ),
        None => (1, aegis_case::auditoria::GENESIS.to_string()),
    };
    // `Entrada::nueva` y no una estructura a mano: el recorte del detalle y el
    // calculo del resumen tienen que ocurrir en el MISMO sitio que en memoria. Si
    // aqui se recortara de otra forma, se guardaria un detalle distinto del que
    // entro en el resumen, la cadena verificaria en memoria y fallaria al leerla
    // de disco — acusando de manipulacion a una entrada honesta, que es la peor
    // averia que puede tener un rastro.
    let e = Entrada::nueva(
        u64::try_from(secuencia).unwrap_or(1),
        caso,
        actor,
        accion,
        detalle,
        cuando_ns,
        anterior,
    );
    sqlx::query(
        r#"INSERT INTO caso_auditoria
             (caso, secuencia, actor, accion, detalle, cuando, anterior, resumen)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
    )
    .bind(caso)
    .bind(secuencia)
    .bind(&e.actor)
    .bind(e.accion.nombre())
    .bind(&e.detalle)
    .bind(de_ns(e.cuando_ns))
    .bind(&e.anterior)
    .bind(&e.resumen)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn texto_rotura(r: &Rotura) -> String {
    match r {
        Rotura::ContenidoAlterado { secuencia } => {
            format!("la entrada {secuencia} no cuadra con su resumen: se altero su contenido")
        }
        Rotura::EslabonRoto { secuencia } => {
            format!("la entrada {secuencia} no engancha con la anterior")
        }
        Rotura::Hueco { esperada } => format!("falta la entrada {esperada}"),
        Rotura::AnclajeRoto { hasta } => format!(
            "la cadena no cuadra con el anclaje publicado hasta la entrada {hasta}: la historia \
             anterior se reescribio entera"
        ),
    }
}

fn de_ns(ns: u64) -> DateTime<Utc> {
    let segundos = i64::try_from(ns / 1_000_000_000).unwrap_or(0);
    let nanos = u32::try_from(ns % 1_000_000_000).unwrap_or(0);
    Utc.timestamp_opt(segundos, nanos)
        .single()
        .unwrap_or_default()
}

fn a_ns(t: DateTime<Utc>) -> u64 {
    u64::try_from(t.timestamp_nanos_opt().unwrap_or(0)).unwrap_or(0)
}

fn estado_de(s: &str) -> Estado {
    match s {
        "en-curso" => Estado::EnCurso,
        "en-espera" => Estado::EnEspera,
        "contenido" => Estado::Contenido,
        "cerrado" => Estado::Cerrado,
        _ => Estado::Nuevo,
    }
}

fn severidad_de(s: &str) -> Severidad {
    match s {
        "critica" => Severidad::Critica,
        "alta" => Severidad::Alta,
        "media" => Severidad::Media,
        "baja" => Severidad::Baja,
        _ => Severidad::Info,
    }
}

fn veredicto_de(s: &str) -> Veredicto {
    match s {
        "verdadero" => Veredicto::Verdadero,
        "falso-positivo" => Veredicto::FalsoPositivo,
        "autorizado" => Veredicto::Autorizado,
        _ => Veredicto::NoConcluyente,
    }
}

fn accion_de(s: &str) -> Accion {
    match s {
        "cambio-de-estado" => Accion::CambioDeEstado,
        "asignado" => Accion::Asignado,
        "alerta-fusionada" => Accion::AlertaFusionada,
        "observable-anadido" => Accion::ObservableAnadido,
        "tarea-creada" => Accion::TareaCreada,
        "tarea-cerrada" => Accion::TareaCerrada,
        "comentario" => Accion::Comentario,
        "consultado" => Accion::Consultado,
        "remediacion-ordenada" => Accion::RemediacionOrdenada,
        "cerrado" => Accion::Cerrado,
        "reabierto" => Accion::Reabierto,
        _ => Accion::Creado,
    }
}

fn alerta_de(f: &sqlx::postgres::PgRow, inquilino: &str, severidad: Severidad) -> Alerta {
    Alerta {
        id: f.get("alerta"),
        inquilino: inquilino.to_string(),
        anfitrion: f.get("anfitrion"),
        sujeto: f.get("sujeto"),
        tecnica: f.try_get("tecnica").ok().flatten(),
        regla: f.get("regla"),
        severidad,
        ocurrio_ns: a_ns(f.get::<DateTime<Utc>, _>("ocurrio_en")),
        observables: Vec::new(),
        resumen: String::new(),
    }
}

/// Tareas de un caso, para el panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VistaTarea {
    /// Identificador dentro del caso.
    pub id: i32,
    /// Que hay que hacer.
    pub titulo: String,
    /// Quien la tiene.
    pub asignada_a: Option<String>,
    /// Como esta.
    pub estado: String,
    /// Por que se descarto.
    pub motivo: Option<String>,
}

impl From<&Tarea> for VistaTarea {
    fn from(t: &Tarea) -> VistaTarea {
        VistaTarea {
            id: i32::try_from(t.id).unwrap_or(0),
            titulo: t.titulo.clone(),
            asignada_a: t.asignada_a.clone(),
            estado: match t.estado {
                aegis_case::modelo::EstadoTarea::Pendiente => "pendiente".into(),
                aegis_case::modelo::EstadoTarea::Hecha => "hecha".into(),
                aegis_case::modelo::EstadoTarea::Descartada => "descartada".into(),
            },
            motivo: t.motivo.clone(),
        }
    }
}

/// Observables de un caso, para el panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VistaObservable {
    /// Tipo.
    pub tipo: String,
    /// Valor.
    pub valor: String,
}

impl From<&Observable> for VistaObservable {
    fn from(o: &Observable) -> VistaObservable {
        VistaObservable {
            tipo: o.tipo().to_string(),
            valor: o.valor().to_string(),
        }
    }
}
