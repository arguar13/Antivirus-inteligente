//! API REST de administracion (axum), la que consume el panel web.
//!
//! # Autenticacion
//!
//! Toda ruta salvo `/salud` y `/api/sesion` exige una sesion valida en la
//! cabecera `Authorization: Bearer <token>`, resuelta contra Redis. Las
//! acciones que TOCAN un endpoint (aislar, liberar) quedan ademas registradas
//! con el usuario que las ordeno: una accion destructiva sobre la maquina de
//! alguien no puede ser anonima.

use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;

use crate::cache::Cache;
use crate::dominio::ServicioFlota;

/// Estado compartido por los manejadores de la API.
#[derive(Clone)]
pub struct EstadoApi {
    /// Nucleo de dominio.
    pub servicio: Arc<ServicioFlota>,
    /// Cache de sesiones y reputacion.
    pub cache: Cache,
    /// Margen en segundos para considerar conectado a un agente.
    pub margen_desconexion_seg: i64,
    /// Direcciones por las que este plano de control es alcanzable.
    ///
    /// Se usan para RECHAZAR una cuarentena de enjambre contra el propio plano
    /// de control. Si se aceptara, cada endpoint de la flota dejaria de poder
    /// hablar con el —incluido para recibir la orden de levantar esa misma
    /// cuarentena—, y la recuperacion seria ir maquina por maquina.
    pub direcciones_propias: Vec<std::net::IpAddr>,
    /// Instrumentacion de la difusion de cuarentena del transporte de flota.
    ///
    /// `None` cuando el transporte nativo no esta en pie (p. ej. en pruebas de
    /// la API sola): el endpoint responde 503 en vez de inventar un cero, que
    /// se leeria como "se difundio al instante".
    pub difusion: Option<Arc<crate::flota::DifusionCuarentena>>,
    /// El puente vivo entre el motor ITDR y el orquestador de remediacion.
    ///
    /// `None` cuando el plano de control arranca sin respuesta automatica (o en
    /// pruebas de la API sola): la ruta de ingesta responde 503 en vez de
    /// aceptar telemetria que nadie va a analizar. Aceptarla y descartarla seria
    /// peor que rechazarla, porque el colector creeria estar cubierto.
    pub remediacion: Option<Arc<crate::remediacion::MotorVivo>>,
}

/// Construye el enrutador de la API.
pub fn enrutador(estado: EstadoApi) -> Router {
    Router::new()
        // Publicas
        .route("/salud", get(salud))
        .route("/api/sesion", post(abrir_sesion).delete(cerrar_sesion))
        // Inventario y alertas
        .route("/api/resumen", get(resumen))
        .route("/api/agentes", get(listar_agentes))
        .route("/api/agentes/{cn}", get(obtener_agente))
        .route("/api/agentes/{cn}/comando", get(tomar_comando))
        .route("/api/alertas", get(listar_alertas))
        .route("/api/agentes/{cn}/alertas", get(listar_alertas_de_agente))
        // Respuesta de un clic
        .route("/api/agentes/{cn}/aislar", post(aislar))
        .route("/api/agentes/{cn}/liberar", post(liberar))
        // Ingesta del colector de identidad (eventos 4769 normalizados): el motor
        // ITDR corre en vivo y el orquestador remedia solo las detecciones criticas.
        // Politica global y motor de reglas
        .route("/api/politicas", post(publicar_politica))
        .route("/api/reglas", get(listar_reglas).post(crear_regla))
        .route("/api/reglas/{id}", axum::routing::delete(borrar_regla))
        .route("/api/reglas/{id}/activa", post(fijar_regla_activa))
        // Inteligencia y linaje
        .route("/api/stix/objetos", get(listar_objetos_stix))
        .route("/api/grafos", get(listar_grafos))
        .route("/api/grafos/{id}", get(obtener_grafo))
        // --- Caceria distribuida AegisQL (FASE 43) ---
        .route("/api/cacerias", get(listar_cacerias).post(lanzar_caza))
        .route("/api/cacerias/{id}", get(obtener_caza))
        .route("/api/cacerias/{id}/cerrar", post(cerrar_caza))
        .route("/api/aegisql/esquema", get(esquema_aegisql))
        // --- Micro-segmentacion Zero-Trust (FASE 44) ---
        .route(
            "/api/cuarentena",
            get(listar_cuarentena).post(ordenar_cuarentena),
        )
        .route("/api/agentes/{cn}/cuarentena", post(cuarentena_de_enjambre))
        .route("/api/cuarentena/difusion", get(difusion_cuarentena))
        // --- Respuesta automatica: ITDR -> AI-RO (FASES 58 + 64) ---
        .route("/api/agentes/{cn}/itdr/telemetria", post(ingerir_identidad))
        .route("/api/remediaciones", get(listar_remediaciones))
        // --- Heuristicas globales: APT distribuida (FASE 45) ---
        .route(
            "/api/heuristicas",
            get(listar_heuristicas).post(crear_heuristica),
        )
        .route(
            "/api/heuristicas/{id}/activa",
            post(fijar_heuristica_activa),
        )
        .route("/api/correlaciones", get(listar_correlaciones))
        .route("/api/correlaciones/{id}", get(obtener_correlacion))
        .route("/api/correlaciones/{id}/cerrar", post(cerrar_correlacion))
        // Tiempo real
        .route("/api/ws", get(websocket))
        // Reputacion k-anonima
        .route("/api/reputacion/{prefijo}", get(consultar_reputacion))
        .route("/api/reputacion", post(registrar_reputacion))
        .with_state(estado)
}

/// Sonda de disponibilidad.
///
/// No basta con responder "vivo": un plano de control que no alcanza su base de
/// datos esta en pie pero es inutil, y el orquestador debe sacarlo del balanceo.
/// Por eso comprueba de verdad las dos dependencias y expone el estado del pool,
/// que es la primera senal de saturacion bajo carga.
async fn salud(State(estado): State<EstadoApi>) -> axum::response::Response {
    let pool = estado.servicio.almacen().pool();
    let bd_ok = sqlx::query("SELECT 1").fetch_one(pool).await.is_ok();
    let cache_ok = estado.cache.ping().await.is_ok();
    let listo = bd_ok && cache_ok;

    let cuerpo = serde_json::json!({
        "estado": if listo { "listo" } else { "degradado" },
        "postgres": bd_ok,
        "redis": cache_ok,
        "pool": { "conexiones": pool.size(), "ociosas": pool.num_idle() },
    });

    // 503 cuando falta una dependencia: es lo que un balanceador entiende.
    let codigo = if listo {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (codigo, Json(cuerpo)).into_response()
}

/// Credenciales para abrir sesion.
#[derive(Deserialize)]
struct Credenciales {
    /// Nombre del administrador.
    usuario: String,
}

/// Abre una sesion de administracion.
///
/// NOTA DE ALCANCE: la verificacion de credenciales real (LDAP, OIDC) es del
/// despliegue corporativo; aqui se emite la sesion contra el proveedor de
/// identidad que el despliegue coloque delante. Lo que este modulo garantiza es
/// que TODA ruta de administracion exige una sesion emitida y viva.
async fn abrir_sesion(
    State(estado): State<EstadoApi>,
    Json(cred): Json<Credenciales>,
) -> impl IntoResponse {
    if cred.usuario.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "usuario vacio"})),
        )
            .into_response();
    }
    match estado.cache.abrir_sesion(&cred.usuario).await {
        Ok(token) => (StatusCode::OK, Json(serde_json::json!({"token": token}))).into_response(),
        Err(e) => error_500(e).into_response(),
    }
}

/// Extrae y valida la sesion de la cabecera `Authorization`.
async fn usuario_autenticado(
    estado: &EstadoApi,
    cabeceras: &header::HeaderMap,
) -> Result<String, axum::response::Response> {
    let token = cabeceras
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");

    if token.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "falta Authorization: Bearer <token>"})),
        )
            .into_response());
    }

    match estado.cache.usuario_de_sesion(token).await {
        Ok(Some(u)) => Ok(u),
        Ok(None) => Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "sesion invalida o caducada"})),
        )
            .into_response()),
        Err(e) => Err(error_500(e).into_response()),
    }
}

/// Respuesta de error interno, sin filtrar detalles al cliente.
fn error_500(e: crate::error::ErrorServidor) -> impl IntoResponse {
    tracing::error!(error = %e, "fallo interno de la API");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({"error": "fallo interno"})),
    )
}

/// Ingiere un lote de telemetria de identidad y DISPARA la respuesta automatica.
///
/// Es la entrada viva del circuito ITDR -> AI-RO: el lote se analiza contra el
/// grafo de identidad de toda la flota, cada deteccion se persiste como alerta y
/// las que superan el umbral lanzan su playbook sobre el endpoint.
///
/// Devuelve 202 y NO 200 a proposito: la respuesta describe lo que se ORDENO,
/// no lo que el endpoint ya aplico. El aislamiento lo aplica el agente en su
/// proximo latido, y confundir "ordenado" con "aplicado" es como se acaba
/// creyendo aislada una maquina que sigue hablando con el atacante.
async fn ingerir_identidad(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
    Path(cn): Path<String>,
    Json(lote): Json<crate::remediacion::dto::LoteIdentidad>,
) -> axum::response::Response {
    if let Err(r) = usuario_autenticado(&estado, &cabeceras).await {
        return r;
    }
    let Some(motor) = estado.remediacion.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "la respuesta automatica no esta activa en este plano de control"
            })),
        )
            .into_response();
    };
    // Las cotas se comprueban ANTES de tocar el motor: un lote desmesurado no
    // puede convertirse en memoria del plano de control.
    if let Err(e) = lote.validar() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response();
    }

    let telemetria = crate::itdr::TelemetriaIdentidad::from(&lote);
    match motor.analizar_y_remediar(&cn, &telemetria).await {
        Ok(ciclo) => {
            let detecciones: Vec<serde_json::Value> = ciclo
                .detecciones
                .iter()
                .map(|d| {
                    let (categoria, mitre) = crate::itdr::categoria_y_mitre_publica(d.clase);
                    serde_json::json!({
                        "clase": crate::remediacion::clave_clase(d.clase),
                        "categoria": categoria,
                        "tecnica_mitre": mitre,
                        "severidad": crate::remediacion::severidad_num(d.severidad),
                        "sujeto": d.sujeto,
                        "evidencia": d.evidencia,
                    })
                })
                .collect();
            let remediaciones: Vec<serde_json::Value> = ciclo
                .remediaciones
                .iter()
                .map(|(id, inf)| {
                    serde_json::json!({
                        "id": id,
                        "clase": crate::remediacion::clave_clase(inf.clase),
                        "estado": crate::remediacion::clave_estado(inf.estado),
                        "acciones": inf.resultados.iter().map(|r| serde_json::json!({
                            "accion": crate::remediacion::clave_accion(r.accion),
                            "exito": r.exito(),
                        })).collect::<Vec<_>>(),
                    })
                })
                .collect();
            (
                StatusCode::ACCEPTED,
                Json(serde_json::json!({
                    "agente": cn,
                    "detecciones": detecciones,
                    "remediaciones": remediaciones,
                    // Se expone a proposito: si este numero crece, el cerrojo
                    // esta conteniendo un ataque que vuelve una y otra vez, y
                    // eso el analista tiene que verlo.
                    "omitidas_por_cerrojo": ciclo.omitidas_por_cerrojo,
                    "incidencias": ciclo.incidencias,
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// Lista las remediaciones automaticas mas recientes con su detalle por accion.
async fn listar_remediaciones(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
    Query(q): Query<Limite>,
) -> axum::response::Response {
    if let Err(r) = usuario_autenticado(&estado, &cabeceras).await {
        return r;
    }
    let limite = q.limite.unwrap_or(50).clamp(1, 500);
    match estado.servicio.almacen().listar_remediaciones(limite).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => error_500(e).into_response(),
    }
}

/// Resumen agregado de la flota.
async fn resumen(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
) -> axum::response::Response {
    if let Err(r) = usuario_autenticado(&estado, &cabeceras).await {
        return r;
    }
    match estado
        .servicio
        .almacen()
        .resumen(estado.margen_desconexion_seg)
        .await
    {
        Ok(r) => (StatusCode::OK, Json(r)).into_response(),
        Err(e) => error_500(e).into_response(),
    }
}

/// Parametros de paginacion.
#[derive(Deserialize)]
struct Limite {
    /// Numero maximo de filas.
    limite: Option<i64>,
    /// Solo alertas sin resolver.
    abiertas: Option<bool>,
}

/// Lista los agentes de la flota.
async fn listar_agentes(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
    Query(q): Query<Limite>,
) -> axum::response::Response {
    if let Err(r) = usuario_autenticado(&estado, &cabeceras).await {
        return r;
    }
    // El limite lo controla el cliente: se acota para que una peticion no pueda
    // pedir la flota entera y tumbar la memoria del servidor.
    let limite = q.limite.unwrap_or(200).clamp(1, 5_000);
    match estado
        .servicio
        .almacen()
        .listar_agentes(estado.margen_desconexion_seg, limite)
        .await
    {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => error_500(e).into_response(),
    }
}

/// Lista las alertas de UN endpoint.
///
/// El listado global ordena por gravedad y recencia sobre toda la flota, asi
/// que en un despliegue grande las alertas de una maquina concreta no salen en
/// las primeras paginas. Para la vista de detalle hace falta preguntar por ella.
async fn listar_alertas_de_agente(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
    Path(cn): Path<String>,
    Query(q): Query<Limite>,
) -> axum::response::Response {
    if let Err(r) = usuario_autenticado(&estado, &cabeceras).await {
        return r;
    }
    let limite = q.limite.unwrap_or(100).clamp(1, 5_000);
    match estado
        .servicio
        .almacen()
        .listar_alertas_de_agente(&cn, limite)
        .await
    {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => error_500(e).into_response(),
    }
}

/// Lista las alertas.
async fn listar_alertas(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
    Query(q): Query<Limite>,
) -> axum::response::Response {
    if let Err(r) = usuario_autenticado(&estado, &cabeceras).await {
        return r;
    }
    let limite = q.limite.unwrap_or(100).clamp(1, 5_000);
    match estado
        .servicio
        .almacen()
        .listar_alertas(limite, q.abiertas.unwrap_or(false))
        .await
    {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => error_500(e).into_response(),
    }
}

/// Cierra la sesion del administrador que la presenta.
async fn cerrar_sesion(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
) -> axum::response::Response {
    let token = cabeceras
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    match estado.cache.cerrar_sesion(token).await {
        Ok(cerrada) => (
            StatusCode::OK,
            Json(serde_json::json!({"cerrada": cerrada})),
        )
            .into_response(),
        Err(e) => error_500(e).into_response(),
    }
}

/// Devuelve el detalle de un agente.
async fn obtener_agente(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
    Path(cn): Path<String>,
) -> axum::response::Response {
    if let Err(r) = usuario_autenticado(&estado, &cabeceras).await {
        return r;
    }
    match estado
        .servicio
        .almacen()
        .obtener_agente(&cn, estado.margen_desconexion_seg)
        .await
    {
        Ok(a) => (StatusCode::OK, Json(a)).into_response(),
        Err(crate::error::ErrorServidor::NoEncontrado(m)) => {
            (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": m}))).into_response()
        }
        Err(e) => error_500(e).into_response(),
    }
}

/// Entrega (y marca como entregado) el comando pendiente de un agente.
///
/// Lo consume tanto el panel —para ver que se le va a mandar a un endpoint—
/// como el motor de empuje de politica global, que lo reutiliza para vaciar la
/// cola de cada agente conectado.
async fn tomar_comando(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
    Path(cn): Path<String>,
) -> axum::response::Response {
    if let Err(r) = usuario_autenticado(&estado, &cabeceras).await {
        return r;
    }
    match estado.servicio.almacen().tomar_comando_pendiente(&cn).await {
        Ok(Some(c)) => (StatusCode::OK, Json(c)).into_response(),
        Ok(None) => (StatusCode::NO_CONTENT, Json(serde_json::json!({}))).into_response(),
        Err(e) => error_500(e).into_response(),
    }
}

/// Alta de un veredicto de reputacion en su cubo k-anonimo.
#[derive(Deserialize)]
struct AltaReputacion {
    /// Hash completo en hexadecimal del artefacto.
    hash: String,
    /// Veredicto que se le asigna.
    veredicto: crate::cache::Veredicto,
}

/// Registra el veredicto de un artefacto.
async fn registrar_reputacion(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
    Json(a): Json<AltaReputacion>,
) -> axum::response::Response {
    if let Err(r) = usuario_autenticado(&estado, &cabeceras).await {
        return r;
    }
    // Un hash que no es hexadecimal contaminaria los cubos con entradas que
    // ningun agente podra casar nunca.
    if a.hash.len() < 16 || !a.hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "hash hexadecimal invalido"})),
        )
            .into_response();
    }
    match estado
        .cache
        .registrar_reputacion(&a.hash.to_ascii_lowercase(), a.veredicto)
        .await
    {
        Ok(()) => (
            StatusCode::CREATED,
            Json(serde_json::json!({"registrado": true})),
        )
            .into_response(),
        Err(e) => error_500(e).into_response(),
    }
}

/// Aisla un endpoint comprometido.
async fn aislar(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
    Path(cn): Path<String>,
) -> axum::response::Response {
    cambiar_aislamiento(estado, cabeceras, cn, true).await
}

/// Libera un endpoint previamente aislado.
async fn liberar(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
    Path(cn): Path<String>,
) -> axum::response::Response {
    cambiar_aislamiento(estado, cabeceras, cn, false).await
}

/// Cambia el aislamiento de un endpoint y encola el comando correspondiente.
async fn cambiar_aislamiento(
    estado: EstadoApi,
    cabeceras: header::HeaderMap,
    cn: String,
    aislar: bool,
) -> axum::response::Response {
    let usuario = match usuario_autenticado(&estado, &cabeceras).await {
        Ok(u) => u,
        Err(r) => return r,
    };

    let almacen = estado.servicio.almacen();
    match almacen.fijar_aislamiento(&cn, aislar).await {
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "el agente no existe"})),
        )
            .into_response(),
        Ok(true) => {
            let accion = if aislar { "aislar" } else { "liberar" };
            // El comando se encola para que el agente lo recoja en su proximo
            // latido: el aislamiento lo APLICA el endpoint, el servidor solo lo
            // ordena. Asi funciona aunque el endpoint este tras un NAT y el
            // servidor no pueda alcanzarlo.
            match almacen
                .encolar_comando(&cn, accion, serde_json::json!({}), &usuario)
                .await
            {
                Ok(id) => {
                    // El resto de consolas abiertas ven el cambio al instante:
                    // dos operadores actuando a ciegas sobre el mismo incidente
                    // es como se duplican las acciones de respuesta.
                    estado.servicio.bus().publicar(
                        crate::eventos::EventoPanel::AislamientoCambiado {
                            cn: cn.clone(),
                            aislado: aislar,
                            por: usuario.clone(),
                        },
                    );
                    (
                        StatusCode::ACCEPTED,
                        Json(serde_json::json!({
                            "comando": id, "accion": accion, "agente": cn, "ordenado_por": usuario
                        })),
                    )
                        .into_response()
                }
                Err(e) => error_500(e).into_response(),
            }
        }
        Err(e) => error_500(e).into_response(),
    }
}

/// Politica a publicar.
#[derive(Deserialize)]
struct NuevaPolitica {
    /// Nombre legible.
    nombre: String,
    /// Contenido de la politica.
    contenido: serde_json::Value,
}

/// Publica una politica nueva y la activa para toda la flota.
async fn publicar_politica(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
    Json(p): Json<NuevaPolitica>,
) -> axum::response::Response {
    if let Err(r) = usuario_autenticado(&estado, &cabeceras).await {
        return r;
    }
    match estado
        .servicio
        .almacen()
        .publicar_politica(&p.nombre, p.contenido)
        .await
    {
        Ok(version) => (
            StatusCode::CREATED,
            Json(serde_json::json!({"version": version})),
        )
            .into_response(),
        Err(e) => error_500(e).into_response(),
    }
}

/// Regla nueva tal y como la escribe el operador.
#[derive(Deserialize)]
struct NuevaRegla {
    /// Nombre legible, unico.
    nombre: String,
    /// Tipo de regla.
    tipo: String,
    /// Parametros, que se validan segun el tipo.
    parametros: serde_json::Value,
    /// Severidad 0..4.
    severidad: Option<i16>,
}

/// Da de alta una regla global y la empuja a la flota.
///
/// La validacion ocurre AQUI, en la cara del operador. Una regla mal formada que
/// el agente ignorase en silencio es lo peor de los dos mundos: el operador cree
/// que la flota esta protegida y no lo esta.
async fn crear_regla(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
    Json(r): Json<NuevaRegla>,
) -> axum::response::Response {
    let usuario = match usuario_autenticado(&estado, &cabeceras).await {
        Ok(u) => u,
        Err(resp) => return resp,
    };

    let Some(tipo) = crate::reglas::TipoRegla::de_str(&r.tipo) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("tipo de regla desconocido: {}", r.tipo),
                "tipos_validos": ["bloquear_puerto", "bloquear_hash", "bloquear_proceso",
                                  "bloquear_red", "aislar_por_puntuacion"]
            })),
        )
            .into_response();
    };

    let parametros = match crate::reglas::validar(tipo, &r.parametros) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("{e}")})),
            )
                .into_response()
        }
    };

    if r.nombre.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "el nombre no puede estar vacio"})),
        )
            .into_response();
    }

    let almacen = estado.servicio.almacen();
    let severidad = r.severidad.unwrap_or(2).clamp(0, 4);
    let id = match almacen
        .crear_regla(&r.nombre, tipo.como_str(), &parametros, severidad, &usuario)
        .await
    {
        Ok(id) => id,
        Err(crate::error::ErrorServidor::BaseDatos(sqlx::Error::Database(e)))
            if e.is_unique_violation() =>
        {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "ya existe una regla con ese nombre"})),
            )
                .into_response()
        }
        Err(e) => return error_500(e).into_response(),
    };

    // Dar de alta la regla y NO publicar dejaria la flota sin ella: las dos
    // cosas son una sola operacion desde el punto de vista del operador.
    match almacen.recompilar_y_publicar(&r.nombre).await {
        Ok(version) => {
            let activas = almacen
                .listar_reglas()
                .await
                .map(|v| v.iter().filter(|x| x.activa).count())
                .unwrap_or(0);
            estado
                .servicio
                .bus()
                .publicar(crate::eventos::EventoPanel::PoliticaPublicada {
                    version,
                    reglas: activas,
                });
            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "regla": id, "version_politica": version, "creada_por": usuario
                })),
            )
                .into_response()
        }
        Err(e) => error_500(e).into_response(),
    }
}

/// Lista las reglas definidas.
async fn listar_reglas(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
) -> axum::response::Response {
    if let Err(r) = usuario_autenticado(&estado, &cabeceras).await {
        return r;
    }
    match estado.servicio.almacen().listar_reglas().await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => error_500(e).into_response(),
    }
}

/// Cambio de estado de una regla.
#[derive(Deserialize)]
struct CambioActiva {
    /// Nuevo estado.
    activa: bool,
}

/// Activa o desactiva una regla y vuelve a publicar la politica.
async fn fijar_regla_activa(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
    Path(id): Path<String>,
    Json(c): Json<CambioActiva>,
) -> axum::response::Response {
    if let Err(r) = usuario_autenticado(&estado, &cabeceras).await {
        return r;
    }
    let Ok(uuid) = id.parse::<uuid::Uuid>() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "identificador de regla invalido"})),
        )
            .into_response();
    };
    let almacen = estado.servicio.almacen();
    match almacen.fijar_regla_activa(uuid, c.activa).await {
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "la regla no existe"})),
        )
            .into_response(),
        Ok(true) => match almacen.recompilar_y_publicar("cambio-de-estado").await {
            Ok(v) => (
                StatusCode::OK,
                Json(serde_json::json!({"version_politica": v})),
            )
                .into_response(),
            Err(e) => error_500(e).into_response(),
        },
        Err(e) => error_500(e).into_response(),
    }
}

/// Borra una regla y vuelve a publicar la politica sin ella.
async fn borrar_regla(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
    Path(id): Path<String>,
) -> axum::response::Response {
    if let Err(r) = usuario_autenticado(&estado, &cabeceras).await {
        return r;
    }
    let Ok(uuid) = id.parse::<uuid::Uuid>() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "identificador de regla invalido"})),
        )
            .into_response();
    };
    let almacen = estado.servicio.almacen();
    match almacen.borrar_regla(uuid).await {
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "la regla no existe"})),
        )
            .into_response(),
        // Borrar la regla y no republicar dejaria la flota aplicandola todavia.
        Ok(true) => match almacen.recompilar_y_publicar("regla-retirada").await {
            Ok(v) => (
                StatusCode::OK,
                Json(serde_json::json!({"version_politica": v})),
            )
                .into_response(),
            Err(e) => error_500(e).into_response(),
        },
        Err(e) => error_500(e).into_response(),
    }
}

/// Lista los objetos STIX ingeridos, los mas avistados primero.
async fn listar_objetos_stix(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
    Query(q): Query<Limite>,
) -> axum::response::Response {
    if let Err(r) = usuario_autenticado(&estado, &cabeceras).await {
        return r;
    }
    let limite = q.limite.unwrap_or(100).clamp(1, 5_000);
    match estado.servicio.almacen().listar_objetos_stix(limite).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => error_500(e).into_response(),
    }
}

/// Lista los grafos de linaje capturados.
async fn listar_grafos(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
    Query(q): Query<Limite>,
) -> axum::response::Response {
    if let Err(r) = usuario_autenticado(&estado, &cabeceras).await {
        return r;
    }
    let limite = q.limite.unwrap_or(50).clamp(1, 1_000);
    match estado.servicio.almacen().listar_grafos(limite).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => error_500(e).into_response(),
    }
}

/// Devuelve los nodos de un grafo, para dibujar el arbol de procesos.
async fn obtener_grafo(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
    Path(id): Path<String>,
) -> axum::response::Response {
    if let Err(r) = usuario_autenticado(&estado, &cabeceras).await {
        return r;
    }
    let Ok(uuid) = id.parse::<uuid::Uuid>() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "identificador de grafo invalido"})),
        )
            .into_response();
    };
    match estado.servicio.almacen().nodos_de_grafo(uuid).await {
        Ok(v) => (
            StatusCode::OK,
            Json(serde_json::json!({"id": id, "nodos": v})),
        )
            .into_response(),
        Err(crate::error::ErrorServidor::NoEncontrado(m)) => {
            (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": m}))).into_response()
        }
        Err(e) => error_500(e).into_response(),
    }
}

/// Token de sesion para la conexion en tiempo real.
#[derive(Deserialize)]
struct TokenWs {
    /// Token emitido por `/api/sesion`.
    token: Option<String>,
}

/// Abre la conexion en tiempo real del panel.
///
/// # Por que el token viaja en la consulta y no en una cabecera
///
/// El API de WebSocket del navegador NO permite anadir cabeceras al handshake:
/// es una limitacion del estandar, no una decision de diseno. Las alternativas
/// reales son una cookie o el parametro de consulta. Se usa el parametro porque
/// mantiene la sesion en el mismo mecanismo que el resto de la API (token
/// portador, sin estado de cookie ni exposicion a CSRF), a cambio de que el
/// token pueda aparecer en registros de acceso: por eso las sesiones caducan y
/// se pueden cerrar. En produccion, ademas, esto viaja siempre sobre TLS.
async fn websocket(
    State(estado): State<EstadoApi>,
    Query(q): Query<TokenWs>,
    ws: WebSocketUpgrade,
) -> axum::response::Response {
    let token = q.token.unwrap_or_default();
    let usuario = match estado.cache.usuario_de_sesion(&token).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "sesion invalida o caducada"})),
            )
                .into_response()
        }
        Err(e) => return error_500(e).into_response(),
    };

    ws.on_upgrade(move |socket| atender_websocket(socket, estado, usuario))
}

/// Bombea los eventos del bus hacia una consola conectada.
async fn atender_websocket(mut socket: WebSocket, estado: EstadoApi, usuario: String) {
    let mut receptor = estado.servicio.bus().suscribir();
    tracing::info!(usuario = %usuario, consolas = estado.servicio.bus().consolas(),
        "consola conectada al tiempo real");

    // Primer mensaje: una instantanea, para que la consola pinte algo de
    // inmediato en vez de una pantalla vacia hasta que ocurra el primer suceso.
    let resumen = estado
        .servicio
        .almacen()
        .resumen(estado.margen_desconexion_seg)
        .await
        .ok();
    if let Some(r) = resumen {
        let inicial = serde_json::json!({"tipo": "instantanea", "resumen": r});
        if socket
            .send(Message::Text(inicial.to_string().into()))
            .await
            .is_err()
        {
            return;
        }
    }

    loop {
        tokio::select! {
            // Eventos del bus hacia la consola.
            recibido = receptor.recv() => match recibido {
                Ok(evento) => {
                    let Ok(texto) = serde_json::to_string(&evento) else { continue };
                    if socket.send(Message::Text(texto.into())).await.is_err() {
                        break;
                    }
                }
                // La consola se quedo atras y se descartaron eventos: se le dice
                // para que pida una instantanea, en vez de dejarla creyendo que
                // tiene el estado completo.
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    let aviso = serde_json::json!({"tipo": "desincronizada", "perdidos": n});
                    if socket.send(Message::Text(aviso.to_string().into())).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            },
            // Mensajes de la consola: solo se atiende el cierre y el ping.
            entrante = socket.recv() => match entrante {
                Some(Ok(Message::Close(_))) | None => break,
                Some(Err(_)) => break,
                _ => {}
            },
        }
    }

    tracing::info!(usuario = %usuario, "consola desconectada del tiempo real");
}

/// Devuelve el cubo de reputacion de un prefijo de hash.
///
/// No exige sesion a proposito: la consultan los agentes, y su valor de
/// privacidad esta en que el servidor no sabe por que hash concreto preguntan.
async fn consultar_reputacion(
    State(estado): State<EstadoApi>,
    Path(prefijo): Path<String>,
) -> axum::response::Response {
    // Un prefijo mas largo del acordado estrecharia el cubo y romperia la
    // k-anonimia: se rechaza en vez de responder con menos privacidad.
    if prefijo.len() != crate::cache::LONGITUD_PREFIJO
        || !prefijo.chars().all(|c| c.is_ascii_hexdigit())
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("el prefijo debe ser {} digitos hexadecimales",
                                 crate::cache::LONGITUD_PREFIJO)
            })),
        )
            .into_response();
    }
    match estado
        .cache
        .consultar_cubo(&prefijo.to_ascii_lowercase())
        .await
    {
        Ok(v) => {
            let entradas: Vec<_> = v
                .into_iter()
                .map(|(sufijo, veredicto)| serde_json::json!({"sufijo": sufijo, "veredicto": veredicto}))
                .collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({"cubo": prefijo, "entradas": entradas})),
            )
                .into_response()
        }
        Err(e) => error_500(e).into_response(),
    }
}

// ---------------------------------------------------------------------------
// FASE 43: caceria distribuida AegisQL
// ---------------------------------------------------------------------------

/// Consulta que el analista quiere lanzar a la flota.
#[derive(Deserialize)]
struct NuevaCaza {
    /// Texto AegisQL.
    consulta: String,
}

/// Lanza una caceria a toda la flota.
///
/// LA VALIDACION OCURRE AQUI Y NO EN EL ENDPOINT
/// ---------------------------------------------
/// La consulta se analiza contra el esquema ANTES de guardarla y de difundirla.
/// Si no se hiciera, una columna mal escrita se convertiria en diez mil fallos
/// remotos —cada uno con su registro y su alerta— por un error que se veia en
/// la consola antes de pulsar "ejecutar". Ademas, el analizador es el que
/// impone el techo de filas: sin pasar por el, una consulta sin `LIMIT` pediria
/// a cada endpoint que devolviera todo lo que tiene.
///
/// El error que se devuelve lleva la posicion exacta y una sugerencia, para que
/// el analista corrija en vez de adivinar.
async fn lanzar_caza(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
    Json(p): Json<NuevaCaza>,
) -> axum::response::Response {
    let operador = match usuario_autenticado(&estado, &cabeceras).await {
        Ok(u) => u,
        Err(r) => return r,
    };

    let consulta = match aegis_parser::sintaxis::analizar(&p.consulta) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": e.mensaje,
                    "sugerencia": e.sugerencia,
                    "inicio": e.inicio,
                    "fin": e.fin,
                    "detalle": e.dibujar(&p.consulta),
                })),
            )
                .into_response()
        }
    };

    let plan = aegis_parser::plan::planificar(consulta);
    let columnas: Vec<String> = match &plan.consulta.proyeccion {
        aegis_parser::ast::Proyeccion::Columnas(c) => {
            c.iter().map(|c| c.nombre.to_string()).collect()
        }
        aegis_parser::ast::Proyeccion::Todo => {
            aegis_parser::plan::columnas_de_asterisco(plan.consulta.tabla)
                .into_iter()
                .map(str::to_string)
                .collect()
        }
        aegis_parser::ast::Proyeccion::Cuenta => vec!["count".to_string()],
    };

    let almacen = estado.servicio.almacen();
    match almacen
        .lanzar_caza(
            &p.consulta,
            plan.consulta.tabla,
            &columnas,
            &operador,
            // El margen de desconexion es tres intervalos de latido: un
            // endpoint que se pierde uno sigue contando como en linea, y el
            // denominador de la cobertura no baja por un paquete perdido.
            (estado.servicio.intervalo_latido_seg() * 3) as i64,
        )
        .await
    {
        Ok(id) => {
            let objetivo = almacen
                .obtener_caza(id)
                .await
                .ok()
                .flatten()
                .map(|c| c.objetivo)
                .unwrap_or(0);
            estado
                .servicio
                .bus()
                .publicar(crate::eventos::EventoPanel::CazaLanzada {
                    caza_id: id.to_string(),
                    consulta: p.consulta.clone(),
                    por: operador,
                    objetivo,
                });
            (
                StatusCode::ACCEPTED,
                Json(serde_json::json!({
                    "id": id,
                    "tabla": plan.consulta.tabla,
                    "columnas": columnas,
                    "objetivo": objetivo,
                    // Se devuelve el coste para que la consola pueda avisar de
                    // que una caceria cara va a tardar en una flota grande.
                    "coste": format!("{:?}", plan.coste_maximo).to_lowercase(),
                })),
            )
                .into_response()
        }
        Err(e) => error_500(e).into_response(),
    }
}

/// Cacerias recientes.
async fn listar_cacerias(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
    Query(q): Query<Limite>,
) -> axum::response::Response {
    if let Err(r) = usuario_autenticado(&estado, &cabeceras).await {
        return r;
    }
    let limite = q.limite.unwrap_or(50).clamp(1, 500);
    match estado.servicio.almacen().listar_cacerias(limite).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => error_500(e).into_response(),
    }
}

/// Una caceria con su resumen agregado y las respuestas mas utiles.
async fn obtener_caza(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<Limite>,
) -> axum::response::Response {
    if let Err(r) = usuario_autenticado(&estado, &cabeceras).await {
        return r;
    }
    let Ok(id) = uuid::Uuid::parse_str(&id) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "identificador invalido"})),
        )
            .into_response();
    };
    let almacen = estado.servicio.almacen();
    let limite = q.limite.unwrap_or(200).clamp(1, 5_000);

    let (caza, resumen, respuestas) = tokio::join!(
        almacen.obtener_caza(id),
        almacen.resumen_caza(id),
        almacen.respuestas_caza(id, limite)
    );

    let caza = match caza {
        Ok(Some(c)) => c,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "no existe esa caceria"})),
            )
                .into_response()
        }
        Err(e) => return error_500(e).into_response(),
    };
    let resumen = match resumen {
        Ok(r) => r,
        Err(e) => return error_500(e).into_response(),
    };
    let respuestas = match respuestas {
        Ok(r) => r,
        Err(e) => return error_500(e).into_response(),
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "caza": caza,
            "resumen": resumen,
            "respuestas": respuestas,
        })),
    )
        .into_response()
}

/// Cierra una caceria: deja de entregarse a los endpoints que reconecten.
async fn cerrar_caza(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
    Path(id): Path<String>,
) -> axum::response::Response {
    if let Err(r) = usuario_autenticado(&estado, &cabeceras).await {
        return r;
    }
    let Ok(id) = uuid::Uuid::parse_str(&id) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "identificador invalido"})),
        )
            .into_response();
    };
    match estado.servicio.almacen().cerrar_caza(id).await {
        Ok(true) => (StatusCode::OK, Json(serde_json::json!({"cerrada": true}))).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "no existe o ya estaba cerrada"})),
        )
            .into_response(),
        Err(e) => error_500(e).into_response(),
    }
}

/// Esquema de AegisQL: tablas, columnas, tipos y coste.
///
/// Lo sirve el mismo binario que valida las consultas, asi que la ayuda que ve
/// el analista en la consola NO PUEDE desincronizarse del esquema real. Una
/// documentacion mantenida a mano al lado del codigo diverge en la primera
/// columna que alguien anade con prisa.
async fn esquema_aegisql(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
) -> axum::response::Response {
    if let Err(r) = usuario_autenticado(&estado, &cabeceras).await {
        return r;
    }
    let tablas: Vec<serde_json::Value> = aegis_parser::esquema::TABLAS
        .iter()
        .map(|t| {
            serde_json::json!({
                "nombre": t.nombre,
                "descripcion": t.descripcion,
                "columnas": t.columnas.iter().map(|c| serde_json::json!({
                    "nombre": c.nombre,
                    "tipo": c.tipo.nombre(),
                    "coste": format!("{:?}", c.coste).to_lowercase(),
                    "descripcion": c.descripcion,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "tablas": tablas,
            "limite_por_defecto": aegis_parser::sintaxis::LIMITE_POR_DEFECTO,
            "limite_maximo": aegis_parser::sintaxis::LIMITE_MAXIMO,
        })),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// FASE 45: heuristicas globales y correlaciones distribuidas
// ---------------------------------------------------------------------------

async fn listar_heuristicas(State(estado): State<EstadoApi>) -> axum::response::Response {
    match estado.servicio.almacen().listar_heuristicas().await {
        Ok(v) => Json(serde_json::json!({"heuristicas": v})).into_response(),
        Err(e) => error_500(e).into_response(),
    }
}

/// Crea una regla de correlacion.
///
/// La regla se valida ANTES de llegar a la base de datos, para que el analista
/// reciba un motivo en castellano en vez de un error de restriccion. Ver
/// `crate::heuristicas` para por que cada limite.
async fn crear_heuristica(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
    Json(p): Json<crate::heuristicas::NuevaHeuristica>,
) -> axum::response::Response {
    let operador = match usuario_autenticado(&estado, &cabeceras).await {
        Ok(u) => u,
        Err(r) => return r,
    };
    let regla = match p.validar() {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };
    match estado
        .servicio
        .almacen()
        .crear_heuristica(&regla, &operador)
        .await
    {
        Ok(id) => (
            StatusCode::CREATED,
            Json(serde_json::json!({"id": id.to_string(), "nombre": regla.nombre})),
        )
            .into_response(),
        Err(e) => error_500(e).into_response(),
    }
}

#[derive(Deserialize)]
struct Activa {
    activa: bool,
}

async fn fijar_heuristica_activa(
    State(estado): State<EstadoApi>,
    Path(id): Path<String>,
    Json(p): Json<Activa>,
) -> axum::response::Response {
    let Ok(id) = id.parse::<uuid::Uuid>() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "identificador invalido"})),
        )
            .into_response();
    };
    match estado
        .servicio
        .almacen()
        .fijar_heuristica_activa(id, p.activa)
        .await
    {
        Ok(true) => Json(serde_json::json!({"activa": p.activa})).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "no existe esa heuristica"})),
        )
            .into_response(),
        Err(e) => error_500(e).into_response(),
    }
}

async fn listar_correlaciones(
    State(estado): State<EstadoApi>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> axum::response::Response {
    let limite = q
        .get("limite")
        .and_then(|l| l.parse::<i64>().ok())
        .unwrap_or(50);
    match estado
        .servicio
        .almacen()
        .correlaciones_abiertas(limite)
        .await
    {
        Ok(v) => Json(serde_json::json!({"correlaciones": v})).into_response(),
        Err(e) => error_500(e).into_response(),
    }
}

/// Devuelve la evidencia MATERIALIZADA de una correlacion.
///
/// No se recalcula: la ventana es deslizante, asi que dentro de dos dias la
/// consulta que la encontro ya no devolveria las mismas maquinas, y el analista
/// que abre el caso el martes tiene que ver la evidencia que lo abrio el lunes.
async fn obtener_correlacion(
    State(estado): State<EstadoApi>,
    Path(id): Path<String>,
) -> axum::response::Response {
    let Ok(id) = id.parse::<uuid::Uuid>() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "identificador invalido"})),
        )
            .into_response();
    };
    match estado.servicio.almacen().evidencia_de_correlacion(id).await {
        Ok(v) => Json(serde_json::json!({"endpoints": v})).into_response(),
        Err(e) => error_500(e).into_response(),
    }
}

#[derive(Deserialize)]
struct Veredicto {
    veredicto: String,
}

/// Cierra una correlacion.
///
/// Cerrarla como falso positivo EXCLUYE la clave de la regla en la misma
/// transaccion. Sin eso, el motor la vuelve a encontrar un minuto despues y
/// reabre exactamente lo que el analista acaba de descartar.
async fn cerrar_correlacion(
    State(estado): State<EstadoApi>,
    Path(id): Path<String>,
    cabeceras: header::HeaderMap,
    Json(p): Json<Veredicto>,
) -> axum::response::Response {
    let operador = match usuario_autenticado(&estado, &cabeceras).await {
        Ok(u) => u,
        Err(r) => return r,
    };
    let Ok(id) = id.parse::<uuid::Uuid>() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "identificador invalido"})),
        )
            .into_response();
    };
    match estado
        .servicio
        .almacen()
        .cerrar_correlacion(id, &p.veredicto, &operador)
        .await
    {
        Ok(true) => Json(serde_json::json!({"cerrada": true})).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "no existe o ya estaba cerrada"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

// ---------------------------------------------------------------------------
// FASE 44: cuarentena de enjambre
// ---------------------------------------------------------------------------

/// Orden de cuarentena escrita por un operador.
#[derive(Deserialize)]
struct NuevaCuarentena {
    /// Direccion a aislar de toda la flota.
    direccion: String,
    /// Por que.
    motivo: String,
    /// Horas hasta que caduque sola. `None` = hasta que se levante a mano.
    horas: Option<i64>,
}

/// Pone una direccion en cuarentena en toda la flota.
async fn ordenar_cuarentena(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
    Json(p): Json<NuevaCuarentena>,
) -> axum::response::Response {
    let operador = match usuario_autenticado(&estado, &cabeceras).await {
        Ok(u) => u,
        Err(r) => return r,
    };

    // La direccion se analiza aqui. Guardarla sin analizar dejaria que una
    // cadena arbitraria llegara al campo INET y el error apareciera en la base
    // de datos, no en la consola de quien la escribio.
    let Ok(ip) = p.direccion.trim().parse::<std::net::IpAddr>() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "no es una direccion IP valida"})),
        )
            .into_response();
    };

    if let Some(r) = negar_si_es_intocable(&estado, ip).await {
        return r;
    }

    match estado
        .servicio
        .almacen()
        .poner_en_cuarentena(ip, None, &p.motivo, &operador, p.horas)
        .await
    {
        Ok(()) => {
            estado
                .servicio
                .bus()
                .publicar(crate::eventos::EventoPanel::CuarentenaCambiada {
                    direccion: ip.to_string(),
                    activa: true,
                    motivo: p.motivo.clone(),
                    por: operador,
                });
            (
                StatusCode::ACCEPTED,
                Json(serde_json::json!({"direccion": ip})),
            )
                .into_response()
        }
        Err(e) => error_500(e).into_response(),
    }
}

/// Ordena la cuarentena de enjambre CONTRA UN ENDPOINT concreto.
///
/// Es el camino que se usa durante un incidente: el operador no sabe la IP del
/// endpoint comprometido, sabe cual es la maquina. La direccion la pone el plano
/// de control desde la que OBSERVO en el handshake mTLS, nunca desde lo que el
/// agente declare: si viniera del agente, uno comprometido podria hacer que la
/// flota aislara al controlador de dominio en su lugar.
async fn cuarentena_de_enjambre(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
    Path(cn): Path<String>,
    Json(p): Json<NuevaCuarentena>,
) -> axum::response::Response {
    let operador = match usuario_autenticado(&estado, &cabeceras).await {
        Ok(u) => u,
        Err(r) => return r,
    };
    let almacen = estado.servicio.almacen();

    let ip = match almacen.direccion_de(&cn).await {
        Ok(Some(ip)) => ip,
        Ok(None) => {
            // No se puede aislar por red a un endpoint cuya direccion no se ha
            // observado nunca. Decirlo es mejor que aislar una direccion que
            // alguien haya escrito a mano y resulte ser la de otra maquina.
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "no se ha observado ninguna direccion de ese endpoint",
                    "ayuda": "la direccion se registra cuando el agente conecta por mTLS",
                })),
            )
                .into_response();
        }
        Err(e) => return error_500(e).into_response(),
    };

    if let Some(r) = negar_si_es_intocable(&estado, ip).await {
        return r;
    }

    match almacen
        .poner_en_cuarentena(ip, Some(&cn), &p.motivo, &operador, p.horas)
        .await
    {
        Ok(()) => {
            estado
                .servicio
                .bus()
                .publicar(crate::eventos::EventoPanel::CuarentenaCambiada {
                    direccion: ip.to_string(),
                    activa: true,
                    motivo: p.motivo.clone(),
                    por: operador,
                });
            (
                StatusCode::ACCEPTED,
                Json(serde_json::json!({"cn": cn, "direccion": ip})),
            )
                .into_response()
        }
        Err(e) => error_500(e).into_response(),
    }
}

/// Rechaza poner en cuarentena una direccion que dejaria a la flota sin control.
///
/// POR QUE ESTA COMPROBACION EXISTE
/// --------------------------------
/// La cuarentena de enjambre corta la red de una direccion en TODA la flota. Si
/// esa direccion fuera la del propio plano de control, cada endpoint dejaria de
/// poder hablar con el —incluido para recibir la orden de que la cuarentena se
/// levanto—. La flota entera quedaria fuera de control de golpe y solo se
/// recuperaria yendo maquina por maquina.
///
/// Es exactamente la clase de orden que alguien teclea a las tres de la manana
/// copiando una IP del sitio equivocado, y la clase de error que un producto de
/// seguridad no puede permitirse ejecutar sin protestar.
async fn negar_si_es_intocable(
    estado: &EstadoApi,
    ip: std::net::IpAddr,
) -> Option<axum::response::Response> {
    if ip.is_loopback() {
        return Some(
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "no se pone en cuarentena una direccion de bucle local"
                })),
            )
                .into_response(),
        );
    }
    for propia in &estado.direcciones_propias {
        if *propia == ip {
            return Some(
                (
                    StatusCode::CONFLICT,
                    Json(serde_json::json!({
                        "error": "esa es una direccion del propio plano de control",
                        "ayuda": "aislarla dejaria a toda la flota sin poder recibir ordenes, \
                                  incluida la de levantar esta cuarentena",
                    })),
                )
                    .into_response(),
            );
        }
    }
    None
}

/// Cuanto ha tardado el plano de control en poner la ultima orden EN EL CABLE.
///
/// POR QUE ESTE NUMERO EXISTE APARTE DEL QUE MIDE EL SIMULADOR
/// ----------------------------------------------------------
/// El simulador mide cuando cada agente RECIBE la orden, que es lo que le
/// importa al cliente y lo que hay que seguir publicando. Pero en un banco de
/// pruebas de UNA SOLA MAQUINA ese numero incluye ademas lo que tardan diez mil
/// agentes virtuales en despertar y leer sus sockets, compitiendo por los mismos
/// nucleos que el servidor. En produccion esos diez mil agentes estan en diez
/// mil maquinas distintas y no le quitan un ciclo al plano de control.
///
/// Este endpoint da la parte que el producto SI controla: desde que la lista
/// nueva queda publicada hasta que el ultimo canal termino de escribirla en su
/// socket. Las dos medidas se publican juntas; dar solo una enganaria en una
/// direccion o en la otra.
async fn difusion_cuarentena(State(estado): State<EstadoApi>) -> axum::response::Response {
    let Some(d) = estado.difusion.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "este proceso no atiende el transporte nativo de flota"
            })),
        )
            .into_response();
    };
    let (gen, escritos, ultimo_us) = d.instantanea();
    Json(serde_json::json!({
        "generacion": gen,
        "canales": escritos,
        "ultimo_ms": ultimo_us as f64 / 1000.0,
        // El reparto: es lo que distingue "va al ritmo que da la maquina" de
        // "va rapido y hay unos pocos rezagados". Ver `DifusionCuarentena`.
        "p50_ms": d.percentil_ms(50.0),
        "p90_ms": d.percentil_ms(90.0),
        "p99_ms": d.percentil_ms(99.0),
    }))
    .into_response()
}

async fn listar_cuarentena(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
    Query(q): Query<serde_json::Value>,
) -> axum::response::Response {
    let operador = match usuario_autenticado(&estado, &cabeceras).await {
        Ok(u) => u,
        Err(r) => return r,
    };

    // Un `levantar=<ip>` en la consulta retira la cuarentena. Se acepta aqui
    // ademas de como POST porque levantar una contencion tiene que ser al menos
    // tan facil como ponerla: si retirarla es dificil, el operador la deja
    // puesta "por si acaso" y acaba habiendo maquinas sanas sin red.
    if let Some(dir) = q.get("levantar").and_then(|v| v.as_str()) {
        let Ok(ip) = dir.parse::<std::net::IpAddr>() else {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "no es una direccion IP valida"})),
            )
                .into_response();
        };
        return match estado
            .servicio
            .almacen()
            .levantar_cuarentena(ip, &operador)
            .await
        {
            Ok(true) => {
                estado
                    .servicio
                    .bus()
                    .publicar(crate::eventos::EventoPanel::CuarentenaCambiada {
                        direccion: ip.to_string(),
                        activa: false,
                        motivo: String::new(),
                        por: operador,
                    });
                (StatusCode::OK, Json(serde_json::json!({"levantada": true}))).into_response()
            }
            Ok(false) => (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "no estaba en cuarentena"})),
            )
                .into_response(),
            Err(e) => error_500(e).into_response(),
        };
    }

    match estado.servicio.almacen().cuarentena_vigente().await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => error_500(e).into_response(),
    }
}
