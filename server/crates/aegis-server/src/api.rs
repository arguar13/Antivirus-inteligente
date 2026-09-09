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
        // Respuesta de un clic
        .route("/api/agentes/{cn}/aislar", post(aislar))
        .route("/api/agentes/{cn}/liberar", post(liberar))
        // Politica global y motor de reglas
        .route("/api/politicas", post(publicar_politica))
        .route("/api/reglas", get(listar_reglas).post(crear_regla))
        .route("/api/reglas/{id}", axum::routing::delete(borrar_regla))
        .route("/api/reglas/{id}/activa", post(fijar_regla_activa))
        // Inteligencia y linaje
        .route("/api/stix/objetos", get(listar_objetos_stix))
        .route("/api/grafos", get(listar_grafos))
        .route("/api/grafos/{id}", get(obtener_grafo))
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
