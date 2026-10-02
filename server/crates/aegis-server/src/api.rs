//! API REST de administracion (axum), la que consume el panel web.
//!
//! # Autenticacion (H-24, H-02)
//!
//! La sesion se exige por CONSTRUCCION y no ruta a ruta. Todas las rutas se
//! declaran en un unico sitio (`declarar`), que ademas las enumera
//! (`rutas_declaradas`), y el enrutador aplica la capa `exigir_sesion` a todas
//! ellas. Una ruta solo queda abierta si esta en [`RUTAS_PUBLICAS`], que es
//! minima: la sonda de salud y el inicio de sesion. Antes cada manejador llamaba
//! a mano a la comprobacion y cinco se quedaron sin ella, una de escritura: una
//! ruta nueva nacia abierta.
//!
//! La sesion se emite SOLO contra una credencial verificada
//! ([`crate::credenciales`]); antes bastaba con escribir un nombre.
//!
//! Las acciones que TOCAN un endpoint (aislar, liberar) quedan ademas
//! registradas con el usuario que las ordeno: una accion destructiva sobre la
//! maquina de alguien no puede ser anonima.

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

/// Rutas que NO exigen sesion, como `(metodo, patron)` tal y como las casa el
/// enrutador. Es la UNICA excepcion a la autenticacion de la API, y es minima a
/// proposito:
///
/// - `GET /salud`: la sonda del balanceador, que no tiene credenciales. Solo
///   devuelve el estado de las dependencias, ningun dato de la flota.
/// - `POST /api/sesion`: el inicio de sesion, que por definicion se pide sin
///   sesion y exige credencial (ver `abrir_sesion`).
///
/// La reputacion k-anonima deja de ser publica. Recorriendo el millon de cubos,
/// un anonimo aprenderia que hashes conoce el producto como maliciosos: un
/// oraculo de evasion. Los agentes la consultaran por el canal mTLS de flota.
///
/// `tests/api_sesion.rs` fija esta lista: ampliarla es una decision revisada.
pub const RUTAS_PUBLICAS: &[(&str, &str)] = &[("GET", "/salud"), ("POST", "/api/sesion")];

/// Unica ruta que acepta el token en la consulta: el API de WebSocket del
/// navegador no permite cabeceras en el handshake (ver `websocket`).
const RUTA_WS: &str = "/api/ws";

/// Una ruta declarada en el enrutador.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RutaDeclarada {
    /// Metodo HTTP, en mayusculas.
    pub metodo: &'static str,
    /// Patron tal y como lo casa axum, con los parametros entre llaves.
    pub patron: &'static str,
}

/// El enrutador en construccion y, a la vez, la lista de lo que declara.
///
/// Es el UNICO modo de anadir una ruta a la API: lo que se declara aqui es
/// exactamente lo que recorre la prueba de 401 (`tests/api_sesion.rs`).
struct Declaracion {
    enrutador: Router<EstadoApi>,
    rutas: Vec<RutaDeclarada>,
}

impl Declaracion {
    /// Declara `patron` con sus `metodos` y su manejador.
    fn ruta(
        mut self,
        patron: &'static str,
        metodos: &[&'static str],
        manejador: axum::routing::MethodRouter<EstadoApi>,
    ) -> Declaracion {
        for &metodo in metodos {
            self.rutas.push(RutaDeclarada { metodo, patron });
        }
        self.enrutador = self.enrutador.route(patron, manejador);
        self
    }
}

/// Declara TODAS las rutas de la API. Es el unico sitio donde se anaden.
fn declarar() -> Declaracion {
    Declaracion {
        enrutador: Router::new(),
        rutas: Vec::new(),
    }
    // Publicas (ver RUTAS_PUBLICAS). El DELETE de /api/sesion exige sesion.
    .ruta("/salud", &["GET"], get(salud))
    .ruta(
        "/api/sesion",
        &["POST", "DELETE"],
        post(abrir_sesion).delete(cerrar_sesion),
    )
    // Inventario y alertas
    .ruta("/api/resumen", &["GET"], get(resumen))
    .ruta("/api/agentes", &["GET"], get(listar_agentes))
    .ruta("/api/agentes/{cn}", &["GET"], get(obtener_agente))
    .ruta("/api/agentes/{cn}/comando", &["GET"], get(tomar_comando))
    .ruta("/api/alertas", &["GET"], get(listar_alertas))
    .ruta(
        "/api/agentes/{cn}/alertas",
        &["GET"],
        get(listar_alertas_de_agente),
    )
    // Respuesta de un clic
    .ruta("/api/agentes/{cn}/aislar", &["POST"], post(aislar))
    .ruta("/api/agentes/{cn}/liberar", &["POST"], post(liberar))
    // Politica global y motor de reglas
    .ruta("/api/politicas", &["POST"], post(publicar_politica))
    .ruta(
        "/api/reglas",
        &["GET", "POST"],
        get(listar_reglas).post(crear_regla),
    )
    .ruta(
        "/api/reglas/{id}",
        &["DELETE"],
        axum::routing::delete(borrar_regla),
    )
    .ruta(
        "/api/reglas/{id}/activa",
        &["POST"],
        post(fijar_regla_activa),
    )
    // Inteligencia y linaje
    .ruta("/api/stix/objetos", &["GET"], get(listar_objetos_stix))
    .ruta("/api/grafos", &["GET"], get(listar_grafos))
    .ruta("/api/grafos/{id}", &["GET"], get(obtener_grafo))
    // Casos (FASE 76). El ciclo de vida del incidente: de alerta a cierre.
    //
    // `verificar` esta en la API a proposito y no en una herramienta de
    // administracion: un rastro que solo se comprueba cuando alguien
    // sospecha es un rastro que nadie comprueba.
    .ruta("/api/casos", &["GET"], get(listar_casos))
    .ruta("/api/casos/{id}", &["GET"], get(obtener_caso))
    .ruta(
        "/api/casos/{id}/estado",
        &["POST"],
        post(cambiar_estado_caso),
    )
    .ruta("/api/casos/{id}/cerrar", &["POST"], post(cerrar_caso))
    .ruta("/api/casos/{id}/tareas", &["POST"], post(crear_tarea_caso))
    .ruta(
        "/api/casos/{id}/tareas/{tarea}/cerrar",
        &["POST"],
        post(cerrar_tarea_caso),
    )
    .ruta("/api/casos/{id}/auditoria", &["GET"], get(rastro_caso))
    .ruta(
        "/api/casos/{id}/auditoria/verificar",
        &["GET"],
        get(verificar_caso),
    )
    .ruta(
        "/api/casos/{id}/auditoria/anclar",
        &["POST"],
        post(anclar_caso),
    )
    .ruta("/api/soc/metricas", &["GET"], get(metricas_soc))
    // Caceria distribuida AegisQL (FASE 43)
    .ruta(
        "/api/cacerias",
        &["GET", "POST"],
        get(listar_cacerias).post(lanzar_caza),
    )
    .ruta("/api/cacerias/{id}", &["GET"], get(obtener_caza))
    .ruta("/api/cacerias/{id}/cerrar", &["POST"], post(cerrar_caza))
    .ruta("/api/aegisql/esquema", &["GET"], get(esquema_aegisql))
    // Micro-segmentacion Zero-Trust (FASE 44)
    .ruta(
        "/api/cuarentena",
        &["GET", "POST"],
        get(listar_cuarentena).post(ordenar_cuarentena),
    )
    .ruta(
        "/api/agentes/{cn}/cuarentena",
        &["POST"],
        post(cuarentena_de_enjambre),
    )
    .ruta(
        "/api/cuarentena/difusion",
        &["GET"],
        get(difusion_cuarentena),
    )
    // Respuesta automatica: ITDR -> AI-RO (FASES 58 + 64)
    .ruta(
        "/api/agentes/{cn}/itdr/telemetria",
        &["POST"],
        post(ingerir_identidad),
    )
    .ruta("/api/remediaciones", &["GET"], get(listar_remediaciones))
    // Heuristicas globales: APT distribuida (FASE 45)
    .ruta(
        "/api/heuristicas",
        &["GET", "POST"],
        get(listar_heuristicas).post(crear_heuristica),
    )
    .ruta(
        "/api/heuristicas/{id}/activa",
        &["POST"],
        post(fijar_heuristica_activa),
    )
    .ruta("/api/correlaciones", &["GET"], get(listar_correlaciones))
    .ruta(
        "/api/correlaciones/{id}",
        &["GET"],
        get(obtener_correlacion),
    )
    .ruta(
        "/api/correlaciones/{id}/cerrar",
        &["POST"],
        post(cerrar_correlacion),
    )
    // Tiempo real (el token puede ir en la consulta: ver `token_de`)
    .ruta("/api/ws", &["GET"], get(websocket))
    // Reputacion k-anonima (con sesion: ver RUTAS_PUBLICAS)
    .ruta(
        "/api/reputacion/{prefijo}",
        &["GET"],
        get(consultar_reputacion),
    )
    .ruta("/api/reputacion", &["POST"], post(registrar_reputacion))
}

/// Todas las rutas declaradas de la API, para las pruebas y la documentacion.
pub fn rutas_declaradas() -> Vec<RutaDeclarada> {
    declarar().rutas
}

/// Indica si `(metodo, patron)` esta en [`RUTAS_PUBLICAS`].
pub fn es_publica(metodo: &str, patron: &str) -> bool {
    RUTAS_PUBLICAS
        .iter()
        .any(|&(m, p)| m == metodo && p == patron)
}

/// Construye el enrutador de la API.
///
/// La capa de sesion se aplica con `route_layer` sobre el enrutador ENTERO:
/// corre despues de casar la ruta (asi conoce su patron) y antes del manejador
/// y de sus extractores. Una ruta nueva queda protegida sin que nadie tenga que
/// acordarse.
pub fn enrutador(estado: EstadoApi) -> Router {
    declarar()
        .enrutador
        .route_layer(axum::middleware::from_fn_with_state(
            estado.clone(),
            exigir_sesion,
        ))
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

    let mut cuerpo = serde_json::json!({
        "estado": if listo { "listo" } else { "degradado" },
        "postgres": bd_ok,
        "redis": cache_ok,
        "pool": { "conexiones": pool.size(), "ociosas": pool.num_idle() },
    });
    // FASE 6.4: la salida al SIEM se reconcilia con estos numeros. Son
    // cuentas, no datos de ningun cliente.
    if let Some(f) = estado.servicio.firehose() {
        cuerpo["firehose"] = f.estado();
    }

    // 503 cuando falta una dependencia: es lo que un balanceador entiende.
    let codigo = if listo {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (codigo, Json(cuerpo)).into_response()
}

/// Credenciales para abrir sesion.
///
/// Sin `Debug` a proposito: la clave no puede acabar en un registro.
#[derive(Deserialize)]
struct Credenciales {
    /// Nombre del operador.
    usuario: String,
    /// Clave del operador; solo vive durante esta peticion.
    clave: String,
}

/// Abre una sesion de administracion contra una credencial VERIFICADA (H-02).
///
/// La clave se comprueba contra el derivado PBKDF2 de `operadores`
/// ([`crate::credenciales`]). Clave erronea y usuario inexistente dan la MISMA
/// respuesta y cuestan lo mismo. Los fallos se cuentan por usuario en Redis y,
/// pasado el cupo, se responde 429 hasta que caduca la ventana, aunque la clave
/// sea la correcta.
async fn abrir_sesion(
    State(estado): State<EstadoApi>,
    Json(cred): Json<Credenciales>,
) -> axum::response::Response {
    let usuario = cred.usuario.trim().to_string();
    if usuario.is_empty() || cred.clave.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "usuario y clave son obligatorios"})),
        )
            .into_response();
    }
    if usuario.len() > crate::credenciales::LONGITUD_MAXIMA_USUARIO
        || cred.clave.len() > crate::credenciales::LONGITUD_MAXIMA_CLAVE
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "credenciales desmesuradas"})),
        )
            .into_response();
    }
    match estado.cache.fallos_acceso(&usuario).await {
        Ok(n) if n >= crate::cache::MAX_FALLOS_ACCESO => {
            tracing::warn!(usuario = %usuario, fallos = n, "inicio de sesion frenado por intentos fallidos");
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({"error": "demasiados intentos fallidos; espera antes de reintentar"})),
            )
                .into_response();
        }
        Ok(_) => {}
        Err(e) => return error_500(e).into_response(),
    }
    let guardado =
        match crate::credenciales::hash_de_operador(estado.servicio.almacen().pool(), &usuario)
            .await
        {
            Ok(h) => h,
            Err(e) => return error_500(e).into_response(),
        };
    let clave = cred.clave;
    // PBKDF2 es trabajo de CPU deliberado (centenares de ms): fuera del runtime.
    let valida = tokio::task::spawn_blocking(move || {
        crate::credenciales::comprobar(&clave, guardado.as_deref())
    })
    .await
    .unwrap_or(false);
    if !valida {
        let _ = estado.cache.contar_fallo_acceso(&usuario).await;
        tracing::warn!(usuario = %usuario, "inicio de sesion rechazado: credencial invalida");
        return no_autorizado("credenciales invalidas");
    }
    let _ = estado.cache.limpiar_fallos_acceso(&usuario).await;
    if let Err(e) =
        crate::credenciales::registrar_acceso(estado.servicio.almacen().pool(), &usuario).await
    {
        tracing::warn!(error = %e, "no se pudo anotar el ultimo acceso del operador");
    }
    // Rol e inquilino salen de `operadores`, nunca de la peticion (FASE 6.2).
    let (rol, inquilino) =
        match crate::autorizacion::operador(estado.servicio.almacen().pool(), &usuario).await {
            Ok(Some(ri)) => ri,
            Ok(None) => return no_autorizado("credenciales invalidas"),
            Err(e) => return error_500(e).into_response(),
        };
    let sesion = crate::autorizacion::SesionOperador {
        usuario: usuario.clone(),
        rol,
        inquilino,
    };
    match estado.cache.abrir_sesion_operador(&sesion).await {
        Ok(token) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "token": token,
                "rol": sesion.rol.nombre(),
                "inquilino": sesion.inquilino,
            })),
        )
            .into_response(),
        Err(e) => error_500(e).into_response(),
    }
}

/// Usuario de la sesion que valido la capa `exigir_sesion`.
///
/// Queda en las extensiones de la peticion para los manejadores que lo
/// necesiten.
#[derive(Debug, Clone)]
pub struct Operador(pub String);

/// Capa que exige sesion a toda ruta que no este en [`RUTAS_PUBLICAS`].
///
/// Si falta el patron casado —no deberia ocurrir con `route_layer`— no hay
/// excepcion posible y se exige sesion: la capa falla cerrada.
async fn exigir_sesion(
    State(estado): State<EstadoApi>,
    peticion: axum::extract::Request,
    siguiente: axum::middleware::Next,
) -> axum::response::Response {
    let patron = peticion
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|m| m.as_str().to_owned())
        .unwrap_or_default();
    if es_publica(peticion.method().as_str(), &patron) {
        return siguiente.run(peticion).await;
    }
    let Some(token) = token_de(&peticion, &patron) else {
        return no_autorizado("falta Authorization: Bearer <token>");
    };
    let sesion = match estado.cache.sesion_operador(&token).await {
        Ok(Some(s)) => s,
        Ok(None) => return no_autorizado("sesion invalida o caducada"),
        Err(e) => return error_500(e).into_response(),
    };
    // Autorizacion (FASE 6.2): rol, contenido de plataforma y dueno del
    // recurso, con los parametros de la ruta ya decodificados.
    let (mut partes, cuerpo) = peticion.into_parts();
    let parametros: Vec<(String, String)> = match <axum::extract::RawPathParams as axum::extract::FromRequestParts<()>>::from_request_parts(&mut partes, &()).await {
        Ok(p) => p
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        Err(_) => Vec::new(),
    };
    let mut peticion = axum::extract::Request::from_parts(partes, cuerpo);
    if let Err(d) = crate::autorizacion::autorizar(
        estado.servicio.almacen().pool(),
        &sesion,
        peticion.method().as_str(),
        &patron,
        &parametros,
    )
    .await
    {
        tracing::warn!(
            usuario = %sesion.usuario,
            inquilino = %sesion.inquilino,
            metodo = %peticion.method(),
            patron = %patron,
            motivo = ?d,
            "peticion denegada"
        );
        return d.respuesta();
    }
    peticion
        .extensions_mut()
        .insert(Operador(sesion.usuario.clone()));
    peticion.extensions_mut().insert(sesion);
    siguiente.run(peticion).await
}

/// Token de la peticion: la cabecera `Authorization: Bearer`, o, SOLO en el
/// handshake de WebSocket de [`RUTA_WS`], el parametro `token` de la consulta.
fn token_de(peticion: &axum::extract::Request, patron: &str) -> Option<String> {
    let portador = peticion
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|t| !t.is_empty());
    if let Some(t) = portador {
        return Some(t.to_string());
    }
    let es_websocket = patron == RUTA_WS
        && peticion
            .headers()
            .get(header::UPGRADE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    if !es_websocket {
        return None;
    }
    peticion
        .uri()
        .query()?
        .split('&')
        .find_map(|par| par.strip_prefix("token="))
        .filter(|t| !t.is_empty())
        .map(str::to_string)
}

/// Respuesta 401 con su motivo.
fn no_autorizado(motivo: &'static str) -> axum::response::Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({"error": motivo})),
    )
        .into_response()
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
    axum::Extension(sesion): axum::Extension<crate::autorizacion::SesionOperador>,
) -> axum::response::Response {
    if let Err(r) = usuario_autenticado(&estado, &cabeceras).await {
        return r;
    }
    match crate::inquilino::resumen(
        estado.servicio.almacen().pool(),
        &sesion.inquilino,
        estado.margen_desconexion_seg,
    )
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
    axum::Extension(sesion): axum::Extension<crate::autorizacion::SesionOperador>,
    Query(q): Query<Limite>,
) -> axum::response::Response {
    if let Err(r) = usuario_autenticado(&estado, &cabeceras).await {
        return r;
    }
    // El limite lo controla el cliente: se acota para que una peticion no pueda
    // pedir la flota entera y tumbar la memoria del servidor.
    let limite = q.limite.unwrap_or(200).clamp(1, 5_000);
    match crate::inquilino::listar_agentes(
        estado.servicio.almacen().pool(),
        &sesion.inquilino,
        estado.margen_desconexion_seg,
        limite,
    )
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
    axum::Extension(sesion): axum::Extension<crate::autorizacion::SesionOperador>,
    Query(q): Query<Limite>,
) -> axum::response::Response {
    if let Err(r) = usuario_autenticado(&estado, &cabeceras).await {
        return r;
    }
    let limite = q.limite.unwrap_or(100).clamp(1, 5_000);
    match crate::inquilino::listar_alertas(
        estado.servicio.almacen().pool(),
        &sesion.inquilino,
        limite,
        q.abiertas.unwrap_or(false),
    )
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
    axum::Extension(sesion): axum::Extension<crate::autorizacion::SesionOperador>,
    ws: WebSocketUpgrade,
) -> axum::response::Response {
    // La sesion ya la valido la capa (`exigir_sesion`): con el token de la
    // cabecera o, solo en este handshake, el de la consulta.
    ws.on_upgrade(move |socket| atender_websocket(socket, estado, sesion))
}

/// Bombea los eventos del bus hacia una consola conectada.
async fn atender_websocket(
    mut socket: WebSocket,
    estado: EstadoApi,
    sesion: crate::autorizacion::SesionOperador,
) {
    let usuario = sesion.usuario.clone();
    let mut receptor = estado.servicio.bus().suscribir();
    tracing::info!(usuario = %usuario, consolas = estado.servicio.bus().consolas(),
        "consola conectada al tiempo real");

    // Primer mensaje: una instantanea, para que la consola pinte algo de
    // inmediato en vez de una pantalla vacia hasta que ocurra el primer suceso.
    // La instantanea es la del inquilino de la sesion (FASE 6.2).
    let resumen = crate::inquilino::resumen(
        estado.servicio.almacen().pool(),
        &sesion.inquilino,
        estado.margen_desconexion_seg,
    )
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
                    // El bus es uno para todos: solo sale lo de su inquilino.
                    if !crate::autorizacion::evento_visible(&sesion, &evento) {
                        continue;
                    }
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
    axum::Extension(sesion): axum::Extension<crate::autorizacion::SesionOperador>,
    Json(p): Json<NuevaCaza>,
) -> axum::response::Response {
    let operador = match usuario_autenticado(&estado, &cabeceras).await {
        Ok(u) => u,
        Err(r) => return r,
    };

    // FASE 6.2 (H-25): techos ANTES de analizar, persistir y difundir.
    if p.consulta.len() > crate::autorizacion::MAX_CONSULTA_BYTES {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({
                "error": format!(
                    "la consulta pasa de {} bytes",
                    crate::autorizacion::MAX_CONSULTA_BYTES
                )
            })),
        )
            .into_response();
    }
    match crate::inquilino::cazas_abiertas(estado.servicio.almacen().pool(), &sesion.inquilino)
        .await
    {
        Ok(n) if n >= crate::autorizacion::MAX_CAZAS_ABIERTAS => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({
                    "error": format!("ya hay {n} cazas abiertas; cierra alguna antes"),
                    "maximo": crate::autorizacion::MAX_CAZAS_ABIERTAS,
                })),
            )
                .into_response()
        }
        Ok(_) => {}
        Err(e) => return error_500(e).into_response(),
    }

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
    // El coste se decide AQUI, antes de guardar y difundir (H-25).
    let tope = crate::autorizacion::coste_maximo_de(sesion.rol);
    if plan.coste_maximo > tope {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({
                "error": "la caza supera el coste que permite el rol",
                "coste": format!("{:?}", plan.coste_maximo).to_lowercase(),
                "tope": format!("{tope:?}").to_lowercase(),
            })),
        )
            .into_response();
    }
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
    match crate::inquilino::lanzar_caza(
        almacen.pool(),
        &sesion.inquilino,
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
    axum::Extension(sesion): axum::Extension<crate::autorizacion::SesionOperador>,
    Query(q): Query<Limite>,
) -> axum::response::Response {
    if let Err(r) = usuario_autenticado(&estado, &cabeceras).await {
        return r;
    }
    let limite = q.limite.unwrap_or(50).clamp(1, 500);
    match crate::inquilino::listar_cacerias(
        estado.servicio.almacen().pool(),
        &sesion.inquilino,
        limite,
    )
    .await
    {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => error_500(e).into_response(),
    }
}

/// Una caceria con su resumen agregado y las respuestas mas utiles.
async fn obtener_caza(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
    axum::Extension(sesion): axum::Extension<crate::autorizacion::SesionOperador>,
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

    // Solo cuentan las respuestas de agentes del inquilino: un agente ajeno
    // podria subir una respuesta con el identificador de esta caza.
    let pool = almacen.pool();
    let (caza, resumen, respuestas) = tokio::join!(
        almacen.obtener_caza(id),
        crate::inquilino::resumen_caza(pool, id, &sesion.inquilino),
        crate::inquilino::respuestas_caza(pool, id, &sesion.inquilino, limite)
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

// --- Casos (FASE 76) --------------------------------------------------------
//
// El ciclo de vida del incidente. La logica entera vive en `aegis-case` como
// funciones puras; `crate::casos` la pone en PostgreSQL; y esto es la superficie
// que ve el panel.

/// Filtro de listado de casos.
///
/// Sin `inquilino` (FASE 6.2): lo fija la sesion. Un `?inquilino=` en la
/// consulta se ignora.
#[derive(Debug, serde::Deserialize)]
struct FiltroCasos {
    limite: Option<i64>,
}

/// Lo que el panel manda para cambiar de estado.
#[derive(Debug, serde::Deserialize)]
struct CambioEstado {
    estado: String,
}

/// Lo que el panel manda para cerrar.
#[derive(Debug, serde::Deserialize)]
struct CierreCaso {
    veredicto: String,
    justificacion: Option<String>,
}

/// Lo que el panel manda para crear una tarea.
#[derive(Debug, serde::Deserialize)]
struct TareaNueva {
    titulo: String,
}

/// Lo que el panel manda para cerrar una tarea.
#[derive(Debug, serde::Deserialize)]
struct CierreTarea {
    motivo: Option<String>,
}

fn servicio_casos(estado: &EstadoApi) -> crate::casos::ServicioCasos {
    crate::casos::ServicioCasos::nuevo(estado.servicio.almacen())
}

/// Rechazo con el motivo legible tal cual.
///
/// Se devuelve 409 y no 400: la peticion esta bien formada, lo que pasa es que
/// el caso no esta en un estado en el que eso se pueda hacer. Y el motivo viaja
/// entero porque el analista lo va a leer en el panel a las tres de la manana.
fn conflicto(e: crate::error::ErrorServidor) -> axum::response::Response {
    match e {
        crate::error::ErrorServidor::Config(motivo) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": motivo })),
        )
            .into_response(),
        otro => error_500(otro).into_response(),
    }
}

async fn listar_casos(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
    axum::Extension(sesion): axum::Extension<crate::autorizacion::SesionOperador>,
    Query(q): Query<FiltroCasos>,
) -> axum::response::Response {
    if let Err(r) = usuario_autenticado(&estado, &cabeceras).await {
        return r;
    }
    let limite = q.limite.unwrap_or(50);
    match servicio_casos(&estado)
        .listar(Some(&sesion.inquilino), limite)
        .await
    {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => error_500(e).into_response(),
    }
}

async fn obtener_caso(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
    Path(id): Path<String>,
) -> axum::response::Response {
    let usuario = match usuario_autenticado(&estado, &cabeceras).await {
        Ok(u) => u,
        Err(r) => return r,
    };
    let s = servicio_casos(&estado);
    // QUIEN VIO QUE tambien es parte de la pregunta que un rastro contesta, y el
    // acceso a informacion personal se audita por obligacion en cualquier
    // regimen de proteccion de datos. Se anota ANTES de devolver el caso.
    if let Err(e) = s.consultado(&id, &usuario).await {
        return conflicto(e);
    }
    match s.listar(None, crate::casos::MAX_LISTADO).await {
        Ok(v) => match v.into_iter().find(|c| c.id == id) {
            Some(c) => (StatusCode::OK, Json(c)).into_response(),
            None => (StatusCode::NOT_FOUND, "caso desconocido").into_response(),
        },
        Err(e) => error_500(e).into_response(),
    }
}

async fn cambiar_estado_caso(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
    Path(id): Path<String>,
    Json(c): Json<CambioEstado>,
) -> axum::response::Response {
    let usuario = match usuario_autenticado(&estado, &cabeceras).await {
        Ok(u) => u,
        Err(r) => return r,
    };
    let nuevo = match c.estado.as_str() {
        "nuevo" => aegis_case::Estado::Nuevo,
        "en-curso" => aegis_case::Estado::EnCurso,
        "en-espera" => aegis_case::Estado::EnEspera,
        "contenido" => aegis_case::Estado::Contenido,
        "cerrado" => aegis_case::Estado::Cerrado,
        otro => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("estado «{otro}» desconocido") })),
            )
                .into_response()
        }
    };
    match servicio_casos(&estado).pasar_a(&id, nuevo, &usuario).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => conflicto(e),
    }
}

async fn cerrar_caso(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
    Path(id): Path<String>,
    Json(c): Json<CierreCaso>,
) -> axum::response::Response {
    let usuario = match usuario_autenticado(&estado, &cabeceras).await {
        Ok(u) => u,
        Err(r) => return r,
    };
    let v = match c.veredicto.as_str() {
        "verdadero" => aegis_case::Veredicto::Verdadero,
        "falso-positivo" => aegis_case::Veredicto::FalsoPositivo,
        "autorizado" => aegis_case::Veredicto::Autorizado,
        "no-concluyente" => aegis_case::Veredicto::NoConcluyente,
        otro => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("veredicto «{otro}» desconocido") })),
            )
                .into_response()
        }
    };
    match servicio_casos(&estado)
        .cerrar(&id, v, c.justificacion, &usuario)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => conflicto(e),
    }
}

async fn crear_tarea_caso(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
    Path(id): Path<String>,
    Json(t): Json<TareaNueva>,
) -> axum::response::Response {
    let usuario = match usuario_autenticado(&estado, &cabeceras).await {
        Ok(u) => u,
        Err(r) => return r,
    };
    match servicio_casos(&estado)
        .anadir_tarea(&id, &t.titulo, &usuario)
        .await
    {
        Ok(n) => (StatusCode::CREATED, Json(serde_json::json!({ "id": n }))).into_response(),
        Err(e) => conflicto(e),
    }
}

async fn cerrar_tarea_caso(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
    Path((id, tarea)): Path<(String, i32)>,
    Json(c): Json<CierreTarea>,
) -> axum::response::Response {
    let usuario = match usuario_autenticado(&estado, &cabeceras).await {
        Ok(u) => u,
        Err(r) => return r,
    };
    match servicio_casos(&estado)
        .cerrar_tarea(&id, tarea, c.motivo, &usuario)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => conflicto(e),
    }
}

async fn rastro_caso(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
    Path(id): Path<String>,
) -> axum::response::Response {
    if let Err(r) = usuario_autenticado(&estado, &cabeceras).await {
        return r;
    }
    match servicio_casos(&estado).rastro(&id).await {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => error_500(e).into_response(),
    }
}

async fn verificar_caso(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
    Path(id): Path<String>,
) -> axum::response::Response {
    if let Err(r) = usuario_autenticado(&estado, &cabeceras).await {
        return r;
    }
    match servicio_casos(&estado).verificar(&id).await {
        // Un rastro roto se devuelve con 200 y `intacto: false`, no con un
        // error: el error se pierde en un registro y lo que hace falta es que el
        // panel lo enseñe en rojo con las roturas enumeradas.
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(e) => error_500(e).into_response(),
    }
}

async fn anclar_caso(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
    Path(id): Path<String>,
) -> axum::response::Response {
    if let Err(r) = usuario_autenticado(&estado, &cabeceras).await {
        return r;
    }
    match servicio_casos(&estado).anclar(&id, None).await {
        Ok(hasta) => (
            StatusCode::OK,
            Json(serde_json::json!({ "anclado_hasta": hasta })),
        )
            .into_response(),
        Err(e) => error_500(e).into_response(),
    }
}

async fn metricas_soc(
    State(estado): State<EstadoApi>,
    cabeceras: header::HeaderMap,
    axum::Extension(sesion): axum::Extension<crate::autorizacion::SesionOperador>,
) -> axum::response::Response {
    if let Err(r) = usuario_autenticado(&estado, &cabeceras).await {
        return r;
    }
    match servicio_casos(&estado)
        .metricas(Some(&sesion.inquilino))
        .await
    {
        Ok(r) => {
            // Lo que el panel necesita para APAGAR reglas, que es la unica
            // metrica que de verdad cambia un centro de operaciones.
            let sospechosas: Vec<_> = r
                .reglas_sospechosas()
                .iter()
                .map(|x| {
                    serde_json::json!({
                        "regla": x.nombre,
                        "ruido_por_ciento": x.ruido_centesimas(),
                        "casos_cerrados": x.casos_cerrados,
                        "falsos_positivos": x.falsos_positivos,
                        "verdaderos": x.verdaderos,
                    })
                })
                .collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "abiertos": r.abiertos,
                    "cerrados": r.cerrados,
                    "vivos": r.vivos,
                    "sin_asignar": r.sin_asignar,
                    "hasta_deteccion_ns": {
                        "p50": r.hasta_deteccion.p50_ns,
                        "p95": r.hasta_deteccion.p95_ns,
                        "p99": r.hasta_deteccion.p99_ns,
                        "maximo": r.hasta_deteccion.maximo_ns,
                    },
                    "hasta_respuesta_ns": {
                        "p50": r.hasta_respuesta.p50_ns,
                        "p95": r.hasta_respuesta.p95_ns,
                        "p99": r.hasta_respuesta.p99_ns,
                        "maximo": r.hasta_respuesta.maximo_ns,
                    },
                    "hasta_cierre_ns": {
                        "p50": r.hasta_cierre.p50_ns,
                        "p95": r.hasta_cierre.p95_ns,
                        "p99": r.hasta_cierre.p99_ns,
                        "maximo": r.hasta_cierre.maximo_ns,
                    },
                    "por_veredicto": r.por_veredicto,
                    "reglas_sospechosas": sospechosas,
                })),
            )
                .into_response()
        }
        Err(e) => error_500(e).into_response(),
    }
}

// ---------------------------------------------------------------------------
// Validacion de entradas: la superficie del fuzzing de la API (E6.13, FASE 6.2)
// ---------------------------------------------------------------------------

/// Error de [`validar_cuerpo`] para una ruta sin esquema declarado.
pub const SIN_ESQUEMA: &str = "ruta sin esquema de cuerpo";

/// Lo que la API hace con el CUERPO de una peticion antes de tocar la base de
/// datos: el MISMO tipo y los MISMOS validadores que el manejador de la ruta.
///
/// Es la superficie del objetivo de fuzzing `api_cuerpos` (server/fuzz). Una
/// ruta de escritura nueva sin entrada aqui hace fallar
/// `tests/rbac_matriz.rs`, asi que ninguna ruta queda sin fuzzing.
///
/// # Errors
///
/// El motivo del rechazo, o [`SIN_ESQUEMA`].
pub fn validar_cuerpo(metodo: &str, patron: &str, cuerpo: &[u8]) -> Result<(), String> {
    fn json<T: serde::de::DeserializeOwned>(b: &[u8]) -> Result<T, String> {
        serde_json::from_slice(b).map_err(|e| e.to_string())
    }
    match (metodo, patron) {
        ("POST", "/api/sesion") => {
            let c: Credenciales = json(cuerpo)?;
            let _ = (c.usuario.len(), c.clave.len());
            Ok(())
        }
        // Rutas de escritura sin cuerpo.
        ("DELETE", "/api/sesion")
        | ("POST", "/api/agentes/{cn}/aislar")
        | ("POST", "/api/agentes/{cn}/liberar")
        | ("DELETE", "/api/reglas/{id}")
        | ("POST", "/api/casos/{id}/auditoria/anclar")
        | ("POST", "/api/cacerias/{id}/cerrar") => Ok(()),
        ("POST", "/api/politicas") => {
            let p: NuevaPolitica = json(cuerpo)?;
            let _ = (p.nombre, p.contenido);
            Ok(())
        }
        ("POST", "/api/reglas") => {
            let r: NuevaRegla = json(cuerpo)?;
            let tipo = crate::reglas::TipoRegla::de_str(&r.tipo).ok_or("tipo desconocido")?;
            crate::reglas::validar(tipo, &r.parametros).map_err(|e| e.to_string())?;
            let _ = (r.nombre, r.severidad);
            Ok(())
        }
        ("POST", "/api/reglas/{id}/activa") => json::<CambioActiva>(cuerpo).map(|c| {
            let _ = c.activa;
        }),
        ("POST", "/api/casos/{id}/estado") => json::<CambioEstado>(cuerpo).map(|c| {
            let _ = c.estado;
        }),
        ("POST", "/api/casos/{id}/cerrar") => json::<CierreCaso>(cuerpo).map(|c| {
            let _ = (c.veredicto, c.justificacion);
        }),
        ("POST", "/api/casos/{id}/tareas") => json::<TareaNueva>(cuerpo).map(|t| {
            let _ = t.titulo;
        }),
        ("POST", "/api/casos/{id}/tareas/{tarea}/cerrar") => json::<CierreTarea>(cuerpo).map(|c| {
            let _ = c.motivo;
        }),
        ("POST", "/api/cacerias") => {
            let p: NuevaCaza = json(cuerpo)?;
            if p.consulta.len() > crate::autorizacion::MAX_CONSULTA_BYTES {
                return Err("consulta desmesurada".to_string());
            }
            let c = aegis_parser::sintaxis::analizar(&p.consulta)
                .map_err(|e| e.dibujar(&p.consulta))?;
            let _ = aegis_parser::plan::planificar(c).coste_maximo;
            Ok(())
        }
        ("POST", "/api/cuarentena") | ("POST", "/api/agentes/{cn}/cuarentena") => {
            let p: NuevaCuarentena = json(cuerpo)?;
            p.direccion
                .trim()
                .parse::<std::net::IpAddr>()
                .map_err(|e| e.to_string())?;
            let _ = (p.motivo, p.horas);
            Ok(())
        }
        ("POST", "/api/agentes/{cn}/itdr/telemetria") => {
            let lote: crate::remediacion::dto::LoteIdentidad = json(cuerpo)?;
            lote.validar().map_err(|e| e.to_string())?;
            let _ = crate::itdr::TelemetriaIdentidad::from(&lote);
            Ok(())
        }
        ("POST", "/api/heuristicas") => {
            let p: crate::heuristicas::NuevaHeuristica = json(cuerpo)?;
            p.validar().map(|_| ()).map_err(|e| e.to_string())
        }
        ("POST", "/api/heuristicas/{id}/activa") => json::<Activa>(cuerpo).map(|a| {
            let _ = a.activa;
        }),
        ("POST", "/api/correlaciones/{id}/cerrar") => json::<Veredicto>(cuerpo).map(|v| {
            let _ = v.veredicto;
        }),
        ("POST", "/api/reputacion") => json::<AltaReputacion>(cuerpo).map(|a| {
            let _ = (a.hash, a.veredicto);
        }),
        _ => Err(SIN_ESQUEMA.to_string()),
    }
}

/// Lo que la API hace con la CONSULTA (`?...`) de una ruta de lectura: los
/// mismos extractores que sus manejadores. Superficie de `api_cuerpos`.
///
/// # Errors
///
/// El rechazo del extractor.
pub fn validar_consulta(patron: &str, consulta: &str) -> Result<(), String> {
    fn q<T: serde::de::DeserializeOwned>(u: &axum::http::Uri) -> Result<(), String> {
        Query::<T>::try_from_uri(u)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
    let Ok(uri) = format!("/x?{consulta}").parse::<axum::http::Uri>() else {
        return Err("consulta que no es una URI".to_string());
    };
    match patron {
        "/api/agentes"
        | "/api/alertas"
        | "/api/agentes/{cn}/alertas"
        | "/api/stix/objetos"
        | "/api/grafos"
        | "/api/cacerias"
        | "/api/cacerias/{id}"
        | "/api/remediaciones" => q::<Limite>(&uri),
        "/api/casos" => q::<FiltroCasos>(&uri),
        "/api/correlaciones" => q::<std::collections::HashMap<String, String>>(&uri),
        "/api/cuarentena" => q::<serde_json::Value>(&uri),
        _ => Ok(()),
    }
}
