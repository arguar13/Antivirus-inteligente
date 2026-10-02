//! Apoyo comun a las pruebas de inquilino hostil, matriz RBAC y AegisQL hostil
//! (FASE 6.2 del MP-16). Cada fichero de `tests/` es un crate aparte y no usa
//! todo lo de aqui.
#![allow(dead_code)]

use std::sync::Arc;

use aegis_prueba::{omitir, Requisito};
use aegis_server::almacen::Almacen;
use aegis_server::api::{self, EstadoApi};
use aegis_server::autorizacion::{self, Rol};
use aegis_server::cache::Cache;
use aegis_server::dominio::ServicioFlota;
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

/// Clave de los operadores de prueba (pasa la longitud minima del alta).
pub const CLAVE: &str = "una clave larga de prueba";

pub fn url_pg() -> String {
    std::env::var("AEGIS_TEST_PG_URL")
        .unwrap_or_else(|_| "postgres://postgres@%2Fvar%2Frun%2Fpostgresql/aegis_test".to_string())
}

pub fn url_redis() -> String {
    std::env::var("AEGIS_TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string())
}

/// Sufijo unico por ejecucion: las pruebas comparten la base de datos.
pub fn unico() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..12].to_string()
}

/// Estado de la API contra PostgreSQL y Redis reales. Sin ellos se omite
/// diciendolo (y, con `AEGIS_EXIGIR=servicios`, falla).
pub async fn estado_real() -> Option<(EstadoApi, Almacen, Arc<ServicioFlota>)> {
    let almacen = match Almacen::conectar(&url_pg(), 8).await {
        Ok(a) => a,
        Err(e) => {
            omitir(&format!("no hay PostgreSQL ({e})"), Requisito::Postgresql);
            return None;
        }
    };
    // Una migracion que no aplica es un fallo, no una omision.
    almacen.migrar().await.expect("las migraciones aplican");
    let cache = match Cache::conectar(&url_redis()).await {
        Ok(c) => c,
        Err(e) => {
            omitir(&format!("no hay Redis ({e})"), Requisito::Redis);
            return None;
        }
    };
    let servicio = Arc::new(ServicioFlota::nuevo(almacen.clone(), 30));
    let estado = EstadoApi {
        servicio: servicio.clone(),
        cache,
        margen_desconexion_seg: 90,
        direcciones_propias: Vec::new(),
        difusion: None,
        remediacion: None,
    };
    Some((estado, almacen, servicio))
}

/// Da de alta un operador con rol e inquilino y devuelve su usuario.
pub async fn operador(almacen: &Almacen, rol: Rol, inquilino: &str) -> String {
    let usuario = format!("op-{}-{}", rol.nombre(), unico());
    // Pocas iteraciones: se mide el circuito, no el coste de PBKDF2.
    let hash = aegis_server::credenciales::derivar_con(CLAVE, 1_000).unwrap();
    aegis_server::credenciales::alta_operador(almacen.pool(), &usuario, &hash)
        .await
        .unwrap();
    assert!(
        autorizacion::asignar_rol(almacen.pool(), &usuario, rol, inquilino)
            .await
            .unwrap(),
        "el operador recien dado de alta existe"
    );
    usuario
}

/// Abre sesion y devuelve el token.
pub async fn entrar(app: &axum::Router, usuario: &str) -> String {
    let (c, cuerpo) = pedir(
        app,
        "POST",
        "/api/sesion",
        None,
        Some(serde_json::json!({ "usuario": usuario, "clave": CLAVE })),
    )
    .await;
    assert_eq!(c, StatusCode::OK, "sesion de {usuario}: {cuerpo}");
    let v: serde_json::Value = serde_json::from_str(&cuerpo).unwrap();
    v["token"].as_str().expect("token").to_string()
}

/// Una peticion contra el enrutador en proceso; devuelve codigo y cuerpo.
pub async fn pedir(
    app: &axum::Router,
    metodo: &str,
    uri: &str,
    token: Option<&str>,
    cuerpo: Option<serde_json::Value>,
) -> (StatusCode, String) {
    let mut b = Request::builder().method(metodo).uri(uri);
    if let Some(t) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let body = match cuerpo {
        Some(v) => {
            b = b.header(header::CONTENT_TYPE, "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    let resp = app
        .clone()
        .oneshot(b.body(body).unwrap())
        .await
        .expect("el enrutador responde");
    let codigo = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap_or_default();
    (codigo, String::from_utf8_lossy(&bytes).into_owned())
}

/// Sustituye los parametros del patron: `{cn}`, `{id}`, `{tarea}` y
/// `{prefijo}`, con codificacion de ruta minima (los CN de prueba no llevan
/// caracteres reservados).
pub fn concretar(patron: &str, cn: &str, id: &str) -> String {
    patron
        .split('/')
        .map(|s| match s {
            "{cn}" => cn.to_string(),
            "{id}" => id.to_string(),
            "{tarea}" => "1".to_string(),
            "{prefijo}" => "abcde".to_string(),
            otro => otro.to_string(),
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// La enrutadora de produccion sobre un estado.
pub fn app(estado: EstadoApi) -> axum::Router {
    api::enrutador(estado)
}
