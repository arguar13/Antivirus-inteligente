//! Puerta de H-24 y H-02: toda ruta de la API exige sesion por CONSTRUCCION, y
//! la sesion solo se emite contra una credencial verificada.
//!
//! Dos clases de prueba:
//!
//! - Sin servicios (corren siempre): la lista publica es la minima y existe, y
//!   ninguna ruta entra en el enrutador por fuera de la declaracion que la
//!   enumera.
//! - Con PostgreSQL y Redis reales: se RECORREN todas las rutas declaradas y
//!   cada una que no este en la lista publica responde 401 sin sesion y con una
//!   sesion inventada. Tambien se prueba el inicio de sesion con credencial y el
//!   freno a los intentos fallidos. Si faltan los servicios, `aegis_prueba`
//!   decide: make ci los exige (la prueba FALLA); en local se omite y lo anota.

use std::sync::Arc;

use aegis_prueba::{omitir, Requisito};

use aegis_server::almacen::Almacen;
use aegis_server::api::{self, EstadoApi, RutaDeclarada, RUTAS_PUBLICAS};
use aegis_server::cache::Cache;
use aegis_server::dominio::ServicioFlota;
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

fn url_pg() -> String {
    std::env::var("AEGIS_TEST_PG_URL")
        .unwrap_or_else(|_| "postgres://postgres@%2Fvar%2Frun%2Fpostgresql/aegis_test".to_string())
}

fn url_redis() -> String {
    std::env::var("AEGIS_TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string())
}

/// Falta un servicio: por el ayudante comun, que en make ci lo exige (la
/// tanda falla) y en local lo anota como omision.
fn falta<T>(que: &str, requisito: Requisito) -> Option<T> {
    omitir(&format!("falta {que}"), requisito);
    None
}

/// Estado de la API contra PostgreSQL y Redis reales.
async fn estado_real() -> Option<(EstadoApi, Almacen)> {
    let almacen = match Almacen::conectar(&url_pg(), 4).await {
        Ok(a) => a,
        Err(e) => return falta(&format!("PostgreSQL ({e})"), Requisito::Postgresql),
    };
    if let Err(e) = almacen.migrar().await {
        return falta(
            &format!("migraciones de PostgreSQL ({e})"),
            Requisito::Postgresql,
        );
    }
    let cache = match Cache::conectar(&url_redis()).await {
        Ok(c) => c,
        Err(e) => return falta(&format!("Redis ({e})"), Requisito::Redis),
    };
    let estado = EstadoApi {
        servicio: Arc::new(ServicioFlota::nuevo(almacen.clone(), 30)),
        cache,
        margen_desconexion_seg: 90,
        direcciones_propias: Vec::new(),
        difusion: None,
        remediacion: None,
    };
    Some((estado, almacen))
}

/// Sustituye cada parametro `{...}` del patron por un valor valido para
/// cualquier tipo de parametro de la API (UUID o texto).
fn concretar(patron: &str) -> String {
    patron
        .split('/')
        .map(|s| {
            if s.starts_with('{') && s.ends_with('}') {
                "00000000-0000-0000-0000-000000000000"
            } else {
                s
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

// ---------------------------------------------------------------------------
// Sin servicios: la forma del enrutador
// ---------------------------------------------------------------------------

#[test]
fn la_lista_publica_es_la_minima_y_toda_ella_existe() {
    // Ampliar esta lista es una decision de seguridad: se cambia AQUI, con
    // revision, y en el modelo de amenazas. No se cuela con una ruta nueva.
    assert_eq!(
        RUTAS_PUBLICAS,
        &[("GET", "/salud"), ("POST", "/api/sesion")],
        "la lista publica de la API cambio"
    );

    let rutas = api::rutas_declaradas();
    for &(metodo, patron) in RUTAS_PUBLICAS {
        assert!(
            rutas.contains(&RutaDeclarada { metodo, patron }),
            "la ruta publica {metodo} {patron} no esta declarada: la lista tiene una entrada muerta"
        );
    }

    let mut vistas = std::collections::HashSet::new();
    for r in &rutas {
        assert!(
            vistas.insert((r.metodo, r.patron)),
            "ruta declarada dos veces: {} {}",
            r.metodo,
            r.patron
        );
        assert!(
            r.patron == "/salud" || r.patron.starts_with("/api/"),
            "ruta fuera de /api: {} {}",
            r.metodo,
            r.patron
        );
    }
}

#[test]
fn ninguna_ruta_entra_por_fuera_de_la_declaracion() {
    // El enrutador de la API solo se construye con `Declaracion::ruta`, que es
    // lo que enumera `rutas_declaradas`. Un `.route(` directo, un `.nest(` o un
    // `.merge(` meterian rutas que la prueba de 401 no veria.
    let api = include_str!("../src/api.rs");
    assert_eq!(
        api.matches(".route(").count(),
        1,
        "src/api.rs: las rutas se declaran con `.ruta(...)`, nunca con `.route(` directo"
    );
    assert_eq!(api.matches(".nest(").count(), 0, "src/api.rs: sin `.nest(`");
    assert_eq!(
        api.matches(".merge(").count(),
        0,
        "src/api.rs: sin `.merge(`"
    );
    assert!(
        api.contains(".route_layer(axum::middleware::from_fn_with_state("),
        "src/api.rs: el enrutador tiene que aplicar la capa de sesion"
    );

    // main.rs solo junta la API con la consola estatica.
    let main = include_str!("../src/main.rs");
    assert_eq!(
        main.matches(".route(").count(),
        0,
        "src/main.rs no declara rutas"
    );
    assert_eq!(
        main.matches(".nest(").count(),
        0,
        "src/main.rs no anida rutas"
    );

    // La consola estatica es publica por necesidad (hay que poder cargar la
    // pagina de acceso), asi que no puede servir nada bajo /api.
    let panel = include_str!("../src/panel.rs");
    for trozo in panel.split(".route(\"").skip(1) {
        let ruta = trozo.split('"').next().unwrap_or("");
        assert!(
            ruta == "/" || ruta.starts_with("/panel/"),
            "src/panel.rs sirve {ruta}: la consola solo puede servir / y /panel/*"
        );
    }
}

// ---------------------------------------------------------------------------
// Con servicios reales: cada ruta, de verdad
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sin_sesion_toda_ruta_no_publica_responde_401() {
    let Some((estado, _)) = estado_real().await else {
        return;
    };
    let app = api::enrutador(estado);
    let rutas = api::rutas_declaradas();
    assert!(!rutas.is_empty());

    for r in rutas {
        let uri = concretar(r.patron);
        for token in [None, Some("sesion-inventada-que-no-existe")] {
            let mut b = Request::builder().method(r.metodo).uri(&uri);
            if let Some(t) = token {
                b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
            }
            let resp = app
                .clone()
                .oneshot(b.body(Body::empty()).unwrap())
                .await
                .expect("el enrutador responde");
            if api::es_publica(r.metodo, r.patron) {
                assert_ne!(
                    resp.status(),
                    StatusCode::UNAUTHORIZED,
                    "{} {uri} es publica y no debe pedir sesion",
                    r.metodo
                );
            } else {
                assert_eq!(
                    resp.status(),
                    StatusCode::UNAUTHORIZED,
                    "{} {uri} ({}) respondio sin sesion valida",
                    r.metodo,
                    if token.is_some() {
                        "sesion inventada"
                    } else {
                        "sin token"
                    }
                );
            }
        }
    }
}

#[tokio::test]
async fn el_tiempo_real_con_token_inventado_en_la_consulta_responde_401() {
    let Some((estado, _)) = estado_real().await else {
        return;
    };
    let app = api::enrutador(estado);
    let peticion = Request::builder()
        .method("GET")
        .uri("/api/ws?token=sesion-inventada-que-no-existe")
        .header(header::UPGRADE, "websocket")
        .header(header::CONNECTION, "upgrade")
        .header(header::SEC_WEBSOCKET_VERSION, "13")
        .header(header::SEC_WEBSOCKET_KEY, "dGhlIHNhbXBsZSBub25jZQ==")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(peticion).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// Pide una sesion y devuelve el codigo y el cuerpo.
async fn pedir_sesion(app: &axum::Router, cuerpo: String) -> (StatusCode, serde_json::Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/sesion")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(cuerpo))
                .unwrap(),
        )
        .await
        .unwrap();
    let codigo = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap_or_default();
    (
        codigo,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

fn credenciales(usuario: &str, clave: &str) -> String {
    serde_json::json!({ "usuario": usuario, "clave": clave }).to_string()
}

#[tokio::test]
async fn la_sesion_solo_se_emite_contra_una_credencial_verificada() {
    let Some((estado, almacen)) = estado_real().await else {
        return;
    };
    let app = api::enrutador(estado);

    let usuario = format!("operador-{}", uuid::Uuid::new_v4().simple());
    let clave = "una clave larga de prueba";
    // Pocas iteraciones: la prueba mide el circuito, no el coste de PBKDF2.
    let hash = aegis_server::credenciales::derivar_con(clave, 1_000).unwrap();
    aegis_server::credenciales::alta_operador(almacen.pool(), &usuario, &hash)
        .await
        .unwrap();

    // El cuerpo de antes de H-02 (solo el nombre) ya no abre nada.
    let (c, _) = pedir_sesion(&app, serde_json::json!({ "usuario": usuario }).to_string()).await;
    assert_ne!(c, StatusCode::OK, "sin clave no hay sesion");

    // Clave erronea y usuario inexistente: 401 y el mismo mensaje.
    let (c, cuerpo_erronea) = pedir_sesion(&app, credenciales(&usuario, "no es la clave")).await;
    assert_eq!(c, StatusCode::UNAUTHORIZED);
    // Nombre unico: los fallos se cuentan por usuario en Redis y un nombre fijo
    // acumularia los de ejecuciones anteriores hasta dar 429.
    let inexistente = format!("nadie-{}", uuid::Uuid::new_v4().simple());
    let (c, cuerpo_inexistente) = pedir_sesion(&app, credenciales(&inexistente, clave)).await;
    assert_eq!(c, StatusCode::UNAUTHORIZED);
    assert_eq!(
        cuerpo_erronea, cuerpo_inexistente,
        "la respuesta no puede revelar si el usuario existe"
    );

    // Clave correcta: sesion, y la sesion abre las rutas protegidas.
    let (c, cuerpo) = pedir_sesion(&app, credenciales(&usuario, clave)).await;
    assert_eq!(c, StatusCode::OK);
    let token = cuerpo["token"].as_str().expect("token").to_string();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/resumen")
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn los_intentos_fallidos_se_frenan_aunque_luego_acierte() {
    let Some((estado, almacen)) = estado_real().await else {
        return;
    };
    let app = api::enrutador(estado);

    let usuario = format!("operador-{}", uuid::Uuid::new_v4().simple());
    let clave = "una clave larga de prueba";
    let hash = aegis_server::credenciales::derivar_con(clave, 1_000).unwrap();
    aegis_server::credenciales::alta_operador(almacen.pool(), &usuario, &hash)
        .await
        .unwrap();

    for _ in 0..aegis_server::cache::MAX_FALLOS_ACCESO {
        let (c, _) = pedir_sesion(&app, credenciales(&usuario, "no es la clave")).await;
        assert_eq!(c, StatusCode::UNAUTHORIZED);
    }
    // Agotado el cupo, ni la clave correcta abre sesion hasta que pase la ventana.
    let (c, _) = pedir_sesion(&app, credenciales(&usuario, clave)).await;
    assert_eq!(c, StatusCode::TOO_MANY_REQUESTS);
}
