//! Servido de la consola de administracion.
//!
//! # Por que va EMBEBIDA en el binario
//!
//! Un directorio de ficheros estaticos junto al servidor es una superficie mas:
//! hay que desplegarlo, mantener sus permisos y confiar en que nadie lo toque.
//! Embebida con `include_str!`, la consola forma parte del binario firmado: el
//! mismo artefacto cuyo SHA-256 y procedencia publica el pipeline. No hay
//! ficheros sueltos que puedan divergir de lo que se audito.
//!
//! # Por que no hay cadena de construccion de frontend
//!
//! Esta pagina es la que puede aislar miles de endpoints. Lo que se revisa tiene
//! que ser exactamente lo que ejecuta el navegador del operador, sin un
//! empaquetador transformando el codigo por el camino ni un arbol de paquetes de
//! terceros que vigilar. Modulos ES nativos y SVG bastan para lo que hace.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;

/// La consola, embebida en el binario.
const INDICE: &str = include_str!("../../../panel/index.html");
/// Hoja de estilos de la consola.
const ESTILO: &str = include_str!("../../../panel/estilo.css");
/// Logica de la consola.
const APLICACION: &str = include_str!("../../../panel/app.js");

/// Rutas de la consola.
pub fn enrutador() -> Router {
    Router::new()
        .route("/", get(|| async { Redirect::permanent("/panel/") }))
        .route("/panel/", get(indice))
        .route("/panel/index.html", get(indice))
        .route("/panel/estilo.css", get(estilo))
        .route("/panel/app.js", get(aplicacion))
}

/// Cabeceras de seguridad comunes a todo lo que sirve la consola.
///
/// Van en cabecera y no solo en la etiqueta `meta` del HTML porque la cabecera
/// la aplica el navegador tambien a lo que no es HTML, y porque una etiqueta
/// dentro del documento solo protege si el documento llego intacto.
fn con_cabeceras(cuerpo: &'static str, tipo: &'static str) -> Response {
    let mut r = (StatusCode::OK, cuerpo).into_response();
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(tipo));
    // Evita que el navegador adivine el tipo y ejecute como script algo que no
    // lo es.
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    // La consola nunca debe cargarse dentro de un marco ajeno: seria un
    // secuestro de clics sobre botones que aislan maquinas.
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    // No filtrar la ruta de la consola —ni el token, si acabara en una URL— a
    // ningun tercero.
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self'; style-src 'self'; \
             img-src 'self' data:; connect-src 'self' ws: wss:; \
             base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        ),
    );
    // La consola va embebida en el binario: si el binario cambia, cambia la
    // consola. No se cachea para que un despliegue nuevo no conviva con una
    // consola vieja en el navegador del operador.
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache, must-revalidate"),
    );
    r
}

/// Documento principal de la consola.
async fn indice() -> Response {
    con_cabeceras(INDICE, "text/html; charset=utf-8")
}

/// Hoja de estilos.
async fn estilo() -> Response {
    con_cabeceras(ESTILO, "text/css; charset=utf-8")
}

/// Modulo de la aplicacion.
async fn aplicacion() -> Response {
    con_cabeceras(APLICACION, "text/javascript; charset=utf-8")
}
