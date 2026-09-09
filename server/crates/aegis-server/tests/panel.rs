//! Pruebas de la consola de administracion.
//!
//! Cubren tres cosas que en una consola con este poder no pueden fallar en
//! silencio: que se sirva con las cabeceras de seguridad correctas, que no
//! cargue NADA de fuera del propio servidor, y que el bus de eventos entregue
//! los sucesos a las consolas conectadas.

use aegis_server::eventos::{BusEventos, EventoPanel};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

/// Pide una ruta a la consola y devuelve (estado, cabeceras, cuerpo).
async fn pedir(ruta: &str) -> (StatusCode, axum::http::HeaderMap, String) {
    let app = aegis_server::panel::enrutador();
    let r = app
        .oneshot(Request::builder().uri(ruta).body(Body::empty()).unwrap())
        .await
        .expect("la consola debe responder");
    let estado = r.status();
    let cabeceras = r.headers().clone();
    let bytes = axum::body::to_bytes(r.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap_or_default();
    (
        estado,
        cabeceras,
        String::from_utf8_lossy(&bytes).to_string(),
    )
}

#[tokio::test]
async fn la_consola_se_sirve_entera_desde_el_binario() {
    for (ruta, tipo, marca) in [
        ("/panel/", "text/html", "AegisCore"),
        ("/panel/estilo.css", "text/css", "--fondo"),
        ("/panel/app.js", "text/javascript", "WebSocket"),
    ] {
        let (estado, cab, cuerpo) = pedir(ruta).await;
        assert_eq!(estado, StatusCode::OK, "{ruta} debe servirse");
        let ct = cab
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            ct.starts_with(tipo),
            "{ruta}: tipo {ct}, se esperaba {tipo}"
        );
        assert!(
            cuerpo.contains(marca),
            "{ruta} no parece el fichero correcto (falta «{marca}»)"
        );
        assert!(!cuerpo.is_empty());
    }
}

#[tokio::test]
async fn la_raiz_lleva_a_la_consola() {
    let (estado, cab, _) = pedir("/").await;
    assert!(
        estado.is_redirection(),
        "la raiz debe redirigir, dio {estado}"
    );
    assert_eq!(
        cab.get(axum::http::header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/panel/")
    );
}

#[tokio::test]
async fn la_consola_llega_con_sus_cabeceras_de_seguridad() {
    let (_, cab, _) = pedir("/panel/").await;

    let valor = |n: axum::http::HeaderName| {
        cab.get(n)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    };

    // Sin esto, el navegador podria ejecutar como script algo que no lo es.
    assert_eq!(valor(axum::http::header::X_CONTENT_TYPE_OPTIONS), "nosniff");
    // Una consola dentro de un marco ajeno es un secuestro de clics sobre
    // botones que aislan maquinas de produccion.
    assert_eq!(valor(axum::http::header::X_FRAME_OPTIONS), "DENY");
    assert_eq!(valor(axum::http::header::REFERRER_POLICY), "no-referrer");

    let csp = valor(axum::http::header::CONTENT_SECURITY_POLICY);
    assert!(csp.contains("default-src 'self'"), "CSP: {csp}");
    assert!(csp.contains("frame-ancestors 'none'"), "CSP: {csp}");
    // Sin `unsafe-inline` ni `unsafe-eval`: si aparecieran, la CSP dejaria de
    // proteger de una inyeccion en el propio documento.
    assert!(
        !csp.contains("unsafe-inline"),
        "la CSP no debe permitir codigo en linea"
    );
    assert!(!csp.contains("unsafe-eval"), "la CSP no debe permitir eval");
}

#[tokio::test]
async fn la_consola_no_carga_nada_de_fuera_del_servidor() {
    // Esta es la prueba que sostiene la decision de no usar un empaquetador:
    // la consola que puede aislar miles de endpoints no debe depender de
    // ninguna CDN ni de ningun origen de terceros. Si alguien anade una
    // referencia externa, esta prueba lo caza.
    let (_, _, html) = pedir("/panel/").await;
    let (_, _, js) = pedir("/panel/app.js").await;
    let (_, _, css) = pedir("/panel/estilo.css").await;

    for (nombre, cuerpo) in [("index.html", &html), ("app.js", &js), ("estilo.css", &css)] {
        for patron in [
            "http://",
            "https://",
            "//cdn",
            "unpkg",
            "jsdelivr",
            "googleapis",
        ] {
            // La unica excepcion legitima es el espacio de nombres de SVG, que
            // es un identificador, no una descarga.
            let sospechosas: Vec<&str> = cuerpo
                .lines()
                .filter(|l| l.contains(patron))
                .filter(|l| !l.contains("www.w3.org/2000/svg"))
                .collect();
            assert!(
                sospechosas.is_empty(),
                "{nombre} referencia un origen externo ({patron}): {sospechosas:?}"
            );
        }
    }
}

#[tokio::test]
async fn el_documento_solo_referencia_recursos_que_el_servidor_sirve() {
    let (_, _, html) = pedir("/panel/").await;
    for recurso in ["/panel/estilo.css", "/panel/app.js"] {
        assert!(html.contains(recurso), "el HTML debe referenciar {recurso}");
        let (estado, _, _) = pedir(recurso).await;
        assert_eq!(estado, StatusCode::OK, "{recurso} debe existir");
    }
}

// ---------------------------------------------------------------------------
// Bus de eventos
// ---------------------------------------------------------------------------

#[tokio::test]
async fn el_bus_entrega_los_sucesos_a_todas_las_consolas_conectadas() {
    let bus = BusEventos::nuevo();
    let mut consola_a = bus.suscribir();
    let mut consola_b = bus.suscribir();
    assert_eq!(bus.consolas(), 2);

    bus.publicar(EventoPanel::AlertaNueva {
        id: "INC-1".into(),
        cn: "endpoint-7".into(),
        severidad: 4,
        categoria: "ransomware".into(),
        descripcion: "cifrado masivo".into(),
        tecnica_mitre: Some("T1486".into()),
    });

    // Las dos consolas ven el mismo suceso: dos operadores de guardia no pueden
    // tener visiones distintas del mismo incidente.
    for consola in [&mut consola_a, &mut consola_b] {
        let e = consola.recv().await.expect("debe llegar el evento");
        match e {
            EventoPanel::AlertaNueva {
                severidad,
                tecnica_mitre,
                ..
            } => {
                assert_eq!(severidad, 4);
                assert_eq!(tecnica_mitre.as_deref(), Some("T1486"));
            }
            otro => panic!("evento inesperado: {otro:?}"),
        }
    }
}

#[tokio::test]
async fn publicar_sin_consolas_conectadas_no_es_un_error() {
    // Que no haya nadie mirando no puede romper la ingesta: el registro
    // duradero esta en la base de datos, el bus solo avisa a quien este.
    let bus = BusEventos::nuevo();
    assert_eq!(bus.consolas(), 0);
    bus.publicar(EventoPanel::PoliticaPublicada {
        version: 3,
        reglas: 2,
    });
}

#[tokio::test]
async fn los_eventos_viajan_como_json_etiquetado_por_tipo() {
    // La consola despacha por el campo `tipo`: si cambiara la forma, el panel
    // dejaria de reaccionar en silencio, que es la peor manera de romperse.
    let e = EventoPanel::AislamientoCambiado {
        cn: "endpoint-9".into(),
        aislado: true,
        por: "operador@empresa".into(),
    };
    let j: serde_json::Value = serde_json::to_value(&e).unwrap();
    assert_eq!(j["tipo"], "aislamiento_cambiado");
    assert_eq!(j["aislado"], true);
    assert_eq!(j["por"], "operador@empresa");

    let alerta = EventoPanel::AlertaNueva {
        id: "x".into(),
        cn: "y".into(),
        severidad: 3,
        categoria: "rootkit".into(),
        descripcion: "d".into(),
        tecnica_mitre: None,
    };
    assert_eq!(
        serde_json::to_value(&alerta).unwrap()["tipo"],
        "alerta_nueva"
    );
}
