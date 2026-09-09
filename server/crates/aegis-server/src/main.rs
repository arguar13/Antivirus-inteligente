//! # aegis-server — plano de control de AegisCore
//!
//! Recoge la telemetria de la flota, la persiste y ofrece la superficie de
//! administracion del panel.
//!
//! # Los tres transportes
//!
//! | Transporte | Quien lo usa | Formato |
//! |---|---|---|
//! | Nativo de flota (mTLS) | los agentes REALES de AegisCore | protobuf con enmarcado de gRPC sobre TLS mutuo crudo |
//! | gRPC estandar (HTTP/2) | integraciones de terceros, conectores de SIEM | gRPC canonico |
//! | REST (HTTP) | el panel web de administracion | JSON |
//!
//! Los tres desembocan en el MISMO nucleo de dominio ([`dominio::ServicioFlota`]),
//! asi que un endpoint recibe la misma decision entre por donde entre.
//!
//! # Sobre la identidad de la flota
//!
//! El plano de control es la CA de la flota: quien firma los certificados con
//! los que los agentes se autentican. Esa CA es material critico y en produccion
//! la provisiona el despliegue. Si no se ha provisionado, el servidor genera una
//! EFIMERA para poder arrancar en desarrollo y lo dice a gritos en el log,
//! porque una CA efimera invalida a toda la flota en cada reinicio.

#![forbid(unsafe_code)]

use std::sync::Arc;

use aegis_fleet::servidor::ServidorFlota;

use aegis_server::almacen::Almacen;
use aegis_server::cache::Cache;
use aegis_server::config::Config;
use aegis_server::dominio::ServicioFlota;
use aegis_server::error::ErrorServidor;
use aegis_server::notificador::Notificador;
use aegis_server::{api, ca, flota, grpc, pb};

/// Validez del certificado del propio plano de control.
const VALIDEZ_CERT_SERVIDOR_SEG: u64 = 24 * 3600;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    iniciar_trazas();
    let cfg = Config::desde_entorno()?;
    tracing::info!("plano de control de AegisCore arrancando");

    // --- Persistencia -------------------------------------------------------
    let almacen = Almacen::conectar(&cfg.pg_url, cfg.pg_max_conexiones).await?;
    almacen.migrar().await?;
    tracing::info!(
        max_conexiones = cfg.pg_max_conexiones,
        "PostgreSQL listo y migrado"
    );

    let cache = Cache::conectar(&cfg.redis_url).await?;
    cache.ping().await?;
    tracing::info!("Redis listo");

    let servicio = Arc::new(ServicioFlota::nuevo(
        almacen.clone(),
        cfg.intervalo_latido.as_secs(),
    ));

    // Puente de avisos entre instancias: sin el, una regla publicada contra otra
    // instancia no despertaria a los agentes suscritos a esta.
    let (version_actual, _) = almacen
        .politica_activa()
        .await
        .unwrap_or((0, serde_json::Value::Null));
    let notificador = Notificador::iniciar(&cfg.pg_url, version_actual).await?;
    tracing::info!(
        version_politica = version_actual,
        "escucha de avisos de politica activa"
    );

    // --- Transporte nativo de la flota (mTLS) ------------------------------
    // Se arranca ANTES que las superficies de administracion: si la flota no
    // puede reportar, el panel no tiene nada que mostrar.
    // La CA se carga del disco o se crea la primera vez; NUNCA es efimera. Un
    // plano de control que regenerase su CA en cada arranque dejaria fuera a
    // toda la flota en el primer reinicio.
    let ca_flota = ca::cargar_o_crear(&cfg.ca_dir)?;
    if ca_flota.recien_creada {
        tracing::warn!(
            certificado = %ca_flota.ruta_cert.display(),
            "CA de flota CREADA por primera vez. Hay que provisionar este certificado \
             como ancla de confianza en cada endpoint; los agentes que confien en otra \
             CA no podran enrolarse."
        );
    } else {
        tracing::info!(
            certificado = %ca_flota.ruta_cert.display(),
            "CA de flota recuperada del disco; los certificados ya emitidos siguen validos"
        );
    }
    let ca = Arc::new(ca_flota.autoridad);
    let id_servidor = ca.emitir("control-plane", VALIDEZ_CERT_SERVIDOR_SEG)?;
    let manejador = Arc::new(
        flota::ManejadorPersistente::nuevo(servicio.clone(), tokio::runtime::Handle::current())
            .con_avisos(notificador.suscriptor()),
    );
    let servidor_flota = ServidorFlota::nuevo(&id_servidor, &ca.cert_der(), manejador)?;
    let flota_en_ejecucion = servidor_flota.escuchar(&cfg.flota_addr)?;
    tracing::info!(direccion = %flota_en_ejecucion.direccion(), "transporte nativo de flota escuchando (mTLS)");

    // --- Superficie gRPC estandar ------------------------------------------
    let grpc_servicio = grpc::ServicioGrpc::nuevo(servicio.clone());
    let grpc_addr = cfg.grpc_addr;
    let tarea_grpc = tokio::spawn(async move {
        tracing::info!(direccion = %grpc_addr, "superficie gRPC estandar escuchando");
        if let Err(e) = tonic::transport::Server::builder()
            .add_service(pb::aegis_fleet_server::AegisFleetServer::new(grpc_servicio))
            .serve(grpc_addr)
            .await
        {
            tracing::error!(error = %e, "la superficie gRPC se detuvo");
        }
    });

    // --- API REST del panel -------------------------------------------------
    let estado_api = api::EstadoApi {
        servicio: servicio.clone(),
        cache: cache.clone(),
        margen_desconexion_seg: cfg.margen_desconexion.as_secs() as i64,
    };
    let app = api::enrutador(estado_api)
        .layer(tower_http::trace::TraceLayer::new_for_http())
        // El panel se sirve desde otro origen durante el desarrollo; en
        // produccion el despliegue lo pone tras el mismo dominio.
        .layer(tower_http::cors::CorsLayer::permissive())
        // Un cuerpo sin limite es una via de agotamiento de memoria trivial.
        .layer(tower_http::limit::RequestBodyLimitLayer::new(1024 * 1024));

    let escucha = tokio::net::TcpListener::bind(cfg.api_addr)
        .await
        .map_err(|e| ErrorServidor::Io {
            op: "bind api",
            source: e,
        })?;
    tracing::info!(direccion = %cfg.api_addr, "API REST de administracion escuchando");

    let tarea_api = tokio::spawn(async move {
        if let Err(e) = axum::serve(escucha, app).await {
            tracing::error!(error = %e, "la API REST se detuvo");
        }
    });

    // --- Parada ordenada ----------------------------------------------------
    esperar_senal().await;
    tracing::info!("senal de parada recibida; cerrando");
    tarea_grpc.abort();
    tarea_api.abort();
    flota_en_ejecucion.parar();
    tracing::info!("plano de control detenido");
    Ok(())
}

/// Configura el registro estructurado.
fn iniciar_trazas() {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};
    let filtro = EnvFilter::try_from_env("AEGIS_LOG")
        .unwrap_or_else(|_| EnvFilter::new("info,sqlx=warn,tower_http=info"));
    tracing_subscriber::registry()
        .with(filtro)
        .with(fmt::layer().with_target(false))
        .init();
}

/// Espera SIGINT o SIGTERM.
///
/// SIGTERM es la que envia systemd y el orquestador de contenedores al parar el
/// servicio; sin atenderla, el proceso moriria de golpe con transacciones
/// abiertas.
async fn esperar_senal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = term => {}
    }
}
