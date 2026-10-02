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
//! | gRPC estandar (HTTP/2) | integraciones de terceros, conectores de SIEM | gRPC canonico, SOLO mTLS con la CA de flota |
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
use aegis_server::{api, ca, flota, grpc, particiones};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    iniciar_trazas();

    // Orden de administracion: alta de un operador de la consola (H-02).
    if std::env::args().nth(1).as_deref() == Some("alta-operador") {
        return alta_operador(std::env::args().nth(2)).await;
    }
    // Rol e inquilino de un operador (FASE 6.2).
    if std::env::args().nth(1).as_deref() == Some("asignar-rol") {
        return asignar_rol(std::env::args().skip(2).collect()).await;
    }

    let cfg = Config::desde_entorno()?;
    tracing::info!("plano de control de AegisCore arrancando");

    // --- Persistencia -------------------------------------------------------
    let almacen = Almacen::conectar(&cfg.pg_url, cfg.pg_max_conexiones).await?;
    almacen.migrar().await?;
    tracing::info!(
        max_conexiones = cfg.pg_max_conexiones,
        "PostgreSQL listo y migrado"
    );

    // --- Particiones mensuales (migracion 0011, H-19) ----------------------
    //
    // ANTES de aceptar nada que escriba: una alerta cuyo mes no tiene hija se
    // rechaza. Si esto falla, el servidor NO arranca, porque un plano de control
    // que acepta conexiones y no puede guardar lo que recibe pierde evidencia.
    // Despues se repite cada hora (y ahi un fallo se registra y se reintenta:
    // hay tres meses de hijas creadas por adelantado).
    let politica_particiones = particiones::Politica::desde_entorno()?;
    let informe = particiones::mantener(&almacen, politica_particiones).await?;
    tracing::info!(
        creadas = informe.creadas,
        purgadas = informe.purgadas,
        retencion_meses = ?politica_particiones.retencion_meses,
        "particiones mensuales al dia"
    );
    let tarea_particiones =
        tokio::spawn(particiones::correr(almacen.clone(), politica_particiones));

    let cache = Cache::conectar(&cfg.redis_url).await?;
    cache.ping().await?;
    tracing::info!("Redis listo");

    let servicio = Arc::new(ServicioFlota::nuevo(
        almacen.clone(),
        cfg.intervalo_latido.as_secs(),
    ));

    // --- Salida de auditoria hacia el SIEM del cliente (FASE 46) -----------
    //
    // El diario se abre ANTES de que nada empiece a producir evidencia, y por
    // eso va aqui, antes que cualquier transporte: el de la flota y el gRPC se
    // construyen con ESTE `servicio`, y montarlo despues (como estuvo) dejaba a
    // las alertas de los agentes en una instancia sin firehose: no llegaban
    // nunca al SIEM. Si el directorio no se puede usar, se arranca SIN firehose
    // y se deja constancia con nivel de error: un plano de control que no
    // arranca porque el SIEM del cliente no esta configurado amplifica la
    // averia en vez de contenerla, pero uno que exporta cero registros en
    // silencio es peor todavia, porque nadie lo descubre hasta que busca la
    // evidencia y no esta.
    let servicio = match montar_firehose(&cfg, servicio.clone()) {
        Some(s) => s,
        None => servicio,
    };

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
    // H-39: el certificado del plano de control se RENUEVA a mitad de su
    // vida, sin reiniciar. Su `notBefore` va atrasado (`emitir_servidor`) para
    // que un agente con el reloj algo por detras no lo vea «aun no valido».
    let validez_cert = cfg.validez_cert_servidor.as_secs();
    let id_servidor = ca.emitir_servidor("control-plane", validez_cert)?;
    let cert_rotativo = aegis_fleet::tls::CertificadoRotativo::nuevo(&id_servidor)?;
    let manejador = Arc::new(
        flota::ManejadorPersistente::nuevo(servicio.clone(), tokio::runtime::Handle::current())
            .con_avisos(&notificador),
    );
    let difusion_cuarentena = manejador.difusion();
    let servidor_flota = ServidorFlota::con_config(
        aegis_fleet::tls::config_servidor_rotativo(cert_rotativo.clone(), &ca.cert_der())?,
        manejador,
    );
    let tarea_cert = renovar_cert_servidor(ca.clone(), cert_rotativo, validez_cert);
    let flota_en_ejecucion = servidor_flota.escuchar(&cfg.flota_addr)?;
    tracing::info!(direccion = %flota_en_ejecucion.direccion(), "transporte nativo de flota escuchando (mTLS)");

    // --- Superficie gRPC estandar: SOLO mTLS (H-01) -------------------------
    //
    // La configuracion TLS es la MISMA que la del transporte nativo
    // (`aegis_fleet::tls::config_servidor`, la CA de flota como unica raiz de
    // confianza) y la identidad sale solo del certificado. Si no se puede
    // construir, la superficie NO se levanta y se dice: nunca se sirve en claro.
    let tarea_grpc = match grpc::configurar_mtls(Some(&id_servidor), Some(&ca.cert_der())) {
        Ok(tls) => {
            let escucha_grpc = tokio::net::TcpListener::bind(cfg.grpc_addr)
                .await
                .map_err(|e| ErrorServidor::Io {
                    op: "bind grpc",
                    source: e,
                })?;
            let grpc_servicio = grpc::ServicioGrpc::nuevo(servicio.clone());
            tracing::info!(
                direccion = %cfg.grpc_addr,
                "superficie gRPC estandar escuchando (solo mTLS con la CA de flota)"
            );
            Some(tokio::spawn(async move {
                if let Err(e) = grpc::servir(escucha_grpc, grpc_servicio, tls).await {
                    tracing::error!(error = %e, "la superficie gRPC se detuvo");
                }
            }))
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                "superficie gRPC NO arrancada: exige mTLS con la CA de flota y no se sirve en claro"
            );
            None
        }
    };

    // --- Correlacion de APT distribuida (FASE 45) --------------------------
    //
    // Un temporizador y no un disparo por alerta: una flota de diez mil
    // endpoints entrega miles de alertas por minuto y cada evaluacion es una
    // agregacion sobre la ventana entera. Evaluar por alerta multiplicaria ese
    // coste para obtener la misma respuesta —una correlacion sobre cuarenta y
    // ocho horas no cambia por una alerta mas—. Ver `correlador`.
    let correlador = aegis_server::correlador::Correlador::nuevo(servicio.clone());
    let tarea_correlador = tokio::spawn(correlador.correr());

    // --- API REST del panel -------------------------------------------------
    // --- Respuesta automatica: ITDR -> AI-RO (integracion viva de la FASE 64) -
    //
    // El motor se construye UNA vez y se comparte: el grafo de identidad de la
    // flota tiene que ser uno solo. Dos motores con dos grafos verian cada uno
    // media escalada de privilegios y ninguno la veria entera.
    let motor_remediacion = Arc::new(aegis_server::remediacion::MotorVivo::de_produccion(
        servicio.clone(),
        almacen.clone(),
    ));
    tracing::info!(
        umbral = ?aegis_orchestrator::Orquestador::nuevo().umbral(),
        enfriamiento_seg = aegis_server::remediacion::ENFRIAMIENTO_SEG,
        "respuesta automatica activa: una deteccion de identidad por encima del umbral \
         lanza su playbook sobre el endpoint sin intervencion humana"
    );

    let estado_api = api::EstadoApi {
        servicio: servicio.clone(),
        remediacion: Some(motor_remediacion),
        cache: cache.clone(),
        margen_desconexion_seg: cfg.margen_desconexion.as_secs() as i64,
        difusion: Some(difusion_cuarentena),
        // Las direcciones por las que este plano de control escucha. Poner
        // cualquiera de ellas en cuarentena dejaria a la flota entera sin poder
        // recibir ordenes, asi que se rechaza. Ver `negar_si_es_intocable`.
        direcciones_propias: vec![cfg.api_addr.ip(), cfg.grpc_addr.ip()]
            .into_iter()
            .chain(
                cfg.flota_addr
                    .split(':')
                    .next()
                    .and_then(|h| h.parse::<std::net::IpAddr>().ok()),
            )
            .collect(),
    };
    let app = api::enrutador(estado_api)
        // La consola se sirve desde el propio binario: un solo artefacto que
        // desplegar, con la misma procedencia que publica el pipeline.
        .merge(aegis_server::panel::enrutador())
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
    tarea_correlador.abort();
    tarea_cert.abort();
    tarea_particiones.abort();
    if let Some(t) = &tarea_grpc {
        t.abort();
    }
    tarea_api.abort();
    flota_en_ejecucion.parar();
    tracing::info!("plano de control detenido");
    Ok(())
}

/// `aegis-server alta-operador <usuario>`: da de alta un operador de la
/// consola, o le cambia la clave (H-02).
///
/// La clave se lee de la ENTRADA ESTANDAR (primera linea) y nunca de un
/// argumento: los argumentos se ven en `ps` y quedan en el historial.
///
/// ```text
/// printf '%s\n' "$CLAVE" | aegis-server alta-operador admin
/// ```
async fn alta_operador(usuario: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    use aegis_server::credenciales;

    let usuario = usuario
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty())
        .ok_or("uso: aegis-server alta-operador <usuario>   (la clave, por la entrada estandar)")?;
    let mut linea = String::new();
    std::io::stdin().read_line(&mut linea)?;
    let clave = linea.trim_end_matches(['\n', '\r']);
    credenciales::validar_alta(&usuario, clave)?;

    let cfg = Config::desde_entorno()?;
    let almacen = Almacen::conectar(&cfg.pg_url, 2).await?;
    almacen.migrar().await?;
    let hash = credenciales::derivar(clave)?;
    credenciales::alta_operador(almacen.pool(), &usuario, &hash).await?;
    tracing::info!(usuario = %usuario, "operador dado de alta");
    Ok(())
}

/// `aegis-server asignar-rol <usuario> <rol> <inquilino>` (FASE 6.2).
///
/// El rol es uno de `analista`, `responsable`, `administrador` o `auditor`; el
/// inquilino, el de los agentes que vera (`flota-<dominio>`), o `plataforma`
/// para gestionar el contenido global.
async fn asignar_rol(args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    use aegis_server::autorizacion;

    let [usuario, rol, inquilino] = args.as_slice() else {
        return Err("uso: aegis-server asignar-rol <usuario> \
                    <analista|responsable|administrador|auditor> <inquilino>"
            .into());
    };
    let rol = autorizacion::rol_de_nombre(rol)
        .ok_or("rol desconocido: analista, responsable, administrador o auditor")?;
    let cfg = Config::desde_entorno()?;
    let almacen = Almacen::conectar(&cfg.pg_url, 2).await?;
    almacen.migrar().await?;
    if !autorizacion::asignar_rol(almacen.pool(), usuario, rol, inquilino).await? {
        return Err(
            format!("no existe el operador {usuario}: dalo de alta con alta-operador").into(),
        );
    }
    tracing::info!(usuario = %usuario, rol = rol.nombre(), inquilino = %inquilino, "rol asignado");
    Ok(())
}

/// Renueva el certificado del plano de control a mitad de su vida (H-39).
fn renovar_cert_servidor(
    ca: Arc<aegis_fleet::AutoridadCertificadora>,
    cert: Arc<aegis_fleet::tls::CertificadoRotativo>,
    validez_seg: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let cada = std::time::Duration::from_secs((validez_seg / 2).max(1));
        loop {
            tokio::time::sleep(cada).await;
            match ca
                .emitir_servidor("control-plane", validez_seg)
                .and_then(|id| cert.renovar(&id))
            {
                Ok(()) => tracing::info!(validez_seg, "certificado del plano de control renovado"),
                Err(e) => tracing::error!(
                    error = %e,
                    "no se pudo renovar el certificado del plano de control; se reintentara"
                ),
            }
        }
    })
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

/// Abre el diario de auditoria y arranca la exportacion, si esta configurada.
///
/// Devuelve `None` —y el plano de control sigue sin firehose— cuando falta
/// configuracion o el diario no se puede abrir. El motivo se registra siempre.
fn montar_firehose(cfg: &Config, servicio: Arc<ServicioFlota>) -> Option<Arc<ServicioFlota>> {
    use aegis_firehose::diario::Config as ConfigDiario;
    use aegis_firehose::reintento::Politica;
    use aegis_firehose::syslog_tls::{ConfigSyslog, DestinoSyslog};

    let dir = cfg.firehose_dir.as_ref()?;
    let servidor = cfg.syslog_servidor.as_ref()?;
    let nombre = cfg.syslog_nombre.clone().unwrap_or_else(|| {
        // Sin nombre explicito, el del propio servidor: es lo correcto cuando se
        // conecta por DNS, y falla ruidosamente cuando no lo es.
        servidor.split(':').next().unwrap_or(servidor).to_string()
    });
    let Some(ruta_ca) = cfg.syslog_ca.as_ref() else {
        tracing::error!(
            "AEGIS_SYSLOG_CA no esta puesta: sin ancla de confianza no se puede \
             verificar al colector, y la telemetria de seguridad no sale sin verificar"
        );
        return None;
    };
    let ca = match std::fs::read(ruta_ca) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, ruta = %ruta_ca.display(),
                "no se pudo leer la CA del colector syslog; AUDITORIA NO EXPORTADA");
            return None;
        }
    };

    let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "control-plane".to_string());
    let mut config_diario = ConfigDiario::nueva(dir);
    config_diario.presupuesto_bytes = cfg.firehose_presupuesto_bytes;

    let firehose = match aegis_server::firehose::Firehose::abrir(config_diario, &hostname) {
        Ok(f) => Arc::new(f.con_retencion(cfg.firehose_retencion)),
        Err(e) => {
            tracing::error!(error = %e, directorio = %dir.display(),
                "no se pudo abrir el diario de auditoria; AUDITORIA NO EXPORTADA");
            return None;
        }
    };

    let destino = match DestinoSyslog::nuevo(ConfigSyslog {
        servidor: servidor.clone(),
        nombre_esperado: nombre,
        ca_pem: ca,
        plazo: std::time::Duration::from_secs(10),
    }) {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, "colector syslog mal configurado; AUDITORIA NO EXPORTADA");
            return None;
        }
    };

    // En un HILO propio y no en el runtime: la exportacion bloquea en E/S de
    // disco y de red, y hacerlo en un worker de tokio castigaria a todo lo
    // demas —los latidos de diez mil agentes, entre otras cosas—.
    let exportador = firehose.clone();
    std::thread::Builder::new()
        .name("aegis-firehose".to_string())
        .spawn(move || exportador.exportar(destino, Politica::default()))
        .ok()?;

    tracing::info!(
        directorio = %dir.display(), colector = %servidor,
        "salida de auditoria hacia el SIEM activa"
    );
    // Se clona el servicio y se le anade la salida: el bus de eventos va dentro
    // y es un emisor de difusion, asi que el clon publica en el MISMO bus. Si
    // no fuera asi, la consola dejaria de recibir avisos en cuanto el firehose
    // estuviera activo, que es un fallo silencioso de los peores.
    Some(Arc::new((*servicio).clone().con_firehose(firehose)))
}
