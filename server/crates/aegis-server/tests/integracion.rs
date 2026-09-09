//! Pruebas de integracion del plano de control.
//!
//! No hay imitaciones aqui: cada prueba habla con un PostgreSQL y un Redis
//! REALES, y la prueba de extremo a extremo levanta el transporte mTLS de verdad
//! y conecta el CLIENTE AUTENTICO del agente (`aegis_fleet::ClienteFlota`, el de
//! la FASE 34). Es la unica forma de demostrar que el servidor y el agente
//! hablan el mismo protocolo: si el enmarcado o los numeros de campo del
//! protobuf divergieran, estas pruebas fallarian.
//!
//! Se omiten con honestidad —sin fingir exito— si la maquina no tiene las bases
//! de datos levantadas.

use std::sync::Arc;

use aegis_fleet::pki::AutoridadCertificadora;
use aegis_fleet::servidor::ServidorFlota;
use aegis_fleet::{ClienteFlota, EmisorLocal, PoliticaRotacion, RotadorCertificados};
use aegis_server::almacen::Almacen;
use aegis_server::cache::{Cache, Veredicto};
use aegis_server::dominio::{clasificar_mitre, ServicioFlota};
use aegis_server::flota::ManejadorPersistente;

/// Cadena de conexion de la base de datos de pruebas.
fn url_pg() -> String {
    std::env::var("AEGIS_TEST_PG_URL")
        .unwrap_or_else(|_| "postgres://postgres@%2Fvar%2Frun%2Fpostgresql/aegis_test".to_string())
}

/// Cadena de conexion de la cache de pruebas.
fn url_redis() -> String {
    std::env::var("AEGIS_TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string())
}

/// Abre el almacen de pruebas, o `None` si no hay PostgreSQL.
async fn almacen_de_pruebas() -> Option<Almacen> {
    let a = Almacen::conectar(&url_pg(), 8).await.ok()?;
    a.migrar().await.ok()?;
    Some(a)
}

/// Identificador unico por prueba: las pruebas comparten la base de datos y no
/// deben pisarse entre si ni depender del orden en que corran.
fn cn_unico(prefijo: &str) -> String {
    format!("{prefijo}-{}", uuid::Uuid::new_v4().simple())
}

// ---------------------------------------------------------------------------
// Persistencia
// ---------------------------------------------------------------------------

#[tokio::test]
async fn un_agente_se_enrola_late_y_reporta_contra_postgres_real() {
    let Some(almacen) = almacen_de_pruebas().await else {
        eprintln!("OMITIDA: no hay PostgreSQL en {}", url_pg());
        return;
    };
    let servicio = ServicioFlota::nuevo(almacen.clone(), 30);
    let cn = cn_unico("agente");

    // Enrolar.
    let id_flota = servicio
        .enrolar(&cn, "id-1", "maquina-1", "1.0.0", b"huella")
        .await
        .expect("enrolamiento");
    assert!(!id_flota.is_empty());

    // Latir: debe devolver la version de politica publicada.
    let estado = servicio.latido(&cn, 22_000, 0, 0).await.expect("latido");
    assert!(
        estado.version_politica >= 1,
        "debe haber una politica activa"
    );
    assert!(!estado.hay_comando, "no se ha encolado ningun comando aun");

    // Reportar un evento: se persiste y devuelve identificador de incidente.
    let id = servicio
        .evento(&cn, 4, "ransomware", "cifrado masivo detectado", 0)
        .await
        .expect("evento");
    assert!(!id.is_nil());

    // El inventario refleja lo ocurrido.
    let vista = almacen.obtener_agente(&cn, 300).await.expect("agente");
    assert_eq!(vista.hostname, "maquina-1");
    assert_eq!(vista.latidos, 1);
    assert_eq!(vista.eventos, 1);
    assert_eq!(vista.rss_kb, 22_000);
    assert!(vista.en_linea, "acaba de latir");
}

#[tokio::test]
async fn el_evento_se_guarda_clasificado_en_mitre_att_ck() {
    let Some(almacen) = almacen_de_pruebas().await else {
        eprintln!("OMITIDA: no hay PostgreSQL");
        return;
    };
    let servicio = ServicioFlota::nuevo(almacen.clone(), 30);
    let cn = cn_unico("mitre");
    servicio
        .enrolar(&cn, "id", "host", "1.0.0", b"h")
        .await
        .unwrap();

    servicio
        .evento(&cn, 3, "inyeccion", "inyeccion en proceso legitimo", 0)
        .await
        .unwrap();

    let alertas = almacen.listar_alertas(50, true).await.unwrap();
    let mia = alertas
        .iter()
        .find(|a| a.cn_agente == cn)
        .expect("la alerta");
    // La categoria del agente se ha traducido a la tecnica del marco ATT&CK:
    // eso es lo que permite correlacionarla con inteligencia externa.
    assert_eq!(mia.tecnica_mitre.as_deref(), Some("T1055"));
    assert_eq!(mia.severidad, 3);
    assert_eq!(clasificar_mitre("inyeccion").unwrap().tecnica, "T1055");
}

#[tokio::test]
async fn una_severidad_fuera_de_rango_no_rompe_la_restriccion_del_esquema() {
    let Some(almacen) = almacen_de_pruebas().await else {
        eprintln!("OMITIDA: no hay PostgreSQL");
        return;
    };
    let servicio = ServicioFlota::nuevo(almacen.clone(), 30);
    let cn = cn_unico("severidad");
    servicio.enrolar(&cn, "id", "h", "1.0", b"h").await.unwrap();

    // El esquema restringe severidad a 0..4. Un agente comprometido que declare
    // 9999 no debe provocar un error de la base de datos: se acota antes.
    let r = servicio
        .evento(&cn, 9999, "rootkit", "severidad absurda", 0)
        .await;
    assert!(r.is_ok(), "la severidad debe acotarse, no reventar: {r:?}");

    let alertas = almacen.listar_alertas(50, true).await.unwrap();
    let mia = alertas.iter().find(|a| a.cn_agente == cn).unwrap();
    assert_eq!(mia.severidad, 4, "acotada al maximo del esquema");
}

#[tokio::test]
async fn el_comando_de_aislamiento_llega_al_agente_por_su_latido() {
    let Some(almacen) = almacen_de_pruebas().await else {
        eprintln!("OMITIDA: no hay PostgreSQL");
        return;
    };
    let servicio = ServicioFlota::nuevo(almacen.clone(), 30);
    let cn = cn_unico("aislar");
    servicio.enrolar(&cn, "id", "h", "1.0", b"h").await.unwrap();

    // El operador aisla el endpoint desde el panel.
    assert!(almacen.fijar_aislamiento(&cn, true).await.unwrap());
    almacen
        .encolar_comando(&cn, "aislar", serde_json::json!({}), "operador@empresa")
        .await
        .unwrap();

    // El siguiente latido del agente le avisa de que tiene algo pendiente: asi
    // funciona aunque el endpoint este tras un NAT y el servidor no lo alcance.
    let estado = servicio.latido(&cn, 1000, 1, 1).await.unwrap();
    assert!(estado.hay_comando, "el latido debe avisar del comando");

    // Se entrega una sola vez.
    let c = almacen
        .tomar_comando_pendiente(&cn)
        .await
        .unwrap()
        .expect("comando");
    assert_eq!(c.accion, "aislar");
    assert!(
        almacen
            .tomar_comando_pendiente(&cn)
            .await
            .unwrap()
            .is_none(),
        "un comando entregado no puede volver a entregarse"
    );

    let vista = almacen.obtener_agente(&cn, 300).await.unwrap();
    assert!(vista.aislado);
}

#[tokio::test]
async fn solo_puede_haber_una_politica_activa() {
    let Some(almacen) = almacen_de_pruebas().await else {
        eprintln!("OMITIDA: no hay PostgreSQL");
        return;
    };
    let v1 = almacen
        .publicar_politica("bloqueo-smb", serde_json::json!({"puerto": 445}))
        .await
        .unwrap();
    let v2 = almacen
        .publicar_politica("bloqueo-rdp", serde_json::json!({"puerto": 3389}))
        .await
        .unwrap();
    assert!(v2 > v1, "cada publicacion incrementa la version");

    // La garantia la impone el indice unico parcial de la base de datos, no el
    // codigo: dos politicas activas dejarian la flota en dos configuraciones.
    let activas: i64 = sqlx::query_scalar("SELECT count(*) FROM politicas WHERE activa")
        .fetch_one(almacen.pool())
        .await
        .unwrap();
    assert_eq!(activas, 1);
}

// ---------------------------------------------------------------------------
// Cache k-anonima
// ---------------------------------------------------------------------------

#[tokio::test]
async fn la_reputacion_se_consulta_por_cubo_sin_revelar_el_hash() {
    let Ok(cache) = Cache::conectar(&url_redis()).await else {
        eprintln!("OMITIDA: no hay Redis en {}", url_redis());
        return;
    };
    if cache.ping().await.is_err() {
        eprintln!("OMITIDA: Redis no responde");
        return;
    }

    // Dos hashes distintos que comparten prefijo caen en el MISMO cubo: esa
    // colision deliberada es lo que impide saber por cual se pregunta.
    let prefijo: String = uuid::Uuid::new_v4().simple().to_string()[..5].to_string();
    let malo = format!("{prefijo}{}", "a".repeat(59));
    let bueno = format!("{prefijo}{}", "b".repeat(59));

    cache
        .registrar_reputacion(&malo, Veredicto::Malicioso)
        .await
        .unwrap();
    cache
        .registrar_reputacion(&bueno, Veredicto::Limpio)
        .await
        .unwrap();

    let cubo = cache.consultar_cubo(&prefijo).await.unwrap();
    assert_eq!(
        cubo.len(),
        2,
        "el cubo devuelve los dos, no solo el buscado"
    );
    let veredictos: Vec<_> = cubo.iter().map(|(_, v)| *v).collect();
    assert!(veredictos.contains(&Veredicto::Malicioso));
    assert!(veredictos.contains(&Veredicto::Limpio));
}

#[tokio::test]
async fn una_sesion_caducada_o_inexistente_no_autentica() {
    let Ok(cache) = Cache::conectar(&url_redis()).await else {
        eprintln!("OMITIDA: no hay Redis");
        return;
    };
    if cache.ping().await.is_err() {
        eprintln!("OMITIDA: Redis no responde");
        return;
    }

    let token = cache.abrir_sesion("operador@empresa").await.unwrap();
    assert_eq!(
        cache.usuario_de_sesion(&token).await.unwrap().as_deref(),
        Some("operador@empresa")
    );

    // Un token inventado no vale.
    assert!(cache
        .usuario_de_sesion("token-inventado")
        .await
        .unwrap()
        .is_none());

    // Y tras cerrar sesion, el que valia deja de valer.
    assert!(cache.cerrar_sesion(&token).await.unwrap());
    assert!(cache.usuario_de_sesion(&token).await.unwrap().is_none());
}

// ---------------------------------------------------------------------------
// Extremo a extremo: el AGENTE REAL contra el servidor real
// ---------------------------------------------------------------------------

/// Construye un cliente de flota autentico, el mismo que corre en el endpoint.
fn agente_real(
    dir: std::net::SocketAddr,
    ca_confianza: &AutoridadCertificadora,
    ca_identidad: Arc<AutoridadCertificadora>,
    cn: &str,
) -> aegis_fleet::Resultado<ClienteFlota> {
    let emisor = Arc::new(EmisorLocal::nuevo(ca_identidad));
    let rotador = Arc::new(RotadorCertificados::nuevo(
        cn,
        PoliticaRotacion::default(),
        emisor,
    )?);
    Ok(ClienteFlota::nuevo(
        dir,
        ca_confianza.cert_der(),
        rotador,
        "endpoint-real",
        "1.0.0",
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn el_agente_autentico_habla_con_el_plano_de_control_sobre_mtls_y_queda_en_postgres() {
    let Some(almacen) = almacen_de_pruebas().await else {
        eprintln!("OMITIDA: no hay PostgreSQL");
        return;
    };
    let servicio = Arc::new(ServicioFlota::nuevo(almacen.clone(), 30));

    // Plano de control real: mTLS con la CA de la flota y persistencia en PostgreSQL.
    let ca = Arc::new(AutoridadCertificadora::nueva("CA de pruebas").unwrap());
    let id_srv = ca.emitir("control-plane", 3600).unwrap();
    let manejador = Arc::new(ManejadorPersistente::nuevo(
        servicio.clone(),
        tokio::runtime::Handle::current(),
    ));
    let servidor = ServidorFlota::nuevo(&id_srv, &ca.cert_der(), manejador)
        .unwrap()
        .escuchar("127.0.0.1:0")
        .unwrap();
    let dir = servidor.direccion();

    let cn = cn_unico("endpoint");
    // Todo el dialogo es sincrono y bloqueante (es un agente, no un servicio
    // asincrono), asi que corre en un hilo aparte para no bloquear el runtime.
    let ca_cliente = ca.clone();
    let cn_hilo = cn.clone();
    let resultado =
        tokio::task::spawn_blocking(move || -> aegis_fleet::Resultado<(bool, bool, String)> {
            let agente = agente_real(dir, &ca_cliente, ca_cliente.clone(), &cn_hilo)?;
            let mut sesion = agente.abrir_sesion()?;
            let enrolamiento = sesion.enrolar(&agente.solicitud_enrolamiento()?)?;

            let mut s2 = agente.abrir_sesion()?;
            let ack = s2.latir(&aegis_fleet::proto::Latido {
                id_agente: cn_hilo.clone(),
                momento_unix: 0,
                rss_kb: 21_500,
                amenazas_activas: 0,
                version_politica: 0,
            })?;

            let mut s3 = agente.abrir_sesion()?;
            let ev = s3.reportar_evento(&aegis_fleet::proto::ReporteEvento {
                id_agente: cn_hilo.clone(),
                severidad: 4,
                categoria: "rootkit".to_string(),
                descripcion: "modulo oculto detectado por verificacion cruzada".to_string(),
                momento_unix: 0,
            })?;

            Ok((enrolamiento.aceptado, ack.recibido, ev.id_incidente))
        })
        .await
        .expect("hilo del agente")
        .expect("dialogo de flota");

    let (enrolado, latido_ok, id_incidente) = resultado;
    assert!(enrolado, "el agente legitimo debe ser enrolado");
    assert!(latido_ok, "el latido debe quedar registrado");
    assert!(
        !id_incidente.is_empty(),
        "el evento debe recibir identificador"
    );

    // Y todo ello tiene que haber aterrizado en PostgreSQL.
    let vista = almacen
        .obtener_agente(&cn, 300)
        .await
        .expect("el agente debe existir en el inventario");
    assert_eq!(vista.rss_kb, 21_500);
    assert_eq!(vista.latidos, 1);
    assert_eq!(vista.eventos, 1);

    let alertas = almacen.listar_alertas(100, true).await.unwrap();
    let mia = alertas
        .iter()
        .find(|a| a.cn_agente == cn)
        .expect("la alerta");
    assert_eq!(
        mia.tecnica_mitre.as_deref(),
        Some("T1014"),
        "rootkit -> T1014"
    );

    servidor.parar();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn un_impostor_con_otra_ca_no_llega_a_tocar_la_base_de_datos() {
    let Some(almacen) = almacen_de_pruebas().await else {
        eprintln!("OMITIDA: no hay PostgreSQL");
        return;
    };
    let servicio = Arc::new(ServicioFlota::nuevo(almacen.clone(), 30));

    let ca = Arc::new(AutoridadCertificadora::nueva("CA de la flota").unwrap());
    let id_srv = ca.emitir("control-plane", 3600).unwrap();
    let manejador = Arc::new(ManejadorPersistente::nuevo(
        servicio,
        tokio::runtime::Handle::current(),
    ));
    let servidor = ServidorFlota::nuevo(&id_srv, &ca.cert_der(), manejador)
        .unwrap()
        .escuchar("127.0.0.1:0")
        .unwrap();
    let dir = servidor.direccion();

    let cn_impostor = cn_unico("impostor");
    let ca_pirata = Arc::new(AutoridadCertificadora::nueva("CA Pirata").unwrap());
    let ca_confianza = ca.clone();
    let cn_hilo = cn_impostor.clone();

    let entro = tokio::task::spawn_blocking(move || {
        // El impostor confia en la CA legitima (asi llega al handshake) pero su
        // certificado lo firma OTRA autoridad: el servidor debe rechazarlo.
        let agente = agente_real(dir, &ca_confianza, ca_pirata, &cn_hilo).unwrap();
        match agente.abrir_sesion() {
            Ok(mut s) => s
                .enrolar(&agente.solicitud_enrolamiento().unwrap())
                .map(|r| r.aceptado)
                .unwrap_or(false),
            Err(_) => false,
        }
    })
    .await
    .expect("hilo del impostor");

    assert!(!entro, "un certificado de otra CA no puede enrolarse");

    // Y, sobre todo, no ha dejado rastro en el inventario: el rechazo ocurre en
    // el handshake, antes de que una sola consulta toque la base de datos.
    assert!(
        almacen.obtener_agente(&cn_impostor, 300).await.is_err(),
        "el impostor no debe existir en la base de datos"
    );

    servidor.parar();
}

// ---------------------------------------------------------------------------
// Superficie gRPC estandar (tonic)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn la_superficie_grpc_estandar_atiende_a_una_integracion_de_terceros() {
    let Some(almacen) = almacen_de_pruebas().await else {
        eprintln!("OMITIDA: no hay PostgreSQL");
        return;
    };
    let servicio = Arc::new(ServicioFlota::nuevo(almacen.clone(), 30));

    // Se levanta la superficie gRPC canonica en un puerto efimero.
    let escucha = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dir = escucha.local_addr().unwrap();
    let servicio_grpc = aegis_server::grpc::ServicioGrpc::nuevo(servicio);
    let servidor = tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(aegis_server::pb::aegis_fleet_server::AegisFleetServer::new(
                servicio_grpc,
            ))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(escucha))
            .await;
    });

    let cn = cn_unico("integracion");
    let mut cliente =
        aegis_server::pb::aegis_fleet_client::AegisFleetClient::connect(format!("http://{dir}"))
            .await
            .expect("conectar por gRPC");

    // Sin identidad, la llamada se rechaza: no se escribe en el inventario a
    // partir de lo que diga el CUERPO del mensaje, que lo controla quien envia.
    let anonima = cliente
        .latir(tonic::Request::new(aegis_server::pb::Latido {
            id_agente: cn.clone(),
            ..Default::default()
        }))
        .await;
    assert!(
        anonima.is_err(),
        "una llamada sin identidad debe rechazarse"
    );
    assert_eq!(anonima.unwrap_err().code(), tonic::Code::Unauthenticated);

    // Con identidad (la que inyectaria el proxy que autentica), funciona.
    let mut peticion = tonic::Request::new(aegis_server::pb::SolicitudEnrolamiento {
        id_agente: cn.clone(),
        hostname: "sonda-de-terceros".to_string(),
        version_agente: "9.9.9".to_string(),
        huella_cert: vec![1, 2, 3],
    });
    peticion
        .metadata_mut()
        .insert("x-aegis-agente", cn.parse().unwrap());
    let respuesta = cliente.enrolar(peticion).await.expect("enrolar por gRPC");
    assert!(respuesta.into_inner().aceptado);

    // Y aterriza en la MISMA base de datos que el transporte nativo: los dos
    // caminos desembocan en el mismo nucleo de dominio.
    let vista = almacen
        .obtener_agente(&cn, 300)
        .await
        .expect("en inventario");
    assert_eq!(vista.hostname, "sonda-de-terceros");

    servidor.abort();
}
