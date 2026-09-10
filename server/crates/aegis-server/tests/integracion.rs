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
use aegis_server::almacen::{Almacen, VistaCorrelacion};
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

/// Serializa las pruebas que afirman algo sobre LA POLITICA ACTIVA.
///
/// Casi todo en este esquema se aisla por CN: cada prueba inventa el suyo y no
/// se cruza con las demas. La politica activa es la excepcion, y no por un
/// descuido: es un SINGLETON GLOBAL por diseno —un indice unico parcial impide
/// que haya dos—, porque dos politicas activas dejarian la flota en dos
/// configuraciones distintas segun a quien preguntara cada agente.
///
/// Consecuencia: una prueba que publica y despues comprueba "la activa es la
/// mia" es correcta solo si nadie mas publica entremedias. Con el runner de
/// cargo lanzando veinte pruebas en paralelo, eso fallaba una de cada tres
/// veces, y el fallo no tenia nada que ver con lo que la prueba pretendia
/// comprobar.
///
/// Lo que NO se hizo: relajar la asercion para que "casi siempre" pase, ni
/// marcar las pruebas como ignoradas, ni pasarlas a `--test-threads=1` (lo que
/// habria serializado tambien las diecisiete que no lo necesitan). Se serializa
/// el acceso al recurso que de verdad es unico, y solo entre quienes lo tocan.
static CERROJO_POLITICA: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
        .evento(&cn, 4, "ransomware", "cifrado masivo detectado", 0, "")
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
        .evento(&cn, 3, "inyeccion", "inyeccion en proceso legitimo", 0, "")
        .await
        .unwrap();

    // Se pregunta POR ESTE endpoint y no se filtra a ojo un listado global.
    //
    // El listado global ordena por gravedad y recencia sobre toda la flota: en
    // cuanto la base de datos acumula unas decenas de alertas mas graves, esta
    // deja de aparecer en la primera pagina y la prueba falla por un motivo que
    // no tiene nada que ver con lo que pretende comprobar. Una prueba que
    // depende del estado global acumulado no prueba nada.
    let alertas = almacen.listar_alertas_de_agente(&cn, 10).await.unwrap();
    let mia = alertas.first().expect("la alerta del endpoint");
    assert_eq!(alertas.len(), 1, "este endpoint solo genero una alerta");
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
        .evento(&cn, 9999, "rootkit", "severidad absurda", 0, "")
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
    let _politica = CERROJO_POLITICA.lock().await;
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

/// Dos publicaciones de politica a la vez NO son un caso de laboratorio: son dos
/// operadores en la consola, o un operador y la automatizacion que empuja una
/// regla nueva tras ingerir inteligencia. Bajo el nivel de aislamiento por
/// defecto de PostgreSQL (READ COMMITTED) el `UPDATE ... WHERE activa` de la
/// segunda transaccion se desbloquea cuando la primera confirma, vuelve a
/// evaluar la condicion sobre la fila YA desactivada y no afecta a ninguna;
/// tampoco ve todavia la fila recien insertada. Su `INSERT` choca entonces
/// contra el indice unico parcial —y contra la clave primaria de version— y la
/// publicacion se pierde con un error crudo de base de datos.
///
/// La garantia que se exige aqui es la del producto: ninguna publicacion se
/// pierde, cada una recibe su propia version, y la flota nunca queda sin
/// politica activa.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn publicaciones_de_politica_simultaneas_se_serializan_sin_perder_ninguna() {
    let _politica = CERROJO_POLITICA.lock().await;
    let Some(almacen) = almacen_de_pruebas().await else {
        eprintln!("OMITIDA: no hay PostgreSQL");
        return;
    };
    const CONCURRENTES: usize = 8;

    let mut tareas = Vec::with_capacity(CONCURRENTES);
    for i in 0..CONCURRENTES {
        let a = almacen.clone();
        tareas.push(tokio::spawn(async move {
            a.publicar_politica(
                &format!("simultanea-{i}"),
                serde_json::json!({ "orden": i }),
            )
            .await
        }));
    }

    let mut versiones = Vec::with_capacity(CONCURRENTES);
    for (i, t) in tareas.into_iter().enumerate() {
        let r = t.await.expect("la tarea no debe entrar en panico");
        versiones.push(r.unwrap_or_else(|e| {
            panic!("la publicacion simultanea {i} se perdio: {e}");
        }));
    }

    versiones.sort_unstable();
    let distintas = {
        let mut v = versiones.clone();
        v.dedup();
        v.len()
    };
    assert_eq!(
        distintas, CONCURRENTES,
        "cada publicacion debe recibir una version propia, sin colisiones: {versiones:?}"
    );

    // Y al terminar la rafaga sigue habiendo exactamente una politica activa:
    // la ultima que confirmo.
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
                detalles_json: String::new(),
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

// ---------------------------------------------------------------------------
// FASE 38: inteligencia STIX, linaje de procesos y empuje de reglas
// ---------------------------------------------------------------------------

use aegis_fleet::proto::{NodoProceso, ReporteGrafo, ReporteStix};
use aegis_server::notificador::Notificador;
use aegis_server::reglas::{compilar_politica, validar, Regla, TipoRegla};

/// Bundle STIX 2.1 con dos objetos, parametrizado para poder repetir el MISMO
/// objeto desde dos agentes distintos y comprobar la deduplicacion.
fn bundle_con(id_indicador: &str) -> String {
    format!(
        r#"{{"type":"bundle","id":"bundle--{}","objects":[
            {{"type":"indicator","spec_version":"2.1","id":"{id_indicador}",
             "pattern":"[file:hashes.'SHA-256' = 'deadbeef']","pattern_type":"stix",
             "valid_from":"2026-01-01T00:00:00Z"}},
            {{"type":"process","id":"process--{}","command_line":"sh -c curl evil"}}
        ]}}"#,
        uuid::Uuid::new_v4(),
        uuid::Uuid::new_v4()
    )
}

#[tokio::test]
async fn un_bundle_stix_se_ingiere_y_sus_objetos_quedan_consultables() {
    let Some(almacen) = almacen_de_pruebas().await else {
        eprintln!("OMITIDA: no hay PostgreSQL");
        return;
    };
    let servicio = ServicioFlota::nuevo(almacen.clone(), 30);
    let cn = cn_unico("stix");
    servicio
        .enrolar(&cn, "id", "host", "1.0", b"h")
        .await
        .unwrap();

    let indicador = format!("indicator--{}", uuid::Uuid::new_v4());
    let ingesta = servicio
        .ingerir_stix(&cn, &bundle_con(&indicador), 0)
        .await
        .expect("la ingesta debe funcionar");

    assert_eq!(ingesta.objetos, 2, "el bundle trae dos objetos");
    assert_eq!(ingesta.reavistados, 0, "es la primera vez que se ven");

    let objetos = almacen.listar_objetos_stix(500).await.unwrap();
    let mio = objetos
        .iter()
        .find(|o| o.id == indicador)
        .expect("el indicador");
    assert_eq!(mio.tipo, "indicator");
    assert_eq!(mio.avistamientos, 1);
}

#[tokio::test]
async fn el_mismo_indicador_visto_por_dos_endpoints_suma_avistamientos_en_vez_de_duplicarse() {
    let Some(almacen) = almacen_de_pruebas().await else {
        eprintln!("OMITIDA: no hay PostgreSQL");
        return;
    };
    let servicio = ServicioFlota::nuevo(almacen.clone(), 30);
    let cn_a = cn_unico("stix-a");
    let cn_b = cn_unico("stix-b");
    servicio
        .enrolar(&cn_a, "a", "host-a", "1.0", b"h")
        .await
        .unwrap();
    servicio
        .enrolar(&cn_b, "b", "host-b", "1.0", b"h")
        .await
        .unwrap();

    // STIX define los identificadores para que dos herramientas que observen el
    // MISMO artefacto produzcan el MISMO id. Aprovecharlo es lo que convierte
    // "cien endpoints vieron esto" en una campana y no en cien anecdotas.
    let indicador = format!("indicator--{}", uuid::Uuid::new_v4());

    servicio
        .ingerir_stix(&cn_a, &bundle_con(&indicador), 0)
        .await
        .unwrap();
    let segunda = servicio
        .ingerir_stix(&cn_b, &bundle_con(&indicador), 0)
        .await
        .unwrap();

    assert_eq!(segunda.reavistados, 1, "el indicador repetido se reconoce");

    let objetos = almacen.listar_objetos_stix(500).await.unwrap();
    let coincidencias: Vec<_> = objetos.iter().filter(|o| o.id == indicador).collect();
    assert_eq!(coincidencias.len(), 1, "un solo objeto, no dos");
    assert_eq!(coincidencias[0].avistamientos, 2, "con dos avistamientos");
}

#[tokio::test]
async fn un_documento_que_no_es_un_bundle_se_rechaza() {
    let Some(almacen) = almacen_de_pruebas().await else {
        eprintln!("OMITIDA: no hay PostgreSQL");
        return;
    };
    let servicio = ServicioFlota::nuevo(almacen.clone(), 30);
    let cn = cn_unico("stix-malo");
    servicio.enrolar(&cn, "id", "h", "1.0", b"h").await.unwrap();

    assert!(servicio.ingerir_stix(&cn, "no soy json", 0).await.is_err());
    assert!(servicio
        .ingerir_stix(&cn, r#"{"type":"otra-cosa","objects":[]}"#, 0)
        .await
        .is_err());
}

#[tokio::test]
async fn el_linaje_de_procesos_se_guarda_entero_con_sus_aristas() {
    let Some(almacen) = almacen_de_pruebas().await else {
        eprintln!("OMITIDA: no hay PostgreSQL");
        return;
    };
    let servicio = ServicioFlota::nuevo(almacen.clone(), 30);
    let cn = cn_unico("grafo");
    servicio.enrolar(&cn, "id", "h", "1.0", b"h").await.unwrap();

    // libreoffice -> sh -> python: el linaje que convierte una rutina en un
    // incidente.
    let nodos = vec![
        NodoProceso {
            clave: 100,
            pid: 10,
            padre: 0,
            creador: 0,
            profundidad: 0,
            imagen: "/usr/lib/libreoffice/soffice.bin".into(),
            cmdline: "soffice --headless doc.odt".into(),
            ..Default::default()
        },
        NodoProceso {
            clave: 200,
            pid: 20,
            padre: 100,
            creador: 100,
            profundidad: 1,
            imagen: "/bin/sh".into(),
            cmdline: "sh -c ...".into(),
            ..Default::default()
        },
        NodoProceso {
            clave: 300,
            pid: 30,
            padre: 200,
            creador: 200,
            profundidad: 2,
            imagen: "/usr/bin/python3".into(),
            cmdline: "python3 -c socket".into(),
            taints: 0b111,
            puntuacion: 90,
            ..Default::default()
        },
    ];

    let (id, n) = servicio.ingerir_grafo(&cn, 300, 0, &nodos).await.unwrap();
    assert_eq!(n, 3);

    // Las aristas tienen que sobrevivir: sin ellas el grafo es una lista.
    let filas: Vec<(i64, i64, String)> = sqlx::query_as(
        "SELECT clave, padre, imagen FROM grafo_nodos WHERE id_grafo = $1 ORDER BY profundidad",
    )
    .bind(id)
    .fetch_all(almacen.pool())
    .await
    .unwrap();

    assert_eq!(filas.len(), 3);
    assert_eq!(filas[0].1, 0, "la raiz del linaje no tiene padre");
    assert_eq!(filas[1].1, 100, "sh cuelga de libreoffice");
    assert_eq!(filas[2].1, 200, "python cuelga de sh");
    assert!(filas[2].2.contains("python"));
}

#[tokio::test]
async fn un_texto_desmesurado_del_endpoint_se_recorta_antes_de_tocar_la_base_de_datos() {
    let Some(almacen) = almacen_de_pruebas().await else {
        eprintln!("OMITIDA: no hay PostgreSQL");
        return;
    };
    let servicio = ServicioFlota::nuevo(almacen.clone(), 30);
    let cn = cn_unico("grafo-largo");
    servicio.enrolar(&cn, "id", "h", "1.0", b"h").await.unwrap();

    // Un agente comprometido controla estos textos: no puede escribir un campo
    // de tamano arbitrario en la base de datos.
    let nodo = NodoProceso {
        clave: 1,
        imagen: "/".to_string() + &"a".repeat(100_000),
        cmdline: "x".repeat(100_000),
        ..Default::default()
    };
    let (id, _) = servicio.ingerir_grafo(&cn, 1, 0, &[nodo]).await.unwrap();

    let (imagen, cmdline): (String, String) =
        sqlx::query_as("SELECT imagen, cmdline FROM grafo_nodos WHERE id_grafo = $1")
            .bind(id)
            .fetch_one(almacen.pool())
            .await
            .unwrap();
    assert!(
        imagen.len() <= 4096,
        "la imagen se recorto: {}",
        imagen.len()
    );
    assert!(
        cmdline.len() <= 8192,
        "la cmdline se recorto: {}",
        cmdline.len()
    );
}

// ---------------------------------------------------------------------------
// El motor de reglas y el EMPUJE de extremo a extremo
// ---------------------------------------------------------------------------

#[tokio::test]
async fn el_motor_compila_las_reglas_activas_en_la_politica_publicada() {
    let _politica = CERROJO_POLITICA.lock().await;
    let Some(almacen) = almacen_de_pruebas().await else {
        eprintln!("OMITIDA: no hay PostgreSQL");
        return;
    };

    let nombre = format!("bloqueo-smb-{}", uuid::Uuid::new_v4().simple());
    let parametros = validar(
        TipoRegla::BloquearPuerto,
        &serde_json::json!({"puerto": 445}),
    )
    .expect("la regla es valida");
    let id = almacen
        .crear_regla(
            &nombre,
            "bloquear_puerto",
            &parametros,
            3,
            "operador@empresa",
        )
        .await
        .unwrap();

    let version = almacen.recompilar_y_publicar(&nombre).await.unwrap();
    let (v_activa, contenido) = almacen.politica_activa().await.unwrap();
    assert_eq!(v_activa, version);
    assert_eq!(contenido["version"], version);

    let reglas = contenido["reglas"].as_array().unwrap();
    let mia = reglas
        .iter()
        .find(|r| r["nombre"] == serde_json::json!(nombre))
        .expect("la regla debe estar en la politica publicada");
    assert_eq!(mia["parametros"]["puerto"], 445);

    // Al desactivarla, la politica nueva ya no la lleva: la flota deja de
    // aplicarla sin que nadie toque endpoint alguno.
    almacen.fijar_regla_activa(id, false).await.unwrap();
    almacen
        .recompilar_y_publicar("desactivacion")
        .await
        .unwrap();
    let (_, contenido2) = almacen.politica_activa().await.unwrap();
    let sigue = contenido2["reglas"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["nombre"] == serde_json::json!(nombre));
    assert!(
        !sigue,
        "una regla desactivada no puede seguir bajando a la flota"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn una_regla_global_llega_al_agente_real_por_empuje_sin_esperar_su_latido() {
    let _politica = CERROJO_POLITICA.lock().await;
    let Some(almacen) = almacen_de_pruebas().await else {
        eprintln!("OMITIDA: no hay PostgreSQL");
        return;
    };
    let servicio = Arc::new(ServicioFlota::nuevo(almacen.clone(), 30));

    // El puente de avisos: es lo que hace que una regla publicada contra otra
    // instancia despierte a los agentes suscritos a esta.
    let (version_inicial, _) = almacen.politica_activa().await.unwrap();
    let notificador = Notificador::iniciar(&url_pg(), version_inicial)
        .await
        .expect("la escucha de avisos debe arrancar");

    let ca = Arc::new(AutoridadCertificadora::nueva("CA de pruebas").unwrap());
    let id_srv = ca.emitir("control-plane", 3600).unwrap();
    let manejador = Arc::new(
        ManejadorPersistente::nuevo(servicio.clone(), tokio::runtime::Handle::current())
            .con_avisos(&notificador),
    );
    let servidor = ServidorFlota::nuevo(&id_srv, &ca.cert_der(), manejador)
        .unwrap()
        .escuchar("127.0.0.1:0")
        .unwrap();
    let dir = servidor.direccion();

    let cn = cn_unico("suscrito");
    let ca_cliente = ca.clone();
    let cn_hilo = cn.clone();

    // El agente REAL se enrola y abre su canal de politica.
    let canal = tokio::task::spawn_blocking(move || {
        let agente = agente_real(dir, &ca_cliente, ca_cliente.clone(), &cn_hilo).unwrap();
        let mut s = agente.abrir_sesion().unwrap();
        s.enrolar(&agente.solicitud_enrolamiento().unwrap())
            .unwrap();
        let sesion = agente.abrir_sesion().unwrap();
        sesion
            .suscribir_politica(version_inicial.max(0) as u64)
            .unwrap()
    })
    .await
    .expect("el agente debe suscribirse");

    // El operador crea la regla desde el panel, un instante despues.
    let alm = almacen.clone();
    let nombre = format!("bloqueo-smb-{}", uuid::Uuid::new_v4().simple());
    let nombre_hilo = nombre.clone();
    let operador = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        let p = validar(
            TipoRegla::BloquearPuerto,
            &serde_json::json!({"puerto": 445}),
        )
        .unwrap();
        alm.crear_regla(&nombre_hilo, "bloquear_puerto", &p, 3, "operador@empresa")
            .await
            .unwrap();
        alm.recompilar_y_publicar(&nombre_hilo).await.unwrap()
    });

    // El agente espera en su canal.
    //
    // Se espera EN BUCLE hasta ver la politica, que es lo que hace un agente de
    // verdad: por el mismo canal viajan tambien latidos y cacerias, asi que un
    // agente que se quedara con el primer marco que llega estaria suponiendo
    // que nadie mas usa el canal. Se acota con un numero de marcos para que un
    // canal que nunca entregue la politica falle en vez de colgarse.
    let inicio = std::time::Instant::now();
    let empuje = tokio::task::spawn_blocking(move || {
        let mut canal = canal;
        // Se acota por TIEMPO y no por numero de marcos. Por el canal viajan
        // tambien cacerias, y cuantas haya abiertas depende de lo que este
        // haciendo el resto de la flota —o, aqui, el resto de la suite—. Un
        // limite de marcos convertiria eso en un fallo aleatorio; un limite de
        // tiempo mide lo que la prueba quiere afirmar: que la politica llega
        // pronto, sin esperar al latido del agente.
        let limite = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while std::time::Instant::now() < limite {
            let marco = canal.siguiente()?;
            if !marco.politica_json.is_empty() {
                return Ok(marco);
            }
        }
        Err(aegis_fleet::FleetError::Protocolo(
            "el canal no entrego politica en 20 s".to_string(),
        ))
    })
    .await
    .expect("hilo del canal")
    .expect("el canal debe entregar politica");
    let transcurrido = inicio.elapsed();

    let version_publicada = operador.await.unwrap();

    assert!(
        !empuje.es_keepalive,
        "debe llegar politica, no un latido de canal"
    );
    assert_eq!(empuje.version, version_publicada.max(0) as u64);
    assert!(
        empuje.politica_json.contains("445"),
        "la regla compilada debe viajar en el empuje: {}",
        empuje.politica_json
    );
    // Esto es lo que distingue un EMPUJE de un sondeo: la orden global llega al
    // publicarse, no en el siguiente latido del agente (que serian 30 s).
    assert!(
        transcurrido < std::time::Duration::from_secs(10),
        "la regla tardo {transcurrido:?} en llegar"
    );

    servidor.parar();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn el_agente_entrega_stix_y_linaje_por_el_canal_mtls_y_queda_en_postgres() {
    let Some(almacen) = almacen_de_pruebas().await else {
        eprintln!("OMITIDA: no hay PostgreSQL");
        return;
    };
    let servicio = Arc::new(ServicioFlota::nuevo(almacen.clone(), 30));

    let ca = Arc::new(AutoridadCertificadora::nueva("CA de pruebas").unwrap());
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

    let cn = cn_unico("intel");
    let indicador = format!("indicator--{}", uuid::Uuid::new_v4());
    let bundle = bundle_con(&indicador);
    let ca_cliente = ca.clone();
    let cn_hilo = cn.clone();

    let (objetos, nodos) = tokio::task::spawn_blocking(move || {
        let agente = agente_real(dir, &ca_cliente, ca_cliente.clone(), &cn_hilo).unwrap();
        let mut s = agente.abrir_sesion().unwrap();
        s.enrolar(&agente.solicitud_enrolamiento().unwrap())
            .unwrap();

        let mut s2 = agente.abrir_sesion().unwrap();
        let ack_stix = s2
            .reportar_stix(&ReporteStix {
                id_agente: cn_hilo.clone(),
                bundle_json: bundle,
                momento_unix: 0,
            })
            .unwrap();

        let mut s3 = agente.abrir_sesion().unwrap();
        let ack_grafo = s3
            .reportar_grafo(&ReporteGrafo {
                id_agente: cn_hilo.clone(),
                raiz: 300,
                momento_unix: 0,
                nodos: vec![
                    NodoProceso {
                        clave: 200,
                        imagen: "/bin/sh".into(),
                        ..Default::default()
                    },
                    NodoProceso {
                        clave: 300,
                        padre: 200,
                        imagen: "/usr/bin/python3".into(),
                        puntuacion: 88,
                        ..Default::default()
                    },
                ],
            })
            .unwrap();

        (ack_stix.objetos_ingeridos, ack_grafo.nodos_ingeridos)
    })
    .await
    .expect("hilo del agente");

    assert_eq!(objetos, 2, "los dos objetos del bundle");
    assert_eq!(nodos, 2, "los dos nodos del linaje");

    // Y todo ello aterrizo en PostgreSQL, por el transporte real del agente.
    let stix = almacen.listar_objetos_stix(500).await.unwrap();
    assert!(
        stix.iter().any(|o| o.id == indicador),
        "el indicador debe estar"
    );

    let grafos: i64 = sqlx::query_scalar("SELECT count(*) FROM grafos WHERE cn_agente = $1")
        .bind(&cn)
        .fetch_one(almacen.pool())
        .await
        .unwrap();
    assert_eq!(grafos, 1);

    servidor.parar();
}

#[tokio::test]
async fn la_politica_compilada_es_la_que_el_agente_puede_aplicar() {
    let _politica = CERROJO_POLITICA.lock().await;
    // Comprobacion de forma: el documento que baja a la flota tiene que llevar
    // su version dentro y las reglas con sus parametros ya normalizados, porque
    // el agente lo guarda en disco y lo aplica sin volver a preguntar.
    let regla = Regla {
        id: uuid::Uuid::new_v4(),
        nombre: "smb".into(),
        tipo: "bloquear_puerto".into(),
        parametros: validar(
            TipoRegla::BloquearPuerto,
            &serde_json::json!({"puerto": 445}),
        )
        .unwrap(),
        activa: true,
        severidad: 3,
        creada_por: "operador".into(),
    };
    let pol = compilar_politica(9, &[regla]);
    assert_eq!(pol["version"], 9);
    assert!(pol["generada_en"].is_string());
    let r = &pol["reglas"][0];
    assert_eq!(r["tipo"], "bloquear_puerto");
    assert_eq!(r["parametros"]["puerto"], 445);
    assert_eq!(r["parametros"]["direccion"], "ambas", "sin huecos");
}

// ---------------------------------------------------------------------------
// FASE 43: cacerias distribuidas AegisQL
// ---------------------------------------------------------------------------

/// Indica si ESA caceria concreta sigue pendiente para ESE agente.
///
/// `caza_pendiente_para` devuelve la caceria abierta mas reciente que el agente
/// no ha contestado, que es justo lo que tiene que hacer en produccion. Aqui se
/// comprueba la propiedad concreta —"esta ya no le toca"— en vez de exigir que
/// no le toque ninguna: la base de datos es compartida y otras pruebas abren
/// las suyas al mismo tiempo. Una asercion sobre el estado global de la tabla
/// fallaria por algo que no tiene nada que ver con lo que se quiere comprobar.
async fn sigue_pendiente(almacen: &Almacen, cn: &str, id: uuid::Uuid) -> bool {
    let mut visto = Vec::new();
    // Se recorren las cacerias abiertas sin contestar marcandolas de una en
    // una, porque la consulta solo devuelve la mas reciente.
    loop {
        match almacen.caza_pendiente_para(cn).await.unwrap() {
            Some((pendiente, _)) if pendiente == id => return true,
            Some((otra, _)) if !visto.contains(&otra) => {
                // Se contesta la ajena para que la consulta siga bajando.
                almacen
                    .guardar_respuesta_caza(
                        otra,
                        cn,
                        &serde_json::json!([]),
                        0,
                        0,
                        0,
                        false,
                        false,
                        0,
                        "",
                    )
                    .await
                    .unwrap();
                visto.push(otra);
            }
            _ => return false,
        }
    }
}

#[tokio::test]
async fn una_caceria_llega_al_agente_que_no_la_ha_contestado_y_deja_de_llegarle_al_responder() {
    let Some(almacen) = almacen_de_pruebas().await else {
        eprintln!("OMITIDA: no hay PostgreSQL");
        return;
    };
    let servicio = ServicioFlota::nuevo(almacen.clone(), 30);
    let cn = cn_unico("cazador");
    servicio
        .enrolar(&cn, "id", "host", "1.0.0", b"h")
        .await
        .unwrap();

    let id = almacen
        .lanzar_caza(
            "SELECT pid FROM processes WHERE uid = 0",
            "processes",
            &["pid".to_string()],
            "analista@soc",
            90,
        )
        .await
        .unwrap();

    // Antes de responder, la caceria le corresponde.
    assert!(
        sigue_pendiente(&almacen, &cn, id).await,
        "la caceria recien lanzada tiene que llegarle"
    );

    // Responde.
    almacen
        .guardar_respuesta_caza(
            id,
            &cn,
            &serde_json::json!([["1"]]),
            1,
            250,
            0,
            false,
            false,
            7,
            "",
        )
        .await
        .unwrap();

    // Y deja de corresponderle: sin esto, un endpoint reejecutaria la misma
    // consulta en cada latido del canal, para siempre.
    assert!(
        !sigue_pendiente(&almacen, &cn, id).await,
        "una caceria ya contestada no puede volver a entregarse"
    );
}

#[tokio::test]
async fn la_respuesta_de_un_agente_es_idempotente_ante_un_reintento() {
    // Un endpoint con mala red que reintenta no puede inflar el recuento: el
    // analista veria una amenaza mas extendida de lo que esta.
    let Some(almacen) = almacen_de_pruebas().await else {
        eprintln!("OMITIDA: no hay PostgreSQL");
        return;
    };
    let servicio = ServicioFlota::nuevo(almacen.clone(), 30);
    let cn = cn_unico("reintento");
    servicio
        .enrolar(&cn, "id", "host", "1.0.0", b"h")
        .await
        .unwrap();

    let id = almacen
        .lanzar_caza(
            "SELECT COUNT(*) FROM processes",
            "processes",
            &["count".into()],
            "op",
            90,
        )
        .await
        .unwrap();

    for _ in 0..3 {
        almacen
            .guardar_respuesta_caza(
                id,
                &cn,
                &serde_json::json!([["5"]]),
                5,
                100,
                0,
                false,
                false,
                3,
                "",
            )
            .await
            .unwrap();
    }

    let r = almacen.resumen_caza(id).await.unwrap();
    assert_eq!(r.respondieron, 1, "tres reintentos son UNA respuesta");
    assert_eq!(
        r.coincidencias, 5,
        "y sus coincidencias no se suman tres veces"
    );
}

#[tokio::test]
async fn el_resumen_agrega_toda_la_flota_y_distingue_lo_que_no_se_pudo_ver() {
    let Some(almacen) = almacen_de_pruebas().await else {
        eprintln!("OMITIDA: no hay PostgreSQL");
        return;
    };
    let servicio = ServicioFlota::nuevo(almacen.clone(), 30);

    let id = almacen
        .lanzar_caza(
            "SELECT pid, sha256 FROM processes WHERE memory.rwx",
            "processes",
            &["pid".into(), "sha256".into()],
            "analista@soc",
            90,
        )
        .await
        .unwrap();

    // Tres endpoints con desenlaces distintos, que es el caso real.
    let limpio = cn_unico("limpio");
    let sucio = cn_unico("sucio");
    let ciego = cn_unico("ciego");
    for cn in [&limpio, &sucio, &ciego] {
        servicio
            .enrolar(cn, "id", "host", "1.0.0", b"h")
            .await
            .unwrap();
    }

    // Uno no encuentra nada.
    almacen
        .guardar_respuesta_caza(
            id,
            &limpio,
            &serde_json::json!([]),
            0,
            300,
            0,
            false,
            false,
            5,
            "",
        )
        .await
        .unwrap();
    // Otro encuentra dos cosas.
    almacen
        .guardar_respuesta_caza(
            id,
            &sucio,
            &serde_json::json!([["1234", "ab".repeat(32)], ["5678", "cd".repeat(32)]]),
            2,
            280,
            0,
            false,
            false,
            12,
            "",
        )
        .await
        .unwrap();
    // Y el tercero no pudo mirar del todo: agoto su presupuesto y hubo valores
    // inaccesibles. Este es el caso que un resumen honesto NO puede esconder.
    almacen
        .guardar_respuesta_caza(
            id,
            &ciego,
            &serde_json::json!([]),
            0,
            40,
            17,
            true,
            true,
            5000,
            "",
        )
        .await
        .unwrap();

    let r = almacen.resumen_caza(id).await.unwrap();
    assert_eq!(r.respondieron, 3);
    assert_eq!(r.con_hallazgos, 1, "solo uno encontro algo");
    assert_eq!(r.coincidencias, 2);
    assert_eq!(r.examinadas, 620);
    assert_eq!(r.inaccesibles, 17, "lo que no se pudo leer no se esconde");
    assert_eq!(r.agotados, 1, "y el que se quedo a medias tampoco");
    assert_eq!(r.peor_ms, 5000);

    // Las respuestas llegan con las utiles primero: en una flota de diez mil,
    // el analista no puede pasar paginas hasta encontrar el hallazgo.
    let respuestas = almacen.respuestas_caza(id, 10).await.unwrap();
    assert_eq!(respuestas[0].cn_agente, sucio);
    assert_eq!(respuestas[0].coincidencias, 2);
}

#[tokio::test]
async fn una_caceria_cerrada_deja_de_entregarse() {
    let Some(almacen) = almacen_de_pruebas().await else {
        eprintln!("OMITIDA: no hay PostgreSQL");
        return;
    };
    let servicio = ServicioFlota::nuevo(almacen.clone(), 30);
    let cn = cn_unico("tarde");
    servicio
        .enrolar(&cn, "id", "host", "1.0.0", b"h")
        .await
        .unwrap();

    let id = almacen
        .lanzar_caza(
            "SELECT pid FROM processes",
            "processes",
            &["pid".into()],
            "op",
            90,
        )
        .await
        .unwrap();
    assert!(sigue_pendiente(&almacen, &cn, id).await);

    assert!(almacen.cerrar_caza(id).await.unwrap());
    assert!(
        !sigue_pendiente(&almacen, &cn, id).await,
        "una caceria cerrada no puede seguir bajando a la flota"
    );
    // Cerrarla dos veces no es un error nuevo, pero tampoco un exito.
    assert!(!almacen.cerrar_caza(id).await.unwrap());
}

#[tokio::test]
async fn el_objetivo_se_congela_al_lanzar_la_caceria() {
    // El denominador de la cobertura tiene que capturarse AL LANZAR. Si se
    // contara al leer el resultado, un endpoint que se apago despues de
    // responder haria bajar el porcentaje sin que nadie dejara de contestar.
    let Some(almacen) = almacen_de_pruebas().await else {
        eprintln!("OMITIDA: no hay PostgreSQL");
        return;
    };
    let servicio = ServicioFlota::nuevo(almacen.clone(), 30);
    let cn = cn_unico("vivo");
    servicio
        .enrolar(&cn, "id", "host", "1.0.0", b"h")
        .await
        .unwrap();
    servicio.latido(&cn, 20_000, 0, 0).await.unwrap();

    let id = almacen
        .lanzar_caza(
            "SELECT pid FROM processes",
            "processes",
            &["pid".into()],
            "op",
            90,
        )
        .await
        .unwrap();

    let caza = almacen.obtener_caza(id).await.unwrap().unwrap();
    assert!(
        caza.objetivo >= 1,
        "al menos el agente que acaba de latir cuenta como objetivo"
    );
    assert_eq!(caza.lanzada_por, "op");
    assert_eq!(caza.tabla, "processes");
    assert!(caza.cerrada_en.is_none());
}

/// La cuarentena de enjambre llega al agente REAL por el canal, y la difusion
/// queda contabilizada.
///
/// LO QUE ESTA PRUEBA IMPIDE QUE VUELVA
/// -----------------------------------
/// El aviso de cuarentena lo reciben a la vez la tarea que refresca la cache en
/// memoria y los canales de los agentes. Cuando el canal despertaba del aviso y
/// leia la cache, podia leerla ANTES de que la tarea la hubiera actualizado: le
/// enviaba al agente la lista anterior —que ya tenia— y, como el aviso ya habia
/// pasado, no habia un segundo despertar. La orden de contencion se perdia en
/// silencio para ese endpoint, que es el peor fallo posible aqui: el operador ve
/// la cuarentena puesta y la maquina comprometida sigue teniendo por donde
/// moverse.
///
/// El canal despierta ahora de la PUBLICACION de la cache, no del aviso, asi que
/// el valor esta garantizado antes de leerlo.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn una_cuarentena_de_enjambre_llega_al_agente_real_y_queda_contabilizada() {
    let Some(almacen) = almacen_de_pruebas().await else {
        eprintln!("OMITIDA: no hay PostgreSQL");
        return;
    };
    let servicio = Arc::new(ServicioFlota::nuevo(almacen.clone(), 30));

    let (version_inicial, _) = almacen.politica_activa().await.unwrap();
    let notificador = Notificador::iniciar(&url_pg(), version_inicial)
        .await
        .expect("la escucha de avisos debe arrancar");

    let ca = Arc::new(AutoridadCertificadora::nueva("CA de pruebas").unwrap());
    let id_srv = ca.emitir("control-plane", 3600).unwrap();
    let manejador = Arc::new(
        ManejadorPersistente::nuevo(servicio.clone(), tokio::runtime::Handle::current())
            .con_avisos(&notificador),
    );
    let difusion = manejador.difusion();
    let servidor = ServidorFlota::nuevo(&id_srv, &ca.cert_der(), manejador)
        .unwrap()
        .escuchar("127.0.0.1:0")
        .unwrap();
    let dir = servidor.direccion();

    // Una direccion irrepetible por ejecucion: la tabla es global y dos pruebas
    // en paralelo no pueden pisarse la lista.
    let octetos = uuid::Uuid::new_v4().as_bytes()[..4].to_vec();
    let ip = std::net::IpAddr::from([203, 0, 113, octetos[0].max(1)]);
    let ip_txt = ip.to_string();

    let cn = cn_unico("cuarentena");
    let ca_cliente = ca.clone();
    let cn_hilo = cn.clone();
    let canal = tokio::task::spawn_blocking(move || {
        let agente = agente_real(dir, &ca_cliente, ca_cliente.clone(), &cn_hilo).unwrap();
        let mut s = agente.abrir_sesion().unwrap();
        s.enrolar(&agente.solicitud_enrolamiento().unwrap())
            .unwrap();
        let sesion = agente.abrir_sesion().unwrap();
        sesion
            .suscribir_politica(version_inicial.max(0) as u64)
            .unwrap()
    })
    .await
    .expect("el agente debe suscribirse");

    // El canal ya esta abierto y al dia; la orden llega DESPUES, que es el caso
    // que importa: un endpoint que estaba conectado cuando el SOC contuvo la
    // amenaza.
    let alm = almacen.clone();
    let operador = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        alm.poner_en_cuarentena(ip, None, "prueba de propagacion", "operador@empresa", None)
            .await
            .unwrap();
    });

    let ip_esperada = ip_txt.clone();
    let empuje = tokio::task::spawn_blocking(move || {
        let mut canal = canal;
        let limite = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while std::time::Instant::now() < limite {
            let marco = canal.siguiente()?;
            if marco.cuarentena_valida && marco.cuarentena.contains(&ip_esperada) {
                return Ok(marco);
            }
        }
        Err(aegis_fleet::FleetError::Protocolo(
            "el canal no entrego la cuarentena en 20 s".to_string(),
        ))
    })
    .await
    .expect("hilo del canal")
    .expect("el canal debe entregar la cuarentena");

    operador.await.unwrap();
    assert!(empuje.cuarentena.contains(&ip_txt));

    // La difusion la cierra la ESCRITURA en el socket, no la composicion del
    // empuje: por eso, en cuanto el agente lo ha leido, ya esta contabilizada.
    //
    // Se deja pasar un segundo antes de mirar. No es para dar tiempo a que
    // llegue —ya llego—, sino para que un canal que se hubiera quedado girando
    // en vacio tenga tiempo de delatarse: el contador solo sube cuando se
    // escribe la lista VIGENTE, asi que un reenvio repetido de la misma orden se
    // ve aqui y en ningun otro sitio.
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    let (generacion, canales, _) = difusion.instantanea();
    assert!(
        generacion > 0,
        "la orden tenia que abrir una generacion de difusion"
    );
    // EXACTAMENTE una. Un agente, una orden, una escritura.
    //
    // LO QUE ESTE NUMERO IMPIDE QUE VUELVA
    // -----------------------------------
    // Los receptores de aviso se clonaban por vuelta del bucle y heredaban la
    // version del original, que no consume nada: en cuanto habia habido un solo
    // aviso, la espera dejaba de esperar y el canal reenviaba la misma orden a
    // toda velocidad. Medido con diez mil canales: SIETE MILLONES de empujes en
    // veinticinco segundos, provocados por una sola orden de contencion. Es una
    // denegacion de servicio que se causa el propio producto justo cuando esta
    // conteniendo un incidente, que es el peor momento posible.
    assert_eq!(
        canales, 1,
        "una sola orden y un solo agente son UNA escritura; \
         mas de una significa que el canal esta reenviando en bucle"
    );

    // Se levanta: la tabla es global y dejarla puesta afectaria a otras pruebas.
    almacen.levantar_cuarentena(ip, "prueba").await.unwrap();
    servidor.parar();
}

// ---------------------------------------------------------------------------
// FASE 45: heuristicas globales — deteccion de APT distribuida
// ---------------------------------------------------------------------------

/// Regla del ejemplo canonico, con umbral parametrizable para las pruebas.
fn regla_reconocimiento(nombre: &str, minimo: i32) -> aegis_server::heuristicas::NuevaHeuristica {
    aegis_server::heuristicas::NuevaHeuristica {
        nombre: nombre.to_string(),
        patron: "Movimiento Lateral Distribuido".to_string(),
        tecnicas: vec![],
        categorias: vec![nombre.to_string()],
        clave_detalle: "cuenta".to_string(),
        ventana_horas: 48,
        minimo_endpoints: minimo,
        severidad: 4,
        tecnica_mitre: Some("T1087".to_string()),
        tactica_mitre: Some("Descubrimiento".to_string()),
    }
}

/// Enrola `n` endpoints y hace que cada uno reporte una alerta con `detalles`.
///
/// La categoria de cada prueba es su propio identificador unico: la tabla de
/// alertas es global y dos pruebas en paralelo no pueden verse la evidencia.
async fn sembrar(
    servicio: &Arc<ServicioFlota>,
    almacen: &Almacen,
    categoria: &str,
    cuenta: &str,
    n: usize,
) -> Vec<String> {
    let mut cns = Vec::new();
    for i in 0..n {
        let cn = cn_unico(&format!("{categoria}-{i}"));
        almacen
            .enrolar(&cn, &cn, &format!("host-{i}"), "1.0", &[], "")
            .await
            .unwrap();
        servicio
            .evento(
                &cn,
                3,
                categoria,
                "enumeracion del dominio",
                0,
                &serde_json::json!({ "cuenta": cuenta }).to_string(),
            )
            .await
            .unwrap();
        cns.push(cn);
    }
    cns
}

/// Desactiva la regla de una prueba al terminar.
///
/// La tabla de reglas es global: una regla viva de una prueba pasada se
/// evaluaria en cada vuelta de todas las siguientes, encareciendo la suite sin
/// comprobar nada.
async fn apagar_regla(almacen: &Almacen, nombre: &str) {
    if let Some(r) = almacen
        .listar_heuristicas()
        .await
        .unwrap()
        .into_iter()
        .find(|r| r.nombre == nombre)
    {
        let _ = almacen.fijar_heuristica_activa(r.id, false).await;
    }
}

/// Correlacion abierta para una clave concreta, si la hay.
///
/// Las pruebas afirman sobre ESTO y no sobre el contador que devuelve la
/// evaluacion. El contador es una estadistica de registro y cuenta TODAS las
/// reglas activas de la base de datos, incluidas las que otras pruebas del
/// mismo runner acaban de crear: afirmar sobre el haria que una prueba fallara
/// por lo que hizo otra. Lo que el producto promete es la correlacion, y eso es
/// lo que se comprueba.
async fn abierta_para(almacen: &Almacen, clave: &str) -> Option<VistaCorrelacion> {
    almacen
        .correlaciones_abiertas(500)
        .await
        .unwrap()
        .into_iter()
        .find(|c| c.clave == clave)
}

/// El caso que justifica toda la fase: nada delata la campana en un endpoint.
#[tokio::test]
async fn una_campana_repartida_entre_endpoints_se_ve_solo_desde_el_plano_de_control() {
    let Some(almacen) = almacen_de_pruebas().await else {
        eprintln!("OMITIDA: no hay PostgreSQL");
        return;
    };
    let servicio = Arc::new(ServicioFlota::nuevo(almacen.clone(), 30));
    let categoria = cn_unico("reconocimiento");
    let cuenta = format!("CORP\\svc-{}", uuid::Uuid::new_v4().simple());

    let regla = regla_reconocimiento(&categoria, 5).validar().unwrap();
    almacen.crear_heuristica(&regla, "analista").await.unwrap();

    // CUATRO endpoints: por debajo del umbral. Ninguno de ellos hizo nada
    // sospechoso —enumerar el dominio es administracion legitima— y el motor
    // tiene que estar de acuerdo.
    sembrar(&servicio, &almacen, &categoria, &cuenta, 4).await;
    let correlador = aegis_server::correlador::Correlador::nuevo(servicio.clone());
    correlador.evaluar_una_vez().await.unwrap();
    assert!(
        abierta_para(&almacen, &cuenta).await.is_none(),
        "cuatro endpoints bajo el umbral no son una campana"
    );

    // El quinto cruza el umbral. La quinta maquina no hizo nada distinto de las
    // cuatro anteriores: lo que cambio es el CONJUNTO, y eso solo lo ve el
    // plano de control.
    sembrar(&servicio, &almacen, &categoria, &cuenta, 1).await;
    correlador.evaluar_una_vez().await.unwrap();
    let mia = abierta_para(&almacen, &cuenta)
        .await
        .expect("cinco endpoints ya son la campana");
    assert_eq!(mia.endpoints, 5);
    assert_eq!(mia.patron, "Movimiento Lateral Distribuido");

    // La evidencia esta materializada: se puede responder "¿que maquinas?".
    let evidencia = almacen.evidencia_de_correlacion(mia.id).await.unwrap();
    assert_eq!(evidencia.len(), 5);

    almacen
        .cerrar_correlacion(mia.id, "confirmada", "analista")
        .await
        .unwrap();
    // La regla se desactiva al terminar: la tabla es global y una regla viva de
    // una prueba pasada seguiria evaluandose en cada vuelta de las siguientes.
    apagar_regla(&almacen, &categoria).await;
}

/// Un endpoint ruidoso no es una campana, por muchas alertas que emita.
#[tokio::test]
async fn un_solo_endpoint_no_puede_fabricar_una_correlacion_distribuida() {
    let Some(almacen) = almacen_de_pruebas().await else {
        eprintln!("OMITIDA: no hay PostgreSQL");
        return;
    };
    let servicio = Arc::new(ServicioFlota::nuevo(almacen.clone(), 30));
    let categoria = cn_unico("ruidoso");
    let cuenta = format!("CORP\\uno-{}", uuid::Uuid::new_v4().simple());

    let regla = regla_reconocimiento(&categoria, 3).validar().unwrap();
    almacen.crear_heuristica(&regla, "analista").await.unwrap();

    let cns = sembrar(&servicio, &almacen, &categoria, &cuenta, 1).await;
    // Doscientas alertas mas del MISMO endpoint. Si el motor contara alertas en
    // vez de endpoints distintos, esto seria una campana de APT de doscientas
    // maquinas — y, peor, un endpoint comprometido podria fabricarla el solo
    // para provocar una respuesta automatica contra la flota.
    for _ in 0..200 {
        servicio
            .evento(
                &cns[0],
                3,
                &categoria,
                "enumeracion",
                0,
                &serde_json::json!({ "cuenta": cuenta }).to_string(),
            )
            .await
            .unwrap();
    }

    let correlador = aegis_server::correlador::Correlador::nuevo(servicio.clone());
    correlador.evaluar_una_vez().await.unwrap();
    assert!(
        abierta_para(&almacen, &cuenta).await.is_none(),
        "doscientas alertas de UN endpoint no son movimiento lateral distribuido"
    );
    apagar_regla(&almacen, &categoria).await;
}

/// Una campana en curso es UNA correlacion, no una por evaluacion.
#[tokio::test]
async fn una_campana_que_dura_no_produce_una_tormenta_de_correlaciones() {
    let Some(almacen) = almacen_de_pruebas().await else {
        eprintln!("OMITIDA: no hay PostgreSQL");
        return;
    };
    let servicio = Arc::new(ServicioFlota::nuevo(almacen.clone(), 30));
    let categoria = cn_unico("persistente");
    let cuenta = format!("CORP\\dur-{}", uuid::Uuid::new_v4().simple());

    let regla = regla_reconocimiento(&categoria, 3).validar().unwrap();
    almacen.crear_heuristica(&regla, "analista").await.unwrap();
    sembrar(&servicio, &almacen, &categoria, &cuenta, 3).await;

    let correlador = aegis_server::correlador::Correlador::nuevo(servicio.clone());
    correlador.evaluar_una_vez().await.unwrap();
    let primera = abierta_para(&almacen, &cuenta)
        .await
        .expect("tiene que abrir");

    // El motor evalua cada minuto y la evidencia sigue en la ventana de 48 h.
    // Sin idempotencia, una campana de tres dias produciria cuatro mil
    // correlaciones identicas: el analista no veria una campana, veria una
    // tormenta, que es el ruido por el que se dejan de mirar las alertas.
    for _ in 0..5 {
        correlador.evaluar_una_vez().await.unwrap();
    }
    let abiertas = almacen.correlaciones_abiertas(500).await.unwrap();
    let mias: Vec<_> = abiertas.iter().filter(|c| c.clave == cuenta).collect();
    assert_eq!(
        mias.len(),
        1,
        "seis evaluaciones sobre la misma evidencia son UNA correlacion, no seis"
    );
    assert_eq!(
        mias[0].id, primera.id,
        "la correlacion ya abierta se ACTUALIZA, no se sustituye"
    );

    // Y si la evidencia crece, la MISMA correlacion la refleja.
    sembrar(&servicio, &almacen, &categoria, &cuenta, 2).await;
    correlador.evaluar_una_vez().await.unwrap();
    let mia = abierta_para(&almacen, &cuenta).await.unwrap();
    assert_eq!(mia.id, primera.id);
    assert_eq!(mia.endpoints, 5, "la correlacion abierta tiene que crecer");
    assert_eq!(
        almacen
            .evidencia_de_correlacion(mia.id)
            .await
            .unwrap()
            .len(),
        5
    );
    apagar_regla(&almacen, &categoria).await;
}

/// Cerrar como falso positivo tiene que impedir que vuelva.
#[tokio::test]
async fn un_falso_positivo_cerrado_no_se_reabre_en_la_evaluacion_siguiente() {
    let Some(almacen) = almacen_de_pruebas().await else {
        eprintln!("OMITIDA: no hay PostgreSQL");
        return;
    };
    let servicio = Arc::new(ServicioFlota::nuevo(almacen.clone(), 30));
    let categoria = cn_unico("inventario");
    // La cuenta de servicio que inventaria el dominio cada noche: el falso
    // positivo clasico de esta clase de deteccion.
    let cuenta = format!("CORP\\inv-{}", uuid::Uuid::new_v4().simple());

    let regla = regla_reconocimiento(&categoria, 3).validar().unwrap();
    almacen.crear_heuristica(&regla, "analista").await.unwrap();
    sembrar(&servicio, &almacen, &categoria, &cuenta, 4).await;

    let correlador = aegis_server::correlador::Correlador::nuevo(servicio.clone());
    correlador.evaluar_una_vez().await.unwrap();
    let abierta = abierta_para(&almacen, &cuenta)
        .await
        .expect("tiene que abrir antes de poder cerrarse");
    assert!(almacen
        .cerrar_correlacion(abierta.id, "falso_positivo", "analista")
        .await
        .unwrap());

    // La evidencia SIGUE en la ventana. Sin excluir la clave al cerrar, el
    // motor la encuentra otra vez un minuto despues y reabre exactamente lo que
    // el analista acaba de descartar. A la tercera vez, nadie mira nada.
    correlador.evaluar_una_vez().await.unwrap();
    assert!(
        abierta_para(&almacen, &cuenta).await.is_none(),
        "un falso positivo cerrado no puede reabrirse solo"
    );

    // Y una campana con OTRA cuenta sigue detectandose: excluir una clave no
    // puede dejar la regla ciega.
    let otra = format!("CORP-otra-{}", uuid::Uuid::new_v4().simple());
    sembrar(&servicio, &almacen, &categoria, &otra, 4).await;
    correlador.evaluar_una_vez().await.unwrap();
    assert!(
        abierta_para(&almacen, &otra).await.is_some(),
        "excluir una clave no puede dejar la regla ciega para las demas"
    );
    apagar_regla(&almacen, &categoria).await;
}

/// Las alertas sin el atributo de agrupacion no participan.
#[tokio::test]
async fn lo_que_no_se_pudo_ver_no_forma_un_grupo_que_dispare_siempre() {
    let Some(almacen) = almacen_de_pruebas().await else {
        eprintln!("OMITIDA: no hay PostgreSQL");
        return;
    };
    let servicio = Arc::new(ServicioFlota::nuevo(almacen.clone(), 30));
    let categoria = cn_unico("sinatributo");

    let regla = regla_reconocimiento(&categoria, 3).validar().unwrap();
    almacen.crear_heuristica(&regla, "analista").await.unwrap();

    // Cinco endpoints que reportan la misma categoria pero NO saben bajo que
    // cuenta. Agrupar por el valor ausente juntaria en un mismo grupo todo lo
    // que no se pudo ver, y ese grupo —el mas grande de la flota— dispararia
    // siempre y en cada evaluacion.
    for i in 0..5 {
        let cn = cn_unico(&format!("{categoria}-mudo-{i}"));
        almacen
            .enrolar(&cn, &cn, "mudo", "1.0", &[], "")
            .await
            .unwrap();
        // Sin atributos, y con un atributo distinto del que agrupa la regla.
        servicio
            .evento(&cn, 3, &categoria, "sin cuenta", 0, "")
            .await
            .unwrap();
        servicio
            .evento(&cn, 3, &categoria, "otro atributo", 0, r#"{"pid":42}"#)
            .await
            .unwrap();
    }

    let correlador = aegis_server::correlador::Correlador::nuevo(servicio.clone());
    correlador.evaluar_una_vez().await.unwrap();
    // Ninguna correlacion de ESTA regla, sea cual sea la clave: no hay ninguna
    // clave posible con la que agrupar.
    let abiertas = almacen.correlaciones_abiertas(500).await.unwrap();
    assert!(
        !abiertas.iter().any(|c| c.regla == categoria),
        "las alertas sin el atributo de agrupacion no pueden formar un grupo"
    );
    apagar_regla(&almacen, &categoria).await;
}

/// Una regla desactivada deja de evaluarse.
#[tokio::test]
async fn una_heuristica_desactivada_no_dispara() {
    let Some(almacen) = almacen_de_pruebas().await else {
        eprintln!("OMITIDA: no hay PostgreSQL");
        return;
    };
    let servicio = Arc::new(ServicioFlota::nuevo(almacen.clone(), 30));
    let categoria = cn_unico("apagada");
    let cuenta = format!("CORP\\off-{}", uuid::Uuid::new_v4().simple());

    let regla = regla_reconocimiento(&categoria, 3).validar().unwrap();
    let id = almacen.crear_heuristica(&regla, "analista").await.unwrap();
    almacen.fijar_heuristica_activa(id, false).await.unwrap();
    sembrar(&servicio, &almacen, &categoria, &cuenta, 5).await;

    let correlador = aegis_server::correlador::Correlador::nuevo(servicio.clone());
    correlador.evaluar_una_vez().await.unwrap();
    assert!(abierta_para(&almacen, &cuenta).await.is_none());

    almacen.fijar_heuristica_activa(id, true).await.unwrap();
    correlador.evaluar_una_vez().await.unwrap();
    assert!(
        abierta_para(&almacen, &cuenta).await.is_some(),
        "reactivar la regla tiene que volver a detectar la campana"
    );
    almacen.fijar_heuristica_activa(id, false).await.unwrap();
}

/// Unos atributos adversos no llegan a la base de datos.
#[tokio::test]
async fn unos_detalles_invalidos_del_endpoint_se_rechazan_antes_de_persistirse() {
    let Some(almacen) = almacen_de_pruebas().await else {
        eprintln!("OMITIDA: no hay PostgreSQL");
        return;
    };
    let servicio = Arc::new(ServicioFlota::nuevo(almacen.clone(), 30));
    let cn = cn_unico("adverso");
    almacen
        .enrolar(&cn, &cn, "adverso", "1.0", &[], "")
        .await
        .unwrap();

    // Son millones de alertas: sin techo, un agente comprometido convierte el
    // historico de seguridad en su almacenamiento gratuito y el disco se llena
    // justo cuando hace falta registrar el incidente.
    let enorme = format!(r#"{{"x":"{}"}}"#, "a".repeat(64 * 1024));
    assert!(servicio
        .evento(&cn, 3, "prueba", "desmesurado", 0, &enorme)
        .await
        .is_err());

    // Un valor anidado no sirve para agrupar y no se acepta.
    assert!(servicio
        .evento(
            &cn,
            3,
            "prueba",
            "anidado",
            0,
            r#"{"cuenta":{"n":"admin"}}"#
        )
        .await
        .is_err());

    // Uno valido si.
    assert!(servicio
        .evento(&cn, 3, "prueba", "correcto", 0, r#"{"cuenta":"admin"}"#)
        .await
        .is_ok());
}
