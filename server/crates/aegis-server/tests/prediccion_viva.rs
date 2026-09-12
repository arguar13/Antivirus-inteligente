//! La contencion preventiva contra **infraestructura real**.
//!
//! Las pruebas del modulo comprueban la logica con un ejecutor anotador. Estas
//! comprueban lo otro: que una propuesta de AegisPredict acaba siendo una orden
//! **encolada de verdad** en PostgreSQL, por el mismo camino que usa la
//! remediacion por deteccion.
//!
//! Por que hace falta, y por que un doble no bastaba: el ejecutor real tiene una
//! clave foranea contra el inventario de agentes. Una propuesta perfectamente
//! razonada sobre un endpoint que nunca se matriculo no falla «un poco», falla
//! con una violacion de integridad referencial — y eso solo se ve contra una base
//! de datos de verdad. Es exactamente el defecto que aparecio en la FASE 64 y que
//! un doble habria escondido otra vez.
//!
//! Si no hay PostgreSQL, estas pruebas se **omiten diciendolo**, nunca pasan en
//! falso.

use aegis_itdr::grafo::Nivel;
use aegis_orchestrator::{AccionRemediacion, EjecutorRemediacion, Objetivo};
use aegis_predict::grafo::{Activo, ClaseActivo, Evidencia, Paso, RelacionSerializable, Via};
use aegis_predict::{ConfigContencion, GrafoAtaque};
use aegis_server::almacen::Almacen;
use aegis_server::prediccion::{contener_preventivamente, ResultadoPreventivo};
use aegis_server::remediacion::EjecutorFlota;

fn url_pg() -> String {
    std::env::var("AEGIS_TEST_PG_URL")
        .unwrap_or_else(|_| "postgres://postgres@%2Fvar%2Frun%2Fpostgresql/aegis_test".to_string())
}

async fn almacen_de_pruebas() -> Option<Almacen> {
    let a = Almacen::conectar(&url_pg(), 8).await.ok()?;
    a.migrar().await.ok()?;
    Some(a)
}

fn cn_unico(prefijo: &str) -> String {
    format!("{prefijo}-{}", uuid::Uuid::new_v4().simple())
}

/// Matricula un endpoint en el inventario. `comandos.cn_agente` tiene clave
/// foranea contra `agentes`, asi que sin esto ninguna orden se puede encolar.
async fn matricular(almacen: &Almacen, cn: &str) {
    sqlx::query(
        "INSERT INTO agentes (cn, id_agente, hostname, version_agente, id_flota) \
         VALUES ($1, 'a', 'h', '1.0', '')",
    )
    .bind(cn)
    .execute(almacen.pool())
    .await
    .expect("matricular el endpoint");
}

/// Las ordenes encoladas para un endpoint, con quien las ordeno.
///
/// El ordenante se trae a proposito: distinguir «se detecto» de «se predijo» es
/// la primera pregunta que hace un analista, y tiene que estar en el dato.
async fn ordenes_encoladas(almacen: &Almacen, cn: &str) -> Vec<(String, String)> {
    sqlx::query_as::<_, (String, String)>(
        "SELECT accion, ordenado_por FROM comandos WHERE cn_agente = $1",
    )
    .bind(cn)
    .fetch_all(almacen.pool())
    .await
    .expect("consultar la cola")
}

/// El grafo clasico: un endpoint raso llega a Administrador de Dominio en dos
/// saltos, por credenciales cacheadas y pertenencia a grupo.
fn grafo(endpoint: &str) -> GrafoAtaque {
    let mut g = GrafoAtaque::nuevo();
    g.agregar(Activo::nuevo(
        endpoint,
        ClaseActivo::Endpoint,
        Nivel::Usuario,
        0,
    ))
    .unwrap();
    g.agregar(Activo::nuevo(
        "svc-backup",
        ClaseActivo::Identidad,
        Nivel::Operador,
        40,
    ))
    .unwrap();
    g.agregar(Activo::nuevo(
        "Domain Admins",
        ClaseActivo::Identidad,
        Nivel::AdminDominio,
        100,
    ))
    .unwrap();
    g.conectar(Paso::nuevo(
        endpoint,
        "svc-backup",
        Via::Identidad(RelacionSerializable::ControlaCredencialesDe),
    ))
    .unwrap();
    g.conectar(Paso::nuevo(
        "svc-backup",
        "Domain Admins",
        Via::Identidad(RelacionSerializable::MiembroDe),
    ))
    .unwrap();
    g
}

/// EL CIRCUITO COMPLETO: se predice un camino, se decide contener, y la orden
/// aparece encolada en PostgreSQL para el endpoint.
#[tokio::test]
async fn una_contencion_preventiva_encola_una_orden_real_en_el_endpoint() {
    let Some(almacen) = almacen_de_pruebas().await else {
        eprintln!("OMITIDA: no hay PostgreSQL en {}", url_pg());
        return;
    };
    let cn = cn_unico("pred");
    matricular(&almacen, &cn).await;

    let ejecutor = EjecutorFlota::en_nombre_de(almacen.clone(), "ai-predict");
    let (informe, resultado) =
        contener_preventivamente(&grafo(&cn), &cn, &ConfigContencion::default(), &ejecutor)
            .await
            .expect("analisis");

    match resultado {
        ResultadoPreventivo::Ejecutada { sujeto, accion, .. } => {
            assert_eq!(sujeto, "svc-backup");
            assert_eq!(accion, AccionRemediacion::RevocarTicketsKerberos);
        }
        otro => panic!("se esperaba una contencion ejecutada: {otro:?}"),
    }

    // Y la orden esta DE VERDAD en la cola del endpoint.
    let encoladas = ordenes_encoladas(&almacen, &cn).await;
    assert_eq!(
        encoladas.len(),
        1,
        "UNA orden, no un playbook: {encoladas:?}"
    );

    // El informe conserva la justificacion completa, que es lo que el analista
    // va a leer para decidir si el motor tenia razon.
    let camino = informe.camino_principal().expect("hay camino");
    assert_eq!(camino.destino, "Domain Admins");
    assert!(camino.explicar().contains("es miembro de"));
}

/// Un endpoint que nunca se matriculo: la propuesta es igual de buena, pero la
/// ejecucion falla y **se dice por que, en una frase**. Sin la comprobacion de
/// inventario, esto seria un error de integridad referencial de PostgreSQL en
/// crudo.
#[tokio::test]
async fn una_contencion_sobre_un_endpoint_no_matriculado_falla_con_un_motivo_legible() {
    let Some(almacen) = almacen_de_pruebas().await else {
        eprintln!("OMITIDA: no hay PostgreSQL en {}", url_pg());
        return;
    };
    let cn = cn_unico("fantasma");
    // A PROPOSITO no se matricula.

    let ejecutor = EjecutorFlota::en_nombre_de(almacen.clone(), "ai-predict");
    let (_, resultado) =
        contener_preventivamente(&grafo(&cn), &cn, &ConfigContencion::default(), &ejecutor)
            .await
            .expect("el analisis si funciona: el grafo no depende del inventario");

    match resultado {
        ResultadoPreventivo::Fallida { motivo, .. } => {
            assert!(
                motivo.contains("inventario"),
                "el motivo tiene que ser legible, no un error de SQL: {motivo}"
            );
        }
        otro => panic!("se esperaba un fallo con motivo: {otro:?}"),
    }
}

/// LA SALVAGUARDA, contra infraestructura real: una evidencia que el atacante
/// acaba de fabricar escala a una persona y **no encola nada**. Es el ataque de
/// la fase, comprobado de extremo a extremo.
#[tokio::test]
async fn una_evidencia_fabricada_no_encola_ninguna_orden() {
    let Some(almacen) = almacen_de_pruebas().await else {
        eprintln!("OMITIDA: no hay PostgreSQL en {}", url_pg());
        return;
    };
    let cn = cn_unico("victima");
    matricular(&almacen, &cn).await;

    let mut g = GrafoAtaque::nuevo();
    g.agregar(Activo::nuevo(&cn, ClaseActivo::Endpoint, Nivel::Usuario, 0))
        .unwrap();
    g.agregar(Activo::nuevo(
        "Domain Admins",
        ClaseActivo::Identidad,
        Nivel::AdminDominio,
        100,
    ))
    .unwrap();
    // El atacante fabrica la arista que llevaria a aislar esta maquina.
    g.conectar(
        Paso::nuevo(
            &cn,
            "Domain Admins",
            Via::Identidad(RelacionSerializable::MiembroDe),
        )
        .con_evidencia(Evidencia::recien_vista()),
    )
    .unwrap();

    let ejecutor = EjecutorFlota::en_nombre_de(almacen.clone(), "ai-predict");
    let cfg = ConfigContencion {
        probabilidad_minima: 0.01,
        ..Default::default()
    };
    let (_, resultado) = contener_preventivamente(&g, &cn, &cfg, &ejecutor)
        .await
        .expect("analisis");

    assert!(
        matches!(resultado, ResultadoPreventivo::Escalada { .. }),
        "una arista fabricada tiene que escalar: {resultado:?}"
    );
    let encoladas = ordenes_encoladas(&almacen, &cn).await;
    assert!(
        encoladas.is_empty(),
        "escalar significa que NO sale ninguna orden: {encoladas:?}"
    );
}

/// La orden preventiva es **la misma** que la de remediacion: mismo verbo, mismo
/// canal, mismo formato. Tres caminos distintos para la misma orden serian tres
/// sitios donde arreglar el mismo fallo.
#[tokio::test]
async fn la_orden_preventiva_usa_el_mismo_verbo_que_la_de_deteccion() {
    let Some(almacen) = almacen_de_pruebas().await else {
        eprintln!("OMITIDA: no hay PostgreSQL en {}", url_pg());
        return;
    };
    let cn = cn_unico("verbo");
    matricular(&almacen, &cn).await;

    // Un camino de RED, que es el unico que se corta aislando.
    let mut g = GrafoAtaque::nuevo();
    g.agregar(Activo::nuevo(&cn, ClaseActivo::Endpoint, Nivel::Usuario, 0))
        .unwrap();
    g.agregar(Activo::nuevo(
        "Domain Admins",
        ClaseActivo::Identidad,
        Nivel::AdminDominio,
        100,
    ))
    .unwrap();
    g.conectar(Paso::nuevo(&cn, "Domain Admins", Via::RedExpuesta))
        .unwrap();

    let ejecutor = EjecutorFlota::en_nombre_de(almacen.clone(), "ai-predict");
    let cfg = ConfigContencion {
        probabilidad_minima: 0.4,
        ..Default::default()
    };
    let (_, resultado) = contener_preventivamente(&g, &cn, &cfg, &ejecutor)
        .await
        .expect("analisis");
    assert!(
        matches!(
            resultado,
            ResultadoPreventivo::Ejecutada {
                accion: AccionRemediacion::AislarRed,
                ..
            }
        ),
        "{resultado:?}"
    );

    let encoladas = ordenes_encoladas(&almacen, &cn).await;
    assert_eq!(encoladas.len(), 1);

    // El mismo verbo que usa el boton de la consola y la remediacion por
    // deteccion: "aislar".
    let esperado = aegis_server::remediacion::orden_de(AccionRemediacion::AislarRed);
    assert!(
        encoladas.iter().any(|(accion, _)| accion == esperado),
        "el verbo de la orden preventiva tiene que ser el mismo: {encoladas:?}"
    );
    // Y el ordenante la marca como PREVENTIVA, no como remediacion.
    assert!(
        encoladas
            .iter()
            .all(|(_, quien)| quien == aegis_server::prediccion::ORDENANTE_PREVENTIVO),
        "una orden nacida de una prediccion tiene que constar como tal: {encoladas:?}"
    );
}

/// Y el ejecutor real satisface el mismo contrato que el doble: si esto dejara de
/// compilar, es que la frontera cambio y hay que mirarla.
#[allow(dead_code)]
fn el_ejecutor_real_es_un_ejecutor_de_remediacion(e: &EjecutorFlota) -> &dyn EjecutorRemediacion {
    e
}

#[allow(dead_code)]
fn un_objetivo_lleva_host_y_sujeto(o: &Objetivo) -> (&str, &str) {
    (&o.host, &o.sujeto)
}
