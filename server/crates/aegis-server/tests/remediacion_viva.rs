//! Integracion viva del orquestador de remediacion contra infraestructura REAL.
//!
//! Aqui no hay dobles. Estas pruebas ejercen las dos FRONTERAS que el modulo
//! `remediacion` declara como muro en sus pruebas unitarias:
//!
//! 1. **El cerrojo distribuido**, que es un indice unico parcial de PostgreSQL.
//!    La propiedad que importa —dos instancias del plano de control procesando
//!    lotes del MISMO ataque a la vez no pueden abrir dos remediaciones— no se
//!    puede afirmar sin una base de datos de verdad: es la base de datos la que
//!    la garantiza.
//! 2. **El ejecutor de flota**, que encola comandos reales y marca el
//!    aislamiento en el inventario.
//!
//! Se omiten con honestidad —sin fingir exito— si la maquina no tiene
//! PostgreSQL. Ver `tools/verificar-orchestrator.sh`, que lo DECLARA en la
//! puerta de calidad en vez de dejarlo en un comentario.

use std::sync::Arc;

use aegis_itdr::kerberos::{EventoKdc, TipoCifrado};
use aegis_itdr::{ClaseAmenaza, Deteccion, Severidad};
use aegis_orchestrator::{AccionRemediacion, EstadoPlaybook, Objetivo};
use aegis_orchestrator::{EjecutorRemediacion, Orquestador};
mod comun;
use aegis_server::dominio::ServicioFlota;
use aegis_server::itdr::TelemetriaIdentidad;
use aegis_server::remediacion::{
    clave_accion, EjecutorFlota, MotorVivo, RegistroPostgres, RegistroRemediacion,
};
use comun::almacen_real;
use sqlx::Row;

const T0: u64 = 1_800_000_000;
const HORA: u64 = 3_600;

fn cn_unico(prefijo: &str) -> String {
    format!("{prefijo}-{}", uuid::Uuid::new_v4().simple())
}

fn deteccion_golden(sujeto: &str) -> Deteccion {
    Deteccion {
        clase: ClaseAmenaza::GoldenTicket,
        severidad: Severidad::Critica,
        sujeto: sujeto.to_string(),
        evidencia: "TGS sin TGT previo durante 12 h".to_string(),
    }
}

/// Telemetria que el detector de Golden Ticket reconoce de verdad: la misma
/// cuenta pide el mismo servicio durante doce horas sin que la KDC emitiera
/// jamas un TGT para ella.
fn telemetria_golden(cuenta: &str) -> TelemetriaIdentidad {
    let mut tel = TelemetriaIdentidad::default();
    for i in 0..12 {
        tel.eventos_kdc.push(EventoKdc::solicitud_servicio(
            cuenta,
            "CIFS/dc.corp.local",
            TipoCifrado::Rc4Hmac,
            T0 + i * HORA,
        ));
    }
    tel
}

// ---------------------------------------------------------------------------
// El cerrojo distribuido
// ---------------------------------------------------------------------------

/// LA PROPIEDAD QUE DEFINE LA INTEGRACION. Dos instancias del plano de control
/// tras un balanceador reciben lotes del mismo ataque a la vez. Ninguna ve la
/// memoria de la otra; lo unico que comparten es PostgreSQL. Si el cerrojo no
/// fuera atomico ahi, el endpoint recibiria el playbook DOS veces.
#[tokio::test]
async fn dos_instancias_a_la_vez_solo_abren_una_remediacion() {
    let Some(almacen) = almacen_real(8).await else {
        return;
    };
    let cn = cn_unico("cerrojo");
    let sujeto = cn_unico("krbtgt");
    let det = deteccion_golden(&sujeto);

    // Dos registros distintos, como dos procesos distintos del plano de control.
    let inst_a = RegistroPostgres::nuevo(almacen.clone());
    let inst_b = RegistroPostgres::nuevo(almacen.clone());

    let (a, b) = tokio::join!(
        inst_a.intentar_abrir(&det, &cn),
        inst_b.intentar_abrir(&det, &cn)
    );
    let a = a.expect("instancia A");
    let b = b.expect("instancia B");

    assert_eq!(
        a.is_some() as u8 + b.is_some() as u8,
        1,
        "exactamente una de las dos instancias tiene que ganar el cerrojo (A={a:?}, B={b:?})"
    );

    // Y una tercera pasada, ya sin concurrencia, tampoco abre: sigue en curso.
    assert!(
        inst_a
            .intentar_abrir(&det, &cn)
            .await
            .expect("tercer intento")
            .is_none(),
        "con una remediacion en curso no se puede abrir otra"
    );
}

/// El enfriamiento mira filas YA CERRADAS, que son invisibles para el indice
/// unico parcial. Por eso hacen falta los dos mecanismos: sin el `WHERE NOT
/// EXISTS`, en cuanto una remediacion se cierra el siguiente lote abriria otra,
/// y el atacante marcaria la cadencia de la respuesta automatica con el ritmo al
/// que genera eventos.
#[tokio::test]
async fn tras_concluir_el_enfriamiento_impide_relanzar_y_luego_deja() {
    let Some(almacen) = almacen_real(8).await else {
        return;
    };
    let cn = cn_unico("enfriamiento");
    let sujeto = cn_unico("krbtgt");
    let det = deteccion_golden(&sujeto);

    // Enfriamiento largo: se abre, se cierra, y NO se puede reabrir.
    let frio = RegistroPostgres::con_enfriamiento(almacen.clone(), 3_600);
    let id = frio
        .intentar_abrir(&det, &cn)
        .await
        .expect("apertura")
        .expect("la primera abre");
    let informe = aegis_orchestrator::InformeRemediacion {
        clase: ClaseAmenaza::GoldenTicket,
        objetivo: Objetivo {
            host: cn.clone(),
            sujeto: sujeto.clone(),
        },
        resultados: vec![
            aegis_orchestrator::ResultadoAccion {
                accion: AccionRemediacion::AislarRed,
                estado: aegis_orchestrator::EstadoAccion::Exito,
            },
            aegis_orchestrator::ResultadoAccion {
                accion: AccionRemediacion::VolcadoForenseMemoria,
                estado: aegis_orchestrator::EstadoAccion::Fallo("sin espacio".into()),
            },
        ],
        estado: EstadoPlaybook::CompletadoConFallos,
    };
    frio.concluir(id, &informe).await.expect("cierre");

    assert!(
        frio.intentar_abrir(&det, &cn)
            .await
            .expect("reapertura en frio")
            .is_none(),
        "dentro del enfriamiento no se relanza"
    );

    // Sin enfriamiento, el mismo ataque visto otra vez SI vuelve a remediarse:
    // un ataque que sigue vivo tiene que volver a responderse.
    let caliente = RegistroPostgres::con_enfriamiento(almacen.clone(), 0);
    assert!(
        caliente
            .intentar_abrir(&det, &cn)
            .await
            .expect("reapertura sin enfriamiento")
            .is_some(),
        "pasado el enfriamiento, un ataque vivo se vuelve a remediar"
    );

    // El informe quedo registrado con el detalle por accion: es lo que permite
    // un reintento idempotente despues de un reinicio del plano de control.
    let vistas = almacen
        .listar_remediaciones(200)
        .await
        .expect("listado de remediaciones");
    let mia = vistas
        .iter()
        .find(|v| v.id == id)
        .expect("la remediacion cerrada tiene que aparecer en el listado");
    assert_eq!(mia.estado, "completado_con_fallos");
    assert_eq!(mia.acciones.len(), 2);
    let volcado = mia
        .acciones
        .iter()
        .find(|a| a.accion == clave_accion(AccionRemediacion::VolcadoForenseMemoria))
        .expect("el volcado tiene que estar registrado");
    assert!(!volcado.exito);
    assert_eq!(volcado.motivo, "sin espacio");
}

// ---------------------------------------------------------------------------
// El ejecutor real contra la flota
// ---------------------------------------------------------------------------

/// El ejecutor de produccion no "simula" aislar: marca el inventario y encola el
/// comando que el agente recogera en su proximo latido, que es EXACTAMENTE el
/// mismo mecanismo que usa el boton de la consola.
#[tokio::test]
async fn el_ejecutor_real_marca_el_aislamiento_y_encola_la_orden() {
    let Some(almacen) = almacen_real(8).await else {
        return;
    };
    let servicio = ServicioFlota::nuevo(almacen.clone(), 30);
    let cn = cn_unico("ejecutor");
    servicio
        .enrolar(&cn, "id-1", "dc01", "1.0.0", b"huella")
        .await
        .expect("enrolamiento");

    let ejecutor = EjecutorFlota::nuevo(almacen.clone());
    let objetivo = Objetivo {
        host: cn.clone(),
        sujeto: "administrator".to_string(),
    };
    ejecutor
        .ejecutar(AccionRemediacion::AislarRed, &objetivo)
        .await
        .expect("aislar");

    // 1. El inventario dice que esta aislado.
    let vista = almacen.obtener_agente(&cn, 300).await.expect("agente");
    assert!(
        vista.aislado,
        "el endpoint tiene que quedar marcado aislado"
    );

    // 2. Hay un comando pendiente, y es el MISMO que ordena la consola.
    let comando = almacen
        .tomar_comando_pendiente(&cn)
        .await
        .expect("consulta de comando")
        .expect("tiene que haber un comando encolado");
    assert_eq!(comando.accion, "aislar");
    assert_eq!(
        comando.parametros.get("sujeto").and_then(|v| v.as_str()),
        Some("administrator"),
        "la identidad implicada tiene que viajar con la orden"
    );
}

/// Un endpoint que NO esta en el inventario no tiene canal por el que recibir
/// ordenes: `comandos.cn_agente` tiene clave foranea contra `agentes`. Las
/// CUATRO acciones fallan, y lo que esta prueba fija es que fallan con UN motivo
/// legible y no con cuatro violaciones de integridad referencial en crudo.
///
/// Esta prueba encontro un defecto real: la version inicial del ejecutor solo
/// comprobaba el inventario en la rama del aislamiento, asi que el informe que
/// leia el analista llevaba tres errores de PostgreSQL sin traducir.
#[tokio::test]
async fn un_endpoint_desconocido_falla_limpio_sin_abortar_el_playbook() {
    let Some(almacen) = almacen_real(8).await else {
        return;
    };
    let ejecutor = EjecutorFlota::nuevo(almacen.clone());
    let objetivo = Objetivo {
        host: cn_unico("fantasma"),
        sujeto: "administrator".to_string(),
    };
    let err = ejecutor
        .ejecutar(AccionRemediacion::AislarRed, &objetivo)
        .await
        .expect_err("un endpoint que no existe no se puede aislar");
    assert!(err.contains("inventario"), "motivo poco util: {err}");

    // El playbook completo sobre ese mismo endpoint inexistente: el aislamiento
    // falla, pero las demas acciones se intentan igualmente.
    let informe = Orquestador::nuevo()
        .remediar(
            &aegis_orchestrator::Disparador {
                clase: ClaseAmenaza::GoldenTicket,
                severidad: Severidad::Critica,
                sujeto: objetivo.sujeto.clone(),
            },
            &objetivo.host,
            &ejecutor,
        )
        .await;
    assert_eq!(informe.estado, EstadoPlaybook::CompletadoConFallos);
    assert_eq!(informe.resultados.len(), 4, "las cuatro se intentaron");
    assert_eq!(
        informe.acciones_fallidas().len(),
        4,
        "sin canal al endpoint no se puede entregar ninguna orden"
    );
    // Y el motivo es UNO y se entiende, en las cuatro. Sin la comprobacion de
    // inventario, tres de estas cadenas serian un error de SQL en bruto.
    for resultado in &informe.resultados {
        match &resultado.estado {
            aegis_orchestrator::EstadoAccion::Fallo(motivo) => assert!(
                motivo.contains("no esta en el inventario"),
                "motivo poco util en {}: {motivo}",
                clave_accion(resultado.accion)
            ),
            otro => panic!("se esperaba fallo en {:?}, no {otro:?}", resultado.accion),
        }
    }
}

// ---------------------------------------------------------------------------
// El circuito entero
// ---------------------------------------------------------------------------

/// De extremo a extremo con TODO real: telemetria de identidad -> deteccion del
/// motor ITDR -> playbook del orquestador -> comandos encolados al endpoint ->
/// alerta persistida -> registro de la remediacion. Sin un solo doble.
#[tokio::test]
async fn el_circuito_completo_de_identidad_a_flota_con_infraestructura_real() {
    let Some(almacen) = almacen_real(8).await else {
        return;
    };
    let servicio = Arc::new(ServicioFlota::nuevo(almacen.clone(), 30));
    let cn = cn_unico("circuito");
    servicio
        .enrolar(&cn, "id-1", "dc01", "1.0.0", b"huella")
        .await
        .expect("enrolamiento");

    let cuenta = cn_unico("administrator");
    let motor = MotorVivo::de_produccion(servicio.clone(), almacen.clone());

    // Una consola conectada: el analista tiene que ver la respuesta ocurrir.
    let mut consola = servicio.bus().suscribir();

    let ciclo = motor
        .analizar_y_remediar(&cn, &telemetria_golden(&cuenta))
        .await
        .expect("analisis");

    assert!(
        ciclo.incidencias.is_empty(),
        "con infraestructura real no debe haber incidencias: {:?}",
        ciclo.incidencias
    );
    assert_eq!(
        ciclo.remediaciones.len(),
        1,
        "un Golden Ticket, un playbook"
    );
    let (id, informe) = &ciclo.remediaciones[0];
    assert_eq!(
        informe.estado,
        EstadoPlaybook::Completado,
        "todas las acciones tenian que conseguirse: {informe:?}"
    );

    // 1. La alerta se persistio, clasificada en MITRE ATT&CK.
    let alertas = almacen
        .listar_alertas_de_agente(&cn, 10)
        .await
        .expect("alertas");
    let alerta = alertas.first().expect("la deteccion tiene que estar");
    assert_eq!(alerta.categoria, "Golden Ticket");
    assert_eq!(
        alerta.tecnica_mitre.as_deref(),
        Some("T1558.001"),
        "la alerta persistida tiene que llevar la misma tecnica que el bus"
    );

    // 2. Las CUATRO ordenes del playbook estan encoladas para el endpoint.
    let pendientes: i64 = sqlx::query("SELECT count(*) AS n FROM comandos WHERE cn_agente = $1")
        .bind(&cn)
        .fetch_one(almacen.pool())
        .await
        .expect("recuento de comandos")
        .get("n");
    assert_eq!(pendientes, 4, "el playbook de Golden Ticket son 4 acciones");

    // 3. El endpoint quedo aislado en el inventario.
    assert!(almacen.obtener_agente(&cn, 300).await.unwrap().aislado);

    // 4. El registro duradero refleja la remediacion con su detalle.
    let vistas = almacen.listar_remediaciones(200).await.expect("listado");
    let mia = vistas.iter().find(|v| v.id == *id).expect("la remediacion");
    assert_eq!(mia.estado, "completado");
    assert_eq!(mia.cn_agente, cn);
    assert_eq!(mia.acciones.len(), 4);
    assert!(mia.acciones.iter().all(|a| a.exito));

    // 5. La consola vio lanzarse y concluir la respuesta, en ese orden.
    let mut vio_lanzada = false;
    let mut vio_concluida = false;
    while let Ok(ev) = consola.try_recv() {
        match ev {
            aegis_server::eventos::EventoPanel::RemediacionLanzada { cn: c, .. } if c == cn => {
                vio_lanzada = true;
            }
            aegis_server::eventos::EventoPanel::RemediacionConcluida {
                cn: c,
                estado,
                fallos,
                ..
            } if c == cn => {
                assert!(
                    vio_lanzada,
                    "'concluida' no puede llegar antes de 'lanzada'"
                );
                assert_eq!(estado, "completado");
                assert_eq!(fallos, 0);
                vio_concluida = true;
            }
            _ => {}
        }
    }
    assert!(
        vio_lanzada && vio_concluida,
        "la consola no vio la respuesta"
    );

    // 6. Y el MISMO ataque visto otra vez no relanza nada: el cerrojo lo impide.
    let repetido = motor
        .analizar_y_remediar(&cn, &telemetria_golden(&cuenta))
        .await
        .expect("segundo lote");
    assert!(repetido.remediaciones.is_empty());
    assert_eq!(repetido.omitidas_por_cerrojo, 1);
    let tras_repetir: i64 = sqlx::query("SELECT count(*) AS n FROM comandos WHERE cn_agente = $1")
        .bind(&cn)
        .fetch_one(almacen.pool())
        .await
        .expect("recuento")
        .get("n");
    assert_eq!(tras_repetir, 4, "el playbook NO se relanzo");
}
