//! Inquilino hostil: un cliente no lee ni escribe los datos de otro por NINGUNA
//! ruta de la API ni por AegisQL (H-03, E6.10 de la FASE 6.2 del MP-16).
//!
//! Montaje, contra PostgreSQL y Redis reales:
//!
//! - dos inquilinos, A y B, cada uno con su agente enrolado por el camino de
//!   produccion (`ServicioFlota::enrolar`, que deriva el inquilino del CN);
//! - B tiene una alerta, un caso y una caza, todos con una MARCA unica;
//! - un responsable de A (lee, trabaja casos, caza y contiene) recorre TODAS
//!   las rutas declaradas con los identificadores de B y con cuerpos validos.
//!
//! Se exige:
//!
//! 1. Ninguna respuesta contiene una marca de B.
//! 2. Las rutas de un recurso de B responden 404 (como si no existiera) y las
//!    de plataforma 403.
//! 3. Despues del barrido, en la BASE DE DATOS: el agente de B no esta aislado
//!    ni tiene comandos, su caso no cambio ni gano tareas y su caza sigue
//!    abierta.
//! 4. Los listados de A no traen nada de B, ni pidiendolo con `?inquilino=`.
//! 5. AegisQL: la caza de A solo se entrega a los agentes de A, y una
//!    respuesta que un agente de B cuele en la caza de A no aparece en ella.

mod comun;

use aegis_server::api;
use aegis_server::autorizacion::{self, regla_de, Alcance, Rol};
use aegis_server::eventos::EventoPanel;
use axum::http::StatusCode;

/// Cuerpo valido para cada ruta de escritura: si la autorizacion fallara, el
/// manejador ACTUARIA, y el barrido lo veria en la base de datos.
fn cuerpo_para(metodo: &str, patron: &str, marca: &str) -> Option<serde_json::Value> {
    if metodo != "POST" {
        return None;
    }
    let v = match patron {
        "/api/casos/{id}/estado" => serde_json::json!({ "estado": "en-curso" }),
        "/api/casos/{id}/cerrar" => {
            serde_json::json!({ "veredicto": "verdadero", "justificacion": marca })
        }
        "/api/casos/{id}/tareas" => serde_json::json!({ "titulo": marca }),
        "/api/casos/{id}/tareas/{tarea}/cerrar" => serde_json::json!({ "motivo": marca }),
        "/api/cacerias" => serde_json::json!({
            "consulta": format!("SELECT pid FROM processes WHERE name = '{marca}'")
        }),
        "/api/agentes/{cn}/cuarentena" | "/api/cuarentena" => {
            serde_json::json!({ "direccion": "10.66.66.66", "motivo": marca })
        }
        "/api/correlaciones/{id}/cerrar" => serde_json::json!({ "veredicto": "falso-positivo" }),
        "/api/reglas/{id}/activa" | "/api/heuristicas/{id}/activa" => {
            serde_json::json!({ "activa": false })
        }
        _ => serde_json::json!({}),
    };
    Some(v)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn un_inquilino_no_lee_ni_escribe_los_datos_de_otro_por_ninguna_ruta() {
    let Some((estado, almacen, servicio)) = comun::estado_real().await else {
        return;
    };
    let pool = almacen.pool().clone();
    let u = comun::unico();
    let (dom_a, dom_b) = (format!("ha{u}"), format!("hb{u}"));
    let (inq_a, inq_b) = (format!("flota-{dom_a}"), format!("flota-{dom_b}"));
    let (cn_a, cn_b) = (format!("pc-a.{dom_a}"), format!("pc-b.{dom_b}"));
    let marca_a = format!("MARCAA{u}");
    let marca_b = format!("MARCAB{u}");

    // --- Montaje ----------------------------------------------------------
    for cn in [&cn_a, &cn_b] {
        let inq = servicio
            .enrolar(cn, cn, "anfitrion", "1.0.0", &[1, 2, 3])
            .await
            .expect("enrolar");
        assert_eq!(inq, autorizacion::inquilino_de_cn(cn));
    }
    for (cn, marca) in [(&cn_a, &marca_a), (&cn_b, &marca_b)] {
        servicio
            .evento(cn, 3, "ransomware", marca, 0, "{}")
            .await
            .expect("alerta");
    }
    let caso_b = format!("caso-{u}-b");
    let caso_a = format!("caso-{u}-a");
    for (id, inq, marca) in [(&caso_b, &inq_b, &marca_b), (&caso_a, &inq_a, &marca_a)] {
        sqlx::query(
            "INSERT INTO casos (id, inquilino, titulo, severidad, abierto_en)
             VALUES ($1, $2, $3, 'alta', now())",
        )
        .bind(id)
        .bind(inq)
        .bind(marca)
        .execute(&pool)
        .await
        .expect("caso");
    }

    let app = comun::app(estado);
    let resp_b = comun::operador(&almacen, Rol::Responsable, &inq_b).await;
    let token_b = comun::entrar(&app, &resp_b).await;
    let (c, cuerpo) = comun::pedir(
        &app,
        "POST",
        "/api/cacerias",
        Some(&token_b),
        cuerpo_para("POST", "/api/cacerias", &marca_b),
    )
    .await;
    assert_eq!(c, StatusCode::ACCEPTED, "B lanza su caza: {cuerpo}");
    let caza_b = serde_json::from_str::<serde_json::Value>(&cuerpo).unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let resp_a = comun::operador(&almacen, Rol::Responsable, &inq_a).await;
    let token_a = comun::entrar(&app, &resp_a).await;
    let marcas_b = [
        cn_b.as_str(),
        marca_b.as_str(),
        caso_b.as_str(),
        caza_b.as_str(),
    ];

    // --- 1 y 2: el barrido de A con los identificadores de B --------------
    let mut barridas = 0usize;
    for r in api::rutas_declaradas() {
        let regla = regla_de(r.metodo, r.patron).expect("clasificada");
        if matches!(regla.alcance, Alcance::Publica | Alcance::Sesion) {
            continue;
        }
        let id = if r.patron.starts_with("/api/casos/") {
            caso_b.as_str()
        } else if r.patron.starts_with("/api/cacerias/") {
            caza_b.as_str()
        } else {
            "00000000-0000-0000-0000-000000000000"
        };
        let uri = comun::concretar(r.patron, &cn_b, id);
        let (codigo, cuerpo) = comun::pedir(
            &app,
            r.metodo,
            &uri,
            Some(&token_a),
            cuerpo_para(r.metodo, r.patron, &marca_a),
        )
        .await;
        for m in marcas_b {
            assert!(
                !cuerpo.contains(m),
                "FUGA: {} {uri} devolvio «{m}» de B a una sesion de A: {cuerpo}",
                r.metodo
            );
        }
        match regla.alcance {
            Alcance::Agente | Alcance::Caso | Alcance::Caza => assert_eq!(
                codigo,
                StatusCode::NOT_FOUND,
                "{} {uri}: un recurso de B se ve como inexistente",
                r.metodo
            ),
            Alcance::Plataforma => assert_eq!(
                codigo,
                StatusCode::FORBIDDEN,
                "{} {uri}: contenido de plataforma",
                r.metodo
            ),
            _ => {}
        }
        barridas += 1;
    }
    println!("AEGIS-MEDIDA inquilino_hostil rutas_barridas={barridas}");

    // --- 3: nada de B cambio ------------------------------------------------
    let aislado: bool = sqlx::query_scalar("SELECT aislado FROM agentes WHERE cn = $1")
        .bind(&cn_b)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!aislado, "A aislo el agente de B");
    let comandos: i64 = sqlx::query_scalar("SELECT count(*) FROM comandos WHERE cn_agente = $1")
        .bind(&cn_b)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(comandos, 0, "A encolo comandos en el agente de B");
    let (estado_caso, tareas): (String, i64) = sqlx::query_as(
        "SELECT c.estado, (SELECT count(*) FROM caso_tareas t WHERE t.caso = c.id)
           FROM casos c WHERE c.id = $1",
    )
    .bind(&caso_b)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(estado_caso, "nuevo", "A cambio el caso de B");
    assert_eq!(tareas, 0, "A anadio tareas al caso de B");
    let caza_b_uuid = uuid::Uuid::parse_str(&caza_b).unwrap();
    let cerrada: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT cerrada_en FROM cacerias WHERE id = $1")
            .bind(caza_b_uuid)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(cerrada.is_none(), "A cerro la caza de B");

    // --- 4: los listados de A, con y sin ?inquilino= -----------------------
    for uri in [
        "/api/agentes".to_string(),
        "/api/alertas".to_string(),
        "/api/resumen".to_string(),
        "/api/casos".to_string(),
        format!("/api/casos?inquilino={inq_b}"),
        format!("/api/soc/metricas?inquilino={inq_b}"),
        "/api/cacerias".to_string(),
    ] {
        let (c, cuerpo) = comun::pedir(&app, "GET", &uri, Some(&token_a), None).await;
        assert_eq!(c, StatusCode::OK, "{uri}: {cuerpo}");
        for m in marcas_b {
            assert!(!cuerpo.contains(m), "FUGA en {uri}: «{m}»");
        }
    }
    let (_, cuerpo) = comun::pedir(&app, "GET", "/api/agentes", Some(&token_a), None).await;
    assert!(cuerpo.contains(&cn_a), "A ve su propio agente");
    let (_, cuerpo) = comun::pedir(&app, "GET", "/api/alertas", Some(&token_a), None).await;
    assert!(cuerpo.contains(&marca_a), "A ve su propia alerta");
    let (_, cuerpo) = comun::pedir(&app, "GET", "/api/resumen", Some(&token_a), None).await;
    let resumen: serde_json::Value = serde_json::from_str(&cuerpo).unwrap();
    assert_eq!(
        resumen["agentes_total"], 1,
        "el resumen de A cuenta solo a A"
    );

    // --- 5: AegisQL ---------------------------------------------------------
    let (c, cuerpo) = comun::pedir(
        &app,
        "POST",
        "/api/cacerias",
        Some(&token_a),
        cuerpo_para("POST", "/api/cacerias", &marca_a),
    )
    .await;
    assert_eq!(c, StatusCode::ACCEPTED, "A lanza su caza: {cuerpo}");
    let caza_a = uuid::Uuid::parse_str(
        serde_json::from_str::<serde_json::Value>(&cuerpo).unwrap()["id"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    // El mismo camino que usa el transporte de flota para entregar cazas.
    let para_b = almacen.caza_pendiente_para(&cn_b).await.unwrap();
    assert!(
        para_b
            .as_ref()
            .is_none_or(|(id, q)| *id != caza_a && !q.contains(&marca_a)),
        "la caza de A se entrego a un agente de B: {para_b:?}"
    );
    let para_a = almacen.caza_pendiente_para(&cn_a).await.unwrap();
    assert_eq!(
        para_a.map(|(id, _)| id),
        Some(caza_a),
        "la caza de A llega a A"
    );

    // Un agente de B cuela una respuesta en la caza de A.
    almacen
        .guardar_respuesta_caza(
            caza_a,
            &cn_b,
            &serde_json::json!([{ "name": marca_b }]),
            1,
            1,
            0,
            false,
            false,
            1,
            "",
        )
        .await
        .unwrap();
    let (c, cuerpo) = comun::pedir(
        &app,
        "GET",
        &format!("/api/cacerias/{caza_a}"),
        Some(&token_a),
        None,
    )
    .await;
    assert_eq!(c, StatusCode::OK, "{cuerpo}");
    for m in marcas_b {
        assert!(
            !cuerpo.contains(m),
            "una respuesta de B entro en la caza de A: «{m}»"
        );
    }
    let v: serde_json::Value = serde_json::from_str(&cuerpo).unwrap();
    assert_eq!(
        v["resumen"]["respondieron"], 0,
        "la respuesta de B no cuenta"
    );

    // --- El tiempo real: el filtro que aplica la API a cada evento ---------
    let sesion_a = autorizacion::SesionOperador {
        usuario: resp_a.clone(),
        rol: Rol::Responsable,
        inquilino: inq_a.clone(),
    };
    let de_b = EventoPanel::AislamientoCambiado {
        cn: cn_b.clone(),
        aislado: true,
        por: "x".into(),
    };
    let de_a = EventoPanel::AislamientoCambiado {
        cn: cn_a.clone(),
        aislado: true,
        por: "x".into(),
    };
    assert!(!autorizacion::evento_visible(&sesion_a, &de_b));
    assert!(autorizacion::evento_visible(&sesion_a, &de_a));
}
