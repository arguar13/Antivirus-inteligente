//! Extension del protocolo de flota (FASE 38): inteligencia y empuje.
//!
//! Cubre las tres capacidades nuevas contra un plano de control REAL sobre
//! mTLS: entrega de bundles STIX 2.1, entrega del subgrafo de linaje que rodea
//! a una deteccion, y el canal por el que el servidor EMPUJA politica.

mod common;

use std::time::{Duration, Instant};

use aegis_fleet::proto::{NodoProceso, ReporteGrafo, ReporteStix, MAX_NODOS_GRAFO};
use common::{agente_legitimo, montar_flota};

/// Bundle STIX 2.1 minimo pero valido en forma.
fn bundle_stix() -> String {
    r#"{"type":"bundle","id":"bundle--0f8b1a2c-1111-4c3d-9e2f-aaaaaaaaaaaa","objects":[
        {"type":"indicator","spec_version":"2.1","id":"indicator--1111aaaa-2222-4bbb-8ccc-dddddddddddd",
         "pattern":"[file:hashes.'SHA-256' = 'abcd']","pattern_type":"stix","valid_from":"2026-01-01T00:00:00Z"},
        {"type":"process","id":"process--2222bbbb-3333-4ccc-8ddd-eeeeeeeeeeee","command_line":"sh -c curl"}
    ]}"#
    .to_string()
}

// ---------------------------------------------------------------------------
// Codificacion
// ---------------------------------------------------------------------------

#[test]
fn los_mensajes_nuevos_sobreviven_al_viaje_de_ida_y_vuelta() {
    let stix = ReporteStix {
        id_agente: "endpoint-7".into(),
        bundle_json: bundle_stix(),
        momento_unix: 1_800_000_000,
    };
    assert_eq!(ReporteStix::decodificar(&stix.codificar()).unwrap(), stix);

    let grafo = ReporteGrafo {
        id_agente: "endpoint-7".into(),
        raiz: 42,
        momento_unix: 1_800_000_000,
        nodos: vec![
            NodoProceso {
                clave: 42,
                pid: 1234,
                padre: 7,
                creador: 7,
                profundidad: 2,
                imagen: "/usr/bin/python3".into(),
                cmdline: "python3 -c import socket".into(),
                clase: 3,
                iniciado_ns: 999,
                terminado_ns: 0,
                taints: 0b101,
                puntuacion: 70,
            },
            NodoProceso {
                clave: 7,
                pid: 900,
                padre: 1,
                creador: 1,
                profundidad: 1,
                imagen: "/bin/sh".into(),
                cmdline: "sh".into(),
                clase: 1,
                iniciado_ns: 500,
                terminado_ns: 0,
                taints: 0b1,
                puntuacion: 20,
            },
        ],
    };
    let vuelta = ReporteGrafo::decodificar(&grafo.codificar()).unwrap();
    assert_eq!(vuelta, grafo, "el subgrafo debe llegar entero y en orden");
    assert_eq!(vuelta.nodos.len(), 2);
}

#[test]
fn un_grafo_desmesurado_se_rechaza_en_la_decodificacion() {
    // Un agente comprometido no debe poder convertir un reporte en una carga de
    // escritura arbitraria sobre el plano de control.
    let mut grafo = ReporteGrafo {
        id_agente: "hostil".into(),
        ..Default::default()
    };
    for i in 0..(MAX_NODOS_GRAFO + 10) {
        grafo.nodos.push(NodoProceso {
            clave: i as u64,
            ..Default::default()
        });
    }
    let r = ReporteGrafo::decodificar(&grafo.codificar());
    assert!(r.is_err(), "debe rechazarse por exceder el limite de nodos");
    let msg = format!("{}", r.err().unwrap());
    assert!(
        msg.contains("nodos"),
        "el error debe explicar el motivo: {msg}"
    );
}

// ---------------------------------------------------------------------------
// Ingesta contra un plano de control real sobre mTLS
// ---------------------------------------------------------------------------

#[test]
fn el_agente_entrega_inteligencia_stix_por_el_canal_mtls() {
    let flota = montar_flota();
    let agente = agente_legitimo(&flota, "agente-stix");

    // Enrolarse primero: el plano de control no ingiere de un desconocido.
    let mut s = agente.abrir_sesion().unwrap();
    assert!(
        s.enrolar(&agente.solicitud_enrolamiento().unwrap())
            .unwrap()
            .aceptado
    );

    let mut s2 = agente.abrir_sesion().unwrap();
    let ack = s2
        .reportar_stix(&ReporteStix {
            id_agente: "agente-stix".into(),
            bundle_json: bundle_stix(),
            momento_unix: 1_800_000_000,
        })
        .unwrap();

    assert!(ack.recibido, "el bundle debe ingerirse: {}", ack.motivo);
    assert!(
        ack.objetos_ingeridos >= 2,
        "debe contar los objetos del bundle"
    );
    assert_eq!(flota.plano.num_stix(), 1);
}

#[test]
fn un_cuerpo_que_no_es_stix_se_rechaza_con_motivo() {
    let flota = montar_flota();
    let agente = agente_legitimo(&flota, "agente-basura");
    let mut s = agente.abrir_sesion().unwrap();
    s.enrolar(&agente.solicitud_enrolamiento().unwrap())
        .unwrap();

    let mut s2 = agente.abrir_sesion().unwrap();
    let r = s2.reportar_stix(&ReporteStix {
        id_agente: "agente-basura".into(),
        bundle_json: "esto no es un bundle".into(),
        momento_unix: 0,
    });

    // Aceptar basura contaminaria la inteligencia de la que despues se tiran
    // hilos: el rechazo llega como error con motivo, no como acuse positivo.
    assert!(r.is_err(), "un cuerpo que no es STIX debe rechazarse");
    assert_eq!(flota.plano.num_stix(), 0);
}

#[test]
fn el_agente_entrega_el_linaje_de_procesos_de_una_deteccion() {
    let flota = montar_flota();
    let agente = agente_legitimo(&flota, "agente-grafo");
    let mut s = agente.abrir_sesion().unwrap();
    s.enrolar(&agente.solicitud_enrolamiento().unwrap())
        .unwrap();

    // El linaje que convierte una rutina en un incidente:
    // libreoffice -> sh -> python abriendo un socket.
    let nodos: Vec<NodoProceso> = [
        (100u64, 0u64, "/usr/lib/libreoffice/soffice.bin", 0u32),
        (200, 100, "/bin/sh", 1),
        (300, 200, "/usr/bin/python3", 2),
    ]
    .iter()
    .map(|(clave, padre, imagen, prof)| NodoProceso {
        clave: *clave,
        pid: (*clave / 10) as u32,
        padre: *padre,
        creador: *padre,
        profundidad: *prof,
        imagen: (*imagen).into(),
        cmdline: (*imagen).into(),
        ..Default::default()
    })
    .collect();

    let mut s2 = agente.abrir_sesion().unwrap();
    let ack = s2
        .reportar_grafo(&ReporteGrafo {
            id_agente: "agente-grafo".into(),
            raiz: 300,
            momento_unix: 1_800_000_000,
            nodos,
        })
        .unwrap();

    assert!(ack.recibido);
    assert_eq!(ack.nodos_ingeridos, 3, "los tres del linaje");
    assert!(!ack.id_grafo.is_empty());
    assert_eq!(flota.plano.num_grafos(), 1);
}

// ---------------------------------------------------------------------------
// El empuje: lo que distingue una politica global de un sondeo
// ---------------------------------------------------------------------------

#[test]
fn una_politica_global_llega_al_agente_suscrito_sin_esperar_a_su_latido() {
    let flota = montar_flota();
    let agente = agente_legitimo(&flota, "agente-suscrito");
    let mut s = agente.abrir_sesion().unwrap();
    s.enrolar(&agente.solicitud_enrolamiento().unwrap())
        .unwrap();

    // El agente abre el canal declarando la version que ya tiene.
    let sesion = agente.abrir_sesion().unwrap();
    let mut canal = sesion.suscribir_politica(1).unwrap();

    // El operador publica desde el panel, en otro hilo, un instante despues.
    let plano = flota.plano.clone();
    let publicador = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        plano.publicar_politica_con(2, r#"{"regla":"denegar_puerto","puerto":445}"#);
    });

    let inicio = Instant::now();
    let empuje = canal
        .siguiente()
        .expect("el canal debe entregar la politica");
    let transcurrido = inicio.elapsed();

    publicador.join().unwrap();

    assert!(
        !empuje.es_keepalive,
        "debe ser politica, no latido de canal"
    );
    assert_eq!(empuje.version, 2);
    assert!(
        empuje.politica_json.contains("445"),
        "debe llegar el contenido de la regla: {}",
        empuje.politica_json
    );
    // La prueba de que es EMPUJE y no sondeo: llega en cuanto se publica, no en
    // el siguiente latido del agente (que seria 30 s despues).
    assert!(
        transcurrido < Duration::from_secs(5),
        "la politica tardo {transcurrido:?}; con empuje debe llegar al publicarse"
    );
}

#[test]
fn un_agente_que_reconecta_atrasado_recibe_la_politica_al_instante() {
    let flota = montar_flota();
    let agente = agente_legitimo(&flota, "agente-atrasado");
    let mut s = agente.abrir_sesion().unwrap();
    s.enrolar(&agente.solicitud_enrolamiento().unwrap())
        .unwrap();

    // La politica se publico MIENTRAS el agente estaba desconectado.
    flota
        .plano
        .publicar_politica_con(7, r#"{"regla":"aislar_subred"}"#);

    let sesion = agente.abrir_sesion().unwrap();
    let mut canal = sesion.suscribir_politica(1).unwrap();

    let inicio = Instant::now();
    let empuje = canal.siguiente().unwrap();
    // No debe esperar al siguiente cambio: viene atrasado y se le pone al dia
    // en cuanto abre el canal.
    assert!(inicio.elapsed() < Duration::from_secs(2));
    assert_eq!(empuje.version, 7);
    assert!(!empuje.es_keepalive);
}

#[test]
fn el_canal_no_entrega_politica_que_el_agente_ya_tiene() {
    let flota = montar_flota();
    let agente = agente_legitimo(&flota, "agente-al-dia");
    let mut s = agente.abrir_sesion().unwrap();
    s.enrolar(&agente.solicitud_enrolamiento().unwrap())
        .unwrap();

    flota.plano.publicar_politica_con(5, r#"{"regla":"x"}"#);

    // El agente declara que ya esta en la version 5: no debe recibir un empuje
    // de contenido, solo latidos de canal. Reenviar politica que el endpoint ya
    // aplico es trabajo inutil multiplicado por el tamano de la flota.
    let sesion = agente.abrir_sesion().unwrap();
    let mut canal = sesion.suscribir_politica(5).unwrap();

    let plano = flota.plano.clone();
    let publicador = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        plano.publicar_politica_con(6, r#"{"regla":"y"}"#);
    });

    let empuje = canal.siguiente().unwrap();
    publicador.join().unwrap();

    assert_eq!(empuje.version, 6, "solo lo que el agente aun no tiene");
    assert!(!empuje.es_keepalive);
}
