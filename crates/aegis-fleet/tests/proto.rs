//! Vueltas de ida y vuelta del codec protobuf.
//!
//! El formato de cable tiene que ser el de protobuf de verdad: si un campo se
//! serializa mal, un cliente protobuf real no lo entiende. Se prueba cada
//! mensaje del servicio y los limites del varint.

use aegis_fleet::proto::*;

#[test]
fn varint_ida_y_vuelta_en_los_limites() {
    for v in [0u64, 1, 127, 128, 300, 16384, u32::MAX as u64, u64::MAX] {
        let mut b = Vec::new();
        escribir_varint(&mut b, v);
        let mut lector = Lector::nuevo(&b);
        // Se envuelve en un campo para leerlo con la maquinaria real.
        let mut campo = Vec::new();
        escribir_u64(&mut campo, 1, v);
        if v == 0 {
            assert!(campo.is_empty(), "el cero no se serializa (proto3)");
            continue;
        }
        let mut l = Lector::nuevo(&campo);
        match l.siguiente().unwrap() {
            Some(Campo::Entero(1, leido)) => assert_eq!(leido, v),
            otro => panic!("se esperaba un entero, no {:?}", otro.is_some()),
        }
        let _ = lector.siguiente();
    }
}

#[test]
fn enrolamiento_ida_y_vuelta() {
    let m = SolicitudEnrolamiento {
        id_agente: "agente-007".into(),
        hostname: "endpoint-berlin".into(),
        version_agente: "2.4.1".into(),
        huella_cert: vec![0xde, 0xad, 0xbe, 0xef],
    };
    let bytes = m.codificar();
    assert_eq!(SolicitudEnrolamiento::decodificar(&bytes).unwrap(), m);
}

#[test]
fn respuesta_enrolamiento_ida_y_vuelta() {
    let m = RespuestaEnrolamiento {
        aceptado: true,
        id_flota: "fleet:agente-007".into(),
        intervalo_latido_seg: 30,
        motivo: String::new(),
    };
    assert_eq!(
        RespuestaEnrolamiento::decodificar(&m.codificar()).unwrap(),
        m
    );
}

#[test]
fn latido_ida_y_vuelta() {
    let m = Latido {
        id_agente: "agente-007".into(),
        momento_unix: 1_726_000_000,
        rss_kb: 22_480,
        amenazas_activas: 3,
        version_politica: 42,
    };
    assert_eq!(Latido::decodificar(&m.codificar()).unwrap(), m);
}

#[test]
fn ack_latido_ida_y_vuelta() {
    let m = AckLatido {
        recibido: true,
        version_politica_disponible: 42,
        hay_comando: true,
    };
    assert_eq!(AckLatido::decodificar(&m.codificar()).unwrap(), m);
}

#[test]
fn reporte_evento_ida_y_vuelta() {
    let m = ReporteEvento {
        id_agente: "agente-007".into(),
        severidad: 3,
        categoria: "ransomware".into(),
        descripcion: "cifrado masivo en /home".into(),
        momento_unix: 1_726_000_500,
        detalles_json: String::new(),
    };
    assert_eq!(ReporteEvento::decodificar(&m.codificar()).unwrap(), m);
}

#[test]
fn ack_evento_ida_y_vuelta() {
    let m = AckEvento {
        recibido: true,
        id_incidente: "INC-000042".into(),
    };
    assert_eq!(AckEvento::decodificar(&m.codificar()).unwrap(), m);
}

#[test]
fn una_trama_truncada_no_entra_en_panico() {
    // Decodificar bytes cortados devuelve error, jamas panico.
    let bytes = SolicitudEnrolamiento {
        id_agente: "x".into(),
        hostname: "y".into(),
        ..Default::default()
    }
    .codificar();
    for corte in 0..bytes.len() {
        let _ = SolicitudEnrolamiento::decodificar(&bytes[..corte]);
    }
}

#[test]
fn campos_desconocidos_se_ignoran() {
    // Un campo de un numero que el mensaje no conoce se salta (compatibilidad
    // hacia delante, como protobuf).
    let mut b = Vec::new();
    escribir_str(&mut b, 1, "agente-007");
    escribir_u64(&mut b, 99, 12345); // campo desconocido
    escribir_str(&mut b, 2, "host");
    let m = SolicitudEnrolamiento::decodificar(&b).unwrap();
    assert_eq!(m.id_agente, "agente-007");
    assert_eq!(m.hostname, "host");
}
