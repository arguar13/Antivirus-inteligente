//! Protocolos sobre UDP con formato fijo: DHCP, NTP y el inicio de QUIC.
//!
//! # Por que van juntos
//!
//! Los tres son datagramas sueltos con cabecera de posicion fija, sin flujo que
//! reensamblar ni estado que arrastrar. Comparten la misma forma de tratarse: un
//! datagrama entra, uno o ningun hecho sale. Separarlos en tres modulos de
//! cuarenta lineas no aportaria nada.
//!
//! # Que aporta cada uno al veredicto
//!
//! - **DHCP** da el nombre de equipo que una maquina **se pone a si misma** y su
//!   direccion fisica. Es la unica fuente que ata una MAC a un nombre sin
//!   depender de que el endpoint lo cuente, y por eso sirve para detectar
//!   maquinas que aparecen en la red sin estar en el inventario.
//! - **NTP** importa por el reves: un servidor NTP que no es el de la
//!   organizacion, o un estrato absurdo, es una via clasica de desplazar el
//!   reloj de una maquina — y desplazar el reloj rompe la validacion de
//!   certificados y los tickets Kerberos.
//! - **QUIC** lleva el SNI en su primer paquete y despues todo va cifrado. Si no
//!   se coge ahi, no se coge: el trafico HTTP/3 seria opaco por completo.

use crate::error::Resultado;
use crate::hecho::{Hecho, ProtocoloApp};
use crate::lector::Lector;

// ---------------------------------------------------------------------------
// DHCP
// ---------------------------------------------------------------------------

/// Marca magica de las opciones DHCP.
pub const MAGIA_DHCP: u32 = 0x6382_5363;

/// Longitud minima de un mensaje DHCP antes de las opciones.
pub const DHCP_FIJO: usize = 236;

/// Tope de opciones que se recorren.
pub const MAX_OPCIONES: usize = 128;

/// Nombre de un tipo de mensaje DHCP.
#[must_use]
pub fn nombre_tipo_dhcp(t: u8) -> &'static str {
    match t {
        1 => "DISCOVER",
        2 => "OFFER",
        3 => "REQUEST",
        4 => "DECLINE",
        5 => "ACK",
        6 => "NAK",
        7 => "RELEASE",
        8 => "INFORM",
        _ => "OTRO",
    }
}

/// Analiza un mensaje DHCP.
#[must_use]
pub fn analizar_dhcp(datos: &[u8]) -> Vec<Hecho> {
    match intentar_dhcp(datos) {
        Ok(h) => h,
        Err(e) => {
            // Solo se reporta como no analizable si de verdad PARECIA DHCP: si
            // no, es simplemente otro protocolo y decir «no pude analizar DHCP»
            // por cada datagrama UDP del mundo seria ruido puro.
            if parece_dhcp(datos) {
                vec![Hecho::no_analizable(ProtocoloApp::Dhcp, &e)]
            } else {
                Vec::new()
            }
        }
    }
}

fn intentar_dhcp(datos: &[u8]) -> Resultado<Vec<Hecho>> {
    let mut l = Lector::nuevo(datos);
    let op = l.u8("dhcp.op")?;
    if op != 1 && op != 2 {
        return Err(crate::error::ErrorDiseccion::NoEsEsteProtocolo("dhcp"));
    }
    l.saltar(27, "dhcp.cabecera")?; // htype..yiaddr y siguientes
    l.saltar(16 - 12, "dhcp.direcciones")?;
    l.ir_a(28, "dhcp.chaddr")?;
    let chaddr = l.tomar(16, "dhcp.chaddr")?;
    let mac = chaddr[..6]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");

    l.ir_a(DHCP_FIJO, "dhcp.magia")?;
    if l.u32("dhcp.magia")? != MAGIA_DHCP {
        return Err(crate::error::ErrorDiseccion::NoEsEsteProtocolo("dhcp"));
    }

    let mut tipo = 0u8;
    let mut nombre = String::new();
    let mut opciones = 0usize;
    while !l.vacio() && opciones < MAX_OPCIONES {
        opciones += 1;
        let codigo = l.u8("dhcp.opcion")?;
        if codigo == 255 {
            break;
        }
        if codigo == 0 {
            continue; // relleno
        }
        let valor = l.bloque_u8("dhcp.opcion.valor")?;
        match codigo {
            53 => tipo = valor.first().copied().unwrap_or(0),
            12 => nombre = crate::lector::ascii_legible(valor),
            _ => {}
        }
    }

    Ok(vec![
        Hecho::ProtocoloIdentificado(ProtocoloApp::Dhcp),
        Hecho::DhcpVisto {
            tipo: nombre_tipo_dhcp(tipo).to_string(),
            mac,
            nombre,
        },
    ])
}

/// Si unos bytes parecen DHCP.
#[must_use]
pub fn parece_dhcp(datos: &[u8]) -> bool {
    datos.len() > DHCP_FIJO + 4
        && (datos[0] == 1 || datos[0] == 2)
        && datos.get(DHCP_FIJO..DHCP_FIJO + 4) == Some(&MAGIA_DHCP.to_be_bytes()[..])
}

// ---------------------------------------------------------------------------
// NTP
// ---------------------------------------------------------------------------

/// Longitud de un paquete NTP basico.
pub const NTP_FIJO: usize = 48;

/// Nombre de un modo NTP.
#[must_use]
pub fn nombre_modo_ntp(m: u8) -> &'static str {
    match m {
        1 => "activo-simetrico",
        2 => "pasivo-simetrico",
        3 => "cliente",
        4 => "servidor",
        5 => "difusion",
        6 => "control",
        7 => "privado",
        _ => "reservado",
    }
}

/// Analiza un paquete NTP.
#[must_use]
pub fn analizar_ntp(datos: &[u8]) -> Vec<Hecho> {
    if datos.len() < NTP_FIJO {
        return Vec::new();
    }
    let primero = datos[0];
    let version = (primero >> 3) & 0x07;
    // Las versiones fuera de 1..=4 no existen: aceptarlas hace ver NTP en
    // cualquier datagrama.
    if !(1..=4).contains(&version) {
        return Vec::new();
    }
    let modo = primero & 0x07;
    let estrato = datos[1];

    vec![
        Hecho::ProtocoloIdentificado(ProtocoloApp::Ntp),
        Hecho::NtpVisto {
            modo: nombre_modo_ntp(modo).to_string(),
            estrato,
        },
    ]
}

/// Si unos bytes parecen NTP.
#[must_use]
pub fn parece_ntp(datos: &[u8]) -> bool {
    datos.len() >= NTP_FIJO && (1..=4).contains(&((datos[0] >> 3) & 0x07))
}

// ---------------------------------------------------------------------------
// QUIC
// ---------------------------------------------------------------------------

/// Tope de identificador de conexion QUIC.
pub const MAX_ID_CONEXION: usize = 20;

/// Analiza el paquete inicial de QUIC.
///
/// Solo se mira la cabecera larga en claro: version e identificadores. La carga
/// va cifrada con claves derivadas de la version y del identificador, y
/// descifrarla —aunque sea posible, porque esas claves son publicas— es
/// exactamente el tipo de complejidad que abre agujeros. El SNI se saca del
/// saludo TLS cuando el flujo va sin cifrar por encima; cuando no, se DICE que
/// no se pudo ver.
#[must_use]
pub fn analizar_quic(datos: &[u8]) -> Vec<Hecho> {
    let Some(&primero) = datos.first() else {
        return Vec::new();
    };
    // Cabecera larga: bit alto a uno y bit de forma fija a uno.
    if primero & 0x80 == 0 || primero & 0x40 == 0 {
        return Vec::new();
    }
    let mut l = Lector::nuevo(datos);
    if l.u8("quic.primero").is_err() {
        return Vec::new();
    }
    let Ok(version) = l.u32("quic.version") else {
        return Vec::new();
    };
    // Version 0 es negociacion de version, no un inicio.
    if version == 0 {
        return Vec::new();
    }
    // Los identificadores llevan su longitud por delante, acotada a 20 por la
    // norma. Una longitud mayor es un intento de hacer leer fuera.
    let Ok(largo_destino) = l.u8("quic.id-destino.largo") else {
        return Vec::new();
    };
    if usize::from(largo_destino) > MAX_ID_CONEXION {
        return Vec::new();
    }
    if l.saltar(usize::from(largo_destino), "quic.id-destino")
        .is_err()
    {
        return Vec::new();
    }
    let Ok(largo_origen) = l.u8("quic.id-origen.largo") else {
        return Vec::new();
    };
    if usize::from(largo_origen) > MAX_ID_CONEXION {
        return Vec::new();
    }

    vec![
        Hecho::ProtocoloIdentificado(ProtocoloApp::Quic),
        Hecho::InicioQuic {
            version,
            // La carga va cifrada: se DICE que no se vio, en vez de dejar el
            // campo vacio como si no hubiera SNI.
            sni: String::new(),
        },
    ]
}

/// Si unos bytes parecen un inicio de QUIC.
#[must_use]
pub fn parece_quic(datos: &[u8]) -> bool {
    datos.len() >= 6 && datos[0] & 0xC0 == 0xC0 && datos[1..5] != [0, 0, 0, 0]
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn mensaje_dhcp(op: u8, tipo: u8, nombre: &str) -> Vec<u8> {
        let mut v = vec![0u8; DHCP_FIJO];
        v[0] = op;
        v[1] = 1; // ethernet
        v[2] = 6; // longitud de MAC
        v[28..34].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
        v.extend_from_slice(&MAGIA_DHCP.to_be_bytes());
        v.extend_from_slice(&[53, 1, tipo]);
        v.push(12);
        v.push(nombre.len() as u8);
        v.extend_from_slice(nombre.as_bytes());
        v.push(255);
        v
    }

    #[test]
    fn un_dhcp_request_se_lee_con_su_mac_y_su_nombre() {
        let m = mensaje_dhcp(1, 3, "portatil-becario");
        let hechos = analizar_dhcp(&m);
        assert!(hechos.contains(&Hecho::ProtocoloIdentificado(ProtocoloApp::Dhcp)));
        match hechos.iter().find(|h| matches!(h, Hecho::DhcpVisto { .. })) {
            Some(Hecho::DhcpVisto { tipo, mac, nombre }) => {
                assert_eq!(tipo, "REQUEST");
                assert_eq!(mac, "de:ad:be:ef:00:01");
                assert_eq!(nombre, "portatil-becario");
            }
            otro => panic!("se esperaba DHCP: {otro:?}"),
        }
    }

    /// Lo que no es DHCP no produce ruido: decir «no pude analizar DHCP» por
    /// cada datagrama UDP del mundo enterraria las senales de verdad.
    #[test]
    fn lo_que_no_es_dhcp_no_produce_ruido() {
        assert!(analizar_dhcp(b"cualquier cosa").is_empty());
        assert!(analizar_dhcp(&[0u8; 300]).is_empty());
        assert!(!parece_dhcp(&[0u8; 300]));
    }

    #[test]
    fn un_ntp_de_cliente_se_lee_con_su_modo_y_estrato() {
        let mut p = vec![0u8; NTP_FIJO];
        p[0] = (4 << 3) | 3; // version 4, modo cliente
        p[1] = 2; // estrato
        let hechos = analizar_ntp(&p);
        match hechos.iter().find(|h| matches!(h, Hecho::NtpVisto { .. })) {
            Some(Hecho::NtpVisto { modo, estrato }) => {
                assert_eq!(modo, "cliente");
                assert_eq!(*estrato, 2);
            }
            otro => panic!("se esperaba NTP: {otro:?}"),
        }
    }

    /// Una version de NTP que no existe no puede identificarse como NTP: si se
    /// aceptara, se veria NTP en cualquier datagrama de 48 bytes.
    #[test]
    fn una_version_de_ntp_inexistente_no_se_toma_por_ntp() {
        let mut p = vec![0u8; NTP_FIJO];
        p[0] = 7 << 3; // version 7: no existe
        assert!(analizar_ntp(&p).is_empty());
        assert!(!parece_ntp(&p));

        let corto = vec![0x23u8; 10];
        assert!(analizar_ntp(&corto).is_empty());
    }

    #[test]
    fn un_inicio_de_quic_se_reconoce_con_su_version() {
        let mut p = vec![0xC3u8];
        p.extend_from_slice(&0x0000_0001u32.to_be_bytes()); // QUIC v1
        p.push(8);
        p.extend_from_slice(&[0xAA; 8]);
        p.push(8);
        p.extend_from_slice(&[0xBB; 8]);
        p.extend_from_slice(&[0u8; 32]);

        let hechos = analizar_quic(&p);
        match hechos
            .iter()
            .find(|h| matches!(h, Hecho::InicioQuic { .. }))
        {
            Some(Hecho::InicioQuic { version, sni }) => {
                assert_eq!(*version, 1);
                assert!(sni.is_empty(), "la carga va cifrada y eso se dice");
            }
            otro => panic!("se esperaba QUIC: {otro:?}"),
        }
    }

    /// Un identificador de conexion mas largo de lo que permite la norma es un
    /// intento de hacer leer fuera.
    #[test]
    fn un_identificador_de_conexion_desmesurado_se_rechaza() {
        let mut p = vec![0xC3u8];
        p.extend_from_slice(&1u32.to_be_bytes());
        p.push(200); // muy por encima del tope de 20
        p.extend_from_slice(&[0xAA; 8]);
        assert!(analizar_quic(&p).is_empty());
    }

    #[test]
    fn la_negociacion_de_version_de_quic_no_es_un_inicio() {
        let mut p = vec![0xC0u8];
        p.extend_from_slice(&0u32.to_be_bytes());
        p.extend_from_slice(&[0u8; 20]);
        assert!(analizar_quic(&p).is_empty());
    }

    #[test]
    fn ninguna_entrada_arbitraria_provoca_panico() {
        let mut semilla = 0x5EED_1234_ABCD_9876u64;
        for _ in 0..10_000 {
            semilla = semilla
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let largo = (semilla >> 32) as usize % 400;
            let datos: Vec<u8> = (0..largo).map(|i| (semilla >> (i % 8)) as u8).collect();
            let _ = analizar_dhcp(&datos);
            let _ = analizar_ntp(&datos);
            let _ = analizar_quic(&datos);
        }
    }
}
