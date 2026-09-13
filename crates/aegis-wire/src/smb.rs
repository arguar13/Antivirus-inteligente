//! Disector de SMB2/SMB3: el protocolo por el que se mueve el ransomware.
//!
//! # Por que SMB importa mas que casi cualquier otro
//!
//! El movimiento lateral y el cifrado masivo de un ransomware pasan por SMB:
//! montar un recurso, listar, abrir y escribir. Ver los nombres de fichero que
//! se abren, y a que ritmo, es lo que distingue una copia de seguridad de un
//! cifrado en curso — y es informacion que el endpoint victima puede estar ya
//! demasiado comprometido para contar.
//!
//! # Los dos detalles del formato que hay que acertar
//!
//! 1. **SMB2 va precedido de NetBIOS sobre TCP**: cuatro bytes, el primero cero
//!    y los tres siguientes la longitud. Quien no los quite lee la cabecera
//!    cuatro bytes desplazada y no reconoce nada.
//! 2. **SMB2 es little-endian**, al reves que casi todo lo que viaja por red.
//!    Leer sus campos en orden de red da numeros que no significan nada, y el
//!    fallo es silencioso: no falla, simplemente informa mal.
//!
//! # Y los mensajes compuestos
//!
//! Un paquete SMB2 puede llevar varias ordenes encadenadas por el campo
//! `NextCommand`. Si ese campo vale cero se acabo la cadena; si el recorrido no
//! exige que avance, un cero mal interpretado es un bucle infinito.

use crate::hecho::{Hecho, ProtocoloApp};
use crate::lector::Lector;

/// Firma de SMB2: `0xFE` + "SMB".
pub const FIRMA_SMB2: [u8; 4] = [0xFE, b'S', b'M', b'B'];

/// Firma de SMB1, que ya no se disecta pero SI se delata.
pub const FIRMA_SMB1: [u8; 4] = [0xFF, b'S', b'M', b'B'];

/// Longitud de la cabecera de SMB2.
pub const CABECERA_SMB2: usize = 64;

/// Tope de ordenes encadenadas en un mismo paquete.
pub const MAX_ENCADENADAS: usize = 16;

/// Nombre de una orden SMB2.
#[must_use]
pub fn nombre_orden(o: u16) -> &'static str {
    match o {
        0x00 => "NEGOTIATE",
        0x01 => "SESSION_SETUP",
        0x02 => "LOGOFF",
        0x03 => "TREE_CONNECT",
        0x04 => "TREE_DISCONNECT",
        0x05 => "CREATE",
        0x06 => "CLOSE",
        0x07 => "FLUSH",
        0x08 => "READ",
        0x09 => "WRITE",
        0x0A => "LOCK",
        0x0B => "IOCTL",
        0x0C => "CANCEL",
        0x0D => "ECHO",
        0x0E => "QUERY_DIRECTORY",
        0x0F => "CHANGE_NOTIFY",
        0x10 => "QUERY_INFO",
        0x11 => "SET_INFO",
        0x12 => "OPLOCK_BREAK",
        _ => "OTRA",
    }
}

/// Quita la envoltura NetBIOS sobre TCP, si la hay.
///
/// Quien no la quite lee la cabecera SMB cuatro bytes desplazada y no reconoce
/// nada — y como no reconoce nada, no informa de nada: ceguera silenciosa.
#[must_use]
pub fn quitar_netbios(datos: &[u8]) -> &[u8] {
    if datos.len() > 4 && datos[0] == 0 && datos[4..].starts_with(&FIRMA_SMB2) {
        &datos[4..]
    } else {
        datos
    }
}

/// Analiza un mensaje SMB2, incluidas sus ordenes encadenadas.
#[must_use]
pub fn analizar(datos: &[u8]) -> Vec<Hecho> {
    let cuerpo = quitar_netbios(datos);

    // SMB1 no se disecta —esta obsoleto y desactivado en todo lo moderno— pero
    // verlo en la red SI es una senal: es lo que usan EternalBlue y las
    // herramientas viejas, y su mera presencia merece constar.
    if cuerpo.starts_with(&FIRMA_SMB1) || (datos.len() > 4 && datos[4..].starts_with(&FIRMA_SMB1)) {
        return vec![
            Hecho::ProtocoloIdentificado(ProtocoloApp::Smb),
            Hecho::AnomaliaDeFlujo {
                codigo: "smb1-en-uso",
                detalle: "trafico SMB1, obsoleto y desactivado por defecto en los sistemas \
                          modernos: su presencia merece revisarse"
                    .to_string(),
            },
        ];
    }

    if !cuerpo.starts_with(&FIRMA_SMB2) {
        return Vec::new();
    }

    let mut hechos = vec![Hecho::ProtocoloIdentificado(ProtocoloApp::Smb)];
    let mut desplazamiento = 0usize;
    let mut encadenadas = 0usize;

    while encadenadas < MAX_ENCADENADAS {
        encadenadas += 1;
        let Some(trozo) = cuerpo.get(desplazamiento..) else {
            break;
        };
        if trozo.len() < CABECERA_SMB2 || !trozo.starts_with(&FIRMA_SMB2) {
            break;
        }

        let mut l = Lector::nuevo(trozo);
        // Los campos de SMB2 son LITTLE-ENDIAN, al reves que casi todo lo que
        // viaja por red. Leerlos en orden de red da numeros sin significado, y
        // el fallo no se nota: informa mal en silencio.
        if l.saltar(12, "smb.cabecera").is_err() {
            break;
        }
        let Ok(orden) = l.u16_le("smb.orden") else {
            break;
        };
        if l.saltar(2, "smb.credito").is_err() {
            break;
        }
        let Ok(_banderas) = l.u32_le("smb.banderas") else {
            break;
        };
        let Ok(siguiente) = l.u32_le("smb.siguiente") else {
            break;
        };

        let recurso = nombre_del_cuerpo(orden, trozo);
        hechos.push(Hecho::OperacionSmb {
            orden: nombre_orden(orden).to_string(),
            recurso,
        });

        // PROGRESO ESTRICTO: `NextCommand` a cero significa fin de la cadena.
        // Sin exigir que avance, un cero mal interpretado es un bucle infinito.
        if siguiente == 0 {
            break;
        }
        let Some(nuevo) = desplazamiento.checked_add(siguiente as usize) else {
            break;
        };
        if nuevo <= desplazamiento || nuevo >= cuerpo.len() {
            break;
        }
        desplazamiento = nuevo;
    }

    hechos
}

/// Saca el nombre de recurso o fichero del cuerpo de la orden, cuando lo lleva.
///
/// SMB2 pone los nombres en UTF-16LE con un desplazamiento y una longitud dentro
/// del cuerpo. Los dos campos los escribe el emisor, asi que los dos se acotan
/// contra el tamano real del mensaje antes de usarlos.
fn nombre_del_cuerpo(orden: u16, mensaje: &[u8]) -> String {
    // TREE_CONNECT: desplazamiento en 64+4, longitud en 64+6.
    // CREATE: desplazamiento en 64+44, longitud en 64+46.
    let (off_desp, off_largo) = match orden {
        0x03 => (CABECERA_SMB2 + 4, CABECERA_SMB2 + 6),
        0x05 => (CABECERA_SMB2 + 44, CABECERA_SMB2 + 46),
        _ => return String::new(),
    };

    let leer_u16 = |p: usize| -> Option<usize> {
        let b = mensaje.get(p..p + 2)?;
        Some(usize::from(u16::from_le_bytes([b[0], b[1]])))
    };
    let (Some(desp), Some(largo)) = (leer_u16(off_desp), leer_u16(off_largo)) else {
        return String::new();
    };
    // Las dos cotas: el desplazamiento tiene que caer dentro y la longitud tiene
    // que caber desde ahi.
    let Some(fin) = desp.checked_add(largo) else {
        return String::new();
    };
    if largo == 0 || fin > mensaje.len() {
        return String::new();
    }
    let Some(bytes) = mensaje.get(desp..fin) else {
        return String::new();
    };
    let unidades: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&unidades)
}

/// Si unos bytes parecen SMB.
#[must_use]
pub fn parece_smb(datos: &[u8]) -> bool {
    let c = quitar_netbios(datos);
    c.starts_with(&FIRMA_SMB2) || c.starts_with(&FIRMA_SMB1)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Construye un mensaje SMB2 de verdad, con su envoltura NetBIOS.
    fn smb2(orden: u16, siguiente: u32, cuerpo_extra: &[u8]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&FIRMA_SMB2);
        m.extend_from_slice(&64u16.to_le_bytes()); // longitud de estructura
        m.extend_from_slice(&0u16.to_le_bytes()); // credito cargado
        m.extend_from_slice(&0u32.to_le_bytes()); // estado
        m.extend_from_slice(&orden.to_le_bytes());
        m.extend_from_slice(&0u16.to_le_bytes()); // credito
        m.extend_from_slice(&0u32.to_le_bytes()); // banderas
        m.extend_from_slice(&siguiente.to_le_bytes());
        m.resize(CABECERA_SMB2, 0);
        m.extend_from_slice(cuerpo_extra);

        let mut v = vec![0u8];
        let l = m.len();
        v.extend_from_slice(&[(l >> 16) as u8, (l >> 8) as u8, l as u8]);
        v.extend_from_slice(&m);
        v
    }

    /// Cuerpo de un TREE_CONNECT con su nombre de recurso.
    fn cuerpo_tree_connect(recurso: &str) -> Vec<u8> {
        let utf16: Vec<u8> = recurso.encode_utf16().flat_map(u16::to_le_bytes).collect();
        // El desplazamiento es absoluto desde el inicio de la cabecera SMB2.
        let desp = CABECERA_SMB2 + 8;
        let mut c = Vec::new();
        c.extend_from_slice(&9u16.to_le_bytes()); // longitud de estructura
        c.extend_from_slice(&0u16.to_le_bytes()); // banderas
        c.extend_from_slice(&(desp as u16).to_le_bytes());
        c.extend_from_slice(&(utf16.len() as u16).to_le_bytes());
        c.extend_from_slice(&utf16);
        c
    }

    #[test]
    fn un_tree_connect_se_lee_con_su_recurso() {
        let m = smb2(0x03, 0, &cuerpo_tree_connect(r"\\servidor\compartido"));
        let hechos = analizar(&m);
        assert!(hechos.contains(&Hecho::ProtocoloIdentificado(ProtocoloApp::Smb)));
        match hechos
            .iter()
            .find(|h| matches!(h, Hecho::OperacionSmb { .. }))
        {
            Some(Hecho::OperacionSmb { orden, recurso }) => {
                assert_eq!(orden, "TREE_CONNECT");
                assert_eq!(recurso, r"\\servidor\compartido");
            }
            otro => panic!("se esperaba una operacion: {otro:?}"),
        }
    }

    /// LA ENVOLTURA NETBIOS: quien no la quite lee la cabecera desplazada y no
    /// reconoce nada — ceguera silenciosa.
    #[test]
    fn la_envoltura_netbios_se_quita_y_sin_ella_tambien_funciona() {
        let con = smb2(0x00, 0, &[]);
        let sin = &con[4..];
        assert!(!analizar(&con).is_empty());
        assert!(!analizar(sin).is_empty());
        assert_eq!(quitar_netbios(&con), sin);
    }

    /// EL ORDEN DE BYTES: SMB2 es little-endian. Leerlo en orden de red da
    /// numeros sin significado, y el fallo informa mal en silencio.
    #[test]
    fn los_campos_se_leen_en_little_endian() {
        // La orden 0x0009 (WRITE). Si se leyera en big-endian daria 0x0900.
        let m = smb2(0x09, 0, &[]);
        let hechos = analizar(&m);
        assert!(hechos.iter().any(|h| matches!(
            h,
            Hecho::OperacionSmb { orden, .. } if orden == "WRITE"
        )));
    }

    #[test]
    fn las_ordenes_encadenadas_se_leen_todas() {
        let primero = smb2(0x03, 0, &[]);
        // Se compone a mano: la primera dice que la siguiente esta a 64 bytes.
        let mut m = primero[4..].to_vec();
        m[20..24].copy_from_slice(&(CABECERA_SMB2 as u32).to_le_bytes());
        let segundo = smb2(0x05, 0, &[]);
        m.extend_from_slice(&segundo[4..]);

        let hechos = analizar(&m);
        let ordenes: Vec<String> = hechos
            .iter()
            .filter_map(|h| match h {
                Hecho::OperacionSmb { orden, .. } => Some(orden.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(ordenes, vec!["TREE_CONNECT", "CREATE"]);
    }

    /// PROGRESO ESTRICTO: una cadena que apunta a si misma no puede hacer un
    /// bucle infinito.
    #[test]
    fn una_cadena_que_no_avanza_no_produce_un_bucle() {
        // `NextCommand` a 0 desde el inicio: se acaba. Y a un valor que apunta
        // hacia atras o a si mismo: tambien.
        for siguiente in [0u32, 1, 4] {
            let m = smb2(0x03, siguiente, &[0u8; 64]);
            let hechos = analizar(&m);
            assert!(hechos.len() <= 2 + MAX_ENCADENADAS, "{hechos:?}");
        }
    }

    /// SMB1 no se disecta pero SI se delata: es lo que usan EternalBlue y las
    /// herramientas viejas, y su presencia merece constar.
    #[test]
    fn el_trafico_smb1_se_delata_aunque_no_se_disecte() {
        let mut m = vec![0u8, 0, 0, 40];
        m.extend_from_slice(&FIRMA_SMB1);
        m.extend_from_slice(&[0u8; 36]);
        let hechos = analizar(&m);
        assert!(hechos.iter().any(|h| matches!(
            h,
            Hecho::AnomaliaDeFlujo { codigo, .. } if *codigo == "smb1-en-uso"
        )));
    }

    /// Un desplazamiento de nombre que apunta fuera del mensaje no puede hacer
    /// leer basura ni entrar en panico.
    #[test]
    fn un_desplazamiento_de_nombre_que_apunta_fuera_se_rechaza() {
        let mut cuerpo = cuerpo_tree_connect("x");
        // Se pone un desplazamiento absurdo.
        cuerpo[4..6].copy_from_slice(&60_000u16.to_le_bytes());
        let m = smb2(0x03, 0, &cuerpo);
        let hechos = analizar(&m);
        assert!(hechos.iter().any(|h| matches!(
            h,
            Hecho::OperacionSmb { recurso, .. } if recurso.is_empty()
        )));
    }

    #[test]
    fn lo_que_no_es_smb_no_produce_hechos_smb() {
        assert!(analizar(b"GET / HTTP/1.1\r\n\r\n").is_empty());
        assert!(analizar(&[0u8; 100]).is_empty());
        assert!(!parece_smb(b"cualquier cosa"));
    }

    #[test]
    fn ninguna_entrada_arbitraria_provoca_panico_ni_bucle() {
        let mut semilla = 0x5342_324D_4249_4E41u64;
        for _ in 0..10_000 {
            semilla = semilla
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let largo = (semilla >> 32) as usize % 400;
            let mut datos: Vec<u8> = (0..largo).map(|i| (semilla >> (i % 8)) as u8).collect();
            // La mitad con firma valida, para llegar al recorrido de la cadena.
            if largo > 68 && largo % 2 == 0 {
                datos[0..4].copy_from_slice(&FIRMA_SMB2);
            }
            let _ = analizar(&datos);
        }
    }
}
