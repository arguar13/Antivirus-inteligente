//! Protocolos de linea: SSH, SMTP y FTP.
//!
//! # Por que van juntos
//!
//! Los tres empiezan con texto ASCII terminado en CRLF y los tres se identifican
//! por su primera linea. Compartir la maquinaria de lineas evita tener tres
//! bucles de troceado ligeramente distintos, que es como aparecen las
//! discrepancias entre disectores.
//!
//! # La cota de linea, y por que es lo primero
//!
//! Un protocolo de texto sin tope de linea es una reserva de memoria controlada
//! por el atacante: basta con mandar megabytes sin un solo salto de linea. Es un
//! fallo que ha aparecido en servidores SMTP y FTP reales. Aqui la linea se corta
//! al tope y se anota, en vez de crecer.

use crate::hecho::{Hecho, ProtocoloApp};
use crate::lector::ascii_legible;

/// Tope de una linea de protocolo.
pub const MAX_LINEA: usize = 4096;

/// Tope de lineas que se procesan de una vez.
pub const MAX_LINEAS: usize = 256;

/// Trocea en lineas, acotando tanto la longitud como el numero.
///
/// Devuelve las lineas y si hubo que recortar alguna. Lo segundo importa: una
/// linea recortada puede haber perdido justo el argumento que interesaba, y
/// tratarla como completa daria una observacion falsa.
#[must_use]
pub fn lineas(datos: &[u8]) -> (Vec<String>, bool) {
    let mut salida = Vec::new();
    let mut recortada = false;
    for cruda in datos.split(|&b| b == b'\n').take(MAX_LINEAS) {
        let sin_cr = match cruda.last() {
            Some(b'\r') => &cruda[..cruda.len() - 1],
            _ => cruda,
        };
        if sin_cr.is_empty() {
            continue;
        }
        if sin_cr.len() > MAX_LINEA {
            recortada = true;
            salida.push(ascii_legible(&sin_cr[..MAX_LINEA]));
        } else {
            salida.push(ascii_legible(sin_cr));
        }
    }
    (salida, recortada)
}

// ---------------------------------------------------------------------------
// SSH
// ---------------------------------------------------------------------------

/// Verbos SMTP que se reconocen.
///
/// Lista cerrada a proposito: aceptar cualquier palabra como verbo hace que el
/// disector vea SMTP en cualquier trafico de texto.
pub const VERBOS_SMTP: &[&str] = &[
    "HELO", "EHLO", "MAIL", "RCPT", "DATA", "QUIT", "RSET", "VRFY", "EXPN", "NOOP", "AUTH",
    "STARTTLS", "BDAT", "HELP",
];

/// Verbos FTP que se reconocen.
pub const VERBOS_FTP: &[&str] = &[
    "USER", "PASS", "ACCT", "CWD", "CDUP", "QUIT", "PORT", "PASV", "EPSV", "EPRT", "TYPE", "RETR",
    "STOR", "STOU", "APPE", "LIST", "NLST", "DELE", "RNFR", "RNTO", "MKD", "RMD", "PWD", "SYST",
    "STAT", "SIZE", "MDTM", "FEAT", "OPTS", "AUTH", "ABOR", "REST", "NOOP",
];

/// Analiza el intercambio de version de SSH.
///
/// La cadena de version es lo unico en claro de una sesion SSH, y lleva la
/// implementacion y su version exacta: `SSH-2.0-OpenSSH_9.6`. Es una senal util
/// —identifica clientes que no deberian estar ahi— y es todo lo que se puede ver
/// sin romper el cifrado, cosa que este producto no hace.
#[must_use]
pub fn analizar_ssh(datos: &[u8]) -> Vec<Hecho> {
    if !datos.starts_with(b"SSH-") {
        return Vec::new();
    }
    let (ls, _) = lineas(datos);
    let Some(version) = ls.first() else {
        return Vec::new();
    };
    // Formato: SSH-<protoversion>-<softwareversion>[ <comentarios>]
    let implementacion = version
        .splitn(3, '-')
        .nth(2)
        .unwrap_or_default()
        .split(' ')
        .next()
        .unwrap_or_default()
        .to_string();

    vec![
        Hecho::ProtocoloIdentificado(ProtocoloApp::Ssh),
        Hecho::VersionSsh {
            version: version.clone(),
            implementacion,
        },
    ]
}

/// Si unos bytes parecen el inicio de SSH.
#[must_use]
pub fn parece_ssh(datos: &[u8]) -> bool {
    datos.starts_with(b"SSH-")
}

// ---------------------------------------------------------------------------
// SMTP
// ---------------------------------------------------------------------------

/// Analiza ordenes SMTP del lado del cliente.
#[must_use]
pub fn analizar_smtp(datos: &[u8]) -> Vec<Hecho> {
    let (ls, _) = lineas(datos);
    let mut hechos = Vec::new();
    let mut identificado = false;
    for l in ls {
        let mut partes = l.splitn(2, ' ');
        let verbo = partes.next().unwrap_or_default().to_ascii_uppercase();
        if !VERBOS_SMTP.contains(&verbo.as_str()) {
            continue;
        }
        if !identificado {
            hechos.push(Hecho::ProtocoloIdentificado(ProtocoloApp::Smtp));
            identificado = true;
        }
        hechos.push(Hecho::OrdenSmtp {
            verbo,
            argumento: partes.next().unwrap_or_default().trim().to_string(),
        });
    }
    hechos
}

/// Si unos bytes parecen SMTP.
#[must_use]
pub fn parece_smtp(datos: &[u8]) -> bool {
    let (ls, _) = lineas(datos);
    ls.first().is_some_and(|l| {
        // Saludo del servidor (220 ...) o una orden del cliente.
        l.starts_with("220 ")
            || l.starts_with("220-")
            || VERBOS_SMTP.contains(
                &l.split(' ')
                    .next()
                    .unwrap_or_default()
                    .to_ascii_uppercase()
                    .as_str(),
            )
    })
}

// ---------------------------------------------------------------------------
// FTP
// ---------------------------------------------------------------------------

/// Analiza ordenes FTP del canal de control.
///
/// El canal de datos va aparte, en otro puerto negociado por `PORT`, `PASV` o
/// `EPSV`. Reconocer esas ordenes es lo que permite despues seguir el canal de
/// datos: sin ello, una transferencia FTP es un flujo anonimo sin relacion
/// visible con nada.
#[must_use]
pub fn analizar_ftp(datos: &[u8]) -> Vec<Hecho> {
    let (ls, _) = lineas(datos);
    let mut hechos = Vec::new();
    let mut identificado = false;
    for l in ls {
        let mut partes = l.splitn(2, ' ');
        let verbo = partes.next().unwrap_or_default().to_ascii_uppercase();
        if !VERBOS_FTP.contains(&verbo.as_str()) {
            continue;
        }
        if !identificado {
            hechos.push(Hecho::ProtocoloIdentificado(ProtocoloApp::Ftp));
            identificado = true;
        }
        let argumento = partes.next().unwrap_or_default().trim().to_string();
        // La contrasena NO se registra. Un EDR que deje contrasenas en claro en
        // su propia telemetria crea la brecha que dice prevenir.
        let argumento = if verbo == "PASS" {
            "(omitida)".to_string()
        } else {
            argumento
        };
        hechos.push(Hecho::OrdenFtp { verbo, argumento });
    }
    hechos
}

/// Si unos bytes parecen FTP.
#[must_use]
pub fn parece_ftp(datos: &[u8]) -> bool {
    let (ls, _) = lineas(datos);
    ls.first().is_some_and(|l| {
        l.starts_with("220 ")
            || l.starts_with("220-")
            || VERBOS_FTP.contains(
                &l.split(' ')
                    .next()
                    .unwrap_or_default()
                    .to_ascii_uppercase()
                    .as_str(),
            )
    })
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn la_cadena_de_version_de_ssh_se_lee_con_su_implementacion() {
        let hechos = analizar_ssh(b"SSH-2.0-OpenSSH_9.6p1 Debian-4\r\n");
        assert!(hechos.contains(&Hecho::ProtocoloIdentificado(ProtocoloApp::Ssh)));
        match hechos
            .iter()
            .find(|h| matches!(h, Hecho::VersionSsh { .. }))
        {
            Some(Hecho::VersionSsh {
                version,
                implementacion,
            }) => {
                assert_eq!(version, "SSH-2.0-OpenSSH_9.6p1 Debian-4");
                assert_eq!(implementacion, "OpenSSH_9.6p1");
            }
            otro => panic!("se esperaba una version: {otro:?}"),
        }
    }

    #[test]
    fn un_cliente_ssh_poco_habitual_se_identifica_igual() {
        // Es la senal util: un cliente que no deberia estar en la red.
        let hechos = analizar_ssh(b"SSH-2.0-paramiko_3.4.0\r\n");
        assert!(hechos.iter().any(|h| matches!(
            h,
            Hecho::VersionSsh { implementacion, .. } if implementacion == "paramiko_3.4.0"
        )));
    }

    #[test]
    fn las_ordenes_smtp_se_leen_y_lo_que_no_es_smtp_no_produce_nada() {
        let hechos = analizar_smtp(b"EHLO cliente.local\r\nMAIL FROM:<a@b.com>\r\nDATA\r\n");
        assert!(hechos.contains(&Hecho::ProtocoloIdentificado(ProtocoloApp::Smtp)));
        let verbos: Vec<String> = hechos
            .iter()
            .filter_map(|h| match h {
                Hecho::OrdenSmtp { verbo, .. } => Some(verbo.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(verbos, vec!["EHLO", "MAIL", "DATA"]);

        assert!(analizar_smtp(b"esto no es smtp\r\nni esto\r\n").is_empty());
    }

    /// LA CONTRASENA NO SE REGISTRA. Un EDR que deje contrasenas en claro en su
    /// propia telemetria crea la brecha que dice prevenir.
    #[test]
    fn la_contrasena_de_ftp_no_queda_en_la_telemetria() {
        let hechos = analizar_ftp(b"USER admin\r\nPASS SuperSecreta123\r\nLIST\r\n");
        let arg_pass = hechos.iter().find_map(|h| match h {
            Hecho::OrdenFtp { verbo, argumento } if verbo == "PASS" => Some(argumento.clone()),
            _ => None,
        });
        assert_eq!(arg_pass.as_deref(), Some("(omitida)"));

        // Y no aparece por ningun otro sitio.
        let todo = format!("{hechos:?}");
        assert!(
            !todo.contains("SuperSecreta123"),
            "la contrasena se ha colado en la telemetria: {todo}"
        );

        // Pero el usuario SI, porque es la senal que interesa.
        assert!(hechos.iter().any(|h| matches!(
            h,
            Hecho::OrdenFtp { verbo, argumento } if verbo == "USER" && argumento == "admin"
        )));
    }

    #[test]
    fn las_ordenes_de_canal_de_datos_de_ftp_se_reconocen() {
        let hechos = analizar_ftp(b"PASV\r\nEPSV\r\nPORT 10,0,0,1,20,0\r\nRETR fichero.bin\r\n");
        let verbos: Vec<String> = hechos
            .iter()
            .filter_map(|h| match h {
                Hecho::OrdenFtp { verbo, .. } => Some(verbo.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(verbos, vec!["PASV", "EPSV", "PORT", "RETR"]);
    }

    /// LA COTA: megabytes sin un salto de linea no pueden hacer reservar
    /// memoria. Es un fallo que ha aparecido en servidores SMTP y FTP reales.
    #[test]
    fn una_linea_desmesurada_se_recorta_y_se_dice() {
        let mut datos = b"USER ".to_vec();
        datos.extend_from_slice(&vec![b'A'; 10 * 1024 * 1024]);
        datos.extend_from_slice(b"\r\n");

        let (ls, recortada) = lineas(&datos);
        assert!(recortada, "el recorte tiene que declararse");
        assert!(ls[0].len() <= MAX_LINEA, "linea = {}", ls[0].len());
    }

    #[test]
    fn una_avalancha_de_lineas_se_acota() {
        let datos = b"NOOP\r\n".repeat(100_000);
        let (ls, _) = lineas(&datos);
        assert!(ls.len() <= MAX_LINEAS, "lineas = {}", ls.len());
    }

    #[test]
    fn los_detectores_reconocen_lo_suyo_y_no_lo_ajeno() {
        assert!(parece_ssh(b"SSH-2.0-x"));
        assert!(!parece_ssh(b"GET / HTTP/1.1"));
        assert!(parece_smtp(b"220 correo.ejemplo.com ESMTP\r\n"));
        assert!(parece_smtp(b"EHLO x\r\n"));
        assert!(parece_ftp(b"USER anonimo\r\n"));
        assert!(!parece_smtp(b"cualquier cosa\r\n"));
        assert!(!parece_ftp(b"cualquier cosa\r\n"));
    }

    #[test]
    fn ninguna_entrada_arbitraria_provoca_panico() {
        let mut semilla = 0x0BAD_C0DE_DEAD_BEEFu64;
        for _ in 0..8000 {
            semilla = semilla
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let largo = (semilla >> 32) as usize % 400;
            let datos: Vec<u8> = (0..largo).map(|i| (semilla >> (i % 8)) as u8).collect();
            let _ = analizar_ssh(&datos);
            let _ = analizar_smtp(&datos);
            let _ = analizar_ftp(&datos);
            let _ = lineas(&datos);
        }
    }
}
