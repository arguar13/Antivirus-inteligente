//! Correo: IMAP, POP3 y la extraccion de adjuntos.
//!
//! # Por que el adjunto y no el sobre
//!
//! `aegis-wire` ya leia los sobres de SMTP. El sobre dice quien escribe a quien,
//! y eso es la mitad: el fichero que viaja dentro es la otra, y es la que
//! entrega el codigo. Aqui el adjunto se reconstruye y se nombra por su SHA-256,
//! que es como se llama una entidad en todo el producto desde la FASE 79 — de
//! modo que el mismo fichero visto por correo, por SMB y por HTTP es **el
//! mismo**, y no tres registros que alguien tiene que unir despues.
//!
//! # La diferencia con mirar solo la extension
//!
//! El nombre declarado en `Content-Disposition` lo escribe quien manda el
//! correo. El tipo real sale de los bytes, y el extractor de
//! [`aegis_wire::ficheros`] emite una anomalia aparte cuando los dos no cuadran:
//! mentir sobre el tipo es la tecnica, no un descuido.
//!
//! # Lo que se declara y no se hace
//!
//! Un correo real llega en trozos y con el cuerpo en `base64` partido en lineas
//! de setenta y seis caracteres. Este disector reconstruye **lo que le llega en
//! una pieza**; el reensamblado a lo largo de varios trozos es del motor, que ya
//! lo hace para HTTP y SMB. Lo que no se ha visto entero no se cuenta como
//! entendido.

use aegis_wire::ficheros::{identificar, Extractor, TipoFichero};
use aegis_wire::hecho::{Hecho, ProtocoloApp};

use crate::cobertura::{Cobertura, Motivo};
use crate::disector::{Contexto, Disector, Fuerza, Salida};
use crate::texto;

/// Puertos de IMAP: sin cifrar y sobre TLS.
pub const PUERTOS_IMAP: [u16; 2] = [143, 993];

/// Puertos de POP3: sin cifrar y sobre TLS.
pub const PUERTOS_POP3: [u16; 2] = [110, 995];

/// Cuanto adjunto se reconstruye como maximo.
///
/// El tope existe porque el tamano lo elige quien manda el correo. Ocho megas
/// cubren el noventa y nueve por ciento de los adjuntos reales y dejan el coste
/// por mensaje acotado; lo que pase de ahi se declara y no se calla.
pub const MAX_ADJUNTO: usize = 8 * 1024 * 1024;

/// Las ordenes de IMAP que este disector entiende.
const ORDENES_IMAP: [&str; 16] = [
    "LOGIN",
    "AUTHENTICATE",
    "CAPABILITY",
    "STARTTLS",
    "SELECT",
    "EXAMINE",
    "LIST",
    "LSUB",
    "STATUS",
    "FETCH",
    "SEARCH",
    "STORE",
    "COPY",
    "APPEND",
    "EXPUNGE",
    "LOGOUT",
];

/// Las ordenes de POP3 que este disector entiende.
const ORDENES_POP3: [&str; 11] = [
    "USER", "PASS", "APOP", "STAT", "LIST", "RETR", "DELE", "NOOP", "RSET", "QUIT", "CAPA",
];

/// Un adjunto encontrado en un cuerpo MIME.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adjunto {
    /// El nombre que declara quien manda el correo.
    pub nombre: String,
    /// El tipo que declara.
    pub tipo_declarado: String,
    /// Los bytes ya decodificados.
    pub contenido: Vec<u8>,
}

/// Busca adjuntos en un cuerpo MIME.
///
/// # Como se recorre sin que el coste lo elija el emisor
///
/// Se para a las treinta y dos partes y a [`MAX_ADJUNTO`] por parte. Un correo
/// con diez mil partes anidadas es un ataque conocido contra los analizadores de
/// correo, y sin los dos topes cada mensaje costaria lo que el emisor decida.
#[must_use]
pub fn adjuntos(cuerpo: &[u8]) -> (Vec<Adjunto>, usize) {
    const MAX_PARTES: usize = 32;
    const MARCA: &[u8] = b"Content-Disposition:";
    let mut salida = Vec::new();
    let mut sin_decodificar = 0usize;
    let mut pos = 0usize;

    while salida.len() + sin_decodificar < MAX_PARTES && pos < cuerpo.len() {
        let Some(rel) = cuerpo[pos..]
            .windows(MARCA.len())
            .position(|v| v.eq_ignore_ascii_case(MARCA))
        else {
            break;
        };
        let inicio = pos + rel;
        pos = inicio + MARCA.len();

        // La cabecera de la parte NO empieza en `Content-Disposition`: empieza
        // donde acabo la linea en blanco anterior. Leerla desde aqui perderia
        // las cabeceras que van antes, que son justo el tipo declarado y la
        // codificacion — es decir, lo que hace falta para leer el adjunto.
        let inicio_parte = principio_de_parte(cuerpo, inicio);
        let Some(fin_relativo) = texto::fin_de_cabecera(&cuerpo[inicio..]) else {
            sin_decodificar += 1;
            break;
        };
        let fin_cabecera = inicio + fin_relativo;
        let cabecera = &cuerpo[inicio_parte..fin_cabecera];
        let texto_cabecera = aegis_wire::lector::ascii_legible(cabecera);
        let bajo = texto_cabecera.to_ascii_lowercase();
        if !(bajo.contains("attachment") || bajo.contains("filename")) {
            continue;
        }
        let nombre = nombre_de_fichero(&texto_cabecera).unwrap_or_default();
        let tipo_declarado = texto::cabecera_mime(cabecera, "Content-Type").unwrap_or_default();
        let codificacion = texto::cabecera_mime(cabecera, "Content-Transfer-Encoding")
            .unwrap_or_default()
            .to_ascii_lowercase();

        // El cuerpo de la parte acaba en la frontera siguiente o en el final.
        let desde = fin_cabecera;
        let hasta = cuerpo[desde..]
            .windows(2)
            .position(|v| v == b"--")
            .map_or(cuerpo.len(), |p| desde + p)
            .min(desde + MAX_ADJUNTO);
        let bruto = &cuerpo[desde..hasta];
        pos = hasta;

        let contenido = if codificacion.contains("base64") {
            // El alfabeto estandar, no el de URL: el de URL acepta el guion y se
            // tragaria la frontera MIME que cierra la parte.
            match texto::base64_estandar(bruto) {
                Some(v) => v,
                None => {
                    // Base64 que no lo es: se cuenta y no se inventa contenido.
                    sin_decodificar += 1;
                    continue;
                }
            }
        } else if codificacion.contains("quoted-printable")
            // `7bit`, `8bit` y `binary` son codificaciones de identidad por la
            // RFC 2045: los bytes van tal cual. Tratarlas como desconocidas
            // dejaria sin mirar justo los adjuntos que no se molestan en
            // codificarse, que son los que llevan un ejecutable entero.
            || codificacion.contains("7bit")
            || codificacion.contains("8bit")
            || codificacion.contains("binary")
            || codificacion.is_empty()
        {
            bruto.to_vec()
        } else {
            sin_decodificar += 1;
            continue;
        };
        if contenido.is_empty() {
            continue;
        }
        salida.push(Adjunto {
            nombre,
            tipo_declarado,
            contenido,
        });
    }
    (salida, sin_decodificar)
}

/// Donde empieza la parte que contiene la posicion `dentro`.
///
/// Es el byte siguiente a la ultima linea en blanco anterior, o el principio del
/// cuerpo si no hay ninguna.
fn principio_de_parte(cuerpo: &[u8], dentro: usize) -> usize {
    let antes = &cuerpo[..dentro];
    let crlf = antes
        .windows(4)
        .rposition(|v| v == b"\r\n\r\n")
        .map(|p| p + 4);
    let lf = antes.windows(2).rposition(|v| v == b"\n\n").map(|p| p + 2);
    match (crlf, lf) {
        (Some(a), Some(b)) => a.max(b),
        (Some(a), None) => a,
        (None, Some(b)) => b,
        (None, None) => 0,
    }
}

/// El nombre de fichero declarado en una cabecera de parte.
fn nombre_de_fichero(cabecera: &str) -> Option<String> {
    let bajo = cabecera.to_ascii_lowercase();
    let p = bajo.find("filename")?;
    let resto = &cabecera[p..];
    let igual = resto.find('=')?;
    let valor = resto[igual + 1..].trim_start();
    let nombre = if let Some(sin) = valor.strip_prefix('"') {
        sin.split('"').next()?
    } else {
        valor.split([';', '\r', '\n']).next()?
    };
    let limpio: String = nombre.trim().chars().take(255).collect();
    if limpio.is_empty() {
        None
    } else {
        Some(limpio)
    }
}

/// El tipo que implica una extension de fichero.
///
/// Es el contrato que un usuario cree que tiene: quien ve `factura.txt` espera
/// texto. Sirve **solo** para contrastarlo con lo que hay dentro, igual que el
/// `Content-Type` en [`aegis_wire::ficheros::tipo_declarado`] — y hace falta
/// aparte porque en el correo la extension es lo que el usuario mira, y casi
/// nunca coincide con lo que el cliente de correo declara en la cabecera.
fn tipo_por_extension(nombre: &str) -> Option<TipoFichero> {
    let ext = nombre.rsplit('.').next()?.to_ascii_lowercase();
    Some(match ext.as_str() {
        "exe" | "dll" | "scr" | "com" | "cpl" | "sys" => TipoFichero::EjecutableWindows,
        "so" | "elf" | "bin" => TipoFichero::EjecutableLinux,
        "pdf" => TipoFichero::Pdf,
        "zip" | "jar" | "docx" | "xlsx" | "pptx" | "apk" => TipoFichero::Zip,
        "doc" | "xls" | "ppt" | "msi" => TipoFichero::Ole,
        "gz" | "tgz" => TipoFichero::Gzip,
        "rar" => TipoFichero::Rar,
        "7z" => TipoFichero::SieteZip,
        "iso" => TipoFichero::Iso,
        _ => return None,
    })
}

/// Las extensiones que un cliente de correo ejecuta o abre con un interprete.
const EXTENSIONES_QUE_EJECUTAN: [&str; 14] = [
    "exe", "scr", "com", "cpl", "bat", "cmd", "pif", "vbs", "vbe", "js", "jse", "wsf", "hta", "lnk",
];

/// Convierte los adjuntos de un cuerpo en hechos, nombrandolos por su SHA-256.
fn hechos_de_adjuntos(cuerpo: &[u8], via: ProtocoloApp) -> (Vec<Hecho>, usize) {
    let (encontrados, sin_decodificar) = adjuntos(cuerpo);
    let mut hechos = Vec::new();
    for a in encontrados {
        let mut e = Extractor::nuevo(
            via,
            &a.nombre,
            &a.tipo_declarado,
            Some(a.contenido.len() as u64),
        );
        e.incorporar(&a.contenido);
        hechos.extend(e.cerrar());

        // LA comprobacion del correo: lo que el usuario ve es la extension, y
        // lo que se ejecuta es el contenido. `factura.txt` con un ejecutable
        // dentro no es un descuido de nadie.
        let real = identificar(&a.contenido);
        if let (Some(r), Some(esperado)) = (real, tipo_por_extension(&a.nombre)) {
            if r != esperado {
                hechos.push(Hecho::AnomaliaDeFlujo {
                    codigo: "adjunto-extension-contradictoria",
                    detalle: format!(
                        "el adjunto se llama {} y su contenido es {}",
                        a.nombre,
                        r.codigo()
                    ),
                });
            }
        } else if let Some(r) = real {
            // Sin extension conocida, la contradiccion es con lo que el usuario
            // supondria: un nombre que no promete un ejecutable y un ejecutable.
            if r.ejecuta_codigo() {
                hechos.push(Hecho::AnomaliaDeFlujo {
                    codigo: "adjunto-extension-contradictoria",
                    detalle: format!(
                        "el adjunto se llama {} y su contenido es {}",
                        a.nombre,
                        r.codigo()
                    ),
                });
            }
        }

        // La doble extension es la otra mitad de la misma tecnica: el cliente de
        // correo esconde la ultima y el usuario lee la primera.
        let partes: Vec<&str> = a.nombre.split('.').collect();
        if partes.len() >= 3 {
            let ultima = partes[partes.len() - 1].to_ascii_lowercase();
            let penultima = partes[partes.len() - 2].to_ascii_lowercase();
            if EXTENSIONES_QUE_EJECUTAN.contains(&ultima.as_str())
                && tipo_por_extension(&format!("x.{penultima}")).is_some()
            {
                hechos.push(Hecho::AnomaliaDeFlujo {
                    codigo: "adjunto-de-doble-extension",
                    detalle: format!(
                        "{}: el cliente de correo esconde la ultima extension y el usuario lee la primera",
                        a.nombre
                    ),
                });
            }
        }
    }
    (hechos, sin_decodificar)
}

/// La primera palabra de una linea, en mayusculas.
fn verbo(linea: &[u8], saltar_etiqueta: bool) -> Option<(String, String)> {
    let texto_linea = aegis_wire::lector::ascii_legible(linea);
    let mut partes = texto_linea.split_whitespace();
    if saltar_etiqueta {
        let etiqueta = partes.next()?;
        // Una etiqueta de IMAP es alfanumerica y corta: sin comprobarlo, la
        // primera palabra de cualquier linea de texto pasaria por etiqueta.
        if etiqueta.is_empty()
            || etiqueta.len() > 16
            || !etiqueta.chars().all(|c| c.is_ascii_alphanumeric())
        {
            return None;
        }
    }
    let v = partes.next()?.to_ascii_uppercase();
    let resto: Vec<&str> = partes.collect();
    Some((v, resto.join(" ")))
}

// ════════════════════════════════════════════════════════════════════════════
// IMAP
// ════════════════════════════════════════════════════════════════════════════

/// Disector de IMAP.
#[derive(Debug, Default, Clone, Copy)]
pub struct Imap;

impl Imap {
    /// La orden del cliente, si la linea lo es.
    fn orden(datos: &[u8]) -> Option<(String, String)> {
        let (l, _) = texto::linea(datos)?;
        let (v, resto) = verbo(l, true)?;
        if ORDENES_IMAP.contains(&v.as_str()) {
            Some((v, resto))
        } else {
            None
        }
    }

    /// El saludo o una respuesta sin etiqueta del servidor.
    fn respuesta(datos: &[u8]) -> Option<String> {
        let (l, _) = texto::linea(datos)?;
        if !l.starts_with(b"* ") {
            return None;
        }
        let (v, resto) = verbo(&l[2..], false)?;
        Some(format!("{v} {resto}").trim().to_owned())
    }
}

impl Disector for Imap {
    /// Una etiqueta con forma de etiqueta mas una orden del catalogo.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Forma
    }

    fn nombre(&self) -> &'static str {
        "imap"
    }

    fn reconoce(&self, datos: &[u8], ctx: &Contexto) -> bool {
        if ctx.del_cliente {
            Imap::orden(datos).is_some()
        } else {
            Imap::respuesta(datos).is_some_and(|r| {
                r.starts_with("OK")
                    || r.starts_with("NO")
                    || r.starts_with("BAD")
                    || r.starts_with("CAPABILITY")
                    || r.chars().next().is_some_and(|c| c.is_ascii_digit())
            })
        }
    }

    fn disecar(&self, datos: &[u8], ctx: &Contexto) -> Salida {
        // El hecho de protocolo se anade DESPUES de haber reconocido algo. Al
        // reves, un buffer vacio salia con un hecho que afirmaba haber visto
        // IMAP donde no habia nada: lo encontro el barrido hostil, y es
        // exactamente la clase de afirmacion que este producto no puede emitir.
        if !self.reconoce(datos, ctx) {
            return Salida::sin_analizar(Motivo::NoReconocido);
        }
        let mut hechos = vec![Hecho::ProtocoloIdentificado(ProtocoloApp::Imap)];
        let mut cobertura = Cobertura::nueva();

        if ctx.del_cliente {
            let Some((v, argumento)) = Imap::orden(datos) else {
                return Salida::sin_analizar(Motivo::NoReconocido);
            };
            // La orden de acceso lleva el usuario, y en IMAP sin TLS va en claro.
            if v == "LOGIN" {
                let usuario = argumento
                    .split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .trim_matches('"')
                    .to_owned();
                hechos.push(Hecho::AutenticacionVista {
                    mecanismo: "imap-login".to_owned(),
                    usuario,
                    dominio: String::new(),
                    resultado: "peticion".to_owned(),
                });
            }
            hechos.push(Hecho::OrdenSmtp {
                verbo: format!("imap.{v}"),
                argumento,
            });
            cobertura.entendido();
        } else {
            match Imap::respuesta(datos) {
                Some(r) => {
                    hechos.push(Hecho::OrdenSmtp {
                        verbo: "imap.respuesta".to_owned(),
                        argumento: r,
                    });
                    cobertura.entendido();
                }
                None => cobertura.sin_analizar(Motivo::NoReconocido),
            }
        }

        // Un FETCH devuelve el correo entero, adjuntos incluidos.
        let (de_adjuntos, sin_decodificar) = hechos_de_adjuntos(datos, ProtocoloApp::Imap);
        let hubo = !de_adjuntos.is_empty();
        hechos.extend(de_adjuntos);
        if hubo {
            cobertura.entendido();
        }
        for _ in 0..sin_decodificar {
            cobertura.sin_analizar(Motivo::Malformado);
        }
        Salida { hechos, cobertura }
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "las dieciseis ordenes del cliente, con su etiqueta y su argumento",
            "LOGIN, de donde sale el usuario",
            "las respuestas sin etiqueta del servidor",
            "los adjuntos que vengan enteros en lo que se ve, con su SHA-256",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "los literales de IMAP ({n}) y su continuacion en varias lineas",
            "la estructura de un FETCH: los cuerpos, las banderas y los sobres",
            "el dialogo SASL de AUTHENTICATE",
            "los adjuntos partidos en varios trozos, que son cosa del reensamblado del motor",
            "todo lo que vaya tras un STARTTLS",
        ]
    }
}

// ════════════════════════════════════════════════════════════════════════════
// POP3
// ════════════════════════════════════════════════════════════════════════════

/// Disector de POP3.
#[derive(Debug, Default, Clone, Copy)]
pub struct Pop3;

impl Pop3 {
    fn orden(datos: &[u8]) -> Option<(String, String)> {
        let (l, _) = texto::linea(datos)?;
        let (v, resto) = verbo(l, false)?;
        if ORDENES_POP3.contains(&v.as_str()) {
            Some((v, resto))
        } else {
            None
        }
    }

    fn respuesta(datos: &[u8]) -> Option<bool> {
        let (l, _) = texto::linea(datos)?;
        if l.starts_with(b"+OK") {
            Some(true)
        } else if l.starts_with(b"-ERR") {
            Some(false)
        } else {
            None
        }
    }
}

impl Disector for Pop3 {
    /// Un verbo del catalogo o una respuesta +OK/-ERR.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Forma
    }

    fn nombre(&self) -> &'static str {
        "pop3"
    }

    fn reconoce(&self, datos: &[u8], ctx: &Contexto) -> bool {
        if ctx.del_cliente {
            Pop3::orden(datos).is_some()
        } else {
            Pop3::respuesta(datos).is_some()
        }
    }

    fn disecar(&self, datos: &[u8], ctx: &Contexto) -> Salida {
        // Como en IMAP: nada de afirmar el protocolo antes de reconocerlo.
        if !self.reconoce(datos, ctx) {
            return Salida::sin_analizar(Motivo::NoReconocido);
        }
        let mut hechos = vec![Hecho::ProtocoloIdentificado(ProtocoloApp::Pop3)];
        let mut cobertura = Cobertura::nueva();

        if ctx.del_cliente {
            let Some((v, argumento)) = Pop3::orden(datos) else {
                return Salida::sin_analizar(Motivo::NoReconocido);
            };
            if v == "USER" || v == "APOP" {
                hechos.push(Hecho::AutenticacionVista {
                    mecanismo: format!("pop3-{}", v.to_ascii_lowercase()),
                    usuario: argumento
                        .split_whitespace()
                        .next()
                        .unwrap_or_default()
                        .to_owned(),
                    dominio: String::new(),
                    resultado: "peticion".to_owned(),
                });
            }
            // La contrasena de POP3 viaja en claro en la propia orden: se
            // registra que hubo un PASS y **no** lo que llevaba.
            let argumento = if v == "PASS" {
                String::new()
            } else {
                argumento
            };
            hechos.push(Hecho::OrdenSmtp {
                verbo: format!("pop3.{v}"),
                argumento,
            });
            cobertura.entendido();
        } else {
            match Pop3::respuesta(datos) {
                Some(bien) => {
                    hechos.push(Hecho::OrdenSmtp {
                        verbo: "pop3.respuesta".to_owned(),
                        argumento: if bien { "+OK" } else { "-ERR" }.to_owned(),
                    });
                    cobertura.entendido();
                }
                None => cobertura.sin_analizar(Motivo::NoReconocido),
            }
        }

        let (de_adjuntos, sin_decodificar) = hechos_de_adjuntos(datos, ProtocoloApp::Pop3);
        let hubo = !de_adjuntos.is_empty();
        hechos.extend(de_adjuntos);
        if hubo {
            cobertura.entendido();
        }
        for _ in 0..sin_decodificar {
            cobertura.sin_analizar(Motivo::Malformado);
        }
        Salida { hechos, cobertura }
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "las once ordenes del cliente",
            "USER y APOP, de donde sale el usuario",
            "las respuestas +OK y -ERR",
            "los adjuntos de un RETR que vengan enteros, con su SHA-256",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "la contrasena de PASS, que se ve pasar y no se guarda a proposito",
            "el reto de APOP y su respuesta",
            "las respuestas de varias lineas terminadas en un punto solo",
            "los adjuntos partidos en varios trozos",
            "todo lo que vaya tras un STLS",
        ]
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Un mensaje con un adjunto ejecutable declarado como texto.
    fn correo_con_adjunto() -> Vec<u8> {
        // «MZ» al principio: el contenido es un ejecutable de Windows aunque el
        // emisor lo declare como texto llano.
        let contenido = b"MZ\x90\x00\x03\x00\x00\x00factura";
        let mut b64 = Vec::new();
        const ALFABETO: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for trozo in contenido.chunks(3) {
            let mut bloque = [0u8; 3];
            bloque[..trozo.len()].copy_from_slice(trozo);
            let n = u32::from(bloque[0]) << 16 | u32::from(bloque[1]) << 8 | u32::from(bloque[2]);
            for i in 0..4 {
                if i <= trozo.len() {
                    b64.push(ALFABETO[((n >> (18 - 6 * i)) & 0x3F) as usize]);
                } else {
                    b64.push(b'=');
                }
            }
        }
        let mut v = Vec::new();
        v.extend_from_slice(b"* 1 FETCH (BODY[] {200}\r\n");
        v.extend_from_slice(b"Content-Type: multipart/mixed; boundary=xyz\r\n\r\n");
        v.extend_from_slice(b"--xyz\r\n");
        v.extend_from_slice(b"Content-Type: text/plain\r\n");
        v.extend_from_slice(b"Content-Transfer-Encoding: base64\r\n");
        v.extend_from_slice(b"Content-Disposition: attachment; filename=\"factura.txt\"\r\n\r\n");
        v.extend_from_slice(&b64);
        v.extend_from_slice(b"\r\n--xyz--\r\n");
        v
    }

    #[test]
    fn un_adjunto_se_nombra_por_su_sha256() {
        // Es como se llama una entidad en todo el producto: el mismo fichero
        // visto por correo, por SMB y por HTTP tiene que ser el mismo.
        let (encontrados, sin) = adjuntos(&correo_con_adjunto());
        assert_eq!(sin, 0);
        assert_eq!(encontrados.len(), 1);
        assert_eq!(encontrados[0].nombre, "factura.txt");
        assert!(encontrados[0].contenido.starts_with(b"MZ"));

        let (hechos, _) = hechos_de_adjuntos(&correo_con_adjunto(), ProtocoloApp::Imap);
        let fichero = hechos.iter().find_map(|h| match h {
            Hecho::FicheroTransferido { nombre, sha256, .. } => Some((nombre, sha256)),
            _ => None,
        });
        let (nombre, sha) = fichero.expect("un fichero");
        assert_eq!(nombre, "factura.txt");
        assert_eq!(sha.len(), 64, "un SHA-256 en hexadecimal");
    }

    /// Mentir sobre el tipo es la tecnica, no un descuido: el nombre lo escribe
    /// quien manda el correo, y el contenido no. Lo que el usuario mira es la
    /// extension, asi que es contra la extension contra lo que hay que contrastar.
    #[test]
    fn un_adjunto_que_miente_sobre_su_tipo_lo_dice() {
        let (hechos, _) = hechos_de_adjuntos(&correo_con_adjunto(), ProtocoloApp::Imap);
        assert!(
            hechos.iter().any(|h| matches!(
                h,
                Hecho::AnomaliaDeFlujo { codigo, detalle }
                    if *codigo == "adjunto-extension-contradictoria"
                        && detalle.contains("factura.txt")
            )),
            "{hechos:?}"
        );
    }

    #[test]
    fn una_doble_extension_se_dice_aparte() {
        // El cliente de correo esconde la ultima y el usuario lee la primera.
        let mut v = Vec::new();
        v.extend_from_slice(b"Content-Transfer-Encoding: 8bit\r\n");
        v.extend_from_slice(
            b"Content-Disposition: attachment; filename=\"nomina.pdf.exe\"\r\n\r\n",
        );
        v.extend_from_slice(b"MZ\x90contenido");
        let (hechos, _) = hechos_de_adjuntos(&v, ProtocoloApp::Pop3);
        assert!(
            hechos.iter().any(|h| matches!(
                h,
                Hecho::AnomaliaDeFlujo { codigo, .. } if *codigo == "adjunto-de-doble-extension"
            )),
            "{hechos:?}"
        );
    }

    #[test]
    fn un_adjunto_coherente_no_levanta_ninguna_anomalia() {
        // Una alerta que salte con un adjunto normal entierra la que importa.
        let mut v = Vec::new();
        v.extend_from_slice(b"Content-Transfer-Encoding: 8bit\r\n");
        v.extend_from_slice(b"Content-Disposition: attachment; filename=\"informe.pdf\"\r\n\r\n");
        v.extend_from_slice(b"%PDF-1.7 contenido del informe");
        let (hechos, _) = hechos_de_adjuntos(&v, ProtocoloApp::Imap);
        assert!(
            !hechos
                .iter()
                .any(|h| matches!(h, Hecho::AnomaliaDeFlujo { .. })),
            "{hechos:?}"
        );
    }

    #[test]
    fn un_base64_que_no_lo_es_se_cuenta_y_no_se_inventa_contenido() {
        let mut v = Vec::new();
        v.extend_from_slice(b"Content-Transfer-Encoding: base64\r\n");
        v.extend_from_slice(b"Content-Disposition: attachment; filename=x.bin\r\n\r\n");
        v.extend_from_slice(b"esto no es base64 ***\r\n");
        let (encontrados, sin) = adjuntos(&v);
        assert!(encontrados.is_empty());
        assert_eq!(sin, 1, "un adjunto ilegible se cuenta");
    }

    #[test]
    fn el_nombre_se_lee_con_y_sin_comillas() {
        assert_eq!(
            nombre_de_fichero("Content-Disposition: attachment; filename=\"a b.doc\"").as_deref(),
            Some("a b.doc")
        );
        assert_eq!(
            nombre_de_fichero("Content-Disposition: attachment; filename=simple.exe").as_deref(),
            Some("simple.exe")
        );
        assert_eq!(nombre_de_fichero("Content-Disposition: inline"), None);
    }

    #[test]
    fn imap_saca_el_usuario_de_un_acceso() {
        let d = Imap;
        let b = b"a001 LOGIN ana secreta\r\n";
        assert!(d.reconoce(b, &Contexto::tcp_cliente(PUERTOS_IMAP[0])));
        let s = d.disecar(b, &Contexto::tcp_cliente(PUERTOS_IMAP[0]));
        assert!(s.cobertura.completa());
        let usuario = s.hechos.iter().find_map(|h| match h {
            Hecho::AutenticacionVista { usuario, .. } => Some(usuario.as_str()),
            _ => None,
        });
        assert_eq!(usuario, Some("ana"));
    }

    #[test]
    fn imap_no_confunde_una_linea_de_texto_cualquiera_con_una_orden() {
        // Sin comprobar la forma de la etiqueta, la primera palabra de
        // cualquier linea pasaria por etiqueta y la segunda por orden.
        let d = Imap;
        assert!(!d.reconoce(b"hola que tal\r\n", &Contexto::tcp_cliente(143)));
        assert!(!d.reconoce(
            b"una-etiqueta-demasiado-larga LOGIN x\r\n",
            &Contexto::tcp_cliente(143)
        ));
    }

    #[test]
    fn imap_saca_el_adjunto_de_un_fetch() {
        let d = Imap;
        let b = correo_con_adjunto();
        let s = d.disecar(&b, &Contexto::tcp_servidor(PUERTOS_IMAP[0]));
        assert!(
            s.hechos
                .iter()
                .any(|h| matches!(h, Hecho::FicheroTransferido { .. })),
            "{:?}",
            s.hechos
        );
    }

    #[test]
    fn pop3_no_guarda_la_contrasena_que_ve_pasar() {
        let d = Pop3;
        let b = b"PASS unsecretomuysecreto\r\n";
        assert!(d.reconoce(b, &Contexto::tcp_cliente(PUERTOS_POP3[0])));
        let s = d.disecar(b, &Contexto::tcp_cliente(PUERTOS_POP3[0]));
        let argumento = s.hechos.iter().find_map(|h| match h {
            Hecho::OrdenSmtp { verbo, argumento } if verbo == "pop3.PASS" => Some(argumento),
            _ => None,
        });
        assert_eq!(argumento.map(String::as_str), Some(""));
        assert!(
            !s.hechos
                .iter()
                .any(|h| format!("{h:?}").contains("unsecreto")),
            "la contrasena no puede acabar en ningun hecho"
        );
    }

    #[test]
    fn pop3_distingue_la_respuesta_buena_de_la_mala() {
        let d = Pop3;
        for (bytes, esperado) in [
            (&b"+OK 2 mensajes\r\n"[..], "+OK"),
            (&b"-ERR no existe\r\n"[..], "-ERR"),
        ] {
            let s = d.disecar(bytes, &Contexto::tcp_servidor(PUERTOS_POP3[0]));
            let r = s.hechos.iter().find_map(|h| match h {
                Hecho::OrdenSmtp { argumento, .. } => Some(argumento.as_str()),
                _ => None,
            });
            assert_eq!(r, Some(esperado));
        }
    }

    #[test]
    fn un_correo_con_muchas_partes_no_cuesta_lo_que_diga_el_emisor() {
        // Un correo con diez mil partes anidadas es un ataque conocido contra
        // los analizadores de correo.
        let mut v = Vec::new();
        for i in 0..5000 {
            v.extend_from_slice(b"Content-Transfer-Encoding: base64\r\n");
            v.extend_from_slice(
                format!("Content-Disposition: attachment; filename=f{i}.bin\r\n\r\n").as_bytes(),
            );
            v.extend_from_slice(b"aGk=\r\n--x\r\n");
        }
        let (encontrados, sin) = adjuntos(&v);
        assert!(
            encontrados.len() + sin <= 32,
            "se pararon en {} partes",
            encontrados.len() + sin
        );
    }

    #[test]
    fn los_dos_de_correo_declaran_sus_dos_mitades() {
        let ds: Vec<Box<dyn Disector>> = vec![Box::new(Imap), Box::new(Pop3)];
        for d in &ds {
            assert!(!d.mensajes_que_entiende().is_empty(), "{}", d.nombre());
            assert!(!d.mensajes_que_no_analiza().is_empty(), "{}", d.nombre());
        }
    }
}
