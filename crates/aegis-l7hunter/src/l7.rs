//! Analisis de la capa 7 sobre el texto en claro que entregan los uprobes.
//!
//! # Que se busca aqui, y que no
//!
//! La periodicidad la decide [`crate::baliza`] con la serie temporal. Este
//! modulo aporta la otra mitad: **que** se esta diciendo. Las dos hacen falta,
//! porque cada una sola produce falsos positivos que la otra descarta:
//!
//! - Un agente de monitorizacion legitimo es PERFECTAMENTE periodico. Por la
//!   serie temporal es indistinguible de una baliza sin jitter; por el contenido,
//!   no se parece en nada.
//! - Una baliza con jitter alto y trafico irregular puede colarse por la serie,
//!   pero su contenido sigue teniendo la forma de una baliza.
//!
//! # Este modulo analiza datos del atacante
//!
//! La carga util viene, literalmente, del canal de un implante. Todo el parseo
//! esta acotado, no reserva memoria en funcion de longitudes declaradas por el
//! par, y no entra en panico con ninguna entrada. Un analizador de protocolo que
//! se cae con un mensaje malformado es una via de denegacion contra el EDR.

use std::collections::BTreeMap;

/// Maximo de cabeceras que se analizan de un mensaje.
///
/// Un mensaje con diez mil cabeceras es un ataque de agotamiento, no trafico.
/// Se analizan las primeras y se DECLARA que se recorto ([`MensajeL7::recortado`]).
pub const MAX_CABECERAS: usize = 64;

/// Longitud maxima de una cabecera que se conserva.
pub const MAX_VALOR_CABECERA: usize = 512;

/// Que protocolo se reconocio dentro del TLS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocolo {
    /// Peticion HTTP/1.x.
    HttpPeticion,
    /// Respuesta HTTP/1.x.
    HttpRespuesta,
    /// El preambulo de conexion de HTTP/2.
    Http2Preambulo,
    /// Datos binarios que no son HTTP.
    ///
    /// NO es una categoria de descarte: un canal binario propio dentro de TLS es
    /// **en si mismo** una senal. El trafico legitimo sobre TLS es
    /// abrumadoramente HTTP; un protocolo a medida es lo que usa un implante que
    /// no quiere parecerse a nada conocido.
    Desconocido,
}

/// Un mensaje L7 analizado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MensajeL7 {
    /// Que se reconocio.
    pub protocolo: Protocolo,
    /// Metodo HTTP, si es una peticion.
    pub metodo: Option<String>,
    /// Ruta pedida, si es una peticion.
    pub uri: Option<String>,
    /// Codigo de estado, si es una respuesta.
    pub estado: Option<u16>,
    /// Cabeceras, con el nombre en minusculas para que la busqueda sea estable
    /// (HTTP no distingue mayusculas en los nombres, y un implante puede usar
    /// `hOsT` justo para saltarse una comparacion ingenua).
    pub cabeceras: BTreeMap<String, String>,
    /// `true` si se dejaron cabeceras sin analizar por la cota.
    pub recortado: bool,
}

impl MensajeL7 {
    /// Una cabecera por nombre (que se busca en minusculas).
    #[must_use]
    pub fn cabecera(&self, nombre: &str) -> Option<&str> {
        self.cabeceras
            .get(&nombre.to_ascii_lowercase())
            .map(String::as_str)
    }

    /// El `Host` de la peticion.
    #[must_use]
    pub fn host(&self) -> Option<&str> {
        self.cabecera("host")
    }

    /// El `User-Agent`.
    #[must_use]
    pub fn agente(&self) -> Option<&str> {
        self.cabecera("user-agent")
    }

    /// `true` si es HTTP en cualquiera de sus formas.
    #[must_use]
    pub const fn es_http(&self) -> bool {
        matches!(
            self.protocolo,
            Protocolo::HttpPeticion | Protocolo::HttpRespuesta | Protocolo::Http2Preambulo
        )
    }
}

/// El preambulo obligatorio con el que empieza toda conexion HTTP/2 en claro.
const PREAMBULO_H2: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Metodos HTTP reconocidos. Un mensaje que empieza por otra cosa no es una
/// peticion, y tratarlo como tal produciria un metodo inventado a partir de
/// bytes binarios.
const METODOS: &[&str] = &[
    "GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "PATCH", "TRACE", "CONNECT",
];

/// Analiza un mensaje en claro.
///
/// Nunca falla: lo que no se reconoce es [`Protocolo::Desconocido`], que es una
/// respuesta util y no un error. Un implante con protocolo propio tiene que
/// producir un veredicto, no una excepcion.
#[must_use]
pub fn analizar(carga: &[u8]) -> MensajeL7 {
    let mut m = MensajeL7 {
        protocolo: Protocolo::Desconocido,
        metodo: None,
        uri: None,
        estado: None,
        cabeceras: BTreeMap::new(),
        recortado: false,
    };

    if carga.starts_with(PREAMBULO_H2) {
        m.protocolo = Protocolo::Http2Preambulo;
        return m;
    }

    // La primera linea decide. Se busca el CRLF, y se acota: sin cota, un flujo
    // binario de un megabyte sin ningun \r\n se recorreria entero por nada.
    let fin_linea = carga
        .iter()
        .take(8192)
        .position(|b| *b == b'\n')
        .unwrap_or(0);
    if fin_linea == 0 {
        return m;
    }
    let primera = recortar_cr(&carga[..fin_linea]);
    let Ok(primera) = std::str::from_utf8(primera) else {
        // Bytes no-UTF8 en la primera linea: no es HTTP en claro.
        return m;
    };

    if let Some(estado) = estado_de_respuesta(primera) {
        m.protocolo = Protocolo::HttpRespuesta;
        m.estado = Some(estado);
    } else if let Some((metodo, uri)) = peticion(primera) {
        m.protocolo = Protocolo::HttpPeticion;
        m.metodo = Some(metodo.to_string());
        m.uri = Some(uri.chars().take(MAX_VALOR_CABECERA).collect());
    } else {
        return m;
    }

    // Cabeceras: hasta la linea vacia, con cota.
    let mut resto = &carga[fin_linea + 1..];
    for _ in 0..MAX_CABECERAS {
        let Some(n) = resto.iter().position(|b| *b == b'\n') else {
            break;
        };
        let linea = recortar_cr(&resto[..n]);
        resto = &resto[n + 1..];
        if linea.is_empty() {
            // Fin de cabeceras: empieza el cuerpo.
            return m;
        }
        let Ok(linea) = std::str::from_utf8(linea) else {
            continue;
        };
        let Some((nombre, valor)) = linea.split_once(':') else {
            continue;
        };
        let nombre = nombre.trim().to_ascii_lowercase();
        if nombre.is_empty() {
            continue;
        }
        let valor: String = valor.trim().chars().take(MAX_VALOR_CABECERA).collect();
        m.cabeceras.insert(nombre, valor);
    }
    // Se salio por la cota y aun quedaban cabeceras.
    m.recortado = resto.contains(&b'\n');
    m
}

/// Quita el `\r` final de una linea terminada en CRLF.
fn recortar_cr(linea: &[u8]) -> &[u8] {
    match linea.last() {
        Some(b'\r') => &linea[..linea.len() - 1],
        _ => linea,
    }
}

/// `HTTP/1.1 200 OK` -> `Some(200)`.
fn estado_de_respuesta(linea: &str) -> Option<u16> {
    let resto = linea.strip_prefix("HTTP/")?;
    let (_version, resto) = resto.split_once(' ')?;
    let codigo = resto.split_whitespace().next()?;
    let n: u16 = codigo.parse().ok()?;
    // Un codigo fuera del rango del estandar no es una respuesta HTTP: es un
    // flujo binario que empieza por algo que se le parece.
    (100..=599).contains(&n).then_some(n)
}

/// `GET /ruta HTTP/1.1` -> `Some(("GET", "/ruta"))`.
fn peticion(linea: &str) -> Option<(&str, &str)> {
    let mut partes = linea.split(' ');
    let metodo = partes.next()?;
    if !METODOS.contains(&metodo) {
        return None;
    }
    let uri = partes.next()?;
    let version = partes.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    Some((metodo, uri))
}

/// Entropia de Shannon de una secuencia de bytes, en bits por byte (`0.0..=8.0`).
///
/// Sirve para dos cosas concretas:
///
/// - Un valor de cookie o un segmento de URI con entropia alta es datos
///   codificados, no texto: es como viaja la metadata de un implante.
/// - Una carga util entera con entropia cercana a 8 dentro de un canal que dice
///   ser HTTP es contenido cifrado DOS veces: cifrado por el implante y despues
///   por el TLS. El trafico legitimo no hace eso.
#[must_use]
pub fn entropia(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut cuenta = [0u32; 256];
    for b in bytes {
        cuenta[*b as usize] += 1;
    }
    let n = bytes.len() as f64;
    -cuenta
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = f64::from(*c) / n;
            p * p.log2()
        })
        .sum::<f64>()
}

/// `true` si el texto parece datos codificados en base64/base64url.
///
/// Es la forma en que los implantes llevan su metadata dentro de una cookie o de
/// un segmento de URI. Se exige longitud minima y alfabeto: una palabra corta de
/// letras y numeros tambien "parece" base64 y marcarla seria ruido.
#[must_use]
pub fn parece_base64(texto: &str) -> bool {
    const MINIMO: usize = 16;
    if texto.len() < MINIMO {
        return false;
    }
    let valido = texto
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'-' | b'_' | b'='));
    if !valido {
        return false;
    }
    // Ademas tiene que MEZCLAR: una cadena de solo digitos (un identificador) o
    // de solo letras (una palabra) pasa el alfabeto y no es base64.
    let digitos = texto.bytes().filter(u8::is_ascii_digit).count();
    let letras = texto.bytes().filter(u8::is_ascii_alphabetic).count();
    digitos > 0 && letras > 0 && (digitos + letras) * 10 >= texto.len() * 8
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn una_peticion_http_se_analiza_entera() {
        let m = analizar(
            b"GET /api/v1/datos?id=7 HTTP/1.1\r\n\
              Host: ejemplo.corp\r\n\
              User-Agent: Mozilla/5.0 (X11; Linux x86_64)\r\n\
              Accept: */*\r\n\
              \r\n\
              cuerpo que no es cabecera",
        );
        assert_eq!(m.protocolo, Protocolo::HttpPeticion);
        assert_eq!(m.metodo.as_deref(), Some("GET"));
        assert_eq!(m.uri.as_deref(), Some("/api/v1/datos?id=7"));
        assert_eq!(m.host(), Some("ejemplo.corp"));
        assert!(m.agente().unwrap().starts_with("Mozilla/5.0"));
        assert!(!m.recortado);
    }

    #[test]
    fn una_respuesta_http_se_distingue_de_una_peticion() {
        let m = analizar(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(m.protocolo, Protocolo::HttpRespuesta);
        assert_eq!(m.estado, Some(404));
        assert_eq!(m.cabecera("content-length"), Some("0"));
        assert!(m.metodo.is_none());
    }

    /// HTTP no distingue mayusculas en los nombres de cabecera, y un implante
    /// puede usar `hOsT` precisamente para saltarse una comparacion ingenua.
    #[test]
    fn el_nombre_de_cabecera_no_distingue_mayusculas() {
        let m = analizar(b"GET / HTTP/1.1\r\nhOsT: c2.malo\r\nUSER-AGENT: x\r\n\r\n");
        assert_eq!(m.host(), Some("c2.malo"));
        assert_eq!(m.agente(), Some("x"));
    }

    #[test]
    fn el_preambulo_de_http2_se_reconoce() {
        let m = analizar(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00");
        assert_eq!(m.protocolo, Protocolo::Http2Preambulo);
        assert!(m.es_http());
    }

    /// Un protocolo binario propio NO es un descarte: es una senal. El trafico
    /// legitimo sobre TLS es abrumadoramente HTTP.
    #[test]
    fn un_protocolo_binario_propio_se_clasifica_en_vez_de_fallar() {
        let m = analizar(&[0x17, 0x03, 0x03, 0x00, 0x2a, 0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(m.protocolo, Protocolo::Desconocido);
        assert!(!m.es_http());
        assert!(m.metodo.is_none() && m.estado.is_none());
    }

    // -----------------------------------------------------------------------
    // Entrada hostil
    // -----------------------------------------------------------------------

    #[test]
    fn ninguna_entrada_puede_provocar_un_panico() {
        let casos: Vec<Vec<u8>> = vec![
            vec![],
            b"GET".to_vec(),
            b"GET ".to_vec(),
            b"GET /".to_vec(),
            b"HTTP/".to_vec(),
            b"HTTP/1.1 ".to_vec(),
            b"HTTP/1.1 99999 x\r\n\r\n".to_vec(),
            b"\n".to_vec(),
            b"\r\n\r\n".to_vec(),
            b":\r\n".to_vec(),
            b"GET / HTTP/1.1\r\n:sinnombre\r\n\r\n".to_vec(),
            vec![0xFF; 4096],
            vec![b'\n'; 4096],
            // Una primera linea enorme sin terminador.
            vec![b'A'; 100_000],
        ];
        for c in casos {
            let _ = analizar(&c);
        }
    }

    /// Un mensaje con diez mil cabeceras es agotamiento de recursos, no trafico.
    /// Se acota Y SE DECLARA: un analisis recortado que no lo dice haria creer
    /// que la cabecera buscada no estaba.
    #[test]
    fn un_mensaje_con_cabeceras_desmesuradas_se_acota_y_se_declara() {
        let mut m = b"GET / HTTP/1.1\r\n".to_vec();
        for i in 0..(MAX_CABECERAS * 3) {
            m.extend_from_slice(format!("X-Relleno-{i}: v\r\n").as_bytes());
        }
        m.extend_from_slice(b"\r\n");
        let a = analizar(&m);
        assert_eq!(a.protocolo, Protocolo::HttpPeticion);
        assert!(a.cabeceras.len() <= MAX_CABECERAS);
        assert!(a.recortado, "el recorte tiene que declararse");
    }

    #[test]
    fn un_valor_de_cabecera_enorme_no_se_guarda_entero() {
        let mut m = b"GET / HTTP/1.1\r\nCookie: ".to_vec();
        m.extend(std::iter::repeat_n(b'A', 100_000));
        m.extend_from_slice(b"\r\n\r\n");
        let a = analizar(&m);
        assert!(a.cabecera("cookie").unwrap().len() <= MAX_VALOR_CABECERA);
    }

    /// Un flujo binario que EMPIEZA por algo parecido a HTTP no puede
    /// clasificarse como HTTP: produciria un metodo o un estado inventado a
    /// partir de bytes que no lo son.
    #[test]
    fn lo_que_solo_se_parece_a_http_no_cuenta_como_http() {
        assert_eq!(
            analizar(b"GETX / HTTP/1.1\r\n\r\n").protocolo,
            Protocolo::Desconocido
        );
        assert_eq!(
            analizar(b"GET / FTP/1.1\r\n\r\n").protocolo,
            Protocolo::Desconocido
        );
        assert_eq!(
            analizar(b"HTTP/1.1 42 x\r\n\r\n").protocolo,
            Protocolo::Desconocido
        );
        assert_eq!(
            analizar(b"HTTP/1.1 600 x\r\n\r\n").protocolo,
            Protocolo::Desconocido
        );
        // Y los codigos del estandar, si.
        assert_eq!(analizar(b"HTTP/1.1 100 x\r\n\r\n").estado, Some(100));
        assert_eq!(analizar(b"HTTP/1.1 599 x\r\n\r\n").estado, Some(599));
    }

    // -----------------------------------------------------------------------
    // Entropia y codificacion
    // -----------------------------------------------------------------------

    #[test]
    fn la_entropia_separa_texto_de_datos_cifrados() {
        // Texto: baja entropia.
        let texto = b"GET /index.html HTTP/1.1\r\nHost: www.ejemplo.com\r\n";
        assert!(entropia(texto) < 5.0, "{}", entropia(texto));

        // Todos los bytes una vez: la entropia maxima es exactamente 8.
        let uniforme: Vec<u8> = (0..=255u8).collect();
        assert!((entropia(&uniforme) - 8.0).abs() < 1e-12);

        // Un solo simbolo repetido: entropia cero.
        assert_eq!(entropia(&[0x41; 1000]), 0.0);
        assert_eq!(entropia(&[]), 0.0);
    }

    #[test]
    fn el_reconocimiento_de_base64_no_marca_texto_normal() {
        // La metadata de un implante en una cookie.
        assert!(parece_base64("aGVsbG8gd29ybGQgMTIzNDU2Nzg5"));
        assert!(parece_base64("dXNlcj1hZG1pbjtob3N0PVdJTjEw"));

        // Y lo que NO puede marcar, o seria ruido puro:
        assert!(!parece_base64("corto"), "demasiado corto");
        assert!(
            !parece_base64("sessionidentifier"),
            "solo letras: es una palabra"
        );
        assert!(
            !parece_base64("12345678901234567890"),
            "solo digitos: es un id"
        );
        assert!(!parece_base64("hola mundo con espacios"), "espacios");
        assert!(!parece_base64("/api/v1/usuarios/42"), "una ruta normal");
    }
}
