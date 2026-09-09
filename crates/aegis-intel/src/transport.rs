//! Transporte de las consultas.
//!
//! # Por que es un rasgo
//!
//! El transporte de produccion es TLS 1.3 con Encrypted Client Hello, de modo
//! que ni el SNI revele que servicio se esta consultando, y por delante un rele
//! de Oblivious HTTP para que quien ve la IP no vea el contenido. Esa pila
//! depende de la plataforma y del despliegue.
//!
//! Lo que NO depende de nada de eso es el resto del modulo: el reparto entre
//! prefijo y sufijo, el formato, la comparacion local y la cache. Separandolo
//! por un rasgo, esa parte — que es donde vive la propiedad de privacidad — se
//! ejercita entera contra un servidor de verdad en `127.0.0.1`, sin red
//! externa y sin certificados.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Error de transporte.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// Fallo de entrada/salida.
    #[error("error de E/S hablando con {endpoint}: {detail}")]
    Io {
        /// Servidor.
        endpoint: String,
        /// Causa.
        detail: std::io::Error,
    },
    /// El servidor respondio con un codigo de error.
    #[error("el servidor respondio {status}")]
    Status {
        /// Codigo HTTP.
        status: u16,
    },
    /// Respuesta que no se pudo interpretar.
    #[error("respuesta ininteligible: {0}")]
    Protocol(String),
    /// La respuesta excede el limite.
    #[error("respuesta de {size} bytes, limite {limit}")]
    TooLarge {
        /// Tamano anunciado o leido.
        size: usize,
        /// Limite.
        limit: usize,
    },
}

/// Tamano maximo de respuesta que se acepta.
///
/// Un cubo de 20 bits ronda los 70 KB en este formato. Un megabyte deja margen
/// de sobra y acota lo que un servidor hostil puede hacerle a la memoria del
/// agente.
pub const RESPUESTA_MAX: usize = 1024 * 1024;

/// Como se hace llegar una consulta al servicio de reputacion.
pub trait Transport: std::fmt::Debug {
    /// Recupera el cuerpo de la ruta indicada.
    fn fetch(&self, path: &str) -> Result<String, TransportError>;
}

/// Cliente HTTP/1.1 minimo sobre TCP.
///
/// No es un cliente HTTP de proposito general y no pretende serlo: habla
/// exactamente el subconjunto que este protocolo necesita — un GET, cabeceras
/// de respuesta, `Content-Length` o `Transfer-Encoding: chunked` — y rechaza
/// todo lo demas. Un cliente completo seria mas dependencias y mas superficie
/// de ataque para un consumidor que solo hace una peticion de una linea.
#[derive(Debug, Clone)]
pub struct HttpTransport {
    /// `host:puerto`.
    pub endpoint: String,
    /// Valor de la cabecera `Host`.
    pub host: String,
    /// Plazo de conexion y lectura.
    pub timeout: Duration,
}

impl HttpTransport {
    /// Crea un transporte contra `endpoint` (`host:puerto`).
    pub fn new(endpoint: impl Into<String>) -> HttpTransport {
        let endpoint = endpoint.into();
        HttpTransport {
            host: endpoint.clone(),
            endpoint,
            // Corto a proposito: la consulta de reputacion NUNCA esta en la
            // ruta de decision, asi que esperar es puro coste. Si el servicio
            // no responde en dos segundos, se decide con lo local.
            timeout: Duration::from_secs(2),
        }
    }

    fn io_err(&self, e: std::io::Error) -> TransportError {
        TransportError::Io {
            endpoint: self.endpoint.clone(),
            detail: e,
        }
    }
}

impl Transport for HttpTransport {
    fn fetch(&self, path: &str) -> Result<String, TransportError> {
        let dir = self
            .endpoint
            .to_socket_addrs()
            .map_err(|e| self.io_err(e))?
            .next()
            .ok_or_else(|| TransportError::Protocol("el endpoint no resuelve".into()))?;

        let flujo = TcpStream::connect_timeout(&dir, self.timeout).map_err(|e| self.io_err(e))?;
        flujo
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| self.io_err(e))?;
        flujo
            .set_write_timeout(Some(self.timeout))
            .map_err(|e| self.io_err(e))?;

        let mut w = flujo.try_clone().map_err(|e| self.io_err(e))?;
        // Sin User-Agent, sin cookies, sin nada que distinga a este cliente de
        // otro: una cabecera caracteristica reintroduce por la puerta de atras
        // la correlacion que el k-anonimato acaba de quitar.
        let peticion = format!(
            "GET {path} HTTP/1.1\r\nHost: {}\r\nAccept: text/plain\r\nConnection: close\r\n\r\n",
            self.host
        );
        w.write_all(peticion.as_bytes())
            .map_err(|e| self.io_err(e))?;
        w.flush().map_err(|e| self.io_err(e))?;

        leer_respuesta(BufReader::new(flujo)).map_err(|e| match e {
            LeerError::Io(e) => self.io_err(e),
            LeerError::Transporte(t) => t,
        })
    }
}

enum LeerError {
    Io(std::io::Error),
    Transporte(TransportError),
}

impl From<std::io::Error> for LeerError {
    fn from(e: std::io::Error) -> LeerError {
        LeerError::Io(e)
    }
}

fn leer_respuesta<R: Read>(mut r: BufReader<R>) -> Result<String, LeerError> {
    let mut linea = String::new();
    r.read_line(&mut linea)?;
    let estado = linea
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| {
            LeerError::Transporte(TransportError::Protocol(format!(
                "linea de estado ininteligible: {:?}",
                linea.trim()
            )))
        })?;

    let mut longitud: Option<usize> = None;
    let mut troceado = false;
    loop {
        let mut h = String::new();
        let n = r.read_line(&mut h)?;
        if n == 0 {
            return Err(LeerError::Transporte(TransportError::Protocol(
                "cabeceras sin terminar".into(),
            )));
        }
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        let Some((k, v)) = h.split_once(':') else {
            continue;
        };
        let k = k.trim().to_ascii_lowercase();
        let v = v.trim();
        if k == "content-length" {
            longitud = v.parse::<usize>().ok();
        } else if k == "transfer-encoding" && v.eq_ignore_ascii_case("chunked") {
            troceado = true;
        }
    }

    if estado != 200 {
        return Err(LeerError::Transporte(TransportError::Status {
            status: estado,
        }));
    }

    let cuerpo = if troceado {
        leer_troceado(&mut r)?
    } else {
        match longitud {
            Some(n) if n > RESPUESTA_MAX => {
                return Err(LeerError::Transporte(TransportError::TooLarge {
                    size: n,
                    limit: RESPUESTA_MAX,
                }))
            }
            Some(n) => {
                let mut buf = vec![0u8; n];
                r.read_exact(&mut buf)?;
                buf
            }
            // Sin longitud: se lee hasta el cierre, siempre acotado.
            None => {
                let mut buf = Vec::new();
                r.take(RESPUESTA_MAX as u64 + 1).read_to_end(&mut buf)?;
                if buf.len() > RESPUESTA_MAX {
                    return Err(LeerError::Transporte(TransportError::TooLarge {
                        size: buf.len(),
                        limit: RESPUESTA_MAX,
                    }));
                }
                buf
            }
        }
    };

    String::from_utf8(cuerpo)
        .map_err(|e| LeerError::Transporte(TransportError::Protocol(e.to_string())))
}

fn leer_troceado<R: Read>(r: &mut BufReader<R>) -> Result<Vec<u8>, LeerError> {
    let mut salida = Vec::new();
    loop {
        let mut cab = String::new();
        if r.read_line(&mut cab)? == 0 {
            return Err(LeerError::Transporte(TransportError::Protocol(
                "trozo sin cabecera".into(),
            )));
        }
        // El tamano puede llevar extensiones tras un punto y coma.
        let tam_txt = cab.trim().split(';').next().unwrap_or("").trim();
        let tam = usize::from_str_radix(tam_txt, 16).map_err(|_| {
            LeerError::Transporte(TransportError::Protocol(format!(
                "tamano de trozo ininteligible: {tam_txt:?}"
            )))
        })?;
        if tam == 0 {
            // Remolque y linea en blanco final.
            loop {
                let mut t = String::new();
                if r.read_line(&mut t)? == 0 || t.trim().is_empty() {
                    break;
                }
            }
            break;
        }
        if salida.len() + tam > RESPUESTA_MAX {
            return Err(LeerError::Transporte(TransportError::TooLarge {
                size: salida.len() + tam,
                limit: RESPUESTA_MAX,
            }));
        }
        let mut buf = vec![0u8; tam];
        r.read_exact(&mut buf)?;
        salida.extend_from_slice(&buf);
        // CRLF de cierre del trozo.
        let mut fin = [0u8; 2];
        r.read_exact(&mut fin)?;
    }
    Ok(salida)
}
