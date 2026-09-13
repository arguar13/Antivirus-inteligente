//! Disector de HTTP/1.1, con deteccion de contrabando de peticiones.
//!
//! # El ataque que este modulo mira: el contrabando de peticiones
//!
//! HTTP/1.1 tiene **dos** formas de decir donde acaba un cuerpo: la cabecera
//! `Content-Length` y la codificacion `Transfer-Encoding: chunked`. La norma dice
//! que si vienen las dos, manda `Transfer-Encoding` — pero no todas las
//! implementaciones lo hacen igual.
//!
//! Ahi nace el *request smuggling*: el atacante manda un mensaje con las dos, el
//! proxy de delante lo interpreta de una forma y el servidor de detras de otra,
//! y lo que para uno es «el cuerpo» para el otro es «la siguiente peticion». El
//! resultado es una peticion que el proxy —y el IDS— nunca vieron.
//!
//! Un disector que elija en silencio una de las dos interpretaciones es
//! **exactamente** el eslabon que hace posible el ataque. Aqui se emite una
//! anomalia con nombre en cuanto aparecen juntas, y ademas se marcan las
//! variantes de ofuscacion conocidas: `Transfer-Encoding` duplicada, con espacio
//! antes de los dos puntos, o con un valor que no es `chunked` exactamente.
//!
//! # Las cotas, porque el cliente escribe las cabeceras
//!
//! Numero de cabeceras, tamano de cada una, tamano de la linea inicial y numero
//! de trozos: todo acotado. Sin eso, una peticion con cien mil cabeceras de un
//! kilobyte hace que el sensor reserve cien megas por conexion, y basta con
//! abrir unas cuantas.

use crate::hecho::{Hecho, ProtocoloApp};
use crate::lector::ascii_legible;

/// Tope de cabeceras por mensaje.
pub const MAX_CABECERAS: usize = 200;

/// Tope de bytes de una linea (inicial o de cabecera).
pub const MAX_LINEA: usize = 8 * 1024;

/// Tope de bytes de cabeceras en total.
pub const MAX_CABECERAS_BYTES: usize = 64 * 1024;

/// Metodos que se reconocen como inicio de peticion.
///
/// La lista es cerrada a proposito: aceptar cualquier palabra como metodo hace
/// que el disector vea peticiones HTTP en trafico binario cualquiera, y a partir
/// de ahi todo lo que emita es ruido.
pub const METODOS: &[&str] = &[
    "GET",
    "POST",
    "HEAD",
    "PUT",
    "DELETE",
    "OPTIONS",
    "TRACE",
    "CONNECT",
    "PATCH",
    "PROPFIND",
    "PROPPATCH",
    "MKCOL",
    "COPY",
    "MOVE",
    "LOCK",
    "UNLOCK",
    "SEARCH",
];

/// Un mensaje HTTP ya separado en sus partes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mensaje {
    /// La linea inicial, tal cual.
    pub linea: String,
    /// Las cabeceras, en orden de aparicion y con su capitalizacion original.
    pub cabeceras: Vec<(String, String)>,
    /// Donde empieza el cuerpo dentro del buffer.
    pub inicio_cuerpo: usize,
    /// Anomalias observadas al separar.
    pub anomalias: Vec<(&'static str, String)>,
}

impl Mensaje {
    /// El valor de una cabecera, sin distinguir mayusculas.
    ///
    /// Devuelve el **primero**, y si hay varios con el mismo nombre lo anota
    /// quien separa el mensaje: cabeceras duplicadas donde no deberia haberlas
    /// son la base de varias tecnicas de contrabando.
    #[must_use]
    pub fn cabecera(&self, nombre: &str) -> Option<&str> {
        self.cabeceras
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(nombre))
            .map(|(_, v)| v.as_str())
    }

    /// Cuantas veces aparece una cabecera.
    #[must_use]
    pub fn veces(&self, nombre: &str) -> usize {
        self.cabeceras
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(nombre))
            .count()
    }
}

/// Separa un mensaje HTTP en linea inicial, cabeceras y cuerpo.
///
/// Devuelve `None` si todavia no llego el final de las cabeceras: en un flujo
/// reensamblado eso es normal, y esperar es lo correcto.
#[must_use]
pub fn separar(datos: &[u8]) -> Option<Mensaje> {
    // El final de las cabeceras es CRLF CRLF. Se acepta tambien LF LF porque hay
    // implementaciones que lo mandan asi, y un IDS que no lo acepte deja de ver
    // ese trafico — que es precisamente lo que busca quien lo manda asi.
    let (fin_cabeceras, salto) = match buscar(datos, b"\r\n\r\n") {
        Some(p) => (p, 4),
        None => match buscar(datos, b"\n\n") {
            Some(p) => (p, 2),
            None => return None,
        },
    };
    if fin_cabeceras > MAX_CABECERAS_BYTES {
        return Some(Mensaje {
            linea: String::new(),
            cabeceras: Vec::new(),
            inicio_cuerpo: fin_cabeceras + salto,
            anomalias: vec![(
                "http-cabeceras-desmesuradas",
                format!("{fin_cabeceras} bytes de cabeceras"),
            )],
        });
    }

    let bloque = &datos[..fin_cabeceras];
    let mut lineas = bloque.split(|&b| b == b'\n');
    let mut anomalias = Vec::new();

    let linea = lineas
        .next()
        .map(|l| ascii_legible(quitar_cr(l)))
        .unwrap_or_default();
    if linea.len() > MAX_LINEA {
        anomalias.push(("http-linea-desmesurada", format!("{} bytes", linea.len())));
    }

    let mut cabeceras = Vec::new();
    for cruda in lineas {
        if cabeceras.len() >= MAX_CABECERAS {
            anomalias.push((
                "http-demasiadas-cabeceras",
                format!("mas de {MAX_CABECERAS}"),
            ));
            break;
        }
        let cruda = quitar_cr(cruda);
        if cruda.is_empty() {
            continue;
        }
        let Some(dp) = cruda.iter().position(|&b| b == b':') else {
            // Una linea de cabecera sin dos puntos no es una cabecera. Puede ser
            // una continuacion plegada (obs-fold), que esta obsoleta justo
            // porque se usa para ofuscar.
            if cruda.first().is_some_and(|c| *c == b' ' || *c == b'\t') {
                anomalias.push((
                    "http-cabecera-plegada",
                    ascii_legible(&cruda[..cruda.len().min(64)]),
                ));
            } else {
                anomalias.push((
                    "http-cabecera-sin-dos-puntos",
                    ascii_legible(&cruda[..cruda.len().min(64)]),
                ));
            }
            continue;
        };

        let nombre_crudo = &cruda[..dp];
        // ESPACIO ANTES DE LOS DOS PUNTOS: la norma lo prohibe expresamente y es
        // una de las formas conocidas de que un proxy y un servidor no vean la
        // misma cabecera.
        if nombre_crudo
            .last()
            .is_some_and(|c| *c == b' ' || *c == b'\t')
        {
            anomalias.push((
                "http-espacio-antes-de-dos-puntos",
                ascii_legible(nombre_crudo),
            ));
        }
        let nombre = ascii_legible(nombre_crudo).trim().to_string();
        let valor = ascii_legible(&cruda[dp + 1..]).trim().to_string();
        cabeceras.push((nombre, valor));
    }

    Some(Mensaje {
        linea,
        cabeceras,
        inicio_cuerpo: fin_cabeceras + salto,
        anomalias,
    })
}

/// Quita el retorno de carro final, si lo hay.
fn quitar_cr(l: &[u8]) -> &[u8] {
    match l.last() {
        Some(b'\r') => &l[..l.len() - 1],
        _ => l,
    }
}

/// Busca una subcadena.
fn buscar(heno: &[u8], aguja: &[u8]) -> Option<usize> {
    if aguja.is_empty() || aguja.len() > heno.len() {
        return None;
    }
    heno.windows(aguja.len()).position(|v| v == aguja)
}

/// Comprueba las condiciones de contrabando de peticiones.
///
/// Se devuelven como anomalias con codigo estable, no como veredicto: hay
/// infraestructuras legitimas que mandan las dos cabeceras por un intermediario
/// mal configurado, y quien decide si eso es un ataque es el arbitro.
#[must_use]
pub fn anomalias_de_contrabando(m: &Mensaje) -> Vec<Hecho> {
    let mut salida = Vec::new();

    let tiene_cl = m.veces("Content-Length") > 0;
    let tiene_te = m.veces("Transfer-Encoding") > 0;

    // LA CONDICION CENTRAL: las dos a la vez.
    if tiene_cl && tiene_te {
        salida.push(Hecho::AnomaliaDeFlujo {
            codigo: "http-contrabando-cl-te",
            detalle: "el mensaje trae Content-Length y Transfer-Encoding a la vez: un proxy \
                      y un servidor pueden partirlo en sitios distintos"
                .to_string(),
        });
    }

    // Duplicadas: dos Content-Length con valores distintos es aun mas claro.
    if m.veces("Content-Length") > 1 {
        let valores: Vec<&str> = m
            .cabeceras
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("Content-Length"))
            .map(|(_, v)| v.as_str())
            .collect();
        let todos_iguales = valores.windows(2).all(|p| p[0] == p[1]);
        salida.push(Hecho::AnomaliaDeFlujo {
            codigo: if todos_iguales {
                "http-content-length-duplicado"
            } else {
                "http-content-length-contradictorio"
            },
            detalle: format!(
                "Content-Length aparece {} veces: {valores:?}",
                valores.len()
            ),
        });
    }
    if m.veces("Transfer-Encoding") > 1 {
        salida.push(Hecho::AnomaliaDeFlujo {
            codigo: "http-transfer-encoding-duplicado",
            detalle: format!(
                "Transfer-Encoding aparece {} veces",
                m.veces("Transfer-Encoding")
            ),
        });
    }

    // Ofuscacion del valor: cualquier cosa que no sea exactamente "chunked" pero
    // que un servidor permisivo interprete como tal.
    if let Some(te) = m.cabecera("Transfer-Encoding") {
        let limpio = te.trim();
        if !limpio.is_empty()
            && !limpio.eq_ignore_ascii_case("chunked")
            && limpio.to_ascii_lowercase().contains("chunked")
        {
            salida.push(Hecho::AnomaliaDeFlujo {
                codigo: "http-transfer-encoding-ofuscado",
                detalle: format!("Transfer-Encoding: {limpio:?}"),
            });
        }
    }

    // Content-Length que no es un numero, o que tiene signo o relleno.
    if let Some(cl) = m.cabecera("Content-Length") {
        if cl.parse::<u64>().is_err() {
            salida.push(Hecho::AnomaliaDeFlujo {
                codigo: "http-content-length-invalido",
                detalle: format!("Content-Length: {cl:?}"),
            });
        }
    }

    // Y las anomalias de separacion que ya se anotaron.
    for (codigo, detalle) in &m.anomalias {
        salida.push(Hecho::AnomaliaDeFlujo {
            codigo,
            detalle: detalle.clone(),
        });
    }

    salida
}

/// Analiza el lado del cliente de un flujo HTTP.
#[must_use]
pub fn analizar_peticion(datos: &[u8]) -> Vec<Hecho> {
    let Some(m) = separar(datos) else {
        return Vec::new();
    };
    let mut partes = m.linea.split_whitespace();
    let metodo = partes.next().unwrap_or_default().to_string();
    if !METODOS.contains(&metodo.as_str()) {
        return Vec::new();
    }
    let uri = partes.next().unwrap_or_default().to_string();
    let version = partes.next().unwrap_or_default().to_string();

    let mut hechos = vec![
        Hecho::ProtocoloIdentificado(ProtocoloApp::Http),
        Hecho::PeticionHttp {
            metodo,
            uri,
            version,
            host: m.cabecera("Host").unwrap_or_default().to_string(),
            agente: m.cabecera("User-Agent").unwrap_or_default().to_string(),
            cabeceras: m.cabeceras.clone(),
        },
    ];
    hechos.extend(anomalias_de_contrabando(&m));
    hechos
}

/// Analiza el lado del servidor de un flujo HTTP.
#[must_use]
pub fn analizar_respuesta(datos: &[u8]) -> Vec<Hecho> {
    let Some(m) = separar(datos) else {
        return Vec::new();
    };
    if !m.linea.starts_with("HTTP/") {
        return Vec::new();
    }
    let estado: u16 = m
        .linea
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);

    let mut hechos = vec![
        Hecho::ProtocoloIdentificado(ProtocoloApp::Http),
        Hecho::RespuestaHttp {
            estado,
            tipo_contenido: m.cabecera("Content-Type").unwrap_or_default().to_string(),
            longitud: m.cabecera("Content-Length").and_then(|v| v.parse().ok()),
            cabeceras: m.cabeceras.clone(),
        },
    ];
    hechos.extend(anomalias_de_contrabando(&m));
    hechos
}

/// Si unos bytes parecen el inicio de una peticion HTTP.
#[must_use]
pub fn parece_peticion(datos: &[u8]) -> bool {
    METODOS.iter().any(|m| {
        datos.len() > m.len()
            && datos.starts_with(m.as_bytes())
            && datos.get(m.len()) == Some(&b' ')
    })
}

/// Si unos bytes parecen el inicio de una respuesta HTTP.
#[must_use]
pub fn parece_respuesta(datos: &[u8]) -> bool {
    datos.starts_with(b"HTTP/")
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn una_peticion_normal_se_lee_entera() {
        let p = b"GET /index.html HTTP/1.1\r\n\
                  Host: ejemplo.com\r\n\
                  User-Agent: curl/8.0\r\n\
                  Accept: */*\r\n\r\n";
        let hechos = analizar_peticion(p);
        match hechos
            .iter()
            .find(|h| matches!(h, Hecho::PeticionHttp { .. }))
        {
            Some(Hecho::PeticionHttp {
                metodo,
                uri,
                version,
                host,
                agente,
                cabeceras,
            }) => {
                assert_eq!(metodo, "GET");
                assert_eq!(uri, "/index.html");
                assert_eq!(version, "HTTP/1.1");
                assert_eq!(host, "ejemplo.com");
                assert_eq!(agente, "curl/8.0");
                assert_eq!(cabeceras.len(), 3);
            }
            otro => panic!("se esperaba una peticion: {otro:?}"),
        }
    }

    /// EL ATAQUE: Content-Length y Transfer-Encoding a la vez. Un disector que
    /// elija en silencio una de las dos ES el eslabon que hace posible el
    /// contrabando.
    #[test]
    fn las_dos_cabeceras_de_longitud_a_la_vez_se_delatan() {
        let p = b"POST / HTTP/1.1\r\n\
                  Host: v\r\n\
                  Content-Length: 6\r\n\
                  Transfer-Encoding: chunked\r\n\r\n\
                  0\r\n\r\nGET /admin HTTP/1.1\r\n\r\n";
        let hechos = analizar_peticion(p);
        assert!(
            hechos.iter().any(|h| matches!(
                h,
                Hecho::AnomaliaDeFlujo { codigo, .. } if *codigo == "http-contrabando-cl-te"
            )),
            "{hechos:?}"
        );
    }

    /// Dos Content-Length con valores DISTINTOS se distingue de dos iguales: lo
    /// primero no tiene lectura benigna.
    #[test]
    fn dos_content_length_contradictorios_se_distinguen_de_dos_iguales() {
        let contradictorio =
            b"POST / HTTP/1.1\r\nHost: v\r\nContent-Length: 6\r\nContent-Length: 0\r\n\r\n";
        let hechos = analizar_peticion(contradictorio);
        assert!(hechos.iter().any(|h| matches!(
            h,
            Hecho::AnomaliaDeFlujo { codigo, .. } if *codigo == "http-content-length-contradictorio"
        )));

        let duplicado =
            b"POST / HTTP/1.1\r\nHost: v\r\nContent-Length: 6\r\nContent-Length: 6\r\n\r\n";
        let hechos = analizar_peticion(duplicado);
        assert!(hechos.iter().any(|h| matches!(
            h,
            Hecho::AnomaliaDeFlujo { codigo, .. } if *codigo == "http-content-length-duplicado"
        )));
    }

    /// El espacio antes de los dos puntos: la norma lo prohibe y es una via
    /// conocida de que un proxy y un servidor no vean la misma cabecera.
    #[test]
    fn el_espacio_antes_de_los_dos_puntos_se_delata() {
        let p = b"POST / HTTP/1.1\r\nHost: v\r\nContent-Length : 6\r\n\r\n";
        let hechos = analizar_peticion(p);
        assert!(
            hechos.iter().any(|h| matches!(
                h,
                Hecho::AnomaliaDeFlujo { codigo, .. } if *codigo == "http-espacio-antes-de-dos-puntos"
            )),
            "{hechos:?}"
        );
    }

    #[test]
    fn un_transfer_encoding_ofuscado_se_delata() {
        let p = b"POST / HTTP/1.1\r\nHost: v\r\nTransfer-Encoding: xchunked\r\n\r\n";
        let hechos = analizar_peticion(p);
        assert!(hechos.iter().any(|h| matches!(
            h,
            Hecho::AnomaliaDeFlujo { codigo, .. } if *codigo == "http-transfer-encoding-ofuscado"
        )));
    }

    #[test]
    fn una_respuesta_normal_se_lee_entera() {
        let r = b"HTTP/1.1 200 OK\r\n\
                  Content-Type: text/html; charset=utf-8\r\n\
                  Content-Length: 1234\r\n\r\n";
        let hechos = analizar_respuesta(r);
        match hechos
            .iter()
            .find(|h| matches!(h, Hecho::RespuestaHttp { .. }))
        {
            Some(Hecho::RespuestaHttp {
                estado,
                tipo_contenido,
                longitud,
                ..
            }) => {
                assert_eq!(*estado, 200);
                assert!(tipo_contenido.starts_with("text/html"));
                assert_eq!(*longitud, Some(1234));
            }
            otro => panic!("se esperaba una respuesta: {otro:?}"),
        }
    }

    /// Trafico que NO es HTTP no puede producir hechos HTTP: si los produjera,
    /// todo lo que emita el disector seria ruido.
    #[test]
    fn el_trafico_que_no_es_http_no_produce_hechos_http() {
        assert!(analizar_peticion(b"\x16\x03\x01\x00\x50binario\r\n\r\n").is_empty());
        assert!(analizar_peticion(b"HOLA / HTTP/1.1\r\nHost: v\r\n\r\n").is_empty());
        assert!(analizar_respuesta(b"GET / HTTP/1.1\r\n\r\n").is_empty());
        assert!(!parece_peticion(b"GETX /"));
        assert!(parece_peticion(b"GET /"));
        assert!(parece_respuesta(b"HTTP/1.1 200"));
    }

    /// Cabeceras incompletas: en un flujo reensamblado es NORMAL que aun no
    /// haya llegado el final, y esperar es lo correcto.
    #[test]
    fn unas_cabeceras_incompletas_no_producen_nada_todavia() {
        assert!(separar(b"GET / HTTP/1.1\r\nHost: eje").is_none());
        assert!(analizar_peticion(b"GET / HTTP/1.1\r\nHost: eje").is_empty());
    }

    /// LA COTA: cien mil cabeceras no hacen reservar cien megas.
    #[test]
    fn una_avalancha_de_cabeceras_no_hace_crecer_la_memoria() {
        let mut p = b"GET / HTTP/1.1\r\n".to_vec();
        for i in 0..50_000 {
            p.extend_from_slice(format!("X-Relleno-{i}: aaaaaaaaaaaaaaaaaaaa\r\n").as_bytes());
        }
        p.extend_from_slice(b"\r\n");

        let m = separar(&p).expect("separa");
        assert!(
            m.cabeceras.len() <= MAX_CABECERAS || m.cabeceras.is_empty(),
            "cabeceras = {}",
            m.cabeceras.len()
        );
    }

    #[test]
    fn el_salto_de_linea_sin_retorno_tambien_se_acepta() {
        // Hay implementaciones que mandan solo LF. Un IDS que no lo acepte deja
        // de ver ese trafico, que es justo lo que busca quien lo manda asi.
        let p = b"GET / HTTP/1.1\nHost: ejemplo.com\n\n";
        let hechos = analizar_peticion(p);
        assert!(hechos
            .iter()
            .any(|h| matches!(h, Hecho::PeticionHttp { .. })));
    }

    #[test]
    fn ningun_mensaje_arbitrario_provoca_panico() {
        let mut semilla = 0x1357_9BDF_0246_8ACEu64;
        for _ in 0..8000 {
            semilla = semilla
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let largo = (semilla >> 32) as usize % 500;
            let mut datos: Vec<u8> = (0..largo).map(|i| (semilla >> (i % 8)) as u8).collect();
            // La mitad con un final de cabeceras valido, para llegar mas adentro.
            if largo % 2 == 0 {
                datos.extend_from_slice(b"\r\n\r\n");
            }
            let _ = analizar_peticion(&datos);
            let _ = analizar_respuesta(&datos);
            let _ = separar(&datos);
        }
    }
}
