//! Web moderna: HTTP/2, HTTP/3 sobre QUIC y WebSocket.
//!
//! # Por que esto no es «mas HTTP»
//!
//! Porque el sensor que sepa leer HTTP/1.1 y nada mas se queda ciego delante del
//! trafico de hoy. En HTTP/2 las cabeceras van **comprimidas con HPACK**, y la
//! compresion usa una tabla que se construye a lo largo de la conexion: quien
//! empiece a mirar por la mitad no puede descomprimir nada. En HTTP/3 todo eso
//! va ademas dentro de QUIC, cifrado desde el primer paquete.
//!
//! Eso no se arregla escribiendo mas codigo, y por eso el muro se declara en vez
//! de esconderse: [`crate::cobertura::Motivo::Cifrado`] para lo que no esta, y
//! [`crate::cobertura::Motivo::TipoNoImplementado`] para lo que si esta y este
//! disector no lee.
//!
//! # Lo que si se saca
//!
//! - De HTTP/2: las tramas con su tipo y su flujo, y de las cabeceras todo lo
//!   que se pueda resolver con la **tabla estatica** de HPACK, que no depende de
//!   haber visto el principio de la conexion. Eso incluye el metodo, el esquema
//!   y las rutas comunes.
//! - De HTTP/3: la version de QUIC y el tipo de paquete. Nada mas, y se dice.
//! - De WebSocket: el saludo de cambio de protocolo y, despues, cada trama con
//!   su codigo de operacion y si venia enmascarada — que es donde se ve un
//!   cliente que no cumple la norma.

use aegis_wire::error::{ErrorDiseccion, Resultado};
use aegis_wire::hecho::{Hecho, ProtocoloApp};
use aegis_wire::lector::Lector;

use crate::cobertura::{Cobertura, Motivo};
use crate::disector::{Contexto, Disector, Fuerza, Salida};
use crate::texto;

// ════════════════════════════════════════════════════════════════════════════
// HTTP/2
// ════════════════════════════════════════════════════════════════════════════

/// El preambulo con el que empieza toda conexion HTTP/2 en claro.
pub const PREAMBULO: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// La tabla estatica de HPACK (RFC 7541, anexo A).
///
/// Es lo unico de HPACK que se puede resolver **sin haber visto el principio de
/// la conexion**, y por eso esta entera: la tabla dinamica es estado del flujo,
/// y un sensor que empiece a mirar por la mitad no la tiene.
pub static TABLA_ESTATICA: &[(&str, &str)] = &[
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// El tipo de trama de HTTP/2.
fn trama_http2(t: u8) -> Option<&'static str> {
    Some(match t {
        0x0 => "datos",
        0x1 => "cabeceras",
        0x2 => "prioridad",
        0x3 => "reiniciar-flujo",
        0x4 => "ajustes",
        0x5 => "promesa-de-empuje",
        0x6 => "ping",
        0x7 => "despedida",
        0x8 => "ventana",
        0x9 => "continuacion",
        _ => return None,
    })
}

/// Lo que se saco de un bloque de cabeceras comprimido.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cabeceras {
    /// Los pares que se pudieron resolver.
    pub resueltas: Vec<(String, String)>,
    /// Cuantas entradas se refieren a la tabla dinamica, que no se sigue.
    pub por_la_tabla_dinamica: usize,
    /// Cuantas cadenas venian codificadas con Huffman.
    pub con_huffman: usize,
}

/// Un entero de HPACK con su prefijo de `bits` (RFC 7541, seccion 5.1).
///
/// El bucle esta acotado a diez continuaciones: sin tope, una cadena de bytes
/// con el bit alto puesto haria girar sobre el buffer entero, y ese buffer lo
/// escribe el emisor.
fn entero_hpack(l: &mut Lector<'_>, bits: u32, primero: u8) -> Resultado<u64> {
    let mascara = (1u16 << bits) - 1;
    let valor = u64::from(u16::from(primero) & mascara);
    if valor < u64::from(mascara) {
        return Ok(valor);
    }
    let mut total = valor;
    let mut desplazamiento = 0u32;
    for _ in 0..10 {
        let b = l.u8("hpack.entero")?;
        total = total
            .checked_add(u64::from(b & 0x7F) << desplazamiento)
            .ok_or(ErrorDiseccion::ValorInvalido {
                campo: "hpack.entero",
                valor: total,
            })?;
        if b & 0x80 == 0 {
            return Ok(total);
        }
        desplazamiento += 7;
    }
    Err(ErrorDiseccion::AnidamientoExcesivo {
        campo: "hpack.entero",
        niveles: 10,
    })
}

/// Una cadena de HPACK. Devuelve `None` cuando venia con Huffman.
fn cadena_hpack(l: &mut Lector<'_>) -> Resultado<Option<String>> {
    let primero = l.u8("hpack.cadena")?;
    let huffman = primero & 0x80 != 0;
    let largo = entero_hpack(l, 7, primero)?;
    if largo > 8192 {
        return Err(ErrorDiseccion::LimiteExcedido {
            campo: "hpack.cadena",
            valor: largo as usize,
            tope: 8192,
        });
    }
    let bytes = l.tomar(largo as usize, "hpack.cadena")?;
    if huffman {
        // La tabla de Huffman de HPACK es un arbol de doscientos cincuenta y
        // seis simbolos. No esta implementada, y contar la cadena como leida
        // seria inventarsela: se declara y se cuenta.
        return Ok(None);
    }
    Ok(Some(aegis_wire::lector::ascii_legible(bytes)))
}

/// Descomprime lo que se pueda de un bloque de cabeceras, sin tabla dinamica.
///
/// # Por que esto vale la pena aun sin la tabla dinamica
///
/// Porque el metodo, el esquema y el estado casi siempre salen de la tabla
/// estatica: son los indices del 2 al 14. Con eso ya se sabe si hubo un POST y
/// contra que autoridad, que es la mitad de lo que se le pide a un registro.
#[must_use]
pub fn descomprimir(bloque: &[u8]) -> Cabeceras {
    const MAX_ENTRADAS: usize = 128;
    let mut salida = Cabeceras::default();
    let mut l = Lector::nuevo(bloque);
    for _ in 0..MAX_ENTRADAS {
        let Ok(primero) = l.u8("hpack.entrada") else {
            break;
        };
        if primero & 0x80 != 0 {
            // Campo indexado: nombre y valor de la tabla.
            let Ok(indice) = entero_hpack(&mut l, 7, primero) else {
                break;
            };
            match TABLA_ESTATICA.get((indice as usize).wrapping_sub(1)) {
                Some((n, v)) if indice >= 1 => {
                    salida.resueltas.push(((*n).to_owned(), (*v).to_owned()));
                }
                _ => salida.por_la_tabla_dinamica += 1,
            }
            continue;
        }
        // Literal. El prefijo depende de si se indexa, y equivocarlo desplaza
        // todo el bloque: seis bits con indexacion incremental, cuatro sin ella.
        let bits = if primero & 0x40 != 0 { 6 } else { 4 };
        let Ok(indice) = entero_hpack(&mut l, bits, primero) else {
            break;
        };
        let nombre = if indice == 0 {
            match cadena_hpack(&mut l) {
                Ok(Some(n)) => n,
                Ok(None) => {
                    salida.con_huffman += 1;
                    // Sin el nombre no se puede seguir: el valor que viene
                    // detras se leeria como si fuera otra entrada.
                    match cadena_hpack(&mut l) {
                        Ok(_) => continue,
                        Err(_) => break,
                    }
                }
                Err(_) => break,
            }
        } else {
            match TABLA_ESTATICA.get((indice as usize) - 1) {
                Some((n, _)) => (*n).to_owned(),
                None => {
                    salida.por_la_tabla_dinamica += 1;
                    match cadena_hpack(&mut l) {
                        Ok(_) => continue,
                        Err(_) => break,
                    }
                }
            }
        };
        match cadena_hpack(&mut l) {
            Ok(Some(v)) => salida.resueltas.push((nombre, v)),
            Ok(None) => salida.con_huffman += 1,
            Err(_) => break,
        }
    }
    salida
}

/// Disector de HTTP/2.
#[derive(Debug, Default, Clone, Copy)]
pub struct Http2;

impl Http2 {
    /// Donde empieza la primera trama: tras el preambulo, si lo hay.
    fn inicio(datos: &[u8]) -> usize {
        if datos.starts_with(PREAMBULO) {
            PREAMBULO.len()
        } else {
            0
        }
    }

    /// `(tipo, banderas, flujo, carga)`.
    fn trama(datos: &[u8], desde: usize) -> Resultado<(u8, u8, u32, &[u8])> {
        let mut l = Lector::nuevo(datos);
        l.ir_a(desde, "http2.trama")?;
        let largo = l.u24("http2.longitud")? as usize;
        let tipo = l.u8("http2.tipo")?;
        if trama_http2(tipo).is_none() {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("http2"));
        }
        let banderas = l.u8("http2.banderas")?;
        let flujo = l.u32("http2.flujo")? & 0x7FFF_FFFF;
        // El maximo por defecto son 16384; la norma permite negociar hasta
        // 2^24-1. Una carga mayor que lo que hay es un emisor que miente.
        if largo > 16 * 1024 * 1024 {
            return Err(ErrorDiseccion::LimiteExcedido {
                campo: "http2.longitud",
                valor: largo,
                tope: 16 * 1024 * 1024,
            });
        }
        let carga = l.tomar(largo, "http2.carga")?;
        Ok((tipo, banderas, flujo, carga))
    }
}

impl Disector for Http2 {
    /// El preambulo, o una trama con tipo conocido y longitud acotada.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Forma
    }

    fn nombre(&self) -> &'static str {
        "http2"
    }

    fn reconoce(&self, datos: &[u8], _ctx: &Contexto) -> bool {
        datos.starts_with(PREAMBULO)
            || datos.starts_with(&PREAMBULO[..datos.len().min(PREAMBULO.len())]) && datos.len() >= 8
            || Http2::trama(datos, 0).is_ok()
    }

    fn disecar(&self, datos: &[u8], _ctx: &Contexto) -> Salida {
        let desde = Http2::inicio(datos);
        let mut hechos = vec![Hecho::ProtocoloIdentificado(ProtocoloApp::Http2)];
        let mut cobertura = Cobertura::nueva();

        if desde > 0 && datos.len() == desde {
            // Solo el preambulo: se reconoce la conexion y no hay trama.
            cobertura.entendido();
            return Salida { hechos, cobertura };
        }

        let (tipo, banderas, flujo, carga) = match Http2::trama(datos, desde) {
            Ok(v) => v,
            Err(e) => return Salida::sin_analizar(Motivo::de_error(&e)),
        };
        let nombre = trama_http2(tipo).unwrap_or("desconocida");

        if tipo == 0x1 || tipo == 0x5 {
            // Una trama de cabeceras puede llevar delante la prioridad y detras
            // el relleno: saltarlos mal desplaza el bloque entero y HPACK saca
            // basura. El relleno va en el primer byte si la bandera esta puesta.
            let mut inicio = 0usize;
            let mut relleno = 0usize;
            if banderas & 0x08 != 0 && !carga.is_empty() {
                relleno = usize::from(carga[0]);
                inicio = 1;
            }
            if tipo == 0x1 && banderas & 0x20 != 0 {
                inicio += 5;
            }
            if tipo == 0x5 {
                inicio += 4;
            }
            let fin = carga.len().saturating_sub(relleno);
            let bloque = carga.get(inicio..fin).unwrap_or(&[]);
            let c = descomprimir(bloque);
            for (n, v) in &c.resueltas {
                hechos.push(Hecho::AnomaliaDeFlujo {
                    codigo: "http2-cabecera",
                    detalle: format!("{n}: {v}"),
                });
            }
            let metodo = c
                .resueltas
                .iter()
                .find(|(n, _)| n == ":method")
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            let ruta = c
                .resueltas
                .iter()
                .find(|(n, _)| n == ":path")
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            let autoridad = c
                .resueltas
                .iter()
                .find(|(n, _)| n == ":authority")
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            if !metodo.is_empty() || !ruta.is_empty() {
                hechos.push(Hecho::PeticionHttp {
                    metodo,
                    uri: ruta,
                    version: "HTTP/2".to_owned(),
                    host: autoridad,
                    agente: c
                        .resueltas
                        .iter()
                        .find(|(n, _)| n == "user-agent")
                        .map(|(_, v)| v.clone())
                        .unwrap_or_default(),
                    cabeceras: c.resueltas.clone(),
                });
            }
            if c.resueltas.is_empty() && (c.por_la_tabla_dinamica > 0 || c.con_huffman > 0) {
                cobertura.sin_analizar(Motivo::TipoNoImplementado);
            } else {
                cobertura.entendido();
            }
            // Lo que se quedo por la tabla dinamica o por Huffman se cuenta
            // aparte: son las cabeceras que existieron y no se leyeron.
            for _ in 0..c.por_la_tabla_dinamica + c.con_huffman {
                cobertura.sin_analizar(Motivo::TipoNoImplementado);
            }
        } else {
            cobertura.entendido();
        }

        hechos.push(Hecho::AnomaliaDeFlujo {
            codigo: "http2-trama",
            detalle: format!("{nombre} en el flujo {flujo}"),
        });
        Salida { hechos, cobertura }
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "el preambulo de conexion",
            "las diez clases de trama, con su flujo y sus banderas",
            "el relleno y la prioridad de una trama de cabeceras, que hay que saltar bien",
            "las cabeceras que salen de la tabla estatica de HPACK: metodo, esquema, estado y las comunes",
            "los literales de HPACK sin Huffman, con nombre propio o por indice estatico",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "las cabeceras que se refieren a la tabla DINAMICA de HPACK: es estado de la conexion, \
             y quien empiece a mirar por la mitad no lo tiene",
            "las cadenas codificadas con Huffman",
            "el cuerpo de las tramas de datos",
            "el reensamblado de un bloque de cabeceras partido en tramas de continuacion",
            "HTTP/2 sobre TLS, que es el caso normal: ahi esto solo se ve tras terminar el cifrado",
        ]
    }
}

// ════════════════════════════════════════════════════════════════════════════
// HTTP/3 sobre QUIC
// ════════════════════════════════════════════════════════════════════════════

/// Disector de HTTP/3 sobre QUIC.
///
/// # El muro entero, dicho de una vez
///
/// Un paquete inicial de QUIC va cifrado con una clave derivada del propio
/// identificador de conexion. Esa parte se podria descifrar; el resto de la
/// conexion, no, porque las claves salen del intercambio TLS. Asi que de HTTP/3
/// se ve **la forma del sobre** y nada del contenido, y eso no lo arregla
/// escribir mas codigo: se declara [`Motivo::Cifrado`], que es distinto de decir
/// que falta trabajo.
#[derive(Debug, Default, Clone, Copy)]
pub struct Http3;

impl Http3 {
    /// `(version, tipo de paquete largo)` si es una cabecera larga de QUIC.
    fn cabecera_larga(datos: &[u8]) -> Resultado<(u32, u8)> {
        let mut l = Lector::nuevo(datos);
        let primero = l.u8("quic.primero")?;
        // Bit de forma larga y bit fijo: los dos tienen que estar puestos.
        if primero & 0x80 == 0 || primero & 0x40 == 0 {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("quic"));
        }
        let version = l.u32("quic.version")?;
        let largo_destino = l.u8("quic.longitud-de-destino")? as usize;
        // La norma acota el identificador de conexion a veinte bytes.
        if largo_destino > 20 {
            return Err(ErrorDiseccion::ValorInvalido {
                campo: "quic.longitud-de-destino",
                valor: largo_destino as u64,
            });
        }
        l.saltar(largo_destino, "quic.destino")?;
        let largo_origen = l.u8("quic.longitud-de-origen")? as usize;
        if largo_origen > 20 {
            return Err(ErrorDiseccion::ValorInvalido {
                campo: "quic.longitud-de-origen",
                valor: largo_origen as u64,
            });
        }
        l.saltar(largo_origen, "quic.origen")?;
        let tipo = (primero >> 4) & 0x03;
        // Un paquete inicial lleva un testigo y una longitud, los dos como
        // enteros de longitud variable. Que los dos quepan en el datagrama es lo
        // que separa QUIC de cuatro bytes con el bit alto puesto: sin esta
        // comprobacion se midio que reclamaba una de cada tres mil entradas
        // cualesquiera.
        if tipo == 0 && version != 0 {
            let testigo = Http3::varint(&mut l)? as usize;
            l.saltar(testigo, "quic.testigo")?;
            let carga = Http3::varint(&mut l)? as usize;
            if carga == 0 || carga > l.restante() {
                return Err(ErrorDiseccion::LongitudImposible {
                    campo: "quic.longitud",
                    declarada: carga,
                    disponible: l.restante(),
                });
            }
        }
        Ok((version, tipo))
    }

    /// Un entero de longitud variable de QUIC: los dos bits altos del primer
    /// byte dicen cuantos ocupa (uno, dos, cuatro u ocho).
    fn varint(l: &mut Lector<'_>) -> Resultado<u64> {
        let primero = l.u8("quic.varint")?;
        let clase = primero >> 6;
        let mut valor = u64::from(primero & 0x3F);
        for _ in 0..((1usize << clase) - 1) {
            valor = (valor << 8) | u64::from(l.u8("quic.varint")?);
        }
        Ok(valor)
    }

    /// El nombre de una version de QUIC.
    fn version(v: u32) -> &'static str {
        match v {
            0x0000_0000 => "negociacion-de-version",
            0x0000_0001 => "quic-1",
            0x6b33_43cf => "quic-2",
            0xff00_001d => "borrador-29",
            _ => "version-no-catalogada",
        }
    }
}

impl Disector for Http3 {
    /// Cabecera larga de QUIC con sus dos bits y sus longitudes de identificador.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Forma
    }

    fn nombre(&self) -> &'static str {
        "http3"
    }

    fn reconoce(&self, datos: &[u8], ctx: &Contexto) -> bool {
        // QUIC va sobre UDP: sobre un transporte ordenado esto no es QUIC, y
        // aceptarlo ahi haria que cualquier flujo TCP con el bit alto puesto se
        // llevara el nombre.
        !ctx.ordenado && Http3::cabecera_larga(datos).is_ok()
    }

    fn disecar(&self, datos: &[u8], ctx: &Contexto) -> Salida {
        // El transporte se comprueba tambien aqui, no solo al reconocer: un
        // disector no puede afirmar haber visto QUIC sobre TCP porque alguien lo
        // llame directamente. Lo encontro el barrido hostil.
        if ctx.ordenado {
            return Salida::sin_analizar(Motivo::NoReconocido);
        }
        let (version, tipo) = match Http3::cabecera_larga(datos) {
            Ok(v) => v,
            Err(e) => return Salida::sin_analizar(Motivo::de_error(&e)),
        };
        let clase = match tipo {
            0 => "inicial",
            1 => "datos-cero",
            2 => "apreton-de-manos",
            _ => "reintento",
        };
        let hechos = vec![
            Hecho::ProtocoloIdentificado(ProtocoloApp::Http3),
            Hecho::InicioQuic {
                version,
                sni: String::new(),
            },
            Hecho::AnomaliaDeFlujo {
                codigo: "http3-paquete",
                detalle: format!("{clase} de {}", Http3::version(version)),
            },
        ];
        // La forma del sobre se entiende; el contenido esta cifrado y no esta.
        let mut cobertura = Cobertura::nueva();
        cobertura.sin_analizar(Motivo::Cifrado);
        Salida { hechos, cobertura }
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "la cabecera larga de QUIC con su version",
            "el tipo de paquete: inicial, datos-cero, apreton de manos y reintento",
            "los identificadores de conexion y su longitud",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "la carga, que va cifrada desde el primer paquete: no esta, y eso no lo \
             arregla escribir mas codigo",
            "las tramas de HTTP/3 y sus cabeceras comprimidas con QPACK",
            "la cabecera corta, que no lleva version ni longitudes visibles",
            "el nombre de servidor del saludo TLS, que viaja dentro del cifrado inicial",
        ]
    }
}

// ════════════════════════════════════════════════════════════════════════════
// WebSocket
// ════════════════════════════════════════════════════════════════════════════

/// El codigo de operacion de una trama de WebSocket.
fn operacion_websocket(o: u8) -> Option<&'static str> {
    Some(match o {
        0x0 => "continuacion",
        0x1 => "texto",
        0x2 => "binario",
        0x8 => "cierre",
        0x9 => "ping",
        0xA => "pong",
        _ => return None,
    })
}

/// Disector de WebSocket.
#[derive(Debug, Default, Clone, Copy)]
pub struct Websocket;

impl Websocket {
    /// Si esto es el saludo de cambio de protocolo.
    fn saludo(datos: &[u8]) -> Option<String> {
        let actualizar = texto::cabecera(datos, "Upgrade")?;
        if !actualizar.eq_ignore_ascii_case("websocket") {
            return None;
        }
        if let Some((_, ruta, _)) = texto::peticion_http(datos) {
            return Some(ruta);
        }
        // Del lado del servidor no hay linea de peticion: la respuesta es un 101.
        let (primera, _) = texto::linea(datos)?;
        if primera.starts_with(b"HTTP/1.1 101") {
            Some("respuesta 101".to_owned())
        } else {
            None
        }
    }

    /// Cuanto ocupa la cabecera de una trama, con su mascara si la lleva.
    fn largo_de_cabecera(datos: &[u8], enmascarada: bool) -> Option<u64> {
        let corta = datos.get(1)? & 0x7F;
        let base: u64 = match corta {
            126 => 4,
            127 => 10,
            _ => 2,
        };
        Some(base + if enmascarada { 4 } else { 0 })
    }

    /// Una trama: `(final, operacion, enmascarada, longitud)`.
    fn trama(datos: &[u8]) -> Resultado<(bool, u8, bool, u64)> {
        let mut l = Lector::nuevo(datos);
        let primero = l.u8("ws.primero")?;
        // Los tres bits reservados tienen que estar a cero salvo que se hayan
        // negociado extensiones. Comprobarlo es lo que impide que dos bytes
        // cualesquiera pasen por una trama de WebSocket.
        if primero & 0x70 != 0 {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("websocket"));
        }
        let operacion = primero & 0x0F;
        if operacion_websocket(operacion).is_none() {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("websocket"));
        }
        let segundo = l.u8("ws.segundo")?;
        let enmascarada = segundo & 0x80 != 0;
        let corta = segundo & 0x7F;
        let largo = match corta {
            126 => u64::from(l.u16("ws.longitud")?),
            127 => l.u64("ws.longitud")?,
            n => u64::from(n),
        };
        // Las tramas de control no pueden pasar de 125 bytes ni fragmentarse.
        if operacion >= 0x8 && (largo > 125 || primero & 0x80 == 0) {
            return Err(ErrorDiseccion::ValorInvalido {
                campo: "ws.trama-de-control",
                valor: largo,
            });
        }
        Ok((primero & 0x80 != 0, operacion, enmascarada, largo))
    }
}

impl Disector for Websocket {
    /// Dos bytes de marco: casi cualquier cosa encaja, y por eso va el ultimo.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Indicio
    }

    /// Si. `reconoce` exige que un cliente enmascare, porque es lo que la norma
    /// le obliga y lo que hace falta para reclamar un flujo. `disecar` no lo
    /// exige, porque una trama de cliente sin mascara en un flujo que YA es
    /// WebSocket es justo lo que hay que poder ver y contar.
    fn disecar_es_mas_ancho(&self) -> bool {
        true
    }

    fn nombre(&self) -> &'static str {
        "websocket"
    }

    /// # Por que reconocer es mas estricto que disecar
    ///
    /// Porque son dos preguntas distintas. `disecar` contesta «como se lee esto,
    /// dado que ya sabemos que es WebSocket», y ahi una trama de cliente sin
    /// mascara es justo lo que hay que poder ver y contar. `reconoce` contesta
    /// «¿me quedo yo con este flujo?», y ahi dos bytes de marco no bastan: se
    /// midio, y una cabecera de Modbus encajaba como una trama de continuacion.
    ///
    /// Asi que para quedarse un flujo sin haber visto el saludo hacen falta tres
    /// cosas: que no sea una continuacion —que sin contexto previo no significa
    /// nada—, que la longitud declarada cuadre con lo que hay, y que un cliente
    /// enmascare, que es lo que la RFC 6455 le obliga a hacer.
    fn reconoce(&self, datos: &[u8], ctx: &Contexto) -> bool {
        if Websocket::saludo(datos).is_some() {
            return true;
        }
        let Ok((_, operacion, enmascarada, largo)) = Websocket::trama(datos) else {
            return false;
        };
        if operacion == 0x0 {
            return false;
        }
        if ctx.del_cliente && !enmascarada {
            return false;
        }
        let cabecera = Websocket::largo_de_cabecera(datos, enmascarada);
        cabecera
            .and_then(|c| u64::try_from(datos.len()).ok().map(|n| (c, n)))
            .is_some_and(|(c, n)| c.saturating_add(largo) == n)
    }

    fn disecar(&self, datos: &[u8], ctx: &Contexto) -> Salida {
        if let Some(donde) = Websocket::saludo(datos) {
            let mut hechos = vec![
                Hecho::ProtocoloIdentificado(ProtocoloApp::Websocket),
                Hecho::EjecucionRemota {
                    via: ProtocoloApp::Websocket,
                    orden: "cambio-de-protocolo".to_owned(),
                    objetivo: donde,
                },
            ];
            if let Some(sub) = texto::cabecera(datos, "Sec-WebSocket-Protocol") {
                hechos.push(Hecho::AnomaliaDeFlujo {
                    codigo: "websocket-subprotocolo",
                    detalle: sub,
                });
            }
            return Salida::entendido(hechos);
        }
        let (ultima, operacion, enmascarada, largo) = match Websocket::trama(datos) {
            Ok(v) => v,
            Err(e) => return Salida::sin_analizar(Motivo::de_error(&e)),
        };
        let nombre = operacion_websocket(operacion).unwrap_or("desconocida");
        let mut hechos = vec![
            Hecho::ProtocoloIdentificado(ProtocoloApp::Websocket),
            Hecho::AnomaliaDeFlujo {
                codigo: "websocket-trama",
                detalle: format!(
                    "{nombre} de {largo} bytes{}{}",
                    if ultima { "" } else { ", fragmentada" },
                    if enmascarada { ", enmascarada" } else { "" }
                ),
            },
        ];
        // La RFC 6455 obliga al cliente a enmascarar. Un cliente que no lo haga
        // no es un fallo cosmetico: es lo que hace un programa a medida, y se
        // dice — sin llamarlo malicioso, que eso lo decide el arbitro.
        if ctx.del_cliente && !enmascarada {
            hechos.push(Hecho::AnomaliaDeFlujo {
                codigo: "websocket-cliente-sin-mascara",
                detalle: "el cliente mando una trama sin enmascarar, que la norma prohibe"
                    .to_owned(),
            });
        }
        Salida::entendido(hechos)
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "el saludo de cambio de protocolo, en los dos sentidos",
            "el subprotocolo negociado",
            "las seis clases de trama con su longitud, incluidas las de 16 y 64 bits",
            "la fragmentacion y el enmascaramiento",
            "un cliente que no enmascara, que la norma prohibe",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "la carga de las tramas, que es del protocolo que se monte encima",
            "el desenmascarado del contenido",
            "las extensiones negociadas, como la compresion por mensaje",
            "el codigo y la razon de una trama de cierre",
        ]
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Una trama de cabeceras de HTTP/2 con `:method POST` y `:path /` sacados
    /// de la tabla estatica, y un `user-agent` literal sin Huffman.
    fn http2_cabeceras() -> Vec<u8> {
        let mut bloque = vec![0x83, 0x84]; // indices 3 y 4
                                           // Literal con indexacion incremental sobre el indice 58 (user-agent).
        bloque.push(0x40 | 58);
        let agente = b"curl/8";
        bloque.push(agente.len() as u8);
        bloque.extend_from_slice(agente);

        let mut v = Vec::new();
        v.extend_from_slice(&(bloque.len() as u32).to_be_bytes()[1..]);
        v.push(0x01); // cabeceras
        v.push(0x04); // fin de cabeceras
        v.extend_from_slice(&1u32.to_be_bytes());
        v.extend_from_slice(&bloque);
        v
    }

    #[test]
    fn http2_saca_el_metodo_y_la_ruta_de_la_tabla_estatica() {
        // Es lo unico de HPACK que se puede resolver sin haber visto el
        // principio de la conexion, y ya es la mitad de lo que se pide.
        let d = Http2;
        let b = http2_cabeceras();
        assert!(d.reconoce(&b, &Contexto::tcp_cliente(80)));
        let s = d.disecar(&b, &Contexto::tcp_cliente(80));
        let peticion = s.hechos.iter().find_map(|h| match h {
            Hecho::PeticionHttp {
                metodo,
                uri,
                agente,
                ..
            } => Some((metodo.as_str(), uri.as_str(), agente.as_str())),
            _ => None,
        });
        assert_eq!(peticion, Some(("POST", "/", "curl/8")));
        assert!(s.cobertura.completa(), "{:?}", s.cobertura);
    }

    #[test]
    fn http2_declara_las_cabeceras_que_dependen_de_la_tabla_dinamica() {
        // Son cabeceras que existieron y no se leyeron: contarlas como leidas
        // seria decir que el mensaje se entendio entero.
        let d = Http2;
        let bloque = vec![0xC0]; // indice 64: ya en la tabla dinamica
        let mut v = Vec::new();
        v.extend_from_slice(&(bloque.len() as u32).to_be_bytes()[1..]);
        v.push(0x01);
        v.push(0x04);
        v.extend_from_slice(&1u32.to_be_bytes());
        v.extend_from_slice(&bloque);
        let s = d.disecar(&v, &Contexto::tcp_cliente(80));
        assert!(!s.cobertura.completa());
        assert!(s.cobertura.perdidos() >= 1);
    }

    #[test]
    fn http2_salta_el_relleno_y_la_prioridad_de_una_trama_de_cabeceras() {
        // Saltarlos mal desplaza el bloque entero y HPACK saca basura.
        let d = Http2;
        let bloque = vec![0x82, 0x84]; // :method GET, :path /
        let mut carga = vec![3u8]; // tres bytes de relleno
        carga.extend_from_slice(&[0, 0, 0, 1, 16]); // prioridad
        carga.extend_from_slice(&bloque);
        carga.extend_from_slice(&[0, 0, 0]); // el relleno
        let mut v = Vec::new();
        v.extend_from_slice(&(carga.len() as u32).to_be_bytes()[1..]);
        v.push(0x01);
        v.push(0x08 | 0x20 | 0x04); // relleno, prioridad, fin de cabeceras
        v.extend_from_slice(&1u32.to_be_bytes());
        v.extend_from_slice(&carga);
        let s = d.disecar(&v, &Contexto::tcp_cliente(80));
        let metodo = s.hechos.iter().find_map(|h| match h {
            Hecho::PeticionHttp { metodo, .. } => Some(metodo.as_str()),
            _ => None,
        });
        assert_eq!(metodo, Some("GET"));
    }

    #[test]
    fn hpack_no_gira_sobre_un_entero_sin_final() {
        // Sin el tope de continuaciones, una cadena de bytes con el bit alto
        // puesto haria girar el bucle sobre el buffer entero.
        let muchos = [0xFFu8; 64];
        let mut l = Lector::nuevo(&muchos[1..]);
        assert!(entero_hpack(&mut l, 7, 0xFF).is_err());
    }

    #[test]
    fn la_tabla_estatica_tiene_las_sesenta_y_una_entradas_de_la_norma() {
        // Una entrada de menos desplaza todos los indices a partir de ella, y
        // entonces `:path` se lee como `:scheme`.
        assert_eq!(TABLA_ESTATICA.len(), 61);
        assert_eq!(TABLA_ESTATICA[1], (":method", "GET"));
        assert_eq!(TABLA_ESTATICA[2], (":method", "POST"));
        assert_eq!(TABLA_ESTATICA[6], (":scheme", "https"));
        assert_eq!(TABLA_ESTATICA[57].0, "user-agent");
        assert_eq!(TABLA_ESTATICA[60].0, "www-authenticate");
    }

    #[test]
    fn http3_declara_cifrado_lo_que_esta_cifrado() {
        // No es que falte trabajo: es que el contenido no esta.
        let d = Http3;
        // Un paquete inicial de QUIC 1 completo: cabecera larga, version, los dos
        // identificadores de conexion, el testigo vacio y la longitud de la carga.
        let mut v = vec![0xC0]; // forma larga, bit fijo, tipo inicial
        v.extend_from_slice(&1u32.to_be_bytes());
        v.push(8);
        v.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        v.push(0); // sin identificador de origen
        v.push(0); // testigo de longitud cero
        v.extend_from_slice(&[0x40, 0x14]); // longitud de carga: 20
        v.extend_from_slice(&[0u8; 20]);
        assert!(d.reconoce(&v, &Contexto::udp(443)));
        let s = d.disecar(&v, &Contexto::udp(443));
        assert_eq!(s.cobertura.sin_analizar.get(&Motivo::Cifrado), Some(&1));
        assert_eq!(
            s.cobertura.perdidos_por_falta_de_codigo(),
            0,
            "lo cifrado no se arregla escribiendo codigo"
        );
    }

    #[test]
    fn http3_no_se_reconoce_sobre_un_transporte_ordenado() {
        // QUIC va sobre UDP: aceptarlo sobre TCP haria que cualquier flujo con
        // el bit alto puesto se llevara el nombre.
        let d = Http3;
        let mut v = vec![0xC0];
        v.extend_from_slice(&1u32.to_be_bytes());
        v.push(0);
        v.push(0);
        v.push(0);
        v.extend_from_slice(&[0x40, 0x14]);
        v.extend_from_slice(&[0u8; 20]);
        assert!(d.reconoce(&v, &Contexto::udp(443)), "sobre UDP si es QUIC");
        assert!(!d.reconoce(&v, &Contexto::tcp_cliente(443)));
    }

    #[test]
    fn websocket_lee_el_saludo_y_luego_las_tramas() {
        let d = Websocket;
        let saludo = b"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Protocol: mando\r\n\r\n";
        assert!(d.reconoce(saludo, &Contexto::tcp_cliente(80)));
        let s = d.disecar(saludo, &Contexto::tcp_cliente(80));
        assert!(s.cobertura.completa());
        assert!(s
            .hechos
            .iter()
            .any(|h| matches!(h, Hecho::AnomaliaDeFlujo { detalle, .. } if detalle == "mando")));

        // Una trama de texto de cinco bytes, enmascarada como manda la norma.
        let trama = [0x81u8, 0x85, 1, 2, 3, 4, 0, 0, 0, 0, 0];
        let s = d.disecar(&trama, &Contexto::tcp_cliente(80));
        assert!(s.hechos.iter().any(
            |h| matches!(h, Hecho::AnomaliaDeFlujo { detalle, .. } if detalle.contains("texto de 5"))
        ));
    }

    #[test]
    fn websocket_dice_cuando_un_cliente_no_enmascara() {
        // No es cosmetico: es lo que hace un programa a medida.
        let d = Websocket;
        let trama = [0x81u8, 0x05, b'h', b'o', b'l', b'a', b'!'];
        let s = d.disecar(&trama, &Contexto::tcp_cliente(80));
        assert!(
            s.hechos.iter().any(|h| matches!(
                h,
                Hecho::AnomaliaDeFlujo { codigo, .. } if *codigo == "websocket-cliente-sin-mascara"
            )),
            "{:?}",
            s.hechos
        );
    }

    #[test]
    fn websocket_rechaza_una_trama_de_control_desmedida() {
        // Las de control no pueden pasar de 125 bytes ni fragmentarse.
        let d = Websocket;
        let trama = [0x89u8, 0xFE, 0x01, 0x00];
        assert!(!d.reconoce(&trama, &Contexto::tcp_cliente(80)));
    }

    #[test]
    fn los_tres_de_la_web_declaran_sus_dos_mitades() {
        let ds: Vec<Box<dyn Disector>> =
            vec![Box::new(Http2), Box::new(Http3), Box::new(Websocket)];
        for d in &ds {
            assert!(!d.mensajes_que_entiende().is_empty(), "{}", d.nombre());
            assert!(!d.mensajes_que_no_analiza().is_empty(), "{}", d.nombre());
        }
    }
}
