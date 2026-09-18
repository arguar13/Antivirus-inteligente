//! Tuneles y evasion: DoH, DoT, WireGuard, IKEv2, SOCKS y los tuneles sobre
//! protocolos corrientes.
//!
//! # Lo que hay que ver y por que casi nadie lo ve
//!
//! Un tunel no es trafico raro: es trafico **permitido** que lleva dentro otra
//! cosa. DNS sobre HTTPS le quita al sensor la unica ventana que le quedaba a la
//! resolucion de nombres; un SOCKS abierto convierte una maquina comprometida en
//! la puerta de toda la red; WireGuard levanta una red privada en catorce lineas
//! de configuracion y por el puerto que quiera.
//!
//! Los disectores de aqui no dicen «esto es malo». Emiten
//! [`Hecho::IndicioDeTunel`] con su **tecnica** y sus numeros, igual que
//! `aegis-wire` hace con los indicios de tunel sobre DNS. Quien decide es el
//! arbitro; un disector que decidiera seria un disector que se equivoca solo.
//!
//! # El caso honesto: lo que va cifrado
//!
//! De DoT y de WireGuard se ve el sobre y no el contenido. Eso se declara con
//! [`Motivo::Cifrado`] y no con «no implementado», porque son cosas distintas:
//! una se arregla escribiendo codigo y la otra no.

use aegis_wire::error::{ErrorDiseccion, Resultado};
use aegis_wire::hecho::{Hecho, ProtocoloApp};
use aegis_wire::lector::Lector;

use crate::cobertura::{Cobertura, Motivo};
use crate::disector::{Contexto, Disector, Fuerza, Salida};
use crate::texto;

// ════════════════════════════════════════════════════════════════════════════
// DNS sobre HTTPS
// ════════════════════════════════════════════════════════════════════════════

/// El tipo de contenido que la RFC 8484 fija para un mensaje DNS sobre HTTP.
pub const TIPO_DOH: &str = "application/dns-message";

/// Disector de DNS sobre HTTPS.
///
/// # Lo que recupera
///
/// Cuando el trafico se ve en claro —en un proxy que termina TLS, o desde el
/// propio equipo—, el cuerpo de una peticion DoH **es un mensaje DNS entero**.
/// Este disector lo saca y con el vuelve el nombre consultado, que es lo que DoH
/// se llevo.
#[derive(Debug, Default, Clone, Copy)]
pub struct Doh;

impl Doh {
    /// El mensaje DNS que lleva dentro, y como venia.
    fn mensaje(datos: &[u8]) -> Option<(Vec<u8>, &'static str)> {
        let (metodo, ruta, _) = texto::peticion_http(datos)?;
        let tipo = texto::cabecera(datos, "Content-Type").unwrap_or_default();
        let acepta = texto::cabecera(datos, "Accept").unwrap_or_default();
        let parece = tipo.to_ascii_lowercase().contains(TIPO_DOH)
            || acepta.to_ascii_lowercase().contains(TIPO_DOH)
            || ruta.contains("/dns-query");
        if !parece {
            return None;
        }
        if metodo == "GET" {
            // En GET el mensaje va en el parametro `dns`, en base64 de URL.
            let p = ruta.find("dns=")?;
            let resto = &ruta[p + 4..];
            let fin = resto.find('&').unwrap_or(resto.len());
            let crudo = texto::base64(&resto.as_bytes()[..fin])?;
            return Some((crudo, "por-parametro"));
        }
        let cuerpo = texto::fin_de_cabecera(datos).map(|p| datos[p..].to_vec())?;
        if cuerpo.is_empty() {
            return None;
        }
        Some((cuerpo, "por-cuerpo"))
    }

    /// El primer nombre consultado de un mensaje DNS.
    ///
    /// No sigue punteros de compresion **a proposito**: en la seccion de
    /// preguntas no los hay, y seguirlos es como se entra en un bucle con un
    /// mensaje preparado. `aegis-wire` ya tiene el disector completo con su
    /// tope de saltos; aqui solo hace falta el nombre.
    fn primer_nombre(mensaje: &[u8]) -> Option<(String, u16)> {
        let mut l = Lector::nuevo(mensaje);
        let _id = l.u16("dns.id").ok()?;
        let _banderas = l.u16("dns.banderas").ok()?;
        let preguntas = l.u16("dns.preguntas").ok()?;
        if preguntas == 0 {
            return None;
        }
        l.saltar(6, "dns.cuentas").ok()?;
        let mut nombre = String::new();
        for _ in 0..128 {
            let n = l.u8("dns.etiqueta").ok()? as usize;
            if n == 0 {
                break;
            }
            if n & 0xC0 != 0 {
                return None;
            }
            let b = l.tomar(n, "dns.etiqueta").ok()?;
            if !nombre.is_empty() {
                nombre.push('.');
            }
            nombre.push_str(&aegis_wire::lector::ascii_legible(b));
        }
        let tipo = l.u16("dns.tipo").ok()?;
        if nombre.is_empty() {
            return None;
        }
        Some((nombre, tipo))
    }
}

impl Disector for Doh {
    /// Una peticion HTTP con el tipo de contenido o la ruta de la RFC 8484.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Marca
    }

    fn nombre(&self) -> &'static str {
        "doh"
    }

    fn reconoce(&self, datos: &[u8], _ctx: &Contexto) -> bool {
        Doh::mensaje(datos).is_some()
    }

    fn disecar(&self, datos: &[u8], _ctx: &Contexto) -> Salida {
        let Some((mensaje, como)) = Doh::mensaje(datos) else {
            return Salida::sin_analizar(Motivo::NoReconocido);
        };
        let mut hechos = vec![
            Hecho::ProtocoloIdentificado(ProtocoloApp::Doh),
            Hecho::IndicioDeTunel {
                portador: ProtocoloApp::Http,
                tecnica: format!("dns-sobre-https-{como}"),
                detalle: "la resolucion de nombres sale del alcance del sensor de DNS".to_owned(),
            },
        ];
        match Doh::primer_nombre(&mensaje) {
            Some((nombre, tipo)) => {
                hechos.push(Hecho::ConsultaDns {
                    id: 0,
                    nombre,
                    tipo: tipo.to_string(),
                });
                Salida::entendido(hechos)
            }
            // Se reconocio el sobre y el mensaje no se pudo leer: casi siempre
            // porque es una respuesta o porque venia partido.
            None => Salida::no_implementado(hechos),
        }
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "la peticion por cuerpo (POST) y por parametro (GET), con su base64 de URL",
            "el nombre consultado y su tipo, que es lo que DoH se llevo",
            "la ruta /dns-query y el tipo application/dns-message",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "las respuestas y sus registros, que son cosa del disector de DNS de aegis-wire",
            "los nombres con punteros de compresion, que aqui no se siguen a proposito",
            "el trafico DoH real, que va dentro de TLS: esto solo se ve donde el TLS se termina",
            "las sesiones DoH sobre HTTP/2, donde las cabeceras van comprimidas",
        ]
    }
}

// ════════════════════════════════════════════════════════════════════════════
// DNS sobre TLS
// ════════════════════════════════════════════════════════════════════════════

/// Puerto de DNS sobre TLS.
pub const PUERTO_DOT: u16 = 853;

/// Disector de DNS sobre TLS.
#[derive(Debug, Default, Clone, Copy)]
pub struct Dot;

impl Dot {
    /// Si esto empieza como un registro de TLS.
    fn registro_tls(datos: &[u8]) -> bool {
        let mut l = Lector::nuevo(datos);
        let Ok(tipo) = l.u8("tls.tipo") else {
            return false;
        };
        if !(20..=23).contains(&tipo) {
            return false;
        }
        let Ok(mayor) = l.u8("tls.mayor") else {
            return false;
        };
        mayor == 3
    }
}

impl Disector for Dot {
    /// Un registro TLS y el puerto 853: en el cable no hay mas.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Indicio
    }

    fn nombre(&self) -> &'static str {
        "dot"
    }

    fn reconoce(&self, datos: &[u8], ctx: &Contexto) -> bool {
        // Aqui el puerto SI es el criterio, y se dice: sobre el cable, DNS sobre
        // TLS es indistinguible de cualquier otro TLS. Fingir que se reconoce
        // por contenido seria mentir sobre como funciona.
        ctx.algun_puerto(PUERTO_DOT) && Dot::registro_tls(datos)
    }

    fn disecar(&self, datos: &[u8], ctx: &Contexto) -> Salida {
        // Reconocer y disecar tienen que decidir lo mismo: este disector usa el
        // contexto —el transporte, el puerto o el sentido— para reclamar un
        // flujo, y sin esta guarda afirmaria su protocolo cuando alguien lo
        // llamara directamente sobre un flujo que no es suyo.
        if !self.reconoce(datos, ctx) {
            return Salida::sin_analizar(Motivo::NoReconocido);
        }

        let hechos = vec![
            Hecho::ProtocoloIdentificado(ProtocoloApp::Dot),
            Hecho::IndicioDeTunel {
                portador: ProtocoloApp::Tls,
                tecnica: "dns-sobre-tls".to_owned(),
                detalle: "por el puerto 853: la resolucion de nombres va cifrada y el \
                          sensor de DNS no la ve"
                    .to_owned(),
            },
        ];
        // El contenido esta cifrado: no es que falte trabajo, es que no esta.
        let mut cobertura = Cobertura::nueva();
        cobertura.sin_analizar(Motivo::Cifrado);
        Salida { hechos, cobertura }
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &["que hay un canal de DNS sobre TLS abierto, por su puerto y por su registro TLS"]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "las consultas y respuestas, que van cifradas",
            "DNS sobre TLS por un puerto distinto del 853, que en el cable es TLS y nada mas",
            "el saludo TLS en si, que es cosa del disector de TLS de aegis-wire",
        ]
    }
}

// ════════════════════════════════════════════════════════════════════════════
// WireGuard
// ════════════════════════════════════════════════════════════════════════════

/// Puerto habitual de WireGuard, que no es obligatorio.
pub const PUERTO_WIREGUARD: u16 = 51820;

/// Las longitudes exactas de los mensajes de WireGuard.
///
/// Son fijas por diseno del protocolo, y por eso identifican WireGuard **por
/// contenido** sin depender del puerto — que es justo lo que hace falta, porque
/// WireGuard se pone en el puerto que quiera.
const LARGOS: [(u8, usize, &str); 3] = [
    (1, 148, "inicio-de-apreton-de-manos"),
    (2, 92, "respuesta-de-apreton-de-manos"),
    (3, 64, "respuesta-con-galleta"),
];

/// Disector de WireGuard.
#[derive(Debug, Default, Clone, Copy)]
pub struct Wireguard;

impl Wireguard {
    fn tipo(datos: &[u8]) -> Option<(u8, &'static str)> {
        let mut l = Lector::nuevo(datos);
        let tipo = l.u8("wg.tipo").ok()?;
        // Los tres bytes siguientes son reserva y valen cero por la norma:
        // comprobarlos es lo que impide que cualquier datagrama corto pase.
        let reserva = l.tomar(3, "wg.reserva").ok()?;
        if reserva != [0, 0, 0] {
            return None;
        }
        for (t, largo, nombre) in LARGOS {
            if tipo == t {
                return if datos.len() == largo {
                    Some((tipo, nombre))
                } else {
                    None
                };
            }
        }
        // Los datos de transporte no tienen longitud fija, pero si minimo: tipo,
        // reserva, indice, contador y al menos la etiqueta de autenticacion.
        if tipo == 4 && datos.len() >= 32 {
            return Some((4, "datos-de-transporte"));
        }
        None
    }
}

impl Disector for Wireguard {
    /// Longitud exacta por tipo de mensaje y tres bytes de reserva a cero.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Marca
    }

    fn nombre(&self) -> &'static str {
        "wireguard"
    }

    fn reconoce(&self, datos: &[u8], ctx: &Contexto) -> bool {
        // Los datos de transporte solos son demasiado poco para acusar a un
        // flujo: se aceptan cuando ya hay un indicio de puerto, y los apretones
        // de manos —que tienen longitud exacta— valen por si mismos.
        match Wireguard::tipo(datos) {
            Some((4, _)) => ctx.algun_puerto(PUERTO_WIREGUARD),
            Some(_) => !ctx.ordenado,
            None => false,
        }
    }

    fn disecar(&self, datos: &[u8], ctx: &Contexto) -> Salida {
        // Reconocer y disecar tienen que decidir lo mismo: este disector usa el
        // contexto —el transporte, el puerto o el sentido— para reclamar un
        // flujo, y sin esta guarda afirmaria su protocolo cuando alguien lo
        // llamara directamente sobre un flujo que no es suyo.
        if !self.reconoce(datos, ctx) {
            return Salida::sin_analizar(Motivo::NoReconocido);
        }
        let Some((tipo, nombre)) = Wireguard::tipo(datos) else {
            return Salida::sin_analizar(Motivo::NoReconocido);
        };
        let mut hechos = vec![
            Hecho::ProtocoloIdentificado(ProtocoloApp::Wireguard),
            Hecho::IndicioDeTunel {
                portador: ProtocoloApp::Wireguard,
                tecnica: format!("wireguard-{nombre}"),
                detalle: "una red privada levantada sobre este enlace: lo que viaje dentro \
                          no lo ve ningun sensor de red"
                    .to_owned(),
            },
        ];
        // Del apreton de manos sale el indice del emisor, que ata los dos
        // sentidos del mismo tunel aunque cambien las direcciones.
        if tipo == 1 || tipo == 2 {
            let mut l = Lector::nuevo(datos);
            if l.saltar(4, "wg.cabecera").is_ok() {
                if let Ok(indice) = l.u32_le("wg.indice") {
                    hechos.push(Hecho::AnomaliaDeFlujo {
                        codigo: "wireguard-indice",
                        detalle: format!("indice del emisor {indice}"),
                    });
                }
            }
        }
        let mut cobertura = Cobertura::nueva();
        cobertura.sin_analizar(Motivo::Cifrado);
        Salida { hechos, cobertura }
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "los cuatro tipos de mensaje, por su longitud exacta y su reserva a cero",
            "el indice del emisor de un apreton de manos, que ata los dos sentidos del tunel",
            "la identificacion por contenido, sin depender del puerto",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "las claves publicas del apreton de manos, que van cifradas con la clave estatica del par",
            "el contenido de los datos de transporte, que es el trafico tunelizado",
            "la marca de tiempo del iniciador, cifrada igual",
        ]
    }
}

// ════════════════════════════════════════════════════════════════════════════
// IKEv2
// ════════════════════════════════════════════════════════════════════════════

/// Puertos de IKE: el original y el de travesia de NAT.
pub const PUERTOS_IKE: [u16; 2] = [500, 4500];

/// El tipo de intercambio de IKEv2.
fn intercambio_ike(t: u8) -> Option<&'static str> {
    Some(match t {
        34 => "inicio-de-asociacion",
        35 => "autenticacion",
        36 => "crear-asociacion-hija",
        37 => "informativo",
        43 => "sesion-de-reanudacion",
        _ => return None,
    })
}

/// Disector de IKEv2.
#[derive(Debug, Default, Clone, Copy)]
pub struct Ikev2;

impl Ikev2 {
    /// `(intercambio, es_peticion, longitud, con marca de travesia de NAT)`.
    fn cabecera(datos: &[u8]) -> Resultado<(u8, bool, usize, bool)> {
        // Por el 4500 va delante una marca de cuatro ceros que separa IKE de
        // ESP. Sin saltarla, toda la cabecera se lee cuatro bytes antes.
        let con_marca = datos.len() > 4 && datos[..4] == [0, 0, 0, 0];
        let base = usize::from(con_marca) * 4;
        let mut l = Lector::nuevo(datos);
        l.ir_a(base, "ike.inicio")?;
        let iniciador = l.u64("ike.spi-del-iniciador")?;
        if iniciador == 0 {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("ikev2"));
        }
        l.saltar(8, "ike.spi-del-respondedor")?;
        l.saltar(1, "ike.siguiente-carga")?;
        let version = l.u8("ike.version")?;
        if version >> 4 != 2 {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("ikev2"));
        }
        let intercambio = l.u8("ike.intercambio")?;
        if intercambio_ike(intercambio).is_none() {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("ikev2"));
        }
        // De las ocho banderas solo tres estan definidas —iniciador, version y
        // respuesta—: las otras cinco estan reservadas y valen cero. Sin exigirlo,
        // «version dos y un intercambio conocido» le pasa a una de cada mil
        // entradas cualesquiera, y se midio que pasaba.
        let banderas = l.u8("ike.banderas")?;
        if banderas & 0xC7 != 0 {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("ikev2"));
        }
        let _id = l.u32("ike.identificador")?;
        let largo = l.u32("ike.longitud")? as usize;
        if largo < 28 {
            return Err(ErrorDiseccion::ValorInvalido {
                campo: "ike.longitud",
                valor: largo as u64,
            });
        }
        // IKE va sobre UDP y un mensaje es un datagrama entero: la longitud
        // declarada tiene que ser exactamente lo que hay tras la marca.
        if base.saturating_add(largo) != datos.len() {
            return Err(ErrorDiseccion::LongitudImposible {
                campo: "ike.longitud",
                declarada: base + largo,
                disponible: datos.len(),
            });
        }
        // El bit de respuesta esta en la posicion cinco de las banderas.
        Ok((intercambio, banderas & 0x20 == 0, largo, con_marca))
    }
}

impl Disector for Ikev2 {
    /// Version dos, intercambio conocido y longitud minima.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Forma
    }

    fn nombre(&self) -> &'static str {
        "ikev2"
    }

    fn reconoce(&self, datos: &[u8], _ctx: &Contexto) -> bool {
        Ikev2::cabecera(datos).is_ok()
    }

    fn disecar(&self, datos: &[u8], _ctx: &Contexto) -> Salida {
        let (intercambio, peticion, largo, con_marca) = match Ikev2::cabecera(datos) {
            Ok(v) => v,
            Err(e) => return Salida::sin_analizar(Motivo::de_error(&e)),
        };
        let nombre = intercambio_ike(intercambio).unwrap_or("desconocido");
        let hechos = vec![
            Hecho::ProtocoloIdentificado(ProtocoloApp::Ikev2),
            Hecho::IndicioDeTunel {
                portador: ProtocoloApp::Ikev2,
                tecnica: format!("ipsec-{nombre}"),
                detalle: format!(
                    "{} de {largo} bytes{}",
                    if peticion { "peticion" } else { "respuesta" },
                    if con_marca {
                        ", con travesia de NAT"
                    } else {
                        ""
                    }
                ),
            },
        ];
        Salida::entendido(hechos)
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "la cabecera de IKEv2 con su tipo de intercambio y si es peticion o respuesta",
            "la marca de travesia de NAT del puerto 4500, que hay que saltar para leer bien",
            "los indices de seguridad que atan los dos sentidos",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "las cargas del intercambio: propuestas, identidades y certificados",
            "las cargas cifradas del intercambio de autenticacion",
            "IKEv1, que tiene otra cabecera y otro juego de intercambios",
            "el trafico ESP que viene despues, que es la carga tunelizada",
        ]
    }
}

// ════════════════════════════════════════════════════════════════════════════
// SOCKS
// ════════════════════════════════════════════════════════════════════════════

/// Puerto habitual de SOCKS, que tampoco es obligatorio.
pub const PUERTO_SOCKS: u16 = 1080;

/// Disector de SOCKS 4 y 5.
///
/// # Por que es el que mas dice
///
/// Porque de una peticion de SOCKS sale **el destino final**: la maquina y el
/// puerto a los que el cliente quiere llegar a traves de este equipo. Un sensor
/// que solo vea la conexion al proxy ve una conversacion; con esto ve el mapa.
#[derive(Debug, Default, Clone, Copy)]
pub struct Socks;

/// Lo que se saco de una peticion de SOCKS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Peticion {
    /// El saludo de SOCKS 5 con los metodos que ofrece el cliente.
    Saludo {
        /// Los metodos de autenticacion ofrecidos.
        metodos: Vec<u8>,
    },
    /// Una peticion con su orden y su destino.
    Orden {
        /// La version, 4 o 5.
        version: u8,
        /// Conectar, enlazar o asociar UDP.
        orden: &'static str,
        /// El destino, como venia (nombre o direccion).
        destino: String,
        /// El puerto de destino.
        puerto: u16,
    },
}

impl Socks {
    fn orden_socks5(o: u8) -> Option<&'static str> {
        Some(match o {
            1 => "conectar",
            2 => "enlazar",
            3 => "asociar-udp",
            _ => return None,
        })
    }

    fn leer(datos: &[u8]) -> Resultado<Peticion> {
        let mut l = Lector::nuevo(datos);
        let version = l.u8("socks.version")?;
        match version {
            5 => {
                let segundo = l.u8("socks.segundo")? as usize;
                // Un saludo lleva el numero de metodos y luego los metodos, y
                // la longitud total tiene que cuadrar: es lo que separa un
                // saludo de una peticion, porque los dos empiezan por un cinco.
                if datos.len() == 2 + segundo && segundo > 0 {
                    let metodos = l.tomar(segundo, "socks.metodos")?;
                    return Ok(Peticion::Saludo {
                        metodos: metodos.to_vec(),
                    });
                }
                let Some(orden) = Socks::orden_socks5(segundo as u8) else {
                    return Err(ErrorDiseccion::NoEsEsteProtocolo("socks"));
                };
                let reservado = l.u8("socks.reservado")?;
                if reservado != 0 {
                    return Err(ErrorDiseccion::NoEsEsteProtocolo("socks"));
                }
                let clase = l.u8("socks.clase-de-direccion")?;
                let destino = match clase {
                    1 => {
                        let b = l.tomar(4, "socks.ipv4")?;
                        format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
                    }
                    3 => {
                        let n = l.u8("socks.longitud-del-nombre")? as usize;
                        if n == 0 {
                            return Err(ErrorDiseccion::ValorInvalido {
                                campo: "socks.longitud-del-nombre",
                                valor: 0,
                            });
                        }
                        let b = l.tomar(n, "socks.nombre")?;
                        aegis_wire::lector::ascii_legible(b)
                    }
                    4 => {
                        let b = l.tomar(16, "socks.ipv6")?;
                        let grupos: Vec<String> = b
                            .chunks_exact(2)
                            .map(|p| format!("{:x}", u16::from_be_bytes([p[0], p[1]])))
                            .collect();
                        grupos.join(":")
                    }
                    otra => {
                        return Err(ErrorDiseccion::ValorInvalido {
                            campo: "socks.clase-de-direccion",
                            valor: u64::from(otra),
                        })
                    }
                };
                let puerto = l.u16("socks.puerto")?;
                Ok(Peticion::Orden {
                    version: 5,
                    orden,
                    destino,
                    puerto,
                })
            }
            4 => {
                let orden = match l.u8("socks.orden")? {
                    1 => "conectar",
                    2 => "enlazar",
                    otra => {
                        return Err(ErrorDiseccion::ValorInvalido {
                            campo: "socks.orden",
                            valor: u64::from(otra),
                        })
                    }
                };
                let puerto = l.u16("socks.puerto")?;
                let ip = l.tomar(4, "socks.ipv4")?;
                let (u, _) =
                    texto::cadena_con_cero(l.resto(), 256).ok_or(ErrorDiseccion::Truncado {
                        campo: "socks.usuario",
                        esperados: 1,
                        habia: 0,
                    })?;
                // En SOCKS 4a una direccion 0.0.0.x con x distinto de cero dice
                // que el nombre real viene detras del usuario.
                let destino = if ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] != 0 {
                    let tras_usuario = &l.resto()[(u.len() + 1).min(l.restante())..];
                    texto::cadena_con_cero(tras_usuario, 256)
                        .map(|(n, _)| n)
                        .unwrap_or_else(|| "0.0.0.0".to_owned())
                } else {
                    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
                };
                Ok(Peticion::Orden {
                    version: 4,
                    orden,
                    destino,
                    puerto,
                })
            }
            _ => Err(ErrorDiseccion::NoEsEsteProtocolo("socks")),
        }
    }
}

impl Disector for Socks {
    /// Version, orden y clase de direccion que cuadran con la longitud.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Forma
    }

    fn nombre(&self) -> &'static str {
        "socks"
    }

    fn reconoce(&self, datos: &[u8], ctx: &Contexto) -> bool {
        ctx.del_cliente && Socks::leer(datos).is_ok()
    }

    fn disecar(&self, datos: &[u8], ctx: &Contexto) -> Salida {
        // Reconocer y disecar tienen que decidir lo mismo: este disector usa el
        // contexto —el transporte, el puerto o el sentido— para reclamar un
        // flujo, y sin esta guarda afirmaria su protocolo cuando alguien lo
        // llamara directamente sobre un flujo que no es suyo.
        if !self.reconoce(datos, ctx) {
            return Salida::sin_analizar(Motivo::NoReconocido);
        }
        match Socks::leer(datos) {
            Ok(Peticion::Saludo { metodos }) => {
                let sin_autenticar = metodos.contains(&0);
                let mut hechos = vec![
                    Hecho::ProtocoloIdentificado(ProtocoloApp::Socks),
                    Hecho::IndicioDeTunel {
                        portador: ProtocoloApp::Socks,
                        tecnica: "socks5-saludo".to_owned(),
                        detalle: format!(
                            "metodos ofrecidos: {}",
                            metodos
                                .iter()
                                .map(u8::to_string)
                                .collect::<Vec<_>>()
                                .join(",")
                        ),
                    },
                ];
                if sin_autenticar {
                    hechos.push(Hecho::AnomaliaDeFlujo {
                        codigo: "socks-sin-autenticacion",
                        detalle: "el cliente ofrece conectarse sin autenticarse".to_owned(),
                    });
                }
                Salida::entendido(hechos)
            }
            Ok(Peticion::Orden {
                version,
                orden,
                destino,
                puerto,
            }) => Salida::entendido(vec![
                Hecho::ProtocoloIdentificado(ProtocoloApp::Socks),
                Hecho::IndicioDeTunel {
                    portador: ProtocoloApp::Socks,
                    tecnica: format!("socks{version}-{orden}"),
                    detalle: format!("hacia {destino}:{puerto}"),
                },
                // El destino como hecho aparte: es el mapa de a donde queria
                // llegar quien uso este equipo de puente.
                Hecho::EjecucionRemota {
                    via: ProtocoloApp::Socks,
                    orden: orden.to_owned(),
                    objetivo: format!("{destino}:{puerto}"),
                },
            ]),
            Err(e) => Salida::sin_analizar(Motivo::de_error(&e)),
        }
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "el saludo de SOCKS 5 con sus metodos, incluido el de no autenticarse",
            "conectar, enlazar y asociar-udp, con su destino y su puerto",
            "los tres tipos de direccion: IPv4, nombre e IPv6",
            "SOCKS 4 y su variante 4a, donde el nombre viaja detras del usuario",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "las respuestas del proxy y su codigo de resultado",
            "el dialogo de autenticacion por usuario y contrasena (RFC 1929)",
            "el trafico que pasa por el tunel una vez abierto",
            "la cabecera de los datagramas de la asociacion UDP",
        ]
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Tuneles sobre protocolos corrientes
// ════════════════════════════════════════════════════════════════════════════

/// A partir de cuantos bits por byte se considera que un campo de texto lleva
/// algo que no es texto.
///
/// Cuatro y medio esta por encima de la entropia del castellano y del ingles
/// —que rondan los cuatro— y por debajo de la de un cifrado o un comprimido, que
/// pasan de siete. El umbral no acusa a nadie: enciende el indicio.
pub const ENTROPIA_SOSPECHOSA: f64 = 4.5;

/// El umbral para una carga **binaria**, que es otro y mas alto.
///
/// Un campo de texto se compara con texto: el castellano ronda los cuatro bits
/// por caracter, asi que cuatro y medio ya es raro. Una carga de ICMP se compara
/// con lo que manda un `ping` del sistema, que es un patron fijo, y con lo que
/// mete un tunel, que va cifrado o comprimido y se acerca a ocho. Usar el umbral
/// del texto aqui encenderia el indicio con cualquier relleno variado, y un
/// indicio que salta con trafico corriente entierra el que importa.
pub const ENTROPIA_DE_CARGA_BINARIA: f64 = 7.0;

/// Cuanto tiene que medir un campo para que su entropia signifique algo.
///
/// Con veinte bytes, cualquier cosa parece aleatoria. El minimo es lo que separa
/// una medida de una casualidad.
pub const MINIMO_PARA_MEDIR: usize = 128;

/// Disector de tuneles sobre HTTP e ICMP.
///
/// # Lo que mira, y por que no dice «malicioso»
///
/// Mide: la entropia de lo que va en una galleta o en un campo de agente, la
/// fraccion de alfabeto base64, y el tamano de una carga de ICMP comparado con
/// lo que mandan los `ping` del sistema. Con eso emite un indicio con sus
/// numeros. Decidir es del arbitro: un disector que decidiera se equivocaria
/// solo, y ademas con datos de una sola conexion.
#[derive(Debug, Default, Clone, Copy)]
pub struct Tunel;

impl Tunel {
    /// Un campo de texto que lleva datos, con su medida.
    fn campo_cargado(datos: &[u8], cabecera: &str) -> Option<(String, f64, u8)> {
        let valor = texto::cabecera(datos, cabecera)?;
        if valor.len() < MINIMO_PARA_MEDIR {
            return None;
        }
        let e = texto::entropia(valor.as_bytes());
        let b64 = texto::fraccion_base64(valor.as_bytes());
        if e >= ENTROPIA_SOSPECHOSA && b64 >= 90 {
            Some((cabecera.to_owned(), e, b64))
        } else {
            None
        }
    }

    /// Una carga de ICMP de eco con su medida, si la hay.
    ///
    /// Un `ping` del sistema manda un patron fijo —en Linux, los bytes del cero
    /// al cincuenta y cinco en orden— y lo mismo en cada paquete. Una carga con
    /// entropia alta en un eco no es un ping.
    fn eco_icmp(datos: &[u8]) -> Option<(usize, f64)> {
        let mut l = Lector::nuevo(datos);
        let tipo = l.u8("icmp.tipo").ok()?;
        if tipo != 8 && tipo != 0 {
            return None;
        }
        let codigo = l.u8("icmp.codigo").ok()?;
        if codigo != 0 {
            return None;
        }
        l.saltar(2, "icmp.suma").ok()?;
        l.saltar(4, "icmp.identificador-y-secuencia").ok()?;
        let carga = l.resto();
        if carga.len() < MINIMO_PARA_MEDIR {
            return None;
        }
        Some((carga.len(), texto::entropia(carga)))
    }
}

impl Disector for Tunel {
    /// Una medida estadistica, que por definicion no es una marca.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Indicio
    }

    fn nombre(&self) -> &'static str {
        "tunel"
    }

    fn reconoce(&self, datos: &[u8], ctx: &Contexto) -> bool {
        if ctx.ordenado {
            ["Cookie", "User-Agent", "Referer", "X-Forwarded-For"]
                .iter()
                .any(|c| Tunel::campo_cargado(datos, c).is_some())
        } else {
            Tunel::eco_icmp(datos).is_some_and(|(_, e)| e >= ENTROPIA_DE_CARGA_BINARIA)
        }
    }

    fn disecar(&self, datos: &[u8], ctx: &Contexto) -> Salida {
        let mut hechos = Vec::new();
        if ctx.ordenado {
            for campo in ["Cookie", "User-Agent", "Referer", "X-Forwarded-For"] {
                if let Some((nombre, e, b64)) = Tunel::campo_cargado(datos, campo) {
                    hechos.push(Hecho::IndicioDeTunel {
                        portador: ProtocoloApp::Http,
                        tecnica: "datos-en-cabecera-de-http".to_owned(),
                        detalle: format!(
                            "la cabecera {nombre} lleva {e:.1} bits por caracter y un \
                             {b64}% de alfabeto base64, que no es lo que lleva ese campo \
                             normalmente"
                        ),
                    });
                }
            }
        } else if let Some((largo, e)) = Tunel::eco_icmp(datos) {
            if e >= ENTROPIA_DE_CARGA_BINARIA {
                hechos.push(Hecho::IndicioDeTunel {
                    portador: ProtocoloApp::Desconocido,
                    tecnica: "datos-en-eco-de-icmp".to_owned(),
                    detalle: format!(
                        "un eco con {largo} bytes de carga a {e:.1} bits por byte; un ping \
                         del sistema manda un patron fijo y de entropia baja"
                    ),
                });
            }
        }
        if hechos.is_empty() {
            return Salida::sin_analizar(Motivo::NoReconocido);
        }
        Salida::entendido(hechos)
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "la entropia y la fraccion base64 de las cabeceras Cookie, User-Agent, Referer y X-Forwarded-For",
            "la carga de un eco de ICMP y su entropia, medida con el umbral de una carga \
             binaria y no con el de un texto",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "lo que lleve el tunel dentro: esto mide la forma, no lee el contenido",
            "los tuneles sobre DNS, que ya mide el disector de DNS de aegis-wire",
            "la periodicidad entre paquetes, que necesita ver el flujo entero y no un mensaje",
            "los campos de menos de ciento veintiocho bytes, donde la entropia no significa nada",
        ]
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn tunel(s: &Salida) -> Option<(&str, &str)> {
        s.hechos.iter().find_map(|h| match h {
            Hecho::IndicioDeTunel {
                tecnica, detalle, ..
            } => Some((tecnica.as_str(), detalle.as_str())),
            _ => None,
        })
    }

    /// Un mensaje DNS de consulta de `ejemplo.es`, tipo A.
    fn mensaje_dns() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&0x1234u16.to_be_bytes());
        v.extend_from_slice(&0x0100u16.to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        v.push(7);
        v.extend_from_slice(b"ejemplo");
        v.push(2);
        v.extend_from_slice(b"es");
        v.push(0);
        v.extend_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes());
        v
    }

    #[test]
    fn doh_recupera_el_nombre_que_se_habia_llevado() {
        // Es lo que DoH le quita al sensor: cuando el trafico se ve en claro, el
        // cuerpo de la peticion es un mensaje DNS entero.
        let d = Doh;
        let mut b = b"POST /dns-query HTTP/1.1\r\nHost: doh\r\nContent-Type: application/dns-message\r\n\r\n".to_vec();
        b.extend_from_slice(&mensaje_dns());
        assert!(d.reconoce(&b, &Contexto::tcp_cliente(443)));
        let s = d.disecar(&b, &Contexto::tcp_cliente(443));
        assert!(s.cobertura.completa());
        let nombre = s.hechos.iter().find_map(|h| match h {
            Hecho::ConsultaDns { nombre, .. } => Some(nombre.as_str()),
            _ => None,
        });
        assert_eq!(nombre, Some("ejemplo.es"));
        assert!(tunel(&s).is_some_and(|(t, _)| t.starts_with("dns-sobre-https")));
    }

    #[test]
    fn doh_lee_tambien_la_forma_con_el_mensaje_en_la_ruta() {
        let d = Doh;
        const ALFABETO: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let m = mensaje_dns();
        let mut b64 = String::new();
        for trozo in m.chunks(3) {
            let mut bloque = [0u8; 3];
            bloque[..trozo.len()].copy_from_slice(trozo);
            let n = u32::from(bloque[0]) << 16 | u32::from(bloque[1]) << 8 | u32::from(bloque[2]);
            for i in 0..=trozo.len() {
                b64.push(ALFABETO[((n >> (18 - 6 * i)) & 0x3F) as usize] as char);
            }
        }
        let peticion = format!("GET /dns-query?dns={b64} HTTP/1.1\r\nHost: doh\r\nAccept: application/dns-message\r\n\r\n");
        let s = d.disecar(peticion.as_bytes(), &Contexto::tcp_cliente(443));
        assert_eq!(
            s.hechos.iter().find_map(|h| match h {
                Hecho::ConsultaDns { nombre, .. } => Some(nombre.as_str()),
                _ => None,
            }),
            Some("ejemplo.es")
        );
    }

    #[test]
    fn doh_no_sigue_un_puntero_de_compresion() {
        // Seguirlos es como se entra en un bucle con un mensaje preparado, y en
        // la seccion de preguntas no los hay.
        let mut m = mensaje_dns();
        m[12] = 0xC0;
        m[13] = 0x0C;
        assert!(Doh::primer_nombre(&m).is_none());
    }

    #[test]
    fn dot_declara_que_se_reconoce_por_el_puerto() {
        // Sobre el cable, DNS sobre TLS es indistinguible de cualquier otro TLS.
        // Fingir que se reconoce por contenido seria mentir sobre como funciona.
        let d = Dot;
        let b = [0x16u8, 0x03, 0x01, 0x00, 0x2a];
        assert!(d.reconoce(&b, &Contexto::tcp_cliente(PUERTO_DOT)));
        assert!(!d.reconoce(&b, &Contexto::tcp_cliente(443)));
        let s = d.disecar(&b, &Contexto::tcp_cliente(PUERTO_DOT));
        assert_eq!(s.cobertura.sin_analizar.get(&Motivo::Cifrado), Some(&1));
    }

    #[test]
    fn wireguard_se_reconoce_por_su_longitud_exacta_y_no_por_el_puerto() {
        // WireGuard se pone en el puerto que quiera; sus mensajes tienen
        // longitud fija por diseno.
        let d = Wireguard;
        let mut b = vec![1u8, 0, 0, 0];
        b.extend_from_slice(&7u32.to_le_bytes());
        b.resize(148, 0);
        assert!(d.reconoce(&b, &Contexto::udp(33333)));
        let s = d.disecar(&b, &Contexto::udp(33333));
        assert!(tunel(&s).is_some_and(|(t, _)| t.contains("inicio-de-apreton")));
        assert!(s
            .hechos
            .iter()
            .any(|h| matches!(h, Hecho::AnomaliaDeFlujo { detalle, .. } if detalle.contains("7"))));
    }

    #[test]
    fn wireguard_no_acepta_un_apreton_de_longitud_equivocada() {
        let d = Wireguard;
        let mut b = vec![1u8, 0, 0, 0];
        b.resize(100, 0);
        assert!(!d.reconoce(&b, &Contexto::udp(PUERTO_WIREGUARD)));
    }

    #[test]
    fn wireguard_exige_la_reserva_a_cero() {
        // Es lo que impide que cualquier datagrama corto pase por WireGuard.
        let d = Wireguard;
        let mut b = vec![1u8, 9, 9, 9];
        b.resize(148, 0);
        assert!(!d.reconoce(&b, &Contexto::udp(PUERTO_WIREGUARD)));
    }

    /// Una cabecera de IKE_SA_INIT, con y sin la marca del 4500.
    fn ike(con_marca: bool) -> Vec<u8> {
        let mut v = Vec::new();
        if con_marca {
            v.extend_from_slice(&[0, 0, 0, 0]);
        }
        v.extend_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes());
        v.extend_from_slice(&0u64.to_be_bytes());
        v.push(33); // siguiente carga
        v.push(0x20); // version 2.0
        v.push(34); // inicio de asociacion
        v.push(0x08); // iniciador
        v.extend_from_slice(&0u32.to_be_bytes());
        v.extend_from_slice(&28u32.to_be_bytes());
        v
    }

    #[test]
    fn ikev2_salta_la_marca_de_travesia_de_nat() {
        // Sin saltarla, toda la cabecera se lee cuatro bytes antes.
        let d = Ikev2;
        for con_marca in [false, true] {
            let b = ike(con_marca);
            assert!(
                d.reconoce(&b, &Contexto::udp(PUERTOS_IKE[1])),
                "{con_marca}"
            );
            let s = d.disecar(&b, &Contexto::udp(PUERTOS_IKE[1]));
            let (t, det) = tunel(&s).expect("un indicio");
            assert_eq!(t, "ipsec-inicio-de-asociacion");
            assert_eq!(det.contains("travesia"), con_marca, "{det}");
        }
    }

    #[test]
    fn socks_saca_el_destino_final_que_es_el_mapa() {
        // Un sensor que solo vea la conexion al proxy ve una conversacion; con
        // esto ve a donde queria llegar quien uso el equipo de puente.
        let d = Socks;
        let mut b = vec![5u8, 1, 0, 3, 11];
        b.extend_from_slice(b"interno.red");
        b.extend_from_slice(&445u16.to_be_bytes());
        assert!(d.reconoce(&b, &Contexto::tcp_cliente(PUERTO_SOCKS)));
        let s = d.disecar(&b, &Contexto::tcp_cliente(PUERTO_SOCKS));
        assert!(s.cobertura.completa());
        assert_eq!(
            tunel(&s),
            Some(("socks5-conectar", "hacia interno.red:445"))
        );
    }

    #[test]
    fn socks_distingue_el_saludo_de_la_peticion_aunque_empiecen_igual() {
        // Los dos empiezan por un cinco: la longitud total es lo que los separa.
        let d = Socks;
        let saludo = [5u8, 2, 0, 2];
        let s = d.disecar(&saludo, &Contexto::tcp_cliente(PUERTO_SOCKS));
        assert!(tunel(&s).is_some_and(|(t, _)| t == "socks5-saludo"));
        assert!(
            s.hechos.iter().any(|h| matches!(
                h,
                Hecho::AnomaliaDeFlujo { codigo, .. } if *codigo == "socks-sin-autenticacion"
            )),
            "{:?}",
            s.hechos
        );
    }

    #[test]
    fn socks4a_lee_el_nombre_que_va_detras_del_usuario() {
        let d = Socks;
        let mut b = vec![4u8, 1];
        b.extend_from_slice(&80u16.to_be_bytes());
        b.extend_from_slice(&[0, 0, 0, 1]);
        b.extend_from_slice(b"ana\0");
        b.extend_from_slice(b"destino.ext\0");
        let s = d.disecar(&b, &Contexto::tcp_cliente(PUERTO_SOCKS));
        assert_eq!(tunel(&s).map(|(_, det)| det), Some("hacia destino.ext:80"));
    }

    #[test]
    fn un_tunel_sobre_http_se_mide_y_no_se_acusa() {
        // El disector emite el indicio con sus numeros. Decidir es del arbitro.
        let d = Tunel;
        let carga: String =
            std::iter::repeat_n("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5", 6).collect();
        let b = format!("GET / HTTP/1.1\r\nHost: x\r\nCookie: sesion={carga}\r\n\r\n");
        assert!(d.reconoce(b.as_bytes(), &Contexto::tcp_cliente(80)));
        let s = d.disecar(b.as_bytes(), &Contexto::tcp_cliente(80));
        let (t, det) = tunel(&s).expect("un indicio");
        assert_eq!(t, "datos-en-cabecera-de-http");
        assert!(det.contains("bits por caracter"), "{det}");
    }

    #[test]
    fn una_galleta_normal_no_enciende_el_indicio() {
        // Un umbral que se encienda con trafico corriente es peor que no tener
        // umbral: entierra lo que si importa.
        let d = Tunel;
        let b = b"GET / HTTP/1.1\r\nHost: x\r\nCookie: sesion=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n\r\n";
        assert!(!d.reconoce(b, &Contexto::tcp_cliente(80)));
    }

    #[test]
    fn un_ping_del_sistema_no_enciende_el_indicio_de_icmp() {
        // Linux manda del cero al cincuenta y cinco en orden y lo repite: son
        // 5,8 bits por byte, que con el umbral del texto encenderia el indicio
        // en cada ping de la red. Por eso la carga binaria tiene el suyo.
        let d = Tunel;
        let mut b = vec![8u8, 0, 0, 0, 0, 1, 0, 1];
        b.extend((0..=55u8).cycle().take(200));
        assert!(texto::entropia(&b[8..]) > ENTROPIA_SOSPECHOSA);
        assert!(!d.reconoce(&b, &Contexto::udp(0)));

        // Un relleno de ceros, que es lo que mandan otros ping, tampoco.
        let mut ceros = vec![8u8, 0, 0, 0, 0, 1, 0, 1];
        ceros.extend(std::iter::repeat_n(0u8, 200));
        assert!(!d.reconoce(&ceros, &Contexto::udp(0)));

        // Y una carga cifrada o comprimida, que llega a ocho bits por byte, si.
        let mut c = vec![8u8, 0, 0, 0, 0, 1, 0, 1];
        c.extend((0..=255u8).cycle().take(512));
        assert!(d.reconoce(&c, &Contexto::udp(0)));
        let s = d.disecar(&c, &Contexto::udp(0));
        assert!(tunel(&s).is_some_and(|(t, _)| t == "datos-en-eco-de-icmp"));
    }

    #[test]
    fn los_seis_de_tuneles_declaran_sus_dos_mitades() {
        let ds: Vec<Box<dyn Disector>> = vec![
            Box::new(Doh),
            Box::new(Dot),
            Box::new(Wireguard),
            Box::new(Ikev2),
            Box::new(Socks),
            Box::new(Tunel),
        ];
        for d in &ds {
            assert!(!d.mensajes_que_entiende().is_empty(), "{}", d.nombre());
            assert!(!d.mensajes_que_no_analiza().is_empty(), "{}", d.nombre());
        }
    }
}
