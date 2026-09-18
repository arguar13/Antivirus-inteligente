//! Mensajeria: AMQP, MQTT, Kafka y gRPC.
//!
//! # Por que un EDR mira una cola de mensajes
//!
//! Porque una cola es un canal de mando y control que ya esta permitido por el
//! cortafuegos. Un agente que publique en un tema y otro que se suscriba tienen
//! un canal bidireccional a traves de una infraestructura legitima, y el sensor
//! que solo mire conexiones directas no ve nada raro: las dos maquinas hablan
//! con el corredor, como todas las demas.
//!
//! En una red industrial esto no es teorico: MQTT es el transporte por defecto
//! de medio internet de las cosas, y el corredor suele estar en la frontera
//! entre la red de oficina y la de planta.
//!
//! Los cuatro emiten [`Hecho::OperacionDeMensajeria`] con el mismo hueco para el
//! tema, de modo que «quien publica en que» es una consulta.

use aegis_wire::error::{ErrorDiseccion, Resultado};
use aegis_wire::hecho::{Hecho, ProtocoloApp};
use aegis_wire::lector::Lector;

use crate::disector::{Contexto, Disector, Fuerza, Salida};

// ════════════════════════════════════════════════════════════════════════════
// AMQP
// ════════════════════════════════════════════════════════════════════════════

/// Puerto de AMQP.
pub const PUERTO_AMQP: u16 = 5672;

/// El final de trama de AMQP 0-9-1, que va tras cada carga.
const FIN_DE_TRAMA: u8 = 0xCE;

/// El metodo de AMQP 0-9-1, por su clase y su numero.
fn metodo_amqp(clase: u16, metodo: u16) -> Option<(&'static str, bool)> {
    Some(match (clase, metodo) {
        (10, 10) => ("conexion-inicio", false),
        (10, 11) => ("conexion-inicio-ok", false),
        (10, 40) => ("conexion-abrir", false),
        (10, 50) => ("conexion-cerrar", false),
        (20, 10) => ("canal-abrir", false),
        (20, 40) => ("canal-cerrar", false),
        (40, 10) => ("declarar-intercambio", true),
        (40, 20) => ("borrar-intercambio", true),
        (50, 10) => ("declarar-cola", true),
        (50, 20) => ("enlazar-cola", true),
        (50, 30) => ("desenlazar-cola", true),
        (50, 40) => ("vaciar-cola", true),
        (50, 50) => ("borrar-cola", true),
        (60, 20) => ("consumir", false),
        (60, 40) => ("publicar", true),
        (60, 70) => ("recoger", false),
        _ => return None,
    })
}

/// Disector de AMQP 0-9-1 y 1.0.
#[derive(Debug, Default, Clone, Copy)]
pub struct Amqp;

impl Amqp {
    /// Si esto es la cabecera de protocolo: `AMQP` y cuatro bytes de version.
    fn saludo(datos: &[u8]) -> Option<String> {
        if datos.len() < 8 || &datos[..4] != b"AMQP" {
            return None;
        }
        Some(format!(
            "{}.{}.{}.{}",
            datos[4], datos[5], datos[6], datos[7]
        ))
    }

    /// Una trama: `(tipo, canal, carga)`.
    fn trama(datos: &[u8]) -> Resultado<(u8, u16, &[u8])> {
        let mut l = Lector::nuevo(datos);
        let tipo = l.u8("amqp.tipo")?;
        if !(1..=8).contains(&tipo) {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("amqp"));
        }
        let canal = l.u16("amqp.canal")?;
        let largo = l.u32("amqp.longitud")? as usize;
        // El maximo negociable de AMQP son 128 kilobytes por defecto y la propia
        // norma lo acota a 2^32; aqui se corta antes porque un cuerpo mayor no
        // se analiza de todas formas y reservarlo lo decidiria el emisor.
        if largo > 1024 * 1024 {
            return Err(ErrorDiseccion::LimiteExcedido {
                campo: "amqp.longitud",
                valor: largo,
                tope: 1024 * 1024,
            });
        }
        let carga = l.tomar(largo, "amqp.carga")?;
        // El byte de fin de trama es lo que separa una trama de AMQP de
        // cualquier buffer que empiece por un uno.
        let fin = l.u8("amqp.fin")?;
        if fin != FIN_DE_TRAMA {
            return Err(ErrorDiseccion::ValorInvalido {
                campo: "amqp.fin",
                valor: u64::from(fin),
            });
        }
        Ok((tipo, canal, carga))
    }

    /// Una cadena corta de AMQP: un byte de longitud y su texto.
    fn cadena_corta(l: &mut Lector<'_>, campo: &'static str) -> Resultado<String> {
        let n = l.u8(campo)? as usize;
        let b = l.tomar(n, campo)?;
        Ok(aegis_wire::lector::ascii_legible(b))
    }

    fn analizar(datos: &[u8]) -> Resultado<Vec<Hecho>> {
        if let Some(version) = Amqp::saludo(datos) {
            return Ok(vec![
                Hecho::ProtocoloIdentificado(ProtocoloApp::Amqp),
                Hecho::OperacionDeMensajeria {
                    sistema: ProtocoloApp::Amqp,
                    operacion: "saludo".to_owned(),
                    tema: format!("version {version}"),
                },
            ]);
        }
        let (tipo, canal, carga) = Amqp::trama(datos)?;
        let mut hechos = vec![Hecho::ProtocoloIdentificado(ProtocoloApp::Amqp)];
        // Solo las tramas de metodo (tipo 1) llevan clase y numero. Las de
        // cabecera, cuerpo y latido no, y leerlas como si lo llevaran daria un
        // metodo inventado.
        if tipo != 1 {
            let que = match tipo {
                2 => "cabecera-de-contenido",
                3 => "cuerpo-de-contenido",
                8 => "latido",
                _ => "trama",
            };
            hechos.push(Hecho::OperacionDeMensajeria {
                sistema: ProtocoloApp::Amqp,
                operacion: que.to_owned(),
                tema: String::new(),
            });
            return Ok(hechos);
        }
        let mut l = Lector::nuevo(carga);
        let clase = l.u16("amqp.clase")?;
        let metodo = l.u16("amqp.metodo")?;
        let Some((nombre, _cambia)) = metodo_amqp(clase, metodo) else {
            return Err(ErrorDiseccion::ValorInvalido {
                campo: "amqp.metodo",
                valor: (u64::from(clase) << 16) | u64::from(metodo),
            });
        };
        // De publicar, consumir y declarar sale el nombre del intercambio o de
        // la cola, que es el «tema» comun de este modulo.
        let tema = match (clase, metodo) {
            (60, 40) => {
                let _reservado = l.u16("amqp.reservado")?;
                let intercambio = Amqp::cadena_corta(&mut l, "amqp.intercambio")?;
                let clave = Amqp::cadena_corta(&mut l, "amqp.clave-de-encaminamiento")?;
                if intercambio.is_empty() {
                    clave
                } else {
                    format!("{intercambio}/{clave}")
                }
            }
            (50, 10) | (50, 20) | (50, 40) | (50, 50) | (60, 20) | (60, 70) => {
                let _reservado = l.u16("amqp.reservado")?;
                Amqp::cadena_corta(&mut l, "amqp.cola")?
            }
            (40, 10) | (40, 20) => {
                let _reservado = l.u16("amqp.reservado")?;
                Amqp::cadena_corta(&mut l, "amqp.intercambio")?
            }
            _ => String::new(),
        };
        hechos.push(Hecho::OperacionDeMensajeria {
            sistema: ProtocoloApp::Amqp,
            operacion: format!("{nombre} (canal {canal})"),
            tema,
        });
        Ok(hechos)
    }
}

impl Disector for Amqp {
    /// La cabecera `AMQP` o una trama con su byte de fin 0xCE.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Marca
    }

    fn nombre(&self) -> &'static str {
        "amqp"
    }

    fn reconoce(&self, datos: &[u8], _ctx: &Contexto) -> bool {
        Amqp::saludo(datos).is_some() || Amqp::trama(datos).is_ok()
    }

    fn disecar(&self, datos: &[u8], _ctx: &Contexto) -> Salida {
        Salida::de_resultado(Amqp::analizar(datos))
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "la cabecera de protocolo con su version, que distingue 0-9-1 de 1.0",
            "las tramas de metodo con su clase y su numero",
            "publicar, con su intercambio y su clave de encaminamiento",
            "declarar, enlazar, vaciar y borrar colas e intercambios",
            "consumir y recoger, con su cola",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "el cuerpo de los mensajes publicados",
            "las propiedades de la cabecera de contenido",
            "las tablas de argumentos de las declaraciones",
            "AMQP 1.0 mas alla de reconocer su cabecera de protocolo: su codificacion es otra",
        ]
    }
}

// ════════════════════════════════════════════════════════════════════════════
// MQTT
// ════════════════════════════════════════════════════════════════════════════

/// Puertos de MQTT: sin cifrar y sobre TLS.
pub const PUERTOS_MQTT: [u16; 2] = [1883, 8883];

/// El tipo de paquete de MQTT.
fn tipo_mqtt(t: u8) -> Option<&'static str> {
    Some(match t {
        1 => "conectar",
        2 => "conexion-aceptada",
        3 => "publicar",
        4 => "publicacion-reconocida",
        5 => "publicacion-recibida",
        6 => "publicacion-liberada",
        7 => "publicacion-completa",
        8 => "suscribir",
        9 => "suscripcion-reconocida",
        10 => "desuscribir",
        11 => "desuscripcion-reconocida",
        12 => "ping",
        13 => "pong",
        14 => "desconectar",
        15 => "reautenticar",
        _ => return None,
    })
}

/// Disector de MQTT 3.1.1 y 5.0.
#[derive(Debug, Default, Clone, Copy)]
pub struct Mqtt;

impl Mqtt {
    /// La longitud restante, codificada en de uno a cuatro bytes de siete bits.
    ///
    /// El tope de cuatro bytes es de la norma y no una precaucion: sin el, una
    /// cadena de bytes con el bit alto puesto haria girar el bucle sobre el
    /// buffer entero, que es un tamano que elige el emisor.
    fn longitud_restante(l: &mut Lector<'_>) -> Resultado<usize> {
        let mut valor = 0usize;
        let mut multiplicador = 1usize;
        for i in 0..4 {
            let b = l.u8("mqtt.longitud")?;
            valor += usize::from(b & 0x7F) * multiplicador;
            if b & 0x80 == 0 {
                return Ok(valor);
            }
            multiplicador *= 128;
            if i == 3 {
                break;
            }
        }
        Err(ErrorDiseccion::ValorInvalido {
            campo: "mqtt.longitud",
            valor: valor as u64,
        })
    }

    /// Una cadena de MQTT: dos bytes de longitud y su texto en UTF-8.
    fn cadena(l: &mut Lector<'_>, campo: &'static str) -> Resultado<String> {
        let n = l.u16(campo)? as usize;
        let b = l.tomar(n, campo)?;
        Ok(aegis_wire::lector::ascii_legible(b))
    }

    /// La cabecera **y** la comprobacion de que este paquete es de MQTT.
    ///
    /// # Por que una sola funcion decide las dos cosas
    ///
    /// Porque dos funciones que decidan lo mismo acaban decidiendo distinto: lo
    /// encontro el barrido hostil, donde ocho kilobytes de la letra `A` no se
    /// reconocian y sin embargo producian dos hechos. Un sensor que afirme cosas
    /// de un flujo que no ha reclamado es peor que uno que calle.
    fn clasificar(datos: &[u8]) -> Option<(u8, u8, usize, usize)> {
        let (tipo, banderas, largo, pos) = Mqtt::cabecera(datos).ok()?;
        if tipo == 1 {
            // Una conexion se comprueba por su nombre de protocolo, que es la
            // unica marca fija que tiene MQTT.
            let mut l = Lector::nuevo(datos);
            l.ir_a(pos, "mqtt").ok()?;
            let nombre = Mqtt::cadena(&mut l, "mqtt.nombre-de-protocolo").ok()?;
            if nombre != "MQTT" && nombre != "MQIsdp" {
                return None;
            }
            return Some((tipo, banderas, largo, pos));
        }
        // Los demas tipos se aceptan solo si la longitud cuadra con lo que hay:
        // sin eso, dos bytes cualesquiera pasarian por MQTT.
        if largo == 0 || pos.saturating_add(largo) != datos.len() {
            return None;
        }
        Some((tipo, banderas, largo, pos))
    }

    /// `(tipo, banderas, longitud, posicion del cuerpo)`.
    fn cabecera(datos: &[u8]) -> Resultado<(u8, u8, usize, usize)> {
        let mut l = Lector::nuevo(datos);
        let primero = l.u8("mqtt.tipo")?;
        let tipo = primero >> 4;
        if tipo_mqtt(tipo).is_none() {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("mqtt"));
        }
        let largo = Mqtt::longitud_restante(&mut l)?;
        Ok((tipo, primero & 0x0F, largo, l.posicion()))
    }

    fn analizar(datos: &[u8]) -> Resultado<Vec<Hecho>> {
        let Some((tipo, banderas, largo, pos)) = Mqtt::clasificar(datos) else {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("mqtt"));
        };
        let nombre = tipo_mqtt(tipo).unwrap_or("desconocido");
        let mut hechos = vec![Hecho::ProtocoloIdentificado(ProtocoloApp::Mqtt)];
        let fin = pos.saturating_add(largo).min(datos.len());
        let mut l = Lector::nuevo(&datos[..fin]);
        l.ir_a(pos.min(fin), "mqtt.cuerpo")?;

        match tipo {
            1 => {
                let protocolo = Mqtt::cadena(&mut l, "mqtt.nombre-de-protocolo")?;
                if protocolo != "MQTT" && protocolo != "MQIsdp" {
                    return Err(ErrorDiseccion::NoEsEsteProtocolo("mqtt"));
                }
                let nivel = l.u8("mqtt.nivel")?;
                let banderas_conexion = l.u8("mqtt.banderas-de-conexion")?;
                let _mantener_vivo = l.u16("mqtt.mantener-vivo")?;
                // En MQTT 5 hay una lista de propiedades entre el keep-alive y
                // el identificador de cliente. Su longitud va codificada igual
                // que la restante, y saltarsela es lo que separa leer bien el
                // identificador de leer basura.
                if nivel >= 5 {
                    let propiedades = Mqtt::longitud_restante(&mut l)?;
                    l.saltar(propiedades, "mqtt.propiedades")?;
                }
                let cliente = Mqtt::cadena(&mut l, "mqtt.identificador-de-cliente")?;
                hechos.push(Hecho::OperacionDeMensajeria {
                    sistema: ProtocoloApp::Mqtt,
                    operacion: format!("conectar (nivel {nivel})"),
                    tema: cliente,
                });
                // El bit de usuario dice que detras viajan credenciales, y en
                // MQTT viajan en claro salvo que el transporte sea TLS.
                if banderas_conexion & 0x80 != 0 {
                    hechos.push(Hecho::AutenticacionVista {
                        mecanismo: "mqtt-usuario".to_owned(),
                        usuario: String::new(),
                        dominio: String::new(),
                        resultado: if banderas_conexion & 0x40 != 0 {
                            "con contrasena".to_owned()
                        } else {
                            "sin contrasena".to_owned()
                        },
                    });
                }
            }
            3 => {
                let tema = Mqtt::cadena(&mut l, "mqtt.tema")?;
                let calidad = (banderas >> 1) & 0x03;
                let retenido = banderas & 0x01 != 0;
                hechos.push(Hecho::OperacionDeMensajeria {
                    sistema: ProtocoloApp::Mqtt,
                    operacion: format!(
                        "publicar (calidad {calidad}{})",
                        if retenido { ", retenido" } else { "" }
                    ),
                    tema,
                });
            }
            8 | 10 => {
                let _id = l.u16("mqtt.identificador")?;
                let tema = Mqtt::cadena(&mut l, "mqtt.tema")?;
                hechos.push(Hecho::OperacionDeMensajeria {
                    sistema: ProtocoloApp::Mqtt,
                    operacion: nombre.to_owned(),
                    tema,
                });
            }
            _ => hechos.push(Hecho::OperacionDeMensajeria {
                sistema: ProtocoloApp::Mqtt,
                operacion: nombre.to_owned(),
                tema: String::new(),
            }),
        }
        Ok(hechos)
    }
}

impl Disector for Mqtt {
    /// Nombre de protocolo en la conexion, o longitud restante que cuadra con lo que hay.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Forma
    }

    fn nombre(&self) -> &'static str {
        "mqtt"
    }

    fn reconoce(&self, datos: &[u8], _ctx: &Contexto) -> bool {
        Mqtt::clasificar(datos).is_some()
    }

    fn disecar(&self, datos: &[u8], _ctx: &Contexto) -> Salida {
        Salida::de_resultado(Mqtt::analizar(datos))
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "la conexion, con su nivel de protocolo y su identificador de cliente",
            "las propiedades de MQTT 5, que se saltan para leer bien lo que va detras",
            "publicar, con su tema, su calidad de servicio y si queda retenido",
            "suscribir y desuscribir, con su tema",
            "la presencia de usuario y contrasena en la conexion",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "la carga de un mensaje publicado",
            "el usuario y la contrasena en si, que se declaran presentes y no se guardan",
            "los temas adicionales de una suscripcion multiple",
            "el contenido de las propiedades de MQTT 5",
        ]
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Kafka
// ════════════════════════════════════════════════════════════════════════════

/// Puerto de Kafka.
pub const PUERTO_KAFKA: u16 = 9092;

/// La clave de interfaz de Kafka.
fn clave_kafka(k: i16) -> Option<&'static str> {
    Some(match k {
        0 => "producir",
        1 => "recoger",
        2 => "desplazamientos",
        3 => "metadatos",
        8 => "confirmar-desplazamiento",
        9 => "leer-desplazamiento",
        10 => "encontrar-coordinador",
        11 => "unirse-al-grupo",
        12 => "latido",
        13 => "salir-del-grupo",
        14 => "sincronizar-grupo",
        15 => "describir-grupos",
        16 => "listar-grupos",
        17 => "saludo-sasl",
        18 => "versiones",
        19 => "crear-temas",
        20 => "borrar-temas",
        21 => "borrar-registros",
        29 => "describir-permisos",
        30 => "crear-permisos",
        31 => "borrar-permisos",
        32 => "describir-configuracion",
        33 => "alterar-configuracion",
        36 => "autenticar-sasl",
        _ => return None,
    })
}

/// Disector de Kafka.
#[derive(Debug, Default, Clone, Copy)]
pub struct Kafka;

impl Kafka {
    /// `(clave, version, cliente)`.
    fn peticion(datos: &[u8]) -> Resultado<(i16, i16, String)> {
        let mut l = Lector::nuevo(datos);
        let largo = l.u32("kafka.longitud")? as usize;
        // El maximo por defecto de un mensaje de Kafka es un megabyte; la norma
        // lo acota a 2^31. Aqui se corta en cien megas: por encima, el numero no
        // es una longitud sino un buffer que alguien quiere que se reserve.
        if !(8..=100 * 1024 * 1024).contains(&largo) {
            return Err(ErrorDiseccion::ValorInvalido {
                campo: "kafka.longitud",
                valor: largo as u64,
            });
        }
        let clave = l.u16("kafka.clave")? as i16;
        if clave_kafka(clave).is_none() {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("kafka"));
        }
        let version = l.u16("kafka.version")? as i16;
        if !(0..=20).contains(&version) {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("kafka"));
        }
        let _correlacion = l.u32("kafka.correlacion")?;
        // El identificador de cliente es una cadena con longitud de dos bytes
        // con signo: -1 significa nula, que no es lo mismo que vacia.
        let n = l.u16("kafka.cliente")? as i16;
        let cliente = if n <= 0 {
            String::new()
        } else {
            let b = l.tomar(n as usize, "kafka.cliente")?;
            aegis_wire::lector::ascii_legible(b)
        };
        Ok((clave, version, cliente))
    }
}

impl Disector for Kafka {
    /// Longitud, clave de interfaz y version dentro de rango.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Forma
    }

    fn nombre(&self) -> &'static str {
        "kafka"
    }

    fn reconoce(&self, datos: &[u8], _ctx: &Contexto) -> bool {
        Kafka::peticion(datos).is_ok()
    }

    fn disecar(&self, datos: &[u8], _ctx: &Contexto) -> Salida {
        match Kafka::peticion(datos) {
            Ok((clave, version, cliente)) => {
                let nombre = clave_kafka(clave).unwrap_or("desconocida");
                Salida::entendido(vec![
                    Hecho::ProtocoloIdentificado(ProtocoloApp::Kafka),
                    Hecho::OperacionDeMensajeria {
                        sistema: ProtocoloApp::Kafka,
                        operacion: format!("{nombre} (version {version})"),
                        tema: cliente,
                    },
                ])
            }
            Err(e) => Salida::sin_analizar(crate::cobertura::Motivo::de_error(&e)),
        }
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "la cabecera de peticion con su clave de interfaz y su version",
            "el identificador de cliente, distinguiendo nulo de vacio",
            "producir, recoger, crear y borrar temas",
            "la gestion de permisos y de configuracion, que es donde se abre un tema a todos",
            "el saludo y la autenticacion SASL",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "los temas y particiones concretos de una peticion de producir o recoger",
            "los registros del lote y su contenido",
            "las respuestas del corredor",
            "las cabeceras flexibles de las versiones modernas, con su codificacion de longitud variable",
        ]
    }
}

// ════════════════════════════════════════════════════════════════════════════
// gRPC
// ════════════════════════════════════════════════════════════════════════════

/// Disector de gRPC, sobre HTTP/2 y en su variante para navegador.
///
/// # El muro, declarado
///
/// Las cabeceras de HTTP/2 van comprimidas con HPACK y su tabla dinamica es
/// **estado del flujo**: sin haber visto el principio de la conexion no se puede
/// descomprimir lo que viene despues. El disector de [`crate::web`] saca lo que
/// se puede sacar sin esa tabla; aqui se reconoce gRPC por el marco de sus
/// mensajes, que si es fijo.
#[derive(Debug, Default, Clone, Copy)]
pub struct Grpc;

impl Grpc {
    /// Un mensaje de gRPC: un byte de compresion y cuatro de longitud.
    fn mensaje(datos: &[u8]) -> Option<(bool, usize)> {
        let mut l = Lector::nuevo(datos);
        let comprimido = l.u8("grpc.compresion").ok()?;
        if comprimido > 1 {
            return None;
        }
        let largo = l.u32("grpc.longitud").ok()? as usize;
        // El marco tiene que cuadrar con lo que hay: es lo unico que distingue
        // un mensaje de gRPC de cinco bytes cualesquiera.
        if largo == 0 || largo > 4 * 1024 * 1024 || l.restante() < largo {
            return None;
        }
        Some((comprimido == 1, largo))
    }

    /// El tipo de contenido, si estos bytes son una peticion HTTP/1.1.
    fn por_cabecera(datos: &[u8]) -> Option<String> {
        let (_, ruta, _) = crate::texto::peticion_http(datos)?;
        let tipo = crate::texto::cabecera(datos, "Content-Type")?;
        let bajo = tipo.to_ascii_lowercase();
        if bajo.starts_with("application/grpc") {
            Some(ruta)
        } else {
            None
        }
    }
}

impl Disector for Grpc {
    /// Un marco de cinco bytes, o una cabecera HTTP; el marco solo es poco.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Indicio
    }

    fn nombre(&self) -> &'static str {
        "grpc"
    }

    fn reconoce(&self, datos: &[u8], _ctx: &Contexto) -> bool {
        Grpc::por_cabecera(datos).is_some() || Grpc::mensaje(datos).is_some()
    }

    fn disecar(&self, datos: &[u8], _ctx: &Contexto) -> Salida {
        if let Some(ruta) = Grpc::por_cabecera(datos) {
            // De la ruta sale el servicio y el metodo: `/paquete.Servicio/Metodo`.
            let mut partes = ruta.trim_start_matches('/').splitn(2, '/');
            let servicio = partes.next().unwrap_or_default().to_owned();
            let metodo = partes.next().unwrap_or_default().to_owned();
            return Salida::entendido(vec![
                Hecho::ProtocoloIdentificado(ProtocoloApp::Grpc),
                Hecho::EjecucionRemota {
                    via: ProtocoloApp::Grpc,
                    orden: metodo,
                    objetivo: servicio,
                },
            ]);
        }
        let Some((comprimido, largo)) = Grpc::mensaje(datos) else {
            return Salida::sin_analizar(crate::cobertura::Motivo::NoReconocido);
        };
        let hechos = vec![
            Hecho::ProtocoloIdentificado(ProtocoloApp::Grpc),
            Hecho::OperacionDeMensajeria {
                sistema: ProtocoloApp::Grpc,
                operacion: if comprimido {
                    "mensaje-comprimido".to_owned()
                } else {
                    "mensaje".to_owned()
                },
                tema: format!("{largo} bytes"),
            },
        ];
        // Se ve el marco y no el contenido: el cuerpo va en protobuf y sin el
        // fichero de definiciones no se puede nombrar ni un campo.
        Salida::no_implementado(hechos)
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "el marco de un mensaje de gRPC: bandera de compresion y longitud",
            "la ruta de gRPC-Web y de gRPC sobre HTTP/1.1, de donde salen el servicio y el metodo",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "el cuerpo en protobuf: sin el fichero de definiciones no se puede nombrar ni un campo",
            "las cabeceras de gRPC sobre HTTP/2, que van comprimidas con HPACK",
            "los avisos finales (trailers) con el codigo de estado",
            "los mensajes comprimidos, que ademas van comprimidos",
        ]
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn mensajeria(s: &Salida) -> Option<(&str, &str)> {
        s.hechos.iter().find_map(|h| match h {
            Hecho::OperacionDeMensajeria {
                operacion, tema, ..
            } => Some((operacion.as_str(), tema.as_str())),
            _ => None,
        })
    }

    /// Un `basic.publish` de AMQP contra el intercambio `eventos` con la clave
    /// `planta.uno`.
    fn amqp_publicar() -> Vec<u8> {
        let mut carga = Vec::new();
        carga.extend_from_slice(&60u16.to_be_bytes());
        carga.extend_from_slice(&40u16.to_be_bytes());
        carga.extend_from_slice(&0u16.to_be_bytes());
        carga.push(7);
        carga.extend_from_slice(b"eventos");
        carga.push(10);
        carga.extend_from_slice(b"planta.uno");
        let mut v = vec![1u8];
        v.extend_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(&(carga.len() as u32).to_be_bytes());
        v.extend_from_slice(&carga);
        v.push(FIN_DE_TRAMA);
        v
    }

    #[test]
    fn amqp_saca_el_intercambio_y_la_clave_de_una_publicacion() {
        let d = Amqp;
        let b = amqp_publicar();
        assert!(d.reconoce(&b, &Contexto::tcp_cliente(PUERTO_AMQP)));
        let s = d.disecar(&b, &Contexto::tcp_cliente(PUERTO_AMQP));
        assert!(s.cobertura.completa(), "{:?}", s.cobertura);
        let (op, tema) = mensajeria(&s).expect("una operacion");
        assert!(op.starts_with("publicar"), "{op}");
        assert_eq!(tema, "eventos/planta.uno");
    }

    #[test]
    fn amqp_exige_el_byte_de_fin_de_trama() {
        // Es lo que separa una trama de AMQP de cualquier buffer que empiece
        // por un uno: sin comprobarlo, el registro se llena de AMQP inventado.
        let d = Amqp;
        let mut b = amqp_publicar();
        let ultimo = b.len() - 1;
        b[ultimo] = 0x00;
        assert!(!d.reconoce(&b, &Contexto::tcp_cliente(PUERTO_AMQP)));
    }

    #[test]
    fn amqp_no_lee_una_trama_de_cuerpo_como_si_fuera_un_metodo() {
        // Las tramas de cabecera y cuerpo no llevan clase ni numero: leerlas
        // como si los llevaran daria un metodo que nadie mando.
        let d = Amqp;
        let mut v = vec![3u8];
        v.extend_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(&4u32.to_be_bytes());
        v.extend_from_slice(b"hola");
        v.push(FIN_DE_TRAMA);
        let s = d.disecar(&v, &Contexto::tcp_cliente(PUERTO_AMQP));
        assert_eq!(mensajeria(&s).map(|(o, _)| o), Some("cuerpo-de-contenido"));
    }

    /// Un CONNECT de MQTT 3.1.1 con identificador de cliente `sensor-7`.
    fn mqtt_conectar(nivel: u8, banderas: u8) -> Vec<u8> {
        let mut cuerpo = Vec::new();
        cuerpo.extend_from_slice(&4u16.to_be_bytes());
        cuerpo.extend_from_slice(b"MQTT");
        cuerpo.push(nivel);
        cuerpo.push(banderas);
        cuerpo.extend_from_slice(&60u16.to_be_bytes());
        if nivel >= 5 {
            cuerpo.push(0); // sin propiedades
        }
        cuerpo.extend_from_slice(&8u16.to_be_bytes());
        cuerpo.extend_from_slice(b"sensor-7");
        let mut v = vec![0x10];
        v.push(cuerpo.len() as u8);
        v.extend_from_slice(&cuerpo);
        v
    }

    #[test]
    fn mqtt_lee_el_identificador_de_cliente_de_una_conexion() {
        let d = Mqtt;
        let b = mqtt_conectar(4, 0);
        assert!(d.reconoce(&b, &Contexto::tcp_cliente(PUERTOS_MQTT[0])));
        let s = d.disecar(&b, &Contexto::tcp_cliente(PUERTOS_MQTT[0]));
        assert!(s.cobertura.completa());
        let (op, tema) = mensajeria(&s).expect("una operacion");
        assert!(op.starts_with("conectar"), "{op}");
        assert_eq!(tema, "sensor-7");
    }

    #[test]
    fn mqtt_salta_las_propiedades_de_la_version_cinco() {
        // Sin saltarlas, el identificador de cliente se lee desde el sitio
        // equivocado y sale basura donde tiene que ir un nombre.
        let d = Mqtt;
        let s = d.disecar(
            &mqtt_conectar(5, 0),
            &Contexto::tcp_cliente(PUERTOS_MQTT[0]),
        );
        assert_eq!(mensajeria(&s).map(|(_, t)| t), Some("sensor-7"));
    }

    #[test]
    fn mqtt_dice_que_una_conexion_lleva_credenciales() {
        let d = Mqtt;
        let s = d.disecar(
            &mqtt_conectar(4, 0xC0),
            &Contexto::tcp_cliente(PUERTOS_MQTT[0]),
        );
        let res = s.hechos.iter().find_map(|h| match h {
            Hecho::AutenticacionVista { resultado, .. } => Some(resultado.as_str()),
            _ => None,
        });
        assert_eq!(res, Some("con contrasena"));
    }

    #[test]
    fn mqtt_saca_el_tema_de_una_publicacion() {
        let d = Mqtt;
        let tema = b"planta/linea1/temperatura";
        let mut cuerpo = (tema.len() as u16).to_be_bytes().to_vec();
        cuerpo.extend_from_slice(tema);
        cuerpo.extend_from_slice(b"21.5");
        let mut v = vec![0x31]; // publicar, retenido
        v.push(cuerpo.len() as u8);
        v.extend_from_slice(&cuerpo);
        let s = d.disecar(&v, &Contexto::tcp_cliente(PUERTOS_MQTT[0]));
        let (op, t) = mensajeria(&s).expect("una operacion");
        assert!(op.contains("retenido"), "{op}");
        assert_eq!(t, "planta/linea1/temperatura");
    }

    #[test]
    fn mqtt_no_gira_sobre_una_longitud_sin_final() {
        // Cuatro bytes es el tope de la norma: sin el, una cadena de bytes con
        // el bit alto puesto haria girar el bucle sobre el buffer entero.
        let d = Mqtt;
        let v = vec![0x30, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        assert!(!d.reconoce(&v, &Contexto::tcp_cliente(PUERTOS_MQTT[0])));
        let s = d.disecar(&v, &Contexto::tcp_cliente(PUERTOS_MQTT[0]));
        assert!(!s.cobertura.completa());
    }

    #[test]
    fn kafka_lee_la_clave_de_interfaz_y_el_cliente() {
        let d = Kafka;
        let cliente = b"productor-1";
        let cuerpo_largo = 2 + 2 + 4 + 2 + cliente.len();
        let mut v = (cuerpo_largo as u32).to_be_bytes().to_vec();
        v.extend_from_slice(&0u16.to_be_bytes()); // producir
        v.extend_from_slice(&9u16.to_be_bytes()); // version
        v.extend_from_slice(&7u32.to_be_bytes()); // correlacion
        v.extend_from_slice(&(cliente.len() as u16).to_be_bytes());
        v.extend_from_slice(cliente);
        assert!(d.reconoce(&v, &Contexto::tcp_cliente(PUERTO_KAFKA)));
        let s = d.disecar(&v, &Contexto::tcp_cliente(PUERTO_KAFKA));
        let (op, quien) = mensajeria(&s).expect("una operacion");
        assert!(op.starts_with("producir"), "{op}");
        assert_eq!(quien, "productor-1");
    }

    #[test]
    fn grpc_saca_el_servicio_y_el_metodo_de_la_ruta() {
        let d = Grpc;
        let b = b"POST /aegis.Control/Ejecutar HTTP/1.1\r\nHost: x\r\nContent-Type: application/grpc-web+proto\r\n\r\n";
        assert!(d.reconoce(b, &Contexto::tcp_cliente(443)));
        let s = d.disecar(b, &Contexto::tcp_cliente(443));
        let (orden, servicio) = s
            .hechos
            .iter()
            .find_map(|h| match h {
                Hecho::EjecucionRemota {
                    orden, objetivo, ..
                } => Some((orden.as_str(), objetivo.as_str())),
                _ => None,
            })
            .expect("una ejecucion");
        assert_eq!(orden, "Ejecutar");
        assert_eq!(servicio, "aegis.Control");
    }

    #[test]
    fn grpc_declara_que_no_lee_el_protobuf() {
        // Sin el fichero de definiciones no se puede nombrar ni un campo, y
        // contar el mensaje como entendido seria inflar la cifra.
        let d = Grpc;
        let mut v = vec![0u8];
        v.extend_from_slice(&4u32.to_be_bytes());
        v.extend_from_slice(&[0x08, 0x96, 0x01, 0x00]);
        let s = d.disecar(&v, &Contexto::tcp_cliente(443));
        assert!(!s.cobertura.completa());
        assert_eq!(
            s.cobertura
                .sin_analizar
                .get(&crate::cobertura::Motivo::TipoNoImplementado),
            Some(&1)
        );
    }

    #[test]
    fn los_cuatro_de_mensajeria_declaran_sus_dos_mitades() {
        let ds: Vec<Box<dyn Disector>> = vec![
            Box::new(Amqp),
            Box::new(Mqtt),
            Box::new(Kafka),
            Box::new(Grpc),
        ];
        for d in &ds {
            assert!(!d.mensajes_que_entiende().is_empty(), "{}", d.nombre());
            assert!(!d.mensajes_que_no_analiza().is_empty(), "{}", d.nombre());
        }
    }
}
