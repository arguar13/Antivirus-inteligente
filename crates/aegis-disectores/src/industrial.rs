//! Protocolos industriales y de tecnologia de operacion: Modbus, DNP3, S7comm,
//! BACnet y OPC-UA.
//!
//! # Por que estos son los que de verdad faltan
//!
//! Son los que un atacante usa para pasar de la red corporativa a la planta, y
//! casi ningun EDR los mira. El movimiento lateral acaba en una estacion de
//! ingenieria, y desde ahi la orden que importa no es «ejecuta esto» sino
//! «escribe este registro» o «para la CPU». Un sensor que no entienda estos
//! cinco protocolos ve ese ultimo salto como trafico TCP a un puerto raro.
//!
//! # La distincion que lleva dentro cada hecho de aqui
//!
//! [`Hecho::OrdenIndustrial`] tiene un campo `escribe`. Leer un registro de un
//! PLC es telemetria y ocurre miles de veces por minuto; escribirlo mueve algo
//! en el mundo fisico. Contarlos juntos entierra el segundo bajo el primero, y
//! es exactamente lo que hace un sensor que solo sepa decir «vi Modbus».
//!
//! # Lo que NO se hace aqui
//!
//! No se responde, no se sondea y no se pregunta al dispositivo. Un PLC de hace
//! veinte anos se cae con un escaneo de puertos: el sensor que «enriquece»
//! preguntandole es el que provoca la parada de planta que venia a evitar. Ver
//! la invariante 10 en la cabecera de [`crate::disector`].

use aegis_wire::error::{ErrorDiseccion, Resultado};
use aegis_wire::hecho::{Hecho, ProtocoloApp};
use aegis_wire::lector::Lector;

use crate::disector::{Contexto, Disector, Fuerza, Salida};

// ════════════════════════════════════════════════════════════════════════════
// Modbus/TCP
// ════════════════════════════════════════════════════════════════════════════

/// Puerto asignado a Modbus/TCP. Desempate, nunca criterio.
pub const PUERTO_MODBUS: u16 = 502;

/// Longitud maxima de la unidad de datos de Modbus, por la especificacion.
///
/// La ADU de Modbus/TCP son 260 bytes: 7 de cabecera MBAP y 253 de PDU. Un campo
/// de longitud mayor no es un mensaje grande, es un mensaje que miente.
const MAX_ADU_MODBUS: usize = 253;

/// Lo que hace una funcion de Modbus.
fn funcion_modbus(fc: u8) -> Option<(&'static str, bool)> {
    Some(match fc {
        0x01 => ("leer-bobinas", false),
        0x02 => ("leer-entradas-discretas", false),
        0x03 => ("leer-registros-retentivos", false),
        0x04 => ("leer-registros-de-entrada", false),
        0x05 => ("escribir-bobina", true),
        0x06 => ("escribir-registro", true),
        0x07 => ("leer-estado-de-excepcion", false),
        // Diagnostico incluye subfunciones que reinician el esclavo o lo dejan
        // en escucha: cambia el estado del dispositivo, asi que escribe.
        0x08 => ("diagnostico", true),
        0x0B => ("leer-contador-de-eventos", false),
        0x0C => ("leer-registro-de-eventos", false),
        0x0F => ("escribir-bobinas", true),
        0x10 => ("escribir-registros", true),
        0x11 => ("identificar-servidor", false),
        0x14 => ("leer-registro-de-fichero", false),
        0x15 => ("escribir-registro-de-fichero", true),
        0x16 => ("escribir-registro-con-mascara", true),
        0x17 => ("leer-y-escribir-registros", true),
        0x18 => ("leer-cola-fifo", false),
        0x2B => ("transporte-de-interfaz-encapsulado", false),
        _ => return None,
    })
}

/// Disector de Modbus/TCP.
#[derive(Debug, Default, Clone, Copy)]
pub struct Modbus;

impl Modbus {
    /// Comprueba la cabecera MBAP y devuelve `(unidad, pdu)`.
    fn cabecera(datos: &[u8]) -> Resultado<(u16, u8, &[u8])> {
        let mut l = Lector::nuevo(datos);
        let transaccion = l.u16("mbap.transaccion")?;
        let protocolo = l.u16("mbap.protocolo")?;
        if protocolo != 0 {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("modbus"));
        }
        let largo = l.u16("mbap.longitud")? as usize;
        // El campo cuenta la unidad y la PDU. Cero o uno no dejan sitio ni para
        // el codigo de funcion; mas de la ADU maxima es una longitud inventada.
        if largo < 2 {
            return Err(ErrorDiseccion::ValorInvalido {
                campo: "mbap.longitud",
                valor: largo as u64,
            });
        }
        if largo > MAX_ADU_MODBUS + 1 {
            return Err(ErrorDiseccion::LimiteExcedido {
                campo: "mbap.longitud",
                valor: largo,
                tope: MAX_ADU_MODBUS + 1,
            });
        }
        let unidad = l.u8("mbap.unidad")?;
        let pdu = l.tomar(largo - 1, "modbus.pdu")?;
        Ok((transaccion, unidad, pdu))
    }

    fn analizar(datos: &[u8], ctx: &Contexto) -> Resultado<Vec<Hecho>> {
        let (_, unidad, pdu) = Modbus::cabecera(datos)?;
        let mut l = Lector::nuevo(pdu);
        let fc = l.u8("modbus.funcion")?;

        // Una respuesta de excepcion lleva la funcion con el bit alto puesto.
        if fc & 0x80 != 0 {
            let codigo = l.u8("modbus.excepcion")?;
            let base = fc & 0x7F;
            // Una excepcion sobre una funcion que no existe no es una excepcion:
            // es un mensaje que no cumple su especificacion, y decirlo es lo que
            // separa un fallo del emisor de un intento de confundir al sensor.
            // Ademas, aceptarla aqui y no al reconocer haria que el disector
            // afirmara cosas de un flujo que no habia reclamado.
            let Some((nombre, _)) = funcion_modbus(base) else {
                return Err(ErrorDiseccion::ValorInvalido {
                    campo: "modbus.funcion-de-la-excepcion",
                    valor: u64::from(base),
                });
            };
            return Ok(vec![
                Hecho::ProtocoloIdentificado(ProtocoloApp::Modbus),
                Hecho::OrdenIndustrial {
                    protocolo: ProtocoloApp::Modbus,
                    funcion: format!("excepcion-de-{nombre}"),
                    unidad: unidad.to_string(),
                    escribe: false,
                    detalle: format!("codigo de excepcion {codigo}"),
                },
            ]);
        }

        let Some((nombre, escribe)) = funcion_modbus(fc) else {
            return Err(ErrorDiseccion::ValorInvalido {
                campo: "modbus.funcion",
                valor: u64::from(fc),
            });
        };

        // El detalle solo se puede leer del lado del cliente: la respuesta a un
        // «leer registros» no repite la direccion, lleva los datos. Inventarla
        // desde una respuesta daria un rango falso en el informe.
        let detalle = if ctx.del_cliente {
            match fc {
                0x01..=0x04 => {
                    let inicio = l.u16("modbus.inicio")?;
                    let cantidad = l.u16("modbus.cantidad")?;
                    format!(
                        "direcciones {inicio}..{}",
                        u32::from(inicio) + u32::from(cantidad)
                    )
                }
                0x05 => {
                    let dir = l.u16("modbus.direccion")?;
                    let valor = l.u16("modbus.valor")?;
                    let estado = if valor == 0xFF00 { "ON" } else { "OFF" };
                    format!("bobina {dir} a {estado}")
                }
                0x06 => {
                    let dir = l.u16("modbus.direccion")?;
                    let valor = l.u16("modbus.valor")?;
                    format!("registro {dir} a {valor}")
                }
                0x0F | 0x10 => {
                    let inicio = l.u16("modbus.inicio")?;
                    let cantidad = l.u16("modbus.cantidad")?;
                    format!("{cantidad} posiciones desde {inicio}")
                }
                0x08 => {
                    let sub = l.u16("modbus.subfuncion")?;
                    let que = match sub {
                        0x0001 => "reiniciar la comunicacion",
                        0x0004 => "dejar el esclavo en solo escucha",
                        0x000A => "borrar contadores",
                        _ => "subfuncion de diagnostico",
                    };
                    format!("{que} (subfuncion {sub})")
                }
                _ => String::new(),
            }
        } else {
            String::new()
        };

        Ok(vec![
            Hecho::ProtocoloIdentificado(ProtocoloApp::Modbus),
            Hecho::OrdenIndustrial {
                protocolo: ProtocoloApp::Modbus,
                funcion: nombre.to_owned(),
                unidad: unidad.to_string(),
                escribe,
                detalle,
            },
        ])
    }
}

impl Disector for Modbus {
    /// Identificador de protocolo cero, longitud acotada y funcion conocida, comprobados entre si.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Forma
    }

    fn nombre(&self) -> &'static str {
        "modbus"
    }

    fn reconoce(&self, datos: &[u8], _ctx: &Contexto) -> bool {
        // Por contenido: identificador de protocolo cero, longitud coherente y
        // una funcion conocida. El puerto 502 no aparece aqui a proposito —un
        // PLC reexpuesto por un tunel sigue hablando Modbus—.
        let Ok((_, _, pdu)) = Modbus::cabecera(datos) else {
            return false;
        };
        match pdu.first() {
            Some(&fc) if fc & 0x80 != 0 => funcion_modbus(fc & 0x7F).is_some(),
            Some(&fc) => funcion_modbus(fc).is_some(),
            None => false,
        }
    }

    fn disecar(&self, datos: &[u8], ctx: &Contexto) -> Salida {
        Salida::de_resultado(Modbus::analizar(datos, ctx))
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "leer-bobinas",
            "leer-entradas-discretas",
            "leer-registros-retentivos",
            "leer-registros-de-entrada",
            "escribir-bobina",
            "escribir-registro",
            "escribir-bobinas",
            "escribir-registros",
            "escribir-registro-con-mascara",
            "leer-y-escribir-registros",
            "diagnostico",
            "respuestas-de-excepcion",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "el contenido de los registros devueltos por una lectura",
            "transporte-de-interfaz-encapsulado (funcion 0x2B) mas alla del codigo",
            "las variantes seriales Modbus RTU y ASCII, que no viajan sobre TCP",
        ]
    }
}

// ════════════════════════════════════════════════════════════════════════════
// DNP3
// ════════════════════════════════════════════════════════════════════════════

/// Puerto asignado a DNP3.
pub const PUERTO_DNP3: u16 = 20000;

/// Lo que hace una funcion de aplicacion de DNP3 (IEEE 1815).
fn funcion_dnp3(fc: u8) -> Option<(&'static str, bool)> {
    Some(match fc {
        0x00 => ("confirmar", false),
        0x01 => ("leer", false),
        0x02 => ("escribir", true),
        // Seleccionar-y-operar es el par que acciona una salida: el primero
        // arma y el segundo dispara. Los dos cambian el estado del dispositivo.
        0x03 => ("seleccionar", true),
        0x04 => ("operar", true),
        0x05 => ("operar-directo", true),
        0x06 => ("operar-directo-sin-respuesta", true),
        0x07 => ("congelar", true),
        0x09 => ("congelar-y-borrar", true),
        0x0D => ("arranque-en-frio", true),
        0x0E => ("arranque-en-caliente", true),
        0x0F => ("inicializar-datos", true),
        0x10 => ("inicializar-aplicacion", true),
        0x11 => ("arrancar-aplicacion", true),
        0x12 => ("parar-aplicacion", true),
        0x13 => ("guardar-configuracion", true),
        0x14 => ("habilitar-no-solicitado", true),
        0x15 => ("deshabilitar-no-solicitado", true),
        0x16 => ("asignar-clase", true),
        0x17 => ("retardo-de-ida-y-vuelta", false),
        0x18 => ("reiniciar-enlace", true),
        0x81 => ("respuesta", false),
        0x82 => ("respuesta-no-solicitada", false),
        0x83 => ("respuesta-autenticada", false),
        _ => return None,
    })
}

/// Disector de DNP3.
#[derive(Debug, Default, Clone, Copy)]
pub struct Dnp3;

impl Dnp3 {
    /// La cabecera de enlace: `(largo, destino, origen, resto)`.
    fn enlace(datos: &[u8]) -> Resultado<(u8, u16, u16, usize)> {
        let mut l = Lector::nuevo(datos);
        let inicio = l.u16("dnp3.inicio")?;
        if inicio != 0x0564 {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("dnp3"));
        }
        let largo = l.u8("dnp3.longitud")?;
        // El campo cuenta desde el byte de control: menos de cinco no deja
        // sitio para control, destino y origen.
        if largo < 5 {
            return Err(ErrorDiseccion::ValorInvalido {
                campo: "dnp3.longitud",
                valor: u64::from(largo),
            });
        }
        let _control = l.u8("dnp3.control")?;
        let destino = l.u16_le("dnp3.destino")?;
        let origen = l.u16_le("dnp3.origen")?;
        Ok((largo, destino, origen, l.posicion()))
    }

    fn analizar(datos: &[u8]) -> Resultado<Vec<Hecho>> {
        let (largo, destino, origen, pos) = Dnp3::enlace(datos)?;
        let mut hechos = vec![Hecho::ProtocoloIdentificado(ProtocoloApp::Dnp3)];

        // Solo la cabecera de enlace: es un mensaje de enlace sin capa de
        // aplicacion (RESET_LINK, LINK_STATUS). Se reconoce y no lleva orden.
        if largo == 5 {
            return Ok(hechos);
        }

        let mut l = Lector::nuevo(datos);
        // La CRC del bloque de cabecera va tras los ocho primeros bytes. No se
        // comprueba —una CRC mala no cambia lo que el emisor pidio, y
        // descartar por ella dejaria de ver justo el trafico manipulado—, pero
        // hay que saltarla para llegar a la capa de transporte.
        l.ir_a(pos + 2, "dnp3.crc-cabecera")?;
        let transporte = l.u8("dnp3.transporte")?;
        let primero = transporte & 0x40 != 0;
        if !primero {
            // Un segmento intermedio no lleva cabecera de aplicacion: leer el
            // siguiente byte como funcion daria una orden inventada.
            return Ok(hechos);
        }
        let _control_app = l.u8("dnp3.control-de-aplicacion")?;
        let fc = l.u8("dnp3.funcion")?;
        let Some((nombre, escribe)) = funcion_dnp3(fc) else {
            return Err(ErrorDiseccion::ValorInvalido {
                campo: "dnp3.funcion",
                valor: u64::from(fc),
            });
        };

        // En las respuestas viene el estado interno del dispositivo, dos bytes
        // de banderas que dicen si hubo reinicio o si hay una alarma.
        let detalle = if fc == 0x81 || fc == 0x82 {
            let iin = l.u16("dnp3.indicaciones")?;
            format!("indicaciones internas 0x{iin:04x}")
        } else {
            String::new()
        };

        hechos.push(Hecho::OrdenIndustrial {
            protocolo: ProtocoloApp::Dnp3,
            funcion: nombre.to_owned(),
            unidad: format!("{origen}->{destino}"),
            escribe,
            detalle,
        });
        Ok(hechos)
    }
}

impl Disector for Dnp3 {
    /// Los dos bytes de inicio 0x0564 mas la longitud minima.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Marca
    }

    fn nombre(&self) -> &'static str {
        "dnp3"
    }

    fn reconoce(&self, datos: &[u8], _ctx: &Contexto) -> bool {
        Dnp3::enlace(datos).is_ok()
    }

    fn disecar(&self, datos: &[u8], _ctx: &Contexto) -> Salida {
        Salida::de_resultado(Dnp3::analizar(datos))
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "la cabecera de enlace con origen y destino",
            "leer",
            "escribir",
            "seleccionar",
            "operar",
            "operar-directo",
            "arranque-en-frio",
            "arranque-en-caliente",
            "parar-aplicacion",
            "respuesta y respuesta-no-solicitada con sus indicaciones internas",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "los objetos de datos: grupo, variacion y sus puntos",
            "los segmentos de transporte intermedios, que no llevan cabecera de aplicacion",
            "la autenticacion segura de DNP3 (IEEE 1815 capitulo 7)",
            "la comprobacion de las CRC de bloque",
        ]
    }
}

// ════════════════════════════════════════════════════════════════════════════
// S7comm (Siemens, sobre TPKT y COTP)
// ════════════════════════════════════════════════════════════════════════════

/// Puerto de ISO-TSAP, por donde va S7comm.
pub const PUERTO_S7COMM: u16 = 102;

/// Lo que hace una funcion de S7comm.
fn funcion_s7(f: u8) -> Option<(&'static str, bool)> {
    Some(match f {
        0x00 => ("diagnostico-de-cpu", false),
        0x04 => ("leer-variable", false),
        0x05 => ("escribir-variable", true),
        0x1A => ("pedir-descarga", true),
        0x1B => ("descargar-bloque", true),
        0x1C => ("fin-de-descarga", true),
        0x1D => ("pedir-subida", false),
        0x1E => ("subir-bloque", false),
        0x1F => ("fin-de-subida", false),
        // Control de PLC: arranque en frio o en caliente segun el servicio que
        // lleva dentro. Cambia el estado de la planta.
        0x28 => ("controlar-plc", true),
        // Parar la CPU. Es la orden que para una planta, y la que distingue a
        // este disector de un sensor que solo sabe decir «vi trafico al 102».
        0x29 => ("parar-cpu", true),
        0xF0 => ("negociar-comunicacion", false),
        _ => return None,
    })
}

/// Disector de S7comm.
#[derive(Debug, Default, Clone, Copy)]
pub struct S7comm;

impl S7comm {
    /// Comprueba TPKT y COTP y devuelve la posicion de la carga S7.
    ///
    /// Devuelve `None` en la posicion cuando el COTP no es de datos: un
    /// `Connect Request` es S7 y no lleva carga, y confundir las dos cosas seria
    /// leer basura como una orden.
    fn tpkt_cotp(datos: &[u8]) -> Resultado<(Option<usize>, u8)> {
        let mut l = Lector::nuevo(datos);
        let version = l.u8("tpkt.version")?;
        if version != 0x03 {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("s7comm"));
        }
        let _reservado = l.u8("tpkt.reservado")?;
        let total = l.u16("tpkt.longitud")? as usize;
        // La longitud de TPKT cuenta sus propios cuatro bytes de cabecera.
        if total < 7 || total > datos.len() {
            return Err(ErrorDiseccion::LongitudImposible {
                campo: "tpkt.longitud",
                declarada: total,
                disponible: datos.len(),
            });
        }
        let largo_cotp = l.u8("cotp.longitud")? as usize;
        if largo_cotp == 0 {
            return Err(ErrorDiseccion::ValorInvalido {
                campo: "cotp.longitud",
                valor: 0,
            });
        }
        let tipo = l.u8("cotp.tipo")?;
        // El campo de longitud de COTP cuenta desde el byte siguiente a el.
        let fin_cotp = 4 + 1 + largo_cotp;
        if fin_cotp > datos.len() {
            return Err(ErrorDiseccion::LongitudImposible {
                campo: "cotp.longitud",
                declarada: fin_cotp,
                disponible: datos.len(),
            });
        }
        match tipo {
            0xF0 => Ok((Some(fin_cotp), tipo)),
            0xE0 | 0xD0 | 0x80 | 0x50 => Ok((None, tipo)),
            _ => Err(ErrorDiseccion::NoEsEsteProtocolo("s7comm")),
        }
    }

    fn analizar(datos: &[u8]) -> Resultado<Vec<Hecho>> {
        let (carga, tipo_cotp) = S7comm::tpkt_cotp(datos)?;
        let mut hechos = vec![Hecho::ProtocoloIdentificado(ProtocoloApp::S7comm)];
        let Some(inicio) = carga else {
            let que = match tipo_cotp {
                0xE0 => "peticion-de-conexion-cotp",
                0xD0 => "confirmacion-de-conexion-cotp",
                0x80 => "desconexion-cotp",
                _ => "control-cotp",
            };
            hechos.push(Hecho::OrdenIndustrial {
                protocolo: ProtocoloApp::S7comm,
                funcion: que.to_owned(),
                unidad: String::new(),
                escribe: false,
                detalle: String::new(),
            });
            return Ok(hechos);
        };

        let mut l = Lector::nuevo(datos);
        l.ir_a(inicio, "s7.inicio")?;
        // Un DT de COTP sin carga es un segmento vacio valido.
        if l.vacio() {
            return Ok(hechos);
        }
        let id = l.u8("s7.protocolo")?;
        if id != 0x32 {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("s7comm"));
        }
        let rosctr = l.u8("s7.rosctr")?;
        let _redundancia = l.u16("s7.redundancia")?;
        let referencia = l.u16("s7.referencia")?;
        let largo_parametro = l.u16("s7.longitud-de-parametro")? as usize;
        let _largo_datos = l.u16("s7.longitud-de-datos")?;
        // Solo el Ack_Data lleva los dos bytes de error; leerlos siempre
        // desplazaria el parametro en todos los demas.
        let error = if rosctr == 0x03 {
            let clase = l.u8("s7.clase-de-error")?;
            let codigo = l.u8("s7.codigo-de-error")?;
            Some((clase, codigo))
        } else {
            None
        };
        if largo_parametro == 0 {
            return Ok(hechos);
        }
        let funcion = l.u8("s7.funcion")?;
        let Some((nombre, escribe)) = funcion_s7(funcion) else {
            return Err(ErrorDiseccion::ValorInvalido {
                campo: "s7.funcion",
                valor: u64::from(funcion),
            });
        };

        let mut detalle = format!("referencia {referencia}");
        if let Some((clase, codigo)) = error {
            if clase != 0 || codigo != 0 {
                detalle.push_str(&format!(", error 0x{clase:02x}{codigo:02x}"));
            }
        }
        // El servicio de «controlar PLC» lleva el nombre del programa pedido en
        // texto: `P_PROGRAM` es un arranque en caliente y `_INSE` carga un
        // bloque. Es lo que separa un arranque de una carga de codigo.
        if funcion == 0x28 {
            let resto = l.resto();
            if let Some(p) = resto.iter().position(|&b| b == b'_' || b == b'P') {
                let txt: String = resto[p..]
                    .iter()
                    .take(16)
                    .take_while(|b| b.is_ascii_graphic())
                    .map(|&b| b as char)
                    .collect();
                if txt.len() >= 3 {
                    detalle.push_str(&format!(", servicio {txt}"));
                }
            }
        }

        hechos.push(Hecho::OrdenIndustrial {
            protocolo: ProtocoloApp::S7comm,
            funcion: nombre.to_owned(),
            unidad: String::new(),
            escribe,
            detalle,
        });
        Ok(hechos)
    }
}

impl Disector for S7comm {
    /// TPKT, COTP y el identificador 0x32 de S7: tres marcas encadenadas.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Marca
    }

    fn nombre(&self) -> &'static str {
        "s7comm"
    }

    fn reconoce(&self, datos: &[u8], ctx: &Contexto) -> bool {
        match S7comm::tpkt_cotp(datos) {
            // Un DT de COTP solo es S7 si dentro lleva el identificador 0x32:
            // por el 102 tambien viajan otros protocolos sobre ISO-TSAP.
            Ok((Some(inicio), _)) => datos.get(inicio) == Some(&0x32),
            // Una peticion de conexion COTP no lleva carga, asi que ahi el
            // puerto si es lo unico que queda —y por eso el contexto entra aqui
            // como desempate declarado y no como criterio principal—.
            Ok((None, _)) => ctx.algun_puerto(PUERTO_S7COMM),
            Err(_) => false,
        }
    }

    fn disecar(&self, datos: &[u8], ctx: &Contexto) -> Salida {
        // Reconocer y disecar tienen que decidir lo mismo: una peticion de
        // conexion COTP no lleva carga que distinga S7comm de otro protocolo de
        // ISO-TSAP, asi que ahi el puerto entra como desempate declarado — y
        // tiene que entrar en los dos sitios, no solo al reconocer.
        if !self.reconoce(datos, ctx) {
            return Salida::sin_analizar(crate::cobertura::Motivo::NoReconocido);
        }
        Salida::de_resultado(S7comm::analizar(datos))
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "negociar-comunicacion",
            "leer-variable",
            "escribir-variable",
            "controlar-plc",
            "parar-cpu",
            "pedir-descarga, descargar-bloque y fin-de-descarga",
            "pedir-subida, subir-bloque y fin-de-subida",
            "las conexiones y desconexiones de COTP",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "los elementos de una lectura o escritura: area, numero de bloque y desplazamiento",
            "el contenido de los bloques que se suben o se bajan",
            "los mensajes de usuario (ROSCTR 0x07) y su diagnostico",
            "S7comm-Plus, el protocolo de las CPU S7-1200 y S7-1500",
        ]
    }
}

// ════════════════════════════════════════════════════════════════════════════
// BACnet/IP
// ════════════════════════════════════════════════════════════════════════════

/// Puerto de BACnet/IP (0xBAC0).
pub const PUERTO_BACNET: u16 = 47808;

/// Servicio confirmado de BACnet, con si cambia algo.
fn servicio_bacnet_confirmado(s: u8) -> Option<(&'static str, bool)> {
    Some(match s {
        0 => ("reconocer-alarma", true),
        1 => ("notificacion-de-cambio-confirmada", false),
        2 => ("notificacion-de-evento-confirmada", false),
        3 => ("resumen-de-alarmas", false),
        4 => ("resumen-de-inscripciones", false),
        5 => ("suscribirse-a-cambios", true),
        6 => ("leer-fichero", false),
        7 => ("escribir-fichero", true),
        8 => ("anadir-a-lista", true),
        9 => ("quitar-de-lista", true),
        10 => ("crear-objeto", true),
        11 => ("borrar-objeto", true),
        12 => ("leer-propiedad", false),
        14 => ("leer-varias-propiedades", false),
        15 => ("escribir-propiedad", true),
        16 => ("escribir-varias-propiedades", true),
        // Deja el dispositivo sordo a la red: es la orden con la que se aisla
        // un controlador de climatizacion antes de manipularlo.
        17 => ("controlar-la-comunicacion-del-dispositivo", true),
        18 => ("transferencia-privada-confirmada", true),
        19 => ("texto-confirmado", false),
        20 => ("reinicializar-dispositivo", true),
        26 => ("leer-rango", false),
        27 => ("operacion-de-seguridad-de-vida", true),
        28 => ("suscribirse-a-cambios-de-propiedad", true),
        29 => ("obtener-informacion-de-eventos", false),
        _ => return None,
    })
}

/// Servicio no confirmado de BACnet, con si cambia algo.
///
/// Los numeros son los de la clausula 21 de ASHRAE 135. Estan escritos aqui uno
/// a uno —y comprobados en una prueba contra el `quien-es`, que es el 8— porque
/// una tabla desplazada en uno no falla: nombra otro servicio, y un informe que
/// diga «sincronizacion de hora» donde hubo un barrido de descubrimiento es peor
/// que no decir nada.
fn servicio_bacnet_no_confirmado(s: u8) -> Option<(&'static str, bool)> {
    Some(match s {
        0 => ("soy", false),
        1 => ("tengo", false),
        2 => ("notificacion-de-cambio", false),
        3 => ("notificacion-de-evento", false),
        4 => ("transferencia-privada-no-confirmada", true),
        5 => ("texto-no-confirmado", false),
        // Poner la hora a todos los dispositivos de una red cambia el estado de
        // todos: en una red de edificio es como se desplaza una programacion
        // horaria sin tocar ni un objeto.
        6 => ("sincronizacion-de-hora", true),
        7 => ("quien-tiene", false),
        8 => ("quien-es", false),
        9 => ("sincronizacion-de-hora-utc", true),
        10 => ("escribir-grupo", true),
        _ => return None,
    })
}

/// Disector de BACnet/IP.
#[derive(Debug, Default, Clone, Copy)]
pub struct Bacnet;

impl Bacnet {
    /// Salta BVLC y NPDU y devuelve la posicion de la APDU.
    fn hasta_apdu(datos: &[u8]) -> Resultado<usize> {
        let mut l = Lector::nuevo(datos);
        let tipo = l.u8("bvlc.tipo")?;
        if tipo != 0x81 {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("bacnet"));
        }
        let funcion = l.u8("bvlc.funcion")?;
        let largo = l.u16("bvlc.longitud")? as usize;
        if largo < 4 || largo > datos.len() {
            return Err(ErrorDiseccion::LongitudImposible {
                campo: "bvlc.longitud",
                declarada: largo,
                disponible: datos.len(),
            });
        }
        // Un NPDU reenviado lleva delante la direccion original de seis bytes.
        if funcion == 0x04 {
            l.saltar(6, "bvlc.origen-reenviado")?;
        }
        let version = l.u8("npdu.version")?;
        if version != 0x01 {
            return Err(ErrorDiseccion::ValorInvalido {
                campo: "npdu.version",
                valor: u64::from(version),
            });
        }
        let control = l.u8("npdu.control")?;
        if control & 0x20 != 0 {
            l.saltar(2, "npdu.red-destino")?;
            let dlen = l.u8("npdu.longitud-destino")? as usize;
            l.saltar(dlen, "npdu.direccion-destino")?;
        }
        if control & 0x08 != 0 {
            l.saltar(2, "npdu.red-origen")?;
            let slen = l.u8("npdu.longitud-origen")? as usize;
            l.saltar(slen, "npdu.direccion-origen")?;
        }
        if control & 0x20 != 0 {
            l.saltar(1, "npdu.saltos")?;
        }
        // Un mensaje de capa de red no lleva APDU.
        if control & 0x80 != 0 {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("bacnet-apdu"));
        }
        Ok(l.posicion())
    }

    fn analizar(datos: &[u8]) -> Resultado<Vec<Hecho>> {
        let inicio = match Bacnet::hasta_apdu(datos) {
            Ok(p) => p,
            // Es BACnet y es de capa de red: se reconoce, y no lleva servicio.
            Err(ErrorDiseccion::NoEsEsteProtocolo("bacnet-apdu")) => {
                return Ok(vec![Hecho::ProtocoloIdentificado(ProtocoloApp::Bacnet)])
            }
            Err(e) => return Err(e),
        };
        let mut hechos = vec![Hecho::ProtocoloIdentificado(ProtocoloApp::Bacnet)];
        let mut l = Lector::nuevo(datos);
        l.ir_a(inicio, "apdu")?;
        let primero = l.u8("apdu.tipo")?;
        let tipo = primero >> 4;
        let (nombre, escribe, detalle) = match tipo {
            0x0 => {
                let _max = l.u8("apdu.maximos")?;
                let invocacion = l.u8("apdu.invocacion")?;
                // Un mensaje segmentado lleva delante su numero y la ventana.
                if primero & 0x08 != 0 {
                    l.saltar(2, "apdu.segmento")?;
                }
                let servicio = l.u8("apdu.servicio")?;
                let Some((n, w)) = servicio_bacnet_confirmado(servicio) else {
                    return Err(ErrorDiseccion::ValorInvalido {
                        campo: "apdu.servicio-confirmado",
                        valor: u64::from(servicio),
                    });
                };
                (n.to_owned(), w, format!("invocacion {invocacion}"))
            }
            0x1 => {
                let servicio = l.u8("apdu.servicio")?;
                let Some((n, w)) = servicio_bacnet_no_confirmado(servicio) else {
                    return Err(ErrorDiseccion::ValorInvalido {
                        campo: "apdu.servicio-no-confirmado",
                        valor: u64::from(servicio),
                    });
                };
                (n.to_owned(), w, String::new())
            }
            0x2 => {
                let invocacion = l.u8("apdu.invocacion")?;
                let servicio = l.u8("apdu.servicio")?;
                let n = servicio_bacnet_confirmado(servicio).map_or("desconocido", |(n, _)| n);
                (
                    format!("confirmacion-de-{n}"),
                    false,
                    format!("invocacion {invocacion}"),
                )
            }
            0x3 => {
                let invocacion = l.u8("apdu.invocacion")?;
                if primero & 0x08 != 0 {
                    l.saltar(2, "apdu.segmento")?;
                }
                let servicio = l.u8("apdu.servicio")?;
                let n = servicio_bacnet_confirmado(servicio).map_or("desconocido", |(n, _)| n);
                (
                    format!("respuesta-de-{n}"),
                    false,
                    format!("invocacion {invocacion}"),
                )
            }
            0x5 => {
                let invocacion = l.u8("apdu.invocacion")?;
                let servicio = l.u8("apdu.servicio")?;
                let n = servicio_bacnet_confirmado(servicio).map_or("desconocido", |(n, _)| n);
                (
                    format!("error-de-{n}"),
                    false,
                    format!("invocacion {invocacion}"),
                )
            }
            0x6 => ("rechazo".to_owned(), false, String::new()),
            0x7 => ("aborto".to_owned(), false, String::new()),
            otro => {
                return Err(ErrorDiseccion::ValorInvalido {
                    campo: "apdu.tipo",
                    valor: u64::from(otro),
                })
            }
        };
        hechos.push(Hecho::OrdenIndustrial {
            protocolo: ProtocoloApp::Bacnet,
            funcion: nombre,
            unidad: String::new(),
            escribe,
            detalle,
        });
        Ok(hechos)
    }
}

impl Disector for Bacnet {
    /// El 0x81 de BVLC mas la version del NPDU y su longitud coherente.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Forma
    }

    fn nombre(&self) -> &'static str {
        "bacnet"
    }

    fn reconoce(&self, datos: &[u8], _ctx: &Contexto) -> bool {
        match Bacnet::hasta_apdu(datos) {
            Ok(_) => true,
            Err(ErrorDiseccion::NoEsEsteProtocolo("bacnet-apdu")) => true,
            Err(_) => false,
        }
    }

    fn disecar(&self, datos: &[u8], _ctx: &Contexto) -> Salida {
        Salida::de_resultado(Bacnet::analizar(datos))
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "la cabecera BVLC, incluida la de un NPDU reenviado",
            "el encaminamiento del NPDU con sus redes de origen y destino",
            "leer-propiedad y leer-varias-propiedades",
            "escribir-propiedad y escribir-varias-propiedades",
            "crear-objeto y borrar-objeto",
            "controlar-la-comunicacion-del-dispositivo",
            "reinicializar-dispositivo",
            "quien-es, soy, quien-tiene y tengo",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "los datos etiquetados de la APDU: identificadores de objeto, propiedades y valores",
            "el reensamblado de las APDU segmentadas",
            "los mensajes de capa de red (Who-Is-Router, I-Am-Router)",
            "BACnet/SC, la variante sobre WebSocket",
        ]
    }
}

// ════════════════════════════════════════════════════════════════════════════
// OPC-UA binario
// ════════════════════════════════════════════════════════════════════════════

/// Puerto de OPC-UA sobre TCP.
pub const PUERTO_OPCUA: u16 = 4840;

/// El servicio de OPC-UA que corresponde a un identificador numerico.
///
/// Los numeros son los del espacio de nombres cero de la especificacion
/// (IEC 62541-6, anexo de identificadores).
fn servicio_opcua(id: u32) -> Option<(&'static str, bool)> {
    Some(match id {
        420 => ("buscar-servidores", false),
        426 => ("obtener-puntos-finales", false),
        446 => ("abrir-canal-seguro", false),
        452 => ("cerrar-canal-seguro", false),
        461 => ("crear-sesion", false),
        467 => ("activar-sesion", false),
        473 => ("cerrar-sesion", false),
        527 => ("navegar", false),
        631 => ("leer", false),
        673 => ("escribir", true),
        712 => ("llamar-a-metodo", true),
        751 => ("crear-elementos-vigilados", true),
        787 => ("crear-suscripcion", false),
        793 => ("modificar-suscripcion", true),
        826 => ("publicar", false),
        _ => return None,
    })
}

/// Disector de OPC-UA binario.
#[derive(Debug, Default, Clone, Copy)]
pub struct OpcUa;

impl OpcUa {
    /// La cabecera comun: `(tipo, trozo, tamano)`.
    fn cabecera(datos: &[u8]) -> Resultado<([u8; 3], u8, usize)> {
        let mut l = Lector::nuevo(datos);
        let t = l.tomar(3, "opcua.tipo")?;
        let tipo = [t[0], t[1], t[2]];
        let conocido = matches!(
            &tipo,
            b"HEL" | b"ACK" | b"ERR" | b"RHE" | b"OPN" | b"CLO" | b"MSG"
        );
        if !conocido {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("opcua"));
        }
        let trozo = l.u8("opcua.trozo")?;
        if !matches!(trozo, b'F' | b'C' | b'A') {
            return Err(ErrorDiseccion::NoEsEsteProtocolo("opcua"));
        }
        let tamano = l.u32_le("opcua.tamano")? as usize;
        // El tamano cuenta la cabecera de ocho bytes. Uno menor es imposible;
        // uno mayor que el mensaje es un trozo pendiente y no un error.
        if tamano < 8 {
            return Err(ErrorDiseccion::ValorInvalido {
                campo: "opcua.tamano",
                valor: tamano as u64,
            });
        }
        Ok((tipo, trozo, tamano))
    }

    /// Lee una cadena de OPC-UA: longitud de cuatro bytes con -1 para nula.
    fn cadena(l: &mut Lector<'_>, campo: &'static str) -> Resultado<String> {
        let largo = l.u32_le(campo)?;
        if largo == u32::MAX {
            return Ok(String::new());
        }
        let bytes = l.tomar(largo as usize, campo)?;
        Ok(aegis_wire::lector::ascii_legible(bytes))
    }

    fn analizar(datos: &[u8]) -> Resultado<Vec<Hecho>> {
        let (tipo, trozo, _tamano) = OpcUa::cabecera(datos)?;
        let mut hechos = vec![Hecho::ProtocoloIdentificado(ProtocoloApp::OpcUa)];
        let mut l = Lector::nuevo(datos);
        l.ir_a(8, "opcua.cuerpo")?;

        match &tipo {
            b"HEL" => {
                l.saltar(20, "opcua.parametros-de-hola")?;
                let url = OpcUa::cadena(&mut l, "opcua.url")?;
                hechos.push(Hecho::EjecucionRemota {
                    via: ProtocoloApp::OpcUa,
                    orden: "hola".to_owned(),
                    objetivo: url,
                });
            }
            b"ACK" => {}
            b"ERR" => {
                let codigo = l.u32_le("opcua.codigo-de-error")?;
                let razon = OpcUa::cadena(&mut l, "opcua.razon")?;
                hechos.push(Hecho::OrdenIndustrial {
                    protocolo: ProtocoloApp::OpcUa,
                    funcion: "error".to_owned(),
                    unidad: String::new(),
                    escribe: false,
                    detalle: format!("0x{codigo:08x} {razon}"),
                });
            }
            b"OPN" => {
                let _canal = l.u32_le("opcua.canal")?;
                let politica = OpcUa::cadena(&mut l, "opcua.politica")?;
                // Una politica `None` deja el resto del dialogo en claro, que es
                // como se ven las ordenes y como se manipulan. Que un servidor
                // industrial la acepte es la observacion, no el veredicto.
                hechos.push(Hecho::OrdenIndustrial {
                    protocolo: ProtocoloApp::OpcUa,
                    funcion: "abrir-canal-seguro".to_owned(),
                    unidad: String::new(),
                    escribe: false,
                    detalle: format!("politica {politica}"),
                });
            }
            b"MSG" | b"CLO" => {
                l.saltar(16, "opcua.cabecera-simetrica")?;
                // El cuerpo empieza por el identificador del tipo de peticion.
                // La codificacion de dos bytes (0x01) lleva un indice de espacio
                // de nombres y un numero de dos bytes; la de cuatro (0x02) lleva
                // el indice y un numero de cuatro.
                let codificacion = l.u8("opcua.codificacion-de-nodo")?;
                let id = match codificacion {
                    0x00 => u32::from(l.u8("opcua.nodo")?),
                    0x01 => {
                        let _ns = l.u8("opcua.espacio-de-nombres")?;
                        u32::from(l.u16_le("opcua.nodo")?)
                    }
                    0x02 => {
                        let _ns = l.u16_le("opcua.espacio-de-nombres")?;
                        l.u32_le("opcua.nodo")?
                    }
                    // El resto de codificaciones llevan cadenas o GUID: se
                    // reconoce el mensaje y no se nombra el servicio.
                    _ => return Ok(hechos),
                };
                match servicio_opcua(id) {
                    Some((nombre, escribe)) => hechos.push(Hecho::OrdenIndustrial {
                        protocolo: ProtocoloApp::OpcUa,
                        funcion: nombre.to_owned(),
                        unidad: String::new(),
                        escribe,
                        detalle: format!("trozo {}", trozo as char),
                    }),
                    None => hechos.push(Hecho::OrdenIndustrial {
                        protocolo: ProtocoloApp::OpcUa,
                        funcion: "servicio-no-catalogado".to_owned(),
                        unidad: String::new(),
                        escribe: false,
                        detalle: format!("identificador {id}"),
                    }),
                }
            }
            _ => {}
        }
        Ok(hechos)
    }
}

impl Disector for OpcUa {
    /// Tres letras de un juego cerrado mas la letra de trozo.
    fn fuerza(&self) -> Fuerza {
        Fuerza::Marca
    }

    fn nombre(&self) -> &'static str {
        "opcua"
    }

    fn reconoce(&self, datos: &[u8], _ctx: &Contexto) -> bool {
        OpcUa::cabecera(datos).is_ok()
    }

    fn disecar(&self, datos: &[u8], _ctx: &Contexto) -> Salida {
        Salida::de_resultado(OpcUa::analizar(datos))
    }

    fn mensajes_que_entiende(&self) -> &'static [&'static str] {
        &[
            "el saludo HEL con su punto final",
            "el ACK y el ERR con su codigo",
            "OPN con la politica de seguridad negociada",
            "los servicios de MSG por identificador: leer, escribir, llamar-a-metodo, navegar",
            "crear-sesion y activar-sesion",
            "crear-suscripcion y crear-elementos-vigilados",
        ]
    }

    fn mensajes_que_no_analiza(&self) -> &'static [&'static str] {
        &[
            "el cuerpo de los servicios: los nodos leidos o escritos y sus valores",
            "los mensajes cifrados o firmados bajo una politica distinta de None",
            "el reensamblado de los mensajes partidos en varios trozos",
            "los identificadores de servicio de espacios de nombres distintos del cero",
            "OPC-UA sobre HTTPS y sobre WebSocket",
        ]
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::cobertura::Motivo;

    /// Una peticion Modbus real de «leer registros retentivos»: MBAP con
    /// transaccion 1, protocolo 0, longitud 6, unidad 1; funcion 0x03,
    /// direccion 0, cantidad 10.
    fn modbus_leer() -> Vec<u8> {
        vec![
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0A,
        ]
    }

    /// La misma forma, pero escribiendo una bobina a ON.
    fn modbus_escribir() -> Vec<u8> {
        vec![
            0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x01, 0x05, 0x00, 0x04, 0xFF, 0x00,
        ]
    }

    fn hechos(s: &Salida) -> &[Hecho] {
        &s.hechos
    }

    fn orden(s: &Salida) -> Option<(&str, bool, &str)> {
        s.hechos.iter().find_map(|h| match h {
            Hecho::OrdenIndustrial {
                funcion,
                escribe,
                detalle,
                ..
            } => Some((funcion.as_str(), *escribe, detalle.as_str())),
            _ => None,
        })
    }

    #[test]
    fn modbus_lee_una_peticion_de_lectura_con_su_rango() {
        let d = Modbus;
        let b = modbus_leer();
        assert!(d.reconoce(&b, &Contexto::tcp_cliente(PUERTO_MODBUS)));
        let s = d.disecar(&b, &Contexto::tcp_cliente(PUERTO_MODBUS));
        assert!(s.cobertura.completa());
        let (f, w, det) = orden(&s).expect("una orden");
        assert_eq!(f, "leer-registros-retentivos");
        assert!(!w);
        assert_eq!(det, "direcciones 0..10");
    }

    /// LA distincion del modulo: leer es telemetria y escribir mueve algo en el
    /// mundo fisico. Un sensor que los cuente juntos entierra el segundo.
    #[test]
    fn modbus_marca_como_escritura_la_orden_que_mueve_algo() {
        let d = Modbus;
        let s = d.disecar(&modbus_escribir(), &Contexto::tcp_cliente(PUERTO_MODBUS));
        let (f, w, det) = orden(&s).expect("una orden");
        assert_eq!(f, "escribir-bobina");
        assert!(w, "escribir una bobina cambia una salida fisica");
        assert_eq!(det, "bobina 4 a ON");
    }

    #[test]
    fn modbus_se_reconoce_fuera_de_su_puerto() {
        // Un PLC reexpuesto por un tunel sigue hablando Modbus, y reconocerlo
        // solo en el 502 es como se pierde justo el caso que importa.
        let d = Modbus;
        assert!(d.reconoce(&modbus_leer(), &Contexto::tcp_cliente(31337)));
    }

    #[test]
    fn modbus_rechaza_una_longitud_que_no_cabe_en_la_adu() {
        // 0xFFFF en el campo de longitud no es un mensaje grande: es un emisor
        // que miente, y leerlo como bueno seria reservar lo que el diga.
        let d = Modbus;
        let mut b = modbus_leer();
        b[4] = 0xFF;
        b[5] = 0xFF;
        assert!(!d.reconoce(&b, &Contexto::tcp_cliente(PUERTO_MODBUS)));
        let s = d.disecar(&b, &Contexto::tcp_cliente(PUERTO_MODBUS));
        assert_eq!(s.cobertura.sin_analizar.get(&Motivo::Malformado), Some(&1));
    }

    #[test]
    fn modbus_lee_una_excepcion_sin_llamarla_escritura() {
        let d = Modbus;
        let b = vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x01, 0x83, 0x02];
        let s = d.disecar(&b, &Contexto::tcp_servidor(PUERTO_MODBUS));
        let (f, w, _) = orden(&s).expect("una orden");
        assert!(f.starts_with("excepcion-de-"), "{f}");
        assert!(!w);
    }

    /// Una trama DNP3 real: cabecera de enlace, CRC, transporte con FIR+FIN y
    /// una peticion de lectura.
    fn dnp3_leer() -> Vec<u8> {
        vec![
            0x05, 0x64, 0x08, 0xC4, 0x01, 0x00, 0x02, 0x00, 0x9C, 0xB2, 0xC0, 0xC1, 0x01,
        ]
    }

    #[test]
    fn dnp3_lee_una_peticion_con_su_origen_y_destino() {
        let d = Dnp3;
        let b = dnp3_leer();
        assert!(d.reconoce(&b, &Contexto::tcp_cliente(PUERTO_DNP3)));
        let s = d.disecar(&b, &Contexto::tcp_cliente(PUERTO_DNP3));
        assert!(s.cobertura.completa());
        let (f, w, _) = orden(&s).expect("una orden");
        assert_eq!(f, "leer");
        assert!(!w);
    }

    #[test]
    fn dnp3_marca_operar_como_escritura() {
        // Seleccionar-y-operar es el par que acciona una salida: arma y
        // dispara. Los dos cambian el estado del dispositivo.
        let d = Dnp3;
        let mut b = dnp3_leer();
        b[12] = 0x04;
        let s = d.disecar(&b, &Contexto::tcp_cliente(PUERTO_DNP3));
        let (f, w, _) = orden(&s).expect("una orden");
        assert_eq!(f, "operar");
        assert!(w);
    }

    #[test]
    fn dnp3_no_inventa_una_orden_en_un_segmento_intermedio() {
        // Un segmento sin el bit de primero no lleva cabecera de aplicacion:
        // leer el siguiente byte como funcion daria una orden que nadie mando.
        let d = Dnp3;
        let mut b = dnp3_leer();
        b[10] = 0x00;
        let s = d.disecar(&b, &Contexto::tcp_cliente(PUERTO_DNP3));
        assert!(orden(&s).is_none(), "{:?}", hechos(&s));
        assert!(s.cobertura.completa());
    }

    /// Un `parar-cpu` de S7comm: TPKT, COTP de datos y la cabecera S7 con la
    /// funcion 0x29.
    fn s7_parar() -> Vec<u8> {
        vec![
            // TPKT: version 3, reservado 0, longitud total 25.
            0x03, 0x00, 0x00, 0x19, // COTP: longitud 2, DT Data, numero con EOT.
            0x02, 0xF0, 0x80, // S7: 0x32, Job, redundancia, referencia 1,
            0x32, 0x01, 0x00, 0x00, 0x00, 0x01, // parametro 16, datos 0
            0x00, 0x10, 0x00, 0x00, // funcion 0x29 y su relleno
            0x29, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x50, 0x5F, 0x50, 0x52, 0x4F,
        ]
    }

    #[test]
    fn s7comm_reconoce_la_orden_que_para_una_planta() {
        // Es el ejemplo del modulo: un sensor sin este disector ve «TCP al 102».
        let d = S7comm;
        let b = s7_parar();
        assert!(d.reconoce(&b, &Contexto::tcp_cliente(PUERTO_S7COMM)));
        let s = d.disecar(&b, &Contexto::tcp_cliente(PUERTO_S7COMM));
        assert!(s.cobertura.completa(), "{:?}", s.cobertura);
        let (f, w, _) = orden(&s).expect("una orden");
        assert_eq!(f, "parar-cpu");
        assert!(w);
    }

    #[test]
    fn s7comm_no_confunde_otro_protocolo_del_puerto_102() {
        // Por ISO-TSAP viajan mas cosas: un DT cuya carga no empiece por 0x32
        // no es S7comm, y decir que si lo es llenaria el informe de ruido.
        let d = S7comm;
        let mut b = s7_parar();
        b[7] = 0x33;
        assert!(!d.reconoce(&b, &Contexto::tcp_cliente(PUERTO_S7COMM)));
    }

    #[test]
    fn s7comm_reconoce_la_conexion_cotp_sin_inventarse_una_carga() {
        let d = S7comm;
        let b = vec![
            0x03, 0x00, 0x00, 0x16, 0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xC1, 0x02, 0x01,
            0x00, 0xC2, 0x02, 0x01, 0x02, 0xC0, 0x01, 0x0A,
        ];
        assert!(d.reconoce(&b, &Contexto::tcp_cliente(PUERTO_S7COMM)));
        let s = d.disecar(&b, &Contexto::tcp_cliente(PUERTO_S7COMM));
        let (f, w, _) = orden(&s).expect("una orden");
        assert_eq!(f, "peticion-de-conexion-cotp");
        assert!(!w);
    }

    /// Un `quien-es` de BACnet a la difusion global: BVLC de difusion original,
    /// NPDU con la red de destino 0xFFFF y su cuenta de saltos, y una APDU no
    /// confirmada. Es el barrido con el que empieza todo reconocimiento de una
    /// red de edificio.
    fn bacnet_quien_es() -> Vec<u8> {
        vec![
            0x81, 0x0B, 0x00, 0x0C, // BVLC: difusion original, doce bytes
            0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF, // NPDU: a la red global, un salto
            0x10, 0x08, // APDU: no confirmada, quien-es
        ]
    }

    #[test]
    fn bacnet_lee_un_descubrimiento() {
        let d = Bacnet;
        let b = bacnet_quien_es();
        assert!(d.reconoce(&b, &Contexto::udp(PUERTO_BACNET)));
        let s = d.disecar(&b, &Contexto::udp(PUERTO_BACNET));
        assert!(s.cobertura.completa(), "{:?}", s.cobertura);
        let (f, w, _) = orden(&s).expect("una orden");
        assert_eq!(f, "quien-es");
        assert!(!w);

        // Y el mismo servicio en su forma local, sin encaminamiento: la APDU
        // esta cuatro bytes antes, y un disector que no siguiera el control del
        // NPDU leeria la red de destino como si fuera el servicio.
        let local = vec![0x81, 0x0A, 0x00, 0x08, 0x01, 0x00, 0x10, 0x08];
        let s = d.disecar(&local, &Contexto::udp(PUERTO_BACNET));
        assert_eq!(orden(&s).map(|(f, _, _)| f), Some("quien-es"));
    }

    /// Una tabla de servicios desplazada en uno no falla: nombra otro servicio.
    /// Estos cuatro numeros son los de la clausula 21 de ASHRAE 135 y estan aqui
    /// para que moverlos duela.
    #[test]
    fn los_servicios_de_bacnet_estan_donde_dice_la_norma() {
        assert_eq!(
            servicio_bacnet_no_confirmado(0).map(|(n, _)| n),
            Some("soy")
        );
        assert_eq!(
            servicio_bacnet_no_confirmado(7).map(|(n, _)| n),
            Some("quien-tiene")
        );
        assert_eq!(
            servicio_bacnet_no_confirmado(8).map(|(n, _)| n),
            Some("quien-es")
        );
        assert_eq!(
            servicio_bacnet_no_confirmado(10),
            Some(("escribir-grupo", true))
        );
        assert_eq!(
            servicio_bacnet_confirmado(15).map(|(n, _)| n),
            Some("escribir-propiedad")
        );
        assert_eq!(
            servicio_bacnet_confirmado(12),
            Some(("leer-propiedad", false))
        );
        assert_eq!(servicio_bacnet_no_confirmado(200), None);
    }

    #[test]
    fn bacnet_marca_como_escritura_la_orden_que_aisla_un_controlador() {
        // `controlar-la-comunicacion-del-dispositivo` deja el equipo sordo a la
        // red: es con lo que se aisla un controlador antes de manipularlo.
        let d = Bacnet;
        let b = vec![0x81, 0x0A, 0x00, 0x0A, 0x01, 0x04, 0x00, 0x05, 0x01, 0x11];
        let s = d.disecar(&b, &Contexto::udp(PUERTO_BACNET));
        let (f, w, _) = orden(&s).expect("una orden");
        assert_eq!(f, "controlar-la-comunicacion-del-dispositivo");
        assert!(w);
    }

    #[test]
    fn bacnet_sigue_el_encaminamiento_declarado_en_el_npdu() {
        // Con las redes de origen y destino presentes, la APDU esta mas lejos.
        // Un disector que no las saltara leeria la direccion como servicio.
        let d = Bacnet;
        let b = vec![
            0x81, 0x0A, 0x00, 0x13, // BVLC: unidifusion original, diecinueve bytes
            0x01, 0x28, // NPDU con destino (0x20) y origen (0x08)
            0x00, 0x0C, 0x01, 0x05, // red 12, direccion de un byte: 5
            0x00, 0x0B, 0x01, 0x03, // red 11, direccion de un byte: 3
            0xFF, // cuenta de saltos
            0x00, 0x05, 0x01, 0x0C, // APDU confirmada: leer-propiedad
        ];
        let s = d.disecar(&b, &Contexto::udp(PUERTO_BACNET));
        let (f, w, _) = orden(&s).expect("una orden");
        assert_eq!(f, "leer-propiedad");
        assert!(!w);
    }

    /// Un HEL de OPC-UA con su punto final.
    fn opcua_hola() -> Vec<u8> {
        let url = b"opc.tcp://planta:4840";
        let mut v = Vec::new();
        v.extend_from_slice(b"HELF");
        let total = 8 + 20 + 4 + url.len();
        v.extend_from_slice(&(total as u32).to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes()); // version
        v.extend_from_slice(&65536u32.to_le_bytes()); // buffer de recepcion
        v.extend_from_slice(&65536u32.to_le_bytes()); // buffer de envio
        v.extend_from_slice(&0u32.to_le_bytes()); // tamano maximo
        v.extend_from_slice(&0u32.to_le_bytes()); // trozos maximos
        v.extend_from_slice(&(url.len() as u32).to_le_bytes());
        v.extend_from_slice(url);
        v
    }

    #[test]
    fn opcua_lee_el_saludo_con_su_punto_final() {
        let d = OpcUa;
        let b = opcua_hola();
        assert!(d.reconoce(&b, &Contexto::tcp_cliente(PUERTO_OPCUA)));
        let s = d.disecar(&b, &Contexto::tcp_cliente(PUERTO_OPCUA));
        assert!(s.cobertura.completa());
        let url = s.hechos.iter().find_map(|h| match h {
            Hecho::EjecucionRemota { objetivo, .. } => Some(objetivo.as_str()),
            _ => None,
        });
        assert_eq!(url, Some("opc.tcp://planta:4840"));
    }

    #[test]
    fn opcua_marca_como_escritura_la_llamada_a_metodo() {
        // Llamar a un metodo de un servidor OPC-UA ejecuta logica en el
        // dispositivo: es lo mas parecido a una ejecucion remota que hay en OT.
        let d = OpcUa;
        let mut v = Vec::new();
        v.extend_from_slice(b"MSGF");
        v.extend_from_slice(&33u32.to_le_bytes());
        v.extend_from_slice(&1u32.to_le_bytes()); // canal
        v.extend_from_slice(&1u32.to_le_bytes()); // testigo
        v.extend_from_slice(&1u32.to_le_bytes()); // secuencia
        v.extend_from_slice(&1u32.to_le_bytes()); // peticion
        v.push(0x01); // codificacion de dos bytes
        v.push(0x00); // espacio de nombres
        v.extend_from_slice(&712u16.to_le_bytes()); // CallRequest
        let s = d.disecar(&v, &Contexto::tcp_cliente(PUERTO_OPCUA));
        let (f, w, _) = orden(&s).expect("una orden");
        assert_eq!(f, "llamar-a-metodo");
        assert!(w);
    }

    #[test]
    fn opcua_dice_cuando_la_politica_deja_el_dialogo_en_claro() {
        let d = OpcUa;
        let pol = b"http://opcfoundation.org/UA/SecurityPolicy#None";
        let mut v = Vec::new();
        v.extend_from_slice(b"OPNF");
        let total = 8 + 4 + 4 + pol.len();
        v.extend_from_slice(&(total as u32).to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&(pol.len() as u32).to_le_bytes());
        v.extend_from_slice(pol);
        let s = d.disecar(&v, &Contexto::tcp_cliente(PUERTO_OPCUA));
        let (f, _, det) = orden(&s).expect("una orden");
        assert_eq!(f, "abrir-canal-seguro");
        assert!(det.ends_with("#None"), "{det}");
    }

    /// Todo disector de este modulo declara las dos mitades de su cobertura. Una
    /// lista vacia de «lo que no analiza» seria decir que lo entiende todo, y de
    /// estos cinco protocolos ninguno se entiende entero.
    #[test]
    fn los_cinco_declaran_lo_que_entienden_y_lo_que_no() {
        let ds: Vec<Box<dyn Disector>> = vec![
            Box::new(Modbus),
            Box::new(Dnp3),
            Box::new(S7comm),
            Box::new(Bacnet),
            Box::new(OpcUa),
        ];
        for d in &ds {
            assert!(!d.mensajes_que_entiende().is_empty(), "{}", d.nombre());
            assert!(
                !d.mensajes_que_no_analiza().is_empty(),
                "{}: ningun protocolo industrial se entiende entero, y decir que si \
                 seria inflar la cifra de cobertura",
                d.nombre()
            );
        }
    }
}
