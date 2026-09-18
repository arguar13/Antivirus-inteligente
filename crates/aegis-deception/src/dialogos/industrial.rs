//! Senuelos industriales: Modbus, S7comm, DNP3, BACnet y OPC-UA.
//!
//! Son los cinco protocolos que disecciona la FASE 89, ahora del otro lado: alli
//! se lee lo que pasa por el cable, aqui se **contesta** como contestaria un
//! automata.
//!
//! # Por que un automata senuelo vale mas que cualquier otro
//!
//! Porque en una red de planta **no hay trafico legitimo hacia una direccion que
//! no existe**. Una oficina tiene escaneres de inventario, agentes de gestion y
//! usuarios que se equivocan de servidor; una red de control no: cada dispositivo
//! habla con los dos o tres que tiene configurados y con ninguno mas. Un automata
//! que nadie ha configurado y que recibe una lectura de registros es, sin
//! ambiguedad, alguien que no deberia estar ahi.
//!
//! Y sobre todo porque aqui se puede distinguir **al que mira del que toca**. Una
//! lectura de registros es reconocimiento; una escritura de bobinas o un «parar
//! CPU» es un intento de actuar sobre un proceso fisico. En una planta esa
//! diferencia no es de severidad: es la diferencia entre un incidente informatico
//! y una parada de produccion o algo peor. Por eso
//! [`Revelacion::OrdenDeEscritura`] existe como variante propia y no como un campo
//! booleano dentro de otra cosa.
//!
//! # BACnet y la razon de ser del limitador
//!
//! BACnet va sobre UDP, y su mensaje `Who-Is` se contesta con un `I-Am` **mucho
//! mayor**. Eso es un amplificador de manual, y se ha usado: quien falsifica la
//! direccion de origen consigue que el automata —o el senuelo— dispare contra una
//! victima que no pidio nada. Por eso este modulo declara [`Transporte::Udp`]
//! donde toca, y el envoltorio de [`crate::dialogo::Conversacion`] recorta: la
//! respuesta no puede ser mayor que la pregunta, **aunque el dialogo la quiera
//! mandar entera**. El senuelo pierde algo de verosimilitud en ese caso concreto y
//! a cambio no se puede usar contra un tercero, que no es un intercambio
//! discutible.

use crate::dialogo::{Dialogo, Paso, Revelacion};
use crate::dialogos::acceso::tam_revelacion;
use crate::limitador::Transporte;

// ─────────────────────────────────────────────────────────────────────────────
// Modbus
// ─────────────────────────────────────────────────────────────────────────────

/// Senuelo de Modbus/TCP.
#[derive(Debug, Default)]
pub struct Modbus {
    dicho: Vec<Revelacion>,
}

impl Modbus {
    /// Un senuelo de Modbus nuevo.
    #[must_use]
    pub fn nuevo() -> Modbus {
        Modbus::default()
    }

    /// Que hace una funcion, y si escribe.
    ///
    /// La tabla es la del estandar. Lo que importa de ella es la columna de
    /// escritura: es lo que separa inventariar de actuar.
    #[must_use]
    pub fn funcion(codigo: u8) -> Option<(&'static str, bool)> {
        Some(match codigo {
            0x01 => ("leer-bobinas", false),
            0x02 => ("leer-entradas-discretas", false),
            0x03 => ("leer-registros-de-retencion", false),
            0x04 => ("leer-registros-de-entrada", false),
            0x05 => ("escribir-una-bobina", true),
            0x06 => ("escribir-un-registro", true),
            0x07 => ("leer-estado-de-excepcion", false),
            0x08 => ("diagnostico", false),
            0x0f => ("escribir-varias-bobinas", true),
            0x10 => ("escribir-varios-registros", true),
            0x11 => ("informe-de-identificacion", false),
            0x16 => ("escribir-registro-con-mascara", true),
            0x17 => ("leer-y-escribir-registros", true),
            0x2b => ("identificacion-del-dispositivo", false),
            _ => return None,
        })
    }
}

impl Dialogo for Modbus {
    fn servicio(&self) -> &'static str {
        "modbus"
    }
    fn transporte(&self) -> Transporte {
        Transporte::Tcp
    }
    fn turno(&mut self, entrada: &[u8]) -> Paso {
        // MBAP: transaccion, protocolo (0), longitud, unidad; y luego la funcion.
        if entrada.len() < 8 || entrada[2] != 0 || entrada[3] != 0 {
            return Paso::Cierra;
        }
        let transaccion = [entrada[0], entrada[1]];
        let unidad = entrada[6];
        let codigo = entrada[7];

        let Some((nombre, escribe)) = Modbus::funcion(codigo) else {
            // Excepcion 01: funcion no soportada, que es lo que contesta un
            // automata de verdad. Anotarlo importa: barrer funciones inexistentes
            // es lo que hace una herramienta de inventario.
            self.dicho.push(Revelacion::Peticion {
                que: format!("funcion desconocida {codigo:#04x} en la unidad {unidad}"),
            });
            return Paso::Responde(respuesta_modbus(
                transaccion,
                unidad,
                codigo | 0x80,
                &[0x01],
            ));
        };

        let detalle = if entrada.len() >= 12 {
            let dir = u16::from_be_bytes([entrada[8], entrada[9]]);
            let n = u16::from_be_bytes([entrada[10], entrada[11]]);
            format!("{nombre} desde {dir}, {n} elementos (unidad {unidad})")
        } else {
            format!("{nombre} (unidad {unidad})")
        };

        if escribe {
            self.dicho
                .push(Revelacion::OrdenDeEscritura { que: detalle });
        } else {
            self.dicho.push(Revelacion::Peticion { que: detalle });
        }

        // Se contesta con valores creibles: un automata que conteste ceros a todo
        // se nota. Diez registros con lecturas de proceso plausibles.
        let cuerpo: Vec<u8> = if escribe {
            entrada[8..entrada.len().min(12)].to_vec()
        } else {
            let mut v = vec![20u8]; // diez registros de dos bytes
            for i in 0..10u16 {
                v.extend_from_slice(&(1000 + i * 37).to_be_bytes());
            }
            v
        };
        Paso::Responde(respuesta_modbus(transaccion, unidad, codigo, &cuerpo))
    }
    fn revelado(&self) -> &[Revelacion] {
        &self.dicho
    }
    fn estado(&self) -> usize {
        self.dicho.iter().map(tam_revelacion).sum()
    }
}

/// Envuelve una respuesta de Modbus en su cabecera MBAP.
fn respuesta_modbus(transaccion: [u8; 2], unidad: u8, funcion: u8, cuerpo: &[u8]) -> Vec<u8> {
    let largo = (cuerpo.len() + 2) as u16; // unidad + funcion + cuerpo
    let mut v = Vec::with_capacity(6 + largo as usize);
    v.extend_from_slice(&transaccion);
    v.extend_from_slice(&[0, 0]); // protocolo
    v.extend_from_slice(&largo.to_be_bytes());
    v.push(unidad);
    v.push(funcion);
    v.extend_from_slice(cuerpo);
    v
}

// ─────────────────────────────────────────────────────────────────────────────
// S7comm
// ─────────────────────────────────────────────────────────────────────────────

/// Senuelo de S7comm (Siemens, sobre TPKT/COTP).
///
/// Es el protocolo con el que se para una linea de produccion Siemens, y por eso
/// su funcion `0x29` —**parar CPU**— se anota como lo que es.
#[derive(Debug, Default)]
pub struct S7 {
    dicho: Vec<Revelacion>,
    conectado: bool,
}

impl S7 {
    /// Un senuelo de S7comm nuevo.
    #[must_use]
    pub fn nuevo() -> S7 {
        S7::default()
    }

    /// Que hace una funcion de S7, y si cambia el estado del automata.
    #[must_use]
    pub fn funcion(codigo: u8) -> (&'static str, bool) {
        match codigo {
            0x04 => ("leer-variable", false),
            0x05 => ("escribir-variable", true),
            0x1a => ("pedir-descarga", true),
            0x1b => ("descargar-bloque", true),
            0x1d => ("pedir-subida", false),
            0x1e => ("subir-bloque", false),
            0x28 => ("arrancar-cpu", true),
            0x29 => ("parar-cpu", true),
            0xf0 => ("negociar-parametros", false),
            _ => ("funcion-desconocida", false),
        }
    }
}

impl Dialogo for S7 {
    fn servicio(&self) -> &'static str {
        "s7comm"
    }
    fn transporte(&self) -> Transporte {
        Transporte::Tcp
    }
    fn turno(&mut self, entrada: &[u8]) -> Paso {
        if entrada.len() < 7 || entrada[0] != 3 {
            return Paso::Cierra;
        }
        // COTP: tipo 0xE0 es peticion de conexion.
        if entrada[5] == 0xE0 {
            self.conectado = true;
            self.dicho.push(Revelacion::Herramienta {
                texto: "pidio conexion COTP a un automata S7".to_owned(),
            });
            // Confirmacion de conexion COTP.
            return Paso::Responde(vec![
                0x03, 0x00, 0x00, 0x16, 0x11, 0xd0, 0x00, 0x01, 0x00, 0x02, 0x00, 0xc0, 0x01, 0x0a,
                0xc1, 0x02, 0x01, 0x00, 0xc2, 0x02, 0x01, 0x02,
            ]);
        }
        // Datos: TPKT(4) + COTP(3) + S7 (0x32, tipo, ...), funcion en el byte 17.
        if entrada.len() < 18 || entrada[7] != 0x32 {
            return Paso::Cierra;
        }
        let codigo = entrada[17];
        let (nombre, escribe) = S7::funcion(codigo);
        let que = format!("S7 {nombre} ({codigo:#04x})");
        if escribe {
            self.dicho.push(Revelacion::OrdenDeEscritura { que });
        } else {
            self.dicho.push(Revelacion::Peticion { que });
        }
        // Respuesta S7 (tipo 3) con error cero.
        let mut v = vec![0x03, 0x00, 0x00, 0x1b, 0x02, 0xf0, 0x80];
        v.extend_from_slice(&[0x32, 0x03]); // protocolo, tipo respuesta
        v.extend_from_slice(&[0x00, 0x00]); // reservado
        v.extend_from_slice(&entrada[11..13]); // referencia
        v.extend_from_slice(&[0x00, 0x02]); // longitud de parametros
        v.extend_from_slice(&[0x00, 0x05]); // longitud de datos
        v.extend_from_slice(&[0x00, 0x00]); // clase y codigo de error
        v.push(codigo);
        v.push(0x01); // un elemento
        v.extend_from_slice(&[0xff, 0x04, 0x00, 0x10]); // ok, bits
        Paso::Responde(v)
    }
    fn revelado(&self) -> &[Revelacion] {
        &self.dicho
    }
    fn estado(&self) -> usize {
        self.dicho.iter().map(tam_revelacion).sum()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DNP3
// ─────────────────────────────────────────────────────────────────────────────

/// Senuelo de DNP3.
///
/// La funcion **`0x0D` (frio) y `0x0E` (caliente)** son reinicios del dispositivo,
/// y `0x03`/`0x04`/`0x05` son el trio «seleccionar, operar, operar directo» con el
/// que se acciona un mando. Todas cambian el mundo fisico y por eso van aparte.
#[derive(Debug, Default)]
pub struct Dnp3 {
    dicho: Vec<Revelacion>,
}

impl Dnp3 {
    /// Un senuelo de DNP3 nuevo.
    #[must_use]
    pub fn nuevo() -> Dnp3 {
        Dnp3::default()
    }

    /// Que hace una funcion de DNP3, y si actua sobre el dispositivo.
    #[must_use]
    pub fn funcion(codigo: u8) -> (&'static str, bool) {
        match codigo {
            0x00 => ("confirmar", false),
            0x01 => ("leer", false),
            0x02 => ("escribir", true),
            0x03 => ("seleccionar", true),
            0x04 => ("operar", true),
            0x05 => ("operar-directo", true),
            0x0d => ("reinicio-en-frio", true),
            0x0e => ("reinicio-en-caliente", true),
            0x12 => ("parar-aplicacion", true),
            0x14 => ("habilitar-no-solicitados", false),
            0x17 => ("borrar-fichero", true),
            _ => ("funcion-desconocida", false),
        }
    }
}

impl Dialogo for Dnp3 {
    fn servicio(&self) -> &'static str {
        "dnp3"
    }
    fn transporte(&self) -> Transporte {
        Transporte::Tcp
    }
    fn turno(&mut self, entrada: &[u8]) -> Paso {
        // Empieza por 0x05 0x64; la capa de aplicacion llega tras 10 de enlace y
        // 1 de transporte.
        if entrada.len() < 13 || entrada[0] != 0x05 || entrada[1] != 0x64 {
            return Paso::Cierra;
        }
        let codigo = entrada[12];
        let (nombre, escribe) = Dnp3::funcion(codigo);
        let origen = u16::from_le_bytes([entrada[6], entrada[7]]);
        let que = format!("DNP3 {nombre} ({codigo:#04x}) desde la estacion {origen}");
        if escribe {
            self.dicho.push(Revelacion::OrdenDeEscritura { que });
        } else {
            self.dicho.push(Revelacion::Peticion { que });
        }
        // Respuesta minima con el indicador interno a cero.
        let mut v = vec![0x05, 0x64, 0x0b, 0x44];
        v.extend_from_slice(&entrada[6..8]); // destino = su origen
        v.extend_from_slice(&entrada[4..6]); // origen = su destino
        v.extend_from_slice(&[0x00, 0x00]); // CRC de enlace (no se calcula)
        v.push(0xc0); // transporte
        v.push(0xc1); // control de aplicacion
        v.push(0x81); // respuesta
        v.extend_from_slice(&[0x00, 0x00]); // indicaciones internas
        Paso::Responde(v)
    }
    fn revelado(&self) -> &[Revelacion] {
        &self.dicho
    }
    fn estado(&self) -> usize {
        self.dicho.iter().map(tam_revelacion).sum()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BACnet
// ─────────────────────────────────────────────────────────────────────────────

/// Senuelo de BACnet/IP.
///
/// **Es el unico de UDP**, y por eso es el que demuestra el limitador. Su
/// `Who-Is` mide ocho bytes y su `I-Am` natural mide bastante mas: sin la cota, el
/// senuelo seria un amplificador con la direccion de esta maquina en los registros
/// de la victima.
#[derive(Debug, Default)]
pub struct Bacnet {
    dicho: Vec<Revelacion>,
}

impl Bacnet {
    /// Un senuelo de BACnet nuevo.
    #[must_use]
    pub fn nuevo() -> Bacnet {
        Bacnet::default()
    }

    /// Los servicios sin confirmar, con los numeros de la norma (clausula 21).
    #[must_use]
    pub fn servicio_sin_confirmar(codigo: u8) -> (&'static str, bool) {
        match codigo {
            0 => ("i-am", false),
            1 => ("i-have", false),
            2 => ("cov-notification-sin-confirmar", false),
            3 => ("notificacion-de-evento-sin-confirmar", false),
            4 => ("mensaje-privado", false),
            5 => ("texto-a-la-consola", true),
            6 => ("hora-a-la-hora", true),
            7 => ("who-has", false),
            8 => ("who-is", false),
            9 => ("hora-utc", true),
            10 => ("escribir-grupo", true),
            _ => ("servicio-desconocido", false),
        }
    }

    /// Los servicios confirmados que cambian el dispositivo.
    #[must_use]
    pub fn servicio_confirmado(codigo: u8) -> (&'static str, bool) {
        match codigo {
            12 => ("leer-propiedad", false),
            14 => ("leer-varias-propiedades", false),
            15 => ("escribir-propiedad", true),
            16 => ("escribir-varias-propiedades", true),
            17 => ("escribir-rango-de-propiedad", true),
            18 => ("control-del-dispositivo", true),
            20 => ("reiniciar-dispositivo", true),
            _ => ("servicio-desconocido", false),
        }
    }
}

impl Dialogo for Bacnet {
    fn servicio(&self) -> &'static str {
        "bacnet"
    }
    fn transporte(&self) -> Transporte {
        Transporte::Udp
    }
    fn turno(&mut self, entrada: &[u8]) -> Paso {
        // BVLC: tipo 0x81, funcion, longitud de 16 bits. Despues NPDU y APDU.
        if entrada.len() < 6 || entrada[0] != 0x81 {
            return Paso::Cierra;
        }
        let largo = u16::from_be_bytes([entrada[2], entrada[3]]) as usize;
        if largo != entrada.len() {
            // Un BVLC que miente sobre su longitud no viene de una herramienta
            // normal; es la forma de un intento de confundir al que lo lea.
            self.dicho.push(Revelacion::Peticion {
                que: format!(
                    "BVLC con longitud falsa: dice {largo} y mide {}",
                    entrada.len()
                ),
            });
            return Paso::Cierra;
        }
        // La cabecera BVLC son CUATRO bytes —tipo, funcion y longitud de 16—, no
        // seis. Detras viene la NPDU: version 1, control, y la APDU empieza tras
        // esos dos si no hay direccionamiento de red.
        let apdu = match entrada.get(4..) {
            Some(n) if n.len() >= 3 && n[0] == 1 => &n[2..],
            _ => return Paso::Cierra,
        };
        let tipo = apdu[0] >> 4;
        let (nombre, escribe) = match tipo {
            0 => {
                // Peticion confirmada: el servicio va en el cuarto byte.
                let c = apdu.get(3).copied().unwrap_or(0xff);
                Bacnet::servicio_confirmado(c)
            }
            1 => {
                let c = apdu.get(1).copied().unwrap_or(0xff);
                Bacnet::servicio_sin_confirmar(c)
            }
            _ => ("apdu-de-otro-tipo", false),
        };
        let que = format!("BACnet {nombre}");
        if escribe {
            self.dicho.push(Revelacion::OrdenDeEscritura { que });
        } else {
            self.dicho.push(Revelacion::Peticion { que });
        }

        // Un `I-Am` de respuesta. Que el limitador lo recorte es el resultado
        // correcto: la alternativa es amplificar.
        let mut apdu_r = vec![0x10, 0x00]; // sin confirmar, i-am
        apdu_r.extend_from_slice(&[0xc4, 0x02, 0x00, 0x27, 0x0f]); // identificador
        apdu_r.extend_from_slice(&[0x22, 0x05, 0xc4]); // longitud maxima
        apdu_r.extend_from_slice(&[0x91, 0x00]); // segmentacion
        apdu_r.extend_from_slice(&[0x21, 0x0b]); // fabricante
        let mut v = vec![0x81, 0x0b];
        let total = (4 + 2 + apdu_r.len()) as u16;
        v.extend_from_slice(&total.to_be_bytes());
        v.extend_from_slice(&[0x01, 0x20]); // NPDU
        v.extend_from_slice(&apdu_r);
        Paso::Responde(v)
    }
    fn revelado(&self) -> &[Revelacion] {
        &self.dicho
    }
    fn estado(&self) -> usize {
        self.dicho.iter().map(tam_revelacion).sum()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OPC-UA
// ─────────────────────────────────────────────────────────────────────────────

/// Senuelo de OPC-UA.
///
/// Contesta al `HELLO` con un `ACKNOWLEDGE` y recoge del mensaje la **URL del
/// punto final** que el cliente buscaba, que suele traer el nombre interno del
/// sistema de control.
#[derive(Debug, Default)]
pub struct OpcUa {
    dicho: Vec<Revelacion>,
}

impl OpcUa {
    /// Un senuelo de OPC-UA nuevo.
    #[must_use]
    pub fn nuevo() -> OpcUa {
        OpcUa::default()
    }

    /// La URL del punto final que trae un `HELLO`.
    ///
    /// Va tras 8 bytes de cabecera y 20 de parametros, con su longitud delante —
    /// **que la escribe el cliente**, asi que se comprueba.
    #[must_use]
    pub fn url(datos: &[u8]) -> Option<String> {
        if datos.len() < 32 || &datos[..4] != b"HELF" {
            return None;
        }
        let n = u32::from_le_bytes([datos[28], datos[29], datos[30], datos[31]]) as usize;
        if n == 0 || n > 512 || 32 + n > datos.len() {
            return None;
        }
        Some(String::from_utf8_lossy(&datos[32..32 + n]).to_string())
    }
}

impl Dialogo for OpcUa {
    fn servicio(&self) -> &'static str {
        "opcua"
    }
    fn transporte(&self) -> Transporte {
        Transporte::Tcp
    }
    fn turno(&mut self, entrada: &[u8]) -> Paso {
        if entrada.len() < 8 {
            return Paso::Cierra;
        }
        match &entrada[..4] {
            b"HELF" => {
                if let Some(u) = OpcUa::url(entrada) {
                    self.dicho.push(Revelacion::Peticion {
                        que: format!("buscaba el punto final «{u}»"),
                    });
                }
                // ACKNOWLEDGE con los mismos limites que pidio.
                let mut v = Vec::from(*b"ACKF");
                v.extend_from_slice(&28u32.to_le_bytes());
                v.extend_from_slice(&0u32.to_le_bytes()); // version
                v.extend_from_slice(&65536u32.to_le_bytes()); // bufer de recepcion
                v.extend_from_slice(&65536u32.to_le_bytes()); // bufer de envio
                v.extend_from_slice(&16_777_216u32.to_le_bytes()); // mensaje maximo
                v.extend_from_slice(&5000u32.to_le_bytes()); // troncos maximos
                Paso::Responde(v)
            }
            b"OPNF" => {
                self.dicho.push(Revelacion::Peticion {
                    que: "abrir canal seguro: iba en serio, no era un barrido".to_owned(),
                });
                // Aqui empieza la criptografia de verdad. Se corta con un error
                // de servicio, que es lo que devuelve un servidor sin la politica
                // que pide el cliente.
                let mut v = Vec::from(*b"ERRF");
                v.extend_from_slice(&16u32.to_le_bytes());
                v.extend_from_slice(&0x8060_0000u32.to_le_bytes()); // BadTcpEndpointUrlInvalid
                v.extend_from_slice(&0u32.to_le_bytes()); // razon vacia
                Paso::RespondeYCierra(v)
            }
            _ => Paso::Cierra,
        }
    }
    fn revelado(&self) -> &[Revelacion] {
        &self.dicho
    }
    fn estado(&self) -> usize {
        self.dicho.iter().map(tam_revelacion).sum()
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::dialogo::Conversacion;
    use crate::limitador::Recorte;

    fn peticion_modbus(funcion: u8, dir: u16, n: u16) -> Vec<u8> {
        let mut v = vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, funcion];
        v.extend_from_slice(&dir.to_be_bytes());
        v.extend_from_slice(&n.to_be_bytes());
        v
    }

    #[test]
    fn modbus_separa_leer_de_escribir() {
        let mut m = Modbus::nuevo();
        m.turno(&peticion_modbus(0x03, 100, 10)); // leer
        m.turno(&peticion_modbus(0x10, 40, 2)); // escribir varios registros
        let graves: Vec<_> = m.revelado().iter().filter(|r| r.es_grave()).collect();
        assert_eq!(graves.len(), 1, "{:?}", m.revelado());
        assert!(graves[0].frase().contains("escribir-varios-registros"));
    }

    #[test]
    fn modbus_contesta_excepcion_a_una_funcion_que_no_existe() {
        let mut m = Modbus::nuevo();
        let p = m.turno(&peticion_modbus(0x63, 0, 1));
        let v = p.bytes();
        assert_eq!(v[7], 0x63 | 0x80, "funcion con el bit de excepcion");
        assert_eq!(v[8], 0x01, "excepcion 1: funcion no soportada");
    }

    #[test]
    fn la_respuesta_de_modbus_declara_su_longitud_de_verdad() {
        let mut m = Modbus::nuevo();
        let p = m.turno(&peticion_modbus(0x03, 0, 10));
        let v = p.bytes();
        let largo = u16::from_be_bytes([v[4], v[5]]) as usize;
        assert_eq!(largo, v.len() - 6);
    }

    #[test]
    fn s7_anota_parar_la_cpu_como_lo_que_es() {
        let mut s = S7::nuevo();
        // Conexion COTP.
        s.turno(&[0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0x00, 0x00]);
        let mut datos = vec![0x03, 0x00, 0x00, 0x20, 0x02, 0xf0, 0x80];
        datos.extend_from_slice(&[0x32, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00, 0x00]);
        datos.push(0x29); // parar CPU, en el byte 17
        datos.extend_from_slice(&[0u8; 8]);
        s.turno(&datos);
        let graves: Vec<_> = s.revelado().iter().filter(|r| r.es_grave()).collect();
        assert_eq!(graves.len(), 1);
        assert!(graves[0].frase().contains("parar-cpu"), "{:?}", graves[0]);
    }

    #[test]
    fn dnp3_anota_operar_y_reiniciar_como_escrituras() {
        let mut d = Dnp3::nuevo();
        let trama = |f: u8| {
            let mut v = vec![
                0x05, 0x64, 0x0b, 0xc4, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0xc0, 0xc1,
            ];
            v.push(f);
            v
        };
        d.turno(&trama(0x01)); // leer
        d.turno(&trama(0x05)); // operar directo
        d.turno(&trama(0x0d)); // reinicio en frio
        let graves: Vec<_> = d.revelado().iter().filter(|r| r.es_grave()).collect();
        assert_eq!(graves.len(), 2, "{:?}", d.revelado());
    }

    fn who_is() -> Vec<u8> {
        // BVLC 0x81 0x0b, longitud 8; NPDU 01 20; APDU 10 08 (who-is).
        vec![0x81, 0x0b, 0x00, 0x08, 0x01, 0x20, 0x10, 0x08]
    }

    #[test]
    fn bacnet_reconoce_el_who_is_con_el_numero_de_la_norma() {
        let mut b = Bacnet::nuevo();
        b.turno(&who_is());
        assert!(
            b.revelado()[0].frase().contains("who-is"),
            "{:?}",
            b.revelado()
        );
    }

    #[test]
    fn bacnet_no_amplifica_aunque_su_respuesta_natural_sea_mayor() {
        // **La cifra de la invariante.** Sin la cota, ocho bytes de pregunta
        // devuelven veinte y pico: un multiplicador apuntando a quien el atacante
        // diga.
        let pregunta = who_is();
        let mut suelto = Bacnet::nuevo();
        let natural = suelto.turno(&pregunta).bytes().len();
        assert!(
            natural > pregunta.len(),
            "el I-Am natural tiene que ser mayor, si no la prueba no prueba nada"
        );

        let mut lim = crate::limitador::Limitador::nuevo();
        let mut c = Conversacion::nueva(Bacnet::nuevo());
        let (salida, motivo) = c.turno(&mut lim, 1, 0, &pregunta);
        assert_eq!(motivo, Recorte::PorAmplificacion);
        assert!(salida.len() <= pregunta.len());
        assert!(
            c.cuentas().amplificacion_en_centesimas() <= 100,
            "{}",
            c.cuentas().frase()
        );
    }

    #[test]
    fn bacnet_no_saluda_porque_esta_en_udp() {
        let mut c = Conversacion::nueva(Bacnet::nuevo());
        assert!(c.saludo().is_empty());
    }

    #[test]
    fn bacnet_no_se_cree_una_longitud_falsa() {
        let mut b = Bacnet::nuevo();
        let mut falso = who_is();
        falso[3] = 0xff;
        let p = b.turno(&falso);
        assert!(p.cierra());
        assert!(b.revelado()[0].frase().contains("longitud falsa"));
    }

    #[test]
    fn opcua_saca_el_punto_final_que_buscaban() {
        let url = "opc.tcp://scada-planta-1:4840/UA/Produccion";
        let mut v = Vec::from(*b"HELF");
        v.extend_from_slice(&((32 + url.len()) as u32).to_le_bytes());
        v.extend_from_slice(&[0u8; 20]);
        v.extend_from_slice(&(url.len() as u32).to_le_bytes());
        v.extend_from_slice(url.as_bytes());
        assert_eq!(OpcUa::url(&v).as_deref(), Some(url));

        let mut o = OpcUa::nuevo();
        let p = o.turno(&v);
        assert_eq!(&p.bytes()[..4], b"ACKF");
        assert!(o.revelado()[0].frase().contains("scada-planta-1"));
    }

    #[test]
    fn ninguno_se_rompe_con_entradas_recortadas_ni_hostiles() {
        let muestras: Vec<Vec<u8>> = vec![
            peticion_modbus(0x03, 0, 10),
            who_is(),
            vec![0x05, 0x64, 0x0b, 0xc4, 1, 0, 2, 0, 0, 0, 0xc0, 0xc1, 0x05],
            vec![0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0x00, 0x00],
            Vec::from(*b"HELF"),
            vec![0xff; 64],
            vec![0x00; 64],
        ];
        for m in muestras {
            for n in 0..=m.len() {
                let t = &m[..n];
                let _ = Modbus::nuevo().turno(t);
                let _ = S7::nuevo().turno(t);
                let _ = Dnp3::nuevo().turno(t);
                let _ = Bacnet::nuevo().turno(t);
                let _ = OpcUa::nuevo().turno(t);
            }
        }
    }
}
