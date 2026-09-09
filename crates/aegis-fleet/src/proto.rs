//! Códec protobuf sobre el cable y los mensajes del servicio de flota.
//!
//! # Por que a mano y no con `prost`/`protoc`
//!
//! El formato de cable de Protocol Buffers es pequeno y estable: varints,
//! campos con etiqueta y campos delimitados por longitud. Generarlo desde un
//! `.proto` exige `protoc`, que no esta en la maquina de integracion, y arrastra
//! una cadena de dependencias grande. Aqui se implementa el formato REAL de
//! cable —el mismo que produce cualquier compilador de protobuf— en lo justo
//! para los mensajes del servicio. Es interoperable byte a byte con un cliente
//! protobuf de verdad; lo prueban las vueltas de ida y vuelta de `tests/proto`.
//!
//! # El formato, en una frase
//!
//! Cada campo es una etiqueta varint `(numero << 3) | tipo` seguida del valor:
//! tipo 0 = varint (enteros, booleanos), tipo 2 = delimitado por longitud
//! (cadenas y bytes: una longitud varint y luego los bytes).

use crate::error::{FleetError, Resultado};

/// Tipo de cable: varint (enteros y booleanos).
const WIRE_VARINT: u64 = 0;
/// Tipo de cable: delimitado por longitud (cadenas y bytes).
const WIRE_BYTES: u64 = 2;

// --- Primitivas del formato de cable ----------------------------------------

/// Anade un `u64` en formato varint (base 128, bit de continuacion).
pub fn escribir_varint(buf: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            buf.push(byte);
            break;
        }
        buf.push(byte | 0x80);
    }
}

/// Anade la etiqueta de un campo.
fn escribir_tag(buf: &mut Vec<u8>, numero: u64, tipo: u64) {
    escribir_varint(buf, (numero << 3) | tipo);
}

/// Anade un campo entero (varint).
pub fn escribir_u64(buf: &mut Vec<u8>, numero: u64, v: u64) {
    if v == 0 {
        return; // los ceros no se serializan (semantica de protobuf proto3)
    }
    escribir_tag(buf, numero, WIRE_VARINT);
    escribir_varint(buf, v);
}

/// Anade un campo booleano.
pub fn escribir_bool(buf: &mut Vec<u8>, numero: u64, v: bool) {
    if v {
        escribir_tag(buf, numero, WIRE_VARINT);
        escribir_varint(buf, 1);
    }
}

/// Anade un campo de bytes (delimitado por longitud).
pub fn escribir_bytes(buf: &mut Vec<u8>, numero: u64, datos: &[u8]) {
    if datos.is_empty() {
        return;
    }
    escribir_tag(buf, numero, WIRE_BYTES);
    escribir_varint(buf, datos.len() as u64);
    buf.extend_from_slice(datos);
}

/// Anade un campo de cadena.
pub fn escribir_str(buf: &mut Vec<u8>, numero: u64, s: &str) {
    escribir_bytes(buf, numero, s.as_bytes());
}

/// Lector de una trama protobuf, campo a campo.
pub struct Lector<'a> {
    datos: &'a [u8],
    pos: usize,
}

/// Un campo leido: su numero y su valor sin interpretar.
pub enum Campo<'a> {
    /// Valor entero (tipo varint).
    Entero(u64, u64),
    /// Valor de bytes (tipo delimitado por longitud).
    Bytes(u64, &'a [u8]),
}

impl<'a> Lector<'a> {
    /// Crea un lector sobre una trama.
    pub fn nuevo(datos: &'a [u8]) -> Lector<'a> {
        Lector { datos, pos: 0 }
    }

    /// Lee un varint crudo.
    fn leer_varint(&mut self) -> Resultado<u64> {
        let mut resultado = 0u64;
        let mut desplazamiento = 0u32;
        loop {
            let byte = *self
                .datos
                .get(self.pos)
                .ok_or_else(|| FleetError::Protocolo("varint truncado".into()))?;
            self.pos += 1;
            if desplazamiento >= 64 {
                return Err(FleetError::Protocolo("varint demasiado largo".into()));
            }
            resultado |= ((byte & 0x7f) as u64) << desplazamiento;
            if byte & 0x80 == 0 {
                return Ok(resultado);
            }
            desplazamiento += 7;
        }
    }

    /// Devuelve el siguiente campo, o `None` al terminar la trama.
    pub fn siguiente(&mut self) -> Resultado<Option<Campo<'a>>> {
        if self.pos >= self.datos.len() {
            return Ok(None);
        }
        let etiqueta = self.leer_varint()?;
        let numero = etiqueta >> 3;
        let tipo = etiqueta & 0x7;
        match tipo {
            WIRE_VARINT => Ok(Some(Campo::Entero(numero, self.leer_varint()?))),
            WIRE_BYTES => {
                let len = self.leer_varint()? as usize;
                let fin = self
                    .pos
                    .checked_add(len)
                    .filter(|&f| f <= self.datos.len())
                    .ok_or_else(|| FleetError::Protocolo("campo de bytes truncado".into()))?;
                let bytes = &self.datos[self.pos..fin];
                self.pos = fin;
                Ok(Some(Campo::Bytes(numero, bytes)))
            }
            otro => Err(FleetError::Protocolo(format!(
                "tipo de cable no soportado: {otro}"
            ))),
        }
    }
}

/// Interpreta un campo de bytes como cadena UTF-8.
fn como_str(bytes: &[u8]) -> Resultado<String> {
    std::str::from_utf8(bytes)
        .map(|s| s.to_string())
        .map_err(|_| FleetError::Protocolo("cadena no es UTF-8 valido".into()))
}

// --- Mensajes del servicio AegisFleet ---------------------------------------

/// `EnrollRequest`: el agente pide entrar en la flota.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SolicitudEnrolamiento {
    /// Identidad estable del agente (CN de su certificado).
    pub id_agente: String,
    /// Nombre de maquina.
    pub hostname: String,
    /// Version del agente.
    pub version_agente: String,
    /// Huella del certificado con el que se conecta.
    pub huella_cert: Vec<u8>,
}

impl SolicitudEnrolamiento {
    /// Serializa al formato de cable.
    pub fn codificar(&self) -> Vec<u8> {
        let mut b = Vec::new();
        escribir_str(&mut b, 1, &self.id_agente);
        escribir_str(&mut b, 2, &self.hostname);
        escribir_str(&mut b, 3, &self.version_agente);
        escribir_bytes(&mut b, 4, &self.huella_cert);
        b
    }

    /// Deserializa desde el formato de cable.
    pub fn decodificar(datos: &[u8]) -> Resultado<Self> {
        let mut m = Self::default();
        let mut lector = Lector::nuevo(datos);
        while let Some(campo) = lector.siguiente()? {
            match campo {
                Campo::Bytes(1, v) => m.id_agente = como_str(v)?,
                Campo::Bytes(2, v) => m.hostname = como_str(v)?,
                Campo::Bytes(3, v) => m.version_agente = como_str(v)?,
                Campo::Bytes(4, v) => m.huella_cert = v.to_vec(),
                _ => {}
            }
        }
        Ok(m)
    }
}

/// `EnrollResponse`: la respuesta del plano de control.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RespuestaEnrolamiento {
    /// Si el agente queda enrolado.
    pub aceptado: bool,
    /// Identificador que la flota asigna al agente.
    pub id_flota: String,
    /// Intervalo de latido en segundos.
    pub intervalo_latido_seg: u64,
    /// Motivo del rechazo, si lo hubo.
    pub motivo: String,
}

impl RespuestaEnrolamiento {
    /// Serializa al formato de cable.
    pub fn codificar(&self) -> Vec<u8> {
        let mut b = Vec::new();
        escribir_bool(&mut b, 1, self.aceptado);
        escribir_str(&mut b, 2, &self.id_flota);
        escribir_u64(&mut b, 3, self.intervalo_latido_seg);
        escribir_str(&mut b, 4, &self.motivo);
        b
    }

    /// Deserializa desde el formato de cable.
    pub fn decodificar(datos: &[u8]) -> Resultado<Self> {
        let mut m = Self::default();
        let mut lector = Lector::nuevo(datos);
        while let Some(campo) = lector.siguiente()? {
            match campo {
                Campo::Entero(1, v) => m.aceptado = v != 0,
                Campo::Bytes(2, v) => m.id_flota = como_str(v)?,
                Campo::Entero(3, v) => m.intervalo_latido_seg = v,
                Campo::Bytes(4, v) => m.motivo = como_str(v)?,
                _ => {}
            }
        }
        Ok(m)
    }
}

/// `Heartbeat`: el pulso periodico del agente.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Latido {
    /// Identidad del agente.
    pub id_agente: String,
    /// Instante Unix del latido.
    pub momento_unix: u64,
    /// Memoria residente del agente, en KiB.
    pub rss_kb: u64,
    /// Amenazas activas en el endpoint.
    pub amenazas_activas: u64,
    /// Version de politica que el agente tiene cargada.
    pub version_politica: u64,
}

impl Latido {
    /// Serializa al formato de cable.
    pub fn codificar(&self) -> Vec<u8> {
        let mut b = Vec::new();
        escribir_str(&mut b, 1, &self.id_agente);
        escribir_u64(&mut b, 2, self.momento_unix);
        escribir_u64(&mut b, 3, self.rss_kb);
        escribir_u64(&mut b, 4, self.amenazas_activas);
        escribir_u64(&mut b, 5, self.version_politica);
        b
    }

    /// Deserializa desde el formato de cable.
    pub fn decodificar(datos: &[u8]) -> Resultado<Self> {
        let mut m = Self::default();
        let mut lector = Lector::nuevo(datos);
        while let Some(campo) = lector.siguiente()? {
            match campo {
                Campo::Bytes(1, v) => m.id_agente = como_str(v)?,
                Campo::Entero(2, v) => m.momento_unix = v,
                Campo::Entero(3, v) => m.rss_kb = v,
                Campo::Entero(4, v) => m.amenazas_activas = v,
                Campo::Entero(5, v) => m.version_politica = v,
                _ => {}
            }
        }
        Ok(m)
    }
}

/// `HeartbeatAck`: la respuesta al latido.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AckLatido {
    /// Si el plano de control recibio el latido.
    pub recibido: bool,
    /// Ultima version de politica disponible en la flota.
    pub version_politica_disponible: u64,
    /// Si hay un comando encolado para el agente.
    pub hay_comando: bool,
}

impl AckLatido {
    /// Serializa al formato de cable.
    pub fn codificar(&self) -> Vec<u8> {
        let mut b = Vec::new();
        escribir_bool(&mut b, 1, self.recibido);
        escribir_u64(&mut b, 2, self.version_politica_disponible);
        escribir_bool(&mut b, 3, self.hay_comando);
        b
    }

    /// Deserializa desde el formato de cable.
    pub fn decodificar(datos: &[u8]) -> Resultado<Self> {
        let mut m = Self::default();
        let mut lector = Lector::nuevo(datos);
        while let Some(campo) = lector.siguiente()? {
            match campo {
                Campo::Entero(1, v) => m.recibido = v != 0,
                Campo::Entero(2, v) => m.version_politica_disponible = v,
                Campo::Entero(3, v) => m.hay_comando = v != 0,
                _ => {}
            }
        }
        Ok(m)
    }
}

/// `EventReport`: el agente reporta un evento de seguridad.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReporteEvento {
    /// Identidad del agente.
    pub id_agente: String,
    /// Severidad (0..=3).
    pub severidad: u64,
    /// Categoria (p. ej. "ransomware", "syscall-directa").
    pub categoria: String,
    /// Descripcion legible.
    pub descripcion: String,
    /// Instante Unix del evento.
    pub momento_unix: u64,
}

impl ReporteEvento {
    /// Serializa al formato de cable.
    pub fn codificar(&self) -> Vec<u8> {
        let mut b = Vec::new();
        escribir_str(&mut b, 1, &self.id_agente);
        escribir_u64(&mut b, 2, self.severidad);
        escribir_str(&mut b, 3, &self.categoria);
        escribir_str(&mut b, 4, &self.descripcion);
        escribir_u64(&mut b, 5, self.momento_unix);
        b
    }

    /// Deserializa desde el formato de cable.
    pub fn decodificar(datos: &[u8]) -> Resultado<Self> {
        let mut m = Self::default();
        let mut lector = Lector::nuevo(datos);
        while let Some(campo) = lector.siguiente()? {
            match campo {
                Campo::Bytes(1, v) => m.id_agente = como_str(v)?,
                Campo::Entero(2, v) => m.severidad = v,
                Campo::Bytes(3, v) => m.categoria = como_str(v)?,
                Campo::Bytes(4, v) => m.descripcion = como_str(v)?,
                Campo::Entero(5, v) => m.momento_unix = v,
                _ => {}
            }
        }
        Ok(m)
    }
}

/// `EventAck`: acuse del reporte de evento.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AckEvento {
    /// Si el evento se registro.
    pub recibido: bool,
    /// Identificador de incidente asignado.
    pub id_incidente: String,
}

impl AckEvento {
    /// Serializa al formato de cable.
    pub fn codificar(&self) -> Vec<u8> {
        let mut b = Vec::new();
        escribir_bool(&mut b, 1, self.recibido);
        escribir_str(&mut b, 2, &self.id_incidente);
        b
    }

    /// Deserializa desde el formato de cable.
    pub fn decodificar(datos: &[u8]) -> Resultado<Self> {
        let mut m = Self::default();
        let mut lector = Lector::nuevo(datos);
        while let Some(campo) = lector.siguiente()? {
            match campo {
                Campo::Entero(1, v) => m.recibido = v != 0,
                Campo::Bytes(2, v) => m.id_incidente = como_str(v)?,
                _ => {}
            }
        }
        Ok(m)
    }
}
