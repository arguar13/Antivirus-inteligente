//! Enmarcado de mensajes estilo gRPC sobre el canal mTLS.
//!
//! # El formato
//!
//! gRPC enmarca cada mensaje con un prefijo de cinco bytes: un byte de bandera
//! de compresion y cuatro bytes de longitud en big-endian, seguidos del mensaje
//! protobuf. Aqui se usa ESE prefijo, precedido de un byte de enrutado —el
//! metodo en la peticion, el estado en la respuesta— que sobre un canal
//! HTTP/2 llevarian las cabeceras `:path` y `grpc-status`. Sobre el flujo mTLS
//! sincrono del producto, un byte cumple el mismo papel.
//!
//! ```text
//! peticion:   [ metodo:u8 ][ comprimido:u8 ][ longitud:u32 BE ][ protobuf... ]
//! respuesta:  [ estado:u8 ][ comprimido:u8 ][ longitud:u32 BE ][ protobuf... ]
//! ```
//!
//! # Por que no HTTP/2 «de verdad»
//!
//! El unico HTTP/2 maduro en Rust es asincrono y arrastra un runtime (`tokio`).
//! El resto de AegisCore es sincrono a proposito, por el presupuesto de memoria
//! y por el control estricto de la concurrencia. El modelo de servicio de gRPC
//! —llamadas unarias con peticion y respuesta protobuf, autenticadas por mTLS—
//! se conserva entero; lo que cambia es que el transporte es el enmarcado de
//! arriba en vez de tramas HTTP/2. La seguridad (mTLS mutuo, protobuf real,
//! certificados rotativos) es identica.

use std::io::{Read, Write};

use crate::error::{FleetError, Resultado};

/// Tamano maximo de una trama: acota la memoria que un par puede forzar a
/// reservar. Un mensaje de flota legitimo es de cientos de bytes.
pub const MAX_TRAMA: usize = 4 * 1024 * 1024;

/// Bandera de compresion «identidad» (sin comprimir), como en gRPC.
const SIN_COMPRIMIR: u8 = 0;

/// Estado de una respuesta: 0 = OK, como el `grpc-status` `OK`.
pub const ESTADO_OK: u8 = 0;
/// Estado: la peticion fue rechazada por el plano de control.
pub const ESTADO_RECHAZADO: u8 = 1;
/// Estado: el metodo no existe.
pub const ESTADO_METODO_DESCONOCIDO: u8 = 12;
/// Estado: error interno del plano de control.
pub const ESTADO_INTERNO: u8 = 13;

/// Metodos del servicio `AegisFleet`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Metodo {
    /// Enrolar el agente en la flota.
    Enrolar,
    /// Emitir un latido.
    Latir,
    /// Reportar un evento de seguridad.
    ReportarEvento,
    /// Entregar un bundle STIX 2.1 de inteligencia.
    ReportarStix,
    /// Entregar el subgrafo de linaje que rodea a una deteccion.
    ReportarGrafo,
    /// Abrir el canal por el que el servidor EMPUJA politica.
    ///
    /// Es el unico metodo que no sigue el patron peticion/respuesta: la
    /// conexion queda abierta y el servidor escribe por ella cuando hay algo
    /// que entregar.
    SuscribirPolitica,
    /// Devolver el resultado de una caceria AegisQL.
    ///
    /// La consulta baja por el canal de suscripcion —ver `EmpujePolitica`— y el
    /// resultado sube por aqui, en una conexion normal de peticion/respuesta.
    /// Separarlos es lo que permite que un endpoint tarde lo que necesite en
    /// responder sin bloquear el canal por el que le llegan las politicas.
    ReportarCaza,
    /// Declarar el estado de motores y del enlace del agente (H-23).
    ///
    /// Un plano de control anterior no lo conoce y contesta «metodo
    /// desconocido» sin cerrar la sesion; el agente lo toma como «no guardado».
    ReportarEstado,
}

impl Metodo {
    /// Codigo de cable del metodo.
    pub fn codigo(self) -> u8 {
        match self {
            Metodo::Enrolar => 1,
            Metodo::Latir => 2,
            Metodo::ReportarEvento => 3,
            Metodo::ReportarStix => 4,
            Metodo::ReportarGrafo => 5,
            Metodo::SuscribirPolitica => 6,
            Metodo::ReportarCaza => 7,
            Metodo::ReportarEstado => 8,
        }
    }

    /// Metodo a partir de su codigo de cable.
    pub fn de_codigo(c: u8) -> Option<Metodo> {
        match c {
            1 => Some(Metodo::Enrolar),
            2 => Some(Metodo::Latir),
            3 => Some(Metodo::ReportarEvento),
            4 => Some(Metodo::ReportarStix),
            5 => Some(Metodo::ReportarGrafo),
            6 => Some(Metodo::SuscribirPolitica),
            7 => Some(Metodo::ReportarCaza),
            8 => Some(Metodo::ReportarEstado),
            _ => None,
        }
    }
}

/// Escribe una trama: un byte de enrutado y el mensaje enmarcado como gRPC.
pub fn escribir_marco<W: Write>(w: &mut W, enrutado: u8, payload: &[u8]) -> Resultado<()> {
    if payload.len() > MAX_TRAMA {
        return Err(FleetError::TramaDemasiadoGrande {
            tam: payload.len(),
            max: MAX_TRAMA,
        });
    }
    let mut cabecera = [0u8; 6];
    cabecera[0] = enrutado;
    cabecera[1] = SIN_COMPRIMIR;
    cabecera[2..6].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    w.write_all(&cabecera).map_err(|e| FleetError::Red {
        op: "escribir cabecera",
        source: e,
    })?;
    w.write_all(payload).map_err(|e| FleetError::Red {
        op: "escribir payload",
        source: e,
    })?;
    w.flush().map_err(|e| FleetError::Red {
        op: "flush",
        source: e,
    })?;
    Ok(())
}

/// Lee una trama: devuelve el byte de enrutado y el mensaje.
pub fn leer_marco<R: Read>(r: &mut R) -> Resultado<(u8, Vec<u8>)> {
    let mut cabecera = [0u8; 6];
    r.read_exact(&mut cabecera).map_err(|e| FleetError::Red {
        op: "leer cabecera",
        source: e,
    })?;
    let enrutado = cabecera[0];
    // cabecera[1] es la bandera de compresion; solo se admite «identidad».
    if cabecera[1] != SIN_COMPRIMIR {
        return Err(FleetError::Protocolo(format!(
            "compresion no soportada: {}",
            cabecera[1]
        )));
    }
    let len = u32::from_be_bytes([cabecera[2], cabecera[3], cabecera[4], cabecera[5]]) as usize;
    if len > MAX_TRAMA {
        return Err(FleetError::TramaDemasiadoGrande {
            tam: len,
            max: MAX_TRAMA,
        });
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).map_err(|e| FleetError::Red {
        op: "leer payload",
        source: e,
    })?;
    Ok((enrutado, payload))
}

/// Realiza una llamada unaria: escribe la peticion, lee la respuesta.
///
/// Devuelve el cuerpo de la respuesta si el estado es OK; si no, un error con el
/// codigo de estado, como haria un cliente gRPC ante un `grpc-status` != OK.
pub fn llamada_unaria<S: Read + Write>(
    stream: &mut S,
    metodo: Metodo,
    peticion: &[u8],
) -> Resultado<Vec<u8>> {
    escribir_marco(stream, metodo.codigo(), peticion)?;
    let (estado, cuerpo) = leer_marco(stream)?;
    if estado == ESTADO_OK {
        Ok(cuerpo)
    } else if estado == ESTADO_RECHAZADO {
        Err(FleetError::NoEnrolado(
            String::from_utf8_lossy(&cuerpo).to_string(),
        ))
    } else {
        Err(FleetError::Tls {
            op: "llamada unaria",
            detail: format!("el plano de control respondio estado {estado}"),
        })
    }
}
