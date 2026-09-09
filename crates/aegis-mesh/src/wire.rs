//! Formato de red de la malla.
//!
//! # Un datagrama, sin fragmentar
//!
//! Cada mensaje cabe en UN datagrama de menos de 1200 bytes. No es una
//! limitacion, es el diseno: un mensaje fragmentado por IP se pierde entero si
//! se pierde un fragmento, y reensamblar es una superficie de ataque clasica.
//! Una vacuna es un hash y cuatro campos; si algun dia no cupiera, la respuesta
//! es enviar el indicador y que el receptor lo pida completo por el canal de
//! sincronizacion, no fragmentar aqui.
//!
//! # La cabecera va autenticada, no cifrada
//!
//! Los campos que el receptor necesita ANTES de descifrar —version, tipo, quien
//! lo envia, el nonce— van en claro pero entran como datos asociados del AEAD.
//! Cifrarlos obligaria a descifrar para saber con que nonce descifrar, que es
//! circular; dejarlos fuera del AEAD permitiria a un atacante cambiar el
//! remitente de un mensaje valido y hacer que la flota atribuya una vacuna a
//! otro equipo.

/// Marca del protocolo: "AGMS" en little-endian.
pub const MAGIC: u32 = 0x534D_4741;

/// Version del formato.
pub const VERSION: u8 = 1;

/// Tamano de la cabecera en claro.
pub const HEADER_LEN: usize = 36;

/// Tamano maximo de un datagrama.
///
/// 1200 bytes es lo que cabe sin fragmentar en cualquier red que soporte los
/// 1280 minimos de IPv6, dejando sitio para las cabeceras.
pub const MAX_DATAGRAM: usize = 1200;

/// Tipo de mensaje.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgType {
    /// Presencia: "estoy aqui y hablo esta version".
    Announce,
    /// Vacuna.
    Vaccine,
}

impl MsgType {
    /// Byte del formato.
    pub fn tag(self) -> u8 {
        match self {
            MsgType::Announce => 1,
            MsgType::Vaccine => 2,
        }
    }

    /// Recupera el tipo de su byte.
    pub fn from_tag(t: u8) -> Option<MsgType> {
        match t {
            1 => Some(MsgType::Announce),
            2 => Some(MsgType::Vaccine),
            _ => None,
        }
    }
}

/// Cabecera en claro de un datagrama.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Version del formato.
    pub version: u8,
    /// Tipo de mensaje.
    pub msg_type: MsgType,
    /// Identificador de sesion del emisor, aleatorio en cada arranque.
    ///
    /// Junto con el contador forma el nonce. Es aleatorio y no persistente a
    /// proposito: un contador que se reiniciara al arrancar el agente repetiria
    /// nonces con la misma clave, y repetir un nonce en AES-GCM no filtra "un
    /// poco", filtra la clave de autenticacion del flujo entero.
    pub session: [u8; 8],
    /// Contador dentro de la sesion.
    pub counter: u32,
    /// Identidad del nodo emisor.
    pub node: [u8; 16],
}

impl Header {
    /// Nonce de 12 bytes: sesion mas contador.
    pub fn nonce(&self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&self.session);
        n[8..].copy_from_slice(&self.counter.to_le_bytes());
        n
    }

    /// Serializa la cabecera.
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        b[4] = self.version;
        b[5] = self.msg_type.tag();
        // b[6..8] reservado, a cero.
        b[8..16].copy_from_slice(&self.session);
        b[16..20].copy_from_slice(&self.counter.to_le_bytes());
        b[20..36].copy_from_slice(&self.node);
        b
    }

    /// Analiza la cabecera de un datagrama.
    pub fn decode(datos: &[u8]) -> Option<Header> {
        if datos.len() < HEADER_LEN {
            return None;
        }
        if u32::from_le_bytes(datos[0..4].try_into().ok()?) != MAGIC {
            return None;
        }
        let mut session = [0u8; 8];
        session.copy_from_slice(&datos[8..16]);
        let mut node = [0u8; 16];
        node.copy_from_slice(&datos[20..36]);
        Some(Header {
            version: datos[4],
            msg_type: MsgType::from_tag(datos[5])?,
            session,
            counter: u32::from_le_bytes(datos[16..20].try_into().ok()?),
            node,
        })
    }
}

/// Escribe un entero de 16 bits.
fn put_u16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_le_bytes());
}

/// Serializa el cuerpo de una vacuna.
///
/// Longitudes ANTES que datos, y de tamano fijo: es lo que permite validar que
/// el mensaje esta completo sin haber leido todavia el contenido, en vez de
/// descubrirlo a mitad con un indice fuera de rango.
pub fn encode_vaccine(v: &crate::vaccine::Vaccine) -> Vec<u8> {
    let tecnicas = v.techniques.join(",");
    let mut b = Vec::with_capacity(16 + v.ioc.value.len() + tecnicas.len());
    b.push(v.ioc.kind.tag());
    b.push(v.severity.tag());
    b.push(v.hops);
    b.push(0); // reservado
    b.extend_from_slice(&v.issued_at.to_le_bytes());
    put_u16(&mut b, v.ioc.value.len() as u16);
    put_u16(&mut b, tecnicas.len() as u16);
    b.extend_from_slice(v.ioc.value.as_bytes());
    b.extend_from_slice(tecnicas.as_bytes());
    b
}

/// Analiza el cuerpo de una vacuna.
///
/// Devuelve `None` ante cualquier incoherencia. Todo lo que llega aqui ya paso
/// el AEAD, asi que un cuerpo mal formado significa que un agente legitimo tiene
/// un defecto o que la clave se filtro; en ambos casos, descartar.
pub fn decode_vaccine(b: &[u8]) -> Option<crate::vaccine::Vaccine> {
    use crate::vaccine::{Severity, Vaccine};
    use aegis_sync::ioc::{Ioc, IocKind};

    if b.len() < 16 {
        return None;
    }
    let kind = IocKind::from_tag(b[0])?;
    let severity = Severity::from_tag(b[1])?;
    let hops = b[2];
    let issued_at = u64::from_le_bytes(b[4..12].try_into().ok()?);
    let len_valor = u16::from_le_bytes(b[12..14].try_into().ok()?) as usize;
    let len_tec = u16::from_le_bytes(b[14..16].try_into().ok()?) as usize;

    // La comprobacion se hace con suma comprobada: `16 + len_valor + len_tec`
    // puede desbordar con longitudes elegidas por un atacante y dar un total
    // pequeno que pase la validacion.
    let total = 16usize.checked_add(len_valor)?.checked_add(len_tec)?;
    if b.len() < total {
        return None;
    }
    let valor = std::str::from_utf8(&b[16..16 + len_valor]).ok()?;
    let tec = std::str::from_utf8(&b[16 + len_valor..total]).ok()?;

    Some(Vaccine {
        ioc: Ioc::new(kind, valor),
        severity,
        issued_at,
        techniques: if tec.is_empty() {
            Vec::new()
        } else {
            tec.split(',').map(str::to_owned).collect()
        },
        hops,
    })
}
