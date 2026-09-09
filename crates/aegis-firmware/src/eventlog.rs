//! Analizador del event log de arranque medido (`binary_bios_measurements`).
//!
//! # Que es y por que importa
//!
//! El firmware, mientras arranca, va MIDIENDO cada componente antes de
//! ejecutarlo —el propio firmware, la tabla de particiones, el gestor de
//! arranque, sus variables de configuracion— y extendiendo cada medida en un
//! PCR del TPM. El resultado es una cadena de la que no se puede salir:
//! cambiar cualquier eslabon cambia el PCR final, y el PCR final no se puede
//! falsificar sin la clave del TPM. Un bootkit tipo BlackLotus altera el gestor
//! de arranque, y esa alteracion queda en el log y en el PCR.
//!
//! Este modulo lee ese log. El log por si solo es texto autoinformado y un
//! atacante podria reescribirlo; su valor esta en poder REPRODUCIRLO (modulo
//! [`crate::pcr`]) y comprobar que el PCR recalculado desde el log coincide con
//! el que el TPM tiene de verdad. Si no coinciden, el log miente.
//!
//! # Los dos formatos
//!
//! - **Heredado** (`TCG_PCClientPCREventStruct`): un solo digest SHA-1 por
//!   evento. Es lo que emitian las plataformas BIOS antiguas.
//! - **Crypto-agil** (`TCG_PCR_EVENT2`): varios digests por evento, uno por
//!   banco de PCR activo. Es el formato UEFI moderno, y el que trae SHA-256.
//!
//! El primer registro es SIEMPRE de formato heredado y de tipo `EV_NO_ACTION`;
//! su contenido es un `TCG_EfiSpecIdEvent` que declara si el resto del log es
//! crypto-agil y que bancos lleva. Analizar el resto con el formato equivocado
//! produce basura que parece valida: por eso el primer registro se analiza
//! aparte y decide como se lee todo lo demas.
//!
//! # Todo es little-endian
//!
//! El event log es little-endian de principio a fin. Lo contrario del protocolo
//! del propio TPM, que es big-endian (modulo [`crate::tpm`]). Usar una sola
//! convencion para los dos produce numeros que parecen razonables y no lo son,
//! y es la trampa mas cara de todo el firmware.

use std::collections::BTreeMap;

use crate::tcg::{EventType, HashAlg, SPEC_ID_SIGNATURE};

/// Un digest de un evento, con su banco.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventDigest {
    /// Algoritmo del banco.
    pub alg: HashAlg,
    /// Bytes del digest, de longitud [`HashAlg::digest_len`].
    pub digest: Vec<u8>,
}

/// Un registro del event log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEvent {
    /// PCR que este evento extiende.
    pub pcr: u32,
    /// Tipo de evento.
    pub event_type: EventType,
    /// Digests, uno por banco (uno solo en el formato heredado).
    pub digests: Vec<EventDigest>,
    /// Datos del evento, sin interpretar.
    pub data: Vec<u8>,
}

impl LogEvent {
    /// Digest de un banco concreto, si el evento lo lleva.
    pub fn digest(&self, alg: HashAlg) -> Option<&[u8]> {
        self.digests
            .iter()
            .find(|d| d.alg == alg)
            .map(|d| d.digest.as_slice())
    }
}

/// El event log ya analizado.
#[derive(Debug, Clone, Default)]
pub struct EventLog {
    /// Registros en orden de aparicion, que es el orden en que se extendieron.
    pub events: Vec<LogEvent>,
    /// Bancos que declara el evento de especificacion, si el log es crypto-agil.
    pub banks: Vec<HashAlg>,
    /// Cierto si el log usa el formato crypto-agil.
    pub crypto_agile: bool,
}

/// Error al analizar el event log.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LogError {
    /// El log termina en mitad de un registro.
    #[error("el event log esta truncado en el offset {0}")]
    Truncated(usize),
    /// Un campo declara un tamano imposible.
    #[error("tamano invalido en el offset {offset}: {detail}")]
    BadSize {
        /// Offset del campo.
        offset: usize,
        /// Motivo.
        detail: &'static str,
    },
    /// El evento de especificacion es incoherente.
    #[error("el evento de especificacion del log es invalido: {0}")]
    BadSpecId(&'static str),
}

/// Lector de bytes little-endian con comprobacion de limites.
///
/// Cada lectura comprueba que hay bytes suficientes ANTES de leer. Es lo que
/// separa un analizador robusto de uno que desborda: el event log es entrada
/// influida por el firmware y, tras un compromiso, por el atacante.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Cursor<'a> {
        Cursor { buf, pos: 0 }
    }

    fn fin(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn u8(&mut self) -> Result<u8, LogError> {
        let b = *self
            .buf
            .get(self.pos)
            .ok_or(LogError::Truncated(self.pos))?;
        self.pos += 1;
        Ok(b)
    }

    fn u16(&mut self) -> Result<u16, LogError> {
        let s = self
            .buf
            .get(self.pos..self.pos + 2)
            .ok_or(LogError::Truncated(self.pos))?;
        self.pos += 2;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }

    fn u32(&mut self) -> Result<u32, LogError> {
        let s = self
            .buf
            .get(self.pos..self.pos + 4)
            .ok_or(LogError::Truncated(self.pos))?;
        self.pos += 4;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn bytes(&mut self, n: usize) -> Result<Vec<u8>, LogError> {
        let s = self
            .buf
            .get(self.pos..self.pos + n)
            .ok_or(LogError::Truncated(self.pos))?;
        self.pos += n;
        Ok(s.to_vec())
    }
}

/// Longitud maxima razonable de los datos de un evento.
///
/// Un `EventSize` mayor es basura o un intento de que el analizador reserve
/// gigabytes: se rechaza. 16 MiB cubre con enormisima holgura cualquier evento
/// real, que rara vez pasa de unos kilobytes.
const MAX_EVENT_DATA: u32 = 16 * 1024 * 1024;

/// Bancos declarados por el evento de especificacion: algoritmo y tamano.
type SpecBanks = Vec<(HashAlg, usize)>;

/// Analiza el event log completo.
pub fn parse(buf: &[u8]) -> Result<EventLog, LogError> {
    if buf.is_empty() {
        return Ok(EventLog::default());
    }
    let mut cur = Cursor::new(buf);

    // El primer registro es SIEMPRE heredado: PCRIndex, EventType, un digest
    // SHA-1 de 20 bytes, EventSize y los datos. Si su tipo es EV_NO_ACTION y sus
    // datos empiezan por la firma de especificacion, el resto es crypto-agil.
    let (primero, spec) = parse_primero(&mut cur)?;

    let mut log = EventLog {
        events: vec![primero],
        banks: Vec::new(),
        crypto_agile: false,
    };

    if let Some(spec) = spec {
        log.crypto_agile = true;
        log.banks = spec.iter().map(|(a, _)| *a).collect();
        let tamanos: BTreeMap<HashAlg, usize> = spec.into_iter().collect();
        while !cur.fin() {
            log.events.push(parse_evento2(&mut cur, &tamanos)?);
        }
    } else {
        // Log heredado entero: todos los registros son SHA-1.
        log.banks = vec![HashAlg::Sha1];
        while !cur.fin() {
            log.events.push(parse_legacy(&mut cur)?);
        }
    }

    Ok(log)
}

/// Analiza el primer registro y, si procede, el evento de especificacion.
fn parse_primero(cur: &mut Cursor) -> Result<(LogEvent, Option<SpecBanks>), LogError> {
    let pcr = cur.u32()?;
    let event_type = EventType::from_u32(cur.u32()?);
    let digest = cur.bytes(HashAlg::Sha1.digest_len())?;
    let event_size = cur.u32()?;
    if event_size > MAX_EVENT_DATA {
        return Err(LogError::BadSize {
            offset: cur.pos,
            detail: "EventSize del primer registro desmesurado",
        });
    }
    let data = cur.bytes(event_size as usize)?;

    let evento = LogEvent {
        pcr,
        event_type,
        digests: vec![EventDigest {
            alg: HashAlg::Sha1,
            digest,
        }],
        data: data.clone(),
    };

    // ¿Es el evento de especificacion crypto-agil?
    let spec = if event_type == EventType::NoAction && data.starts_with(SPEC_ID_SIGNATURE) {
        Some(parse_spec_id(&data)?)
    } else {
        None
    };
    Ok((evento, spec))
}

/// Analiza el `TCG_EfiSpecIdEvent` para saber que bancos lleva el log.
///
/// Layout tras la firma de 16 bytes: `platformClass` (u32), `specVersionMinor`
/// (u8), `specVersionMajor` (u8), `specErrata` (u8), `uintnSize` (u8),
/// `numberOfAlgorithms` (u32), y luego `numberOfAlgorithms` pares
/// `(algorithmId: u16, digestSize: u16)`.
fn parse_spec_id(data: &[u8]) -> Result<SpecBanks, LogError> {
    let mut c = Cursor::new(data);
    // firma(16) + platformClass(4) + 4 x u8 = 24 bytes de cabecera.
    let _ = c.bytes(SPEC_ID_SIGNATURE.len());
    let _platform_class = c
        .u32()
        .map_err(|_| LogError::BadSpecId("sin platformClass"))?;
    let _minor = c
        .u8()
        .map_err(|_| LogError::BadSpecId("sin specVersionMinor"))?;
    let _major = c
        .u8()
        .map_err(|_| LogError::BadSpecId("sin specVersionMajor"))?;
    let _errata = c.u8().map_err(|_| LogError::BadSpecId("sin specErrata"))?;
    let _uintn = c.u8().map_err(|_| LogError::BadSpecId("sin uintnSize"))?;
    let n = c
        .u32()
        .map_err(|_| LogError::BadSpecId("sin numberOfAlgorithms"))?;
    if n == 0 || n > 16 {
        return Err(LogError::BadSpecId("numberOfAlgorithms fuera de rango"));
    }
    let mut bancos = Vec::new();
    for _ in 0..n {
        let alg_id = c
            .u16()
            .map_err(|_| LogError::BadSpecId("sin algorithmId"))?;
        let size = c.u16().map_err(|_| LogError::BadSpecId("sin digestSize"))? as usize;
        if let Some(alg) = HashAlg::from_id(alg_id) {
            // El tamano declarado tiene que cuadrar con el del algoritmo, o el
            // log es incoherente y no se puede reproducir con garantia.
            if alg.digest_len() != size {
                return Err(LogError::BadSpecId("digestSize no cuadra con el algoritmo"));
            }
            bancos.push((alg, size));
        }
        // Un algoritmo desconocido se ignora: no se sabe su tamano, y el
        // analisis de los eventos siguientes solo mira los bancos conocidos.
    }
    if bancos.is_empty() {
        return Err(LogError::BadSpecId("ningun banco conocido"));
    }
    Ok(bancos)
}

/// Analiza un registro heredado (`TCG_PCClientPCREventStruct`).
fn parse_legacy(cur: &mut Cursor) -> Result<LogEvent, LogError> {
    let pcr = cur.u32()?;
    let event_type = EventType::from_u32(cur.u32()?);
    let digest = cur.bytes(HashAlg::Sha1.digest_len())?;
    let event_size = cur.u32()?;
    if event_size > MAX_EVENT_DATA {
        return Err(LogError::BadSize {
            offset: cur.pos,
            detail: "EventSize desmesurado",
        });
    }
    let data = cur.bytes(event_size as usize)?;
    Ok(LogEvent {
        pcr,
        event_type,
        digests: vec![EventDigest {
            alg: HashAlg::Sha1,
            digest,
        }],
        data,
    })
}

/// Analiza un registro crypto-agil (`TCG_PCR_EVENT2`).
///
/// Layout: `PCRIndex` (u32), `EventType` (u32), `Digests` (`TPML_DIGEST_VALUES`:
/// `count` u32 y luego `count` pares `(algorithmId u16, digest[size])`),
/// `EventSize` (u32), `Event[EventSize]`.
fn parse_evento2(
    cur: &mut Cursor,
    tamanos: &BTreeMap<HashAlg, usize>,
) -> Result<LogEvent, LogError> {
    let pcr = cur.u32()?;
    let event_type = EventType::from_u32(cur.u32()?);
    let count = cur.u32()?;
    if count as usize > tamanos.len().max(16) {
        return Err(LogError::BadSize {
            offset: cur.pos,
            detail: "count de digests mayor que los bancos declarados",
        });
    }

    let mut digests = Vec::new();
    for _ in 0..count {
        let alg_id = cur.u16()?;
        let alg = HashAlg::from_id(alg_id).ok_or(LogError::BadSize {
            offset: cur.pos,
            detail: "algoritmo de digest desconocido en un TCG_PCR_EVENT2",
        })?;
        // El tamano se toma del evento de especificacion, no de una tabla
        // fija: el log declara sus propios bancos, y fiarse de otra cosa
        // desalinea todo lo que venga despues.
        let size = *tamanos.get(&alg).unwrap_or(&alg.digest_len());
        let digest = cur.bytes(size)?;
        digests.push(EventDigest { alg, digest });
    }

    let event_size = cur.u32()?;
    if event_size > MAX_EVENT_DATA {
        return Err(LogError::BadSize {
            offset: cur.pos,
            detail: "EventSize desmesurado",
        });
    }
    let data = cur.bytes(event_size as usize)?;
    Ok(LogEvent {
        pcr,
        event_type,
        digests,
        data,
    })
}

/// Ruta del event log en un sistema con TPM y firmware que lo entrego.
pub const RUTA_EVENT_LOG: &str = "/sys/kernel/security/tpm0/binary_bios_measurements";

/// Lee y analiza el event log del sistema, si existe.
///
/// El `st_size` de este fichero de securityfs no es fiable: se lee hasta EOF en
/// vez de fiarse del tamano anunciado.
pub fn leer_del_sistema() -> Result<Option<EventLog>, LogError> {
    match std::fs::read(RUTA_EVENT_LOG) {
        Ok(bytes) => parse(&bytes).map(Some),
        // Sin fichero, no hay log: puede que no haya TPM, o que el firmware no
        // entregara ninguno. Distinguirlo es cosa del modulo de deteccion.
        Err(_) => Ok(None),
    }
}
