//! Codificacion del protocolo de reputacion.
//!
//! # Formato
//!
//! Peticion: `GET /v1/rep/<prefijo>` con `Accept: text/plain`. El prefijo son
//! cinco caracteres hexadecimales y es **lo unico que sale del equipo**.
//!
//! Respuesta: una linea por candidato del cubo,
//!
//! ```text
//! <sufijo 59 hex>:<veredicto>:<confianza>:<antiguedad_s>:<prevalencia>
//! ```
//!
//! # Por que texto y no un formato binario
//!
//! Porque la respuesta se comprime en el transporte y el ahorro binario es
//! marginal frente a un cubo de mil entradas, mientras que un formato
//! inspeccionable a ojo permite auditar que el cliente no esta enviando de mas.
//! En un mecanismo cuyo unico valor es una promesa de privacidad, poder
//! comprobar la promesa con `curl` vale mas que unos kilobytes.
//!
//! # Robustez
//!
//! El analizador **descarta las lineas que no entiende en vez de fallar**. Un
//! servidor mas nuevo que anada un campo dejaria inservible a un cliente
//! estricto, y un cliente sin reputacion es un cliente que consulta a ciegas.
//! Lo que no hace es aceptar una linea a medias: o la entiende entera o la
//! tira.

use crate::hash::{Digest256, Prefix, Suffix, SUFIJO_LEN};
use crate::verdict::{Record, Reputation};

/// Una entrada del cubo devuelto por el servidor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BucketEntry {
    /// Sufijo del hash. Sirve para comparar localmente.
    pub suffix: Suffix,
    /// Registro de reputacion.
    pub record: Record,
}

/// Numero maximo de entradas que se aceptan en un cubo.
///
/// Un cubo de 20 bits sobre mil millones de hashes ronda las 1.024 entradas.
/// El limite esta en 64 veces esa cifra: por encima, un servidor hostil o
/// averiado podria agotar la memoria del agente con una sola respuesta.
pub const ENTRADAS_MAX: usize = 65_536;

/// Construye la ruta de consulta para un prefijo.
pub fn request_path(p: Prefix) -> String {
    format!("/v1/rep/{p}")
}

/// Analiza la respuesta del servidor para un prefijo.
///
/// Devuelve `(entradas, lineas descartadas)`. Las descartadas se cuentan para
/// poder detectar una incompatibilidad de version en vez de sufrirla en
/// silencio.
pub fn parse_bucket(cuerpo: &str) -> (Vec<BucketEntry>, usize) {
    let mut salida = Vec::new();
    let mut descartadas = 0usize;

    for linea in cuerpo.lines() {
        let l = linea.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        if salida.len() >= ENTRADAS_MAX {
            descartadas += 1;
            continue;
        }
        match parse_line(l) {
            Some(e) => salida.push(e),
            None => descartadas += 1,
        }
    }
    (salida, descartadas)
}

fn parse_line(l: &str) -> Option<BucketEntry> {
    let mut it = l.split(':');
    let suffix = Suffix::parse(it.next()?).ok()?;
    let rep = {
        let v = it.next()?;
        let b = v.as_bytes();
        if b.len() != 1 {
            return None;
        }
        Reputation::from_code(b[0])?
    };
    let confidence: u8 = it.next()?.parse().ok()?;
    if confidence > 100 {
        return None;
    }
    let first_seen_age_s: u64 = it.next()?.parse().ok()?;
    let prevalence: u32 = it.next()?.parse().ok()?;
    // Campos de mas: un servidor mas nuevo. Se ignoran, no se rechaza la linea.
    Some(BucketEntry {
        suffix,
        record: Record {
            reputation: rep,
            confidence,
            first_seen_age_s,
            prevalence,
        },
    })
}

/// Busca la huella completa dentro del cubo devuelto.
///
/// **Esta es la comparacion que no sale del equipo.** El servidor entrego mil
/// candidatos sin saber cual interesaba; aqui se elige, en memoria del agente.
///
/// Devuelve el registro de "desconocido" si no esta, que es informacion y no
/// ausencia de informacion: un fichero que no esta en un corpus de mil millones
/// tiene el perfil del malware dirigido.
pub fn resolve(d: Digest256, entradas: &[BucketEntry]) -> Record {
    let propio = d.suffix();
    for e in entradas {
        if e.suffix == propio {
            return e.record;
        }
    }
    Record::unknown()
}

/// Serializa un cubo. La usa el servidor de pruebas y sirve de referencia
/// ejecutable del formato.
pub fn render_bucket(entradas: &[BucketEntry]) -> String {
    let mut s = String::with_capacity(entradas.len() * (SUFIJO_LEN + 16));
    for e in entradas {
        s.push_str(e.suffix.as_str());
        s.push(':');
        s.push(e.record.reputation.code() as char);
        s.push(':');
        s.push_str(&e.record.confidence.to_string());
        s.push(':');
        s.push_str(&e.record.first_seen_age_s.to_string());
        s.push(':');
        s.push_str(&e.record.prevalence.to_string());
        s.push('\n');
    }
    s
}
