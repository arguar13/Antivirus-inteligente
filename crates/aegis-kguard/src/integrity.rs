//! Verificacion de integridad del bytecode eBPF con HMAC-SHA256.
//!
//! # Por que hace falta
//!
//! El agente carga en el kernel unos ficheros objeto (`.bpf.o`) compilados a
//! parte. Entre que se compilan y que se cargan hay una ventana: alguien con
//! acceso al disco podria sustituir un `.bpf.o` por otro y conseguir que el
//! propio agente cargue en Ring 0 un programa que no es el suyo. Un programa en
//! el kernel con los permisos del agente es lo mas valioso que puede robar un
//! atacante, y cargarlo con las manos del defensor es la via mas limpia.
//!
//! La defensa es firmar el bytecode. En la compilacion se calcula el
//! HMAC-SHA256 de cada objeto con una clave, y se guarda en un manifiesto. Al
//! cargar, el agente recalcula el HMAC del objeto que va a cargar y lo compara:
//! si no coincide, se niega a cargarlo.
//!
//! # Por que HMAC y no un hash a secas
//!
//! Un SHA-256 pelado detecta la corrupcion accidental, pero no al atacante: si
//! cambia el `.bpf.o`, recalcula el SHA-256 y actualiza el manifiesto, y el
//! agente no nota nada. El HMAC exige una CLAVE que el atacante no tiene: puede
//! cambiar el objeto, pero no puede producir el HMAC valido sin la clave, asi
//! que la comparacion falla. La clave vive en el binario del agente, protegida
//! por el blindaje de `aegis-harden`; es el mismo modelo de amenaza honesto.
//!
//! # Comparacion en tiempo constante
//!
//! La comparacion del HMAC se hace en tiempo constante. Comparar byte a byte y
//! salir al primero que difiere filtra, por el tiempo de respuesta, cuantos
//! bytes iniciales acerto el atacante, y con suficientes intentos eso permite
//! reconstruir el HMAC objetivo byte a byte. En un HMAC ya calculado el margen
//! es teorico, pero la comparacion constante no cuesta nada y cierra la via.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Error de integridad del bytecode.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IntegrityError {
    /// El objeto no esta en el manifiesto: no se firmo, asi que no se carga.
    #[error("el objeto {0} no esta firmado en el manifiesto")]
    NotInManifest(String),
    /// El HMAC calculado no coincide con el firmado: manipulacion o corrupcion.
    #[error("el HMAC de {0} no coincide: el bytecode fue manipulado o corrompido")]
    Mismatch(String),
    /// Una linea del manifiesto no tiene el formato esperado.
    #[error("linea de manifiesto invalida: {0:?}")]
    BadManifestLine(String),
    /// Un digest del manifiesto no tiene 64 caracteres hexadecimales.
    #[error("digest de longitud invalida para {0}")]
    BadDigest(String),
}

/// Calcula el HMAC-SHA256 de unos datos con la clave dada.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    // `new_from_slice` solo falla con claves de longitud invalida, y HMAC
    // acepta cualquier longitud de clave, asi que no puede fallar aqui.
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC acepta cualquier longitud de clave");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Compara dos digests en tiempo constante.
///
/// El tiempo de ejecucion depende solo de la longitud, no del contenido: no
/// hay salida anticipada al primer byte que difiere.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Un manifiesto de firmas: nombre de objeto -> HMAC esperado.
///
/// El formato es una linea por objeto, `nombre  hex64`, la misma convencion que
/// `sha256sum`, para que sea inspeccionable con herramientas corrientes.
#[derive(Debug, Clone, Default)]
pub struct Manifest {
    entradas: Vec<(String, [u8; 32])>,
}

impl Manifest {
    /// Manifiesto vacio.
    pub fn new() -> Manifest {
        Manifest::default()
    }

    /// Registra la firma de un objeto.
    pub fn insert(&mut self, nombre: impl Into<String>, hmac: [u8; 32]) {
        let nombre = nombre.into();
        self.entradas.retain(|(n, _)| n != &nombre);
        self.entradas.push((nombre, hmac));
    }

    /// Firma esperada de un objeto.
    pub fn get(&self, nombre: &str) -> Option<&[u8; 32]> {
        self.entradas
            .iter()
            .find(|(n, _)| n == nombre)
            .map(|(_, h)| h)
    }

    /// Numero de objetos firmados.
    pub fn len(&self) -> usize {
        self.entradas.len()
    }

    /// Indica si esta vacio.
    pub fn is_empty(&self) -> bool {
        self.entradas.is_empty()
    }

    /// Analiza un manifiesto en texto.
    ///
    /// Formato por linea: `nombre<espacios>hex64`. Se ignoran lineas vacias y
    /// las que empiezan por `#`. Una linea malformada es un error, no se salta:
    /// un manifiesto de integridad a medias es peor que ninguno.
    pub fn parse(texto: &str) -> Result<Manifest, IntegrityError> {
        let mut m = Manifest::new();
        for linea in texto.lines() {
            let l = linea.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            let mut it = l.split_whitespace();
            let nombre = it
                .next()
                .ok_or_else(|| IntegrityError::BadManifestLine(l.to_string()))?;
            let hex = it
                .next()
                .ok_or_else(|| IntegrityError::BadManifestLine(l.to_string()))?;
            if it.next().is_some() {
                return Err(IntegrityError::BadManifestLine(l.to_string()));
            }
            let hmac =
                parse_hex32(hex).ok_or_else(|| IntegrityError::BadDigest(nombre.to_string()))?;
            m.insert(nombre, hmac);
        }
        Ok(m)
    }

    /// Serializa el manifiesto en el formato de texto.
    pub fn render(&self) -> String {
        let mut orden = self.entradas.clone();
        orden.sort_by(|a, b| a.0.cmp(&b.0));
        let mut s = String::new();
        s.push_str("# @generated - firmas HMAC-SHA256 del bytecode eBPF de AegisCore\n");
        for (nombre, hmac) in &orden {
            s.push_str(nombre);
            s.push_str("  ");
            for b in hmac {
                s.push_str(&format!("{b:02x}"));
            }
            s.push('\n');
        }
        s
    }

    /// Verifica que el objeto `nombre` con contenido `bytes` coincide con su
    /// firma, usando `key`.
    pub fn verify(&self, nombre: &str, bytes: &[u8], key: &[u8]) -> Result<(), IntegrityError> {
        let esperado = self
            .get(nombre)
            .ok_or_else(|| IntegrityError::NotInManifest(nombre.to_string()))?;
        let calculado = hmac_sha256(key, bytes);
        if constant_time_eq(&calculado, esperado) {
            Ok(())
        } else {
            Err(IntegrityError::Mismatch(nombre.to_string()))
        }
    }
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let b = s.as_bytes();
    for i in 0..32 {
        let hi = hex_nibble(b[2 * i])?;
        let lo = hex_nibble(b[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}
