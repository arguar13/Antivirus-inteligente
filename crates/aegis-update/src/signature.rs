//! Verificacion de firmas Ed25519 de los artefactos de actualizacion.
//!
//! # Por que se firma TODO lo que se descarga
//!
//! Un motor de actualizacion es una via directa para ejecutar codigo del
//! atacante con los permisos del defensor: si el agente descarga y aplica un
//! binario, una regla YARA o un modelo ONNX que alguien pudo sustituir en
//! transito o en el servidor, el atacante ya no necesita evadir el EDR, lo pilota.
//!
//! La defensa es que **nada se aplica sin una firma valida**. El servidor de
//! actualizaciones firma cada artefacto con una clave privada Ed25519 que solo
//! el tiene; el agente lleva la clave PUBLICA correspondiente y verifica la
//! firma antes de tocar nada. Un artefacto manipulado, o firmado con otra clave,
//! no verifica y no se aplica.
//!
//! Ed25519 y no RSA: firmas y claves pequenas, verificacion rapida y sin los
//! parametros que hay que elegir bien en RSA (tamano, relleno) y que son una
//! fuente habitual de fallos de implementacion.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// Error de verificacion de firma.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    /// La clave publica no tiene 32 bytes o no es un punto valido.
    #[error("clave publica invalida")]
    BadPublicKey,
    /// La firma no tiene 64 bytes.
    #[error("firma de longitud invalida: {0}")]
    BadSignatureLength(usize),
    /// La firma no verifica contra la clave y el contenido.
    #[error("firma invalida: el artefacto fue manipulado o firmado con otra clave")]
    Invalid,
}

/// Clave publica de verificacion de actualizaciones.
#[derive(Debug, Clone)]
pub struct UpdateKey {
    key: VerifyingKey,
}

impl UpdateKey {
    /// Construye la clave a partir de sus 32 bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<UpdateKey, SignatureError> {
        VerifyingKey::from_bytes(bytes)
            .map(|key| UpdateKey { key })
            .map_err(|_| SignatureError::BadPublicKey)
    }

    /// Construye la clave desde una cadena hexadecimal de 64 caracteres.
    pub fn from_hex(s: &str) -> Result<UpdateKey, SignatureError> {
        let bytes = hex32(s).ok_or(SignatureError::BadPublicKey)?;
        UpdateKey::from_bytes(&bytes)
    }

    /// Verifica que `signature` es una firma valida de `bytes` con esta clave.
    pub fn verify(&self, bytes: &[u8], signature: &[u8]) -> Result<(), SignatureError> {
        if signature.len() != 64 {
            return Err(SignatureError::BadSignatureLength(signature.len()));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(signature);
        let sig = Signature::from_bytes(&arr);
        self.key
            .verify(bytes, &sig)
            .map_err(|_| SignatureError::Invalid)
    }

    /// Los 32 bytes de la clave.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.key.to_bytes()
    }
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let b = s.as_bytes();
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = (nib(b[2 * i])? << 4) | nib(b[2 * i + 1])?;
    }
    Some(out)
}

fn nib(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}
