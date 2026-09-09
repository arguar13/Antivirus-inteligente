//! Cifrado por fila del cuerpo de los eventos.
//!
//! Cada cuerpo se cifra con AES-256-GCM. Dos propiedades sostienen la seguridad
//! del esquema, y las dos son responsabilidad de quien llama (el `store`), no de
//! este modulo:
//!
//! 1. **El nonce no se repite jamas bajo la misma clave.** GCM se rompe por
//!    completo si un par (clave, nonce) se reutiliza: se filtra el XOR de los
//!    dos textos y se puede falsificar la autenticacion. El `store` construye el
//!    nonce como `id ‖ segmento`, ambos monotonos, de modo que ni dentro de un
//!    fichero ni entre ficheros rotados se repite.
//! 2. **El texto cifrado esta ligado a su fila.** El dato autenticado adicional
//!    (AAD) incluye id, instante, tipo y actor. Sin esa ligadura, un atacante
//!    con acceso al fichero podria intercambiar los cuerpos de dos filas sin
//!    romper ningun tag GCM, porque cada tag solo protege su propio texto. Con
//!    la AAD, mover un cuerpo a otra fila invalida la autenticacion.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};

/// Error de cifrado o descifrado de una fila.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CryptoError {
    /// El cuerpo cifrado no autentica: clave, nonce o AAD equivocados, o fila
    /// manipulada.
    #[error("el cuerpo de auditoria no autentica (fila {id})")]
    Authentication {
        /// Fila implicada.
        id: i64,
    },
    /// El cuerpo descifrado no era UTF-8.
    #[error("el cuerpo descifrado no es UTF-8 (fila {id})")]
    NotUtf8 {
        /// Fila implicada.
        id: i64,
    },
}

/// Identidad de una fila, lo que la liga a su texto cifrado.
#[derive(Debug, Clone, Copy)]
pub struct RowId<'a> {
    /// Identificador de fila.
    pub id: i64,
    /// Secuencia del segmento (fichero) en el que vive.
    pub segment: u32,
    /// Instante del evento.
    pub ts_ns: u64,
    /// Actor implicado.
    pub actor: u64,
    /// Tipo del evento.
    pub kind: &'a str,
}

impl RowId<'_> {
    /// Nonce de 12 bytes, unico por fila y por segmento.
    ///
    /// `id` es unico dentro de un segmento y `segment` es unico entre
    /// segmentos, asi que el par no se repite en toda la vida del despliegue
    /// (hasta 2^32 rotaciones, que a 100 MB por fichero son 400 PB de log).
    pub fn nonce(&self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&(self.id as u64).to_le_bytes());
        n[8..].copy_from_slice(&self.segment.to_le_bytes());
        n
    }

    /// Dato autenticado que ata el texto cifrado a esta fila.
    pub fn aad(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(8 + 4 + 8 + 8 + 4 + self.kind.len());
        v.extend_from_slice(&self.id.to_le_bytes());
        v.extend_from_slice(&self.segment.to_le_bytes());
        v.extend_from_slice(&self.ts_ns.to_le_bytes());
        v.extend_from_slice(&self.actor.to_le_bytes());
        v.extend_from_slice(&(self.kind.len() as u32).to_le_bytes());
        v.extend_from_slice(self.kind.as_bytes());
        v
    }
}

/// Cifra un cuerpo para una fila concreta. Devuelve el texto cifrado con tag.
pub fn encrypt_body(key: &[u8; 32], row: RowId<'_>, detail: &str) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = row.nonce();
    cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: detail.as_bytes(),
                aad: &row.aad(),
            },
        )
        .expect("el cifrado GCM no falla con clave y nonce validos")
}

/// Descifra el cuerpo de una fila.
pub fn decrypt_body(
    key: &[u8; 32],
    row: RowId<'_>,
    ciphertext: &[u8],
) -> Result<String, CryptoError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = row.nonce();
    let claro = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &row.aad(),
            },
        )
        .map_err(|_| CryptoError::Authentication { id: row.id })?;
    String::from_utf8(claro).map_err(|_| CryptoError::NotUtf8 { id: row.id })
}
