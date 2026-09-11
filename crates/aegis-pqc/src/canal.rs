//! Capa de establecimiento de clave hibrida estilo HPKE (RFC 9180), construida
//! sobre el KEM `X25519MLKEM768`, para proteger los payloads del canal C2.
//!
//! # Por que POR ENCIMA del mTLS, y no en su lugar
//!
//! El canal agente<->plano de control ya va por mTLS (rustls). Pero rustls hoy
//! negocia X25519, que una computadora cuantica rompera: el trafico grabado hoy
//! se descifra manana ("Harvest Now, Decrypt Later"). Esta capa sella el payload
//! con un secreto derivado del KEM hibrido ANTES de entregarlo al mTLS, de modo
//! que aunque el tunel TLS caiga ante la cuantica, el contenido sigue protegido
//! por ML-KEM. Es defensa en profundidad, y no depende de que rustls traiga un
//! KEM hibrido: la capa es nuestra y se prueba de verdad.
//!
//! # El esquema (HPKE de un disparo)
//!
//! El receptor (el plano de control, o el agente para la respuesta) publica su
//! clave publica hibrida. El emisor encapsula contra ella, deriva una clave
//! AES-256-GCM del secreto de sesion con HKDF, y sella el payload. El
//! [`SobreSellado`] lleva el encapsulado, el nonce y el texto cifrado. El
//! receptor desencapsula, deriva la MISMA clave y abre.
//!
//! AES-256-GCM es el mismo stack simetrico que ya usan la cuarentena y el
//! rollback: Grover solo lo baja a ~128 bits efectivos, que siguen siendo
//! seguros, asi que lo simetrico no se migra.

use crate::kem_hibrido::ENCAPSULADO_LEN;
use crate::kem_hibrido::{ClavePublicaHibrida, EncapsuladoHibrido, ParHibrido, SecretoSesion};
use crate::PqcError;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

/// Longitud del nonce de AES-256-GCM.
pub const NONCE_LEN: usize = 12;
/// Longitud de la etiqueta de autenticacion de AES-256-GCM.
pub const TAG_LEN: usize = 16;

// Dominio de separacion de la derivacion de clave AEAD. Cambiarlo es un cambio
// de suite (agilidad).
const INFO_CLAVE: &[u8] = b"AegisCore/PQC/canal/aes256gcm/clave/v1";

/// Sobre sellado que viaja por el canal: `encapsulado || nonce || ciphertext`.
///
/// El `ciphertext` incluye la etiqueta GCM de 16 bytes.
#[derive(Clone)]
pub struct SobreSellado {
    encapsulado: EncapsuladoHibrido,
    nonce: [u8; NONCE_LEN],
    ct: Vec<u8>,
}

impl SobreSellado {
    /// Serializa el sobre como `encapsulado (1120) || nonce (12) || ciphertext`.
    #[must_use]
    pub fn a_bytes(&self) -> Vec<u8> {
        let enc = self.encapsulado.a_bytes();
        let mut out = Vec::with_capacity(enc.len() + NONCE_LEN + self.ct.len());
        out.extend_from_slice(&enc);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ct);
        out
    }

    /// Reconstruye desde el formato de wire.
    ///
    /// # Errores
    /// [`PqcError::TamanoInvalido`] si faltan bytes para el encapsulado, el nonce
    /// y al menos la etiqueta GCM.
    pub fn desde_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        let minimo = ENCAPSULADO_LEN + NONCE_LEN + TAG_LEN;
        if bytes.len() < minimo {
            return Err(PqcError::TamanoInvalido {
                campo: "sobre sellado",
                esperado: minimo,
                recibido: bytes.len(),
            });
        }
        let encapsulado = EncapsuladoHibrido::desde_bytes(&bytes[..ENCAPSULADO_LEN])?;
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[ENCAPSULADO_LEN..ENCAPSULADO_LEN + NONCE_LEN]);
        let ct = bytes[ENCAPSULADO_LEN + NONCE_LEN..].to_vec();
        Ok(Self {
            encapsulado,
            nonce,
            ct,
        })
    }
}

/// Deriva la clave AES-256-GCM del secreto de sesion con HKDF-SHA256.
fn derivar_clave_aead(ss: &SecretoSesion) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, ss.as_bytes());
    let mut clave = [0u8; 32];
    hk.expand(INFO_CLAVE, &mut clave)
        .expect("32 bytes estan dentro del limite de HKDF-SHA256");
    clave
}

/// Sella `plaintext` hacia el poseedor de `pk`, autenticando los datos asociados
/// `aad` (que no se cifran pero quedan atados a la integridad del sobre).
///
/// Cada llamada genera un encapsulado fresco, asi que la clave AEAD es unica por
/// mensaje y el nonce nunca se reutiliza bajo la misma clave.
///
/// # Errores
/// [`PqcError::Entropia`] si no hay entropia; [`PqcError::MaterialInvalido`] si
/// la clave publica no es valida.
pub fn sellar(
    pk: &ClavePublicaHibrida,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<SobreSellado, PqcError> {
    let (encapsulado, ss) = pk.encapsular_aleatorio()?;
    let mut clave = derivar_clave_aead(&ss);
    let cifrador = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&clave));

    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|_| PqcError::Entropia)?;

    let ct = cifrador
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| PqcError::MaterialInvalido("cifrado AES-GCM fallido"))?;
    clave.zeroize();

    Ok(SobreSellado {
        encapsulado,
        nonce,
        ct,
    })
}

/// Abre un [`SobreSellado`] con el par del receptor, exigiendo los mismos datos
/// asociados `aad` con los que se sello.
///
/// # Errores
/// [`PqcError::AperturaInvalida`] si el AEAD no autentica: sobre manipulado,
/// `aad` distinto, o clave equivocada. No se distingue el motivo a proposito
/// (no dar un oraculo al atacante).
pub fn abrir(par: &ParHibrido, aad: &[u8], sobre: &SobreSellado) -> Result<Vec<u8>, PqcError> {
    let ss = par.desencapsular(&sobre.encapsulado);
    let mut clave = derivar_clave_aead(&ss);
    let cifrador = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&clave));

    let pt = cifrador
        .decrypt(
            Nonce::from_slice(&sobre.nonce),
            Payload {
                msg: &sobre.ct,
                aad,
            },
        )
        .map_err(|_| PqcError::AperturaInvalida);
    clave.zeroize();
    pt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_sellar_abrir() {
        let receptor = ParHibrido::generar_aleatorio().expect("entropia");
        let aad = b"agente-4820/latido";
        let msg = b"telemetria confidencial del endpoint";
        let sobre = sellar(&receptor.publica, aad, msg).expect("sellar");
        let abierto = abrir(&receptor, aad, &sobre).expect("abrir");
        assert_eq!(abierto, msg);
    }

    #[test]
    fn ciphertext_manipulado_no_abre() {
        let receptor = ParHibrido::generar_aleatorio().expect("entropia");
        let mut sobre = sellar(&receptor.publica, b"aad", b"secreto").expect("sellar");
        let n = sobre.ct.len();
        sobre.ct[n - 1] ^= 0x01; // toca la etiqueta GCM
        assert!(matches!(
            abrir(&receptor, b"aad", &sobre),
            Err(PqcError::AperturaInvalida)
        ));
    }

    #[test]
    fn encapsulado_manipulado_no_abre() {
        let receptor = ParHibrido::generar_aleatorio().expect("entropia");
        let sobre = sellar(&receptor.publica, b"aad", b"secreto").expect("sellar");
        // Manipular el encapsulado -> el receptor deriva otra clave -> GCM falla.
        let mut bytes = sobre.a_bytes();
        bytes[0] ^= 0x01;
        let sobre_malo = SobreSellado::desde_bytes(&bytes).expect("tamano");
        assert!(matches!(
            abrir(&receptor, b"aad", &sobre_malo),
            Err(PqcError::AperturaInvalida)
        ));
    }

    #[test]
    fn aad_distinto_no_abre() {
        let receptor = ParHibrido::generar_aleatorio().expect("entropia");
        let sobre = sellar(&receptor.publica, b"aad-correcto", b"secreto").expect("sellar");
        assert!(matches!(
            abrir(&receptor, b"aad-distinto", &sobre),
            Err(PqcError::AperturaInvalida)
        ));
    }

    #[test]
    fn clave_de_otro_receptor_no_abre() {
        let receptor = ParHibrido::generar_aleatorio().expect("entropia");
        let otro = ParHibrido::generar_aleatorio().expect("entropia");
        let sobre = sellar(&receptor.publica, b"aad", b"secreto").expect("sellar");
        assert!(matches!(
            abrir(&otro, b"aad", &sobre),
            Err(PqcError::AperturaInvalida)
        ));
    }

    #[test]
    fn wire_roundtrip() {
        let receptor = ParHibrido::generar_aleatorio().expect("entropia");
        let sobre = sellar(
            &receptor.publica,
            b"aad",
            b"un mensaje mas largo que un bloque AES",
        )
        .expect("sellar");
        let bytes = sobre.a_bytes();
        let sobre2 = SobreSellado::desde_bytes(&bytes).expect("desde_bytes");
        let abierto = abrir(&receptor, b"aad", &sobre2).expect("abrir");
        assert_eq!(abierto, b"un mensaje mas largo que un bloque AES");
    }

    #[test]
    fn dos_sellados_del_mismo_mensaje_difieren() {
        // Confidencialidad: cada sellado usa un encapsulado fresco, asi que el
        // texto cifrado no se repite aunque el mensaje sea identico.
        let receptor = ParHibrido::generar_aleatorio().expect("entropia");
        let a = sellar(&receptor.publica, b"aad", b"mismo mensaje").expect("a");
        let b = sellar(&receptor.publica, b"aad", b"mismo mensaje").expect("b");
        assert_ne!(a.a_bytes(), b.a_bytes());
        // Pero ambos abren al mismo claro.
        assert_eq!(abrir(&receptor, b"aad", &a).unwrap(), b"mismo mensaje");
        assert_eq!(abrir(&receptor, b"aad", &b).unwrap(), b"mismo mensaje");
    }
}
