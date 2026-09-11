//! Identidad del atestador: la clave publica de la AK y su Name.
//!
//! El verificador necesita dos cosas de la clave de atestacion (AK): con que
//! clave comprobar la firma del quote, y como saber que ESA clave es la
//! matriculada y no otra. Lo primero es la clave publica; lo segundo es el
//! *Name* del TPM = `nameAlg || H_nameAlg(publicArea)`, el identificador que ata
//! el quote a una clave concreta.
//!
//! Se parsea el `TPMT_PUBLIC` que emite el TPM. La asuncion —documentada— es que
//! la AK es una clave de FIRMA: su `symmetric` es `TPM_ALG_NULL`. Eso es cierto
//! para toda clave de atestacion; una clave de cifrado no firma quotes.

use crate::codec::{CodecError, Lector};
use aegis_firmware::HashAlg;
use sha2::{Digest, Sha256};

/// `TPM_ALG_RSA`.
const TPM_ALG_RSA: u16 = 0x0001;
/// `TPM_ALG_ECC`.
const TPM_ALG_ECC: u16 = 0x0023;
/// `TPM_ALG_NULL`.
const TPM_ALG_NULL: u16 = 0x0010;

/// La clave publica de una AK, en la forma minima que hace falta para verificar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClavePublicaAk {
    /// RSA: modulo `n` y exponente `e` (big-endian). `e` vacio o cero significa
    /// el 65537 por defecto del TPM.
    Rsa2048 {
        /// Modulo.
        n: Vec<u8>,
        /// Exponente (65537 si va vacio).
        e: Vec<u8>,
    },
    /// ECDSA sobre NIST P-256: coordenadas `x` e `y` sin comprimir.
    EcdsaP256 {
        /// Coordenada X (32 bytes).
        x: Vec<u8>,
        /// Coordenada Y (32 bytes).
        y: Vec<u8>,
    },
    /// Ed25519: los 32 bytes de la clave. No es formato TPM clasico; se soporta
    /// por el patron ya usado en `aegis-update`.
    Ed25519([u8; 32]),
}

/// Un fallo al interpretar la identidad de la AK.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IdentidadError {
    /// El buffer se acabo.
    #[error("codec: {0}")]
    Codec(#[from] CodecError),
    /// El tipo de clave no es RSA ni ECC.
    #[error("tipo de clave no soportado: {0:#06x}")]
    TipoNoSoportado(u16),
    /// El `nameAlg` no es un hash conocido.
    #[error("nameAlg desconocido: {0:#06x}")]
    NameAlgDesconocido(u16),
    /// La curva ECC no es NIST P-256.
    #[error("curva ECC no soportada: {0:#06x}")]
    CurvaNoSoportada(u16),
    /// Se asumio `symmetric = NULL` (clave de firma) y no lo era.
    #[error("la AK no es una clave de firma (symmetric != NULL)")]
    NoEsClaveDeFirma,
}

/// El area publica parseada: la clave y el algoritmo de su Name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AreaPublica {
    /// El algoritmo con el que se computa el Name.
    pub name_alg: HashAlg,
    /// La clave publica.
    pub clave: ClavePublicaAk,
    /// El Name computado: `nameAlg (be) || H_nameAlg(publicArea)`.
    pub name: Vec<u8>,
}

impl AreaPublica {
    /// Parsea un `TPMT_PUBLIC` (el contenido de un `TPM2B_PUBLIC`) y computa el
    /// Name sobre los bytes crudos de ese mismo `publicArea`.
    pub fn parse(public_area: &[u8]) -> Result<AreaPublica, IdentidadError> {
        let mut c = Lector::new(public_area);
        let tipo = c.u16()?;
        let name_alg_id = c.u16()?;
        let name_alg =
            HashAlg::from_id(name_alg_id).ok_or(IdentidadError::NameAlgDesconocido(name_alg_id))?;
        let _object_attributes = c.u32()?;
        let _auth_policy = c.tpm2b()?;

        let clave = match tipo {
            TPM_ALG_RSA => {
                // TPMS_RSA_PARMS
                let symmetric = c.u16()?;
                if symmetric != TPM_ALG_NULL {
                    return Err(IdentidadError::NoEsClaveDeFirma);
                }
                let scheme = c.u16()?;
                if scheme != TPM_ALG_NULL {
                    // scheme lleva un hash asociado.
                    let _hash = c.u16()?;
                }
                let _key_bits = c.u16()?;
                let exponent = c.u32()?;
                // unique: TPM2B_PUBLIC_KEY_RSA (el modulo)
                let n = c.tpm2b()?;
                let e = if exponent == 0 {
                    Vec::new()
                } else {
                    exponent.to_be_bytes().to_vec()
                };
                ClavePublicaAk::Rsa2048 { n, e }
            }
            TPM_ALG_ECC => {
                // TPMS_ECC_PARMS
                let symmetric = c.u16()?;
                if symmetric != TPM_ALG_NULL {
                    return Err(IdentidadError::NoEsClaveDeFirma);
                }
                let scheme = c.u16()?;
                if scheme != TPM_ALG_NULL {
                    let _hash = c.u16()?;
                }
                let curve = c.u16()?;
                // TPM_ECC_NIST_P256 = 0x0003
                if curve != 0x0003 {
                    return Err(IdentidadError::CurvaNoSoportada(curve));
                }
                let kdf = c.u16()?;
                if kdf != TPM_ALG_NULL {
                    let _hash = c.u16()?;
                }
                // unique: TPMS_ECC_POINT { x: TPM2B, y: TPM2B }
                let x = c.tpm2b()?;
                let y = c.tpm2b()?;
                ClavePublicaAk::EcdsaP256 { x, y }
            }
            otro => return Err(IdentidadError::TipoNoSoportado(otro)),
        };

        let name = nombre_desde_area(name_alg, public_area);
        Ok(AreaPublica {
            name_alg,
            clave,
            name,
        })
    }
}

/// Computa el Name de un objeto TPM: `nameAlg (big-endian) || H_nameAlg(area)`.
/// Se computa sobre los bytes crudos del `publicArea`, sin re-serializar, para
/// que coincida exactamente con lo que hace el TPM.
pub fn nombre_desde_area(name_alg: HashAlg, public_area: &[u8]) -> Vec<u8> {
    let mut out = name_alg.id().to_be_bytes().to_vec();
    // Un TPM puede nombrar con otros bancos; el arranque medido de AegisCore usa
    // SHA-256, asi que es el unico camino ejercitado. Otros bancos producen un
    // Name sin digest, que el verificador rechazara al no casar.
    if name_alg == HashAlg::Sha256 {
        let mut h = Sha256::new();
        h.update(public_area);
        out.extend_from_slice(&h.finalize());
    }
    out
}
