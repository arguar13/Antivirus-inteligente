//! El motor de decision: dado un quote, decide si creerselo.
//!
//! Es el codigo que puede estar mal de forma peligrosa. Un fallo de mas
//! cuarentena a una maquina sana (y con la FASE 44, a un ritmo de milisegundos
//! por toda la flota); un fallo de menos acepta telemetria fabricada por un
//! atacante como si fuera de un endpoint sano. Por eso la cadena de veredicto es
//! explicita y cada paso tiene su vector de prueba, negativo incluido.
//!
//! La cadena, en orden:
//! 1. parsear el `TPMS_ATTEST`;
//! 2. verificar la FIRMA sobre los bytes marshalados, con la clave de la AK,
//!    despachando por algoritmo;
//! 3. exigir el magic `TCG` y el tipo QUOTE;
//! 4. exigir que el `qualifiedSigner` sea el Name de la AK matriculada;
//! 5. exigir que `extraData` sea el nonce del desafio (frescura);
//! 6. RECOMPUTAR el `pcrDigest` a partir de los PCR presentados y exigir que
//!    case con el del quote —asi la firma ata los valores presentados—;
//! 7. si hay valores dorados, exigir que los PCR presentados coincidan.
//!
//! El orden importa: la firma se comprueba ANTES que nada del contenido, porque
//! hasta que la firma no verifica, el contenido son bytes de un atacante.

use crate::attest::{Attest, AttestError, TPM_GENERATED_VALUE, TPM_ST_ATTEST_QUOTE};
use crate::identidad::ClavePublicaAk;
use aegis_firmware::{CheckState, HashAlg};
use sha2::{Digest, Sha256};

/// Por que un quote no es de fiar. Cada variante es un paso de la cadena que no
/// se cumplio.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerificadorError {
    /// El `TPMS_ATTEST` no parsea.
    #[error("el quote no parsea: {0}")]
    Parse(#[from] AttestError),
    /// La clave publica de la AK no se pudo reconstruir (modulo/punto invalido).
    #[error("la clave de la AK es invalida")]
    ClaveInvalida,
    /// La firma no verifica con la AK. La causa mas grave: el quote no lo firmo
    /// quien dice, o los bytes se manipularon.
    #[error("la firma del quote no verifica")]
    FirmaInvalida,
    /// Falta el magic `TCG`: no lo genero un TPM.
    #[error("magic invalido: {0:#010x} (se esperaba TPM_GENERATED_VALUE)")]
    MagicInvalido(u32),
    /// El tipo no es QUOTE: es otra atestacion (una clave, el tiempo) que no
    /// dice nada de los PCR.
    #[error("tipo {0:#06x}: no es un quote de PCR")]
    NoEsQuote(u16),
    /// El `qualifiedSigner` no es el Name de la AK matriculada.
    #[error("el quote lo firma otra clave, no la AK matriculada")]
    NombreAkNoCoincide,
    /// El `extraData` no es el nonce esperado: el quote no responde a este
    /// desafio (podria ser una reproduccion de uno viejo).
    #[error("el nonce del quote no coincide con el desafio")]
    NonceNoCoincide,
    /// El `pcrDigest` firmado no casa con el hash de los PCR presentados: los
    /// valores presentados NO son los que el TPM firmo.
    #[error("el digest de PCR firmado no casa con los PCR presentados")]
    PcrDigestNoCoincide,
    /// Un PCR presentado no coincide con su valor dorado: el arranque cambio.
    #[error("el PCR {0} no coincide con el valor dorado")]
    PcrDoradoNoCoincide(u32),
    /// El hash del `nameAlg`/scheme no esta soportado para recomputar el digest.
    #[error("algoritmo de digest no soportado para la verificacion")]
    AlgNoSoportado,
}

/// Lo que se necesita para juzgar un quote.
pub struct Entrada<'a> {
    /// Los bytes exactos del `TPMS_ATTEST` que el TPM firmo.
    pub attest_firmado: &'a [u8],
    /// La firma sobre esos bytes. Ed25519/ECDSA: `r||s` (64 bytes). RSA: el
    /// bloque PKCS#1 v1.5.
    pub firma: &'a [u8],
    /// La clave publica de la AK.
    pub ak: &'a ClavePublicaAk,
    /// El Name de la AK matriculada, si se quiere atar el quote a ella.
    pub ak_name_esperado: Option<&'a [u8]>,
    /// El nonce del desafio que se espera en `extraData`.
    pub nonce_esperado: &'a [u8],
    /// Los valores de PCR que el agente presenta, en orden ascendente de indice.
    pub pcrs_presentados: &'a [(u32, Vec<u8>)],
    /// El hash del esquema de firma, con el que el TPM computo el `pcrDigest`.
    pub hash_firma: HashAlg,
    /// Valores dorados a contrastar, si los hay.
    pub dorados: Option<&'a [(u32, Vec<u8>)]>,
}

/// El veredicto sobre un quote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Veredicto {
    /// El quote es autentico, fresco, y (si habia dorados) el arranque coincide.
    Valido,
    /// El quote no es de fiar, por el motivo dado.
    Fallo(String),
}

impl Veredicto {
    /// Traduce el veredicto al tri-estado de `aegis-firmware`. `Valido -> Ok`;
    /// `Fallo -> Inseguro`. La ausencia de TPM NO llega aqui: eso es
    /// `NoAplicable`, y lo decide quien llama antes de pedir un quote.
    pub fn a_checkstate(&self) -> CheckState {
        match self {
            Veredicto::Valido => CheckState::Ok,
            Veredicto::Fallo(m) => CheckState::Fallo(m.clone()),
        }
    }

    /// `true` si el quote no es de fiar (atajo para el enganche con la
    /// cuarentena).
    pub fn es_fallo(&self) -> bool {
        matches!(self, Veredicto::Fallo(_))
    }
}

/// Verifica un quote de principio a fin. Devuelve el motivo exacto del primer
/// paso que falla, para que el operador sepa por que se cuarentena una maquina.
pub fn verificar_quote(e: &Entrada) -> Result<Veredicto, VerificadorError> {
    // 1. Parsear.
    let attest = Attest::parse(e.attest_firmado)?;

    // 2. Firma ANTES que el contenido: hasta aqui, todo son bytes de un posible
    //    atacante.
    if !verificar_firma(e.ak, e.attest_firmado, e.firma)? {
        return Ok(Veredicto::Fallo(
            VerificadorError::FirmaInvalida.to_string(),
        ));
    }

    // 3. Magic y tipo.
    if attest.magic != TPM_GENERATED_VALUE {
        return Ok(Veredicto::Fallo(
            VerificadorError::MagicInvalido(attest.magic).to_string(),
        ));
    }
    if attest.tipo != TPM_ST_ATTEST_QUOTE {
        return Ok(Veredicto::Fallo(
            VerificadorError::NoEsQuote(attest.tipo).to_string(),
        ));
    }

    // 4. Que lo firme la AK matriculada, no cualquier clave valida.
    if let Some(name) = e.ak_name_esperado {
        if attest.qualified_signer != name {
            return Ok(Veredicto::Fallo(
                VerificadorError::NombreAkNoCoincide.to_string(),
            ));
        }
    }

    // 5. Frescura: el nonce del desafio.
    if attest.extra_data != e.nonce_esperado {
        return Ok(Veredicto::Fallo(
            VerificadorError::NonceNoCoincide.to_string(),
        ));
    }

    // 6. Recomputar el pcrDigest y exigir que case: asi los PCR presentados
    //    quedan atados a la firma.
    let digest = digest_de_pcrs(e.hash_firma, e.pcrs_presentados)?;
    if digest != attest.quote.pcr_digest {
        return Ok(Veredicto::Fallo(
            VerificadorError::PcrDigestNoCoincide.to_string(),
        ));
    }

    // 7. Contraste con los dorados, si los hay.
    if let Some(dorados) = e.dorados {
        for (pcr, valor) in dorados {
            match e.pcrs_presentados.iter().find(|(p, _)| p == pcr) {
                Some((_, presentado)) if presentado == valor => {}
                _ => {
                    return Ok(Veredicto::Fallo(
                        VerificadorError::PcrDoradoNoCoincide(*pcr).to_string(),
                    ));
                }
            }
        }
    }

    Ok(Veredicto::Valido)
}

/// Concatena los valores de PCR en orden ascendente de indice y los hashea con
/// el algoritmo del esquema de firma. Es como el TPM computa el `pcrDigest`.
fn digest_de_pcrs(alg: HashAlg, pcrs: &[(u32, Vec<u8>)]) -> Result<Vec<u8>, VerificadorError> {
    let mut ordenados: Vec<&(u32, Vec<u8>)> = pcrs.iter().collect();
    ordenados.sort_by_key(|(p, _)| *p);
    match alg {
        HashAlg::Sha256 => {
            let mut h = Sha256::new();
            for (_, v) in ordenados {
                h.update(v);
            }
            Ok(h.finalize().to_vec())
        }
        _ => Err(VerificadorError::AlgNoSoportado),
    }
}

/// Verifica la firma segun el tipo de clave de la AK. Devuelve `Ok(false)` si la
/// firma no verifica, `Err` si la clave publica no se pudo reconstruir.
fn verificar_firma(
    ak: &ClavePublicaAk,
    mensaje: &[u8],
    firma: &[u8],
) -> Result<bool, VerificadorError> {
    match ak {
        ClavePublicaAk::Ed25519(bytes) => {
            use ed25519_dalek::{Signature, VerifyingKey};
            let vk =
                VerifyingKey::from_bytes(bytes).map_err(|_| VerificadorError::ClaveInvalida)?;
            let sig = match Signature::from_slice(firma) {
                Ok(s) => s,
                Err(_) => return Ok(false),
            };
            Ok(vk.verify_strict(mensaje, &sig).is_ok())
        }
        ClavePublicaAk::EcdsaP256 { x, y } => {
            use p256::ecdsa::signature::Verifier;
            use p256::ecdsa::{Signature, VerifyingKey};
            // SEC1 sin comprimir: 0x04 || X || Y.
            let mut sec1 = Vec::with_capacity(1 + x.len() + y.len());
            sec1.push(0x04);
            sec1.extend_from_slice(x);
            sec1.extend_from_slice(y);
            let vk = VerifyingKey::from_sec1_bytes(&sec1)
                .map_err(|_| VerificadorError::ClaveInvalida)?;
            let sig = match Signature::from_slice(firma) {
                Ok(s) => s,
                Err(_) => return Ok(false),
            };
            Ok(vk.verify(mensaje, &sig).is_ok())
        }
        ClavePublicaAk::Rsa2048 { n, e } => {
            use rsa::pkcs1v15::{Signature, VerifyingKey};
            use rsa::signature::Verifier;
            use rsa::{BigUint, RsaPublicKey};
            let n = BigUint::from_bytes_be(n);
            let e = if e.is_empty() {
                BigUint::from(65_537u32)
            } else {
                BigUint::from_bytes_be(e)
            };
            let pk = RsaPublicKey::new(n, e).map_err(|_| VerificadorError::ClaveInvalida)?;
            let vk = VerifyingKey::<Sha256>::new(pk);
            let sig = match Signature::try_from(firma) {
                Ok(s) => s,
                Err(_) => return Ok(false),
            };
            Ok(vk.verify(mensaje, &sig).is_ok())
        }
    }
}
