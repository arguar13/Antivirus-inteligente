//! ML-DSA-65 (FIPS 204; ex CRYSTALS-Dilithium), la firma post-cuantica de
//! AegisCore.
//!
//! # Por que ml-dsa de RustCrypto y firma determinista
//!
//! La implementacion es el crate `ml-dsa` de RustCrypto, la misma familia que
//! `aes-gcm` y `sha2` que el proyecto ya usa. Se emplea la variante de firma
//! **determinista** (la aleatoriedad interna `rnd` vale cero) por dos razones:
//! (1) es reproducible, lo que permite casar los **KAT oficiales** de ACVP byte a
//! byte; y (2) no introduce una dependencia de RNG en el momento de firmar. La
//! seguridad de ML-DSA no depende de que la firma sea aleatoria.
//!
//! # El contexto y la separacion de dominios
//!
//! FIPS 204 admite un `ctx` (cadena de contexto, <=255 bytes) que se ata a la
//! firma. AegisCore lo usa para separar dominios: una firma valida para un
//! artefacto de "reglas" no debe poder reinterpretarse como valida para un
//! "binario". La clave que verifica una actualizacion es la del plano de control.

use crate::PqcError;
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, SigningKey, VerifyingKey, B32,
};
use zeroize::Zeroize;

/// Tamano de la clave publica de verificacion (FIPS 204, ML-DSA-65).
pub const PK_LEN: usize = 1952;
/// Tamano de la semilla de generacion de clave (`xi`, FIPS 204 KeyGen).
pub const SEMILLA_LEN: usize = 32;
/// Tamano de la firma.
pub const FIRMA_LEN: usize = 3309;
/// Tamano de la clave secreta en su forma expandida (`skEncode`, FIPS 204).
pub const SK_EXPANDIDA_LEN: usize = 4032;
/// Maximo del contexto de separacion de dominios que admite FIPS 204.
pub const CTX_MAX: usize = 255;

// --- Asserts de ABI/tamano en COMPILACION ---------------------------------
// Atan nuestras constantes (las que fija FIPS 204) a los tipos reales de ml-dsa.
// Si la dependencia cambiara un tamano, el crate NO COMPILA.
const _: () = assert!(core::mem::size_of::<EncodedVerifyingKey<MlDsa65>>() == PK_LEN);
const _: () = assert!(core::mem::size_of::<EncodedSignature<MlDsa65>>() == FIRMA_LEN);
const _: () =
    assert!(core::mem::size_of::<ml_dsa::ExpandedSigningKeyBytes<MlDsa65>>() == SK_EXPANDIDA_LEN);
const _: () = assert!(core::mem::size_of::<B32>() == SEMILLA_LEN);

/// Clave de firma ML-DSA-65.
///
/// Se guarda en su forma de **semilla** (32 bytes), que es la representacion
/// recomendada por FIPS 204 para una clave nueva: mas pequena y sin el riesgo de
/// una forma expandida mal formada. La expansion se recomputa al firmar.
pub struct ClaveFirma(SigningKey<MlDsa65>);

/// Clave publica de verificacion ML-DSA-65 (1952 bytes, `pkEncode`).
#[derive(Clone, PartialEq, Eq)]
pub struct ClaveVerificacion([u8; PK_LEN]);

/// Firma ML-DSA-65 (3309 bytes).
#[derive(Clone, PartialEq, Eq)]
pub struct Firma([u8; FIRMA_LEN]);

impl ClaveFirma {
    /// Genera una clave de firma de forma **determinista** desde una semilla de
    /// 32 bytes (FIPS 204 KeyGen).
    #[must_use]
    pub fn generar(semilla: &[u8; SEMILLA_LEN]) -> Self {
        // `B32::from` consume un array de 32 bytes; es la semilla `xi`.
        let xi = B32::from(*semilla);
        Self(SigningKey::<MlDsa65>::from_seed(&xi))
    }

    /// Genera una clave de firma tomando la semilla de la entropia del sistema.
    ///
    /// # Errores
    /// [`PqcError::Entropia`] si el sistema no puede entregar aleatoriedad segura.
    pub fn generar_aleatorio() -> Result<Self, PqcError> {
        let mut semilla = [0u8; SEMILLA_LEN];
        getrandom::getrandom(&mut semilla).map_err(|_| PqcError::Entropia)?;
        let clave = Self::generar(&semilla);
        semilla.zeroize();
        Ok(clave)
    }

    /// Deriva la clave publica de verificacion correspondiente.
    #[must_use]
    pub fn clave_verificacion(&self) -> ClaveVerificacion {
        let vk = self.0.expanded_key().verifying_key();
        let enc = vk.encode();
        let mut bytes = [0u8; PK_LEN];
        bytes.copy_from_slice(AsRef::<[u8]>::as_ref(&enc));
        ClaveVerificacion(bytes)
    }

    /// Exporta la semilla de 32 bytes (forma recomendada para respaldar la clave).
    #[must_use]
    pub fn semilla(&self) -> [u8; SEMILLA_LEN] {
        let s = self.0.to_seed();
        let mut out = [0u8; SEMILLA_LEN];
        out.copy_from_slice(AsRef::<[u8]>::as_ref(&s));
        out
    }

    /// Firma `mensaje` bajo el contexto `ctx` de forma determinista (FIPS 204).
    ///
    /// # Errores
    /// [`PqcError::MaterialInvalido`] si `ctx` supera [`CTX_MAX`] bytes (limite de
    /// FIPS 204).
    pub fn firmar(&self, mensaje: &[u8], ctx: &[u8]) -> Result<Firma, PqcError> {
        if ctx.len() > CTX_MAX {
            return Err(PqcError::MaterialInvalido("contexto ML-DSA > 255 bytes"));
        }
        let firma = self
            .0
            .expanded_key()
            .sign_deterministic(mensaje, ctx)
            .map_err(|_| PqcError::MaterialInvalido("firma ML-DSA fallida"))?;
        let enc = firma.encode();
        let mut bytes = [0u8; FIRMA_LEN];
        bytes.copy_from_slice(AsRef::<[u8]>::as_ref(&enc));
        Ok(Firma(bytes))
    }
}

impl core::fmt::Debug for ClaveFirma {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Nunca se imprime el material secreto.
        f.debug_struct("ClaveFirma").finish_non_exhaustive()
    }
}

impl ClaveVerificacion {
    /// Construye desde bytes, validando el tamano exacto.
    ///
    /// # Errores
    /// [`PqcError::TamanoInvalido`] si `bytes` no mide exactamente [`PK_LEN`].
    pub fn desde_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        let arr: [u8; PK_LEN] = bytes.try_into().map_err(|_| PqcError::TamanoInvalido {
            campo: "clave de verificacion ML-DSA",
            esperado: PK_LEN,
            recibido: bytes.len(),
        })?;
        Ok(Self(arr))
    }

    /// Vista de los 1952 bytes de la clave publica.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; PK_LEN] {
        &self.0
    }

    /// Verifica `firma` sobre `mensaje` bajo el contexto `ctx`.
    ///
    /// Devuelve `true` solo si la firma es valida. Cualquier material mal formado
    /// (clave o firma) devuelve `false`: ante la duda, se rechaza.
    #[must_use]
    pub fn verificar(&self, mensaje: &[u8], ctx: &[u8], firma: &Firma) -> bool {
        let Ok(enc_vk) = EncodedVerifyingKey::<MlDsa65>::try_from(&self.0[..]) else {
            return false;
        };
        let vk = VerifyingKey::<MlDsa65>::decode(&enc_vk);

        let Ok(enc_sig) = EncodedSignature::<MlDsa65>::try_from(&firma.0[..]) else {
            return false;
        };
        let Some(sig) = Signature::<MlDsa65>::decode(&enc_sig) else {
            return false;
        };
        vk.verify_with_context(mensaje, ctx, &sig)
    }
}

impl Firma {
    /// Construye desde bytes, validando el tamano exacto.
    ///
    /// # Errores
    /// [`PqcError::TamanoInvalido`] si `bytes` no mide exactamente [`FIRMA_LEN`].
    pub fn desde_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        let arr: [u8; FIRMA_LEN] = bytes.try_into().map_err(|_| PqcError::TamanoInvalido {
            campo: "firma ML-DSA",
            esperado: FIRMA_LEN,
            recibido: bytes.len(),
        })?;
        Ok(Self(arr))
    }

    /// Vista de los 3309 bytes de la firma.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; FIRMA_LEN] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helpers de prueba (sin dependencias externas).
    fn hex(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "longitud hex impar");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }
    fn casos(json: &str) -> Vec<serde_json::Value> {
        let v: serde_json::Value = serde_json::from_str(json).expect("json");
        v["casos"].as_array().expect("casos").clone()
    }
    fn campo(c: &serde_json::Value, k: &str) -> Vec<u8> {
        hex(c[k].as_str().unwrap_or_else(|| panic!("campo {k}")))
    }

    #[test]
    fn roundtrip_firma_verificacion() {
        let sk = ClaveFirma::generar_aleatorio().expect("entropia");
        let vk = sk.clave_verificacion();
        let msg = b"telemetria del agente 4820";
        let ctx = b"aegis/update/binario";
        let firma = sk.firmar(msg, ctx).expect("firmar");
        assert!(
            vk.verificar(msg, ctx, &firma),
            "la firma propia debe verificar"
        );
    }

    #[test]
    fn firma_determinista() {
        let sk = ClaveFirma::generar_aleatorio().expect("entropia");
        let msg = b"mismo mensaje";
        let ctx = b"mismo ctx";
        let f1 = sk.firmar(msg, ctx).expect("f1");
        let f2 = sk.firmar(msg, ctx).expect("f2");
        assert_eq!(f1.as_bytes(), f2.as_bytes(), "firma determinista: identica");
    }

    #[test]
    fn mensaje_o_contexto_alterados_no_verifican() {
        let sk = ClaveFirma::generar_aleatorio().expect("entropia");
        let vk = sk.clave_verificacion();
        let firma = sk.firmar(b"original", b"ctx").expect("firmar");
        assert!(
            !vk.verificar(b"alterado", b"ctx", &firma),
            "mensaje alterado"
        );
        assert!(
            !vk.verificar(b"original", b"otro-ctx", &firma),
            "ctx alterado"
        );
    }

    #[test]
    fn firma_alterada_o_clave_ajena_no_verifican() {
        let sk = ClaveFirma::generar_aleatorio().expect("entropia");
        let vk = sk.clave_verificacion();
        let firma = sk.firmar(b"m", b"c").expect("firmar");

        let mut bytes = *firma.as_bytes();
        bytes[0] ^= 0x01;
        let firma_mala = Firma::desde_bytes(&bytes).expect("tamano");
        assert!(!vk.verificar(b"m", b"c", &firma_mala), "firma alterada");

        let otra = ClaveFirma::generar_aleatorio().expect("entropia");
        assert!(
            !otra.clave_verificacion().verificar(b"m", b"c", &firma),
            "clave ajena"
        );
    }

    #[test]
    fn ctx_demasiado_largo_falla() {
        let sk = ClaveFirma::generar_aleatorio().expect("entropia");
        let ctx = vec![0u8; CTX_MAX + 1];
        assert!(matches!(
            sk.firmar(b"m", &ctx),
            Err(PqcError::MaterialInvalido(_))
        ));
    }

    #[test]
    fn desde_bytes_valida_tamano() {
        assert!(matches!(
            ClaveVerificacion::desde_bytes(&[0u8; PK_LEN - 1]),
            Err(PqcError::TamanoInvalido { .. })
        ));
        assert!(matches!(
            Firma::desde_bytes(&[0u8; FIRMA_LEN + 1]),
            Err(PqcError::TamanoInvalido { .. })
        ));
    }

    // --- KAT oficiales FIPS 204 (NIST ACVP) ---------------------------------
    //
    // keyGen byte-exacto (pk y sk) y sigGen determinista byte-exacto. Ambos
    // necesitan la forma expandida de la clave; `to_expanded`/`from_expanded`
    // estan marcados "deprecated" en ml-dsa porque desaconsejan ALMACENAR claves
    // expandidas en produccion (preferir la semilla), no porque sean incorrectos:
    // para reproducir un vector KAT a partir de su skEncode oficial es justo la
    // API que toca. Se aisla aqui, en prueba, y nunca en la API publica.

    #[test]
    fn kat_keygen_fips204() {
        let cs = casos(include_str!("../tests/vectors/dsa_keygen.json"));
        assert!(!cs.is_empty());
        for c in cs {
            let mut seed = [0u8; SEMILLA_LEN];
            seed.copy_from_slice(&campo(&c, "seed"));
            let sk = ClaveFirma::generar(&seed);

            // pk via API publica.
            assert_eq!(
                &sk.clave_verificacion().as_bytes()[..],
                &campo(&c, "pk")[..],
                "pk no coincide (tcId {})",
                c["tcId"]
            );

            // sk (forma expandida) via to_expanded (deprecated: solo KAT).
            #[allow(deprecated)]
            let sk_exp = sk.0.expanded_key().to_expanded();
            assert_eq!(
                AsRef::<[u8]>::as_ref(&sk_exp),
                &campo(&c, "sk")[..],
                "sk expandida no coincide (tcId {})",
                c["tcId"]
            );
        }
    }

    #[test]
    fn kat_siggen_determinista_fips204() {
        use ml_dsa::ExpandedSigningKey;
        let cs = casos(include_str!("../tests/vectors/dsa_siggen.json"));
        assert!(!cs.is_empty());
        for c in cs {
            let sk_bytes = campo(&c, "sk");
            let enc = ml_dsa::ExpandedSigningKeyBytes::<MlDsa65>::try_from(&sk_bytes[..])
                .expect("skEncode de 4032 bytes");
            // from_expanded (deprecated: solo KAT, vectores NIST de confianza).
            #[allow(deprecated)]
            let esk = ExpandedSigningKey::<MlDsa65>::from_expanded(&enc);

            let msg = campo(&c, "message");
            let ctx = campo(&c, "context");
            let firma = esk.sign_deterministic(&msg, &ctx).expect("firmar");
            let firma_enc = firma.encode();
            assert_eq!(
                AsRef::<[u8]>::as_ref(&firma_enc),
                &campo(&c, "signature")[..],
                "firma determinista no coincide (tcId {})",
                c["tcId"]
            );
        }
    }
}
