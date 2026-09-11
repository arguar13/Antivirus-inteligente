//! ML-KEM-768 (FIPS 203; ex CRYSTALS-Kyber), el mecanismo de encapsulado de
//! clave post-cuantico de AegisCore.
//!
//! # Por que libcrux y una API derandomizada
//!
//! La implementacion es `libcrux-ml-kem` de Cryspen: **Rust puro y formalmente
//! verificado** (con hax), la misma que usa Firefox. No arrastra C inestable, asi
//! que corre en el borde sin conexion. Se usa la API **derandomizada** —la que
//! recibe la aleatoriedad como argumento en vez de tomarla de un RNG interno—
//! por dos razones: (1) es la unica forma de reproducir los **KAT oficiales** de
//! ACVP (que fijan la aleatoriedad), y (2) deja la politica de entropia en manos
//! del llamante. Los constructores `*_aleatorio` de este modulo son la comodidad
//! de produccion: toman la entropia del sistema por encima de esa misma API.
//!
//! # IND-CCA2 y rechazo implicito
//!
//! ML-KEM es IND-CCA2: ante un ciphertext manipulado, `desencapsular` **no
//! falla** —devuelve un secreto DISTINTO y deterministico (rechazo implicito)—.
//! Eso evita un oraculo de relleno: el atacante no aprende nada de si acerto. La
//! prueba negativa de este modulo lo verifica volteando un bit del ciphertext.

use crate::PqcError;
use libcrux_ml_kem::mlkem768::{self, MlKem768Ciphertext, MlKem768PrivateKey, MlKem768PublicKey};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Tamano de la clave publica de encapsulado `ek` (FIPS 203, ML-KEM-768).
pub const PK_LEN: usize = 1184;
/// Tamano de la clave secreta de desencapsulado `dk`.
pub const SK_LEN: usize = 2400;
/// Tamano del texto cifrado `ct`.
pub const CT_LEN: usize = 1088;
/// Tamano del secreto compartido `ss`.
pub const SS_LEN: usize = 32;
/// Tamano de la semilla de generacion de claves (`d || z`, FIPS 203 KeyGen).
pub const SEMILLA_LEN: usize = 64;
/// Tamano de la aleatoriedad de encapsulado (el mensaje `m`, FIPS 203 Encaps).
pub const ENCAPS_ALEATORIEDAD_LEN: usize = 32;

// --- Asserts de ABI/tamano en COMPILACION ---------------------------------
//
// Las constantes de arriba son las que fija FIPS 203 para ML-KEM-768. Estas
// comprobaciones las atan al tipo real de libcrux: si una futura version de la
// dependencia cambiara cualquier tamano, el crate NO COMPILA, en vez de
// corromperse en silencio. Es la "verificacion de tamano/ABI comprobable en
// compilacion" que exige la honestidad de la fase.
const _: () = assert!(core::mem::size_of::<MlKem768PublicKey>() == PK_LEN);
const _: () = assert!(core::mem::size_of::<MlKem768PrivateKey>() == SK_LEN);
const _: () = assert!(core::mem::size_of::<MlKem768Ciphertext>() == CT_LEN);
const _: () = assert!(libcrux_ml_kem::KEY_GENERATION_SEED_SIZE == SEMILLA_LEN);
const _: () = assert!(libcrux_ml_kem::ENCAPS_SEED_SIZE == ENCAPS_ALEATORIEDAD_LEN);

/// Clave publica ML-KEM-768 (encapsulation key, `ek`): 1184 bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct ClavePublica([u8; PK_LEN]);

/// Clave secreta ML-KEM-768 (decapsulation key, `dk`): 2400 bytes.
///
/// Material secreto: se limpia de memoria al soltarse.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ClaveSecreta([u8; SK_LEN]);

/// Texto cifrado de encapsulado (`ct`): 1088 bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct TextoCifrado([u8; CT_LEN]);

/// Secreto compartido de 32 bytes producido por encapsular/desencapsular.
///
/// Material secreto: se limpia de memoria al soltarse. No implementa
/// comparacion: un secreto no se compara por igualdad en produccion, se deriva
/// (ver [`crate::kem_hibrido`]).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secreto([u8; SS_LEN]);

/// Par de claves ML-KEM-768 recien generado.
pub struct ParClaves {
    /// Clave publica, que se envia al par.
    pub publica: ClavePublica,
    secreta: ClaveSecreta,
}

impl ClavePublica {
    /// Construye desde bytes, validando el tamano exacto.
    ///
    /// # Errores
    /// [`PqcError::TamanoInvalido`] si `bytes` no mide exactamente [`PK_LEN`].
    pub fn desde_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        Ok(Self(array_exacto(bytes, PK_LEN, "clave publica ML-KEM")?))
    }

    /// Vista de los 1184 bytes de la clave publica.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; PK_LEN] {
        &self.0
    }
}

impl ClaveSecreta {
    /// Construye desde bytes, validando el tamano exacto.
    ///
    /// # Errores
    /// [`PqcError::TamanoInvalido`] si `bytes` no mide exactamente [`SK_LEN`].
    pub fn desde_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        Ok(Self(array_exacto(bytes, SK_LEN, "clave secreta ML-KEM")?))
    }

    /// Vista de los 2400 bytes de la clave secreta.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SK_LEN] {
        &self.0
    }
}

impl TextoCifrado {
    /// Construye desde bytes, validando el tamano exacto.
    ///
    /// # Errores
    /// [`PqcError::TamanoInvalido`] si `bytes` no mide exactamente [`CT_LEN`].
    pub fn desde_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        Ok(Self(array_exacto(bytes, CT_LEN, "texto cifrado ML-KEM")?))
    }

    /// Vista de los 1088 bytes del texto cifrado.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; CT_LEN] {
        &self.0
    }
}

impl Secreto {
    /// Vista de los 32 bytes del secreto compartido.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SS_LEN] {
        &self.0
    }
}

impl ParClaves {
    /// Genera un par de claves de forma **determinista** a partir de una semilla
    /// de 64 bytes (`d || z`), tal y como lo define FIPS 203 KeyGen.
    #[must_use]
    pub fn generar(semilla: &[u8; SEMILLA_LEN]) -> Self {
        let par = mlkem768::generate_key_pair(*semilla);
        Self {
            publica: ClavePublica(*par.public_key().as_slice()),
            secreta: ClaveSecreta(*par.private_key().as_slice()),
        }
    }

    /// Genera un par de claves tomando la semilla de la entropia del sistema.
    ///
    /// # Errores
    /// [`PqcError::Entropia`] si el sistema no puede entregar aleatoriedad segura.
    pub fn generar_aleatorio() -> Result<Self, PqcError> {
        let mut semilla = [0u8; SEMILLA_LEN];
        getrandom::getrandom(&mut semilla).map_err(|_| PqcError::Entropia)?;
        let par = Self::generar(&semilla);
        semilla.zeroize();
        Ok(par)
    }

    /// Acceso de solo lectura a la clave secreta (no se expone por copia para no
    /// multiplicar material secreto en memoria sin querer).
    #[must_use]
    pub fn secreta(&self) -> &ClaveSecreta {
        &self.secreta
    }

    /// Descompone el par en sus dos claves, transfiriendo la propiedad (lo usa
    /// el KEM hibrido para quedarse con la clave secreta sin clonarla).
    #[must_use]
    pub fn into_partes(self) -> (ClavePublica, ClaveSecreta) {
        (self.publica, self.secreta)
    }
}

/// Encapsula contra `pk` usando una aleatoriedad `m` dada (API derandomizada).
///
/// Antes de encapsular **valida** la clave publica: una `ek` mal formada podria
/// venir de un atacante, y FIPS 203 exige comprobar el rango de los coeficientes.
///
/// # Errores
/// [`PqcError::MaterialInvalido`] si la clave publica no supera la validacion.
pub fn encapsular(
    pk: &ClavePublica,
    aleatoriedad: &[u8; ENCAPS_ALEATORIEDAD_LEN],
) -> Result<(TextoCifrado, Secreto), PqcError> {
    let pk_lib = MlKem768PublicKey::from(pk.0);
    if !mlkem768::validate_public_key(&pk_lib) {
        return Err(PqcError::MaterialInvalido(
            "clave publica ML-KEM no canonica",
        ));
    }
    let (ct, ss) = mlkem768::encapsulate(&pk_lib, *aleatoriedad);
    Ok((TextoCifrado(*ct.as_slice()), Secreto(ss)))
}

/// Encapsula contra `pk` tomando la aleatoriedad de la entropia del sistema.
///
/// # Errores
/// [`PqcError::Entropia`] si no hay entropia; [`PqcError::MaterialInvalido`] si
/// la clave publica no es valida.
pub fn encapsular_aleatorio(pk: &ClavePublica) -> Result<(TextoCifrado, Secreto), PqcError> {
    let mut m = [0u8; ENCAPS_ALEATORIEDAD_LEN];
    getrandom::getrandom(&mut m).map_err(|_| PqcError::Entropia)?;
    let r = encapsular(pk, &m);
    m.zeroize();
    r
}

/// Desencapsula `ct` con la clave secreta `sk`.
///
/// No devuelve `Result`: ML-KEM es IND-CCA2 y ante un ciphertext manipulado
/// **no falla**, devuelve un secreto distinto por rechazo implicito. Quien llama
/// nunca aprende del resultado si el ciphertext era autentico.
#[must_use]
pub fn desencapsular(sk: &ClaveSecreta, ct: &TextoCifrado) -> Secreto {
    let sk_lib = MlKem768PrivateKey::from(sk.0);
    let ct_lib = MlKem768Ciphertext::from(ct.0);
    Secreto(mlkem768::decapsulate(&sk_lib, &ct_lib))
}

/// Copia un slice a un array de tamano fijo, fallando si el tamano no es exacto.
fn array_exacto<const N: usize>(
    bytes: &[u8],
    esperado: usize,
    campo: &'static str,
) -> Result<[u8; N], PqcError> {
    let arr: [u8; N] = bytes.try_into().map_err(|_| PqcError::TamanoInvalido {
        campo,
        esperado,
        recibido: bytes.len(),
    })?;
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_encaps_decaps() {
        let par = ParClaves::generar_aleatorio().expect("entropia");
        let (ct, ss_a) = encapsular_aleatorio(&par.publica).expect("encaps");
        let ss_b = desencapsular(par.secreta(), &ct);
        assert_eq!(
            ss_a.as_bytes(),
            ss_b.as_bytes(),
            "el secreto debe coincidir"
        );
    }

    #[test]
    fn encapsular_es_determinista_con_la_misma_aleatoriedad() {
        let par = ParClaves::generar_aleatorio().expect("entropia");
        let m = [7u8; ENCAPS_ALEATORIEDAD_LEN];
        let (ct1, ss1) = encapsular(&par.publica, &m).expect("encaps1");
        let (ct2, ss2) = encapsular(&par.publica, &m).expect("encaps2");
        assert_eq!(ct1.as_bytes(), ct2.as_bytes());
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    #[test]
    fn bit_alterado_en_ct_da_secreto_distinto_no_falla() {
        // Rechazo implicito IND-CCA2: desencapsular un ct manipulado NO falla,
        // devuelve un secreto DISTINTO. Verificamos ambas cosas.
        let par = ParClaves::generar_aleatorio().expect("entropia");
        let (ct, ss_ok) = encapsular_aleatorio(&par.publica).expect("encaps");

        let mut bytes = *ct.as_bytes();
        bytes[0] ^= 0x01; // voltea un solo bit
        let ct_malo = TextoCifrado::desde_bytes(&bytes).expect("tamano");

        let ss_malo = desencapsular(par.secreta(), &ct_malo);
        assert_ne!(
            ss_ok.as_bytes(),
            ss_malo.as_bytes(),
            "un ct alterado debe producir un secreto distinto"
        );
    }

    #[test]
    fn desde_bytes_valida_tamano() {
        assert!(matches!(
            ClavePublica::desde_bytes(&[0u8; PK_LEN - 1]),
            Err(PqcError::TamanoInvalido { .. })
        ));
        assert!(ClavePublica::desde_bytes(&[0u8; PK_LEN]).is_ok());
        assert!(matches!(
            TextoCifrado::desde_bytes(&[0u8; CT_LEN + 1]),
            Err(PqcError::TamanoInvalido { .. })
        ));
    }

    #[test]
    fn clave_publica_no_canonica_se_rechaza_al_encapsular() {
        // Una ek de puros 0xFF no es canonica (coeficientes fuera de rango).
        let pk = ClavePublica([0xFFu8; PK_LEN]);
        assert!(matches!(
            encapsular(&pk, &[0u8; ENCAPS_ALEATORIEDAD_LEN]),
            Err(PqcError::MaterialInvalido(_))
        ));
    }
}
