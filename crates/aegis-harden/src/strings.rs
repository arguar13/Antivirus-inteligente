//! Cifrado de cadenas criticas del binario.
//!
//! # El problema
//!
//! Un binario compilado lleva sus cadenas de texto en claro. `strings binario`
//! sobre el agente revelaria de un vistazo los endpoints de la nube, los
//! nombres de las reglas YARA, las rutas que vigila y los mensajes internos:
//! un mapa del producto regalado a quien quiera evadirlo. Es lo primero que
//! mira cualquier analista, y lo mas barato de conseguir.
//!
//! # El mecanismo
//!
//! Las cadenas sensibles no se compilan en claro. Una herramienta de
//! construccion (`tools/obfuscate.py`) las cifra con **AES-256-GCM** y emite una
//! tabla de textos cifrados. En el binario solo hay ruido. Al arrancar, el
//! agente deriva la clave y descifra la tabla en memoria, dentro de un almacen
//! que se pone a cero al liberarse.
//!
//! # El modelo de amenaza, sin exageraciones
//!
//! Esto detiene el analisis ESTATICO: `strings`, la vista de cadenas de Ghidra
//! o IDA, un `grep` sobre el binario. No detiene a un analista decidido con un
//! depurador, porque la clave tiene que estar en el binario para que el propio
//! binario pueda descifrarse; es una propiedad inherente de la ofuscacion de
//! cadenas, no un defecto de esta implementacion. Por eso:
//!
//! 1. La clave **no es un bloque contiguo**. Se deriva por SHA-256 de cuatro
//!    fragmentos de 64 bits dispersos mas una sal, de modo que no hay 32 bytes
//!    seguidos que un analista pueda reconocer como "la clave".
//! 2. El descifrado en caliente se combina con la **anti-depuracion** de
//!    [`crate::antidebug`]: subir el coste del analisis estatico solo vale la
//!    pena si tambien se sube el del dinamico.
//!
//! La promesa honesta es "sube el coste", no "es irrompible". Un producto de
//! seguridad que mintiera sobre su propia resistencia seria una contradiccion.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// Error al descifrar una cadena ofuscada.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RevealError {
    /// El texto cifrado no autentica: clave equivocada, nonce equivocado o
    /// tabla manipulada.
    #[error("el texto cifrado no autentica")]
    Authentication,
    /// El texto descifrado no era UTF-8 valido.
    #[error("el texto descifrado no es UTF-8")]
    NotUtf8,
    /// El nonce no tiene los 12 bytes que exige GCM.
    #[error("nonce de {0} bytes, se esperaban 12")]
    BadNonce(usize),
}

/// Deriva la clave de 256 bits a partir de los fragmentos y la sal.
///
/// Se usa SHA-256 y no los fragmentos en crudo por dos razones: el resultado
/// tiene la longitud exacta de la clave de AES-256, y el paso de hash rompe
/// cualquier relacion visible entre los fragmentos y los bytes de la clave,
/// de modo que encontrar los fragmentos no basta para saltarse el hash.
pub fn derive_key(shards: &[u64; 4], salt: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    // Los fragmentos se mezclan en little-endian, el mismo orden que usa el
    // tool de Python: la interoperabilidad exige que ambos lados coincidan
    // byte a byte, y esta prueba la cubre `tools/obfuscate.py --self-test`.
    for s in shards {
        h.update(s.to_le_bytes());
    }
    h.update(salt);
    h.update(b"aegiscore/string-obfuscation/v1");
    h.finalize().into()
}

/// Descifra un unico texto cifrado con la clave dada.
pub fn reveal(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> Result<String, RevealError> {
    if nonce.len() != 12 {
        return Err(RevealError::BadNonce(nonce.len()));
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let mut claro = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| RevealError::Authentication)?;

    let salida = String::from_utf8(claro.clone()).map_err(|_| {
        claro.zeroize();
        RevealError::NotUtf8
    })?;
    claro.zeroize();
    Ok(salida)
}

/// Una entrada de la tabla generada: nombre logico, nonce y texto cifrado.
///
/// El nombre NO es secreto (es una etiqueta para buscar la cadena en el
/// codigo); lo secreto es el texto en claro, que solo existe cifrado en el
/// binario.
pub type Entry = (&'static str, &'static [u8], &'static [u8]);

/// Cadena descifrada, que se pone a cero al liberarse.
///
/// Retenerla mas de lo necesario amplia la ventana en la que un volcado de
/// memoria la expone. Se envuelve para que al salir de ambito sus bytes se
/// borren en vez de quedar en el monton.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Secret(String);

impl Secret {
    /// Acceso al texto en claro mientras el secreto siga vivo.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Nunca se imprime el contenido: un secreto que aparece en un log deja
        // de serlo, y este tipo existe precisamente para eso.
        write!(f, "Secret(<{} bytes ocultos>)", self.0.len())
    }
}

/// Almacen de cadenas descifradas al arrancar.
///
/// Se descifra una vez, al inicio, y se consulta por nombre en tiempo constante.
/// Descifrar en cada uso multiplicaria el coste sin ganar seguridad: la cadena
/// ya esta en memoria descifrada mientras el proceso corre.
pub struct Vault {
    key: [u8; 32],
    entradas: std::collections::HashMap<&'static str, Secret>,
}

impl Vault {
    /// Descifra una tabla generada con la clave derivada de los fragmentos.
    ///
    /// Falla en cuanto una entrada no autentica: una tabla a medias es peor que
    /// ninguna, porque dejaria al agente operando con endpoints o reglas a
    /// medio cargar sin avisar.
    pub fn unseal(shards: &[u64; 4], salt: &[u8], tabla: &[Entry]) -> Result<Vault, RevealError> {
        let key = derive_key(shards, salt);
        let mut entradas = std::collections::HashMap::with_capacity(tabla.len());
        for (nombre, nonce, ct) in tabla {
            let claro = reveal(&key, nonce, ct)?;
            entradas.insert(*nombre, Secret(claro));
        }
        Ok(Vault { key, entradas })
    }

    /// Recupera una cadena por su nombre logico.
    pub fn get(&self, nombre: &str) -> Option<&str> {
        self.entradas.get(nombre).map(Secret::as_str)
    }

    /// Numero de cadenas en el almacen.
    pub fn len(&self) -> usize {
        self.entradas.len()
    }

    /// Indica si esta vacio.
    pub fn is_empty(&self) -> bool {
        self.entradas.is_empty()
    }

    /// Nombres disponibles, para diagnostico.
    pub fn names(&self) -> impl Iterator<Item = &&'static str> {
        self.entradas.keys()
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        // La clave derivada se borra explicitamente; los secretos se borran
        // solos por su `Drop`. Asi no queda material sensible en el monton tras
        // liberar el almacen.
        self.key.zeroize();
    }
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Vault({} cadenas)", self.entradas.len())
    }
}
