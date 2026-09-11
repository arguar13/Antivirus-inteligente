//! Almacen de copias-sombra CIFRADAS.
//!
//! Las copias del contenido original se guardan en disco, asi que estan al
//! alcance del mismo ransomware que intenta cifrarlo todo. Si estuvieran en
//! claro, el ransomware las veria y las cifraria o borraria como a cualquier
//! otro fichero. Por eso se cifran con AES-256-GCM bajo una clave que el proceso
//! atacante no tiene: aunque las encuentre, para el son ruido, y GCM detecta
//! cualquier intento de alterarlas.
//!
//! Es el mismo stack criptografico que la cuarentena de `aegis-resp`
//! (AES-256-GCM + HKDF-SHA256), por consistencia y para no anadir dependencias.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// Identificador de una copia-sombra: 16 bytes aleatorios, tambien el nombre de
/// su fichero en el almacen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SombraId(pub [u8; 16]);

impl SombraId {
    fn generar() -> SombraId {
        let mut b = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut b);
        SombraId(b)
    }

    /// El id en hexadecimal, usado como nombre de fichero.
    pub fn hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Un fallo del almacen de copias-sombra.
#[derive(Debug, thiserror::Error)]
pub enum SombraError {
    /// Error de E/S al escribir o leer una copia.
    #[error("E/S del almacen de sombras: {0}")]
    Io(#[from] std::io::Error),
    /// El descifrado fallo: la copia esta corrupta o alterada (GCM lo detecta).
    #[error("la copia-sombra no se pudo descifrar (corrupta o alterada)")]
    Descifrado,
    /// El blob es demasiado corto para contener salt, nonce y datos.
    #[error("copia-sombra truncada")]
    Truncada,
}

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

/// El almacen: un directorio con copias-sombra cifradas y una clave maestra en
/// memoria que se borra al soltarla.
pub struct AlmacenSombra {
    dir: PathBuf,
    maestra: [u8; 32],
}

impl Drop for AlmacenSombra {
    fn drop(&mut self) {
        self.maestra.zeroize();
    }
}

impl AlmacenSombra {
    /// Abre (creando el directorio si hace falta) un almacen bajo `dir` con la
    /// clave maestra dada. La clave nunca sale de aqui; deriva una clave por
    /// copia con HKDF.
    pub fn abrir(dir: &Path, maestra: [u8; 32]) -> Result<AlmacenSombra, SombraError> {
        std::fs::create_dir_all(dir)?;
        Ok(AlmacenSombra {
            dir: dir.to_path_buf(),
            maestra,
        })
    }

    fn clave_de(&self, salt: &[u8]) -> Key<Aes256Gcm> {
        let hk = Hkdf::<Sha256>::new(Some(salt), &self.maestra);
        let mut clave = [0u8; 32];
        // El info ata la clave derivada a su proposito.
        hk.expand(b"aegis-rollback-shadow", &mut clave)
            .expect("32 bytes cabe en la salida de HKDF-SHA256");
        let k = *Key::<Aes256Gcm>::from_slice(&clave);
        clave.zeroize();
        k
    }

    /// Guarda una copia-sombra del contenido original de un fichero. La ruta
    /// original se guarda DENTRO del texto cifrado, para recuperarla al revertir
    /// sin dejarla en claro en el nombre del fichero.
    pub fn guardar(&self, ruta_original: &[u8], contenido: &[u8]) -> Result<SombraId, SombraError> {
        let id = SombraId::generar();

        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut nonce);

        // plaintext = len_ruta(u32 be) || ruta || contenido
        let mut plano = Vec::with_capacity(4 + ruta_original.len() + contenido.len());
        plano.extend_from_slice(&(ruta_original.len() as u32).to_be_bytes());
        plano.extend_from_slice(ruta_original);
        plano.extend_from_slice(contenido);

        let cifrador = Aes256Gcm::new(&self.clave_de(&salt));
        let ct = cifrador
            .encrypt(Nonce::from_slice(&nonce), plano.as_ref())
            .map_err(|_| SombraError::Descifrado)?;

        // blob = salt || nonce || ciphertext
        let mut blob = Vec::with_capacity(SALT_LEN + NONCE_LEN + ct.len());
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        plano.zeroize();

        std::fs::write(self.dir.join(id.hex()), &blob)?;
        Ok(id)
    }

    /// Recupera el contenido original y su ruta desde una copia-sombra.
    pub fn recuperar(&self, id: SombraId) -> Result<(Vec<u8>, Vec<u8>), SombraError> {
        let blob = std::fs::read(self.dir.join(id.hex()))?;
        if blob.len() < SALT_LEN + NONCE_LEN {
            return Err(SombraError::Truncada);
        }
        let (salt, resto) = blob.split_at(SALT_LEN);
        let (nonce, ct) = resto.split_at(NONCE_LEN);

        let cifrador = Aes256Gcm::new(&self.clave_de(salt));
        let plano = cifrador
            .decrypt(Nonce::from_slice(nonce), ct)
            .map_err(|_| SombraError::Descifrado)?;

        if plano.len() < 4 {
            return Err(SombraError::Truncada);
        }
        let len_ruta = u32::from_be_bytes([plano[0], plano[1], plano[2], plano[3]]) as usize;
        if plano.len() < 4 + len_ruta {
            return Err(SombraError::Truncada);
        }
        let ruta = plano[4..4 + len_ruta].to_vec();
        let contenido = plano[4 + len_ruta..].to_vec();
        Ok((ruta, contenido))
    }

    /// Borra una copia-sombra (tras revertir, o al caducar).
    pub fn purgar(&self, id: SombraId) -> Result<(), SombraError> {
        match std::fs::remove_file(self.dir.join(id.hex())) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}
