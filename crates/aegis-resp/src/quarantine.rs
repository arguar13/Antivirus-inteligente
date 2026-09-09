//! Cuarentena cifrada con AES-256-GCM.
//!
//! # Por que se cifra
//!
//! No por confidencialidad: el contenido ya estaba en el disco en claro. Por
//! tres razones operativas:
//!
//! 1. **Impedir la reejecucion.** Un fichero en cuarentena no debe poder
//!    ejecutarse ni por accidente ni porque alguien copie el directorio.
//! 2. **Evitar que otro antivirus destruya la evidencia.** Si otro producto
//!    escanea nuestra cuarentena y encuentra muestras en claro, las
//!    "desinfecta" y la evidencia desaparece.
//! 3. **Integridad demostrable.** La etiqueta GCM prueba que lo restaurado es
//!    bit a bit el original. Sin autenticacion, restaurar seria un acto de fe.
//!
//! # Formato del contenedor
//!
//! ```text
//! [ 0..48]  cabecera en claro, AUTENTICADA como datos asociados (AAD)
//! [48..64]  etiqueta GCM de 128 bits
//! [64.. ]   texto cifrado
//! ```
//!
//! El texto en claro es `u32(len_metadatos) || metadatos || contenido`. Los
//! metadatos van DENTRO del cifrado, no en la cabecera: la ruta original de un
//! fichero puede ser en si misma informacion sensible.
//!
//! La cabecera va en claro pero autenticada: alterar `key_id` o el nonce para
//! intentar un ataque de sustitucion invalida la etiqueta y el descifrado falla.
//!
//! # Derivacion de claves
//!
//! Cada fichero se cifra con una clave DISTINTA, derivada por HKDF de la clave
//! maestra usando el identificador del fichero como sal. Eso elimina por
//! construccion la reutilizacion de nonce, que en GCM es catastrofica: revela
//! el flujo de claves y permite falsificar etiquetas. Depender de que el
//! generador aleatorio nunca repita un nonce de 96 bits seria confiar en algo
//! que no hace falta confiar.

use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Magia del contenedor.
const MAGIC: &[u8; 6] = b"AEGISQ";
/// Version del formato.
const VERSION: u16 = 1;
/// Longitud de la cabecera autenticada.
const HEADER_LEN: usize = 48;
/// Longitud de la etiqueta GCM.
const TAG_LEN: usize = 16;
/// Longitud del nonce de GCM.
const NONCE_LEN: usize = 12;
/// Contexto de derivacion. Cambiarlo invalida todas las claves derivadas.
const HKDF_INFO: &[u8] = b"aegis-quarantine-v1";
/// Extension de los contenedores. Se excluye del escaneo para evitar recursion.
pub const CONTAINER_EXT: &str = "aegisq";

/// Error de la cuarentena.
#[derive(Debug, thiserror::Error)]
pub enum QuarantineError {
    /// Error de entrada/salida.
    #[error("error de E/S en {path}: {source}")]
    Io {
        /// Ruta implicada.
        path: String,
        /// Causa.
        source: std::io::Error,
    },

    /// El contenedor no empieza por la magia esperada.
    #[error("no es un contenedor de cuarentena de AegisCore")]
    BadMagic,

    /// Version de formato desconocida.
    #[error("version de contenedor {found} desconocida; esta version entiende hasta la {VERSION}")]
    BadVersion {
        /// Version encontrada.
        found: u16,
    },

    /// El contenedor esta truncado.
    #[error("contenedor truncado: {len} bytes, se necesitan al menos {min}")]
    Truncated {
        /// Bytes disponibles.
        len: usize,
        /// Minimo necesario.
        min: usize,
    },

    /// La autenticacion fallo: contenido o cabecera alterados, o clave erronea.
    #[error(
        "la verificacion de integridad fallo. El contenedor fue alterado, o se \
         esta usando una clave maestra distinta de la que lo cifro"
    )]
    IntegrityFailure,

    /// Los metadatos no son interpretables.
    #[error("metadatos del contenedor ilegibles: {0}")]
    BadMetadata(&'static str),

    /// La clave maestra no tiene el tamano correcto.
    #[error("la clave maestra debe tener 32 bytes, tiene {0}")]
    BadMasterKey(usize),

    /// El destino de restauracion ya existe.
    #[error("el destino {0} ya existe; restaurar encima destruiria ese fichero")]
    DestinationExists(String),
}

fn io_err(path: &Path, e: std::io::Error) -> QuarantineError {
    QuarantineError::Io {
        path: path.display().to_string(),
        source: e,
    }
}

/// Metadatos forenses que se conservan junto al contenido.
///
/// Restaurar solo el contenido no basta. Un fichero devuelto sin sus permisos
/// ni sus marcas de tiempo es evidencia destruida y, a menudo, una aplicacion
/// rota.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMetadata {
    /// Ruta original absoluta.
    pub original_path: PathBuf,
    /// Tamano en bytes.
    pub size: u64,
    /// SHA-256 del contenido original.
    pub sha256: [u8; 32],
    /// Modo POSIX, permisos y bits especiales.
    pub mode: u32,
    /// Propietario.
    pub uid: u32,
    /// Grupo.
    pub gid: u32,
    /// Modificacion, en nanosegundos desde la epoca.
    pub mtime_ns: i128,
    /// Ultimo acceso.
    pub atime_ns: i128,
    /// Instante de la puesta en cuarentena.
    pub quarantined_at_ns: i128,
    /// Motor que motivo la deteccion.
    pub engine: String,
    /// Detalle de la deteccion.
    pub reason: String,
}

impl FileMetadata {
    /// Serializa a texto de lineas `clave=valor`.
    ///
    /// Formato de texto y no binario a proposito: los metadatos son la parte
    /// forense del contenedor, y que sean legibles en cuanto se descifran vale
    /// mas que los pocos bytes que ahorraria una codificacion compacta.
    pub fn encode(&self) -> String {
        let mut s = String::new();
        // La ruta se codifica en hexadecimal porque puede contener saltos de
        // linea y bytes no UTF-8: un atacante puede crear un fichero cuyo
        // nombre inyecte lineas falsas en estos metadatos.
        s.push_str(&format!(
            "path_hex={}\n",
            hex(self.original_path.as_os_str().as_encoded_bytes())
        ));
        s.push_str(&format!("size={}\n", self.size));
        s.push_str(&format!("sha256={}\n", hex(&self.sha256)));
        s.push_str(&format!("mode={:o}\n", self.mode));
        s.push_str(&format!("uid={}\n", self.uid));
        s.push_str(&format!("gid={}\n", self.gid));
        s.push_str(&format!("mtime_ns={}\n", self.mtime_ns));
        s.push_str(&format!("atime_ns={}\n", self.atime_ns));
        s.push_str(&format!("quarantined_at_ns={}\n", self.quarantined_at_ns));
        s.push_str(&format!("engine_hex={}\n", hex(self.engine.as_bytes())));
        s.push_str(&format!("reason_hex={}\n", hex(self.reason.as_bytes())));
        s
    }

    /// Analiza los metadatos.
    pub fn decode(texto: &str) -> Result<FileMetadata, QuarantineError> {
        let mut m = std::collections::HashMap::new();
        for l in texto.lines() {
            if let Some((k, v)) = l.split_once('=') {
                m.insert(k, v);
            }
        }
        let get = |k: &str| m.get(k).copied();

        let path_bytes = unhex(get("path_hex").ok_or(QuarantineError::BadMetadata("path_hex"))?)
            .ok_or(QuarantineError::BadMetadata("path_hex mal codificado"))?;
        let sha_bytes = unhex(get("sha256").ok_or(QuarantineError::BadMetadata("sha256"))?)
            .ok_or(QuarantineError::BadMetadata("sha256 mal codificado"))?;
        if sha_bytes.len() != 32 {
            return Err(QuarantineError::BadMetadata("sha256 no mide 32 bytes"));
        }
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&sha_bytes);

        let num = |k: &'static str| -> Result<u64, QuarantineError> {
            get(k)
                .and_then(|v| v.parse().ok())
                .ok_or(QuarantineError::BadMetadata(k))
        };
        let inum = |k: &'static str| -> Result<i128, QuarantineError> {
            get(k)
                .and_then(|v| v.parse().ok())
                .ok_or(QuarantineError::BadMetadata(k))
        };

        Ok(FileMetadata {
            original_path: PathBuf::from(std::ffi::OsString::from(
                String::from_utf8_lossy(&path_bytes).into_owned(),
            )),
            size: num("size")?,
            sha256,
            mode: get("mode")
                .and_then(|v| u32::from_str_radix(v, 8).ok())
                .ok_or(QuarantineError::BadMetadata("mode"))?,
            uid: num("uid")? as u32,
            gid: num("gid")? as u32,
            mtime_ns: inum("mtime_ns")?,
            atime_ns: inum("atime_ns")?,
            quarantined_at_ns: inum("quarantined_at_ns")?,
            engine: unhex(get("engine_hex").unwrap_or(""))
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default(),
            reason: unhex(get("reason_hex").unwrap_or(""))
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default(),
        })
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Identificador de un elemento en cuarentena.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct QuarantineId(pub [u8; 16]);

impl QuarantineId {
    /// Genera un identificador aleatorio.
    pub fn generate() -> QuarantineId {
        let mut b = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut b);
        QuarantineId(b)
    }

    /// Representacion hexadecimal.
    pub fn to_hex(self) -> String {
        hex(&self.0)
    }

    /// Analiza una representacion hexadecimal.
    pub fn from_hex(s: &str) -> Option<QuarantineId> {
        let b = unhex(s)?;
        if b.len() != 16 {
            return None;
        }
        let mut id = [0u8; 16];
        id.copy_from_slice(&b);
        Some(QuarantineId(id))
    }
}

impl std::fmt::Display for QuarantineId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Deriva la clave de un fichero a partir de la maestra.
///
/// Clave distinta por fichero: comprometer una no ayuda con las demas, y hace
/// imposible reutilizar un nonce con la misma clave aunque el generador
/// aleatorio fallara.
fn derive_key(master: &[u8], id: QuarantineId) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(&id.0), master);
    let mut okm = Zeroizing::new([0u8; 32]);
    // `expand` solo falla si la longitud pedida excede 255*32 bytes; 32 no.
    hk.expand(HKDF_INFO, okm.as_mut())
        .expect("32 bytes siempre caben en la salida de HKDF-SHA256");
    okm
}

/// Almacen de cuarentena.
pub struct Quarantine {
    dir: PathBuf,
    master: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for Quarantine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // La clave maestra no se imprime jamas, ni siquiera en Debug: los
        // volcados de depuracion acaban en registros y en informes de fallo.
        f.debug_struct("Quarantine")
            .field("dir", &self.dir)
            .field("master", &"<oculta>")
            .finish()
    }
}

impl Quarantine {
    /// Abre o crea un almacen.
    ///
    /// La clave maestra deberia venir sellada en el TPM. Cuando no hay TPM se
    /// guarda en un fichero con permisos 0600 dentro del almacen, y esa
    /// degradacion se documenta en vez de ocultarse.
    pub fn open(dir: &Path) -> Result<Quarantine, QuarantineError> {
        std::fs::create_dir_all(dir).map_err(|e| io_err(dir, e))?;
        // Solo el propietario entra. La ACL sola no basta contra un
        // administrador, pero es la primera barrera y no cuesta nada.
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| io_err(dir, e))?;

        let key_path = dir.join("master.key");
        let master = if key_path.exists() {
            let b = std::fs::read(&key_path).map_err(|e| io_err(&key_path, e))?;
            if b.len() != 32 {
                return Err(QuarantineError::BadMasterKey(b.len()));
            }
            Zeroizing::new(b)
        } else {
            let mut b = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut b);
            // Se crea con 0600 ANTES de escribir el contenido: crearla legible
            // y ajustar despues deja una ventana en la que la clave es visible.
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&key_path)
                .map_err(|e| io_err(&key_path, e))?;
            f.write_all(&b).map_err(|e| io_err(&key_path, e))?;
            f.sync_all().map_err(|e| io_err(&key_path, e))?;
            Zeroizing::new(b)
        };

        Ok(Quarantine {
            dir: dir.to_path_buf(),
            master,
        })
    }

    /// Ruta del contenedor de un identificador.
    pub fn container_path(&self, id: QuarantineId) -> PathBuf {
        self.dir.join(format!("{}.{}", id.to_hex(), CONTAINER_EXT))
    }

    /// Pone un fichero en cuarentena y **elimina el original**.
    pub fn quarantine_file(
        &self,
        path: &Path,
        engine: &str,
        reason: &str,
    ) -> Result<QuarantineId, QuarantineError> {
        let md = std::fs::metadata(path).map_err(|e| io_err(path, e))?;
        let contenido = std::fs::read(path).map_err(|e| io_err(path, e))?;

        let mut h = Sha256::new();
        h.update(&contenido);
        let sha256: [u8; 32] = h.finalize().into();

        let ahora_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i128)
            .unwrap_or(0);

        let meta = FileMetadata {
            original_path: path.canonicalize().unwrap_or_else(|_| path.to_path_buf()),
            size: md.len(),
            sha256,
            mode: md.permissions().mode(),
            uid: md.uid(),
            gid: md.gid(),
            mtime_ns: i128::from(md.mtime()) * 1_000_000_000 + i128::from(md.mtime_nsec()),
            atime_ns: i128::from(md.atime()) * 1_000_000_000 + i128::from(md.atime_nsec()),
            quarantined_at_ns: ahora_ns,
            engine: engine.to_string(),
            reason: reason.to_string(),
        };

        let id = QuarantineId::generate();
        let contenedor = self.seal(id, &meta, &contenido)?;

        let destino = self.container_path(id);
        // Escritura atomica: se escribe a un temporal y se renombra. Si el
        // proceso muere a mitad, no queda un contenedor a medias que parezca
        // valido y cuyo original ya se borro.
        let tmp = destino.with_extension("tmp");
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|e| io_err(&tmp, e))?;
            f.write_all(&contenedor).map_err(|e| io_err(&tmp, e))?;
            f.sync_all().map_err(|e| io_err(&tmp, e))?;
        }
        std::fs::rename(&tmp, &destino).map_err(|e| io_err(&destino, e))?;

        // El original se elimina SOLO despues de que el contenedor este en
        // disco y sincronizado. Al reves, un corte de corriente perderia el
        // fichero para siempre.
        std::fs::remove_file(path).map_err(|e| io_err(path, e))?;

        Ok(id)
    }

    /// Cifra metadatos y contenido en un contenedor.
    fn seal(
        &self,
        id: QuarantineId,
        meta: &FileMetadata,
        contenido: &[u8],
    ) -> Result<Vec<u8>, QuarantineError> {
        let meta_txt = meta.encode();
        let meta_bytes = meta_txt.as_bytes();

        let mut claro = Vec::with_capacity(4 + meta_bytes.len() + contenido.len());
        claro.extend_from_slice(&(meta_bytes.len() as u32).to_le_bytes());
        claro.extend_from_slice(meta_bytes);
        claro.extend_from_slice(contenido);

        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        // Cabecera: se construye antes de cifrar porque es el AAD.
        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(MAGIC);
        header.extend_from_slice(&VERSION.to_le_bytes());
        header.extend_from_slice(&id.0);
        header.extend_from_slice(&nonce_bytes);
        header.extend_from_slice(&(claro.len() as u64).to_le_bytes());
        header.extend_from_slice(&[0u8; 4]); // reservado
        debug_assert_eq!(header.len(), HEADER_LEN);

        let clave = derive_key(&self.master, id);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(clave.as_ref()));
        let cifrado = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &claro,
                    aad: &header,
                },
            )
            .map_err(|_| QuarantineError::IntegrityFailure)?;

        // aes-gcm devuelve texto cifrado con la etiqueta al final. Se separa
        // para dejarla en la cabecera, que es donde la espera el formato.
        let (ct, tag) = cifrado.split_at(cifrado.len() - TAG_LEN);

        let mut salida = Vec::with_capacity(HEADER_LEN + TAG_LEN + ct.len());
        salida.extend_from_slice(&header);
        salida.extend_from_slice(tag);
        salida.extend_from_slice(ct);
        Ok(salida)
    }

    /// Descifra y verifica un contenedor.
    pub fn open_container(&self, bytes: &[u8]) -> Result<(FileMetadata, Vec<u8>), QuarantineError> {
        let minimo = HEADER_LEN + TAG_LEN;
        if bytes.len() < minimo {
            return Err(QuarantineError::Truncated {
                len: bytes.len(),
                min: minimo,
            });
        }
        if &bytes[0..6] != MAGIC {
            return Err(QuarantineError::BadMagic);
        }
        let version = u16::from_le_bytes([bytes[6], bytes[7]]);
        if version != VERSION {
            return Err(QuarantineError::BadVersion { found: version });
        }

        let mut id = [0u8; 16];
        id.copy_from_slice(&bytes[8..24]);
        let id = QuarantineId(id);
        let nonce = &bytes[24..36];

        let header = &bytes[..HEADER_LEN];
        let tag = &bytes[HEADER_LEN..HEADER_LEN + TAG_LEN];
        let ct = &bytes[HEADER_LEN + TAG_LEN..];

        let mut con_tag = Vec::with_capacity(ct.len() + TAG_LEN);
        con_tag.extend_from_slice(ct);
        con_tag.extend_from_slice(tag);

        let clave = derive_key(&self.master, id);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(clave.as_ref()));
        let claro = cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: &con_tag,
                    aad: header,
                },
            )
            .map_err(|_| QuarantineError::IntegrityFailure)?;

        if claro.len() < 4 {
            return Err(QuarantineError::BadMetadata(
                "longitud de metadatos ausente",
            ));
        }
        let meta_len = u32::from_le_bytes([claro[0], claro[1], claro[2], claro[3]]) as usize;
        if claro.len() < 4 + meta_len {
            return Err(QuarantineError::BadMetadata("metadatos truncados"));
        }
        let meta_txt = String::from_utf8_lossy(&claro[4..4 + meta_len]).into_owned();
        let meta = FileMetadata::decode(&meta_txt)?;
        let contenido = claro[4 + meta_len..].to_vec();

        Ok((meta, contenido))
    }

    /// Lee un elemento de la cuarentena sin restaurarlo.
    pub fn inspect(&self, id: QuarantineId) -> Result<FileMetadata, QuarantineError> {
        let p = self.container_path(id);
        let bytes = std::fs::read(&p).map_err(|e| io_err(&p, e))?;
        Ok(self.open_container(&bytes)?.0)
    }

    /// Restaura un elemento a su ruta original, o a `dest` si se indica.
    pub fn restore(
        &self,
        id: QuarantineId,
        dest: Option<&Path>,
    ) -> Result<PathBuf, QuarantineError> {
        let p = self.container_path(id);
        let bytes = std::fs::read(&p).map_err(|e| io_err(&p, e))?;
        let (meta, contenido) = self.open_container(&bytes)?;

        let destino = dest
            .map(|d| d.to_path_buf())
            .unwrap_or_else(|| meta.original_path.clone());

        // Se comprueba el destino ANTES de escribir: restaurar encima de algo
        // que ocupa ya esa ruta destruiria ese fichero.
        if destino.exists() {
            return Err(QuarantineError::DestinationExists(
                destino.display().to_string(),
            ));
        }
        if let Some(padre) = destino.parent() {
            std::fs::create_dir_all(padre).map_err(|e| io_err(padre, e))?;
        }

        let tmp = destino.with_extension("aegis-restore-tmp");
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|e| io_err(&tmp, e))?;
            f.write_all(&contenido).map_err(|e| io_err(&tmp, e))?;
            f.sync_all().map_err(|e| io_err(&tmp, e))?;
        }
        std::fs::rename(&tmp, &destino).map_err(|e| io_err(&destino, e))?;

        // Restaurar los atributos: sin ellos la evidencia queda destruida y a
        // menudo la aplicacion que usaba el fichero se rompe.
        std::fs::set_permissions(&destino, std::fs::Permissions::from_mode(meta.mode))
            .map_err(|e| io_err(&destino, e))?;
        restore_owner(&destino, meta.uid, meta.gid);
        restore_times(&destino, meta.atime_ns, meta.mtime_ns);

        std::fs::remove_file(&p).map_err(|e| io_err(&p, e))?;
        Ok(destino)
    }

    /// Lista los identificadores en cuarentena.
    pub fn list(&self) -> Result<Vec<QuarantineId>, QuarantineError> {
        let mut salida = Vec::new();
        let dir = std::fs::read_dir(&self.dir).map_err(|e| io_err(&self.dir, e))?;
        for e in dir.flatten() {
            let nombre = e.file_name();
            let Some(n) = nombre.to_str() else { continue };
            let Some(stem) = n.strip_suffix(&format!(".{CONTAINER_EXT}")) else {
                continue;
            };
            if let Some(id) = QuarantineId::from_hex(stem) {
                salida.push(id);
            }
        }
        salida.sort();
        Ok(salida)
    }

    /// Elimina definitivamente un elemento de la cuarentena.
    pub fn purge(&self, id: QuarantineId) -> Result<(), QuarantineError> {
        let p = self.container_path(id);
        std::fs::remove_file(&p).map_err(|e| io_err(&p, e))
    }
}

fn restore_owner(path: &Path, uid: u32, gid: u32) {
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) else {
        return;
    };
    // SAFETY: `c` es una cadena C valida y viva durante la llamada. Si falla
    // (por falta de CAP_CHOWN) se ignora: es preferible restaurar el fichero
    // con el propietario equivocado que no restaurarlo.
    unsafe {
        libc::chown(c.as_ptr(), uid, gid);
    }
}

fn restore_times(path: &Path, atime_ns: i128, mtime_ns: i128) {
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) else {
        return;
    };
    let ts = |ns: i128| libc::timespec {
        tv_sec: (ns / 1_000_000_000) as libc::time_t,
        tv_nsec: (ns % 1_000_000_000) as i64,
    };
    let tiempos = [ts(atime_ns), ts(mtime_ns)];
    // SAFETY: cadena C valida y array de dos timespec, que es lo que utimensat
    // espera. AT_FDCWD con ruta absoluta o relativa al directorio actual.
    unsafe {
        libc::utimensat(libc::AT_FDCWD, c.as_ptr(), tiempos.as_ptr(), 0);
    }
}
