//! Secure Boot, variables UEFI y la lista de revocacion DBX.
//!
//! # Que se comprueba
//!
//! - **Secure Boot esta imponiendo de verdad.** No basta con `SecureBoot == 1`:
//!   con `SetupMode == 1` cualquiera puede matricular una clave sin
//!   autenticacion, que es exactamente el estado que busca un bootkit. Hace
//!   falta `SecureBoot == 1` **y** `SetupMode == 0`.
//! - **La lista de revocacion (DBX).** UEFI publica en `dbx` los hashes de los
//!   gestores de arranque que se sabe que estan comprometidos. Un BlackLotus se
//!   revoca anadiendo su hash aqui; comprobar si el binario arrancado esta en la
//!   DBX es la deteccion directa de un bootkit conocido.
//!
//! # El prefijo de 4 bytes: el detalle que rompe todo lo demas
//!
//! Cada fichero de `efivarfs` empieza con 4 bytes de ATRIBUTOS en little-endian
//! y solo despues vienen los datos de la variable: `file_size == 4 + data_size`.
//! Saltarse ese prefijo desplaza cada offset del analisis de la DBX, y
//! `SignatureListSize` se lee como basura: el analizador o desborda o emite
//! hashes falsos. Es el error numero uno de todo el firmware, y aqui esta
//! aislado en [`leer_variable`], que devuelve por separado atributos y datos.
//!
//! # Solo lectura, jamas escritura
//!
//! Los ficheros de `efivarfs` se abren **estrictamente** en solo lectura.
//! Borrar variables EFI ha dejado inservibles maquinas reales; `efivarfs` marca
//! las variables no incluidas en su lista blanca como inmutables justo por eso.
//! Un producto de deteccion no escribe nunca.

use crate::guid::Guid;

/// Punto de montaje de `efivarfs`.
pub const DIR_EFIVARS: &str = "/sys/firmware/efi/efivars";

/// Directorio que solo existe si la maquina arranco por UEFI.
pub const DIR_EFI: &str = "/sys/firmware/efi";

/// GUID de las variables globales EFI (`SecureBoot`, `SetupMode`, `PK`...).
pub const EFI_GLOBAL: Guid = Guid::from_fields(
    0x8be4df61,
    0x93ca,
    0x11d2,
    [0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c],
);

/// GUID de la base de datos de seguridad de imagenes (`db`, `dbx`).
pub const EFI_IMAGE_SECURITY_DATABASE: Guid = Guid::from_fields(
    0xd719b2cb,
    0x3d3a,
    0x4596,
    [0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f],
);

/// GUID de tipo `EFI_CERT_SHA256`: la firma es un hash SHA-256 de 32 bytes.
pub const EFI_CERT_SHA256: Guid = Guid::from_fields(
    0xc1c41626,
    0x504c,
    0x4092,
    [0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28],
);

/// GUID de tipo `EFI_CERT_X509_SHA256`: hash de un certificado (32 bytes) mas
/// una marca de tiempo `EFI_TIME` de 16 bytes. `SignatureSize` = 64, no 56: la
/// `EFI_TIME` mide 16 bytes, no 8.
pub const EFI_CERT_X509_SHA256: Guid = Guid::from_fields(
    0x3bd2a492,
    0x96c0,
    0x4079,
    [0xb4, 0x20, 0xfc, 0x40, 0xb6, 0x4e, 0x28, 0x07],
);

/// GUID de tipo `EFI_CERT_SHA384`. El GUID correcto es
/// `ff3e5307-9fd0-48c9-85f7-8ba0b6c92e83`; no confundir con `EFI_CERT_SHA224`.
pub const EFI_CERT_SHA384: Guid = Guid::from_fields(
    0xff3e5307,
    0x9fd0,
    0x48c9,
    [0x85, 0xf7, 0x8b, 0xa0, 0xb6, 0xc9, 0x2e, 0x83],
);

/// GUID de tipo `EFI_CERT_SHA512`.
pub const EFI_CERT_SHA512: Guid = Guid::from_fields(
    0x093e0fae,
    0xa6c4,
    0x4f50,
    [0x9f, 0x1b, 0xd4, 0x1e, 0x2b, 0x89, 0xc1, 0x9a],
);

/// GUID de tipo `EFI_CERT_X509`: un certificado X.509 completo.
pub const EFI_CERT_X509: Guid = Guid::from_fields(
    0xa5c059a1,
    0x94e4,
    0x4aa7,
    [0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72],
);

/// Bits de atributo de una variable EFI (UEFI 2.10, seccion 8.2).
pub mod attr {
    /// La variable persiste entre arranques.
    pub const NON_VOLATILE: u32 = 0x0000_0001;
    /// Accesible en tiempo de servicios de arranque.
    pub const BOOTSERVICE_ACCESS: u32 = 0x0000_0002;
    /// Accesible en tiempo de ejecucion.
    pub const RUNTIME_ACCESS: u32 = 0x0000_0004;
    /// Escritura autenticada por tiempo (la que llevan db/dbx).
    pub const TIME_BASED_AUTHENTICATED_WRITE_ACCESS: u32 = 0x0000_0020;
}

/// Error al leer una variable UEFI.
#[derive(Debug, thiserror::Error)]
pub enum UefiError {
    /// Esta maquina no arranco por UEFI.
    #[error("esta maquina no arranco por UEFI (sin {0})")]
    SinUefi(&'static str),
    /// `efivarfs` no esta montado, aunque hay UEFI.
    #[error("efivarfs no esta montado en {0}: las variables no son legibles")]
    EfivarsNoMontado(&'static str),
    /// La variable no existe.
    #[error("la variable UEFI {0} no existe")]
    Ausente(String),
    /// El fichero es mas corto que el prefijo de atributos.
    #[error("la variable {nombre} mide {len} bytes, menos que el prefijo de 4")]
    SinPrefijo {
        /// Nombre.
        nombre: String,
        /// Longitud.
        len: usize,
    },
    /// Error de E/S.
    #[error("error de E/S leyendo {nombre}: {source}")]
    Io {
        /// Nombre.
        nombre: String,
        /// Causa.
        #[source]
        source: std::io::Error,
    },
}

/// Indica si esta maquina arranco por UEFI.
pub fn hay_uefi() -> bool {
    std::path::Path::new(DIR_EFI).is_dir()
}

/// Indica si `efivarfs` esta montado.
pub fn efivars_montado() -> bool {
    std::fs::read_to_string("/proc/mounts")
        .map(|m| {
            m.lines()
                .any(|l| l.split_whitespace().nth(2) == Some("efivarfs"))
        })
        .unwrap_or(false)
}

/// Una variable UEFI leida: sus atributos y sus datos, ya sin el prefijo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Variable {
    /// Atributos (los 4 bytes de prefijo, en little-endian).
    pub attributes: u32,
    /// Datos, sin el prefijo de atributos.
    pub data: Vec<u8>,
}

impl Variable {
    /// Indica si un bit de atributo esta puesto.
    pub fn tiene(&self, bit: u32) -> bool {
        self.attributes & bit != 0
    }
}

/// Lee una variable UEFI de `efivarfs`, separando el prefijo de atributos.
///
/// `nombre_guid` es el nombre de fichero completo `<Nombre>-<GUID>`.
pub fn leer_variable(nombre_guid: &str) -> Result<Variable, UefiError> {
    let ruta = format!("{DIR_EFIVARS}/{nombre_guid}");
    // Solo lectura, SIEMPRE. Ver la nota de cabecera.
    let bytes = match std::fs::read(&ruta) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(UefiError::Ausente(nombre_guid.to_string()))
        }
        Err(source) => {
            return Err(UefiError::Io {
                nombre: nombre_guid.to_string(),
                source,
            })
        }
    };
    parse_variable_bytes(&bytes).map_err(|len| UefiError::SinPrefijo {
        nombre: nombre_guid.to_string(),
        len,
    })
}

/// Separa el prefijo de 4 bytes de atributos de los datos de la variable.
///
/// Es el analisis mas critico del modulo y por eso vive aparte de la E/S: el
/// prefijo de `efivarfs` es little-endian y `file_size == 4 + data_size`.
/// Devuelve el tamano recibido como error si es menor que el prefijo, para que
/// el llamante no lo interprete como una variable de datos vacios.
pub fn parse_variable_bytes(bytes: &[u8]) -> Result<Variable, usize> {
    if bytes.len() < 4 {
        return Err(bytes.len());
    }
    let attributes = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    Ok(Variable {
        attributes,
        data: bytes[4..].to_vec(),
    })
}

/// Estado de Secure Boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecureBootState {
    /// `SecureBoot`: el firmware dice que Secure Boot esta activo.
    pub secure_boot: bool,
    /// `SetupMode`: en modo configuracion cualquiera puede matricular claves.
    pub setup_mode: bool,
}

impl SecureBootState {
    /// Indica si Secure Boot esta IMPONIENDO de verdad.
    ///
    /// Requiere las dos condiciones: activo y fuera de modo configuracion. Un
    /// `secure_boot` a cierto con `setup_mode` a cierto NO impone nada.
    pub fn imponiendo(&self) -> bool {
        self.secure_boot && !self.setup_mode
    }
}

/// Lee el estado de Secure Boot de las variables globales.
pub fn estado_secure_boot() -> Result<SecureBootState, UefiError> {
    if !hay_uefi() {
        return Err(UefiError::SinUefi("/sys/firmware/efi"));
    }
    if !efivars_montado() {
        return Err(UefiError::EfivarsNoMontado(DIR_EFIVARS));
    }
    let sb = leer_variable(&formato_global("SecureBoot"))?;
    let sm = leer_variable(&formato_global("SetupMode"))?;
    Ok(SecureBootState {
        secure_boot: sb.data.first().copied().unwrap_or(0) == 1,
        setup_mode: sm.data.first().copied().unwrap_or(0) == 1,
    })
}

/// Nombre de fichero de una variable global.
fn formato_global(nombre: &str) -> String {
    format!("{nombre}-{}", EFI_GLOBAL.hyphenated())
}

/// Nombre de fichero de una variable de la base de datos de seguridad.
pub fn formato_db(nombre: &str) -> String {
    format!("{nombre}-{}", EFI_IMAGE_SECURITY_DATABASE.hyphenated())
}

// ------------------------------------------------------------------------
// Analisis de la DBX (lista de revocacion)
// ------------------------------------------------------------------------

/// Una firma de una lista de la DBX/db.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// Tipo de la firma (hash SHA-256, certificado X.509...).
    pub tipo: Guid,
    /// Propietario de la firma.
    pub owner: Guid,
    /// Datos de la firma, sin el GUID de propietario. Para un hash es el hash;
    /// para un `EFI_CERT_X509_SHA256`, el hash del certificado seguido de la
    /// marca de tiempo.
    pub datos: Vec<u8>,
}

impl Signature {
    /// Si la firma es un hash SHA-256 puro, devuelve sus 32 bytes.
    pub fn hash_sha256(&self) -> Option<&[u8]> {
        if self.tipo == EFI_CERT_SHA256 && self.datos.len() == 32 {
            Some(&self.datos)
        } else {
            None
        }
    }
}

/// Error al analizar una lista de firmas.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SigError {
    /// Un campo declara un tamano incoherente.
    #[error("lista de firmas malformada en el offset {offset}: {detail}")]
    Malformada {
        /// Offset.
        offset: usize,
        /// Motivo.
        detail: &'static str,
    },
}

/// Tamano de la cabecera `EFI_SIGNATURE_LIST` sin la cabecera de firma.
///
/// `SignatureType` (16) + `SignatureListSize` (4) + `SignatureHeaderSize` (4) +
/// `SignatureSize` (4).
const CAB_LISTA: usize = 28;

/// Analiza una `db`/`dbx`: una o varias `EFI_SIGNATURE_LIST` concatenadas.
///
/// El bucle recorre TODAS las listas —`p += SignatureListSize`— hasta agotar el
/// buffer: quedarse en la primera pierde la mayoria de las revocaciones, porque
/// la DBX real es una lista grande de hashes SHA-256 seguida de varias de
/// certificados. Cada tamano se comprueba antes de usarlo: la DBX es entrada
/// influida por un atacante tras un compromiso.
pub fn parse_signature_lists(buf: &[u8]) -> Result<Vec<Signature>, SigError> {
    let mut firmas = Vec::new();
    let mut pos = 0usize;

    while pos + CAB_LISTA <= buf.len() {
        let tipo = Guid::from_bytes(&buf[pos..pos + 16]);
        let list_size = u32_le(&buf[pos + 16..pos + 20]) as usize;
        let header_size = u32_le(&buf[pos + 20..pos + 24]) as usize;
        let sig_size = u32_le(&buf[pos + 24..pos + 28]) as usize;

        // Comprobaciones antes de dereferenciar nada.
        if list_size < CAB_LISTA + header_size {
            return Err(SigError::Malformada {
                offset: pos,
                detail: "SignatureListSize menor que sus cabeceras",
            });
        }
        if sig_size <= 16 {
            return Err(SigError::Malformada {
                offset: pos,
                detail: "SignatureSize no deja sitio ni para el GUID de propietario",
            });
        }
        if pos + list_size > buf.len() {
            return Err(SigError::Malformada {
                offset: pos,
                detail: "la lista se sale del buffer",
            });
        }

        // El area de firmas empieza tras la cabecera de lista y la de firma.
        let inicio = pos + CAB_LISTA + header_size;
        let fin = pos + list_size;
        let cuerpo = &buf[inicio..fin];
        if cuerpo.len() % sig_size != 0 {
            return Err(SigError::Malformada {
                offset: inicio,
                detail: "el area de firmas no es multiplo de SignatureSize",
            });
        }

        for chunk in cuerpo.chunks_exact(sig_size) {
            // SignatureSize INCLUYE los 16 bytes del GUID de propietario: el
            // dato empieza en +16 y mide SignatureSize - 16.
            let owner = Guid::from_bytes(&chunk[0..16]);
            let datos = chunk[16..].to_vec();
            firmas.push(Signature { tipo, owner, datos });
        }

        pos += list_size;
    }
    Ok(firmas)
}

/// La DBX ya analizada, con los hashes de revocacion a mano.
#[derive(Debug, Clone, Default)]
pub struct Dbx {
    /// Todas las firmas de la lista.
    pub firmas: Vec<Signature>,
}

impl Dbx {
    /// Analiza la DBX cruda (ya sin el prefijo de atributos).
    pub fn parse(buf: &[u8]) -> Result<Dbx, SigError> {
        Ok(Dbx {
            firmas: parse_signature_lists(buf)?,
        })
    }

    /// Indica si un hash SHA-256 Authenticode esta revocado.
    ///
    /// El hash tiene que ser el Authenticode del PE/COFF, NO un `sha256sum`
    /// plano del fichero: la DBX guarda el primero, que excluye a proposito el
    /// `CheckSum` de la cabecera, la entrada de la tabla de certificados y la
    /// seccion de certificados de atributo. Comparar contra un hash plano da
    /// siempre "no revocado", un falso negativo.
    pub fn revoca_hash(&self, authenticode_sha256: &[u8]) -> bool {
        self.firmas
            .iter()
            .filter_map(|f| f.hash_sha256())
            .any(|h| h == authenticode_sha256)
    }

    /// Numero de hashes SHA-256 de revocacion.
    pub fn num_hashes_sha256(&self) -> usize {
        self.firmas
            .iter()
            .filter(|f| f.hash_sha256().is_some())
            .count()
    }
}

/// Lee y analiza la DBX del sistema.
pub fn leer_dbx() -> Result<Dbx, UefiError> {
    let v = leer_variable(&formato_db("dbx"))?;
    Dbx::parse(&v.data).map_err(|_| UefiError::Io {
        nombre: "dbx".into(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, "DBX malformada"),
    })
}

fn u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}
