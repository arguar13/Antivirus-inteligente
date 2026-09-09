//! Constantes del estandar TCG (Trusted Computing Group).
//!
//! Los numeros de este modulo no son elecciones de diseno: son el estandar, y
//! equivocarse en uno no da un error de compilacion, da una medicion que parece
//! valida y no lo es. Cada valor lleva su referencia para que sea verificable
//! contra la especificacion, no contra la memoria de quien lo escribio.

/// Algoritmos de hash, en la codificacion `TPM_ALG_ID` (TCG Algorithm Registry).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HashAlg {
    /// SHA-1 (`TPM_ALG_SHA1`).
    Sha1,
    /// SHA-256 (`TPM_ALG_SHA256`).
    Sha256,
    /// SHA-384 (`TPM_ALG_SHA384`).
    Sha384,
    /// SHA-512 (`TPM_ALG_SHA512`).
    Sha512,
    /// SM3-256 (`TPM_ALG_SM3_256`).
    Sm3_256,
}

impl HashAlg {
    /// Identificador `TPM_ALG_ID` de 16 bits.
    pub fn id(self) -> u16 {
        match self {
            HashAlg::Sha1 => 0x0004,
            HashAlg::Sha256 => 0x000B,
            HashAlg::Sha384 => 0x000C,
            HashAlg::Sha512 => 0x000D,
            HashAlg::Sm3_256 => 0x0012,
        }
    }

    /// Recupera el algoritmo a partir de su identificador.
    pub fn from_id(id: u16) -> Option<HashAlg> {
        Some(match id {
            0x0004 => HashAlg::Sha1,
            0x000B => HashAlg::Sha256,
            0x000C => HashAlg::Sha384,
            0x000D => HashAlg::Sha512,
            0x0012 => HashAlg::Sm3_256,
            _ => return None,
        })
    }

    /// Tamano del digest en bytes.
    pub fn digest_len(self) -> usize {
        match self {
            HashAlg::Sha1 => 20,
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
            HashAlg::Sha512 => 64,
            HashAlg::Sm3_256 => 32,
        }
    }

    /// Nombre corto, como lo publica el kernel en `pcr-<alg>`.
    pub fn sysfs_name(self) -> &'static str {
        match self {
            HashAlg::Sha1 => "sha1",
            HashAlg::Sha256 => "sha256",
            HashAlg::Sha384 => "sha384",
            HashAlg::Sha512 => "sha512",
            HashAlg::Sm3_256 => "sm3",
        }
    }
}

/// Numero de PCRs de una plataforma TCG PC Client.
pub const NUM_PCRS: usize = 24;

/// Tipos de evento del event log (`TCG_PCR_EVENT` `EventType`), los que
/// interesan a la deteccion de bootkits. La lista completa es larga; aqui estan
/// los que el motor sabe interpretar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    /// `EV_PREBOOT_CERT` (0x00000000).
    PrebootCert,
    /// `EV_POST_CODE` (0x00000001): firmware que se mide a si mismo.
    PostCode,
    /// `EV_NO_ACTION` (0x00000003): NO extiende el PCR. El primer evento del
    /// log crypto-agil es de este tipo y declara el formato.
    NoAction,
    /// `EV_SEPARATOR` (0x00000004): marca el fin de la fase de firmware.
    Separator,
    /// `EV_ACTION` (0x00000005).
    Action,
    /// `EV_EVENT_TAG` (0x00000006).
    EventTag,
    /// `EV_S_CRTM_CONTENTS` (0x00000007).
    SCrtmContents,
    /// `EV_S_CRTM_VERSION` (0x00000008).
    SCrtmVersion,
    /// `EV_EFI_VARIABLE_DRIVER_CONFIG` (0x80000001): mide db/dbx/PK/KEK.
    EfiVariableDriverConfig,
    /// `EV_EFI_VARIABLE_BOOT` (0x80000002): mide BootOrder y las Boot####.
    EfiVariableBoot,
    /// `EV_EFI_BOOT_SERVICES_APPLICATION` (0x80000003): mide el binario
    /// arrancado —el bootloader—, el objetivo directo de un bootkit.
    EfiBootServicesApplication,
    /// `EV_EFI_BOOT_SERVICES_DRIVER` (0x80000004).
    EfiBootServicesDriver,
    /// `EV_EFI_GPT_EVENT` (0x80000006): mide la tabla de particiones.
    EfiGptEvent,
    /// `EV_EFI_VARIABLE_AUTHORITY` (0x800000E0): la clave con la que se validó
    /// el binario arrancado.
    EfiVariableAuthority,
    /// Cualquier otro tipo, con su valor crudo.
    Other(u32),
}

impl EventType {
    /// Recupera el tipo a partir de su valor.
    pub fn from_u32(v: u32) -> EventType {
        match v {
            0x0000_0000 => EventType::PrebootCert,
            0x0000_0001 => EventType::PostCode,
            0x0000_0003 => EventType::NoAction,
            0x0000_0004 => EventType::Separator,
            0x0000_0005 => EventType::Action,
            0x0000_0006 => EventType::EventTag,
            0x0000_0007 => EventType::SCrtmContents,
            0x0000_0008 => EventType::SCrtmVersion,
            0x8000_0001 => EventType::EfiVariableDriverConfig,
            0x8000_0002 => EventType::EfiVariableBoot,
            0x8000_0003 => EventType::EfiBootServicesApplication,
            0x8000_0004 => EventType::EfiBootServicesDriver,
            0x8000_0006 => EventType::EfiGptEvent,
            0x8000_00E0 => EventType::EfiVariableAuthority,
            otro => EventType::Other(otro),
        }
    }

    /// Valor de 32 bits.
    pub fn as_u32(self) -> u32 {
        match self {
            EventType::PrebootCert => 0x0000_0000,
            EventType::PostCode => 0x0000_0001,
            EventType::NoAction => 0x0000_0003,
            EventType::Separator => 0x0000_0004,
            EventType::Action => 0x0000_0005,
            EventType::EventTag => 0x0000_0006,
            EventType::SCrtmContents => 0x0000_0007,
            EventType::SCrtmVersion => 0x0000_0008,
            EventType::EfiVariableDriverConfig => 0x8000_0001,
            EventType::EfiVariableBoot => 0x8000_0002,
            EventType::EfiBootServicesApplication => 0x8000_0003,
            EventType::EfiBootServicesDriver => 0x8000_0004,
            EventType::EfiGptEvent => 0x8000_0006,
            EventType::EfiVariableAuthority => 0x8000_00E0,
            EventType::Other(v) => v,
        }
    }

    /// Indica si el evento EXTIENDE el PCR.
    ///
    /// `EV_NO_ACTION` no lo hace: es informativo (el primer evento del log
    /// crypto-agil, por ejemplo, declara el formato y no se mide). Tratarlo como
    /// si extendiera rompe el recalculo del PCR, y es el error mas facil de
    /// cometer al reproducir un log.
    pub fn extiende_pcr(self) -> bool {
        !matches!(self, EventType::NoAction)
    }

    /// Nombre legible.
    pub fn as_str(self) -> &'static str {
        match self {
            EventType::PrebootCert => "EV_PREBOOT_CERT",
            EventType::PostCode => "EV_POST_CODE",
            EventType::NoAction => "EV_NO_ACTION",
            EventType::Separator => "EV_SEPARATOR",
            EventType::Action => "EV_ACTION",
            EventType::EventTag => "EV_EVENT_TAG",
            EventType::SCrtmContents => "EV_S_CRTM_CONTENTS",
            EventType::SCrtmVersion => "EV_S_CRTM_VERSION",
            EventType::EfiVariableDriverConfig => "EV_EFI_VARIABLE_DRIVER_CONFIG",
            EventType::EfiVariableBoot => "EV_EFI_VARIABLE_BOOT",
            EventType::EfiBootServicesApplication => "EV_EFI_BOOT_SERVICES_APPLICATION",
            EventType::EfiBootServicesDriver => "EV_EFI_BOOT_SERVICES_DRIVER",
            EventType::EfiGptEvent => "EV_EFI_GPT_EVENT",
            EventType::EfiVariableAuthority => "EV_EFI_VARIABLE_AUTHORITY",
            EventType::Other(_) => "EV_OTHER",
        }
    }
}

/// Firma del evento que declara el formato crypto-agil (`Spec ID Event03`).
///
/// Va en el campo de evento del primer registro, que es de tipo
/// `EV_NO_ACTION`. Su presencia es lo que distingue un log crypto-agil
/// (`TCG_PCR_EVENT2`, multi-banco) de uno heredado de solo SHA-1.
pub const SPEC_ID_SIGNATURE: &[u8] = b"Spec ID Event03\0";
