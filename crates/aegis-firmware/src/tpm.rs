//! Lectura de PCRs del TPM 2.0.
//!
//! # Dos interfaces, en orden de preferencia
//!
//! 1. **sysfs** (`/sys/class/tpm/tpm0/pcr-<alg>/<n>`, kernel ≥ 5.12). Es la
//!    correcta para un producto de seguridad de solo lectura: no requiere root,
//!    no toma el dispositivo en exclusiva, no puede perturbar a otro usuario del
//!    TPM y no hay que ensamblar comandos. Se prefiere siempre que este.
//! 2. **dispositivo de caracteres** (`/dev/tpmrm0`), cuando sysfs no expone los
//!    PCRs. Se envia el comando `TPM2_PCR_Read` en crudo. Se usa `/dev/tpmrm0`
//!    (el gestor de recursos del kernel, compartible) y NO `/dev/tpm0`, que es
//!    de apertura exclusiva: un segundo proceso recibe `EBUSY`, y ese `EBUSY`
//!    significa "en uso", no "ausente".
//!
//! # La regla que no se negocia
//!
//! Si no hay TPM, **no se inventa un PCR**. Un valor de 32 bytes que parece un
//! PCR pero no viene de un TPM es una atestacion falsificada, y es
//! estrictamente peor que informar "no disponible", porque la politica de aguas
//! abajo confiaria en el. La deteccion de bancos tampoco se inventa: NO existe
//! ningun fichero `active_banks` —enumerarlo seria leer una ruta que no hay en
//! ningun kernel—; los bancos se descubren enumerando los directorios
//! `pcr-<alg>`.

use crate::tcg::{HashAlg, NUM_PCRS};

/// Directorio de clase del primer TPM.
pub const DIR_TPM: &str = "/sys/class/tpm/tpm0";

/// Error al leer el TPM.
#[derive(Debug, thiserror::Error)]
pub enum TpmError {
    /// No hay TPM en esta maquina.
    #[error("no hay TPM en esta maquina (sin {0})")]
    Ausente(&'static str),
    /// El TPM es de la generacion 1.2, incompatible con los comandos 2.0.
    #[error("el TPM es 1.2, no 2.0: usa un juego de comandos distinto")]
    Tpm12,
    /// Un valor de PCR de sysfs no tiene el formato esperado.
    #[error("el PCR {pcr} del banco {alg:?} no se pudo interpretar: {detail}")]
    PcrInvalido {
        /// Banco.
        alg: HashAlg,
        /// Numero de PCR.
        pcr: usize,
        /// Motivo.
        detail: &'static str,
    },
    /// Error de E/S.
    #[error("error de E/S leyendo el TPM en {op}: {source}")]
    Io {
        /// Operacion.
        op: &'static str,
        /// Causa.
        #[source]
        source: std::io::Error,
    },
    /// El TPM respondio con un codigo de error.
    #[error("el TPM devolvio el codigo de respuesta {0:#010x}")]
    RespuestaTpm(u32),
    /// La respuesta del TPM no se pudo interpretar.
    #[error("respuesta del TPM malformada: {0}")]
    RespuestaMalformada(&'static str),
}

/// Indica si esta maquina tiene un TPM accesible por sysfs.
pub fn hay_tpm() -> bool {
    std::path::Path::new(DIR_TPM).exists()
}

/// Version mayor del TPM (`tpm_version_major`), o `None` si no se pudo leer.
pub fn version_mayor() -> Option<u32> {
    std::fs::read_to_string(format!("{DIR_TPM}/tpm_version_major"))
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
}

/// Bancos de PCR activos, descubiertos enumerando los directorios `pcr-<alg>`.
///
/// NO se lee un fichero `active_banks`: no existe en ningun kernel. El kernel
/// crea un directorio `pcr-<alg>` por cada banco asignado, y esa es la unica
/// fuente fiable.
pub fn bancos_activos() -> Vec<HashAlg> {
    let mut bancos = Vec::new();
    let Ok(dir) = std::fs::read_dir(DIR_TPM) else {
        return bancos;
    };
    for e in dir.flatten() {
        let nombre = e.file_name();
        let Some(nombre) = nombre.to_str() else {
            continue;
        };
        if let Some(alg) = nombre.strip_prefix("pcr-") {
            for a in [
                HashAlg::Sha1,
                HashAlg::Sha256,
                HashAlg::Sha384,
                HashAlg::Sha512,
                HashAlg::Sm3_256,
            ] {
                if a.sysfs_name() == alg {
                    bancos.push(a);
                }
            }
        }
    }
    bancos.sort_by_key(|a| a.id());
    bancos
}

/// Interpreta un valor de PCR de sysfs: hex (mayuscula o minuscula) y un salto
/// de linea final.
pub fn parse_pcr_hex(texto: &str, alg: HashAlg) -> Option<Vec<u8>> {
    let t = texto.trim();
    if t.len() != alg.digest_len() * 2 {
        return None;
    }
    (0..t.len() / 2)
        .map(|i| u8::from_str_radix(&t[2 * i..2 * i + 2], 16).ok())
        .collect()
}

/// Lee un banco entero de PCRs por sysfs.
pub fn leer_banco_sysfs(alg: HashAlg) -> Result<crate::pcr::PcrBank, TpmError> {
    let dir = format!("{DIR_TPM}/pcr-{}", alg.sysfs_name());
    if !std::path::Path::new(&dir).exists() {
        return Err(TpmError::Ausente("directorio pcr-<alg>"));
    }
    let mut valores = Vec::with_capacity(NUM_PCRS);
    for pcr in 0..NUM_PCRS {
        let ruta = format!("{dir}/{pcr}");
        let texto = std::fs::read_to_string(&ruta).map_err(|source| TpmError::Io {
            op: "leer pcr sysfs",
            source,
        })?;
        let v = parse_pcr_hex(&texto, alg).ok_or(TpmError::PcrInvalido {
            alg,
            pcr,
            detail: "el valor no es hex de la longitud del banco",
        })?;
        valores.push(v);
    }
    Ok(crate::pcr::PcrBank { alg, valores })
}

// ------------------------------------------------------------------------
// Comando TPM2_PCR_Read en crudo, para la via del dispositivo de caracteres
// ------------------------------------------------------------------------

/// `TPM_ST_NO_SESSIONS`.
const TPM_ST_NO_SESSIONS: u16 = 0x8001;
/// `TPM_CC_PCR_Read`.
const TPM_CC_PCR_READ: u32 = 0x0000_017E;
/// `TPM_RC_SUCCESS`.
const TPM_RC_SUCCESS: u32 = 0x0000_0000;

/// Construye el comando `TPM2_PCR_Read` para un banco y un mapa de bits de PCRs.
///
/// Todo big-endian, al reves que el event log. El mapa de bits son 3 bytes:
/// bit 0 del byte 0 es el PCR 0, bit 7 del byte 0 es el PCR 7, el byte 1 cubre
/// 8-15 y el byte 2, 16-23.
///
/// Se expone y se prueba byte a byte porque un comando mal formado no da un
/// error claro: el TPM responde otra cosa, o nada, y el fallo se manifiesta
/// como un PCR equivocado mucho mas tarde.
pub fn construir_pcr_read(alg: HashAlg, bitmap: [u8; 3]) -> Vec<u8> {
    let mut cmd = Vec::with_capacity(20);
    cmd.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes()); // tag
    cmd.extend_from_slice(&20u32.to_be_bytes()); // commandSize (se rellena; es fijo 20)
    cmd.extend_from_slice(&TPM_CC_PCR_READ.to_be_bytes()); // commandCode
    cmd.extend_from_slice(&1u32.to_be_bytes()); // TPML_PCR_SELECTION.count = 1
    cmd.extend_from_slice(&alg.id().to_be_bytes()); // hashAlg
    cmd.push(3u8); // sizeofSelect
    cmd.extend_from_slice(&bitmap); // pcrSelect[3]
    debug_assert_eq!(cmd.len(), 20);
    cmd
}

/// Mapa de bits que selecciona un conjunto de PCRs.
pub fn bitmap_de(pcrs: &[u32]) -> [u8; 3] {
    let mut b = [0u8; 3];
    for &p in pcrs {
        if p < 24 {
            b[(p / 8) as usize] |= 1 << (p % 8);
        }
    }
    b
}

/// Un digest devuelto por `TPM2_PCR_Read`, con el numero de PCR que se pidio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcrLeido {
    /// Numero de PCR.
    pub pcr: u32,
    /// Valor.
    pub valor: Vec<u8>,
}

/// Lo que devuelve una respuesta de `TPM2_PCR_Read`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcrReadResp {
    /// Contador de actualizaciones de PCR del TPM.
    pub update_counter: u32,
    /// Mapa de bits de los PCRs REALMENTE devueltos.
    pub devuelto: [u8; 3],
    /// Digests devueltos, en el orden del mapa de bits.
    pub digests: Vec<Vec<u8>>,
}

/// Interpreta la respuesta de `TPM2_PCR_Read`.
///
/// El TPM devuelve COMO MUCHO 8 digests por llamada, y `pcrSelectionOut` (el
/// campo `devuelto`) dice cuales; el llamante tiene que quitar esos bits de su
/// peticion y repetir hasta vaciar el mapa. Interpretar 24 digests de una sola
/// respuesta es un error.
pub fn parse_pcr_read(resp: &[u8]) -> Result<PcrReadResp, TpmError> {
    let mut c = ByteReader::new(resp);
    let _tag = c.u16()?;
    let _size = c.u32()?;
    let rc = c.u32()?;
    if rc != TPM_RC_SUCCESS {
        return Err(TpmError::RespuestaTpm(rc));
    }
    let update_counter = c.u32()?;
    // pcrSelectionOut: count, luego {hashAlg u16, sizeofSelect u8, select[n]}.
    let sel_count = c.u32()?;
    if sel_count != 1 {
        return Err(TpmError::RespuestaMalformada(
            "se esperaba una unica seleccion de PCR",
        ));
    }
    let _alg = c.u16()?;
    let sizeof_select = c.u8()? as usize;
    if sizeof_select != 3 {
        return Err(TpmError::RespuestaMalformada("sizeofSelect no es 3"));
    }
    let sel = c.bytes(3)?;
    let devuelto = [sel[0], sel[1], sel[2]];
    // pcrValues: count, luego {size u16, digest[size]}.
    let val_count = c.u32()?;
    if val_count > 8 {
        return Err(TpmError::RespuestaMalformada(
            "mas de 8 digests en una respuesta",
        ));
    }
    let mut digests = Vec::new();
    for _ in 0..val_count {
        let size = c.u16()? as usize;
        digests.push(c.bytes(size)?);
    }
    Ok(PcrReadResp {
        update_counter,
        devuelto,
        digests,
    })
}

/// Lector de bytes big-endian con comprobacion de limites.
struct ByteReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    fn new(buf: &'a [u8]) -> ByteReader<'a> {
        ByteReader { buf, pos: 0 }
    }
    fn u8(&mut self) -> Result<u8, TpmError> {
        let b = *self
            .buf
            .get(self.pos)
            .ok_or(TpmError::RespuestaMalformada("respuesta truncada"))?;
        self.pos += 1;
        Ok(b)
    }
    fn u16(&mut self) -> Result<u16, TpmError> {
        let s = self
            .buf
            .get(self.pos..self.pos + 2)
            .ok_or(TpmError::RespuestaMalformada("respuesta truncada"))?;
        self.pos += 2;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Result<u32, TpmError> {
        let s = self
            .buf
            .get(self.pos..self.pos + 4)
            .ok_or(TpmError::RespuestaMalformada("respuesta truncada"))?;
        self.pos += 4;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn bytes(&mut self, n: usize) -> Result<Vec<u8>, TpmError> {
        let s = self
            .buf
            .get(self.pos..self.pos + n)
            .ok_or(TpmError::RespuestaMalformada("respuesta truncada"))?;
        self.pos += n;
        Ok(s.to_vec())
    }
}
