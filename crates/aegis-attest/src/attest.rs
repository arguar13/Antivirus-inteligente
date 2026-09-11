//! Codec de `TPMS_ATTEST` con su union `TPMS_QUOTE_INFO` (TPM 2.0, Parte 2).
//!
//! Esta es la estructura que el TPM FIRMA. La firma cubre EXACTAMENTE estos
//! bytes, asi que el verificador tiene que poder re-serializar lo que parsea y
//! obtener el original: si el parser interpreta un campo mal, el re-marshalado
//! no casa y se detecta antes de fiarse de nada. Por eso el codec expone
//! `parse` y `marshal` como inversas exactas, y las pruebas hacen round-trip
//! byte a byte sobre vectores construidos segun la spec.

use crate::codec::{CodecError, Escritor, Lector};
use aegis_firmware::HashAlg;

/// `TPM_GENERATED_VALUE`: los cuatro bytes magicos `0xFF 'T' 'C' 'G'` con los
/// que el TPM marca todo lo que genera el. Que esten es la primera comprobacion:
/// una estructura sin ellos no la produjo un TPM.
pub const TPM_GENERATED_VALUE: u32 = 0xFF54_4347;

/// `TPM_ST_ATTEST_QUOTE`: el tipo de atestacion que declara los PCR. Se exige
/// exactamente este: un TPM puede firmar otras cosas (certificacion de claves,
/// tiempo), y aceptarlas como si fueran un quote de arranque seria confundir una
/// afirmacion con otra.
pub const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;

/// Una `TPMS_PCR_SELECTION`: que banco de hash y que PCR se seleccionaron. El
/// mapa de bits tiene `sizeofSelect` bytes; el PCR *n* esta seleccionado si el
/// bit `n % 8` del byte `n / 8` esta a uno.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeleccionPcr {
    /// Banco de hash de esta seleccion.
    pub alg: HashAlg,
    /// Mapa de bits de PCR seleccionados (`sizeofSelect` bytes).
    pub bitmap: Vec<u8>,
}

/// La union `TPMS_QUOTE_INFO`: que se selecciono y el digest de sus valores.
///
/// Ojo: el quote NO contiene los valores de los PCR, solo su *digest*. Los
/// valores los presenta el agente por separado; el verificador recomputa su
/// digest y lo compara con este. Asi la firma del TPM ata los valores
/// presentados sin que el TPM tenga que firmarlos uno a uno.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuoteInfo {
    /// Selecciones de PCR (normalmente una, el banco SHA-256).
    pub selecciones: Vec<SeleccionPcr>,
    /// `pcrDigest`: hash de la concatenacion de los valores seleccionados.
    pub pcr_digest: Vec<u8>,
}

/// Un `TPMS_ATTEST` de tipo quote, ya parseado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attest {
    /// Debe ser [`TPM_GENERATED_VALUE`].
    pub magic: u32,
    /// Debe ser [`TPM_ST_ATTEST_QUOTE`].
    pub tipo: u16,
    /// `qualifiedSigner`: el Name de la clave que firma (ata el quote a una AK).
    pub qualified_signer: Vec<u8>,
    /// `extraData`: el nonce del desafio. Es lo que da frescura: sin el, un
    /// quote de un arranque limpio se reproduce eternamente.
    pub extra_data: Vec<u8>,
    /// `clock` de `TPMS_CLOCK_INFO`.
    pub clock: u64,
    /// `resetCount`.
    pub reset_count: u32,
    /// `restartCount`.
    pub restart_count: u32,
    /// `safe` (`TPMI_YES_NO`).
    pub safe: u8,
    /// `firmwareVersion` del TPM.
    pub firmware_version: u64,
    /// La informacion del quote propiamente dicha.
    pub quote: QuoteInfo,
}

/// Un fallo al parsear `TPMS_ATTEST`.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AttestError {
    /// El buffer se acabo o un `TPM2B` era invalido.
    #[error("codec: {0}")]
    Codec(#[from] CodecError),
    /// El algoritmo de hash de una seleccion no es uno conocido.
    #[error("algoritmo de hash desconocido: {0:#06x}")]
    AlgDesconocido(u16),
    /// Quedaron bytes sin consumir tras la estructura: no es exactamente un
    /// `TPMS_ATTEST`, y aceptar los sobrantes seria aceptar datos no firmados
    /// pegados al final.
    #[error("{0} bytes de mas tras el TPMS_ATTEST")]
    BytesDeMas(usize),
}

impl Attest {
    /// Parsea un `TPMS_ATTEST` de tipo quote. Exige consumir el buffer entero.
    pub fn parse(buf: &[u8]) -> Result<Attest, AttestError> {
        let mut c = Lector::new(buf);
        let magic = c.u32()?;
        let tipo = c.u16()?;
        let qualified_signer = c.tpm2b()?;
        let extra_data = c.tpm2b()?;
        let clock = c.u64()?;
        let reset_count = c.u32()?;
        let restart_count = c.u32()?;
        let safe = c.u8()?;
        let firmware_version = c.u64()?;

        // TPML_PCR_SELECTION
        let count = c.u32()? as usize;
        let mut selecciones = Vec::with_capacity(count);
        for _ in 0..count {
            let alg_id = c.u16()?;
            let alg = HashAlg::from_id(alg_id).ok_or(AttestError::AlgDesconocido(alg_id))?;
            let size_select = c.u8()? as usize;
            let bitmap = c.bytes(size_select)?;
            selecciones.push(SeleccionPcr { alg, bitmap });
        }
        let pcr_digest = c.tpm2b()?;

        if c.restantes() != 0 {
            return Err(AttestError::BytesDeMas(c.restantes()));
        }

        Ok(Attest {
            magic,
            tipo,
            qualified_signer,
            extra_data,
            clock,
            reset_count,
            restart_count,
            safe,
            firmware_version,
            quote: QuoteInfo {
                selecciones,
                pcr_digest,
            },
        })
    }

    /// Re-serializa a los bytes exactos que el TPM firmo. Inversa de [`parse`].
    ///
    /// [`parse`]: Attest::parse
    pub fn marshal(&self) -> Vec<u8> {
        let mut w = Escritor::new();
        w.u32(self.magic);
        w.u16(self.tipo);
        w.tpm2b(&self.qualified_signer);
        w.tpm2b(&self.extra_data);
        w.u64(self.clock);
        w.u32(self.reset_count);
        w.u32(self.restart_count);
        w.u8(self.safe);
        w.u64(self.firmware_version);
        w.u32(self.quote.selecciones.len() as u32);
        for s in &self.quote.selecciones {
            w.u16(s.alg.id());
            w.u8(s.bitmap.len() as u8);
            w.bytes(&s.bitmap);
        }
        w.tpm2b(&self.quote.pcr_digest);
        w.finalizar()
    }
}
