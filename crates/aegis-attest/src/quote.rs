//! Constructor del comando `TPM2_Quote` (TPM 2.0, Parte 3).
//!
//! Es la contraparte de `construir_pcr_read` de `aegis-firmware`: el agente lo
//! ensambla y lo escribe en `/dev/tpmrm0` para pedirle al chip que firme el
//! estado de los PCR con la AK. Se ensambla a mano, byte a byte, en vez de con
//! `tss-esapi`, por la misma razon: esa libreria arrastra `libtss2` en C, que
//! este entorno no puede instalar.
//!
//! Un comando mal marshalado no da un error claro: el TPM responde otra cosa, y
//! el fallo aparece como un quote invalido mucho despues. Por eso el comando se
//! prueba con asercion byte a byte contra la spec, aunque su EJECUCION contra un
//! chip real sea fontaneria gated ([`crate::emisor`]).

use crate::codec::Escritor;
use aegis_firmware::HashAlg;

/// `TPM_ST_SESSIONS`: el tag de un comando que lleva area de autorizacion. El
/// quote necesita autorizar el uso de la AK, asi que siempre lleva sesion.
const TPM_ST_SESSIONS: u16 = 0x8002;

/// `TPM_CC_Quote`.
const TPM_CC_QUOTE: u32 = 0x0000_0158;

/// `TPM_ALG_NULL`: sin esquema explicito, el TPM usa el de la clave.
const TPM_ALG_NULL: u16 = 0x0010;

/// Ensambla un `TPM2_Quote`.
///
/// - `ak_handle`: el handle de la clave de atestacion cargada (p.ej.
///   `0x81010001` para una AK persistente).
/// - `sesion`: los bytes del area de autorizacion ya construida (una sesion de
///   password o HMAC). Se pasan crudos porque su construccion depende de como se
///   autorizo la AK, que es politica del endpoint.
/// - `nonce`: `qualifyingData`, el desafio del servidor que da frescura.
/// - `alg`: banco de PCR a citar.
/// - `pcrs`: indices de PCR a incluir.
pub fn construir_quote(
    ak_handle: u32,
    sesion: &[u8],
    nonce: &[u8],
    alg: HashAlg,
    pcrs: &[u32],
) -> Vec<u8> {
    // Cuerpo despues de la cabecera (tag/size/cc se anteponen al final, cuando
    // ya se sabe el tamano total).
    let mut cuerpo = Escritor::new();
    cuerpo.u32(ak_handle); // objectHandle (el objeto que firma)

    // authorizationSize + authorization area
    cuerpo.u32(sesion.len() as u32);
    cuerpo.bytes(sesion);

    // qualifyingData: TPM2B_DATA con el nonce
    cuerpo.tpm2b(nonce);

    // inScheme: TPMT_SIG_SCHEME = TPM_ALG_NULL (usar el de la clave)
    cuerpo.u16(TPM_ALG_NULL);

    // PCRselect: TPML_PCR_SELECTION con una seleccion
    cuerpo.u32(1); // count
    cuerpo.u16(alg.id());
    cuerpo.u8(3); // sizeofSelect: 3 bytes cubren los PCR 0..23
    cuerpo.bytes(&bitmap_de(pcrs));

    let cuerpo = cuerpo.finalizar();

    // Cabecera: tag || commandSize || commandCode
    let total = 2 + 4 + 4 + cuerpo.len();
    let mut cmd = Escritor::new();
    cmd.u16(TPM_ST_SESSIONS);
    cmd.u32(total as u32);
    cmd.u32(TPM_CC_QUOTE);
    cmd.bytes(&cuerpo);
    cmd.finalizar()
}

/// Mapa de bits de 3 bytes (PCR 0..23) con los PCR de `pcrs` a uno. Mismo
/// convenio little-endian-por-byte que `aegis-firmware::tpm::bitmap_de`: el PCR
/// *n* es el bit `n % 8` del byte `n / 8`.
pub fn bitmap_de(pcrs: &[u32]) -> [u8; 3] {
    let mut b = [0u8; 3];
    for &p in pcrs {
        if p < 24 {
            b[(p / 8) as usize] |= 1 << (p % 8);
        }
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn el_bitmap_pone_el_bit_correcto() {
        assert_eq!(bitmap_de(&[0, 1, 2, 3, 4, 5, 6, 7]), [0xFF, 0x00, 0x00]);
        assert_eq!(bitmap_de(&[8]), [0x00, 0x01, 0x00]);
        assert_eq!(bitmap_de(&[23]), [0x00, 0x00, 0x80]);
        // Un PCR fuera de rango no corrompe el mapa.
        assert_eq!(bitmap_de(&[99]), [0x00, 0x00, 0x00]);
    }

    #[test]
    fn el_comando_quote_casa_byte_a_byte_con_la_spec() {
        let cmd = construir_quote(
            0x8101_0001,
            &[0xAA, 0xBB],
            &[0x01, 0x02],
            HashAlg::Sha256,
            &[0, 7],
        );
        // tag = TPM_ST_SESSIONS
        assert_eq!(&cmd[0..2], &0x8002u16.to_be_bytes());
        // commandSize = longitud total real
        assert_eq!(
            u32::from_be_bytes([cmd[2], cmd[3], cmd[4], cmd[5]]),
            cmd.len() as u32
        );
        // commandCode = TPM_CC_Quote
        assert_eq!(&cmd[6..10], &0x0000_0158u32.to_be_bytes());
        // objectHandle
        assert_eq!(&cmd[10..14], &0x8101_0001u32.to_be_bytes());
        // authorizationSize + sesion
        assert_eq!(u32::from_be_bytes([cmd[14], cmd[15], cmd[16], cmd[17]]), 2);
        assert_eq!(&cmd[18..20], &[0xAA, 0xBB]);
        // qualifyingData: TPM2B con el nonce
        assert_eq!(&cmd[20..22], &2u16.to_be_bytes());
        assert_eq!(&cmd[22..24], &[0x01, 0x02]);
        // inScheme NULL
        assert_eq!(&cmd[24..26], &0x0010u16.to_be_bytes());
        // TPML_PCR_SELECTION: count=1, alg=SHA256, size=3, bitmap con PCR 0 y 7
        assert_eq!(&cmd[26..30], &1u32.to_be_bytes());
        assert_eq!(&cmd[30..32], &0x000Bu16.to_be_bytes());
        assert_eq!(cmd[32], 3);
        assert_eq!(&cmd[33..36], &[0b1000_0001, 0, 0]); // PCR 0 y 7
    }
}
