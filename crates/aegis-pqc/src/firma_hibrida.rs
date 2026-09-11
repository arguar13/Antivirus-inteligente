//! Firma hibrida Ed25519 + ML-DSA-65: se acepta **solo si verifican las dos**.
//!
//! # Por que las dos, y no una
//!
//! El firmado protege la via mas peligrosa de un EDR: la actualizacion. Si un
//! atacante consigue firmar un binario, pilota el agente con los permisos del
//! defensor. Ed25519 es solido hoy pero caera ante una computadora cuantica;
//! ML-DSA-65 resiste a la cuantica pero es joven. Exigir que **ambas** firmas
//! verifiquen significa que un falsificador tiene que romper las dos a la vez:
//! el clasico (hoy imposible) Y el post-cuantico (la apuesta del NIST). Mitiga
//! "Harvest Now, Decrypt Later" sin apostarlo todo a una primitiva nueva.
//!
//! # El formato de wire lleva la suite (agilidad)
//!
//! La firma serializada empieza por un byte de suite ([`SuiteFirma`]). Hoy solo
//! se acepta la hibrida; manana, cuando ML-DSA acumule anos de escrutinio, se
//! podra pasar a PQC-puro cambiando la politica, sin un "dia bandera".
//!
//! # Separacion de dominios
//!
//! ML-DSA ata el contexto de forma nativa. Ed25519 no tiene `ctx`, asi que se le
//! antepone un dominio y el contexto enmarcado por longitud, de modo que una
//! firma valida para un dominio no se reinterprete en otro.

use crate::firma::{self, ClaveFirma, ClaveVerificacion, Firma};
use crate::suite::SuiteFirma;
use crate::PqcError;
use ed25519_dalek::{
    Signature as FirmaEd, Signer, SigningKey as ClaveFirmaEd, VerifyingKey as ClaveVerifEd,
};
use zeroize::Zeroize;

/// Longitud de una clave publica Ed25519.
pub const ED25519_PK_LEN: usize = 32;
/// Longitud de una firma Ed25519.
pub const ED25519_SIG_LEN: usize = 64;
/// Longitud de una semilla Ed25519 (la clave secreta).
pub const ED25519_SEMILLA_LEN: usize = 32;
/// Longitud serializada de la clave publica hibrida (Ed25519 || ML-DSA pk).
pub const CLAVE_PUBLICA_LEN: usize = ED25519_PK_LEN + firma::PK_LEN;
/// Longitud serializada de la firma hibrida: `suite(1) || ed25519(64) || mldsa`.
pub const FIRMA_HIBRIDA_LEN: usize = 1 + ED25519_SIG_LEN + firma::FIRMA_LEN;

// Dominio de separacion para la parte Ed25519. Cambiarlo es un cambio de suite.
const ED_DOMINIO: &[u8] = b"AegisCore/firma-hibrida/ed25519/v1";

/// Clave de firma hibrida (Ed25519 + ML-DSA-65). Material secreto.
pub struct ClaveFirmaHibrida {
    ed: ClaveFirmaEd,
    mldsa: ClaveFirma,
}

impl core::fmt::Debug for ClaveFirmaHibrida {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClaveFirmaHibrida").finish_non_exhaustive()
    }
}

/// Clave publica de verificacion hibrida (Ed25519 + ML-DSA-65).
#[derive(Clone)]
pub struct ClaveVerificacionHibrida {
    ed: [u8; ED25519_PK_LEN],
    mldsa: ClaveVerificacion,
}

/// Firma hibrida: una Ed25519 y una ML-DSA-65 sobre el mismo mensaje y contexto.
#[derive(Clone)]
pub struct FirmaHibrida {
    ed: [u8; ED25519_SIG_LEN],
    mldsa: Firma,
}

/// Enmarca el mensaje para la parte Ed25519: dominio || len(ctx) || ctx || msg.
/// Devuelve `None` si el contexto excede 255 bytes (igual limite que ML-DSA).
fn enmarcar_ed25519(ctx: &[u8], mensaje: &[u8]) -> Option<Vec<u8>> {
    if ctx.len() > firma::CTX_MAX {
        return None;
    }
    let mut m = Vec::with_capacity(ED_DOMINIO.len() + 1 + ctx.len() + mensaje.len());
    m.extend_from_slice(ED_DOMINIO);
    // El contexto enmarcado por longitud: un salto en msg no puede fabricar ctx.
    m.push(ctx.len() as u8);
    m.extend_from_slice(ctx);
    m.extend_from_slice(mensaje);
    Some(m)
}

impl ClaveFirmaHibrida {
    /// Genera una clave de firma hibrida tomando la entropia del sistema.
    ///
    /// # Errores
    /// [`PqcError::Entropia`] si el sistema no puede entregar aleatoriedad.
    pub fn generar_aleatorio() -> Result<Self, PqcError> {
        let mut semilla = [0u8; ED25519_SEMILLA_LEN];
        getrandom::getrandom(&mut semilla).map_err(|_| PqcError::Entropia)?;
        let ed = ClaveFirmaEd::from_bytes(&semilla);
        semilla.zeroize();
        let mldsa = ClaveFirma::generar_aleatorio()?;
        Ok(Self { ed, mldsa })
    }

    /// Construye de forma determinista desde dos semillas (Ed25519 y ML-DSA).
    /// Util para derivar la clave de firma del plano de control desde un secreto
    /// maestro, y para pruebas reproducibles.
    #[must_use]
    pub fn desde_semillas(
        ed_semilla: &[u8; ED25519_SEMILLA_LEN],
        mldsa_semilla: &[u8; firma::SEMILLA_LEN],
    ) -> Self {
        Self {
            ed: ClaveFirmaEd::from_bytes(ed_semilla),
            mldsa: ClaveFirma::generar(mldsa_semilla),
        }
    }

    /// Deriva la clave publica de verificacion hibrida.
    #[must_use]
    pub fn clave_verificacion(&self) -> ClaveVerificacionHibrida {
        ClaveVerificacionHibrida {
            ed: self.ed.verifying_key().to_bytes(),
            mldsa: self.mldsa.clave_verificacion(),
        }
    }

    /// Firma `mensaje` bajo el contexto `ctx` con ambas primitivas.
    ///
    /// # Errores
    /// [`PqcError::MaterialInvalido`] si `ctx` supera 255 bytes.
    pub fn firmar(&self, mensaje: &[u8], ctx: &[u8]) -> Result<FirmaHibrida, PqcError> {
        let enmarcado = enmarcar_ed25519(ctx, mensaje)
            .ok_or(PqcError::MaterialInvalido("contexto > 255 bytes"))?;
        let ed_sig = self.ed.sign(&enmarcado);
        let mldsa_sig = self.mldsa.firmar(mensaje, ctx)?;
        Ok(FirmaHibrida {
            ed: ed_sig.to_bytes(),
            mldsa: mldsa_sig,
        })
    }
}

impl ClaveVerificacionHibrida {
    /// Construye desde las dos claves publicas.
    #[must_use]
    pub fn nueva(ed: [u8; ED25519_PK_LEN], mldsa: ClaveVerificacion) -> Self {
        Self { ed, mldsa }
    }

    /// Serializa como `ed25519_pk (32) || mldsa_pk (1952)`.
    #[must_use]
    pub fn a_bytes(&self) -> [u8; CLAVE_PUBLICA_LEN] {
        let mut out = [0u8; CLAVE_PUBLICA_LEN];
        out[..ED25519_PK_LEN].copy_from_slice(&self.ed);
        out[ED25519_PK_LEN..].copy_from_slice(self.mldsa.as_bytes());
        out
    }

    /// Reconstruye desde el formato de wire.
    ///
    /// # Errores
    /// [`PqcError::TamanoInvalido`] si `bytes` no mide [`CLAVE_PUBLICA_LEN`].
    pub fn desde_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() != CLAVE_PUBLICA_LEN {
            return Err(PqcError::TamanoInvalido {
                campo: "clave publica hibrida de firma",
                esperado: CLAVE_PUBLICA_LEN,
                recibido: bytes.len(),
            });
        }
        let mut ed = [0u8; ED25519_PK_LEN];
        ed.copy_from_slice(&bytes[..ED25519_PK_LEN]);
        let mldsa = ClaveVerificacion::desde_bytes(&bytes[ED25519_PK_LEN..])?;
        Ok(Self { ed, mldsa })
    }

    /// Verifica la firma hibrida: `true` **solo si verifican las dos**.
    ///
    /// Cualquier material mal formado, un contexto demasiado largo, o el fallo de
    /// cualquiera de las dos firmas, devuelve `false`. Ante la duda, se rechaza.
    #[must_use]
    pub fn verificar(&self, mensaje: &[u8], ctx: &[u8], firma: &FirmaHibrida) -> bool {
        // 1. Ed25519 (con verificacion estricta: rechaza puntos de orden pequeno
        //    y formas no canonicas).
        let Some(enmarcado) = enmarcar_ed25519(ctx, mensaje) else {
            return false;
        };
        let Ok(vk) = ClaveVerifEd::from_bytes(&self.ed) else {
            return false;
        };
        let sig = FirmaEd::from_bytes(&firma.ed);
        let ed_ok = vk.verify_strict(&enmarcado, &sig).is_ok();

        // 2. ML-DSA-65.
        let mldsa_ok = self.mldsa.verificar(mensaje, ctx, &firma.mldsa);

        // Se exige que AMBAS sean validas.
        ed_ok && mldsa_ok
    }

    /// Como [`verificar`](Self::verificar) pero devolviendo un `Result`.
    ///
    /// # Errores
    /// [`PqcError::FirmaInvalida`] si la firma hibrida no verifica.
    pub fn verificar_estricto(
        &self,
        mensaje: &[u8],
        ctx: &[u8],
        firma: &FirmaHibrida,
    ) -> Result<(), PqcError> {
        if self.verificar(mensaje, ctx, firma) {
            Ok(())
        } else {
            Err(PqcError::FirmaInvalida)
        }
    }
}

impl FirmaHibrida {
    /// Construye desde las dos firmas.
    #[must_use]
    pub fn nueva(ed: [u8; ED25519_SIG_LEN], mldsa: Firma) -> Self {
        Self { ed, mldsa }
    }

    /// Serializa como `suite(1) || ed25519(64) || mldsa(3309)`.
    #[must_use]
    pub fn a_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FIRMA_HIBRIDA_LEN);
        out.push(SuiteFirma::Ed25519MlDsa65.as_u8());
        out.extend_from_slice(&self.ed);
        out.extend_from_slice(self.mldsa.as_bytes());
        out
    }

    /// Reconstruye desde el formato de wire, exigiendo la suite hibrida.
    ///
    /// # Errores
    /// [`PqcError::SuiteNoAceptada`] si el byte de suite no es el de la hibrida;
    /// [`PqcError::TamanoInvalido`] si la longitud total no cuadra.
    pub fn desde_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() != FIRMA_HIBRIDA_LEN {
            return Err(PqcError::TamanoInvalido {
                campo: "firma hibrida",
                esperado: FIRMA_HIBRIDA_LEN,
                recibido: bytes.len(),
            });
        }
        // Agilidad: el primer byte es la suite; se exige la hibrida.
        SuiteFirma::aceptar_hibrida(bytes[0])?;

        let mut ed = [0u8; ED25519_SIG_LEN];
        ed.copy_from_slice(&bytes[1..1 + ED25519_SIG_LEN]);
        let mldsa = Firma::desde_bytes(&bytes[1 + ED25519_SIG_LEN..])?;
        Ok(Self { ed, mldsa })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clave() -> ClaveFirmaHibrida {
        ClaveFirmaHibrida::desde_semillas(&[3u8; 32], &[7u8; 32])
    }

    #[test]
    fn roundtrip_firma_hibrida() {
        let sk = clave();
        let vk = sk.clave_verificacion();
        let firma = sk.firmar(b"binario v2", b"aegis/update").expect("firmar");
        assert!(vk.verificar(b"binario v2", b"aegis/update", &firma));
    }

    #[test]
    fn se_acepta_solo_si_verifican_las_dos() {
        let sk = clave();
        let vk = sk.clave_verificacion();
        let firma = sk.firmar(b"m", b"c").expect("firmar");

        // Alterar SOLO la parte Ed25519 -> rechazo (aunque ML-DSA siga bien).
        let mut f_ed = firma.clone();
        f_ed.ed[0] ^= 0x01;
        assert!(
            !vk.verificar(b"m", b"c", &f_ed),
            "ed25519 roto debe invalidar aunque ml-dsa verifique"
        );

        // Alterar SOLO la parte ML-DSA -> rechazo (aunque Ed25519 siga bien).
        let mldsa_bytes = {
            let mut b = *firma.mldsa.as_bytes();
            b[0] ^= 0x01;
            b
        };
        let f_mldsa = FirmaHibrida::nueva(firma.ed, Firma::desde_bytes(&mldsa_bytes).unwrap());
        assert!(
            !vk.verificar(b"m", b"c", &f_mldsa),
            "ml-dsa roto debe invalidar aunque ed25519 verifique"
        );

        // Ambas intactas -> acepta.
        assert!(vk.verificar(b"m", b"c", &firma));
    }

    #[test]
    fn firma_ed25519_valida_de_otro_mensaje_no_cuela() {
        // Una parte Ed25519 que es una firma VALIDA pero de otro mensaje no debe
        // hacer pasar la hibrida (el binding msg/ctx lo impide).
        let sk = clave();
        let vk = sk.clave_verificacion();
        let f1 = sk.firmar(b"mensaje-1", b"c").expect("f1");
        let f2 = sk.firmar(b"mensaje-2", b"c").expect("f2");
        // Ed de f2 (valida para mensaje-2) + ML-DSA de f1.
        let mezcla = FirmaHibrida::nueva(f2.ed, f1.mldsa.clone());
        assert!(!vk.verificar(b"mensaje-1", b"c", &mezcla));
    }

    #[test]
    fn determinista() {
        let sk = clave();
        let f1 = sk.firmar(b"m", b"c").expect("f1");
        let f2 = sk.firmar(b"m", b"c").expect("f2");
        assert_eq!(f1.a_bytes(), f2.a_bytes(), "ambas primitivas deterministas");
    }

    #[test]
    fn wire_roundtrip_y_suite() {
        let sk = clave();
        let firma = sk.firmar(b"m", b"c").expect("firmar");
        let bytes = firma.a_bytes();
        assert_eq!(bytes.len(), FIRMA_HIBRIDA_LEN);
        assert_eq!(bytes[0], SuiteFirma::Ed25519MlDsa65.as_u8());

        let firma2 = FirmaHibrida::desde_bytes(&bytes).expect("desde_bytes");
        let vk = sk.clave_verificacion();
        assert!(vk.verificar(b"m", b"c", &firma2));

        // Un byte de suite clasico (Ed25519 a secas) se rechaza por politica.
        let mut degradada = bytes.clone();
        degradada[0] = SuiteFirma::Ed25519.as_u8();
        assert!(matches!(
            FirmaHibrida::desde_bytes(&degradada),
            Err(PqcError::SuiteNoAceptada(_))
        ));
    }

    #[test]
    fn clave_publica_wire_roundtrip() {
        let sk = clave();
        let vk = sk.clave_verificacion();
        let bytes = vk.a_bytes();
        assert_eq!(bytes.len(), CLAVE_PUBLICA_LEN);
        let vk2 = ClaveVerificacionHibrida::desde_bytes(&bytes).expect("pk");
        let firma = sk.firmar(b"m", b"c").expect("firmar");
        assert!(vk2.verificar(b"m", b"c", &firma));
    }
}
