//! Requisitos para correr como **Proceso Protegido Antimalware** (PPL).
//!
//! Un proceso PPL-Antimalware instruye al kernel de Windows para que **bloquee**
//! cualquier intento —incluso de un administrador— de terminarlo, inyectarle
//! hilos o volcar su memoria. Es la unica forma soportada de que el agente
//! sobreviva a un atacante con `SeDebugPrivilege` (que tiene cualquier cosa que
//! corra como SYSTEM). Complementa a la defensa por `ObRegisterCallbacks` de la
//! FASE 47: PPL la respalda el kernel, no un callback nuestro.
//!
//! # El muro, declarado
//!
//! Correr como PPL-Antimalware exige que el binario este firmado con un
//! certificado con el EKU de Early Launch Anti-Malware
//! (`1.3.6.1.4.1.311.61.4.1`) y co-firmado por Microsoft. Ese certificado se
//! obtiene de Microsoft, no se puede fabricar, y sin el el kernel rechaza la
//! solicitud de proteccion. La comprobacion de **requisitos** es pura y se
//! prueba aqui; la proteccion **real** solo ocurre en un Windows con el binario
//! debidamente firmado, y queda gated igual que el driver del minifilter.

/// EKU de Early Launch Anti-Malware. Sin el, no hay ELAM ni PPL-Antimalware.
pub const EKU_ELAM: &str = "1.3.6.1.4.1.311.61.4.1";

/// Codigo de nivel de proteccion `PS_PROTECTION` que Windows espera:
/// `(Signer << 4) | Type`, con Signer=Antimalware(3), Type=ProtectedLight(1).
pub const NIVEL_PPL_ANTIMALWARE_CODIGO: u8 = (3 << 4) | 1;

/// Nivel de proteccion que un proceso puede solicitar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NivelProteccion {
    /// Sin proteccion de kernel (un proceso normal).
    Ninguna = 0,
    /// Proceso protegido ligero, firmante Antimalware.
    PplAntimalware = NIVEL_PPL_ANTIMALWARE_CODIGO,
}

impl NivelProteccion {
    /// El byte `PS_PROTECTION` correspondiente.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Requisitos que el binario del agente debe cumplir para poder solicitar PPL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequisitosPpl {
    /// El binario esta firmado con un certificado que lleva el EKU [`EKU_ELAM`].
    pub certificado_am_con_eku: bool,
    /// El binario esta co-firmado por Microsoft (obligatorio para AM).
    pub firmado_por_microsoft: bool,
}

impl RequisitosPpl {
    /// `true` si se cumplen TODOS los requisitos para PPL-Antimalware.
    #[must_use]
    pub const fn cumplidos(&self) -> bool {
        self.certificado_am_con_eku && self.firmado_por_microsoft
    }

    /// El nivel de proteccion que el proceso puede solicitar de forma realista.
    ///
    /// Si falta cualquier requisito, es [`NivelProteccion::Ninguna`]: pedir PPL
    /// sin el certificado solo consigue que el kernel rechace el arranque, lo que
    /// es peor que no pedirlo. La honestidad tambien es no fingir una proteccion
    /// que el kernel no va a conceder.
    #[must_use]
    pub const fn nivel_solicitable(&self) -> NivelProteccion {
        if self.cumplidos() {
            NivelProteccion::PplAntimalware
        } else {
            NivelProteccion::Ninguna
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn el_codigo_de_nivel_es_el_de_windows() {
        // Signer=Antimalware(3), Type=ProtectedLight(1) -> 0x31.
        assert_eq!(NIVEL_PPL_ANTIMALWARE_CODIGO, 0x31);
        assert_eq!(NivelProteccion::PplAntimalware.as_u8(), 0x31);
        assert_eq!(NivelProteccion::Ninguna.as_u8(), 0x00);
    }

    #[test]
    fn sin_certificado_am_no_hay_ppl() {
        let sin = RequisitosPpl {
            certificado_am_con_eku: false,
            firmado_por_microsoft: true,
        };
        assert!(!sin.cumplidos());
        assert_eq!(sin.nivel_solicitable(), NivelProteccion::Ninguna);
    }

    #[test]
    fn sin_cofirma_de_microsoft_no_hay_ppl() {
        let sin = RequisitosPpl {
            certificado_am_con_eku: true,
            firmado_por_microsoft: false,
        };
        assert!(!sin.cumplidos());
        assert_eq!(sin.nivel_solicitable(), NivelProteccion::Ninguna);
    }

    #[test]
    fn con_todo_en_regla_se_puede_pedir_ppl() {
        let ok = RequisitosPpl {
            certificado_am_con_eku: true,
            firmado_por_microsoft: true,
        };
        assert!(ok.cumplidos());
        assert_eq!(ok.nivel_solicitable(), NivelProteccion::PplAntimalware);
    }

    #[test]
    fn el_eku_es_el_de_early_launch_antimalware() {
        assert_eq!(EKU_ELAM, "1.3.6.1.4.1.311.61.4.1");
    }
}
