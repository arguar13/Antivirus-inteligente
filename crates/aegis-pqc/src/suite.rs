//! Agilidad criptografica: identificadores de suite en el formato de wire.
//!
//! Migrar diez mil agentes de criptografia clasica a post-cuantica no se hace en
//! un "dia bandera" en el que todos cambian a la vez: siempre hay agentes viejos
//! y nuevos conviviendo durante la transicion. Para que el receptor sepa que
//! esperar sin adivinar, **cada mensaje y cada artefacto llevan un byte de suite**
//! al principio. Eso permite recorrer el camino en tres escalones sin romper la
//! flota:
//!
//! ```text
//!   clasico        ->   hibrido          ->   PQC-puro
//!   X25519              X25519MLKEM768        ML-KEM-768
//!   Ed25519             Ed25519+ML-DSA-65     ML-DSA-65
//! ```
//!
//! El escalon intermedio (hibrido) es donde AegisCore vive hoy: seguro si aguanta
//! el primitivo clasico **o** el PQC. El escalon `PQC-puro` queda definido en el
//! wire pero NO se acepta por politica todavia (ver [`SuiteFirma::exige_pqc`] y
//! [`SuiteKem::exige_pqc`]); se reserva para cuando las implementaciones PQC
//! acumulen los anos de escrutinio que hoy tiene lo clasico.

use core::fmt;

/// Error al interpretar o aceptar un identificador de suite recibido por el wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuiteError {
    /// El byte de suite no corresponde a ninguna suite conocida.
    Desconocida(u8),
    /// La suite es conocida pero la politica local no la acepta (p. ej. se
    /// recibio `clasico` cuando se exige al menos `hibrido`).
    Degradada {
        /// Byte de suite recibido.
        recibida: u8,
        /// Texto de la politica minima exigida.
        minima: &'static str,
    },
}

impl fmt::Display for SuiteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SuiteError::Desconocida(b) => write!(f, "byte de suite desconocido: {b:#04x}"),
            SuiteError::Degradada { recibida, minima } => write!(
                f,
                "suite degradada {recibida:#04x}: la politica exige al menos {minima}"
            ),
        }
    }
}

impl std::error::Error for SuiteError {}

/// Suite de **firma** anunciada en el wire (1 byte).
///
/// El orden numerico refleja el escalon de migracion: a mayor valor, mas
/// resistencia post-cuantica.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SuiteFirma {
    /// Solo Ed25519 (clasico). Rompible por una CRQC; se conserva para
    /// interoperar con agentes aun no migrados.
    Ed25519 = 1,
    /// Hibrida: Ed25519 **y** ML-DSA-65. Valida sii verifican las dos. Es la
    /// suite objetivo de la FASE 59.
    Ed25519MlDsa65 = 2,
    /// Solo ML-DSA-65 (PQC-puro). Definida en el wire; reservada para el futuro.
    MlDsa65 = 3,
}

impl SuiteFirma {
    /// Byte que se serializa en el wire.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// `true` si la suite incorpora el primitivo post-cuantico ML-DSA.
    #[must_use]
    pub const fn incluye_pqc(self) -> bool {
        matches!(self, SuiteFirma::Ed25519MlDsa65 | SuiteFirma::MlDsa65)
    }

    /// `true` si la suite exige PQC-puro (sin respaldo clasico). Hoy es `true`
    /// solo para [`SuiteFirma::MlDsa65`], que la politica aun no acepta.
    #[must_use]
    pub const fn exige_pqc(self) -> bool {
        matches!(self, SuiteFirma::MlDsa65)
    }

    /// Interpreta un byte de wire, aplicando la **politica minima** de FASE 59:
    /// se rechaza `Ed25519` a secas (degradacion) y se acepta `hibrido`.
    /// `MlDsa65` (PQC-puro) tambien se rechaza por politica: aun no es la suite
    /// objetivo.
    ///
    /// # Errores
    /// [`SuiteError::Desconocida`] si el byte no corresponde a ninguna suite;
    /// [`SuiteError::Degradada`] si es conocida pero por debajo de la politica.
    pub fn aceptar_hibrida(byte: u8) -> Result<Self, SuiteError> {
        match Self::try_from(byte)? {
            SuiteFirma::Ed25519MlDsa65 => Ok(SuiteFirma::Ed25519MlDsa65),
            otra => Err(SuiteError::Degradada {
                recibida: otra.as_u8(),
                minima: "Ed25519+ML-DSA-65 (hibrida)",
            }),
        }
    }
}

impl TryFrom<u8> for SuiteFirma {
    type Error = SuiteError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(SuiteFirma::Ed25519),
            2 => Ok(SuiteFirma::Ed25519MlDsa65),
            3 => Ok(SuiteFirma::MlDsa65),
            otro => Err(SuiteError::Desconocida(otro)),
        }
    }
}

/// Suite de **KEM** (intercambio de claves) anunciada en el wire (1 byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SuiteKem {
    /// Solo X25519 (clasico). Vulnerable a "Harvest Now, Decrypt Later".
    X25519 = 1,
    /// Hibrido: X25519 combinado con ML-KEM-768. Suite objetivo de la FASE 59.
    X25519MlKem768 = 2,
    /// Solo ML-KEM-768 (PQC-puro). Definido en el wire; reservado para el futuro.
    MlKem768 = 3,
}

impl SuiteKem {
    /// Byte que se serializa en el wire.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// `true` si la suite incorpora el primitivo post-cuantico ML-KEM.
    #[must_use]
    pub const fn incluye_pqc(self) -> bool {
        matches!(self, SuiteKem::X25519MlKem768 | SuiteKem::MlKem768)
    }

    /// `true` si la suite exige PQC-puro (sin respaldo clasico).
    #[must_use]
    pub const fn exige_pqc(self) -> bool {
        matches!(self, SuiteKem::MlKem768)
    }

    /// Interpreta un byte de wire aplicando la politica minima de FASE 59: solo
    /// se acepta el KEM hibrido.
    ///
    /// # Errores
    /// [`SuiteError::Desconocida`] o [`SuiteError::Degradada`] segun el caso.
    pub fn aceptar_hibrida(byte: u8) -> Result<Self, SuiteError> {
        match Self::try_from(byte)? {
            SuiteKem::X25519MlKem768 => Ok(SuiteKem::X25519MlKem768),
            otra => Err(SuiteError::Degradada {
                recibida: otra.as_u8(),
                minima: "X25519MLKEM768 (hibrido)",
            }),
        }
    }
}

impl TryFrom<u8> for SuiteKem {
    type Error = SuiteError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(SuiteKem::X25519),
            2 => Ok(SuiteKem::X25519MlKem768),
            3 => Ok(SuiteKem::MlKem768),
            otro => Err(SuiteError::Desconocida(otro)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_byte_de_suite() {
        for s in [
            SuiteFirma::Ed25519,
            SuiteFirma::Ed25519MlDsa65,
            SuiteFirma::MlDsa65,
        ] {
            assert_eq!(SuiteFirma::try_from(s.as_u8()), Ok(s));
        }
        for s in [
            SuiteKem::X25519,
            SuiteKem::X25519MlKem768,
            SuiteKem::MlKem768,
        ] {
            assert_eq!(SuiteKem::try_from(s.as_u8()), Ok(s));
        }
    }

    #[test]
    fn byte_desconocido_se_rechaza() {
        assert_eq!(SuiteFirma::try_from(0), Err(SuiteError::Desconocida(0)));
        assert_eq!(SuiteFirma::try_from(99), Err(SuiteError::Desconocida(99)));
        assert_eq!(SuiteKem::try_from(0), Err(SuiteError::Desconocida(0)));
    }

    #[test]
    fn politica_rechaza_degradacion_a_clasico_y_a_pqc_puro() {
        // Clasico a secas: degradacion, se rechaza.
        assert!(matches!(
            SuiteFirma::aceptar_hibrida(SuiteFirma::Ed25519.as_u8()),
            Err(SuiteError::Degradada { .. })
        ));
        assert!(matches!(
            SuiteKem::aceptar_hibrida(SuiteKem::X25519.as_u8()),
            Err(SuiteError::Degradada { .. })
        ));
        // PQC-puro: aun no es la suite objetivo, se rechaza.
        assert!(matches!(
            SuiteFirma::aceptar_hibrida(SuiteFirma::MlDsa65.as_u8()),
            Err(SuiteError::Degradada { .. })
        ));
        // Hibrida: se acepta.
        assert_eq!(
            SuiteFirma::aceptar_hibrida(SuiteFirma::Ed25519MlDsa65.as_u8()),
            Ok(SuiteFirma::Ed25519MlDsa65)
        );
        assert_eq!(
            SuiteKem::aceptar_hibrida(SuiteKem::X25519MlKem768.as_u8()),
            Ok(SuiteKem::X25519MlKem768)
        );
    }

    #[test]
    fn banderas_pqc_coherentes() {
        assert!(!SuiteFirma::Ed25519.incluye_pqc());
        assert!(SuiteFirma::Ed25519MlDsa65.incluye_pqc());
        assert!(!SuiteFirma::Ed25519MlDsa65.exige_pqc());
        assert!(SuiteFirma::MlDsa65.exige_pqc());
        assert!(!SuiteKem::X25519.incluye_pqc());
        assert!(SuiteKem::X25519MlKem768.incluye_pqc());
        assert!(SuiteKem::MlKem768.exige_pqc());
    }
}
