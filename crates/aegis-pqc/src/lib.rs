//! # `aegis-pqc` — Criptografia post-cuantica hibrida (FASE 59)
//!
//! ## El problema real: "Harvest Now, Decrypt Later"
//!
//! Un adversario con recursos graba HOY el trafico cifrado entre el agente y el
//! plano de control y lo guarda. El dia que exista una computadora cuantica
//! relevante (una CRQC), corre el algoritmo de Shor y rompe de golpe **X25519**
//! (el intercambio de claves del canal C2) y las firmas **Ed25519/ECDSA/RSA**
//! (el firmado de binarios y actualizaciones). No hace falta romperlo hoy: basta
//! con guardar el cifrado de hoy y descifrarlo manana. Por eso la migracion es
//! urgente aunque la CRQC todavia no exista.
//!
//! Grover solo **debilita** lo simetrico: AES-256 baja a ~128 bits efectivos, que
//! siguen siendo seguros. No se toca. Hay que migrar DOS cosas:
//!
//! 1. El **intercambio de claves** del canal C2 (lo urgente por HNDL).
//! 2. El **firmado** de binarios/actualizaciones (para no depender de una clave
//!    que una CRQC rompera).
//!
//! ## La decision clave: HIBRIDO, nunca PQC en solitario
//!
//! Las implementaciones PQC son jovenes; podrian tener un fallo aun no
//! descubierto. Por eso cada primitivo PQC se combina con uno clasico probado, de
//! modo que el canal es seguro si aguanta **cualquiera de los dos**. Es el
//! consenso de la industria (IETF, Cloudflare, NSA CNSA 2.0):
//!
//! - **KEM hibrido `X25519MLKEM768`**: el secreto compartido sale de
//!   `HKDF(x25519_ss || mlkem768_ss || transcript)`, atado al transcript. Ver
//!   [`kem_hibrido`].
//! - **Firma hibrida `Ed25519+ML-DSA-65`**: un artefacto se acepta SOLO si
//!   verifican Ed25519 **Y** ML-DSA-65. Ver [`firma_hibrida`].
//!
//! ## Algoritmos (estandares NIST 2024, con los nombres correctos)
//!
//! | Rol | Estandar | Nombre FIPS | Nombre viejo | Nivel |
//! |---|---|---|---|---|
//! | KEM   | FIPS 203 | ML-KEM-768 | CRYSTALS-Kyber     | 3 |
//! | Firma | FIPS 204 | ML-DSA-65  | CRYSTALS-Dilithium | 3 |
//!
//! En el codigo se usan los nombres FIPS; el nombre viejo solo en comentarios.
//!
//! ## Honestidad de validacion: esta fase NO tiene muro de hardware
//!
//! A diferencia de TPM, Intel PT o el driver de Windows, aqui **todo se prueba de
//! verdad**. El ancla son los **Known Answer Tests (KAT) oficiales** de FIPS
//! 203/204 (vectores NIST ACVP): una implementacion sutilmente mal pasa el
//! roundtrip pero FALLA los KAT. Ademas hay negativos (bit alterado, firma
//! alterada) y asserts de tamano/ABI verificados en **compilacion** contra las
//! constantes FIPS. Ver los modulos [`kem`] y [`firma`] y las pruebas de
//! integracion en `tests/`.
//!
//! ## Agilidad criptografica
//!
//! El formato de wire lleva un identificador de suite ([`SuiteKem`],
//! [`SuiteFirma`]) para poder migrar la flota `clasico -> hibrido -> PQC-puro`
//! sin un "dia bandera".

#![forbid(unsafe_code)]

pub mod suite;

#[cfg(feature = "kem")]
pub mod canal;
#[cfg(feature = "kem")]
pub mod kem;
#[cfg(feature = "kem")]
pub mod kem_hibrido;

#[cfg(feature = "sign")]
pub mod firma;
#[cfg(feature = "sign")]
pub mod firma_hibrida;

pub use suite::{SuiteError, SuiteFirma, SuiteKem};

use thiserror::Error;

/// Error comun de las operaciones post-cuanticas de AegisCore.
///
/// Las variantes estan pensadas para fallar de forma RUIDOSA y no ambigua: una
/// verificacion criptografica que falla nunca debe confundirse con un exito, ni
/// un tamano de clave incorrecto debe pasar silenciosamente a una primitiva.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PqcError {
    /// Un buffer no tiene el tamano exacto que exige el estandar FIPS.
    ///
    /// Se nombra el campo, el tamano esperado y el recibido: un desalineamiento
    /// de tamano en cripto es casi siempre un error de integracion que, de pasar,
    /// corromperia la operacion sin un mensaje util.
    #[error("tamano invalido en {campo}: se esperaban {esperado} bytes, llegaron {recibido}")]
    TamanoInvalido {
        /// Nombre del campo o buffer que no cuadra (p. ej. "clave publica").
        campo: &'static str,
        /// Tamano que exige el estandar.
        esperado: usize,
        /// Tamano realmente recibido.
        recibido: usize,
    },

    /// Una clave, ciphertext o firma esta mal formada segun la propia primitiva
    /// (no solo por tamano): p. ej. una clave publica ML-KEM que no decodifica.
    #[error("material criptografico mal formado: {0}")]
    MaterialInvalido(&'static str),

    /// La verificacion de una firma (clasica, PQC o hibrida) ha FALLADO.
    ///
    /// Es el caso de seguridad central: ante la duda, se rechaza.
    #[error("verificacion de firma fallida")]
    FirmaInvalida,

    /// El identificador de suite en el wire no se reconoce o no se acepta por
    /// politica (p. ej. se recibe `clasico` donde la politica exige `hibrido`).
    #[error("suite criptografica no aceptada: {0}")]
    SuiteNoAceptada(#[from] SuiteError),

    /// No se pudo obtener entropia del sistema para un constructor aleatorio.
    ///
    /// Es un fallo de entorno, no de logica: sin una fuente de aleatoriedad
    /// segura no se genera una clave efimera, y fabricarla con un PRNG sembrado
    /// seria peor que fallar (un atacante podria predecirla).
    #[error("no se pudo obtener entropia del sistema")]
    Entropia,

    /// La apertura de un sobre sellado (capa HPKE del canal C2) fallo: el AEAD
    /// no autentica. El sobre fue manipulado, va con datos asociados distintos,
    /// o se abre con la clave equivocada. Ante la duda, no se entrega nada.
    #[error("apertura de sobre sellado fallida: el AEAD no autentica")]
    AperturaInvalida,
}
