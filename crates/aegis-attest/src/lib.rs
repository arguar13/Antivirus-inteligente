//! Atestacion remota con raiz de confianza en hardware (TPM 2.0) — FASE 49.
//!
//! # Por que existe
//!
//! El plano de control de AegisCore recibe telemetria de diez mil agentes y les
//! emite ordenes. Hasta ahora confiaba en que un latido que dice "soy el agente
//! 4820 y estoy sano" lo manda de verdad el agente 4820 y de verdad esta sano.
//! Un atacante que ha comprometido el endpoint puede mentir en ambas cosas: el
//! binario del agente puede estar parcheado en disco o en memoria, y la
//! telemetria puede estar fabricada. Ninguna firma de software lo detecta,
//! porque el software que firma es el que esta comprometido.
//!
//! La unica raiz de confianza que sobrevive a un sistema operativo comprometido
//! es el hardware. El TPM 2.0 mide el arranque en sus PCR y puede FIRMAR una
//! declaracion de esos valores —un *quote*— con una clave que nunca sale del
//! chip. El plano de control verifica esa firma antes de creerse nada. Si el
//! arranque fue manipulado, o el binario no es el matriculado, o alguien
//! reproduce un quote viejo, la verificacion falla y se invoca la Cuarentena de
//! Enjambre de la FASE 44.
//!
//! # La linea que este crate no cruza
//!
//! Emitir el quote exige hablar con `/dev/tpmrm0` en una maquina con TPM. Este
//! entorno no tiene ninguno —ni chip, ni simulador—. Siguiendo el patron de la
//! FASE 47, la parte que puede estar mal de forma peligrosa —VERIFICAR el quote:
//! comprobar la firma, recomputar el digest de PCR, exigir frescura— es Rust
//! portable que se prueba con firmas REALES en cada `make ci`. La FONTANERIA que
//! habla con el chip ([`emisor`]) esta aislada tras la feature `tpm-hardware` y
//! el CI declara que no se compilo aqui, en vez de fingir que si.
//!
//! # Un endpoint sin TPM no es "inseguro": es [`CheckState::NoAplicable`]
//!
//! Media flota puede ser microVMs sin TPM. Tratar "no hay TPM" como fallo
//! cuarentenaria a todas por algo que no es un ataque. Se reutiliza el
//! tri-estado de `aegis-firmware`: sin TPM el veredicto es `NoAplicable`, nunca
//! `Ok` (aceptar telemetria no atestada como si lo estuviera) ni fallo.
//!
//! [`CheckState::NoAplicable`]: aegis_firmware::CheckState::NoAplicable

#![forbid(unsafe_code)]

mod codec;

pub mod attest;
pub mod cadena;
pub mod identidad;
pub mod ima;
pub mod malla;
pub mod nonce;
pub mod politica;
pub mod quote;
pub mod revocacion;
pub mod verificador;

#[cfg(feature = "tpm-hardware")]
pub mod emisor;

pub use attest::{Attest, QuoteInfo, SeleccionPcr, TPM_GENERATED_VALUE, TPM_ST_ATTEST_QUOTE};
pub use cadena::{CadenaAtestacion, Eslabon, Nivel};
pub use identidad::{ClavePublicaAk, IdentidadError};
pub use ima::{casar, sin_procedencia, InventarioProcedencia, MedidaIma, Procedencia};
pub use malla::Par;
pub use nonce::{Nonce, RegistroNonces};
pub use politica::{ErrorPolitica, ExigenciaPcr, PoliticaPcr};
pub use revocacion::{ErrorRevocacion, EstadoNodo, LimitadorRevocacion};
pub use verificador::{Veredicto, VerificadorError};
