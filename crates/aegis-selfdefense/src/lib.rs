//! # `aegis-selfdefense` — Autodefensa legitima (FASE 55')
//!
//! ## La linea que no se cruza
//!
//! AegisCore es 100% defensivo. Un EDR tiene que sobrevivir a un atacante con
//! privilegios de administrador que intenta matarlo, borrarlo o cegarlo —ese es
//! el primer paso de casi todo ataque serio—. Pero **jamas** debe pelear contra
//! el **dueno legitimo** del equipo. Prohibido: bootkits, persistencia en
//! firmware contra el dueno, evadir la eliminacion autorizada, u ocultarse. Por
//! eso **siempre existe un camino de desinstalacion autorizado** que controla el
//! dueno de la flota.
//!
//! Ese camino es un **OTP** (una orden de operacion autorizada, de un solo uso)
//! que **solo el Control Plane puede emitir**, firmado con la firma hibrida de
//! la FASE 59. Con un OTP valido, desinstalar/parar/borrar AegisCore **se
//! permite**. Sin el, el motor de tamper deniega el sabotaje. Es la diferencia
//! entre un EDR y un rootkit: un rootkit no le da a nadie la llave para quitarlo.
//!
//! ## Las tres piezas (y su honestidad de validacion)
//!
//! - **Tamper Protection con OTP** ([`otp`], [`replay`], [`tamper`]): la parte
//!   que puede estar MAL de forma peligrosa. De MENOS, un atacante mata el EDR;
//!   de MAS, el dueno no puede desinstalarlo (y eso lo convierte en malware). La
//!   verificacion del OTP y la decision son Rust puro, probados con **firmas
//!   hibridas reales** y anti-replay real, en cada `make ci`.
//! - **ELAM** ([`elam`]): la clasificacion de un driver de arranque como
//!   bueno/malo/desconocido, con el invariante ETICO de que **nunca** se deja la
//!   maquina del dueno sin arrancar (un driver critico dudoso se marca, no se
//!   bloquea). Logica portable, probada aqui.
//! - **PPL** ([`ppl`]): los requisitos para correr como Proceso Protegido
//!   Antimalware. La comprobacion de requisitos es pura; la proteccion real
//!   necesita el certificado AM firmado por Microsoft y queda gated (el CI lo
//!   declara), igual que el driver WDK del minifilter.
//!
//! La DECISION de tamper vive ademas en C portable
//! (`kernel/windows/aegis/aegis_tamper_politica.c`), que el futuro minifilter
//! del WDK incluye; este modulo Rust es su espejo probado contra la misma tabla
//! de verdad.
//!
//! ## Resiliencia empresarial (FASE 60): los contratos de ABI y el guardian
//!
//! Sobre esas piezas, la autodefensa se lleva a nivel de sistema con dos capas
//! mas:
//!
//! - **Contratos de ABI** ([`abi`]): las estructuras binarias EXACTAS con las
//!   que la decision cruza al kernel de Windows —el callback de ELAM
//!   (`BDCB_*`) y el byte `PS_PROTECTION` de PPL—, con tamano, offsets y codigos
//!   reales del WDK verificados EN COMPILACION. Si la ABI se desincroniza, no
//!   compila. La carga en vivo del driver es el muro, declarado.
//! - **Guardian de detencion** ([`resiliencia`], [`AegisResilience`]): traduce
//!   una senal de parada del sistema operativo (`SIGTERM`, un control del SCM,
//!   una peticion de desinstalar) a su [`OperacionProtegida`] y le aplica la
//!   regla de tamper con verificacion real del OTP. Es "el agente rechaza
//!   cualquier senal de parada sin un OTP del Control Plane", extremo a extremo y
//!   con firmas hibridas reales. Y no miente: declara cuando una senal
//!   (`SIGKILL`/`SIGSTOP`) no es interceptable desde el espacio de usuario y su
//!   cumplimiento es cosa del kernel (PPL).

#![forbid(unsafe_code)]

pub mod abi;
pub mod elam;
pub mod otp;
pub mod ppl;
pub mod replay;
pub mod resiliencia;
pub mod tamper;

pub use elam::{ClasificacionElam, PoliticaElam};
pub use otp::{OperacionProtegida, OrdenAutorizada, Otp};
pub use ppl::{NivelProteccion, RequisitosPpl};
pub use replay::RegistroOtp;
pub use resiliencia::{AegisResilience, MotivoDetencion, ResultadoDetencion, SenalDetencion};
pub use tamper::{decidir, ContextoTamper, Solicitante, Veredicto};

use thiserror::Error;

/// Error de la autodefensa.
///
/// Cada variante es un motivo por el que un OTP se rechaza. Se distinguen para
/// el registro de auditoria del Control Plane —el dueno tiene derecho a saber
/// por que su orden no se acepto—, a diferencia del AEAD del canal, donde no
/// distinguir el motivo evita dar un oraculo al atacante: aqui el "atacante" que
/// presenta un OTP invalido no aprende nada util, porque no puede fabricar uno
/// valido sin la clave del Control Plane.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum TamperError {
    /// El OTP no tiene el tamano/formato esperado.
    #[error("OTP mal formado: {0}")]
    FormatoInvalido(&'static str),

    /// La firma hibrida del OTP no verifica: no lo emitio el Control Plane.
    #[error("firma del OTP invalida: no lo emitio el Control Plane")]
    FirmaInvalida,

    /// El OTP autoriza a OTRO host (no puede reutilizarse en esta maquina).
    #[error("OTP para otro host: no autoriza esta maquina")]
    HostEquivocado,

    /// El OTP autoriza OTRA operacion (p. ej. parar, no desinstalar).
    #[error("OTP para otra operacion: autoriza {autorizada:?}, se pidio {pedida:?}")]
    OperacionEquivocada {
        /// Operacion que el OTP autoriza.
        autorizada: OperacionProtegida,
        /// Operacion que se intento realizar.
        pedida: OperacionProtegida,
    },

    /// El OTP esta fuera de su ventana de validez (caducado o del futuro).
    #[error("OTP fuera de la ventana de validez")]
    FueraDeVentana,

    /// El OTP ya se uso: un OTP es de un SOLO uso (anti-replay).
    #[error("OTP ya consumido: es de un solo uso")]
    Replay,

    /// No se pudo obtener entropia para el nonce al EMITIR un OTP (fallo de
    /// entorno del Control Plane, no un rechazo).
    #[error("sin entropia del sistema para emitir el OTP")]
    Entropia,
}

impl From<aegis_pqc::PqcError> for TamperError {
    fn from(_: aegis_pqc::PqcError) -> Self {
        // Cualquier fallo criptografico al verificar la firma del OTP se colapsa
        // en "firma invalida": ante la duda, no se autoriza.
        TamperError::FirmaInvalida
    }
}
