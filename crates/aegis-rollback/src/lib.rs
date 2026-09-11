//! Reversion de ransomware: deshacer el cifrado en milisegundos (FASE 50).
//!
//! # Que anade y que reutiliza
//!
//! El DETECTOR ya existe: `aegis-ransom` mira velocidad de escritura, honeypots
//! y entropia y produce un veredicto, y `KillResponder` ya mata el arbol de
//! procesos. Lo que faltaba es DESHACER: cuando el veredicto llega, los primeros
//! ficheros ya estan cifrados. Esta fase no es un detector nuevo; es la
//! capacidad de revertir, y orquesta lo que ya hay.
//!
//! La idea: interceptar la escritura ANTES de que ocurra, guardar una
//! copia-sombra CIFRADA del contenido original, y —si se confirma ransomware—
//! matar el proceso y restaurar los ficheros desde las copias-sombra. Si el
//! veredicto no llega, las copias caducan y se borran.
//!
//! # La parte que puede estar mal de forma peligrosa
//!
//! El [`journal`]: decide QUE escritura merece copia y CUANDO. Si guarda la
//! version equivocada —la ya cifrada— el rollback restaura basura; si captura
//! demasiado tarde, el original ya se perdio. Es logica portable y se prueba
//! aqui con un cifrador sintetico REAL (ChaCha20) que sube la entropia igual que
//! el ransomware de verdad, restaurando ficheros de verdad en disco.
//!
//! # La fontaneria, aislada
//!
//! La captura CoW en vivo —fanotify en Linux, el minifilter `.sys` en
//! Windows— intercepta la escritura en el kernel. Necesita `CAP_SYS_ADMIN` o el
//! WDK, asi que esta tras la feature `fanotify` (Linux) o gated por `$WDK_ROOT`
//! (Windows), y el CI declara si se ejercio. La DECISION del minifilter vive
//! aparte en `aegis_rollback_politica.c`, C portable, por el mismo motivo que en
//! la FASE 47.

// El nucleo es libre de `unsafe`. La unica excepcion es el modulo `captura`
// (gated tras la feature `fanotify`), que hace syscalls: alli el `unsafe` se
// justifica bloque a bloque con SAFETY. Por eso es `deny` (admite una excepcion
// local documentada) y no `forbid` (que no admite ninguna).
#![deny(unsafe_code)]

pub mod journal;
pub mod plan;
pub mod revert;
pub mod shadowstore;

#[cfg(feature = "fanotify")]
#[allow(unsafe_code)] // syscalls de fanotify; cada bloque lleva su justificacion SAFETY
pub mod captura;

pub use journal::{DecisionDiario, Journal};
pub use plan::{PasoReversion, PlanReversion};
pub use revert::{RevertError, Reverter, ReverterFichero};
pub use shadowstore::{AlmacenSombra, SombraError, SombraId};
