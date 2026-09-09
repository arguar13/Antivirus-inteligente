//! # aegis-syscallguard
//!
//! Deteccion de **syscalls directas**: la tecnica con la que el malware moderno
//! entra al kernel sin pasar por el trampolin de `libc` que los EDR vigilan.
//!
//! # El problema que resuelve
//!
//! Todo el resto del producto que observa el comportamiento —los enganches de
//! `libc` de [`aegis-evasion`], la telemetria de syscalls— asume que las
//! syscalls salen de donde siempre: el `.text` de `libc`. Un atacante que
//! incrusta su propia instruccion `syscall` (`0F 05` en x86-64) y salta al
//! kernel por su cuenta lo esquiva entero. El enganche nunca se dispara; la
//! syscall pasa sin ser vista.
//!
//! # Como se detecta, en tres capas
//!
//! | Capa | Mecanismo | Estado en esta maquina |
//! |---|---|---|
//! | Verificacion cruzada | [`guardia`]: el kernel da el puntero de instruccion de cada syscall ([`PTRACE_GET_SYSCALL_INFO`]), y se cruza con `/proc/<pid>/maps` | operativa |
//! | Registros de depuracion | [`drx`]: puntos de ruptura por hardware sobre la puerta de syscall sancionada | disponible |
//! | PMU | [`pmu`]: contador de hardware para cribado barato y continuo | no aplicable (microVM sin PMU) |
//!
//! [`PTRACE_GET_SYSCALL_INFO`]: abi::PTRACE_GET_SYSCALL_INFO
//!
//! # La verificacion cruzada, en concreto
//!
//! El hardware captura, en cada syscall, la direccion exacta desde la que se
//! llamo al kernel. Esa es una vista; el mapa de memoria del proceso es la
//! otra. Se cruzan ([`origen`]):
//!
//! - Puntero en el `.text` de `libc`/`ld` → legitima.
//! - Puntero en memoria ANONIMA ejecutable → codigo sin fichero detras: la
//!   firma de la syscall directa. Nadie compila asi.
//! - Puntero imposible, o `syscall` que no esta donde el kernel dice → la
//!   propia informacion del kernel es sospechosa. **Si el kernel miente, se
//!   descubre** leyendo los bytes reales de la memoria.
//!
//! # Por que "respaldada por hardware"
//!
//! El puntero de instruccion que se cruza no lo inventa el agente: lo captura
//! la CPU en el instante del `syscall` y el kernel lo transcribe. La PMU y los
//! registros de depuracion son hardware puro. Donde la PMU no esta —esta
//! maquina—, se dice con claridad y la deteccion sigue en pie sobre el
//! trazador, que no la necesita.
//!
//! [`aegis-evasion`]: https://docs.rs/aegis-evasion
//! [`aegis-scan`]: https://docs.rs/aegis-scan

#![deny(missing_docs)]

pub mod abi;
pub mod drx;
pub mod error;
pub mod guardia;
pub mod origen;
pub mod perf;
pub mod pmu;
pub mod report;

pub use drx::{sondear_drx, SoporteDrx, VigilanteEjecucion};
pub use error::SyscallGuardError;
pub use guardia::{ConfigPerfilado, SyscallGuard};
pub use origen::{clasificar, OrigenSyscall, Severidad};
pub use pmu::{sondear_pmu, ContadorHardware, SoportePmu};
pub use report::{
    AnomaliaSyscall, ConteoOrigen, EstadoSyscall, InformeSyscall, SoporteSyscallGuard,
};
