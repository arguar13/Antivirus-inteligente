//! # aegis-watchdog
//!
//! Watchdog de alta disponibilidad del agente de AegisCore.
//!
//! Un EDR que se puede tumbar con un `kill` no protege nada: el atacante lo
//! primero que hace es apagar la vigilancia. El agente no puede impedir su
//! propia terminacion (un `SIGKILL` de root no se bloquea), asi que la
//! resiliencia la aporta un proceso aparte, minimo, que lo vuelve a arrancar.
//!
//! - [`heartbeat`]: el agente escribe un latido periodico; el watchdog sabe asi
//!   si esta VIVO y no solo presente.
//! - [`supervisor`]: la decision de reiniciar, distinguiendo muerto de colgado y
//!   de parada autorizada.
//! - [`watchdog`]: lanza, observa y reinicia el objetivo.
//!
//! Al reiniciar no se pierden las politicas: el agente las recarga de disco al
//! arrancar, y el watchdog solo lo vuelve a poner en marcha.

#![deny(missing_docs)]

pub mod heartbeat;
pub mod supervisor;
pub mod watchdog;

pub use heartbeat::{now_ns, Heartbeat};
pub use supervisor::{decide, Decision, TargetState};
pub use watchdog::{Target, Watchdog, WatchdogError};
