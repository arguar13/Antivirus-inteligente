#![no_main]
//! Fuzz del parser del registro de eventos TCG.
//!
//! El event log lo produce el firmware y lo lee el agente para reconstruir los
//! PCR. Un firmware comprometido —o un fichero manipulado— puede entregar un log
//! arbitrario. El parser tiene que rechazarlo con `Err`, no caerse.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = aegis_firmware::eventlog::parse(data);
});
