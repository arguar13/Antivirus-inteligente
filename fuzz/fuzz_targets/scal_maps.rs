#![no_main]
//! Fuzz del parser de `/proc/<pid>/maps`.
//!
//! Aunque el kernel produce estas lineas, el parser se usa sobre procesos
//! arbitrarios y su robustez es la base de todo el analisis de memoria. Debe
//! devolver una lista (posiblemente vacia) ante cualquier texto, sin panicar.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let texto = String::from_utf8_lossy(data);
    let _ = aegis_scal::linux::memory::parse_maps(&texto);
});
