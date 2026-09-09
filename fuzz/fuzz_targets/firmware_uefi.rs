#![no_main]
//! Fuzz de los parsers de variables UEFI y listas de firmas (DBX).
//!
//! El contenido de una variable efivarfs y las listas de firmas de la DBX son
//! datos estructurados que, en un endpoint comprometido, pueden estar
//! manipulados. Los tres parsers deben tolerar cualquier byte.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = aegis_firmware::uefi::parse_variable_bytes(data);
    let _ = aegis_firmware::uefi::parse_signature_lists(data);
    let _ = aegis_firmware::uefi::Dbx::parse(data);
});
