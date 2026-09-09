#![no_main]
//! Fuzz del extractor de CN de certificados.
//!
//! `subject_cn` camina DER que, en el peor caso, viene de un certificado que un
//! atacante construyo a mano. Ante cualquier byte, debe devolver `None` o un
//! `String`, nunca panicar por un indice fuera de rango o un varint absurdo.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = aegis_fleet::x509::subject_cn(data);
});
