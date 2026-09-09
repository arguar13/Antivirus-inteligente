#![no_main]
//! Fuzz del lector de tramas RPC.
//!
//! `leer_marco` interpreta una cabecera con una longitud que controla el par.
//! El objetivo comprueba que una longitud enorme o una trama cortada dan `Err`
//! —o bloquean por falta de datos, que aqui se acota— y jamas reservan memoria
//! sin limite ni panican.

use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    let _ = aegis_fleet::rpc::leer_marco(&mut cursor);
});
