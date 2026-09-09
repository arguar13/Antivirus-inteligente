//! # aegis-kguard
//!
//! Guarda de Ring 0: integridad del bytecode eBPF y bloqueo de sus mapas.
//!
//! El agente carga programas en el kernel. Dos cosas pueden salir mal entre la
//! compilacion y la carga, y las dos las cubre este crate:
//!
//! - [`integrity`]: que el `.bpf.o` que se carga no sea el que se compilo.
//!   Se firma con HMAC-SHA256 en la compilacion y se verifica antes de cargar.
//! - [`mapperms`]: que los mapas fijados queden legibles por cualquiera. Se
//!   exige 0600 y propietario root, y se comprueba tras fijar.
//!
//! Ninguna de las dos requiere un kernel para probarse: la firma y la
//! comparacion son aritmetica pura, y la logica de permisos opera sobre un modo
//! y un uid. Por eso el crate es verificable entero en el host, que es donde
//! vive el valor de la correccion.

#![deny(missing_docs)]

pub mod integrity;
pub mod mapperms;

/// Clave de desarrollo para firmar el bytecode eBPF.
///
/// Es la MISMA que usa `drivers/linux/aegis-bpf/tools/sign_bytecode.py` como
/// clave por defecto, de modo que el manifiesto que firma Python lo verifica
/// este crate. En produccion la clave es un secreto de compilacion que sustituye
/// a esta; que este en claro aqui no debilita nada mientras se use solo para el
/// pipeline de desarrollo y las pruebas.
pub const DEV_BPF_KEY: [u8; 32] = [
    0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
];

pub use integrity::{constant_time_eq, hmac_sha256, IntegrityError, Manifest};
pub use mapperms::{evaluar, MapPermVerdict, MODO_MAPA};
