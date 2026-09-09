//! # aegis-harden
//!
//! Blindaje del agente de Ring 3 contra la ingenieria inversa.
//!
//! Reune las dos defensas que se refuerzan entre si:
//!
//! - [`strings`]: las cadenas criticas del binario (endpoints, nombres de
//!   reglas, rutas) no se compilan en claro; se cifran con AES-256-GCM y se
//!   descifran en memoria al arrancar. Detiene el analisis ESTATICO.
//! - [`antidebug`]: detecta y bloquea la conexion de un depurador. Detiene el
//!   analisis DINAMICO.
//!
//! Ninguna de las dos es infalible por separado, y el `README` del crate es
//! explicito sobre sus limites: la clave de descifrado tiene que estar en el
//! binario, y un depurador a nivel de kernel sortea a `ptrace`. Juntas suben el
//! coste del analisis lo suficiente para dejar fuera al atacante oportunista y
//! al analisis automatizado, que es el objetivo realista.
//!
//! La tabla de cadenas cifradas la genera `tools/obfuscate.py` a partir de
//! `tools/secrets.json`, y `tools/obfuscate.py --self-test` demuestra que lo
//! que cifra Python lo descifra este crate, byte a byte.

#![deny(missing_docs)]

pub mod antidebug;
pub mod strings;

mod generated_strings;

/// Descifra al arrancar la tabla de cadenas criticas generada por
/// `tools/obfuscate.py`.
///
/// Es el punto de entrada normal: el resto del agente pide sus endpoints,
/// nombres de reglas y rutas por nombre a traves del [`strings::Vault`] que
/// devuelve esta funcion, en vez de llevarlos en claro.
pub fn unseal_builtin() -> Result<strings::Vault, strings::RevealError> {
    strings::Vault::unseal(
        &generated_strings::KEY_SHARDS,
        generated_strings::KEY_SALT,
        generated_strings::ENTRIES,
    )
}

/// Nombres de las cadenas ofuscadas disponibles en el binario.
pub fn builtin_names() -> impl Iterator<Item = &'static str> {
    generated_strings::ENTRIES.iter().map(|(n, _, _)| *n)
}

pub use antidebug::{detect, enforce, DebuggerCheck, Enforcement, Policy};
pub use strings::{derive_key, reveal, Entry, RevealError, Secret, Vault};
