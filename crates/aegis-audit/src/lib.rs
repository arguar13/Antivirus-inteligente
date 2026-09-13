//! # aegis-audit
//!
//! Registro local de auditoria: SQLite embebida, cuerpos cifrados con
//! AES-256-GCM y rotacion automatica.
//!
//! Un EDR tiene que dejar constancia de lo que ve —para el analisis forense
//! posterior, para el operador, para saber por que aisló un proceso— sin
//! convertir esa constancia en un problema. Dos riesgos, dos respuestas:
//!
//! - **Ese registro es informacion sensible.** Lleva rutas, lineas de comando y
//!   detalle de la actividad del equipo. Los cuerpos se cifran por fila; ver el
//!   modelo de amenaza en [`logger`].
//! - **Ese registro no puede llenar el disco.** Rota al superar un tamano y
//!   conserva un numero acotado de segmentos: el coste en disco esta acotado por
//!   diseno.
//!
//! La base es SQLite embebida (compilada dentro, sin dependencias del sistema),
//! de modo que consultar por instante o gravedad es una consulta indexada y no
//! un recorrido de todo el fichero.

// SEGURIDAD DE MEMORIA IMPUESTA POR EL COMPILADOR (FASE 80).
//
// Este crate no necesita `unsafe`, asi que lo prohibe. No es una declaracion de
// intenciones: `forbid` no se puede levantar desde dentro ni con un `allow`, asi
// que el dia que alguien optimice un bucle con un puntero crudo, no compila.
//
// La invariante del producto no admite tercera opcion: todo crate del agente O
// declara esto, O esta en `tools/lineabase-unsafe.txt` con su razon escrita. Un
// crate que se cuele sin ninguna de las dos hace fallar
// `tools/verificar-invariantes.sh`.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod crypto;
pub mod event;
pub mod logger;

pub use crypto::CryptoError;
pub use event::{AuditEvent, Severity, StoredEvent};
pub use logger::{AuditConfig, AuditError, AuditLogger};
