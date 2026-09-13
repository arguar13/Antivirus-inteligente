//! # aegis-fim
//!
//! Monitorizacion de integridad de ficheros criticos: inotify + BLAKE3.
//!
//! Un cambio no autorizado en `/etc`, en los directorios de arranque o en los
//! binarios del sistema es la firma de casi cualquier persistencia: una puerta
//! trasera en `sshd`, una tarea de cron maliciosa, un `sudoers` alterado. El FIM
//! los detecta comparando el estado actual contra una linea base conocida-buena.
//!
//! - [`hash`]: BLAKE3 de los ficheros, concurrente. Rapido porque se recalcula a
//!   menudo, y paralelo porque en el arranque hay cientos de ficheros.
//! - [`watch`]: inotify avisa al kernel de cada cambio, de modo que el agente
//!   reacciona en milisegundos y rehashea solo el fichero que cambio, en vez de
//!   sondear todo cada pocos segundos.
//! - [`baseline`]: la linea base y la comparacion que convierte un cambio en una
//!   alerta de integridad.
//! - [`monitor`]: une las tres cosas.
//!
//! El foco es EXCLUSIVAMENTE ficheros de sistema criticos. Vigilar todo el disco
//! seria caro y ruidoso; la persistencia vive en un puñado de sitios conocidos.

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

pub mod baseline;
pub mod hash;
pub mod monitor;
pub mod watch;

pub use baseline::{Baseline, IntegrityChange};
pub use hash::{hash_bytes, hash_file, hash_files_concurrent, to_hex, Blake3};
pub use monitor::{rutas_criticas_por_defecto, FimConfig, FimMonitor};
pub use watch::{ChangeEvent, ChangeKind, WatchError, Watcher};
