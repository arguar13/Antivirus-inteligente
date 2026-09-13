//! # aegis-scan
//!
//! Motor de deteccion profunda de AegisCore: firmas YARA sobre ficheros y sobre
//! la memoria de procesos vivos.
//!
//! Escanear ficheros solo ve lo que el atacante dejo en disco. El malware
//! moderno no deja nada: se descomprime en memoria, se inyecta en un proceso
//! legitimo o se ejecuta desde un descriptor que nunca toco el sistema de
//! ficheros. [`memory`] y [`yara::YaraEngine::scan_process`] son lo que permite
//! mirar donde si esta.
//!
//! El escaneo corre en hilos propios ([`service`]) con una cola acotada y envio
//! no bloqueante, porque quien encola es el hilo que drena el ring buffer de
//! eBPF: si ese hilo se bloquea, el kernel empieza a descartar eventos y el
//! producto se queda ciego justo durante el pico que provoco la saturacion.

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

pub mod memory;
pub mod memscanner;
pub mod rules;
pub mod service;
pub mod yara;

pub use memory::{MemoryRegion, MemoryScanPolicy, Perms, RegionClass};
pub use memscanner::{
    AegisMemScanner, CoincidenciaMem, ConfigEscaner, Estrangulador, FuenteMemoria, MemScanError,
    RegionMem, RitmoMaximo, SinEstrangular,
};
pub use service::{ScanJob, ScanOutcome, ScanService, ScanServiceConfig, ScanTarget};
pub use yara::{Detection, ProcessScanReport, Severity, YaraEngine, YaraError};
