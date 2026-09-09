//! Esqueleto del backend de macOS.
//!
//! # Estado
//!
//! Igual que el de Windows: los tipos implementan los cuatro rasgos y devuelven
//! [`ScalError::Unsupported`] nombrando la interfaz nativa que falta. No
//! simulan resultados, por la misma razon: una lista vacia se lee como "no hay
//! nada malo".
//!
//! # Particularidad de macOS
//!
//! `EndpointSecurity` exige que el binario lleve el *entitlement*
//! `com.apple.developer.endpoint-security.client`, que Apple concede caso por
//! caso, y ademas obliga a responder a los eventos con veredicto dentro de un
//! plazo o el sistema mata al cliente. Eso condiciona el diseno del port entero
//! y esta anotado aqui para que no se descubra a mitad de la implementacion.
//!
//! # Interfaces nativas previstas
//!
//! | Rasgo | Interfaz |
//! |---|---|
//! | `ProcessLifecycleProvider` | `EndpointSecurity` (`ES_EVENT_TYPE_NOTIFY_EXEC`, `..._EXIT`); consulta con `sysctl` `KERN_PROC_ALL`. La identidad estable es `kp_proc.p_starttime`. |
//! | `FileSystemMonitor` | `FSEvents` para la vigilancia de integridad; `ES_EVENT_TYPE_AUTH_*` para el camino con veredicto. |
//! | `NetworkFilter` | `NEFilterProvider` de Network Extension, o `pf` con un ancla propia cuando no hay extension firmada. |
//! | `MemoryInspector` | `mach_vm_region_recurse` para enumerar y `mach_vm_read_overwrite` para leer, con `task_for_pid`. |

use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use crate::error::ScalError;
use crate::fsmon::{FileEvent, FileSystemMonitor};
use crate::memory::{MemoryInspector, MemoryRegion};
use crate::netfilter::{BlockReason, BlockedAddress, NetworkFilter};
use crate::platform::{Capabilities, Platform, Support};
use crate::process::{ProcessEvent, ProcessInfo, ProcessKey, ProcessLifecycleProvider};

const PLAT: Platform = Platform::MacOs;

fn falta(feature: &'static str, detail: &'static str) -> ScalError {
    ScalError::Unsupported {
        feature,
        platform: PLAT,
        detail,
    }
}

/// Capacidades de macOS en el estado actual del port.
pub fn capabilities() -> Capabilities {
    Capabilities {
        platform: PLAT,
        process_events: Support::Unavailable("falta el cliente de EndpointSecurity"),
        process_query: Support::Unavailable("falta sysctl KERN_PROC_ALL"),
        file_events: Support::Unavailable("falta el flujo de FSEvents"),
        network_filter: Support::Unavailable("falta el NEFilterProvider o el ancla de pf"),
        memory_inspection: Support::Unavailable("falta mach_vm_region_recurse/mach_vm_read"),
    }
}

/// Ciclo de vida de procesos en macOS.
#[derive(Debug, Clone, Copy, Default)]
pub struct EndpointSecurityProcesses;

impl ProcessLifecycleProvider for EndpointSecurityProcesses {
    fn platform(&self) -> Platform {
        PLAT
    }
    fn list(&self) -> Result<Vec<ProcessInfo>, ScalError> {
        Err(falta("process.list", "sysctl KERN_PROC_ALL"))
    }
    fn info(&self, _pid: u32) -> Result<ProcessInfo, ScalError> {
        Err(falta("process.info", "sysctl KERN_PROC_PID"))
    }
    fn key_of(&self, _pid: u32) -> Result<ProcessKey, ScalError> {
        Err(falta("process.key_of", "kp_proc.p_starttime"))
    }
    fn children_of(&self, _pid: u32) -> Result<Vec<u32>, ScalError> {
        Err(falta("process.children_of", "sysctl KERN_PROC_ALL"))
    }
    fn is_alive(&self, _key: ProcessKey) -> bool {
        false
    }
    fn poll(&mut self, _timeout: Duration) -> Result<Vec<ProcessEvent>, ScalError> {
        Err(falta("process.poll", "EndpointSecurity es_new_client"))
    }
}

/// Vigilancia del sistema de ficheros en macOS.
#[derive(Debug, Clone, Copy, Default)]
pub struct FsEventsMonitor;

impl FileSystemMonitor for FsEventsMonitor {
    fn platform(&self) -> Platform {
        PLAT
    }
    fn watch(&mut self, _dir: &Path) -> Result<(), ScalError> {
        Err(falta("fsmon.watch", "FSEventStreamCreate"))
    }
    fn watched(&self) -> usize {
        0
    }
    fn poll(&mut self, _timeout: Duration) -> Result<Vec<FileEvent>, ScalError> {
        Err(falta("fsmon.poll", "FSEventStreamScheduleWithRunLoop"))
    }
}

/// Filtro de red en macOS.
#[derive(Debug, Clone, Copy, Default)]
pub struct NetworkExtensionFilter;

impl NetworkFilter for NetworkExtensionFilter {
    fn platform(&self) -> Platform {
        PLAT
    }
    fn available(&self) -> bool {
        false
    }
    fn block(
        &self,
        _addr: IpAddr,
        _reason: BlockReason,
        _ttl: Option<Duration>,
    ) -> Result<(), ScalError> {
        Err(falta("netfilter.block", "NEFilterProvider o ancla de pf"))
    }
    fn unblock(&self, _addr: IpAddr) -> Result<(), ScalError> {
        Err(falta("netfilter.unblock", "NEFilterProvider o ancla de pf"))
    }
    fn blocked(&self) -> Result<Vec<BlockedAddress>, ScalError> {
        Err(falta("netfilter.blocked", "pfctl -a aegis -s Tables"))
    }
    fn flush(&self) -> Result<(), ScalError> {
        Err(falta("netfilter.flush", "pfctl -a aegis -F all"))
    }
}

/// Lector de memoria en macOS.
#[derive(Debug, Clone, Copy, Default)]
pub struct MachMemoryInspector;

impl MemoryInspector for MachMemoryInspector {
    fn platform(&self) -> Platform {
        PLAT
    }
    fn regions(&self, _pid: u32) -> Result<Vec<MemoryRegion>, ScalError> {
        Err(falta("memory.regions", "mach_vm_region_recurse"))
    }
    fn read(&self, _pid: u32, _addr: u64, _len: usize) -> Result<Vec<u8>, ScalError> {
        Err(falta("memory.read", "mach_vm_read_overwrite"))
    }
}
