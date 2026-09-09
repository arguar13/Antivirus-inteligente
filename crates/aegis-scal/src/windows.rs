//! Esqueleto del backend de Windows.
//!
//! # Estado
//!
//! Los tipos de este modulo implementan los cuatro rasgos y devuelven
//! [`ScalError::Unsupported`] con el nombre de la interfaz nativa que falta por
//! escribir. NO simulan nada: un backend que devolviera listas vacias haria que
//! el motor de deteccion creyera que la maquina esta limpia, que es peor que no
//! tener backend.
//!
//! # Por que se compila en todas las plataformas
//!
//! El modulo no contiene FFI de Windows, solo las implementaciones de los
//! rasgos. Eso es deliberado: asi `cargo clippy` y `cargo test` en el Linux del
//! CI comprueban de verdad que estas implementaciones siguen cuadrando con los
//! rasgos. Un esqueleto detras de `#[cfg(target_os = "windows")]` deja de
//! compilar en cuanto alguien cambia una firma y nadie se entera hasta el dia
//! del port. Lo que si va bajo `cfg` es la ELECCION del backend anfitrion, en
//! [`crate::SystemCore::host`].
//!
//! # Interfaces nativas previstas
//!
//! | Rasgo | Interfaz |
//! |---|---|
//! | `ProcessLifecycleProvider` | Proveedor ETW `Microsoft-Windows-Kernel-Process`; consulta con `NtQuerySystemInformation`/`CreateToolhelp32Snapshot`. La identidad estable es el `CreateTime` del `KERNEL_USER_TIMES`. |
//! | `FileSystemMonitor` | Minifiltro propio (`FltRegisterFilter`) para el camino con veredicto; `ReadDirectoryChangesW` para la vigilancia de integridad. |
//! | `NetworkFilter` | Windows Filtering Platform: sublayer propio con `FwpmSubLayerAdd0` y filtros `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6`. |
//! | `MemoryInspector` | `VirtualQueryEx` para enumerar y `ReadProcessMemory` para leer, con `PROCESS_QUERY_LIMITED_INFORMATION`. |

use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use crate::error::ScalError;
use crate::fsmon::{FileEvent, FileSystemMonitor};
use crate::memory::{MemoryInspector, MemoryRegion};
use crate::netfilter::{BlockReason, BlockedAddress, NetworkFilter};
use crate::platform::{Capabilities, Platform, Support};
use crate::process::{ProcessEvent, ProcessInfo, ProcessKey, ProcessLifecycleProvider};

const PLAT: Platform = Platform::Windows;

fn falta(feature: &'static str, detail: &'static str) -> ScalError {
    ScalError::Unsupported {
        feature,
        platform: PLAT,
        detail,
    }
}

/// Capacidades de Windows en el estado actual del port.
pub fn capabilities() -> Capabilities {
    Capabilities {
        platform: PLAT,
        process_events: Support::Unavailable("falta el consumidor ETW de Kernel-Process"),
        process_query: Support::Unavailable("falta NtQuerySystemInformation"),
        file_events: Support::Unavailable("falta ReadDirectoryChangesW"),
        network_filter: Support::Unavailable("falta el sublayer de WFP"),
        memory_inspection: Support::Unavailable("falta VirtualQueryEx/ReadProcessMemory"),
    }
}

/// Ciclo de vida de procesos en Windows.
#[derive(Debug, Clone, Copy, Default)]
pub struct EtwProcesses;

impl ProcessLifecycleProvider for EtwProcesses {
    fn platform(&self) -> Platform {
        PLAT
    }
    fn list(&self) -> Result<Vec<ProcessInfo>, ScalError> {
        Err(falta("process.list", "NtQuerySystemInformation"))
    }
    fn info(&self, _pid: u32) -> Result<ProcessInfo, ScalError> {
        Err(falta("process.info", "NtQuerySystemInformation"))
    }
    fn key_of(&self, _pid: u32) -> Result<ProcessKey, ScalError> {
        Err(falta("process.key_of", "GetProcessTimes"))
    }
    fn children_of(&self, _pid: u32) -> Result<Vec<u32>, ScalError> {
        Err(falta("process.children_of", "CreateToolhelp32Snapshot"))
    }
    fn is_alive(&self, _key: ProcessKey) -> bool {
        false
    }
    fn poll(&mut self, _timeout: Duration) -> Result<Vec<ProcessEvent>, ScalError> {
        Err(falta(
            "process.poll",
            "ETW Microsoft-Windows-Kernel-Process",
        ))
    }
}

/// Vigilancia del sistema de ficheros en Windows.
#[derive(Debug, Clone, Copy, Default)]
pub struct DirectoryChangesMonitor;

impl FileSystemMonitor for DirectoryChangesMonitor {
    fn platform(&self) -> Platform {
        PLAT
    }
    fn watch(&mut self, _dir: &Path) -> Result<(), ScalError> {
        Err(falta("fsmon.watch", "ReadDirectoryChangesW"))
    }
    fn watched(&self) -> usize {
        0
    }
    fn poll(&mut self, _timeout: Duration) -> Result<Vec<FileEvent>, ScalError> {
        Err(falta("fsmon.poll", "ReadDirectoryChangesW"))
    }
}

/// Filtro de red en Windows.
#[derive(Debug, Clone, Copy, Default)]
pub struct WfpFilter;

impl NetworkFilter for WfpFilter {
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
        Err(falta("netfilter.block", "FwpmFilterAdd0"))
    }
    fn unblock(&self, _addr: IpAddr) -> Result<(), ScalError> {
        Err(falta("netfilter.unblock", "FwpmFilterDeleteById0"))
    }
    fn blocked(&self) -> Result<Vec<BlockedAddress>, ScalError> {
        Err(falta("netfilter.blocked", "FwpmFilterEnum0"))
    }
    fn flush(&self) -> Result<(), ScalError> {
        Err(falta("netfilter.flush", "FwpmSubLayerDeleteByKey0"))
    }
}

/// Lector de memoria en Windows.
#[derive(Debug, Clone, Copy, Default)]
pub struct WinMemoryInspector;

impl MemoryInspector for WinMemoryInspector {
    fn platform(&self) -> Platform {
        PLAT
    }
    fn regions(&self, _pid: u32) -> Result<Vec<MemoryRegion>, ScalError> {
        Err(falta("memory.regions", "VirtualQueryEx"))
    }
    fn read(&self, _pid: u32, _addr: u64, _len: usize) -> Result<Vec<u8>, ScalError> {
        Err(falta("memory.read", "ReadProcessMemory"))
    }
}
