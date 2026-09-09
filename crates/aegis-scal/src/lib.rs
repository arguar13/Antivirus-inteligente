//! # aegis-scal
//!
//! Capa de abstraccion del nucleo del sistema (*System Core Abstraction
//! Layer*).
//!
//! Define, en cuatro rasgos, TODO lo que AegisCore necesita del sistema
//! operativo:
//!
//! - [`ProcessLifecycleProvider`]: quien nace, quien muere y quien es hijo de
//!   quien.
//! - [`FileSystemMonitor`]: que cambia en el disco.
//! - [`NetworkFilter`]: que direcciones se cortan.
//! - [`MemoryInspector`]: que hay dentro de un proceso vivo.
//!
//! # Por que existe
//!
//! Sin esta capa, portar el producto a Windows significaria reescribir el motor
//! de correlacion, el de ransomware, el forense y el de respuesta, porque todos
//! hablan de `/proc`, de `inotify` y de `nftables`. Con ella, lo que se
//! reescribe es un backend, y el valor del producto —la logica de deteccion—
//! se compila igual en los tres sistemas.
//!
//! # La regla que hace que esto no sea una fachada
//!
//! Una capa de abstraccion que finge que todos los sistemas pueden lo mismo es
//! peor que ninguna, porque convierte una limitacion visible en un punto ciego
//! silencioso. Por eso [`Capabilities`] es parte de la interfaz: cada backend
//! declara, capacidad por capacidad, si la implementa con la interfaz nativa,
//! por una via degradada —diciendo cual es la limitacion— o si no la implementa.
//! Un motor que dependa de eventos de proceso nativos puede consultarlo y
//! apagarse, en vez de dar falsos negativos.
//!
//! # Un PID no es una identidad
//!
//! El tipo transversal de la capa es [`ProcessKey`], que lleva el PID **y** el
//! instante de arranque. Los PID se reciclan; cualquier estructura indexada por
//! PID a secas acaba atribuyendo las acciones de un proceso nuevo al historial
//! del anterior. Los tres sistemas exponen la marca de arranque, asi que la
//! identidad correcta se puede construir en los tres.

#![deny(missing_docs)]

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
compile_error!("AegisCore SCAL solo contempla Linux, Windows y macOS");

pub mod error;
pub mod fsmon;
pub mod macos;
pub mod memory;
pub mod netfilter;
pub mod platform;
pub mod process;
pub mod windows;

#[cfg(target_os = "linux")]
pub mod linux;

pub use error::ScalError;
pub use fsmon::{FileAction, FileEvent, FileSystemMonitor};
pub use memory::{MemoryInspector, MemoryRegion, Perms, RegionClass};
pub use netfilter::{BlockReason, BlockedAddress, NetworkFilter};
pub use platform::{Capabilities, Platform, Support};
pub use process::{ProcessEvent, ProcessInfo, ProcessKey, ProcessLifecycleProvider, ProcessState};

/// Capacidades de la plataforma anfitriona.
pub fn capabilities() -> Capabilities {
    capabilities_of(Platform::HOST)
}

/// Capacidades declaradas de una plataforma cualquiera.
///
/// Se puede preguntar por una plataforma que no es la anfitriona: la consola de
/// administracion necesita saber que puede pedirle a un agente de Windows sin
/// tener que correr en Windows.
pub fn capabilities_of(p: Platform) -> Capabilities {
    match p {
        #[cfg(target_os = "linux")]
        Platform::Linux => linux::capabilities(),
        // Fuera de Linux no se puede hablar por el backend de Linux: sus
        // capacidades reales dependen del kernel de la maquina, y afirmarlas
        // desde otro sistema seria inventarlas.
        #[cfg(not(target_os = "linux"))]
        Platform::Linux => Capabilities {
            platform: Platform::Linux,
            process_events: Support::Unavailable("backend no compilado en este binario"),
            process_query: Support::Unavailable("backend no compilado en este binario"),
            file_events: Support::Unavailable("backend no compilado en este binario"),
            network_filter: Support::Unavailable("backend no compilado en este binario"),
            memory_inspection: Support::Unavailable("backend no compilado en este binario"),
        },
        Platform::Windows => windows::capabilities(),
        Platform::MacOs => macos::capabilities(),
    }
}

/// Conjunto de backends de la plataforma anfitriona.
///
/// Es el punto por el que el resto del producto entra a la capa. Se entrega
/// como objetos de rasgo y no como tipos concretos a proposito: el codigo que
/// los usa no debe poder llamar a nada especifico de Linux, porque en el
/// momento en que lo hace deja de compilar en Windows y la capa no ha servido
/// para nada.
pub struct SystemCore {
    /// Ciclo de vida de procesos.
    pub processes: Box<dyn ProcessLifecycleProvider + Send>,
    /// Vigilancia del sistema de ficheros.
    pub files: Box<dyn FileSystemMonitor + Send>,
    /// Filtro de red.
    pub network: Box<dyn NetworkFilter + Send + Sync>,
    /// Lector de memoria.
    pub memory: Box<dyn MemoryInspector + Send + Sync>,
}

impl std::fmt::Debug for SystemCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SystemCore")
            .field("platform", &Platform::HOST)
            .finish()
    }
}

impl SystemCore {
    /// Construye los backends de la plataforma anfitriona.
    ///
    /// Falla solo si un backend no puede ni siquiera inicializarse —en Linux,
    /// que `inotify_init1` agote los descriptores del proceso—. Que una
    /// capacidad no este implementada NO es un fallo aqui: se ve en
    /// [`SystemCore::capabilities`] y en el error de cada llamada concreta.
    pub fn host() -> Result<SystemCore, ScalError> {
        #[cfg(target_os = "linux")]
        {
            let files = linux::fsmon::InotifyMonitor::new().map_err(|e| ScalError::Os {
                op: "inotify_init1",
                source: std::io::Error::other(e.to_string()),
            })?;
            Ok(SystemCore {
                processes: Box::new(linux::process::ProcFsProcesses::new()),
                files: Box::new(files),
                network: Box::new(linux::netfilter::NftablesFilter::new()),
                memory: Box::new(linux::memory::ProcMemoryInspector::new()),
            })
        }
        #[cfg(target_os = "windows")]
        {
            Ok(SystemCore {
                processes: Box::new(windows::EtwProcesses),
                files: Box::new(windows::DirectoryChangesMonitor),
                network: Box::new(windows::WfpFilter),
                memory: Box::new(windows::WinMemoryInspector),
            })
        }
        #[cfg(target_os = "macos")]
        {
            Ok(SystemCore {
                processes: Box::new(macos::EndpointSecurityProcesses),
                files: Box::new(macos::FsEventsMonitor),
                network: Box::new(macos::NetworkExtensionFilter),
                memory: Box::new(macos::MachMemoryInspector),
            })
        }
    }

    /// Capacidades de estos backends.
    pub fn capabilities(&self) -> Capabilities {
        capabilities()
    }
}
