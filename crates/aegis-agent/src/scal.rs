//! Puente entre la telemetria de eBPF y la capa de abstraccion del sistema.
//!
//! El agente tiene dos fuentes que hablan de lo mismo con vocabularios
//! distintos: las sondas de eBPF, que avisan de un `execve` en microsegundos, y
//! el censo de `/proc` de [`aegis_scal`], que responde consultas completas. Este
//! modulo las junta en un solo [`ProcessLifecycleProvider`] para que el resto
//! del producto no tenga que saber de ninguna de las dos.
//!
//! # La decision que hace que esto sea correcto
//!
//! La IDENTIDAD siempre la fija `procfs`, nunca el evento de eBPF. Las dos
//! fuentes tienen relojes distintos —`procfs` cuenta tics desde el arranque del
//! sistema y la sonda entrega nanosegundos monotonos—, y construir claves con
//! uno u otro segun quien avise primero produciria dos identidades para el
//! mismo proceso. Cuando el proceso ya murio antes de poder resolverlo, el
//! evento se cuenta como perdido ([`EbpfProcessProvider::perdidos`]) en vez de
//! inventar una clave: un contador visible es preferible a una identidad falsa.
//!
//! # Y por que no se duplican los eventos
//!
//! Cuando el puente emite un nacimiento o una muerte aprendidos por eBPF,
//! reconcilia el censo de `procfs` con esa informacion. Sin eso, el censo
//! siguiente volveria a ver el mismo proceso como nuevo y el motor conductual
//! contaria dos veces cada cadena.

use aegis_scal::fsmon::{FileAction, FileEvent};

use crate::triage::TelemetryEvent;

/// Traduce un evento de telemetria a un cambio en el sistema de ficheros.
///
/// Devuelve mas de uno para un renombrado: mover un fichero es a la vez una
/// salida del origen y una entrada en el destino, y un vigilante que solo viera
/// una de las dos mitades dejaria la linea base descuadrada.
///
/// Los eventos que no hablan del contenido del disco —una asociacion de
/// descriptor, un `ptrace`, una conexion— devuelven la lista vacia. Es
/// deliberado: forzarlos a un `FileEvent` seria justo la clase de traduccion
/// falsa que esta capa existe para evitar.
pub fn eventos_de_fichero(ev: &TelemetryEvent) -> Vec<FileEvent> {
    match ev {
        TelemetryEvent::FileWrite { path, .. } => vec![FileEvent {
            path: std::path::PathBuf::from(path.as_ref()),
            kind: FileAction::Modified,
        }],
        TelemetryEvent::FileWriteSample { .. } => Vec::new(),
        TelemetryEvent::FileRename { from, to, .. } => vec![
            FileEvent {
                path: std::path::PathBuf::from(from.as_ref()),
                kind: FileAction::MovedOut,
            },
            FileEvent {
                path: std::path::PathBuf::from(to.as_ref()),
                kind: FileAction::MovedIn,
            },
        ],
        _ => Vec::new(),
    }
}

#[cfg(target_os = "linux")]
pub use linux::EbpfProcessProvider;

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::{HashMap, VecDeque};
    use std::time::Duration;

    use aegis_scal::error::ScalError;
    use aegis_scal::linux::process::ProcFsProcesses;
    use aegis_scal::platform::Platform;
    use aegis_scal::process::{ProcessEvent, ProcessInfo, ProcessKey, ProcessLifecycleProvider};

    use crate::graph::ProcKey;
    use crate::triage::TelemetryEvent;

    /// Proveedor de ciclo de vida que combina las sondas de eBPF con `procfs`.
    #[derive(Debug)]
    pub struct EbpfProcessProvider {
        procfs: ProcFsProcesses,
        /// Actor del ABI -> identidad de la capa. Es lo que permite resolver la
        /// identidad de una MUERTE: el evento de salida solo trae el actor, y
        /// para entonces `/proc/<pid>` ya no existe.
        identidades: HashMap<ProcKey, ProcessKey>,
        cola: VecDeque<ProcessEvent>,
        perdidos: u64,
    }

    impl EbpfProcessProvider {
        /// Crea el puente, tomando el censo inicial de `procfs`.
        pub fn new() -> EbpfProcessProvider {
            EbpfProcessProvider {
                procfs: ProcFsProcesses::new(),
                identidades: HashMap::new(),
                cola: VecDeque::new(),
                perdidos: 0,
            }
        }

        /// Eventos de eBPF que no se pudieron convertir porque el proceso ya no
        /// existia al resolverlo.
        ///
        /// Un valor alto significa que la maquina crea procesos que viven menos
        /// de lo que tarda el agente en drenar el ring: es una senal de carga,
        /// no un error, pero deja de verse el linaje de esas cadenas.
        pub fn perdidos(&self) -> u64 {
            self.perdidos
        }

        /// Numero de identidades vivas que el puente esta siguiendo.
        pub fn seguidos(&self) -> usize {
            self.identidades.len()
        }

        /// Convierte un evento de telemetria en un evento de la capa.
        ///
        /// Devuelve `true` si el evento produjo un cambio de ciclo de vida.
        pub fn ingest(&mut self, ev: &TelemetryEvent) -> bool {
            match ev {
                TelemetryEvent::Exec { actor, pid, .. } => {
                    // La identidad la fija `procfs`, no el evento: ver la nota
                    // del modulo sobre los dos relojes.
                    let Ok(info) = self.procfs.info(*pid) else {
                        self.perdidos += 1;
                        return false;
                    };
                    self.identidades.insert(*actor, info.key);
                    self.procfs.reconciliar_alta(info.key);
                    self.cola.push_back(ProcessEvent::Started(Box::new(info)));
                    true
                }
                TelemetryEvent::Exit { actor, .. } => {
                    let Some(key) = self.identidades.remove(actor) else {
                        // Salida de un proceso que ya existia antes de arrancar
                        // el agente: no hay identidad que reportar, y el censo
                        // la vera por su cuenta en la siguiente vuelta.
                        return false;
                    };
                    self.procfs.reconciliar_baja(key);
                    self.cola.push_back(ProcessEvent::Exited {
                        key,
                        exit_code: None,
                    });
                    true
                }
                _ => false,
            }
        }
    }

    impl Default for EbpfProcessProvider {
        fn default() -> Self {
            EbpfProcessProvider::new()
        }
    }

    impl ProcessLifecycleProvider for EbpfProcessProvider {
        fn platform(&self) -> Platform {
            Platform::Linux
        }

        fn list(&self) -> Result<Vec<ProcessInfo>, ScalError> {
            self.procfs.list()
        }

        fn info(&self, pid: u32) -> Result<ProcessInfo, ScalError> {
            self.procfs.info(pid)
        }

        fn key_of(&self, pid: u32) -> Result<ProcessKey, ScalError> {
            self.procfs.key_of(pid)
        }

        fn children_of(&self, pid: u32) -> Result<Vec<u32>, ScalError> {
            self.procfs.children_of(pid)
        }

        fn is_alive(&self, key: ProcessKey) -> bool {
            self.procfs.is_alive(key)
        }

        fn poll(&mut self, timeout: Duration) -> Result<Vec<ProcessEvent>, ScalError> {
            if !self.cola.is_empty() {
                return Ok(self.cola.drain(..).collect());
            }
            // Sin nada de eBPF se cae al censo, que es la red de seguridad: ve
            // los procesos que ya existian y los que la sonda no alcanzo a
            // emitir por ring lleno.
            self.procfs.poll(timeout)
        }
    }
}
