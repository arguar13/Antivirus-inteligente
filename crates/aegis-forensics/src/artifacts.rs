//! Artefactos de un incidente: lo que hay que recoger antes de que desaparezca.
//!
//! # Por que se recoge automaticamente
//!
//! Un incidente se investiga horas o dias despues. Para entonces el proceso ya
//! murio, sus sockets se cerraron, su memoria se libero y puede que el binario
//! se haya borrado a si mismo. **Lo que no se recogio en el momento no existe.**
//! Por eso la recogida la dispara la deteccion y no un analista.
//!
//! # Que se recoge, y por que eso
//!
//! - **Arbol de procesos**: quien lanzo a quien. Sin el linaje, un `curl` no
//!   dice nada; con el, es la segunda etapa de una ejecucion remota.
//! - **Sockets**: con quien hablaba. Es lo que permite pivotar a la
//!   infraestructura del atacante y buscarla en el resto de la flota.
//! - **Hashes de los binarios**: identidad del ejecutable, que sobrevive a que
//!   lo renombren o lo borren.
//! - **Memoria**: las regiones anonimas ejecutables, que es donde vive el codigo
//!   que no tiene fichero detras.

use std::path::PathBuf;

/// Que disparo la recogida.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trigger {
    /// Motor que la pidio (conductual, ransomware, decepcion...).
    pub source: String,
    /// Descripcion legible.
    pub reason: String,
    /// Puntuacion o gravedad asociada, si la hay.
    pub score: Option<u8>,
    /// Tecnicas de MITRE atribuidas, por identificador (`T1055`).
    pub techniques: Vec<String>,
}

/// Un proceso del arbol recogido.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessArtifact {
    /// PID.
    pub pid: u32,
    /// PID del padre.
    pub ppid: u32,
    /// Marca de arranque, que junto al PID forma la identidad estable.
    pub start_stamp: u64,
    /// Imagen ejecutada.
    pub image: Option<PathBuf>,
    /// Linea de comandos.
    pub cmdline: Vec<String>,
    /// Usuario efectivo.
    pub uid: u32,
    /// SHA-256 del binario, en hexadecimal.
    ///
    /// Es `None` cuando el binario ya no esta en disco —el caso de un proceso
    /// que se borro a si mismo—, que en un informe forense es en si mismo un
    /// dato: significa que la evidencia se destruyo.
    pub sha256: Option<String>,
    /// Tamano del binario.
    pub image_size: Option<u64>,
}

/// Protocolo de un socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketProto {
    /// TCP sobre IPv4.
    Tcp,
    /// TCP sobre IPv6.
    Tcp6,
    /// UDP sobre IPv4.
    Udp,
    /// UDP sobre IPv6.
    Udp6,
}

impl SocketProto {
    /// Nombre del protocolo de transporte, para STIX.
    pub fn transport(self) -> &'static str {
        match self {
            SocketProto::Tcp | SocketProto::Tcp6 => "tcp",
            SocketProto::Udp | SocketProto::Udp6 => "udp",
        }
    }

    /// Nombre de la capa de red, para STIX.
    pub fn network(self) -> &'static str {
        match self {
            SocketProto::Tcp | SocketProto::Udp => "ipv4",
            SocketProto::Tcp6 | SocketProto::Udp6 => "ipv6",
        }
    }

    /// Fichero de `procfs` del que se lee.
    pub fn procfile(self) -> &'static str {
        match self {
            SocketProto::Tcp => "tcp",
            SocketProto::Tcp6 => "tcp6",
            SocketProto::Udp => "udp",
            SocketProto::Udp6 => "udp6",
        }
    }
}

/// Un socket abierto por un proceso del arbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketArtifact {
    /// PID que lo tiene abierto.
    pub pid: u32,
    /// Protocolo.
    pub proto: SocketProto,
    /// Direccion local.
    pub local: std::net::SocketAddr,
    /// Direccion remota.
    pub remote: std::net::SocketAddr,
    /// Estado, en la nomenclatura de `procfs`.
    pub state: &'static str,
    /// Inodo, que es lo que ata el descriptor a la entrada de `/proc/net`.
    pub inode: u64,
}

impl SocketArtifact {
    /// Indica si el socket esta conectado a algo remoto.
    ///
    /// Un socket a la escucha tiene destino `0.0.0.0:0`: no aporta un extremo
    /// con el que pivotar, y meterlo como `network-traffic` en el informe
    /// ensuciaria la busqueda por infraestructura.
    pub fn is_connected(&self) -> bool {
        self.remote.port() != 0 && !self.remote.ip().is_unspecified()
    }
}

/// Resumen de una region de memoria que merece constar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionArtifact {
    /// Direccion inicial.
    pub start: u64,
    /// Tamano.
    pub len: u64,
    /// Permisos en la forma de `procfs`.
    pub perms: String,
    /// Fichero que la respalda, si lo hay.
    pub path: Option<String>,
}

/// Lo que se recogio de la memoria del proceso.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemoryArtifact {
    /// Regiones totales del espacio de direcciones.
    pub regions_total: usize,
    /// Regiones anonimas y ejecutables: codigo sin fichero detras.
    pub anonymous_exec: Vec<RegionArtifact>,
    /// Bytes leidos de esas regiones.
    pub bytes_read: usize,
    /// Hallazgos del analisis de exploits.
    pub findings: Vec<String>,
}

/// Conjunto completo de artefactos de un incidente.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentArtifacts {
    /// Identificador del incidente, derivado de su contenido.
    pub id: String,
    /// Instante de la recogida, en el reloj de pared, formato STIX.
    pub collected_at: String,
    /// Que la disparo.
    pub trigger: Trigger,
    /// Proceso raiz del incidente.
    pub root_pid: u32,
    /// Arbol de procesos, empezando por la raiz.
    pub processes: Vec<ProcessArtifact>,
    /// Sockets de los procesos del arbol.
    pub sockets: Vec<SocketArtifact>,
    /// Memoria del proceso raiz.
    pub memory: MemoryArtifact,
    /// Lo que no se pudo recoger, y por que.
    ///
    /// Un informe forense que calla lo que le falto induce a concluir que algo
    /// no ocurrio cuando lo unico cierto es que no se pudo mirar.
    pub gaps: Vec<String>,
}

impl IncidentArtifacts {
    /// Numero total de artefactos recogidos.
    pub fn len(&self) -> usize {
        self.processes.len() + self.sockets.len() + self.memory.anonymous_exec.len()
    }

    /// Indica si no se recogio nada.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Sockets con un extremo remoto real.
    pub fn connected_sockets(&self) -> impl Iterator<Item = &SocketArtifact> {
        self.sockets.iter().filter(|s| s.is_connected())
    }
}
