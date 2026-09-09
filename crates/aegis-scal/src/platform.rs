//! Identidad de la plataforma y mapa de lo que soporta.
//!
//! El motor de deteccion tiene que poder preguntar "puedo contar con eventos de
//! proceso nativos aqui?" y recibir una respuesta que no sea un `bool`. La
//! diferencia entre "lo hago con la interfaz nativa" y "lo hago sondeando" no es
//! cosmetica: la segunda tiene latencia y puntos ciegos, y una regla que asuma
//! la primera dara falsos negativos silenciosos en la segunda.

use std::fmt;

/// Sistema operativo sobre el que corre la capa.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Platform {
    /// Linux (eBPF, procfs, inotify, nftables).
    Linux,
    /// Windows (minifilter, ETW, WFP).
    Windows,
    /// macOS (EndpointSecurity, FSEvents, Network Extension).
    MacOs,
}

impl Platform {
    /// Plataforma sobre la que se compilo este binario.
    pub const HOST: Platform = HOST_PLATFORM;

    /// Nombre corto y estable, apto para registros y para el canal de control.
    pub fn as_str(self) -> &'static str {
        match self {
            Platform::Linux => "linux",
            Platform::Windows => "windows",
            Platform::MacOs => "macos",
        }
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(target_os = "linux")]
const HOST_PLATFORM: Platform = Platform::Linux;
#[cfg(target_os = "windows")]
const HOST_PLATFORM: Platform = Platform::Windows;
#[cfg(target_os = "macos")]
const HOST_PLATFORM: Platform = Platform::MacOs;

/// Grado de soporte de una capacidad concreta en una plataforma.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Support {
    /// Implementado con la interfaz nativa: baja latencia y sin puntos ciegos
    /// conocidos.
    Native,
    /// Implementado, pero por una via con peores propiedades. El texto explica
    /// cual es la limitacion, porque el llamante tiene que poder decidir si le
    /// vale: un sondeo de 200 ms no ve un proceso que vive 20 ms.
    Degraded(&'static str),
    /// No implementado en esta plataforma. El texto dice que interfaz nativa
    /// falta por escribir, no "TODO".
    Unavailable(&'static str),
}

impl Support {
    /// Indica si la capacidad se puede usar, aunque sea de forma degradada.
    pub fn is_usable(self) -> bool {
        !matches!(self, Support::Unavailable(_))
    }

    /// Indica si la capacidad usa la interfaz nativa.
    pub fn is_native(self) -> bool {
        matches!(self, Support::Native)
    }
}

impl fmt::Display for Support {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Support::Native => f.write_str("nativo"),
            Support::Degraded(m) => write!(f, "degradado ({m})"),
            Support::Unavailable(m) => write!(f, "no disponible ({m})"),
        }
    }
}

/// Mapa de capacidades de un conjunto de backends.
///
/// Se publica por el canal de control para que la consola sepa que puede pedir.
/// Un producto multiplataforma que miente sobre lo que puede hacer en cada
/// sistema es peor que uno que solo corre en uno.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// Plataforma a la que corresponde el mapa.
    pub platform: Platform,
    /// Eventos de creacion y fin de proceso.
    pub process_events: Support,
    /// Consulta del arbol de procesos.
    pub process_query: Support,
    /// Eventos de cambio en el sistema de ficheros.
    pub file_events: Support,
    /// Bloqueo de direcciones en el cortafuegos del sistema.
    pub network_filter: Support,
    /// Lectura de la memoria de otro proceso sin pararlo.
    pub memory_inspection: Support,
}

impl Capabilities {
    /// Capacidades que no estan disponibles, con su motivo.
    ///
    /// Se devuelve en el orden en que estan declaradas para que el informe sea
    /// reproducible.
    pub fn missing(&self) -> Vec<(&'static str, &'static str)> {
        let campos: [(&'static str, Support); 5] = [
            ("process_events", self.process_events),
            ("process_query", self.process_query),
            ("file_events", self.file_events),
            ("network_filter", self.network_filter),
            ("memory_inspection", self.memory_inspection),
        ];
        campos
            .iter()
            .filter_map(|(n, s)| match s {
                Support::Unavailable(m) => Some((*n, *m)),
                _ => None,
            })
            .collect()
    }

    /// Indica si todas las capacidades estan disponibles de alguna forma.
    pub fn complete(&self) -> bool {
        self.missing().is_empty()
    }
}
