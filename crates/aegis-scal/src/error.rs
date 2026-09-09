//! Errores de la capa de abstraccion.
//!
//! El criterio para el conjunto de variantes es que el llamante pueda DECIDIR
//! con ellas. `Unsupported` no es lo mismo que `PermissionDenied`: ante lo
//! primero hay que apagar la regla que dependia de esa capacidad, ante lo
//! segundo hay que avisar de que el agente esta mal desplegado.

use std::io;
use std::path::PathBuf;

use crate::platform::Platform;

/// Error de cualquiera de los backends de la capa.
#[derive(Debug, thiserror::Error)]
pub enum ScalError {
    /// La plataforma no implementa la capacidad pedida.
    #[error("'{feature}' no esta implementado en {platform}: {detail}")]
    Unsupported {
        /// Capacidad pedida.
        feature: &'static str,
        /// Plataforma en la que se pidio.
        platform: Platform,
        /// Interfaz nativa que hace falta escribir.
        detail: &'static str,
    },

    /// El proceso no existe, o murio entre enumerarlo y consultarlo.
    ///
    /// Es la condicion NORMAL en un sistema vivo, no un fallo: enumerar
    /// `/proc` y leer cada entrada no es atomico.
    #[error("el proceso {0} ya no existe")]
    NoSuchProcess(u32),

    /// Faltan permisos o capacidades para la operacion.
    #[error("permisos insuficientes para {op}; hace falta {needs}")]
    PermissionDenied {
        /// Operacion intentada.
        op: &'static str,
        /// Capacidad o privilegio que falta.
        needs: &'static str,
    },

    /// Error del sistema operativo en una llamada concreta.
    #[error("fallo de sistema en {op}: {source}")]
    Os {
        /// Llamada que fallo.
        op: &'static str,
        /// Causa.
        #[source]
        source: io::Error,
    },

    /// Ruta invalida o inaccesible.
    #[error("ruta no utilizable: {path} ({detail})")]
    BadPath {
        /// Ruta afectada.
        path: PathBuf,
        /// Motivo.
        detail: &'static str,
    },

    /// Falta una herramienta externa de la que depende el backend.
    #[error("falta la herramienta '{tool}', necesaria para {purpose}")]
    MissingTool {
        /// Nombre del ejecutable.
        tool: &'static str,
        /// Para que se necesitaba.
        purpose: &'static str,
    },

    /// Fallo propio del backend, con su texto original.
    ///
    /// Es la valvula para los errores que solo tienen sentido dentro de un
    /// backend concreto —un mapa de eBPF que no se pudo actualizar, una
    /// extension del sistema que rechazo la regla— y que traducir a una variante
    /// generica solo serviria para perder la causa.
    #[error("el backend '{backend}' fallo: {detail}")]
    Backend {
        /// Backend que fallo.
        backend: &'static str,
        /// Causa, tal y como la dio.
        detail: String,
    },

    /// La herramienta externa corrio pero devolvio error.
    #[error("'{tool}' fallo con codigo {code}: {stderr}")]
    ToolFailed {
        /// Nombre del ejecutable.
        tool: &'static str,
        /// Codigo de salida.
        code: i32,
        /// Salida de error, ya recortada.
        stderr: String,
    },
}

impl ScalError {
    /// Construye un error de capacidad no implementada para la plataforma
    /// anfitriona.
    pub fn unsupported(feature: &'static str, detail: &'static str) -> ScalError {
        ScalError::Unsupported {
            feature,
            platform: Platform::HOST,
            detail,
        }
    }

    /// Indica si el error significa "esto aqui no existe", que el llamante
    /// debe tratar apagando la funcionalidad y no reintentando.
    pub fn is_unsupported(&self) -> bool {
        matches!(
            self,
            ScalError::Unsupported { .. } | ScalError::MissingTool { .. }
        )
    }

    /// Indica si el error es transitorio y tiene sentido reintentar mas tarde.
    ///
    /// Un proceso que desaparecio no vuelve, pero la siguiente consulta sobre
    /// OTRO proceso si puede funcionar: por eso `NoSuchProcess` cuenta como
    /// transitorio a efectos de no abortar un barrido entero.
    pub fn is_transient(&self) -> bool {
        match self {
            ScalError::NoSuchProcess(_) => true,
            ScalError::Os { source, .. } => matches!(
                source.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ),
            _ => false,
        }
    }
}
