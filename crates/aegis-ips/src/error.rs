//! Los errores del IPS.
//!
//! Cada variante dice QUE fallo y CON QUE, no solo que algo fallo. Un error que
//! solo dice «no se pudo cargar» obliga a reproducirlo para saber por que, y en
//! un endpoint de un cliente reproducirlo no siempre es una opcion.

use thiserror::Error;

/// Errores del plano de aplicacion del IPS.
#[derive(Debug, Error)]
pub enum ErrorIps {
    /// No se pudo cargar el objeto eBPF.
    #[error("no se pudo cargar el programa eBPF {programa}: {detalle}")]
    Carga {
        /// Que programa.
        programa: &'static str,
        /// Que dijo el sistema.
        detalle: String,
    },

    /// No se pudo enganchar el programa a una interfaz.
    #[error("no se pudo enganchar {programa} a {interfaz} ({gancho}): {detalle}")]
    Enganche {
        /// Que programa.
        programa: &'static str,
        /// Que interfaz.
        interfaz: String,
        /// Ingreso o egreso.
        gancho: &'static str,
        /// Que dijo el sistema.
        detalle: String,
    },

    /// Un mapa esperado no existe en el objeto.
    ///
    /// Es un desajuste entre el bytecode y este codigo, no un fallo del entorno:
    /// se distingue para que nadie pierda el tiempo mirando permisos.
    #[error("el objeto eBPF no tiene el mapa «{0}»: bytecode y userland no cuadran")]
    MapaAusente(&'static str),

    /// Fallo al leer o escribir un mapa.
    #[error("fallo al operar sobre el mapa «{mapa}»: {detalle}")]
    Mapa {
        /// Que mapa.
        mapa: &'static str,
        /// Que dijo el sistema.
        detalle: String,
    },

    /// Se pidio algo que solo tiene sentido con IPv4.
    ///
    /// El plano de datos de esta fase juzga IPv4. Decirlo con un error propio
    /// —en vez de fallar en silencio— es lo que impide creer que un flujo IPv6
    /// quedo cubierto cuando no lo esta.
    #[error("el plano de datos de esta fase solo juzga IPv4; {0} no se puede bajar al kernel")]
    SoloIpv4(String),
}
