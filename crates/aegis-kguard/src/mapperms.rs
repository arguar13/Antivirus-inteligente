//! Bloqueo de permisos de los mapas eBPF.
//!
//! # El problema
//!
//! Los mapas eBPF son la memoria compartida entre Ring 0 y Ring 3: el ring
//! buffer de eventos, la configuracion, las tablas de estado. Por defecto un
//! mapa vive solo mientras alguien tiene su descriptor, pero en cuanto se
//! **fija** (pin) en el sistema de ficheros bpf para que sobreviva a reinicios
//! del agente, aparece como un fichero, y ese fichero tiene permisos. Si se fija
//! con permisos laxos, cualquier usuario del sistema puede abrirlo, volcar su
//! contenido —que incluye rutas vigiladas, PIDs sospechosos, configuracion de
//! deteccion— o, peor, escribir en la configuracion para desactivar sondas.
//!
//! # La regla
//!
//! Los mapas criticos se fijan con permisos **0600 y propietario root**: solo
//! root los lee o escribe. No 0640 ni 0644: el contenido de un mapa de un EDR
//! no es informacion que un usuario sin privilegios deba poder leer, y un grupo
//! con acceso amplia la superficie sin necesidad.
//!
//! Este modulo no fija los mapas (eso lo hace el cargador con libbpf); calcula y
//! **verifica** los permisos, que es la parte con logica y la que se puede
//! probar sin un kernel. El cargador aplica lo que este modulo dicta y despues
//! comprueba que el resultado es el esperado: fijar con una mascara y no
//! comprobar el resultado deja pasar un umask heredado que afloje los permisos.

/// Permisos exigidos a un mapa fijado: `rw-------`.
pub const MODO_MAPA: u32 = 0o600;

/// Propietario exigido: root.
pub const UID_ROOT: u32 = 0;

/// Diagnostico de los permisos de un mapa fijado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapPermVerdict {
    /// Permisos correctos: 0600 y root.
    Locked,
    /// Accesible por otros: el modo concede bits a grupo u otros.
    TooOpen {
        /// Modo encontrado (12 bits de permiso).
        mode: u32,
    },
    /// El propietario no es root.
    WrongOwner {
        /// UID encontrado.
        uid: u32,
    },
}

impl MapPermVerdict {
    /// Indica si el mapa esta correctamente bloqueado.
    pub fn is_locked(self) -> bool {
        matches!(self, MapPermVerdict::Locked)
    }
}

/// Evalua un modo y un propietario contra la regla de bloqueo.
///
/// `mode` son los bits de permiso (los 12 inferiores de `st_mode`). Se comprueba
/// el propietario primero: un mapa de root con 0600 esta bien, pero uno de un
/// usuario cualquiera con 0600 sigue siendo suyo para leerlo.
pub fn evaluar(mode: u32, uid: u32) -> MapPermVerdict {
    if uid != UID_ROOT {
        return MapPermVerdict::WrongOwner { uid };
    }
    // Cualquier bit fuera de los del propietario (0o077: grupo y otros) es
    // acceso de mas.
    if mode & 0o077 != 0 {
        return MapPermVerdict::TooOpen { mode: mode & 0o777 };
    }
    MapPermVerdict::Locked
}

/// Comprueba en disco los permisos de un mapa fijado en `ruta`.
///
/// Devuelve el veredicto, o un error de E/S si el fichero no existe o no se
/// puede consultar. La existencia del fichero ya es una precondicion: si el
/// mapa no esta fijado donde se espera, es un problema distinto que trata el
/// cargador.
#[cfg(target_os = "linux")]
pub fn verificar_en_disco(ruta: &std::path::Path) -> std::io::Result<MapPermVerdict> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(ruta)?;
    Ok(evaluar(meta.mode() & 0o777, meta.uid()))
}

/// Aplica los permisos de bloqueo a un mapa recien fijado.
///
/// Se hace en dos pasos deliberados: `chmod` a 0600 y despues **verificar** que
/// quedo asi. El umask del proceso que fijo el mapa puede haber recortado bits
/// de forma que el resultado no sea el pedido; comprobarlo despues es lo que
/// convierte "pedimos 0600" en "es 0600".
#[cfg(target_os = "linux")]
pub fn bloquear(ruta: &std::path::Path) -> std::io::Result<MapPermVerdict> {
    use std::os::unix::fs::PermissionsExt;
    let permisos = std::fs::Permissions::from_mode(MODO_MAPA);
    std::fs::set_permissions(ruta, permisos)?;
    verificar_en_disco(ruta)
}
