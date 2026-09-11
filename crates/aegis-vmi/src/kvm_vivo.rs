//! Ruta EN VIVO del hipervisor sobre KVM (Linux). GATED tras la caracteristica
//! `kvm`.
//!
//! Este modulo es la fontaneria real que habla con `/dev/kvm` para crear la
//! maquina virtual y, sobre ella, programar las EPT y atrapar sus violaciones.
//! Necesita **VT-x/AMD-V** en el procesador y privilegios sobre `/dev/kvm`, que
//! el runner del CI no tiene. Por eso vive tras `#[cfg(feature = "kvm")]`: el CI
//! comprueba que **compila** (`cargo check --features kvm`) y DECLARA que no se
//! pudo ejercer, en vez de fingir una ejecucion.
//!
//! El nucleo que DECIDE —recorrer las EPT, clasificar una violacion, parsear el
//! kernel, detectar lo oculto— es Rust puro y se prueba de verdad en los modulos
//! [`crate::ept`] y [`crate::introspeccion`]; esto es solo la puerta al hardware.

use std::io;

/// Identificador de dispositivo de KVM (`KVMIO`), del `linux/kvm.h`.
const KVMIO: u64 = 0xAE;
/// `KVM_GET_API_VERSION = _IO(KVMIO, 0x00)`.
const KVM_GET_API_VERSION: u64 = KVMIO << 8;
/// La version de la API de KVM que este codigo espera (estable desde hace anos).
pub const VERSION_API_ESPERADA: i32 = 12;

/// `struct kvm_userspace_memory_region` de `linux/kvm.h`: describe una region de
/// memoria del invitado. Es la estructura que se usaria para mapear la RAM de la
/// VM y, con `flags`, marcar paginas de solo lectura para la introspeccion.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct RegionMemoriaUsuario {
    /// Ranura de memoria.
    pub slot: u32,
    /// Banderas (p. ej. `KVM_MEM_READONLY` para atrapar escrituras).
    pub flags: u32,
    /// Direccion fisica de invitado donde empieza la region.
    pub direccion_fisica_invitado: u64,
    /// Tamano de la region en bytes.
    pub tamano: u64,
    /// Direccion en el espacio del proceso anfitrion que respalda la region.
    pub direccion_anfitrion: u64,
}

// La ABI tiene que cuadrar EXACTAMENTE con la del kernel: 4+4+8+8+8 = 32 bytes.
const _: () = assert!(core::mem::size_of::<RegionMemoriaUsuario>() == 32);

/// Abre `/dev/kvm` y devuelve la version de su API. Es la comprobacion mas basica
/// de que la puerta al Ring -1 esta disponible en esta maquina.
///
/// # Errores
/// Devuelve el error de E/S si `/dev/kvm` no existe, no hay permisos, o el ioctl
/// falla —lo que ocurre en un entorno sin virtualizacion o sin privilegios—.
pub fn version_api() -> io::Result<i32> {
    // SAFETY: se abre una ruta constante valida; el descriptor se cierra siempre
    // antes de salir.
    let fd = unsafe { libc::open(c"/dev/kvm".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` es un descriptor valido recien abierto; el ioctl no toma
    // argumento de salida.
    let version = unsafe { libc::ioctl(fd, KVM_GET_API_VERSION as _) };
    // SAFETY: se cierra el descriptor que se abrio arriba.
    unsafe {
        libc::close(fd);
    }
    if version < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(version)
}

/// `true` si esta maquina puede, en principio, arrancar el hipervisor: existe
/// `/dev/kvm`, hay permisos y la version de la API es la esperada. Lo usa el CI
/// para DECLARAR con honestidad si la ruta en vivo se pudo ejercer.
#[must_use]
pub fn hay_soporte() -> bool {
    matches!(version_api(), Ok(v) if v == VERSION_API_ESPERADA)
}
