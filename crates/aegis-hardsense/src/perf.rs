//! Envoltorio minimo de `perf_event_open(2)` para los contadores de la PMU que
//! usa AegisHPC.
//!
//! `libc` no expone `perf_event_attr`, asi que se refleja aqui con su layout de
//! kernel (136 bytes, `PERF_ATTR_SIZE_VER8`), como hacen tambien
//! `aegis-syscallguard` y `aegis-ptguard`: cada crate de hardware es
//! autocontenido, con su espejo minimo verificado en compilacion, para no
//! arrastrar la maquinaria de los otros. Solo se nombran los campos que se usan;
//! el resto es relleno a cero, que es su valor por defecto valido.
//!
//! Nada de esto hace `panic`: abrir un contador en una maquina sin PMU (un
//! microVM, por ejemplo) devuelve `ENOENT`, y eso es una respuesta que se
//! reporta con honestidad ([`crate::contadores`]), no un fallo del producto.

use std::os::fd::{FromRawFd, OwnedFd};

/// `PERF_TYPE_HARDWARE`: eventos de la PMU del procesador.
pub const PERF_TYPE_HARDWARE: u32 = 0;

/// `PERF_COUNT_HW_CPU_CYCLES`: ciclos de reloj del nucleo.
pub const PERF_COUNT_HW_CPU_CYCLES: u64 = 0;
/// `PERF_COUNT_HW_INSTRUCTIONS`: instrucciones retiradas.
pub const PERF_COUNT_HW_INSTRUCTIONS: u64 = 1;
/// `PERF_COUNT_HW_CACHE_MISSES`: fallos de la ultima cache (LLC) en la mayoria de
/// los procesadores. El pico anomalo de este contador es la firma de un ataque de
/// canal lateral por cache (Flush+Reload, Prime+Probe, Spectre).
pub const PERF_COUNT_HW_CACHE_MISSES: u64 = 3;
/// `PERF_COUNT_HW_BRANCH_INSTRUCTIONS`: saltos ejecutados.
pub const PERF_COUNT_HW_BRANCH_INSTRUCTIONS: u64 = 4;
/// `PERF_COUNT_HW_BRANCH_MISSES`: saltos mal predichos. Una cadena ROP/JOP
/// dispara esta cuenta: el predictor no aprendio esos retornos/saltos a gadgets.
pub const PERF_COUNT_HW_BRANCH_MISSES: u64 = 5;

/// `disabled`: el evento arranca parado; se habilita con `ioctl(ENABLE)`.
pub const ATTR_DISABLED: u64 = 1 << 0;
/// `exclude_kernel`: no contar lo que pasa en modo kernel.
pub const ATTR_EXCLUDE_KERNEL: u64 = 1 << 5;
/// `exclude_hv`: no contar lo que pasa en el hipervisor.
pub const ATTR_EXCLUDE_HV: u64 = 1 << 6;

/// `ioctl` que habilita el evento.
pub const PERF_EVENT_IOC_ENABLE: libc::c_ulong = 0x2400;
/// `ioctl` que deshabilita el evento.
pub const PERF_EVENT_IOC_DISABLE: libc::c_ulong = 0x2401;
/// `ioctl` que pone el contador a cero.
pub const PERF_EVENT_IOC_RESET: libc::c_ulong = 0x2403;

/// Tamano de `perf_event_attr` que declara este crate (`PERF_ATTR_SIZE_VER8`).
pub const PERF_ATTR_SIZE: u32 = 136;

/// Espejo `repr(C)` de `struct perf_event_attr`, fijado a 136 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PerfEventAttr {
    /// `PERF_TYPE_*`.
    pub tipo: u32,
    /// Tamano de la estructura; debe ser [`PERF_ATTR_SIZE`].
    pub size: u32,
    /// Evento concreto (`PERF_COUNT_*`).
    pub config: u64,
    /// `sample_period`/`sample_freq` (sin usar aqui).
    pub sample_period: u64,
    /// `sample_type` (sin usar aqui).
    pub sample_type: u64,
    /// `read_format` (sin usar aqui).
    pub read_format: u64,
    /// Union de bitfields: `disabled`, `exclude_kernel`, `exclude_hv`, ...
    pub flags: u64,
    /// `wakeup_events`/`wakeup_watermark` (sin usar).
    pub wakeup: u32,
    /// `bp_type` (sin usar aqui).
    pub bp_type: u32,
    /// `config1` (sin usar aqui).
    pub config1: u64,
    /// `config2` (sin usar aqui).
    pub config2: u64,
    /// Resto de la estructura hasta 136 bytes, todo a cero.
    pub _resto: [u8; 64],
}

const _: () = {
    assert!(core::mem::size_of::<PerfEventAttr>() == PERF_ATTR_SIZE as usize);
    assert!(core::mem::offset_of!(PerfEventAttr, flags) == 40);
    assert!(core::mem::offset_of!(PerfEventAttr, config1) == 56);
};

impl PerfEventAttr {
    /// Un contador de hardware para `evento` (`PERF_COUNT_HW_*`) sobre el proceso,
    /// a cero y parado, sin contar kernel ni hipervisor.
    #[must_use]
    pub fn contador_hw(evento: u64) -> Self {
        PerfEventAttr {
            tipo: PERF_TYPE_HARDWARE,
            size: PERF_ATTR_SIZE,
            config: evento,
            sample_period: 0,
            sample_type: 0,
            read_format: 0,
            flags: ATTR_DISABLED | ATTR_EXCLUDE_KERNEL | ATTR_EXCLUDE_HV,
            wakeup: 0,
            bp_type: 0,
            config1: 0,
            config2: 0,
            _resto: [0; 64],
        }
    }
}

/// Llama a `perf_event_open(2)`. `pid=0, cpu=-1` mide el hilo llamante en
/// cualquier CPU. Devuelve el descriptor propietario o el `errno`.
pub fn perf_event_open(
    attr: &PerfEventAttr,
    pid: libc::pid_t,
    cpu: libc::c_int,
    grupo: libc::c_int,
    flags: libc::c_ulong,
) -> Result<OwnedFd, std::io::Error> {
    // SAFETY: `attr` apunta a una estructura valida del tamano que declara su
    // campo `size`; el kernel solo lee de ella.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_perf_event_open,
            attr as *const PerfEventAttr,
            pid,
            cpu,
            grupo,
            flags,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` es un descriptor recien abierto y valido del que este proceso
    // es dueno en exclusiva.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) })
}

/// Lee el contador de 64 bits de un descriptor de perf.
pub fn leer_contador(fd: &OwnedFd) -> Result<u64, std::io::Error> {
    use std::os::fd::AsRawFd;
    let mut valor: u64 = 0;
    // SAFETY: se leen 8 bytes en `valor`, que tiene ese tamano; el descriptor de
    // un contador de perf entrega exactamente un u64.
    let n = unsafe {
        libc::read(
            fd.as_raw_fd(),
            core::ptr::addr_of_mut!(valor).cast::<libc::c_void>(),
            core::mem::size_of::<u64>(),
        )
    };
    if n != core::mem::size_of::<u64>() as isize {
        return Err(std::io::Error::last_os_error());
    }
    Ok(valor)
}

/// `ioctl` sin argumento sobre un descriptor de perf (ENABLE/DISABLE/RESET).
pub fn perf_ioctl(fd: &OwnedFd, peticion: libc::c_ulong) -> Result<(), std::io::Error> {
    use std::os::fd::AsRawFd;
    // SAFETY: `ioctl` sobre un descriptor de perf valido con una peticion sin
    // argumento de datos.
    let r = unsafe { libc::ioctl(fd.as_raw_fd(), peticion as _, 0) };
    if r < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
