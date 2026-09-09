//! Envoltorio fino de `perf_event_open(2)` y de su `struct perf_event_attr`.
//!
//! `libc` no expone `perf_event_attr`, asi que se fija aqui con su layout de
//! kernel (136 bytes, `PERF_ATTR_SIZE_VER8`). Lo usan los dos consumidores de
//! hardware del crate: el contador de la PMU ([`crate::pmu`]) y el punto de
//! ruptura de los registros de depuracion ([`crate::drx`]).
//!
//! Todo lo que toca el kernel devuelve `Result`. Un `perf_event_open` sin
//! permiso, o en una maquina sin PMU, no es un fallo del producto: es una
//! respuesta que hay que reportar con honestidad, no un `panic`.

use std::os::fd::{FromRawFd, OwnedFd};

/// `PERF_TYPE_HARDWARE`: eventos de la PMU del procesador.
pub const PERF_TYPE_HARDWARE: u32 = 0;
/// `PERF_TYPE_SOFTWARE`: eventos que cuenta el kernel sin hardware.
pub const PERF_TYPE_SOFTWARE: u32 = 1;
/// `PERF_TYPE_BREAKPOINT`: puntos de ruptura por hardware (registros DRx).
pub const PERF_TYPE_BREAKPOINT: u32 = 5;

/// `PERF_COUNT_HW_INSTRUCTIONS`: instrucciones retiradas.
pub const PERF_COUNT_HW_INSTRUCTIONS: u64 = 1;
/// `PERF_COUNT_SW_TASK_CLOCK`: reloj de CPU del proceso (evento software).
pub const PERF_COUNT_SW_TASK_CLOCK: u64 = 1;

/// `HW_BREAKPOINT_X`: se dispara al EJECUTAR la direccion vigilada.
pub const HW_BREAKPOINT_X: u32 = 4;
/// Longitud de un punto de ruptura de ejecucion: el tamano de una palabra.
pub const HW_BREAKPOINT_LEN_8: u64 = 8;

// Bits del campo de banderas de `perf_event_attr`, en su union de bitfields.
/// `disabled`: el evento arranca parado, se habilita con `ioctl(ENABLE)`.
pub const ATTR_DISABLED: u64 = 1 << 0;
/// `exclude_kernel`: no contar lo que pasa en modo kernel.
pub const ATTR_EXCLUDE_KERNEL: u64 = 1 << 5;
/// `exclude_hv`: no contar lo que pasa en el hipervisor.
pub const ATTR_EXCLUDE_HV: u64 = 1 << 6;

// ioctl del descriptor de perf. `_IO('$', n)` con `'$' == 0x24`.
/// Habilita el evento.
pub const PERF_EVENT_IOC_ENABLE: libc::c_ulong = 0x2400;
/// Deshabilita el evento.
pub const PERF_EVENT_IOC_DISABLE: libc::c_ulong = 0x2401;
/// Pone el contador a cero.
pub const PERF_EVENT_IOC_RESET: libc::c_ulong = 0x2403;

/// Tamano de `perf_event_attr` que declara este crate (`PERF_ATTR_SIZE_VER8`, el de este kernel).
pub const PERF_ATTR_SIZE: u32 = 136;

/// Espejo `repr(C)` de `struct perf_event_attr`, fijado a 128 bytes.
///
/// Solo se nombran los campos que este crate ajusta; el resto es relleno a
/// cero. El kernel valida `size`, de ahi que la estructura tenga que medir
/// exactamente lo que declara `PERF_ATTR_SIZE`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PerfEventAttr {
    /// `PERF_TYPE_*`.
    pub tipo: u32,
    /// Tamano de la estructura; debe ser `PERF_ATTR_SIZE`.
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
    /// `bp_type` (`HW_BREAKPOINT_*`) para puntos de ruptura.
    pub bp_type: u32,
    /// `bp_addr`/`config1`: direccion vigilada del punto de ruptura.
    pub bp_addr: u64,
    /// `bp_len`/`config2`: longitud del punto de ruptura.
    pub bp_len: u64,
    /// Resto de la estructura hasta 128 bytes, todo a cero.
    pub _resto: [u8; 64],
}

const _: () = {
    assert!(core::mem::size_of::<PerfEventAttr>() == PERF_ATTR_SIZE as usize);
    assert!(core::mem::offset_of!(PerfEventAttr, flags) == 40);
    assert!(core::mem::offset_of!(PerfEventAttr, bp_type) == 52);
    assert!(core::mem::offset_of!(PerfEventAttr, bp_addr) == 56);
    assert!(core::mem::offset_of!(PerfEventAttr, bp_len) == 64);
};

impl PerfEventAttr {
    /// Estructura a cero con el `size` correcto.
    pub fn nueva(tipo: u32) -> Self {
        PerfEventAttr {
            tipo,
            size: PERF_ATTR_SIZE,
            config: 0,
            sample_period: 0,
            sample_type: 0,
            read_format: 0,
            flags: ATTR_DISABLED | ATTR_EXCLUDE_KERNEL | ATTR_EXCLUDE_HV,
            wakeup: 0,
            bp_type: 0,
            bp_addr: 0,
            bp_len: 0,
            _resto: [0; 64],
        }
    }
}

/// Llama a `perf_event_open(2)`.
///
/// Devuelve el descriptor propietario (que cierra el evento al soltarse) o el
/// `errno` como `io::Error`. `pid`/`cpu` siguen la convencion del syscall:
/// `pid=0, cpu=-1` mide el hilo llamante en cualquier CPU.
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
    // SAFETY: `fd` es un descriptor recien abierto y valido, del que este
    // proceso es dueno en exclusiva.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) })
}

/// Lee el contador de 64 bits de un descriptor de perf.
pub fn leer_contador(fd: &OwnedFd) -> Result<u64, std::io::Error> {
    use std::os::fd::AsRawFd;
    let mut valor: u64 = 0;
    // SAFETY: se leen 8 bytes en `valor`, que tiene ese tamano; el descriptor
    // de un contador de perf entrega exactamente un u64.
    let n = unsafe {
        libc::read(
            fd.as_raw_fd(),
            &mut valor as *mut u64 as *mut libc::c_void,
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
