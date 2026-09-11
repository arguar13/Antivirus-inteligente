//! Fontaneria de captura Intel PT en vivo. GATED tras la feature `pt-live`.
//!
//! # Por que no se compila ni se prueba en el CI de este proyecto
//!
//! La captura abre `perf_event_open` con `PERF_TYPE=intel_pt`, mapea el area AUX
//! donde la CPU vuelca la traza por DMA, y engancha la salida al proceso
//! sospechoso. Necesita el flag `intel_pt` en la CPU y `perf_event_paranoid`
//! bajo. Este Xeon virtual no lo tiene, asi que la captura vive tras la feature
//! `pt-live` y el CI declara que no se ejercio, en vez de fingir.
//!
//! El NUCLEO —decodificar, reconstruir, decidir— y la ABI ([`crate::perf_pt`])
//! si se prueban en cada `make ci`. Esto de aqui es E/S contra el kernel: se
//! valida en una maquina con Intel PT.
//!
//! # El overhead, por que el anillo AUX se lee en otro hilo
//!
//! Intel PT escribe la traza por DMA en un buffer circular sin interrumpir al
//! proceso trazado: por eso el overhead es de un pequeno porcentaje y no del 10x
//! de un tracer por software. El coste esta en VACIAR ese buffer y decodificarlo,
//! y se hace en un hilo aparte para no meterse en el camino del proceso
//! vigilado. Si el consumidor no vacia a tiempo, la CPU emite un OVF y se pierde
//! traza —un hueco honesto que el decodificador reconoce—.

use crate::perf_pt::PerfEventAttr;
use std::os::unix::io::RawFd;

/// El `PERF_TYPE` de Intel PT lo asigna el kernel en el arranque; se lee de
/// sysfs, no es una constante.
pub const SYSFS_TIPO_PT: &str = "/sys/bus/event_source/devices/intel_pt/type";

/// Un fallo al montar la captura.
#[derive(Debug, thiserror::Error)]
pub enum CapturaError {
    /// La maquina no tiene Intel PT.
    #[error("esta maquina no soporta Intel PT")]
    SinIntelPt,
    /// `perf_event_open` o el `mmap` fallaron.
    #[error("perf/mmap: {0}")]
    Io(#[from] std::io::Error),
}

/// Lee el `PERF_TYPE` que el kernel asigno a Intel PT.
pub fn tipo_pt() -> Result<u32, CapturaError> {
    std::fs::read_to_string(SYSFS_TIPO_PT)
        .map_err(|_| CapturaError::SinIntelPt)?
        .trim()
        .parse()
        .map_err(|_| CapturaError::SinIntelPt)
}

/// Abre un `perf_event` de Intel PT atado a un PID. Devuelve el descriptor; el
/// mapeo del anillo de datos y del area AUX lo hace el consumidor.
pub fn abrir_pt(pid: i32) -> Result<RawFd, CapturaError> {
    let attr = PerfEventAttr::intel_pt(tipo_pt()?);

    // SAFETY: perf_event_open es la syscall; `attr` es una estructura repr(C)
    // valida y completamente inicializada (ver perf_pt). cpu=-1 (cualquiera),
    // group_fd=-1, sin flags.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_perf_event_open,
            &attr as *const PerfEventAttr,
            pid,
            -1i32,
            -1i32,
            0u64,
        )
    };
    if fd < 0 {
        return Err(CapturaError::Io(std::io::Error::last_os_error()));
    }
    Ok(fd as RawFd)
}
