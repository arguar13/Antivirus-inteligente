//! Latido del agente: como el watchdog sabe que sigue VIVO y no solo presente.
//!
//! Un proceso puede estar presente (su PID existe) y sin embargo colgado: un
//! interbloqueo, un bucle infinito, un `read` que nunca vuelve. Comprobar solo
//! el PID no lo detecta. El agente escribe periodicamente un latido —un instante
//! monotono— en un fichero conocido; el watchdog lo lee y, si deja de avanzar,
//! sabe que el agente esta colgado aunque su proceso siga ahi.
//!
//! El fichero es diminuto (un entero de texto) y la escritura es atomica por
//! renombrado, para que el watchdog nunca lea un latido a medias.

use std::io::Write;
use std::path::{Path, PathBuf};

/// Latido escrito por el agente y leido por el watchdog.
#[derive(Debug, Clone)]
pub struct Heartbeat {
    path: PathBuf,
}

impl Heartbeat {
    /// Crea un latido ligado a una ruta.
    pub fn new(path: impl Into<PathBuf>) -> Heartbeat {
        Heartbeat { path: path.into() }
    }

    /// Escribe un latido con el instante dado (nanosegundos monotonos).
    ///
    /// Escribe en un fichero temporal y renombra: el watchdog nunca ve un valor
    /// a medias, porque el renombrado es atomico.
    pub fn beat(&self, ts_ns: u64) -> std::io::Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = self.path.with_extension("tmp");
        {
            let mut f = std::fs::File::create(&tmp)?;
            write!(f, "{ts_ns}")?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)
    }

    /// Lee el ultimo latido, o `None` si no hay o no se puede interpretar.
    pub fn read(&self) -> Option<u64> {
        std::fs::read_to_string(&self.path)
            .ok()?
            .trim()
            .parse::<u64>()
            .ok()
    }

    /// Ruta del fichero de latido.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Instante monotono en nanosegundos, para el latido.
///
/// Se usa el reloj monotono y no la hora del sistema: el latido mide tiempo
/// transcurrido, y un ajuste del reloj (NTP, cambio de hora) no debe hacer creer
/// al watchdog que el agente lleva colgado horas.
pub fn now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime escribe en una timespec valida de la pila.
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as u64) * 1_000_000_000 + ts.tv_nsec as u64
}
