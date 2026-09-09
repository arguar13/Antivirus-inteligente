//! El watchdog: supervisa un objetivo y lo reinicia cuando procede.

use std::path::PathBuf;
use std::process::{Child, Command};

use crate::heartbeat::{self, Heartbeat};
use crate::supervisor::{decide, Decision, TargetState};

/// Error del watchdog.
#[derive(Debug, thiserror::Error)]
pub enum WatchdogError {
    /// No se pudo lanzar el objetivo.
    #[error("no se pudo lanzar {cmd}: {detail}")]
    Spawn {
        /// Orden.
        cmd: String,
        /// Causa.
        detail: std::io::Error,
    },
}

/// Descripcion de lo que se supervisa.
#[derive(Debug, Clone)]
pub struct Target {
    /// Ejecutable a lanzar.
    pub program: PathBuf,
    /// Argumentos.
    pub args: Vec<String>,
    /// Ruta del fichero de latido que escribe el objetivo.
    pub heartbeat: PathBuf,
    /// Ruta de la marca de apagado autorizado.
    pub shutdown_marker: PathBuf,
    /// Margen de latido en milisegundos antes de considerarlo colgado.
    pub max_heartbeat_age_ms: u64,
}

/// Watchdog de un objetivo.
#[derive(Debug)]
pub struct Watchdog {
    target: Target,
    hijo: Option<Child>,
    heartbeat: Heartbeat,
    /// Reinicios realizados.
    restarts: u64,
}

impl Watchdog {
    /// Crea el watchdog para un objetivo.
    pub fn new(target: Target) -> Watchdog {
        let heartbeat = Heartbeat::new(target.heartbeat.clone());
        Watchdog {
            target,
            hijo: None,
            heartbeat,
            restarts: 0,
        }
    }

    /// Lanza el objetivo por primera vez.
    ///
    /// Al arrancar se retira cualquier marca de apagado anterior: una marca vieja
    /// de una parada previa haria que el watchdog se negase a supervisar.
    pub fn spawn(&mut self) -> Result<(), WatchdogError> {
        let _ = std::fs::remove_file(&self.target.shutdown_marker);
        let hijo = Command::new(&self.target.program)
            .args(&self.target.args)
            .spawn()
            .map_err(|e| WatchdogError::Spawn {
                cmd: self.target.program.display().to_string(),
                detail: e,
            })?;
        self.hijo = Some(hijo);
        Ok(())
    }

    /// PID del objetivo, si esta lanzado.
    pub fn pid(&self) -> Option<u32> {
        self.hijo.as_ref().map(Child::id)
    }

    /// Reinicios realizados.
    pub fn restarts(&self) -> u64 {
        self.restarts
    }

    /// Observa el estado actual del objetivo.
    pub fn observe(&mut self, ahora_ns: u64) -> TargetState {
        let alive = self.esta_vivo();
        let heartbeat_age_ms = self.heartbeat.read().map(|t| {
            // Si el latido es del futuro (relojes), se trata como recien latido.
            ahora_ns.saturating_sub(t) / 1_000_000
        });
        let shutdown_requested = self.target.shutdown_marker.exists();
        TargetState {
            alive,
            heartbeat_age_ms,
            shutdown_requested,
        }
    }

    /// Un ciclo de supervision: observa, decide y actua. Devuelve la decision.
    pub fn supervise_once(&mut self, ahora_ns: u64) -> Result<Decision, WatchdogError> {
        let estado = self.observe(ahora_ns);
        let decision = decide(estado, self.target.max_heartbeat_age_ms);
        if decision.is_restart() {
            self.reiniciar()?;
        }
        Ok(decision)
    }

    /// Reinicia el objetivo: termina el proceso anterior si sigue (colgado) y
    /// lanza uno nuevo. Las politicas de seguridad no se pierden porque el agente
    /// las recarga de disco al arrancar; el watchdog solo lo vuelve a poner en
    /// marcha.
    pub fn reiniciar(&mut self) -> Result<(), WatchdogError> {
        if let Some(mut h) = self.hijo.take() {
            // Si estaba colgado, sigue vivo: se termina para no dejar dos.
            let _ = h.kill();
            let _ = h.wait();
        }
        self.spawn()?;
        self.restarts += 1;
        Ok(())
    }

    /// Recolecta el estado de salida si el hijo ya termino, para no dejar
    /// zombis. Devuelve `true` si el hijo sigue vivo.
    fn esta_vivo(&mut self) -> bool {
        match self.hijo.as_mut() {
            None => false,
            Some(h) => match h.try_wait() {
                Ok(Some(_)) => false, // termino
                Ok(None) => true,     // sigue
                Err(_) => false,
            },
        }
    }

    /// Detiene la supervision y el objetivo (parada ordenada del watchdog).
    pub fn stop(&mut self) {
        if let Some(mut h) = self.hijo.take() {
            let _ = h.kill();
            let _ = h.wait();
        }
    }
}

/// Instante monotono en nanosegundos.
pub fn now_ns() -> u64 {
    heartbeat::now_ns()
}
