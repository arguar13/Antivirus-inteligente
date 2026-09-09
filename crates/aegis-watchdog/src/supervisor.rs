//! Supervision del agente: cuando reiniciarlo y cuando no.
//!
//! # Que cuenta como "hay que reiniciar"
//!
//! Dos fallos distintos, y el watchdog los distingue:
//!
//! - **Muerto**: el proceso ya no existe. Un `SIGKILL` —que no se puede
//!   bloquear desde el proceso victima— entra aqui. La resiliencia ante la
//!   terminacion no la da el agente resistiendose (no puede), la da el watchdog
//!   volviendolo a arrancar.
//! - **Colgado**: el proceso existe pero su latido dejo de avanzar. Un
//!   interbloqueo o un bucle infinito no matan el proceso, pero lo dejan
//!   inutil; comprobar solo el PID no lo veria.
//!
//! # Lo que NO hay que reiniciar
//!
//! Una parada AUTORIZADA. Cuando a alguien con permiso le pide al agente que se
//! detenga, este deja una marca de apagado limpio; el watchdog la ve y no
//! reinicia. Sin esto, seria imposible parar el agente: el watchdog lo
//! resucitaria una y otra vez. La marca es la frontera entre "lo mataron" y "lo
//! pararon".

/// Estado observado del objetivo supervisado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetState {
    /// El proceso existe.
    pub alive: bool,
    /// Antiguedad del ultimo latido en milisegundos, si hay latido.
    pub heartbeat_age_ms: Option<u64>,
    /// Hay una marca de apagado autorizado.
    pub shutdown_requested: bool,
}

/// Decision del supervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Todo en orden, no hacer nada.
    Healthy,
    /// El proceso murio; reiniciar.
    RestartDead,
    /// El proceso esta colgado (latido rancio); reiniciar.
    RestartHung,
    /// Parada autorizada; no reiniciar.
    Stop,
    /// Aun no ha dado su primer latido tras arrancar; esperar sin reiniciar.
    Starting,
}

impl Decision {
    /// Indica si la decision implica reiniciar.
    pub fn is_restart(self) -> bool {
        matches!(self, Decision::RestartDead | Decision::RestartHung)
    }
}

/// Decide que hacer a partir del estado observado.
///
/// `max_heartbeat_age_ms` es el margen: un latido mas viejo que eso significa
/// colgado. Se elige varias veces el periodo de latido del agente, para no
/// reiniciar por una pausa puntual (un barrido de GC, una rafaga de E/S).
pub fn decide(state: TargetState, max_heartbeat_age_ms: u64) -> Decision {
    // La parada autorizada manda sobre todo lo demas: aunque el proceso haya
    // muerto, si se pidio pararlo, no se reinicia.
    if state.shutdown_requested {
        return Decision::Stop;
    }
    if !state.alive {
        return Decision::RestartDead;
    }
    match state.heartbeat_age_ms {
        // Vivo pero aun sin latir: acaba de arrancar, se le da margen.
        None => Decision::Starting,
        Some(edad) if edad > max_heartbeat_age_ms => Decision::RestartHung,
        Some(_) => Decision::Healthy,
    }
}
