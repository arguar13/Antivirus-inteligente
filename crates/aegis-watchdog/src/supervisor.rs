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
//! - **Desbordado**: el proceso existe, late con normalidad y se esta comiendo
//!   la maquina. Una fuga lenta no mata ni cuelga a nadie: llega a 2 GiB a las
//!   tres de la manana y para entonces el problema ya no es el agente, es el
//!   host de produccion que se ha llevado por delante. Un watchdog que solo
//!   mira el latido da esto por bueno hasta el final.
//!
//! El tercero es el que mas cuesta reconocer y el que mas dano hace, porque un
//! EDR que tumba al host que protege es peor que un EDR ausente: el ausente al
//! menos no causa la caida.
//!
//! # Lo que NO hay que reiniciar
//!
//! Una parada AUTORIZADA. Cuando a alguien con permiso le pide al agente que se
//! detenga, este deja una marca de apagado limpio; el watchdog la ve y no
//! reinicia. Sin esto, seria imposible parar el agente: el watchdog lo
//! resucitaria una y otra vez. La marca es la frontera entre "lo mataron" y "lo
//! pararon".

use aegis_presupuesto::Veredicto;

/// Estado observado del objetivo supervisado.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetState {
    /// El proceso existe.
    pub alive: bool,
    /// Antiguedad del ultimo latido en milisegundos, si hay latido.
    pub heartbeat_age_ms: Option<u64>,
    /// Hay una marca de apagado autorizado.
    pub shutdown_requested: bool,
    /// Veredicto del presupuesto de memoria sobre el objetivo.
    ///
    /// Lo produce [`aegis_presupuesto::Vigilante`], que ya exige varias muestras
    /// seguidas sobre el techo antes de pedir reinicio. Esa confirmacion no es
    /// un detalle: reiniciar el EDR abre una ventana sin proteccion, y sin ella
    /// un atacante capaz de provocar picos de memoria tendria un interruptor
    /// para apagar la vigilancia a voluntad.
    pub memoria: Veredicto,
}

impl Default for TargetState {
    /// Objetivo sano: vivo, recien latido, sin parada pedida y dentro de
    /// presupuesto. Existe para que anadir una causa de fallo nueva no obligue a
    /// reescribir cada sitio que construye un estado.
    fn default() -> Self {
        Self {
            alive: true,
            heartbeat_age_ms: Some(0),
            shutdown_requested: false,
            memoria: Veredicto::Seguir,
        }
    }
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
    /// El proceso se ha pasado del techo de memoria de forma sostenida.
    RestartMemoria {
        /// Consumo maximo observado, en bytes.
        observado: u64,
        /// Techo que se ha superado, en bytes.
        techo: u64,
    },
    /// Parada autorizada; no reiniciar.
    Stop,
    /// Aun no ha dado su primer latido tras arrancar; esperar sin reiniciar.
    Starting,
}

impl Decision {
    /// Indica si la decision implica reiniciar.
    pub fn is_restart(self) -> bool {
        matches!(
            self,
            Decision::RestartDead | Decision::RestartHung | Decision::RestartMemoria { .. }
        )
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
    // La memoria se mira antes que el latido porque un agente desbordado amenaza
    // al host, no solo a si mismo, y porque late perfectamente mientras lo hace:
    // esperar a que el latido se enrancie seria esperar a que sea tarde.
    if let Veredicto::Reiniciar { observado, techo } = state.memoria {
        return Decision::RestartMemoria { observado, techo };
    }
    match state.heartbeat_age_ms {
        // Vivo pero aun sin latir: acaba de arrancar, se le da margen.
        None => Decision::Starting,
        Some(edad) if edad > max_heartbeat_age_ms => Decision::RestartHung,
        Some(_) => Decision::Healthy,
    }
}
