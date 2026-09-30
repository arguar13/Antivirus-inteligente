//! El watchdog: supervisa un objetivo y lo reinicia cuando procede.

use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use aegis_presupuesto::{Presupuesto, Veredicto, Vigilante};

use crate::heartbeat::{self, Heartbeat};
use crate::supervisor::{decide, Decision, TargetState};

/// Cuanto se espera a que el objetivo salga por si mismo tras SIGTERM en una
/// parada autorizada, antes del SIGKILL.
pub const PLAZO_PARADA: Duration = Duration::from_secs(10);

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
    /// Presupuesto de memoria que se le exige al objetivo.
    ///
    /// Por omision, el que corresponde a este host ([`Presupuesto::del_host`]).
    /// El watchdog es la segunda de las tres capas que lo obligan: la primera es
    /// el propio agente conteniendose, y la tercera el cgroup. Esta existe
    /// porque la primera la ejecuta el proceso que puede estar fallando, y
    /// porque no todo despliegue corre bajo systemd.
    pub presupuesto: Presupuesto,
}

impl Target {
    /// Objetivo con el presupuesto de memoria de este host.
    #[must_use]
    pub fn nuevo(program: PathBuf, heartbeat: PathBuf, shutdown_marker: PathBuf) -> Target {
        Target {
            program,
            args: Vec::new(),
            heartbeat,
            shutdown_marker,
            max_heartbeat_age_ms: 5_000,
            presupuesto: Presupuesto::del_host(),
        }
    }
}

/// Watchdog de un objetivo.
#[derive(Debug)]
pub struct Watchdog {
    target: Target,
    hijo: Option<Child>,
    heartbeat: Heartbeat,
    /// Reinicios realizados.
    restarts: u64,
    /// Seguimiento del consumo de memoria del objetivo.
    vigilante: Vigilante,
}

impl Watchdog {
    /// Crea el watchdog para un objetivo.
    pub fn new(target: Target) -> Watchdog {
        let heartbeat = Heartbeat::new(target.heartbeat.clone());
        let vigilante = Vigilante::nuevo(target.presupuesto);
        Watchdog {
            target,
            hijo: None,
            heartbeat,
            restarts: 0,
            vigilante,
        }
    }

    /// Seguimiento de memoria del objetivo.
    ///
    /// Expone el maximo observado y el numero de muestras, que es lo que hay que
    /// ensenar cuando alguien pregunta cuanto gasta el agente de verdad: la
    /// media esconde justo el pico que decide si cabe.
    pub fn vigilante(&self) -> &Vigilante {
        &self.vigilante
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
        // El seguimiento de memoria es del proceso, no del watchdog. Si el
        // contador de muestras sobre el techo sobreviviese al reinicio, el
        // proceso nuevo nacerian ya condenado y el watchdog lo mataria en el
        // primer ciclo, una y otra vez: una fuga acotada se convertiria en una
        // maquina sin EDR, que es peor que la fuga.
        self.vigilante = Vigilante::nuevo(self.target.presupuesto);
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

    /// Observa el estado actual del objetivo, **sin** avanzar el muestreo.
    ///
    /// El veredicto de memoria que devuelve es el ultimo calculado por
    /// [`Watchdog::muestrear_memoria`]. Que observar no muestree es deliberado:
    /// `MUESTRAS_PARA_REINICIO` cuenta ciclos de supervision, y si cada consulta
    /// de estado contase como muestra, cualquiera que sondease el watchdog en
    /// bucle —una prueba esperando a que el objetivo arranque, una consola
    /// refrescando— acortaria a voluntad el plazo antes de reiniciar el EDR.
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
            memoria: self.vigilante.veredicto(),
        }
    }

    /// Toma una muestra del consumo del objetivo.
    ///
    /// Es lo que hace avanzar el contador de muestras seguidas sobre el techo, y
    /// lo llama [`Watchdog::supervise_once`] exactamente una vez por ciclo.
    ///
    /// Si el proceso no esta o no se puede medir no se acumula nada: un fallo de
    /// lectura de `/proc` no es una fuga, y tratarlo como tal haria que el
    /// watchdog reiniciase al agente por no poder mirarlo, que es justo el
    /// comportamiento que un atacante querria provocar.
    pub fn muestrear_memoria(&mut self) -> Veredicto {
        if let Some(uso) = self.pid().and_then(aegis_presupuesto::uso_de) {
            self.vigilante.observar(&uso);
        }
        self.vigilante.veredicto()
    }

    /// Un ciclo de supervision: observa, decide y actua. Devuelve la decision.
    pub fn supervise_once(&mut self, ahora_ns: u64) -> Result<Decision, WatchdogError> {
        self.muestrear_memoria();
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
    ///
    /// Es la parada AUTORIZADA, asi que se le pide al objetivo que pare: SIGTERM,
    /// y SIGKILL solo si en [`PLAZO_PARADA`] no ha salido. Antes era SIGKILL
    /// directamente: el agente no llegaba a desenganchar lo suyo ni a publicar
    /// su informe final, y el cgroup de su trabajador confinado quedaba huerfano
    /// (visto en la matriz de kernels, FASE 1 del MP-16).
    pub fn stop(&mut self) {
        self.stop_con_plazo(PLAZO_PARADA);
    }

    /// Como [`Watchdog::stop`], con otro plazo antes del SIGKILL.
    pub fn stop_con_plazo(&mut self, plazo: Duration) {
        let Some(mut h) = self.hijo.take() else {
            return;
        };
        if let Ok(pid) = i32::try_from(h.id()) {
            // SAFETY: `kill` solo recibe enteros; el pid es el de un hijo propio
            // que todavia no se ha recolectado, asi que no puede estar reciclado.
            unsafe {
                libc::kill(pid, libc::SIGTERM);
            }
        }
        let inicio = Instant::now();
        while inicio.elapsed() < plazo {
            if let Ok(Some(_)) = h.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = h.kill();
        let _ = h.wait();
    }
}

/// Instante monotono en nanosegundos.
pub fn now_ns() -> u64 {
    heartbeat::now_ns()
}
