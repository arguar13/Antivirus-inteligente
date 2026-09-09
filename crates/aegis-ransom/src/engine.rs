//! Motor de deteccion y contencion de ransomware.
//!
//! Combina las senales de [`crate::velocity`] y [`crate::honeypot`] en un
//! veredicto y, cuando procede, contiene el proceso.
//!
//! # La jerarquia de señales
//!
//! No todas valen lo mismo, y tratarlas por igual es como se construye un
//! detector que o no dispara nunca o dispara siempre:
//!
//! | Senal | Valor | Por que |
//! |---|---|---|
//! | Senuelo tocado | **Concluyente** | Nadie sabe que ese fichero existe |
//! | Transicion de entropia | Muy alta | Un compresor nace escribiendo ruido; un cifrador cambia |
//! | Velocidad + dispersion | Alta | Solo si van juntas: una copia de seguridad es rapida pero no dispersa |
//! | Renombrado masivo a extension nueva | Alta | Casi todas las familias renombran |
//! | Alta entropia sola | Baja | La produce cualquier compresor |
//!
//! # El orden de la contencion
//!
//! Al confirmar, primero se corta el dano y despues se investiga. Terminar el
//! arbol de procesos detiene la escritura de forma inmediata; suspenderlo para
//! analizarlo con calma suena mejor pero cada milisegundo de duda son ficheros
//! cifrados que ya no se recuperan.

use std::collections::HashSet;

use crate::honeypot::HoneypotSet;
use crate::velocity::{VelocityConfig, VelocityTracker, WriteObservation};

/// Una senal que contribuye al veredicto.
#[derive(Debug, Clone, PartialEq)]
pub enum Signal {
    /// Un fichero senuelo fue abierto para escritura o modificado.
    HoneypotTouched {
        /// Ruta del senuelo.
        path: String,
    },
    /// El proceso paso de escribir contenido estructurado a escribir ruido.
    EntropyTransition {
        /// Entropia media de la fase anterior.
        before: f64,
        /// Entropia media de la fase reciente.
        after: f64,
    },
    /// Muchos ficheros distintos modificados en la ventana.
    HighVelocity {
        /// Ficheros distintos.
        files: u32,
        /// Duracion de la ventana en milisegundos.
        window_ms: u64,
    },
    /// El proceso toca muchos directorios distintos.
    DirectorySpread {
        /// Directorios distintos.
        dirs: u32,
    },
    /// Rafaga de escrituras de alta entropia.
    HighEntropyBurst {
        /// Numero de escrituras.
        count: u32,
    },
    /// Renombrado masivo, con extensiones que el sistema no habia visto.
    RenameBurst {
        /// Renombrados en la ventana.
        count: u32,
        /// Extensiones nuevas distintas.
        new_extensions: u32,
    },
}

impl Signal {
    /// Peso de la senal en la puntuacion acumulada.
    pub fn weight(&self) -> u32 {
        match self {
            // Concluyente por si sola: el peso solo existe para que aparezca en
            // la puntuacion del informe.
            Signal::HoneypotTouched { .. } => 100,
            Signal::EntropyTransition { .. } => 55,
            Signal::HighVelocity { .. } => 30,
            Signal::DirectorySpread { .. } => 20,
            Signal::HighEntropyBurst { .. } => 20,
            Signal::RenameBurst { .. } => 35,
        }
    }
}

/// Veredicto sobre un proceso.
#[derive(Debug, Clone, PartialEq)]
pub enum RansomVerdict {
    /// Nada que reportar.
    Normal,
    /// Señales presentes pero insuficientes.
    Suspicious {
        /// Puntuacion acumulada.
        score: u32,
        /// Senales observadas.
        signals: Vec<Signal>,
    },
    /// Confirmado.
    Ransomware {
        /// Puntuacion acumulada.
        score: u32,
        /// Senales observadas.
        signals: Vec<Signal>,
    },
}

impl RansomVerdict {
    /// Indica si el veredicto exige contener.
    pub fn is_ransomware(&self) -> bool {
        matches!(self, RansomVerdict::Ransomware { .. })
    }

    /// Senales que lo sostienen.
    pub fn signals(&self) -> &[Signal] {
        match self {
            RansomVerdict::Normal => &[],
            RansomVerdict::Suspicious { signals, .. }
            | RansomVerdict::Ransomware { signals, .. } => signals,
        }
    }
}

/// Deteccion emitida por el motor.
#[derive(Debug, Clone, PartialEq)]
pub struct Detection {
    /// Clave estable del proceso.
    pub actor: u64,
    /// PID.
    pub pid: u32,
    /// Veredicto.
    pub verdict: RansomVerdict,
    /// Instante.
    pub detected_at_ns: u64,
}

/// Accion tomada tras confirmar.
#[derive(Debug, Clone, PartialEq)]
pub enum ContainmentOutcome {
    /// El proceso fue terminado.
    Killed {
        /// Procesos terminados del arbol.
        processes: usize,
    },
    /// La contencion fallo.
    Failed {
        /// Motivo.
        reason: String,
    },
    /// No se intento porque no habia respondedor configurado.
    NotAttempted,
}

/// Quien ejecuta la contencion.
///
/// Es un rasgo y no una llamada directa para que el motor se pueda probar sin
/// terminar procesos de verdad. Una prueba que mata procesos del sistema para
/// comprobar la logica de deteccion es una prueba que nadie se atreve a
/// ejecutar dos veces.
pub trait Responder: std::fmt::Debug {
    /// Termina el arbol de procesos con raiz en `pid`.
    fn contain(&self, pid: u32) -> ContainmentOutcome;
}

/// Configuracion del motor.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Configuracion del seguimiento de velocidad.
    pub velocity: VelocityConfig,
    /// Puntuacion a partir de la cual se confirma ransomware.
    pub confirm_score: u32,
    /// Puntuacion a partir de la cual se reporta como sospechoso.
    pub suspicious_score: u32,
    /// Contener automaticamente al confirmar.
    pub auto_contain: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            velocity: VelocityConfig::default(),
            // Exige mas de una senal fuerte, o una concluyente. Con 55, la
            // transicion de entropia sola no basta: hace falta que ademas haya
            // velocidad o dispersion.
            confirm_score: 80,
            suspicious_score: 30,
            auto_contain: true,
        }
    }
}

/// Motor anti-ransomware.
#[derive(Debug)]
pub struct RansomwareEngine {
    tracker: VelocityTracker,
    honeypots: HoneypotSet,
    config: EngineConfig,
    /// Procesos ya contenidos. Sin esto, cada escritura posterior de un proceso
    /// que ya se esta terminando vuelve a disparar la deteccion y el informe se
    /// llena de duplicados del mismo incidente.
    contenidos: HashSet<u64>,
    responder: Option<Box<dyn Responder + Send + Sync>>,
}

impl RansomwareEngine {
    /// Crea un motor.
    pub fn new(config: EngineConfig, honeypots: HoneypotSet) -> RansomwareEngine {
        RansomwareEngine {
            tracker: VelocityTracker::new(config.velocity),
            honeypots,
            config,
            contenidos: HashSet::new(),
            responder: None,
        }
    }

    /// Instala el ejecutor de contencion.
    pub fn with_responder(mut self, r: Box<dyn Responder + Send + Sync>) -> RansomwareEngine {
        self.responder = Some(r);
        self
    }

    /// Conjunto de senuelos.
    pub fn honeypots(&self) -> &HoneypotSet {
        &self.honeypots
    }

    /// Seguimiento de velocidad.
    pub fn tracker(&self) -> &VelocityTracker {
        &self.tracker
    }

    /// Procesos contenidos hasta ahora.
    pub fn contained(&self) -> usize {
        self.contenidos.len()
    }

    /// Notifica la apertura de un fichero con intencion de escritura.
    ///
    /// Es el punto MAS TEMPRANO en el que se puede detectar un cifrador: si la
    /// ruta es un senuelo, se confirma antes incluso de que llegue a escribir.
    /// Detectarlo en la escritura ya seria un fichero perdido.
    pub fn on_open_for_write(
        &mut self,
        actor: u64,
        pid: u32,
        ruta: &str,
        ts_ns: u64,
    ) -> Option<Detection> {
        if !self.honeypots.is_canary_str(ruta) {
            return None;
        }
        self.tracker.on_honeypot(actor, ts_ns);
        Some(self.emitir(
            actor,
            pid,
            ts_ns,
            vec![Signal::HoneypotTouched {
                path: ruta.to_string(),
            }],
        ))
    }

    /// Notifica una escritura a partir de la muestra cruda del buffer.
    ///
    /// Es la entrada que usa el agente con los eventos del sondeo del kernel:
    /// la entropia se calcula aqui, al vuelo, sobre los bytes que el proceso
    /// acaba de entregar al `write`. Calcularla sobre el fichero ya escrito
    /// llegaria tarde, y el valor Q8.8 que calcula el kernel es una
    /// aproximacion barata pensada para filtrar, no para decidir.
    ///
    /// Una muestra vacia o mas corta que
    /// [`aegis_ml::entropy::MUESTRA_MINIMA`] significa que no hay base para
    /// juzgar: se propaga como `None`, no como cero. Ver
    /// [`WriteObservation::entropy_ratio`].
    pub fn on_write_sample(
        &mut self,
        actor: u64,
        pid: u32,
        ruta: Option<&str>,
        muestra: &[u8],
        bytes: u64,
        ts_ns: u64,
    ) -> Option<Detection> {
        let entropia = aegis_ml::entropy::entropia_normalizada(muestra);
        self.on_write(actor, pid, ruta, entropia, bytes, ts_ns)
    }

    /// Notifica una escritura con la fraccion de entropia ya calculada.
    ///
    /// `entropy` es la fraccion normalizada en `[0, 1]`, no bits por byte: ver
    /// [`crate::velocity::RATIO_CIFRADO`].
    pub fn on_write(
        &mut self,
        actor: u64,
        pid: u32,
        ruta: Option<&str>,
        entropy: Option<f64>,
        bytes: u64,
        ts_ns: u64,
    ) -> Option<Detection> {
        if let Some(p) = ruta {
            if self.honeypots.is_canary_str(p) {
                self.tracker.on_honeypot(actor, ts_ns);
                return Some(self.emitir(
                    actor,
                    pid,
                    ts_ns,
                    vec![Signal::HoneypotTouched {
                        path: p.to_string(),
                    }],
                ));
            }
        }
        self.tracker.on_write(
            actor,
            ruta,
            WriteObservation {
                entropy_ratio: entropy,
                bytes,
                ts_ns,
            },
        );
        self.evaluar(actor, pid, ts_ns)
    }

    /// Notifica un renombrado.
    pub fn on_rename(
        &mut self,
        actor: u64,
        pid: u32,
        origen: &str,
        destino: &str,
        ts_ns: u64,
    ) -> Option<Detection> {
        if self.honeypots.is_canary_str(origen) {
            self.tracker.on_honeypot(actor, ts_ns);
            return Some(self.emitir(
                actor,
                pid,
                ts_ns,
                vec![Signal::HoneypotTouched {
                    path: origen.to_string(),
                }],
            ));
        }
        self.tracker.on_rename(actor, origen, destino, ts_ns);
        self.evaluar(actor, pid, ts_ns)
    }

    /// Olvida un proceso terminado.
    pub fn on_exit(&mut self, actor: u64) {
        self.tracker.forget(actor);
        self.contenidos.remove(&actor);
    }

    /// Mantenimiento periodico.
    ///
    /// Ademas de podar, verifica los senuelos EN DISCO. El evento en tiempo real
    /// puede haberse perdido: si el ring se lleno durante el pico de actividad,
    /// esta comprobacion descubre el dano igual. Un detector que solo mira
    /// eventos se queda ciego justo cuando mas eventos hay.
    pub fn maintain(&mut self, now_ns: u64) -> MaintenanceReport {
        let podados = self.tracker.prune(now_ns);
        let manipulados = self.honeypots.verify();
        MaintenanceReport {
            pruned: podados,
            tampered_canaries: manipulados.len(),
            tampered: manipulados,
        }
    }

    /// Reune las senales presentes y decide.
    fn evaluar(&mut self, actor: u64, pid: u32, ts_ns: u64) -> Option<Detection> {
        let cfg = self.config.velocity;
        let nuevas_ext = self.tracker.new_extensions(actor);
        let estado = self.tracker.state(actor)?;

        let mut senales = Vec::new();

        if estado.honeypot_hits() > 0 {
            senales.push(Signal::HoneypotTouched {
                path: "<detectado previamente>".into(),
            });
        }
        if estado.entropy_transition() {
            senales.push(Signal::EntropyTransition {
                before: estado.earlier_entropy().unwrap_or(0.0),
                after: estado.recent_entropy().unwrap_or(0.0),
            });
        }
        if estado.distinct_files() >= cfg.file_rate_threshold {
            senales.push(Signal::HighVelocity {
                files: estado.distinct_files(),
                window_ms: cfg.window_ns / 1_000_000,
            });
        }
        if estado.distinct_dirs() >= cfg.dir_spread_threshold {
            senales.push(Signal::DirectorySpread {
                dirs: estado.distinct_dirs(),
            });
        }
        if estado.high_entropy_writes() >= cfg.high_entropy_threshold {
            senales.push(Signal::HighEntropyBurst {
                count: estado.high_entropy_writes(),
            });
        }
        if estado.renames() >= cfg.rename_threshold && nuevas_ext >= cfg.new_extension_threshold {
            senales.push(Signal::RenameBurst {
                count: estado.renames(),
                new_extensions: nuevas_ext,
            });
        }

        if senales.is_empty() {
            return None;
        }
        Some(self.emitir(actor, pid, ts_ns, senales))
    }

    fn emitir(&mut self, actor: u64, pid: u32, ts_ns: u64, senales: Vec<Signal>) -> Detection {
        let puntuacion: u32 = senales.iter().map(Signal::weight).sum();
        let concluyente = senales
            .iter()
            .any(|s| matches!(s, Signal::HoneypotTouched { .. }));

        let veredicto = if concluyente || puntuacion >= self.config.confirm_score {
            RansomVerdict::Ransomware {
                score: puntuacion,
                signals: senales,
            }
        } else if puntuacion >= self.config.suspicious_score {
            RansomVerdict::Suspicious {
                score: puntuacion,
                signals: senales,
            }
        } else {
            RansomVerdict::Normal
        };

        Detection {
            actor,
            pid,
            verdict: veredicto,
            detected_at_ns: ts_ns,
        }
    }

    /// Contiene el proceso si el veredicto lo exige y no se contuvo ya.
    ///
    /// Devuelve `None` si no habia nada que contener. La deduplicacion por actor
    /// evita que cada escritura posterior de un proceso que ya se esta
    /// terminando vuelva a disparar la contencion.
    pub fn contain(&mut self, d: &Detection) -> Option<ContainmentOutcome> {
        if !d.verdict.is_ransomware() {
            return None;
        }
        if !self.contenidos.insert(d.actor) {
            return None;
        }
        if !self.config.auto_contain {
            return Some(ContainmentOutcome::NotAttempted);
        }
        match &self.responder {
            Some(r) => Some(r.contain(d.pid)),
            None => Some(ContainmentOutcome::NotAttempted),
        }
    }
}

/// Resultado del mantenimiento periodico.
#[derive(Debug, Clone)]
pub struct MaintenanceReport {
    /// Procesos olvidados por inactividad.
    pub pruned: usize,
    /// Senuelos encontrados manipulados en disco.
    pub tampered_canaries: usize,
    /// Detalle de los manipulados.
    pub tampered: Vec<crate::honeypot::TamperedCanary>,
}
