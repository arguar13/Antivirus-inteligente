//! Etapa anti-ransomware del pipeline de telemetria.
//!
//! # Por que corre en el bucle de eventos y no en un hilo aparte
//!
//! Todo lo caro de este producto (YARA, el modelo de ML, el desempaquetado)
//! corre en hilos separados precisamente para no bloquear el consumo del ring
//! buffer. Esta etapa es la excepcion, y a proposito.
//!
//! El motivo es el presupuesto de dano. Un cifrador procesa entre 1.000 y 5.000
//! ficheros por minuto: a esa velocidad, encolar la deteccion para que la
//! atienda otro hilo cuesta ficheros que ya no se recuperan. Y puede correr en
//! linea porque **esta acotada en tiempo constante por evento**: una busqueda en
//! tabla para resolver el descriptor, un hash de la ruta, una insercion en dos
//! conjuntos y la entropia de 512 bytes. No hay recorridos, no hay E/S, no hay
//! esperas.
//!
//! La regla que separa una cosa de otra es simple: en el bucle solo va lo que
//! decide en O(1) y lo que tiene que decidir YA.

use aegis_ransom::engine::Detection;
use aegis_ransom::{ContainmentOutcome, FdMap, RansomwareEngine};

use crate::triage::TelemetryEvent;

/// Banderas de `open(2)` que indican intencion de escritura.
const O_WRONLY: u32 = 0o1;
const O_RDWR: u32 = 0o2;
const O_TRUNC: u32 = 0o1000;

/// Edad maxima de una asociacion descriptor -> ruta.
///
/// Existe porque el evento de fin de proceso puede perderse cuando el ring se
/// llena, que es justo lo que pasa durante un ataque. Sin esta poda la tabla
/// retendria rutas de procesos muertos hasta la cota dura.
const EDAD_MAX_FD_NS: u64 = 300_000_000_000;

/// Contadores de la etapa.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RansomStats {
    /// Escrituras con muestra procesadas.
    pub writes: u64,
    /// Escrituras cuya ruta no se pudo resolver.
    pub writes_sin_ruta: u64,
    /// Asociaciones descriptor -> ruta registradas.
    pub binds: u64,
    /// Renombrados procesados.
    pub renames: u64,
    /// Detecciones confirmadas.
    pub confirmadas: u64,
    /// Contenciones ejecutadas.
    pub contenciones: u64,
}

/// Etapa anti-ransomware conectada a la telemetria.
#[derive(Debug)]
pub struct RansomStage {
    engine: RansomwareEngine,
    fds: FdMap,
    stats: RansomStats,
}

/// Lo que la etapa produce al procesar un evento.
#[derive(Debug)]
pub struct RansomAction {
    /// Deteccion emitida.
    pub detection: Detection,
    /// Resultado de la contencion, si se intento.
    pub containment: Option<ContainmentOutcome>,
}

impl RansomStage {
    /// Crea la etapa sobre un motor ya configurado.
    pub fn new(engine: RansomwareEngine) -> RansomStage {
        RansomStage {
            engine,
            fds: FdMap::new(),
            stats: RansomStats::default(),
        }
    }

    /// Contadores.
    pub fn stats(&self) -> RansomStats {
        self.stats
    }

    /// Motor subyacente.
    pub fn engine(&self) -> &RansomwareEngine {
        &self.engine
    }

    /// Tabla de descriptores.
    pub fn fds(&self) -> &FdMap {
        &self.fds
    }

    /// Procesa un evento de telemetria.
    ///
    /// Devuelve la accion solo cuando el veredicto es de ransomware confirmado.
    /// Los veredictos de sospecha se cuentan pero no se propagan: informar de
    /// cada proceso que escribe rapido llenaria la consola de ruido y ensenaria
    /// al operador a ignorar las alertas de este motor, que es justo lo que no
    /// puede pasar con la unica alerta que exige actuar en segundos.
    pub fn on_event(&mut self, ev: &TelemetryEvent) -> Option<RansomAction> {
        let deteccion = match ev {
            TelemetryEvent::FdBind {
                actor,
                pid,
                fd,
                path,
                open_flags,
                ts_ns,
            } => {
                self.stats.binds += 1;
                self.fds.bind(actor.0, *fd, path, *ts_ns);
                // Abrir un senuelo para escritura confirma AQUI, antes de que
                // llegue a escribir un solo byte. Detectarlo en la escritura ya
                // seria un fichero perdido.
                if *open_flags & (O_WRONLY | O_RDWR | O_TRUNC) != 0 {
                    self.engine.on_open_for_write(actor.0, *pid, path, *ts_ns)
                } else {
                    None
                }
            }

            TelemetryEvent::FileWrite {
                actor,
                pid,
                path,
                flags,
                ts_ns,
            } => {
                if *flags & (O_WRONLY | O_RDWR | O_TRUNC) != 0 {
                    self.engine.on_open_for_write(actor.0, *pid, path, *ts_ns)
                } else {
                    None
                }
            }

            TelemetryEvent::FileWriteSample {
                actor,
                pid,
                fd,
                bytes,
                sample,
                ts_ns,
                ..
            } => {
                self.stats.writes += 1;
                // La ruta se copia porque `on_write_sample` toma `&mut self` y
                // la referencia sale de `self.fds`. Solo ocurre en escrituras
                // con ruta conocida y es una cadena corta.
                let ruta = self.fds.resolve(actor.0, *fd).map(str::to_owned);
                if ruta.is_none() {
                    self.stats.writes_sin_ruta += 1;
                }
                self.engine
                    .on_write_sample(actor.0, *pid, ruta.as_deref(), sample, *bytes, *ts_ns)
            }

            TelemetryEvent::FileRename {
                actor,
                pid,
                from,
                to,
                ts_ns,
            } => {
                self.stats.renames += 1;
                self.engine.on_rename(actor.0, *pid, from, to, *ts_ns)
            }

            TelemetryEvent::Exit { actor, .. } => {
                self.fds.forget_process(actor.0);
                self.engine.on_exit(actor.0);
                None
            }

            _ => None,
        }?;

        if !deteccion.verdict.is_ransomware() {
            return None;
        }
        self.stats.confirmadas += 1;
        let contencion = self.engine.contain(&deteccion);
        if contencion.is_some() {
            self.stats.contenciones += 1;
        }
        Some(RansomAction {
            detection: deteccion,
            containment: contencion,
        })
    }

    /// Mantenimiento periodico. Se llama entre lotes, nunca por evento.
    pub fn maintain(&mut self, now_ns: u64) -> RansomMaintenance {
        let m = self.engine.maintain(now_ns);
        let fds = self.fds.prune(now_ns, EDAD_MAX_FD_NS);
        RansomMaintenance {
            pruned_processes: m.pruned,
            pruned_fd_tables: fds,
            tampered_canaries: m.tampered_canaries,
        }
    }
}

/// Resultado del mantenimiento de la etapa.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RansomMaintenance {
    /// Procesos olvidados por inactividad.
    pub pruned_processes: usize,
    /// Tablas de descriptores descartadas.
    pub pruned_fd_tables: usize,
    /// Senuelos encontrados manipulados en el barrido en disco.
    pub tampered_canaries: usize,
}

/// La deteccion de secuestro de datos (ransomware), como motor del contrato.
///
/// Corre en el camino caliente por lo que explica la cabecera de este modulo:
/// es O(1) por evento y tiene que decidir YA. Nace en solo-auditoria: el motor
/// se construye sin respondedor, asi que `contain` no toca ningun proceso; la
/// confirmacion llega al arbitro como juicio malicioso con su evidencia.
pub struct MotorSecuestro {
    etapa: RansomStage,
    identidad: crate::motores::Identidad,
}

impl MotorSecuestro {
    /// Sin señuelos desplegados y sin respondedor.
    pub fn nuevo(identidad: crate::motores::Identidad) -> MotorSecuestro {
        MotorSecuestro {
            etapa: RansomStage::new(RansomwareEngine::new(
                aegis_ransom::EngineConfig::default(),
                aegis_ransom::HoneypotSet::default(),
            )),
            identidad,
        }
    }
}

impl aegis_motor::Motor<crate::motores::EventoAgente> for MotorSecuestro {
    fn ficha(&self) -> aegis_motor::Ficha {
        aegis_motor::Ficha {
            nombre: "secuestro",
            firma: aegis_entidad::Motor::Conductual,
            camino: aegis_motor::Camino::Caliente,
            presupuesto: aegis_motor::Presupuesto::caliente(300, 16 * 1024 * 1024),
            requisitos: &[aegis_motor::Requisito::TelemetriaKernel],
        }
    }

    fn evaluar(
        &mut self,
        ev: &crate::motores::EventoAgente,
        _plazo: &aegis_motor::Plazo,
    ) -> aegis_motor::Dictamen {
        use aegis_entidad::{Confianza, Juicio, Senal, Severidad};
        let Some(accion) = self.etapa.on_event(&ev.evento) else {
            return aegis_motor::Dictamen::NoAplica;
        };
        let d = &accion.detection;
        let entidad = aegis_entidad::entidad::proceso_por_clave(
            &self.identidad.maquina,
            self.identidad.boot,
            d.actor,
        );
        aegis_motor::Dictamen::Senales(vec![Senal::nueva(
            aegis_entidad::Motor::Conductual,
            entidad,
            Juicio::Malicioso,
            Severidad::Critica,
            Confianza::ALTA,
            format!(
                "secuestro de datos confirmado (pid {}): {:?}; contencion: {:?}",
                d.pid, d.verdict, accion.containment
            ),
            d.detected_at_ns,
        )])
    }

    fn memoria(&self) -> usize {
        self.etapa.fds().tracked_fds() * 96
            + self.etapa.fds().tracked_processes() * 128
            + self.etapa.engine().tracker().tracked() * 256
    }

    fn mantener(&mut self, ahora_ns: u64) {
        self.etapa.maintain(ahora_ns);
    }
}
