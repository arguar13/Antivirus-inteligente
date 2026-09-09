//! Servicio de escaneo en hilos dedicados.
//!
//! # La propiedad que define este modulo
//!
//! **Encolar un trabajo NUNCA bloquea al que lo encola.**
//!
//! Quien encola es el hilo que drena el ring buffer de eBPF. Si ese hilo se
//! bloqueara esperando un hueco en la cola, dejaria de drenar; el ring se
//! llenaria; el kernel empezaria a descartar eventos; y el producto se quedaria
//! ciego exactamente durante el pico de actividad que provoco la saturacion.
//! Es un fallo que se realimenta: cuanto mas hay que ver, menos se ve.
//!
//! Por eso la cola es ACOTADA y el envio es no bloqueante. Cuando esta llena se
//! descarta el trabajo y se cuenta. Un escaneo perdido es un punto ciego
//! puntual; un colector bloqueado es una ceguera total.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use crate::memory::MemoryScanPolicy;
use crate::yara::{Detection, ProcessScanReport, YaraEngine, YaraError};

/// Que escanear.
#[derive(Debug, Clone)]
pub enum ScanTarget {
    /// Un fichero del disco.
    File(PathBuf),
    /// La memoria de un proceso vivo.
    Process {
        /// PID.
        pid: i32,
        /// Politica de barrido.
        policy: MemoryScanPolicy,
    },
    /// Un buffer ya en memoria del agente.
    Bytes(Arc<Vec<u8>>),
}

/// Trabajo encolado.
#[derive(Debug, Clone)]
pub struct ScanJob {
    /// Objetivo.
    pub target: ScanTarget,
    /// Correlacion con el evento que lo motivo.
    pub correlation: u64,
    /// Prioridad. Los trabajos de prioridad alta se aceptan aunque la cola
    /// este por encima del umbral de descarte.
    pub urgent: bool,
}

/// Resultado de un trabajo.
#[derive(Debug)]
pub struct ScanOutcome {
    /// Trabajo original.
    pub job: ScanJob,
    /// Coincidencias sobre fichero o buffer.
    pub detections: Vec<Detection>,
    /// Informe si el objetivo era un proceso.
    pub process_report: Option<ProcessScanReport>,
    /// Error, si lo hubo.
    pub error: Option<String>,
}

impl ScanOutcome {
    /// Indica si hubo alguna coincidencia.
    pub fn is_detection(&self) -> bool {
        !self.detections.is_empty()
            || self
                .process_report
                .as_ref()
                .is_some_and(|r| !r.detections.is_empty())
    }
}

/// Contadores del servicio.
#[derive(Debug, Default)]
pub struct ScanServiceStats {
    /// Trabajos aceptados.
    pub submitted: AtomicU64,
    /// Trabajos descartados por cola llena.
    ///
    /// Distinto de cero significa que hubo ficheros o procesos que nunca se
    /// miraron. Es una metrica de COBERTURA, no de rendimiento.
    pub dropped_queue_full: AtomicU64,
    /// Trabajos completados.
    pub completed: AtomicU64,
    /// Trabajos que terminaron en error.
    pub failed: AtomicU64,
    /// Trabajos con coincidencia.
    pub detections: AtomicU64,
    /// Bytes escaneados en total.
    pub bytes_scanned: AtomicU64,
}

impl ScanServiceStats {
    /// Instantanea legible.
    pub fn snapshot(&self) -> [(&'static str, u64); 6] {
        [
            ("encolados", self.submitted.load(Ordering::Relaxed)),
            (
                "descartados_cola_llena",
                self.dropped_queue_full.load(Ordering::Relaxed),
            ),
            ("completados", self.completed.load(Ordering::Relaxed)),
            ("fallidos", self.failed.load(Ordering::Relaxed)),
            ("detecciones", self.detections.load(Ordering::Relaxed)),
            ("bytes", self.bytes_scanned.load(Ordering::Relaxed)),
        ]
    }
}

/// Configuracion del servicio.
#[derive(Debug, Clone, Copy)]
pub struct ScanServiceConfig {
    /// Numero de hilos de escaneo.
    pub workers: usize,
    /// Capacidad de la cola.
    ///
    /// Acotada a proposito: una cola sin limite convierte una rafaga de
    /// eventos en consumo de memoria sin techo, y el agente muere por OOM justo
    /// cuando la maquina esta bajo carga.
    pub queue_capacity: usize,
}

impl Default for ScanServiceConfig {
    fn default() -> Self {
        Self {
            // Escanear es trabajo de fondo: no debe competir con el sistema que
            // se protege. Dos hilos absorben las rafagas sin monopolizar la CPU.
            workers: 2,
            queue_capacity: 1024,
        }
    }
}

type Callback = Arc<dyn Fn(ScanOutcome) + Send + Sync>;

/// Servicio de escaneo con hilos propios.
pub struct ScanService {
    tx: SyncSender<ScanJob>,
    workers: Vec<JoinHandle<()>>,
    parar: Arc<AtomicBool>,
    /// Contadores publicos.
    pub stats: Arc<ScanServiceStats>,
    /// Motor compartido, para recargar reglas en caliente.
    pub engine: Arc<YaraEngine>,
}

impl std::fmt::Debug for ScanService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanService")
            .field("workers", &self.workers.len())
            .field("stats", &self.stats.snapshot())
            .finish()
    }
}

impl ScanService {
    /// Arranca el servicio.
    ///
    /// `on_result` se invoca desde los hilos de escaneo, nunca desde el que
    /// encola.
    pub fn start(
        engine: Arc<YaraEngine>,
        config: ScanServiceConfig,
        on_result: Callback,
    ) -> ScanService {
        let (tx, rx) = sync_channel::<ScanJob>(config.queue_capacity.max(1));
        let rx = Arc::new(Mutex::new(rx));
        let stats = Arc::new(ScanServiceStats::default());
        let parar = Arc::new(AtomicBool::new(false));

        let mut workers = Vec::new();
        for i in 0..config.workers.max(1) {
            let rx = Arc::clone(&rx);
            let engine = Arc::clone(&engine);
            let stats = Arc::clone(&stats);
            let parar = Arc::clone(&parar);
            let cb = Arc::clone(&on_result);

            let h = std::thread::Builder::new()
                .name(format!("aegis-scan-{i}"))
                .spawn(move || worker_loop(rx, engine, stats, parar, cb))
                .expect("crear hilo de escaneo");
            workers.push(h);
        }

        ScanService {
            tx,
            workers,
            parar,
            stats,
            engine,
        }
    }

    /// Encola un trabajo SIN bloquear.
    ///
    /// Devuelve `false` si la cola estaba llena y el trabajo se descarto. Quien
    /// llama no debe reintentar en bucle: eso reintroduce el bloqueo que este
    /// diseno existe para evitar.
    pub fn submit(&self, job: ScanJob) -> bool {
        match self.tx.try_send(job) {
            Ok(()) => {
                self.stats.submitted.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(TrySendError::Full(_)) => {
                self.stats
                    .dropped_queue_full
                    .fetch_add(1, Ordering::Relaxed);
                false
            }
            Err(TrySendError::Disconnected(_)) => false,
        }
    }

    /// Detiene el servicio y espera a que los hilos terminen.
    pub fn shutdown(mut self) {
        self.parar.store(true, Ordering::Relaxed);
        // Al soltar el emisor, los receptores obtienen `Disconnected` y salen
        // del bucle aunque estuvieran esperando.
        let (tx_vacio, _) = sync_channel::<ScanJob>(1);
        let _ = std::mem::replace(&mut self.tx, tx_vacio);
        for h in self.workers.drain(..) {
            let _ = h.join();
        }
    }
}

impl Drop for ScanService {
    fn drop(&mut self) {
        self.parar.store(true, Ordering::Relaxed);
    }
}

fn worker_loop(
    rx: Arc<Mutex<Receiver<ScanJob>>>,
    engine: Arc<YaraEngine>,
    stats: Arc<ScanServiceStats>,
    parar: Arc<AtomicBool>,
    on_result: Callback,
) {
    loop {
        if parar.load(Ordering::Relaxed) {
            return;
        }

        // El lock del receptor se toma SOLO para extraer el trabajo y se suelta
        // antes de escanear. Mantenerlo durante el escaneo serializaria todos
        // los hilos y haria inutil tener mas de uno.
        let job = {
            let guard = match rx.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            match guard.recv_timeout(std::time::Duration::from_millis(200)) {
                Ok(j) => j,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
            }
        };

        let resultado = ejecutar(&engine, &job, &stats);
        stats.completed.fetch_add(1, Ordering::Relaxed);
        if resultado.error.is_some() {
            stats.failed.fetch_add(1, Ordering::Relaxed);
        }
        if resultado.is_detection() {
            stats.detections.fetch_add(1, Ordering::Relaxed);
        }
        on_result(resultado);
    }
}

fn ejecutar(engine: &YaraEngine, job: &ScanJob, stats: &ScanServiceStats) -> ScanOutcome {
    let mut salida = ScanOutcome {
        job: job.clone(),
        detections: Vec::new(),
        process_report: None,
        error: None,
    };

    let resultado: Result<(), YaraError> = match &job.target {
        ScanTarget::File(p) => match std::fs::metadata(p) {
            Ok(md) => {
                stats.bytes_scanned.fetch_add(md.len(), Ordering::Relaxed);
                engine.scan_file(p).map(|d| salida.detections = d)
            }
            Err(e) => Err(YaraError::Io {
                path: p.display().to_string(),
                source: e,
            }),
        },
        ScanTarget::Bytes(b) => {
            stats
                .bytes_scanned
                .fetch_add(b.len() as u64, Ordering::Relaxed);
            engine.scan_bytes(b).map(|d| salida.detections = d)
        }
        ScanTarget::Process { pid, policy } => engine.scan_process(*pid, policy).map(|r| {
            stats
                .bytes_scanned
                .fetch_add(r.bytes_scanned, Ordering::Relaxed);
            salida.process_report = Some(r);
        }),
    };

    if let Err(e) = resultado {
        salida.error = Some(e.to_string());
    }
    salida
}
