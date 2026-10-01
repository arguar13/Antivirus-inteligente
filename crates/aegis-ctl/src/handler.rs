//! Manejador de control real: conecta las peticiones con los subsistemas.
//!
//! Vive aqui y no en el servidor para que el servidor no dependa de los motores
//! de escaneo y respuesta: el protocolo es una cosa, lo que hace cada comando es
//! otra. El agente construye este manejador con lo que tiene a mano y se lo pasa
//! al servidor.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use aegis_resp::{IsolationPolicy, Isolator, Quarantine};
use aegis_scan::YaraEngine;

use crate::protocol::{IsolateInfo, IsolateMode, Request, Response, ScanInfo, StatusInfo};
use crate::server::ControlHandler;

/// Fuente de las estadisticas que reporta `status`.
///
/// Es un rasgo para no acoplar el manejador al tipo concreto del pipeline del
/// agente: el manejador solo necesita numeros, no la estructura que los produce.
pub trait StatusSource: Send + Sync {
    /// Eventos recibidos del kernel.
    fn events_received(&self) -> u64;
    /// Eventos escalados.
    fn events_escalated(&self) -> u64;
    /// Estado textual.
    fn state(&self) -> String;
    /// El detalle del ultimo informe del agente, una linea por pieza. Por
    /// defecto, nada: quien no tenga motores que contar no cuenta nada.
    fn detalle(&self) -> Vec<String> {
        Vec::new()
    }
}

/// Manejador de control del agente.
pub struct AgentControl<S: StatusSource> {
    // El motor YARA se construye la PRIMERA vez que se pide un escaneo, no al
    // arrancar: cargar las reglas cuesta memoria, y el presupuesto del agente en
    // reposo —81 MiB en una estacion, 48 en una pasarela— no debe incluir un
    // motor que quiza no se use en toda la
    // vida del proceso. Un escaneo bajo demanda es ocasional; pagar su coste
    // cuando llega es lo correcto.
    yara: OnceLock<Arc<YaraEngine>>,
    quarantine_dir: PathBuf,
    /// Si el aislamiento se aplica de verdad o solo se simula. En pruebas y en
    /// arranques sin privilegios, dry-run.
    isolate_dry_run: bool,
    arranque: std::time::Instant,
    status: Arc<S>,
    escaneos: AtomicU64,
}

impl<S: StatusSource> AgentControl<S> {
    /// Construye el manejador con un motor YARA ya cargado.
    ///
    /// Util en pruebas, donde se quiere un motor determinista. En el agente se
    /// prefiere [`AgentControl::lazy`], que difiere el coste de las reglas.
    pub fn new(
        yara: Arc<YaraEngine>,
        quarantine_dir: PathBuf,
        isolate_dry_run: bool,
        status: Arc<S>,
    ) -> AgentControl<S> {
        let celda = OnceLock::new();
        let _ = celda.set(yara);
        AgentControl {
            yara: celda,
            quarantine_dir,
            isolate_dry_run,
            arranque: std::time::Instant::now(),
            status,
            escaneos: AtomicU64::new(0),
        }
    }

    /// Construye el manejador SIN cargar YARA todavia: se cargara la primera vez
    /// que llegue un escaneo. Es la forma que usa el agente para no pagar la
    /// memoria de las reglas en reposo.
    pub fn lazy(quarantine_dir: PathBuf, isolate_dry_run: bool, status: Arc<S>) -> AgentControl<S> {
        AgentControl {
            yara: OnceLock::new(),
            quarantine_dir,
            isolate_dry_run,
            arranque: std::time::Instant::now(),
            status,
            escaneos: AtomicU64::new(0),
        }
    }

    /// Motor YARA, cargandolo la primera vez.
    fn motor(&self) -> Result<&Arc<YaraEngine>, String> {
        // `get_or_init` no admite fallo, asi que si ya esta se devuelve, y si no
        // se intenta cargar; un fallo de compilacion de reglas se propaga como
        // error de la peticion en vez de abortar el agente.
        if let Some(m) = self.yara.get() {
            return Ok(m);
        }
        let motor = YaraEngine::with_base_rules()
            .map_err(|e| format!("no se pudieron cargar las reglas YARA: {e}"))?;
        let _ = self.yara.set(Arc::new(motor));
        self.yara
            .get()
            .ok_or_else(|| "no se pudo inicializar el motor YARA".to_string())
    }

    /// Escaneos atendidos hasta ahora.
    pub fn scans_served(&self) -> u64 {
        self.escaneos.load(Ordering::Relaxed)
    }

    fn rss_kb() -> u64 {
        let s = std::fs::read_to_string("/proc/self/statm").unwrap_or_default();
        let paginas: u64 = s
            .split_whitespace()
            .nth(1)
            .and_then(|x| x.parse().ok())
            .unwrap_or(0);
        paginas * 4
    }

    fn hacer_status(&self) -> Response {
        Response::Status(StatusInfo {
            rss_kb: Self::rss_kb(),
            uptime_s: self.arranque.elapsed().as_secs(),
            events_received: self.status.events_received(),
            events_escalated: self.status.events_escalated(),
            state: self.status.state(),
            detalle: self.status.detalle(),
        })
    }

    fn hacer_scan(&self, path: &str) -> Response {
        self.escaneos.fetch_add(1, Ordering::Relaxed);
        // Solo rutas absolutas: un escaneo bajo demanda con ruta relativa
        // dependeria del directorio de trabajo del agente, que no es
        // predecible.
        if !path.starts_with('/') {
            return Response::Error("la ruta de escaneo debe ser absoluta".into());
        }
        let motor = match self.motor() {
            Ok(m) => m,
            Err(e) => return Response::Error(e),
        };
        match motor.scan_file(std::path::Path::new(path)) {
            Ok(detecciones) => {
                let reglas: Vec<String> = detecciones.iter().map(|d| d.rule.clone()).collect();
                Response::Scan(ScanInfo {
                    path: path.to_string(),
                    detected: !reglas.is_empty(),
                    rules: reglas,
                })
            }
            Err(e) => Response::Error(format!("escaneo fallido: {e}")),
        }
    }

    fn hacer_isolate(&self, mode: IsolateMode) -> Response {
        let policy = match mode {
            IsolateMode::Containment => IsolationPolicy::containment(),
            IsolateMode::Total => IsolationPolicy::total(),
        };
        let isolator = if self.isolate_dry_run {
            Isolator::dry_run()
        } else {
            Isolator::new()
        };
        match isolator.isolate(&policy) {
            Ok(reglas) => Response::Isolated(IsolateInfo {
                mode: mode.as_str().to_string(),
                applied: !self.isolate_dry_run,
                rule_lines: reglas.lines().count(),
            }),
            Err(e) => Response::Error(format!("aislamiento fallido: {e}")),
        }
    }

    fn hacer_quarantine_list(&self) -> Response {
        match Quarantine::open(&self.quarantine_dir) {
            Ok(q) => match q.list() {
                Ok(ids) => Response::Quarantine(ids.iter().map(|id| id.to_hex()).collect()),
                Err(e) => Response::Error(format!("no se pudo listar la cuarentena: {e}")),
            },
            Err(e) => Response::Error(format!("no se pudo abrir la cuarentena: {e}")),
        }
    }
}

impl<S: StatusSource> ControlHandler for AgentControl<S> {
    fn handle(&self, req: Request) -> Response {
        match req {
            Request::Status => self.hacer_status(),
            Request::Scan { path } => self.hacer_scan(&path),
            Request::Isolate { mode } => self.hacer_isolate(mode),
            Request::QuarantineList => self.hacer_quarantine_list(),
        }
    }
}
