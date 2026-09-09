//! Grafo de linaje de procesos.
//!
//! Una deteccion aislada casi nunca concluye nada. `python` abriendo un socket
//! es rutina; `libreoffice -> sh -> python` abriendo un socket es un incidente.
//! El grafo es lo que convierte lo primero en lo segundo.
//!
//! # Invariante de concurrencia
//!
//! **Nunca se mantiene viva una guarda de [`DashMap`] mientras se accede a otra
//! entrada del mismo mapa.** `DashMap` reparte las entradas en fragmentos con un
//! `RwLock` cada uno; si un hilo retiene la guarda del fragmento A y pide la de
//! B mientras otro hilo hace lo contrario, hay abrazo mortal. Todos los metodos
//! de este modulo copian lo que necesitan del nodo, sueltan la guarda y solo
//! entonces siguen. Los recorridos de ancestros lo hacen paso a paso por ese
//! motivo, no por comodidad.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use dashmap::DashMap;

use crate::error::GraphError;

/// Identidad estable de un proceso.
///
/// No es un PID. Los PID se reciclan, y un ataque que espere al reciclado
/// consigue que la telemetria atribuya sus acciones a un proceso inocente ya
/// terminado. El kernel deriva esta clave de `(pid, start_boottime)`, cuyo par
/// no se repite en la vida del sistema.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProcKey(pub u64);

impl ProcKey {
    /// Clave nula: "sin actor".
    pub const NONE: ProcKey = ProcKey(0);

    /// Indica si la clave designa a un proceso real.
    #[inline]
    pub fn is_some(self) -> bool {
        self.0 != 0
    }
}

/// Propiedades que se heredan hacia abajo por el arbol de procesos.
///
/// Es la parte del grafo que mas deteccion aporta por linea de codigo: permite
/// escribir reglas sobre el ORIGEN de una cadena en vez de sobre el nombre del
/// proceso que actua, que es trivial de cambiar para un atacante.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct TaintSet(u32);

impl TaintSet {
    /// Descendiente de una suite ofimatica.
    pub const OFFICE_CHILD: TaintSet = TaintSet(1 << 0);
    /// Descendiente de un navegador.
    pub const BROWSER_CHILD: TaintSet = TaintSet(1 << 1);
    /// La imagen llego de una fuente no local.
    pub const FROM_INTERNET: TaintSet = TaintSet(1 << 2);
    /// Bajo una sesion remota (ssh, escritorio remoto, WMI).
    pub const REMOTE_ORIGIN: TaintSet = TaintSet(1 << 3);
    /// Descendiente de un interprete de comandos.
    pub const SHELL_CHILD: TaintSet = TaintSet(1 << 4);
    /// Descendiente de un interprete de scripts.
    pub const INTERPRETER_CHILD: TaintSet = TaintSet(1 << 5);
    /// Ejecutado desde un directorio de escritura temporal.
    pub const FROM_TEMP: TaintSet = TaintSet(1 << 6);
    /// Descendiente de un gestor de paquetes o de un sistema de compilacion.
    ///
    /// Atenua: estos arboles escriben miles de ficheros y lanzan cientos de
    /// procesos de forma legitima. Sin esta marca, un servidor de compilacion
    /// dispara todas las reglas conductuales a la vez.
    pub const BUILD_SYSTEM: TaintSet = TaintSet(1 << 7);

    /// Conjunto vacio.
    pub const EMPTY: TaintSet = TaintSet(0);

    /// Indica si contiene todas las marcas de `other`.
    #[inline]
    pub fn contains(self, other: TaintSet) -> bool {
        self.0 & other.0 == other.0
    }

    /// Indica si comparte alguna marca con `other`.
    #[inline]
    pub fn intersects(self, other: TaintSet) -> bool {
        self.0 & other.0 != 0
    }

    /// Union de conjuntos.
    #[inline]
    pub fn union(self, other: TaintSet) -> TaintSet {
        TaintSet(self.0 | other.0)
    }

    /// Representacion cruda, para telemetria.
    #[inline]
    pub fn bits(self) -> u32 {
        self.0
    }
}

impl std::ops::BitOr for TaintSet {
    type Output = TaintSet;
    fn bitor(self, rhs: TaintSet) -> TaintSet {
        self.union(rhs)
    }
}

impl std::ops::BitOrAssign for TaintSet {
    fn bitor_assign(&mut self, rhs: TaintSet) {
        self.0 |= rhs.0;
    }
}

/// Familia a la que pertenece una imagen ejecutable.
///
/// Se deriva del nombre base del ejecutable. Es deliberadamente una heuristica
/// barata: el grafo la usa para decidir que marcas propagar, no para emitir
/// veredictos, asi que un fallo de clasificacion degrada el contexto sin
/// producir un falso positivo por si solo.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ImageClass {
    /// Interprete de comandos.
    Shell,
    /// Interprete de scripts.
    Interpreter,
    /// Navegador web.
    Browser,
    /// Suite ofimatica.
    Office,
    /// Servicio de acceso remoto.
    RemoteAccess,
    /// Gestor de paquetes o herramienta de compilacion.
    BuildSystem,
    /// Cualquier otra cosa.
    Other,
}

/// Clasifica una imagen por su nombre base.
pub fn classify_image(path: &str) -> ImageClass {
    let base = path.rsplit('/').next().unwrap_or(path);
    // Se recorta el sufijo de version habitual en Linux (python3.11 -> python3).
    let stem = base.trim_end_matches(|c: char| c == '.' || c.is_ascii_digit());

    match stem {
        "sh" | "bash" | "dash" | "zsh" | "ksh" | "fish" | "busybox" => ImageClass::Shell,
        "python" | "perl" | "ruby" | "node" | "php" | "lua" | "tclsh" | "osascript" => {
            ImageClass::Interpreter
        }
        "firefox" | "chrome" | "chromium" | "chromium-browser" | "brave" | "opera" | "epiphany" => {
            ImageClass::Browser
        }
        "soffice" | "libreoffice" | "oowriter" | "oocalc" | "winword" | "excel" | "powerpnt" => {
            ImageClass::Office
        }
        "sshd" | "xrdp" | "vncserver" | "telnetd" => ImageClass::RemoteAccess,
        "make" | "ninja" | "cargo" | "rustc" | "cc" | "gcc" | "clang" | "ld" | "apt"
        | "apt-get" | "dpkg" | "rpm" | "yum" | "dnf" | "pacman" | "npm" | "pip" => {
            ImageClass::BuildSystem
        }
        _ => ImageClass::Other,
    }
}

/// Indica si una ruta esta en un directorio de escritura temporal.
///
/// Ejecutar desde estos sitios es normal en compilaciones e instaladores, y es
/// tambien el patron de casi toda carga util descargada. La marca aporta
/// contexto; no acusa por si sola.
pub fn is_temp_path(path: &str) -> bool {
    const TEMP_PREFIXES: [&str; 6] = [
        "/tmp/",
        "/var/tmp/",
        "/dev/shm/",
        "/run/user/",
        "/home/.cache/",
        "/root/.cache/",
    ];
    TEMP_PREFIXES.iter().any(|p| path.starts_with(p))
}

/// Estado conductual acumulado de un proceso.
///
/// Los contadores se agregan por proceso y decaen con el tiempo: sin
/// decaimiento, un proceso de vida larga acumularia puntuacion indefinidamente
/// por actividad benigna dispersa en horas.
#[derive(Debug, Default)]
pub struct BehaviorState {
    /// Aperturas con intencion de escritura.
    pub writes: AtomicU64,
    /// Aperturas de escritura sobre rutas sensibles.
    pub sensitive_writes: AtomicU64,
    /// Llamadas a ptrace sobre otros procesos.
    pub ptrace_calls: AtomicU64,
    /// Conexiones salientes a destinos publicos.
    pub public_connections: AtomicU64,
    /// Procesos hijo lanzados.
    pub children_spawned: AtomicU64,
    /// Puntuacion acumulada, en milesimas para evitar coma flotante en la
    /// ruta caliente.
    score_milli: AtomicU64,
    /// Instante de la ultima actualizacion de la puntuacion.
    score_updated_ns: AtomicU64,
}

/// Semivida del decaimiento de la puntuacion conductual.
const SCORE_HALF_LIFE_NS: u64 = 60 * 1_000_000_000;

/// Tope de la puntuacion acumulada.
///
/// Sin tope, un proceso de larga vida alcanza valores de miles que no aportan
/// nada: por encima del umbral ya esta escalado, y seguir sumando solo hace que
/// tarde varias semividas en volver a bajar cuando la actividad cesa.
const SCORE_CEILING_MILLI: u64 = 1000 * 1000;

impl BehaviorState {
    /// Suma `points` a la puntuacion, aplicando primero el decaimiento
    /// acumulado desde la ultima actualizacion.
    pub fn add_score(&self, points: u32, now_ns: u64) -> u32 {
        let previo = self.decayed_score_milli(now_ns);
        let nuevo = previo
            .saturating_add(u64::from(points) * 1000)
            .min(SCORE_CEILING_MILLI);
        self.score_milli.store(nuevo, Ordering::Relaxed);
        self.score_updated_ns.store(now_ns, Ordering::Relaxed);
        (nuevo / 1000).min(u64::from(u32::MAX)) as u32
    }

    /// Puntuacion actual con el decaimiento aplicado.
    pub fn score(&self, now_ns: u64) -> u32 {
        (self.decayed_score_milli(now_ns) / 1000).min(u64::from(u32::MAX)) as u32
    }

    fn decayed_score_milli(&self, now_ns: u64) -> u64 {
        let base = self.score_milli.load(Ordering::Relaxed);
        if base == 0 {
            return 0;
        }
        let last = self.score_updated_ns.load(Ordering::Relaxed);
        let elapsed = now_ns.saturating_sub(last);
        let semividas = elapsed / SCORE_HALF_LIFE_NS;
        if semividas >= 20 {
            return 0; // por debajo de una millonesima: se considera cero
        }
        base >> semividas
    }
}

/// Un proceso en el grafo.
#[derive(Debug)]
pub struct ProcessNode {
    /// Identidad estable.
    pub key: ProcKey,
    /// PID visible en el sistema.
    pub pid: u32,
    /// Padre segun el sistema operativo.
    pub parent: ProcKey,
    /// Quien invoco realmente la creacion. Si difiere de `parent`, hubo
    /// suplantacion de proceso padre (solo observable en Windows).
    pub creator: ProcKey,
    /// Profundidad desde la raiz. Acota el coste de recorrer ancestros.
    pub depth: u16,
    /// Ruta de la imagen.
    pub image: Arc<str>,
    /// Linea de comandos, truncada por el productor.
    pub cmdline: Arc<str>,
    /// Familia de la imagen.
    pub class: ImageClass,
    /// Instante de arranque, en nanosegundos desde el arranque del sistema.
    pub started_ns: u64,
    /// Instante de salida, si ya termino.
    pub exited_ns: Option<u64>,
    /// Marcas heredadas y propias.
    pub taints: TaintSet,
    /// Estado conductual.
    pub behavior: BehaviorState,
}

/// Datos minimos para dar de alta un proceso.
#[derive(Debug, Clone)]
pub struct ExecEvent {
    /// Identidad del proceso que ejecuta.
    pub key: ProcKey,
    /// PID.
    pub pid: u32,
    /// Padre declarado.
    pub parent: ProcKey,
    /// Creador real.
    pub creator: ProcKey,
    /// Ruta de la imagen.
    pub image: Arc<str>,
    /// Linea de comandos.
    pub cmdline: Arc<str>,
    /// Instante de arranque.
    pub started_ns: u64,
}

/// Limites del grafo.
#[derive(Debug, Clone, Copy)]
pub struct GraphConfig {
    /// Numero maximo de nodos vivos. Al superarse se expulsan los muertos mas
    /// antiguos.
    pub max_nodes: usize,
    /// Tiempo que se conserva un nodo muerto.
    ///
    /// No es cero porque una deteccion puede llegar despues de que el proceso
    /// haya salido, y sin su nodo se pierde el linaje del incidente.
    pub dead_grace_ns: u64,
    /// Profundidad maxima de la cadena de ancestros.
    pub max_depth: u16,
}

impl Default for GraphConfig {
    fn default() -> Self {
        Self {
            max_nodes: 16_384,
            dead_grace_ns: 5 * 60 * 1_000_000_000,
            max_depth: 64,
        }
    }
}

/// Instantanea inmutable de un nodo, para consumo fuera del grafo.
///
/// Se devuelve por valor a proposito: entregar una referencia obligaria a
/// mantener viva la guarda del fragmento de `DashMap`, que es exactamente el
/// patron que puede provocar abrazos mortales.
#[derive(Debug, Clone)]
pub struct NodeSnapshot {
    /// Identidad.
    pub key: ProcKey,
    /// PID.
    pub pid: u32,
    /// Padre.
    pub parent: ProcKey,
    /// Profundidad.
    pub depth: u16,
    /// Imagen.
    pub image: Arc<str>,
    /// Linea de comandos.
    pub cmdline: Arc<str>,
    /// Familia.
    pub class: ImageClass,
    /// Marcas.
    pub taints: TaintSet,
    /// Vivo o no.
    pub alive: bool,
}

/// Grafo concurrente de procesos.
#[derive(Debug)]
pub struct ProcessGraph {
    nodes: DashMap<ProcKey, ProcessNode>,
    /// Cola de muertos pendientes de expirar, ordenada por instante de salida.
    reaper: Mutex<VecDeque<(u64, ProcKey)>>,
    config: GraphConfig,
}

impl ProcessGraph {
    /// Crea un grafo con los limites indicados.
    pub fn new(config: GraphConfig) -> Self {
        Self {
            nodes: DashMap::new(),
            reaper: Mutex::new(VecDeque::new()),
            config,
        }
    }

    /// Numero de nodos, vivos y en periodo de gracia.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Indica si el grafo esta vacio.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Da de alta un proceso, heredando las marcas de su padre.
    ///
    /// Devuelve el conjunto de marcas resultante.
    pub fn on_exec(&self, ev: ExecEvent) -> TaintSet {
        // Se lee el padre y se SUELTA la guarda antes de insertar al hijo.
        // Mantenerla viva mientras se inserta es el patron que puede bloquear
        // dos fragmentos a la vez (ver invariante del modulo).
        let (heredadas, profundidad_padre, clase_padre) = match self.nodes.get(&ev.parent) {
            Some(p) => (p.taints, p.depth, Some(p.class)),
            None => (TaintSet::EMPTY, 0, None),
        };

        let clase = classify_image(&ev.image);
        let mut taints = heredadas;

        // Marcas que aporta el PADRE por su familia.
        if let Some(pc) = clase_padre {
            match pc {
                ImageClass::Office => taints |= TaintSet::OFFICE_CHILD,
                ImageClass::Browser => taints |= TaintSet::BROWSER_CHILD,
                ImageClass::Shell => taints |= TaintSet::SHELL_CHILD,
                ImageClass::Interpreter => taints |= TaintSet::INTERPRETER_CHILD,
                ImageClass::RemoteAccess => taints |= TaintSet::REMOTE_ORIGIN,
                ImageClass::BuildSystem => taints |= TaintSet::BUILD_SYSTEM,
                ImageClass::Other => {}
            }
        }

        // Marcas que aporta el PROPIO proceso por su ruta.
        if is_temp_path(&ev.image) {
            taints |= TaintSet::FROM_TEMP;
        }

        let depth = profundidad_padre
            .saturating_add(1)
            .min(self.config.max_depth);

        let nodo = ProcessNode {
            key: ev.key,
            pid: ev.pid,
            parent: ev.parent,
            creator: ev.creator,
            depth,
            image: ev.image,
            cmdline: ev.cmdline,
            class: clase,
            started_ns: ev.started_ns,
            exited_ns: None,
            taints,
            behavior: BehaviorState::default(),
        };
        self.nodes.insert(ev.key, nodo);

        // Contabilizar el hijo en el padre, con la guarda ya liberada arriba.
        if let Some(p) = self.nodes.get(&ev.parent) {
            p.behavior.children_spawned.fetch_add(1, Ordering::Relaxed);
        }

        taints
    }

    /// Marca un proceso como terminado y lo encola para expiracion.
    ///
    /// El nodo no se borra: sigue disponible durante el periodo de gracia para
    /// que una deteccion tardia conserve su linaje.
    pub fn on_exit(&self, key: ProcKey, now_ns: u64) {
        let existia = match self.nodes.get_mut(&key) {
            Some(mut n) => {
                n.exited_ns = Some(now_ns);
                true
            }
            None => false,
        };
        if existia {
            if let Ok(mut q) = self.reaper.lock() {
                q.push_back((now_ns, key));
            }
        }
    }

    /// Devuelve una instantanea del nodo, si existe.
    pub fn snapshot(&self, key: ProcKey) -> Option<NodeSnapshot> {
        let n = self.nodes.get(&key)?;
        Some(NodeSnapshot {
            key: n.key,
            pid: n.pid,
            parent: n.parent,
            depth: n.depth,
            image: Arc::clone(&n.image),
            cmdline: Arc::clone(&n.cmdline),
            class: n.class,
            taints: n.taints,
            alive: n.exited_ns.is_none(),
        })
    }

    /// Marcas de un proceso, o el conjunto vacio si no esta en el grafo.
    pub fn taints(&self, key: ProcKey) -> TaintSet {
        self.nodes.get(&key).map(|n| n.taints).unwrap_or_default()
    }

    /// Aplica `f` al estado conductual del proceso.
    ///
    /// Devuelve `false` si el proceso no esta en el grafo, que ocurre de forma
    /// legitima cuando un evento llega despues de que su nodo expirara.
    pub fn with_behavior<F, R>(&self, key: ProcKey, f: F) -> Option<R>
    where
        F: FnOnce(&BehaviorState) -> R,
    {
        let n = self.nodes.get(&key)?;
        Some(f(&n.behavior))
    }

    /// Cadena de ancestros, del proceso hacia la raiz, sin incluirlo.
    ///
    /// Cada paso lee un nodo, copia la clave del padre y suelta la guarda antes
    /// de continuar: recorrerlo con las guardas vivas bloquearia varios
    /// fragmentos a la vez.
    pub fn ancestry(&self, key: ProcKey) -> Result<Vec<NodeSnapshot>, GraphError> {
        let mut cadena = Vec::new();
        let mut actual = match self.nodes.get(&key) {
            Some(n) => n.parent,
            None => return Err(GraphError::UnknownProcess(key.0)),
        };

        let limite = self.config.max_depth;
        let mut pasos = 0u16;
        while actual.is_some() {
            if pasos >= limite {
                return Err(GraphError::AncestryTooDeep { limit: limite });
            }
            let Some(snap) = self.snapshot(actual) else {
                break; // el ancestro ya expiro: la cadena se corta aqui
            };
            actual = snap.parent;
            cadena.push(snap);
            pasos += 1;
        }
        Ok(cadena)
    }

    /// Indica si el proceso o alguno de sus ancestros lleva alguna de las
    /// marcas indicadas.
    ///
    /// Las marcas ya se propagan al crear el nodo, asi que basta consultar el
    /// propio proceso; el recorrido se reserva para reconstruir el incidente.
    pub fn has_taint(&self, key: ProcKey, marcas: TaintSet) -> bool {
        self.taints(key).intersects(marcas)
    }

    /// Expira los nodos muertos cuyo periodo de gracia ha vencido y fuerza el
    /// limite de tamano.
    ///
    /// Devuelve cuantos nodos se eliminaron. Se llama periodicamente desde el
    /// bucle del colector, nunca desde la ruta caliente de un evento.
    pub fn reap(&self, now_ns: u64) -> usize {
        let mut eliminados = 0;
        let Ok(mut q) = self.reaper.lock() else {
            return 0;
        };

        // 1. Vencidos por tiempo.
        while let Some(&(muerte_ns, key)) = q.front() {
            if now_ns.saturating_sub(muerte_ns) < self.config.dead_grace_ns {
                break; // la cola esta ordenada: el resto es mas reciente
            }
            q.pop_front();
            if self.nodes.remove(&key).is_some() {
                eliminados += 1;
            }
        }

        // 2. Presion de memoria: se expulsan los muertos mas antiguos aunque no
        //    hayan cumplido la gracia. Perder contexto historico es preferible
        //    a que el agente crezca sin limite en un servidor que crea miles de
        //    procesos por minuto.
        while self.nodes.len() > self.config.max_nodes {
            match q.pop_front() {
                Some((_, key)) => {
                    if self.nodes.remove(&key).is_some() {
                        eliminados += 1;
                    }
                }
                None => break, // todos los nodos estan vivos: no hay nada que expulsar
            }
        }

        eliminados
    }
}

impl Default for ProcessGraph {
    fn default() -> Self {
        Self::new(GraphConfig::default())
    }
}
