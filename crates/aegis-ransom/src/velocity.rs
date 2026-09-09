//! Seguimiento de velocidad de modificacion y transicion de entropia.
//!
//! # Que distingue a un cifrador de un proceso normal
//!
//! No es la entropia. Un compresor, un cliente de copias de seguridad y un
//! motor de base de datos escriben datos de entropia maxima todo el dia. Lo que
//! distingue a un cifrador son tres cosas a la vez:
//!
//! 1. **Velocidad**: modifica cientos de ficheros por segundo.
//! 2. **Dispersion**: recorre el arbol de documentos, no trabaja sobre unos
//!    pocos ficheros propios.
//! 3. **Transicion**: LEE contenido estructurado y ESCRIBE ruido. El mismo
//!    proceso que hace un minuto escribia texto plano ahora escribe datos
//!    indistinguibles de aleatorios.
//!
//! La tercera es la que mas separa. Un compresor nace escribiendo alta
//! entropia; un cifrador CAMBIA. Por eso este modulo no mide solo el valor
//! actual sino el historial: guarda las ultimas escrituras de cada proceso y
//! busca el salto entre una fase de baja entropia y otra de alta.
//!
//! # Presupuesto de latencia
//!
//! Un cifrador moderno procesa entre 1.000 y 5.000 ficheros por minuto. El
//! objetivo del producto es detenerlo en menos de 500 ms desde el primer
//! fichero cifrado, con menos de 20 ficheros perdidos. Todo lo de este modulo
//! esta acotado en tiempo constante por evento: no hay recorridos, no hay
//! asignaciones en la ruta caliente.

use std::collections::{HashMap, HashSet, VecDeque};

/// Numero de escrituras recientes que se recuerdan por proceso.
///
/// Suficiente para ver una transicion y lo bastante pequeno para que el coste
/// por proceso sea de cientos de bytes, no de kilobytes.
pub const HISTORIAL: usize = 64;
/// Escrituras recientes que forman la "fase actual".
pub const FASE_RECIENTE: usize = 16;

/// Fraccion de entropia por encima de la cual un buffer se considera cifrado.
///
/// # Por que una fraccion y no bits por byte
///
/// La version anterior de este modulo comparaba contra 7,9 bits/byte absolutos.
/// Ese umbral **no lo cruza jamas ningun dato real** a la muestra de 512 bytes
/// que entrega el sondeo del kernel: datos de `/dev/urandom` a ese tamano miden
/// 7,47-7,67, porque con 512 muestras sobre 256 simbolos la entropia medida se
/// queda estructuralmente por debajo del maximo teorico. Todo el detector de
/// entropia habria estado muerto en produccion mientras pasaba cualquier prueba
/// que le inyectase flotantes inventados.
///
/// Se compara contra [`aegis_ml::entropy::entropia_maxima_esperada`], que es la
/// entropia que de hecho producen datos aleatorios a ese tamano. Ver
/// [`aegis_ml::entropy::FRACCION_CIFRADO`].
pub use aegis_ml::entropy::FRACCION_CIFRADO as RATIO_CIFRADO;
/// Fraccion por debajo de la cual un buffer se considera contenido estructurado.
pub use aegis_ml::entropy::FRACCION_ESTRUCTURADA as RATIO_ESTRUCTURADO;

/// Configuracion del detector.
#[derive(Debug, Clone, Copy)]
pub struct VelocityConfig {
    /// Ventana de observacion en nanosegundos.
    pub window_ns: u64,
    /// Ficheros distintos modificados por ventana que definen "alta velocidad".
    pub file_rate_threshold: u32,
    /// Directorios distintos tocados que definen "dispersion".
    pub dir_spread_threshold: u32,
    /// Escrituras de alta entropia por ventana.
    pub high_entropy_threshold: u32,
    /// Renombrados por ventana.
    pub rename_threshold: u32,
    /// Extensiones nuevas distintas por ventana.
    pub new_extension_threshold: u32,
    /// Procesos en seguimiento simultaneo.
    pub max_tracked: usize,
    /// Ficheros distintos por proceso que se recuerdan.
    pub max_files_per_process: usize,
}

impl Default for VelocityConfig {
    fn default() -> Self {
        Self {
            window_ns: 1_000_000_000,
            // 20 ficheros en un segundo es la cota que fija el presupuesto de
            // dano: por encima, el cifrador ya lleva ventaja.
            file_rate_threshold: 20,
            dir_spread_threshold: 3,
            high_entropy_threshold: 12,
            rename_threshold: 20,
            new_extension_threshold: 1,
            max_tracked: 4096,
            max_files_per_process: 2048,
        }
    }
}

/// Una escritura observada.
#[derive(Debug, Clone, Copy)]
pub struct WriteObservation {
    /// Entropia de la muestra como fraccion de la maxima alcanzable a su
    /// tamano, en `[0, 1]`. Ver [`RATIO_CIFRADO`].
    ///
    /// Es opcional a proposito. El sondeo del kernel solo muestrea escrituras
    /// por encima de un tamano minimo; las demas llegan sin muestra. Anotarlas
    /// como entropia cero seria FABRICAR una fase estructurada que nunca se
    /// observo, y con ella una transicion falsa en cuanto el proceso escriba
    /// algo comprimido. Una escritura sin muestra cuenta para velocidad y
    /// dispersion, pero no toca el historial de entropia.
    pub entropy_ratio: Option<f64>,
    /// Bytes escritos.
    pub bytes: u64,
    /// Instante.
    pub ts_ns: u64,
}

/// Estado acumulado de un proceso dentro de la ventana.
#[derive(Debug)]
pub struct ProcessState {
    ventana_ns: u64,
    ficheros: HashSet<u64>,
    directorios: HashSet<u64>,
    extensiones_nuevas: HashSet<u64>,
    escrituras: u32,
    escrituras_alta_entropia: u32,
    renombrados: u32,
    bytes: u64,
    senuelos_tocados: u32,
    /// Historial de fracciones de entropia recientes.
    historial: VecDeque<f64>,
    /// Instante de la primera escritura de alta entropia de la fase actual.
    primera_alta_ns: Option<u64>,
    ultimo_ns: u64,
}

impl ProcessState {
    fn nuevo(ts_ns: u64) -> ProcessState {
        ProcessState {
            ventana_ns: ts_ns,
            ficheros: HashSet::new(),
            directorios: HashSet::new(),
            extensiones_nuevas: HashSet::new(),
            escrituras: 0,
            escrituras_alta_entropia: 0,
            renombrados: 0,
            bytes: 0,
            senuelos_tocados: 0,
            historial: VecDeque::with_capacity(HISTORIAL),
            primera_alta_ns: None,
            ultimo_ns: ts_ns,
        }
    }

    fn rotar_si_procede(&mut self, ts_ns: u64, ventana: u64) {
        if ts_ns.saturating_sub(self.ventana_ns) <= ventana {
            return;
        }
        self.ventana_ns = ts_ns;
        self.ficheros.clear();
        self.directorios.clear();
        self.extensiones_nuevas.clear();
        self.escrituras = 0;
        self.escrituras_alta_entropia = 0;
        self.renombrados = 0;
        self.bytes = 0;
        self.primera_alta_ns = None;
        // El historial de entropia NO se limpia al rotar la ventana: la
        // transicion de texto plano a cifrado puede cruzar el limite de la
        // ventana, y borrarla ahi seria perder justo la senal que se busca.
    }

    /// Ficheros distintos modificados en la ventana.
    pub fn distinct_files(&self) -> u32 {
        self.ficheros.len() as u32
    }

    /// Directorios distintos tocados.
    pub fn distinct_dirs(&self) -> u32 {
        self.directorios.len() as u32
    }

    /// Escrituras en la ventana.
    pub fn writes(&self) -> u32 {
        self.escrituras
    }

    /// Escrituras de alta entropia en la ventana.
    pub fn high_entropy_writes(&self) -> u32 {
        self.escrituras_alta_entropia
    }

    /// Renombrados en la ventana.
    pub fn renames(&self) -> u32 {
        self.renombrados
    }

    /// Senuelos tocados.
    pub fn honeypot_hits(&self) -> u32 {
        self.senuelos_tocados
    }

    /// Fraccion de entropia media de las escrituras mas recientes.
    pub fn recent_entropy(&self) -> Option<f64> {
        let n = self.historial.len().min(FASE_RECIENTE);
        if n == 0 {
            return None;
        }
        let suma: f64 = self.historial.iter().rev().take(n).sum();
        Some(suma / n as f64)
    }

    /// Fraccion de entropia media de las escrituras anteriores a la fase reciente.
    pub fn earlier_entropy(&self) -> Option<f64> {
        if self.historial.len() <= FASE_RECIENTE {
            return None;
        }
        let anteriores = self.historial.len() - FASE_RECIENTE;
        let suma: f64 = self.historial.iter().take(anteriores).sum();
        Some(suma / anteriores as f64)
    }

    /// Indica si el proceso paso de escribir contenido estructurado a escribir
    /// datos indistinguibles de aleatorios.
    ///
    /// Es la senal que separa un cifrador de un compresor: el compresor NACE
    /// escribiendo alta entropia, el cifrador CAMBIA. Exigir ambas fases evita
    /// clasificar como ransomware a `tar czf`, que es exactamente el falso
    /// positivo que haria inutilizable esta deteccion.
    pub fn entropy_transition(&self) -> bool {
        let (Some(antes), Some(ahora)) = (self.earlier_entropy(), self.recent_entropy()) else {
            return false;
        };
        antes < RATIO_ESTRUCTURADO && ahora > RATIO_CIFRADO
    }

    /// Instante en que empezo la fase de alta entropia, si empezo.
    pub fn first_high_entropy_ns(&self) -> Option<u64> {
        self.primera_alta_ns
    }
}

/// Hash estable de una ruta.
///
/// Se guardan hashes y no rutas: retener las cadenas de miles de ficheros por
/// proceso multiplicaria por veinte la memoria del seguimiento, y para contar
/// distintos el hash basta.
pub fn hash_ruta(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x1000_0000_01b3);
    }
    h
}

/// Directorio padre de una ruta.
pub fn directorio(ruta: &str) -> &str {
    match ruta.rfind('/') {
        Some(0) => "/",
        Some(i) => &ruta[..i],
        None => ".",
    }
}

/// Extension de una ruta, sin el punto.
pub fn extension(ruta: &str) -> Option<&str> {
    let base = ruta.rsplit('/').next()?;
    let i = base.rfind('.')?;
    // Un punto inicial es un fichero oculto, no una extension.
    if i == 0 {
        return None;
    }
    let ext = &base[i + 1..];
    if ext.is_empty() || ext.len() > 16 {
        None
    } else {
        Some(ext)
    }
}

/// Seguimiento de velocidad por proceso.
#[derive(Debug)]
pub struct VelocityTracker {
    config: VelocityConfig,
    procesos: HashMap<u64, ProcessState>,
    /// Extensiones que el sistema ya habia visto antes de empezar a vigilar.
    ///
    /// Una extension nueva solo es una senal si de verdad es nueva; sin esta
    /// linea base, la primera vez que alguien guarda un `.parquet` el detector
    /// grita.
    extensiones_conocidas: HashSet<u64>,
}

impl VelocityTracker {
    /// Crea un seguimiento.
    pub fn new(config: VelocityConfig) -> VelocityTracker {
        let mut conocidas = HashSet::new();
        for e in EXTENSIONES_HABITUALES {
            conocidas.insert(hash_ruta(e));
        }
        VelocityTracker {
            config,
            procesos: HashMap::new(),
            extensiones_conocidas: conocidas,
        }
    }

    /// Configuracion en uso.
    pub fn config(&self) -> &VelocityConfig {
        &self.config
    }

    /// Numero de procesos en seguimiento.
    pub fn tracked(&self) -> usize {
        self.procesos.len()
    }

    /// Anade una extension a la linea base de conocidas.
    pub fn learn_extension(&mut self, ext: &str) {
        self.extensiones_conocidas
            .insert(hash_ruta(&ext.to_ascii_lowercase()));
    }

    /// Estado de un proceso, si esta en seguimiento.
    pub fn state(&self, actor: u64) -> Option<&ProcessState> {
        self.procesos.get(&actor)
    }

    /// Olvida un proceso, tipicamente al terminar.
    pub fn forget(&mut self, actor: u64) {
        self.procesos.remove(&actor);
    }

    fn entrada(&mut self, actor: u64, ts_ns: u64) -> &mut ProcessState {
        if !self.procesos.contains_key(&actor) && self.procesos.len() >= self.config.max_tracked {
            // Cota dura: se expulsa el proceso con actividad mas antigua. Sin
            // ella, un arbol de compilacion que crea miles de procesos hace
            // crecer el seguimiento sin techo.
            if let Some(v) = self
                .procesos
                .iter()
                .min_by_key(|(_, s)| s.ultimo_ns)
                .map(|(k, _)| *k)
            {
                self.procesos.remove(&v);
            }
        }
        let ventana = self.config.window_ns;
        let e = self
            .procesos
            .entry(actor)
            .or_insert_with(|| ProcessState::nuevo(ts_ns));
        e.rotar_si_procede(ts_ns, ventana);
        e.ultimo_ns = ts_ns;
        e
    }

    /// Registra una escritura.
    pub fn on_write(&mut self, actor: u64, ruta: Option<&str>, obs: WriteObservation) {
        let max_ficheros = self.config.max_files_per_process;
        let e = self.entrada(actor, obs.ts_ns);
        e.escrituras = e.escrituras.saturating_add(1);
        e.bytes = e.bytes.saturating_add(obs.bytes);

        if let Some(entropia) = obs.entropy_ratio {
            if e.historial.len() == HISTORIAL {
                e.historial.pop_front();
            }
            e.historial.push_back(entropia);

            if entropia > RATIO_CIFRADO {
                e.escrituras_alta_entropia = e.escrituras_alta_entropia.saturating_add(1);
                if e.primera_alta_ns.is_none() {
                    e.primera_alta_ns = Some(obs.ts_ns);
                }
            }
        }

        if let Some(p) = ruta {
            if e.ficheros.len() < max_ficheros {
                e.ficheros.insert(hash_ruta(p));
            }
            if e.directorios.len() < max_ficheros {
                e.directorios.insert(hash_ruta(directorio(p)));
            }
        }
    }

    /// Registra un renombrado.
    pub fn on_rename(&mut self, actor: u64, origen: &str, destino: &str, ts_ns: u64) {
        let nueva = extension(destino)
            .map(|e| hash_ruta(&e.to_ascii_lowercase()))
            .filter(|h| !self.extensiones_conocidas.contains(h));
        let max_ficheros = self.config.max_files_per_process;

        let e = self.entrada(actor, ts_ns);
        e.renombrados = e.renombrados.saturating_add(1);
        if e.ficheros.len() < max_ficheros {
            e.ficheros.insert(hash_ruta(origen));
        }
        if e.directorios.len() < max_ficheros {
            e.directorios.insert(hash_ruta(directorio(origen)));
        }
        if let Some(h) = nueva {
            e.extensiones_nuevas.insert(h);
        }
    }

    /// Registra que un proceso toco un fichero senuelo.
    pub fn on_honeypot(&mut self, actor: u64, ts_ns: u64) {
        let e = self.entrada(actor, ts_ns);
        e.senuelos_tocados = e.senuelos_tocados.saturating_add(1);
    }

    /// Extensiones nuevas vistas por el proceso en la ventana.
    pub fn new_extensions(&self, actor: u64) -> u32 {
        self.procesos
            .get(&actor)
            .map(|e| e.extensiones_nuevas.len() as u32)
            .unwrap_or(0)
    }

    /// Elimina los procesos sin actividad reciente.
    pub fn prune(&mut self, now_ns: u64) -> usize {
        let limite = self.config.window_ns.saturating_mul(30);
        let antes = self.procesos.len();
        self.procesos
            .retain(|_, s| now_ns.saturating_sub(s.ultimo_ns) < limite);
        antes - self.procesos.len()
    }
}

impl Default for VelocityTracker {
    fn default() -> Self {
        Self::new(VelocityConfig::default())
    }
}

/// Extensiones que cualquier sistema tiene y que nunca son "nuevas".
const EXTENSIONES_HABITUALES: &[&str] = &[
    "txt",
    "log",
    "conf",
    "cfg",
    "ini",
    "json",
    "xml",
    "yaml",
    "yml",
    "toml",
    "md",
    "csv",
    "tsv",
    "pdf",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
    "odt",
    "ods",
    "odp",
    "rtf",
    "jpg",
    "jpeg",
    "png",
    "gif",
    "bmp",
    "svg",
    "webp",
    "ico",
    "mp3",
    "mp4",
    "avi",
    "mkv",
    "mov",
    "wav",
    "flac",
    "zip",
    "tar",
    "gz",
    "bz2",
    "xz",
    "zst",
    "7z",
    "rar",
    "iso",
    "so",
    "a",
    "o",
    "ko",
    "dll",
    "exe",
    "bin",
    "img",
    "deb",
    "rpm",
    "apk",
    "c",
    "h",
    "cpp",
    "hpp",
    "rs",
    "go",
    "py",
    "js",
    "ts",
    "java",
    "rb",
    "php",
    "sh",
    "pl",
    "sql",
    "db",
    "sqlite",
    "bak",
    "tmp",
    "swp",
    "lock",
    "pid",
    "sock",
    "key",
    "pem",
    "crt",
    "cer",
    "html",
    "css",
    "woff",
    "woff2",
    "ttf",
    "otf",
    "part",
    "crdownload",
];
