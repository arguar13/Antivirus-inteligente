//! El lado del agente: arrancar el trabajador, ponerle techo, pedirle analisis
//! con plazo y sobrevivir a que muera.
//!
//! # Lo que el agente impone desde fuera
//!
//! Lo que un proceso comprometido no puede quitarse a si mismo:
//!
//! - **Plazo por peticion.** Si no responde a tiempo, se le mata (SIGKILL) y la
//!   peticion es `SinDatos` por plazo. Escribir la peticion tambien tiene plazo:
//!   va por un hilo propio, y matar al hijo desbloquea la escritura.
//! - **cgroup con techo de memoria, CPU y procesos.** El trabajador vive en su
//!   propio cgroup; si pasa del techo de memoria, el kernel lo mata (OOM) y se
//!   distingue de cualquier otra muerte leyendo `memory.events`.
//! - **Freno de reinicios.** Morir es normal (un fichero que revienta un
//!   parser); morir en bucle no. Tras `max_muertes` en `ventana`, el trabajador
//!   se queda apagado `enfriamiento` y todo lo que habria analizado es `SinDatos`
//!   por trabajador caido. El nucleo del agente sigue protegiendo igual.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::time::{Duration, Instant};

use aegis_motor::Histograma;

use crate::analizadores::Analizador;
use crate::confinamiento::{landlock_del_saludo, UID_POR_DEFECTO};
use crate::protocolo::{
    decodificar_fallo, escribir, leer, ErrorProtocolo, Hola, Informe, Peticion, Tipo, Trama,
};
use crate::servidor::VAR_UID;

/// Como arrancar y vigilar al trabajador.
#[derive(Debug, Clone)]
pub struct ConfigTrabajador {
    /// El ejecutable: el propio agente.
    pub programa: PathBuf,
    /// Como se le ve en `ps` (argv[0]). Con `programa` = /proc/self/exe, sin
    /// esto el trabajador se llamaria «/proc/self/exe».
    pub nombre: Option<OsString>,
    /// Sus argumentos: los que lo convierten en trabajador.
    pub argumentos: Vec<OsString>,
    /// El uid propio con el que se confina.
    pub uid: u32,
    /// Techo de memoria del cgroup, en bytes.
    pub memoria_max: u64,
    /// Techo de CPU: `(cuota, periodo)` en microsegundos.
    pub cpu_max: (u64, u64),
    /// Cuanto se espera al saludo.
    pub plazo_arranque: Duration,
    /// Muertes toleradas en la ventana antes de enfriar.
    pub max_muertes: usize,
    /// La ventana en la que se cuentan las muertes.
    pub ventana: Duration,
    /// Cuanto se queda apagado tras morir en bucle.
    pub enfriamiento: Duration,
}

impl ConfigTrabajador {
    /// El trabajador es este mismo binario con `--trabajador`.
    ///
    /// # Errores
    ///
    /// Si no se puede saber la ruta del ejecutable actual.
    pub fn este_binario() -> std::io::Result<ConfigTrabajador> {
        let yo = std::env::current_exe()?;
        Ok(ConfigTrabajador {
            // /proc/self/exe y no la ruta: al actualizar el paquete la ruta ya
            // es el binario NUEVO y la del viejo dice «(deleted)». Un trabajador
            // relanzado antes de que el postinst reinicie tiene que ser de ESTA
            // version, que es la que habla su protocolo (FASE 3 del MP-16).
            programa: PathBuf::from("/proc/self/exe"),
            nombre: Some(yo.into_os_string()),
            argumentos: vec!["--trabajador".into()],
            uid: UID_POR_DEFECTO,
            memoria_max: 256 * 1024 * 1024,
            cpu_max: (50_000, 100_000),
            plazo_arranque: Duration::from_secs(10),
            max_muertes: 5,
            ventana: Duration::from_secs(60),
            enfriamiento: Duration::from_secs(120),
        })
    }
}

/// Por que no hay informe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FalloAnalisis {
    /// No respondio a tiempo y se le mato.
    Plazo(Duration),
    /// Murio atendiendo la peticion.
    Murio(String),
    /// No esta disponible (no arranca, o enfria tras morir en bucle).
    NoDisponible(String),
    /// El analizador no pudo mirar esos bytes (formato ilegible, por ejemplo).
    NoPudo(String),
}

impl std::fmt::Display for FalloAnalisis {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FalloAnalisis::Plazo(d) => {
                write!(f, "sin respuesta en {} ms: se le mato", d.as_millis())
            }
            FalloAnalisis::Murio(m) => write!(f, "murio: {m}"),
            FalloAnalisis::NoDisponible(m) => write!(f, "no disponible: {m}"),
            FalloAnalisis::NoPudo(m) => write!(f, "no pudo mirar: {m}"),
        }
    }
}

/// Lo que se publica del trabajador.
#[derive(Debug, Clone, Default)]
pub struct EstadoTrabajador {
    /// Veces que se arranco.
    pub arranques: u64,
    /// Veces que murio sin que se le pidiera.
    pub muertes: u64,
    /// De esas, las que mato el techo de memoria del cgroup.
    pub muertes_por_memoria: u64,
    /// Peticiones que vencieron su plazo.
    pub plazos: u64,
    /// Analisis que terminaron con informe.
    pub analisis: u64,
    /// Analisis que el analizador no pudo hacer.
    pub no_pudo: u64,
    /// Veces que se quedo apagado por morir en bucle.
    pub enfriamientos: u64,
    /// La ultima causa de muerte.
    pub ultima_muerte: Option<String>,
    /// El confinamiento que declaro en su saludo.
    pub confinamiento: String,
    /// Como quedo su cgroup.
    pub cgroup: String,
    /// Latencia de cada analisis, ida y vuelta.
    pub latencia: Histograma,
}

/// El cgroup propio del trabajador.
struct Cgroup {
    dir: PathBuf,
    /// Por que no hay techo de CPU, si no lo hay.
    sin_cpu: Option<String>,
    /// El techo de memoria que se le puso de verdad.
    memoria: u64,
}

/// El cgroup del servicio, si la unidad se lo delega al agente.
///
/// La unidad del paquete pone `Delegate=yes` y `AEGIS_CGROUP_DELEGADO=1`, y el
/// watchdog se baja a la hoja `supervision` antes de lanzar al agente. Solo asi
/// el cgroup del servicio se queda sin procesos propios y puede repartir
/// controladores a sus hijos: cgroup v2 no deja hacer las dos cosas.
fn base_delegada() -> Option<PathBuf> {
    std::env::var_os("AEGIS_CGROUP_DELEGADO")?;
    let propio = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let ruta = propio.lines().find_map(|l| l.strip_prefix("0::"))?.trim();
    let servicio = ruta.strip_suffix("/supervision")?;
    let base = Path::new("/sys/fs/cgroup").join(servicio.trim_start_matches('/'));
    base.join("cgroup.subtree_control")
        .is_file()
        .then_some(base)
}

/// Suelo del techo del trabajador bajo el servicio: con menos no analiza nada.
const SUELO_TRABAJADOR: u64 = 32 * 1024 * 1024;

/// El techo del trabajador dentro del servicio: lo que la unidad deja entre su
/// pico (`memory.high`) y su techo (`memory.max`), que es lo que el presupuesto
/// no le da al nucleo. Asi agente y trabajador juntos no llegan al OOM del
/// servicio. Nunca por encima del configurado; sin techos numericos en la
/// unidad, el configurado.
fn techo_bajo_el_servicio(max: Option<u64>, alto: Option<u64>, configurado: u64) -> u64 {
    match (max, alto) {
        (Some(max), Some(alto)) if max > alto => {
            configurado.min((max - alto).max(SUELO_TRABAJADOR))
        }
        _ => configurado,
    }
}

fn leer_limite(base: &Path, fichero: &str) -> Option<u64> {
    std::fs::read_to_string(base.join(fichero))
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
}

impl Cgroup {
    /// Crea (o reutiliza) el cgroup y le pone el techo.
    ///
    /// Con la unidad del paquete (`Delegate=yes`) cuelga del cgroup del
    /// servicio ([`base_delegada`]): la parada de systemd lo alcanza, systemd no
    /// le reajusta el reparto y su memoria cuenta en el presupuesto del agente.
    /// Sin delegacion (el agente lanzado a mano o por otra unidad) se crea bajo
    /// la raiz de cgroup v2, la unica que puede tener procesos y a la vez
    /// repartir controladores a sus hijos.
    fn crear(config: &ConfigTrabajador) -> Result<Cgroup, String> {
        if !Path::new("/sys/fs/cgroup/cgroup.controllers").is_file() {
            return Err("no hay cgroup v2 unificado en /sys/fs/cgroup".into());
        }
        let delegado = base_delegada();
        let raiz_propia = delegado
            .clone()
            .unwrap_or_else(|| PathBuf::from("/sys/fs/cgroup"));
        let raiz = raiz_propia.as_path();
        Cgroup::limpiar_huerfanos(raiz);
        // Los controladores que el hijo necesita tienen que estar repartidos
        // desde la raiz. Se daba por hecho, y en las VM de la matriz la raiz no
        // repartia `cpu`: el cgroup entero fallaba (FASE 1 del MP-16). Memoria y
        // numero de procesos son obligatorios; la CPU, si el kernel no deja
        // activarla, se declara.
        for c in ["memory", "pids"] {
            Cgroup::repartir(raiz, c)?;
        }
        let sin_cpu = Cgroup::repartir(raiz, "cpu").err();
        // Uno por cliente: dos trabajadores en el mismo cgroup se repartirian el
        // techo, y el recuento de muertes por memoria dejaria de ser de uno.
        static SIGUIENTE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SIGUIENTE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = raiz.join(format!("aegis-trabajador-{}-{n}", std::process::id()));
        if !dir.is_dir() {
            std::fs::create_dir(&dir).map_err(|e| format!("crear {}: {e}", dir.display()))?;
        }
        let memoria = match &delegado {
            Some(base) => techo_bajo_el_servicio(
                leer_limite(base, "memory.max"),
                leer_limite(base, "memory.high"),
                config.memoria_max,
            ),
            None => config.memoria_max,
        };
        let mut cg = Cgroup {
            dir,
            sin_cpu,
            memoria,
        };
        cg.escribir("memory.max", &memoria.to_string())?;
        // Sin intercambio: con swap, el techo de memoria no seria un techo.
        let _ = cg.escribir("memory.swap.max", "0");
        cg.escribir("pids.max", "1")?;
        if cg.sin_cpu.is_none() {
            if let Err(m) = cg.escribir(
                "cpu.max",
                &format!("{} {}", config.cpu_max.0, config.cpu_max.1),
            ) {
                cg.sin_cpu = Some(m);
            }
        }
        Ok(cg)
    }

    /// Activa un controlador en el reparto de `raiz` (la de cgroup v2 o la del
    /// servicio delegado), si no lo esta ya.
    fn repartir(raiz: &Path, controlador: &str) -> Result<(), String> {
        let control = raiz.join("cgroup.subtree_control");
        let activos =
            std::fs::read_to_string(&control).map_err(|e| format!("{}: {e}", control.display()))?;
        if activos.split_whitespace().any(|c| c == controlador) {
            return Ok(());
        }
        std::fs::write(&control, format!("+{controlador}"))
            .map_err(|e| format!("activar el controlador {controlador}: {e}"))
    }

    /// Borra los cgroups de trabajadores de agentes que ya no existen.
    ///
    /// Un agente que muere sin ordenar su salida (SIGKILL, un corte de luz no:
    /// eso ya vacia /sys/fs/cgroup) deja su cgroup vacio detras. El nombre lleva
    /// el pid del agente: si ese proceso no existe, el cgroup es huerfano. Un
    /// cgroup con procesos no se deja borrar, asi que esto no puede llevarse por
    /// delante nada vivo.
    fn limpiar_huerfanos(raiz: &Path) {
        let Ok(dir) = std::fs::read_dir(raiz) else {
            return;
        };
        for e in dir.flatten() {
            let nombre = e.file_name();
            let Some(resto) = nombre
                .to_str()
                .and_then(|n| n.strip_prefix("aegis-trabajador-"))
            else {
                continue;
            };
            let Some(pid) = resto.split('-').next().and_then(|p| p.parse::<u32>().ok()) else {
                continue;
            };
            if !Path::new(&format!("/proc/{pid}")).exists() {
                let _ = std::fs::remove_dir(e.path());
            }
        }
    }

    fn escribir(&self, fichero: &str, valor: &str) -> Result<(), String> {
        std::fs::write(self.dir.join(fichero), valor).map_err(|e| format!("{fichero}={valor}: {e}"))
    }

    fn meter(&self, pid: u32) -> Result<(), String> {
        self.escribir("cgroup.procs", &pid.to_string())
    }

    fn muertes_por_memoria(&self) -> u64 {
        std::fs::read_to_string(self.dir.join("memory.events"))
            .ok()
            .and_then(|s| {
                s.lines()
                    .find_map(|l| l.strip_prefix("oom_kill "))
                    .and_then(|v| v.trim().parse().ok())
            })
            .unwrap_or(0)
    }
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(&self.dir);
    }
}

struct Vivo {
    hijo: Child,
    peticiones: Sender<Trama>,
    respuestas: Receiver<Result<Trama, ErrorProtocolo>>,
}

impl Vivo {
    fn matar(&mut self) -> String {
        let _ = self.hijo.kill();
        match self.hijo.wait() {
            Ok(s) => describir(s),
            Err(e) => format!("sin estado de salida: {e}"),
        }
    }
}

fn describir(s: std::process::ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt;
    match (s.code(), s.signal()) {
        (Some(c), _) => format!("salio con codigo {c}"),
        (None, Some(sig)) => format!("muerto por la senal {sig}"),
        _ => "termino".into(),
    }
}

/// El cliente del trabajador confinado.
pub struct Trabajador {
    config: ConfigTrabajador,
    vivo: Option<Vivo>,
    cgroup: Option<Cgroup>,
    hola: Option<Hola>,
    siguiente: u64,
    muertes: VecDeque<Instant>,
    apagado_hasta: Option<Instant>,
    oom_visto: u64,
    estado: EstadoTrabajador,
}

impl Trabajador {
    /// Arranca el trabajador y espera su saludo.
    ///
    /// # Errores
    ///
    /// Si no arranca, no saluda a tiempo o no pudo confinarse lo bastante: en
    /// ese caso no se usa, y el motor que lo necesita queda declarado como no
    /// disponible en este host.
    pub fn arrancar(config: ConfigTrabajador) -> Result<Trabajador, String> {
        let cgroup = Cgroup::crear(&config);
        let (cgroup, estado_cgroup) = match cgroup {
            Ok(c) => {
                let cpu = match &c.sin_cpu {
                    None => format!("cpu {}/{}", config.cpu_max.0, config.cpu_max.1),
                    Some(m) => format!("SIN techo de cpu ({m})"),
                };
                let d = format!(
                    "{} (memoria {} MiB, {cpu}, 1 proceso)",
                    c.dir.display(),
                    c.memoria / (1024 * 1024),
                );
                (Some(c), d)
            }
            Err(m) => (None, format!("SIN cgroup: {m}")),
        };
        let mut t = Trabajador {
            config,
            vivo: None,
            cgroup,
            hola: None,
            siguiente: 1,
            muertes: VecDeque::new(),
            apagado_hasta: None,
            oom_visto: 0,
            estado: EstadoTrabajador {
                cgroup: estado_cgroup,
                ..EstadoTrabajador::default()
            },
        };
        t.lanzar()?;
        Ok(t)
    }

    /// Lo que declaro el trabajador al saludar.
    pub fn hola(&self) -> Option<&Hola> {
        self.hola.as_ref()
    }

    /// Contadores.
    pub fn estado(&self) -> &EstadoTrabajador {
        &self.estado
    }

    /// El pid del proceso trabajador, mientras el cliente lo tiene en marcha.
    ///
    /// `None` si no hay proceso: no arranco, murio y aun no se ha relanzado (se
    /// relanza en la siguiente peticion) o esta enfriando tras morir en bucle.
    ///
    /// Mientras dure el prestamo de `&self`, este pid no puede pasar a otro
    /// proceso: el cliente solo recoge al hijo (`wait`) desde metodos que piden
    /// `&mut self`, y un hijo sin recoger conserva su pid. Lo que si puede
    /// pasar es que el trabajador haya muerto sin que el cliente lo sepa
    /// todavia: es un zombi, y quien lo mida tiene que comprobar que vive
    /// (`aegis-enforce` lo hace con el `State:` de su status).
    pub fn pid(&self) -> Option<u32> {
        self.vivo.as_ref().map(|v| v.hijo.id())
    }

    /// La ABI de Landlock que el trabajador en marcha declaro en su saludo
    /// (`landlock=si (N)`), si se puso un dominio.
    ///
    /// Es una declaracion del propio trabajador, hecha antes de leer un byte
    /// hostil: el kernel no publica el dominio fuera del proceso. Se toma del
    /// saludo del proceso que esta en marcha ahora, nunca del de uno anterior:
    /// sin proceso, `None`.
    pub fn landlock_declarado(&self) -> Option<u32> {
        self.vivo.as_ref()?;
        landlock_del_saludo(&self.hola.as_ref()?.confinamiento)
    }

    fn lanzar(&mut self) -> Result<(), String> {
        let mut orden = Command::new(&self.config.programa);
        if let Some(n) = &self.config.nombre {
            std::os::unix::process::CommandExt::arg0(&mut orden, n);
        }
        let mut hijo = orden
            .args(&self.config.argumentos)
            .env_clear()
            .env(VAR_UID, self.config.uid.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("no arranca {}: {e}", self.config.programa.display()))?;
        self.estado.arranques += 1;

        if let Some(cg) = &self.cgroup {
            if let Err(m) = cg.meter(hijo.id()) {
                let _ = hijo.kill();
                let _ = hijo.wait();
                return Err(format!("no se pudo meter en su cgroup: {m}"));
            }
        }
        // Heredaba el OOMScoreAdjust=-500 del agente. Con los dos bajo el mismo
        // MemoryMax del servicio, ante un OOM el que muere es el trabajador (se
        // relanza y su analisis es SinDatos), nunca el nucleo. Subirse la
        // puntuacion no necesita privilegios; si ya salio, no hay nada que hacer.
        let _ = std::fs::write(format!("/proc/{}/oom_score_adj", hijo.id()), "1000");

        let entrada: ChildStdin = hijo.stdin.take().ok_or("sin stdin")?;
        let salida = hijo.stdout.take().ok_or("sin stdout")?;
        let errores = hijo.stderr.take().ok_or("sin stderr")?;

        // Lo que el trabajador dice por stderr (un panico, por ejemplo) se
        // publica, recortado: lo escribe un proceso que puede estar comprometido.
        std::thread::Builder::new()
            .name("trabajador-stderr".into())
            .spawn(move || {
                for linea in BufReader::new(errores)
                    .lines()
                    .map_while(Result::ok)
                    .take(64)
                {
                    let corta: String = linea.chars().take(300).collect();
                    eprintln!("aegis-agent: trabajador: {corta}");
                }
            })
            .map_err(|e| e.to_string())?;

        let (tx_resp, respuestas) = mpsc::channel();
        std::thread::Builder::new()
            .name("trabajador-lector".into())
            .spawn(move || {
                let mut r = BufReader::new(salida);
                loop {
                    let t = leer(&mut r);
                    let fin = t.is_err();
                    if tx_resp.send(t).is_err() || fin {
                        break;
                    }
                }
            })
            .map_err(|e| e.to_string())?;

        let (peticiones, rx_pet) = mpsc::channel::<Trama>();
        std::thread::Builder::new()
            .name("trabajador-escritor".into())
            .spawn(move || {
                let mut w = entrada;
                while let Ok(t) = rx_pet.recv() {
                    if escribir(&mut w, &t).is_err() {
                        break;
                    }
                }
            })
            .map_err(|e| e.to_string())?;

        let mut vivo = Vivo {
            hijo,
            peticiones,
            respuestas,
        };
        let saludo = match vivo.respuestas.recv_timeout(self.config.plazo_arranque) {
            Ok(Ok(t)) if t.tipo == Tipo::Hola => {
                Hola::decodificar(&t.carga).map_err(|e| e.to_string())
            }
            Ok(Ok(_)) => Err("la primera trama no es un saludo".into()),
            Ok(Err(e)) => Err(format!("{e} ({})", vivo.matar())),
            Err(_) => Err(format!(
                "sin saludo en {:?} ({})",
                self.config.plazo_arranque,
                vivo.matar()
            )),
        };
        let hola = match saludo {
            Ok(h) => h,
            Err(m) => {
                let _ = vivo.matar();
                return Err(m);
            }
        };
        self.estado.confinamiento = hola.confinamiento.clone();
        if hola.analizadores.is_empty() {
            let _ = vivo.matar();
            return Err(format!(
                "no pudo confinarse lo bastante: {}",
                hola.confinamiento
            ));
        }
        self.hola = Some(hola);
        self.vivo = Some(vivo);
        Ok(())
    }

    fn registrar_muerte(&mut self, motivo: String) {
        self.estado.muertes += 1;
        if let Some(cg) = &self.cgroup {
            let oom = cg.muertes_por_memoria();
            if oom > self.oom_visto {
                self.estado.muertes_por_memoria += oom - self.oom_visto;
                self.oom_visto = oom;
            }
        }
        self.estado.ultima_muerte = Some(motivo);
        let ahora = Instant::now();
        self.muertes.push_back(ahora);
        while self
            .muertes
            .front()
            .is_some_and(|t| ahora.duration_since(*t) > self.config.ventana)
        {
            self.muertes.pop_front();
        }
        if self.muertes.len() >= self.config.max_muertes {
            self.apagado_hasta = Some(ahora + self.config.enfriamiento);
            self.estado.enfriamientos += 1;
            self.muertes.clear();
        }
    }

    /// Pide un analisis y espera la respuesta como mucho `plazo`.
    ///
    /// # Errores
    ///
    /// Ver [`FalloAnalisis`]. Ninguno es fatal para quien llama: el trabajador
    /// se relanza solo en la siguiente peticion, o se queda enfriando.
    pub fn analizar(
        &mut self,
        analizador: Analizador,
        datos: &[u8],
        plazo: Duration,
    ) -> Result<Informe, FalloAnalisis> {
        if let Some(hasta) = self.apagado_hasta {
            if Instant::now() < hasta {
                return Err(FalloAnalisis::NoDisponible(format!(
                    "enfriando tras {} muertes en {:?}; ultima: {}",
                    self.config.max_muertes,
                    self.config.ventana,
                    self.estado.ultima_muerte.as_deref().unwrap_or("?")
                )));
            }
            self.apagado_hasta = None;
        }
        if self.vivo.is_none() {
            if let Err(m) = self.lanzar() {
                self.registrar_muerte(format!("no relanza: {m}"));
                return Err(FalloAnalisis::NoDisponible(m));
            }
        }
        if !self
            .hola
            .as_ref()
            .is_some_and(|h| h.analizadores.contains(&analizador))
        {
            return Err(FalloAnalisis::NoPudo(format!(
                "el trabajador no sabe analizar «{}»",
                analizador.nombre()
            )));
        }

        let id = self.siguiente;
        self.siguiente += 1;
        let trama = Trama {
            tipo: Tipo::Peticion,
            id,
            carga: Peticion {
                analizador,
                datos: datos.to_vec(),
            }
            .codificar(),
        };
        let inicio = Instant::now();
        let Some(vivo) = self.vivo.as_mut() else {
            return Err(FalloAnalisis::NoDisponible("sin trabajador".into()));
        };
        if vivo.peticiones.send(trama).is_err() {
            let motivo = vivo.matar();
            self.vivo = None;
            self.registrar_muerte(motivo.clone());
            return Err(FalloAnalisis::Murio(motivo));
        }

        loop {
            let restante = plazo.saturating_sub(inicio.elapsed());
            let Some(vivo) = self.vivo.as_mut() else {
                return Err(FalloAnalisis::NoDisponible("sin trabajador".into()));
            };
            match vivo.respuestas.recv_timeout(restante) {
                Ok(Ok(t)) if t.id != id => continue, // respuesta tardia de otra peticion
                Ok(Ok(t)) => {
                    let ns = u64::try_from(inicio.elapsed().as_nanos()).unwrap_or(u64::MAX);
                    self.estado.latencia.anotar(ns);
                    return match t.tipo {
                        Tipo::Informe => match Informe::decodificar(&t.carga) {
                            Ok(i) => {
                                self.estado.analisis += 1;
                                Ok(i)
                            }
                            Err(e) => {
                                // Un informe que no se puede leer es un
                                // trabajador que no se comporta: fuera.
                                let m = format!("informe invalido: {e}");
                                let _ = vivo.matar();
                                self.vivo = None;
                                self.registrar_muerte(m.clone());
                                Err(FalloAnalisis::Murio(m))
                            }
                        },
                        Tipo::Fallo => {
                            self.estado.no_pudo += 1;
                            Err(FalloAnalisis::NoPudo(
                                decodificar_fallo(&t.carga).unwrap_or_else(|e| e.to_string()),
                            ))
                        }
                        _ => {
                            let _ = vivo.matar();
                            self.vivo = None;
                            self.registrar_muerte("trama inesperada".into());
                            Err(FalloAnalisis::Murio("trama inesperada".into()))
                        }
                    };
                }
                Ok(Err(_)) | Err(RecvTimeoutError::Disconnected) => {
                    let motivo = vivo.matar();
                    self.vivo = None;
                    self.registrar_muerte(motivo.clone());
                    return Err(FalloAnalisis::Murio(motivo));
                }
                Err(RecvTimeoutError::Timeout) => {
                    let motivo = format!("plazo vencido; {}", vivo.matar());
                    self.vivo = None;
                    self.estado.plazos += 1;
                    self.registrar_muerte(motivo);
                    return Err(FalloAnalisis::Plazo(plazo));
                }
            }
        }
    }
}

impl Drop for Trabajador {
    fn drop(&mut self) {
        if let Some(mut v) = self.vivo.take() {
            let _ = v.matar();
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    const MIB: u64 = 1024 * 1024;

    #[test]
    fn el_techo_bajo_el_servicio_es_el_hueco_entre_pico_y_techo() {
        // Host de 2 GiB: techo 160 MiB, pico 96 MiB -> 64 MiB para el trabajador.
        assert_eq!(
            techo_bajo_el_servicio(Some(160 * MIB), Some(96 * MIB), 256 * MIB),
            64 * MIB
        );
        // Nunca mas que lo configurado.
        assert_eq!(
            techo_bajo_el_servicio(Some(1536 * MIB), Some(1024 * MIB), 256 * MIB),
            256 * MIB
        );
        // Ni menos que el suelo.
        assert_eq!(
            techo_bajo_el_servicio(Some(100 * MIB), Some(95 * MIB), 256 * MIB),
            SUELO_TRABAJADOR
        );
        // Sin techos numericos («max») o incoherentes: el configurado.
        assert_eq!(techo_bajo_el_servicio(None, None, 256 * MIB), 256 * MIB);
        assert_eq!(
            techo_bajo_el_servicio(Some(96 * MIB), Some(160 * MIB), 256 * MIB),
            256 * MIB
        );
    }
}
