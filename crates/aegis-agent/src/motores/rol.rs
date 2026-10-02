//! Anomalia por rol (FASE 5.3 del MP-16): lo que este host hace de costumbre, y
//! lo que hace por primera vez.
//!
//! Un servidor web lanza siempre los mismos hijos y habla siempre con los mismos
//! sitios. El dia que `nginx` lanza `/bin/sh`, o que `postgres` abre una
//! conexion a una red que nunca habia tocado, no hay firma que lo diga, pero el
//! propio host si: no lo habia hecho nunca. Este motor aprende, en una ventana,
//! dos lineas base por host:
//!
//! - los pares (ejecutable, padre) que se lanzan;
//! - los destinos de red de cada ejecutable, por red (/24 en IPv4, /48 en IPv6)
//!   y puerto: la IP exacta cambia con cada CDN y no dice nada.
//!
//! # Tri-estado: lo nuevo no acusa
//!
//! Durante la ventana solo aprende. Despues, lo conocido no dice nada (no es
//! «limpio»: es que no hay nada que añadir), y lo nuevo es una señal
//! **`NoConcluyente`** con la evidencia en la frase. El arbitro no la cuenta
//! para decidir —`Senal::aporta` la descarta—, pero queda en el expediente: si
//! otro motor acusa al mismo proceso, el veredicto la lleva consigo. Lo nuevo es
//! contexto para una acusacion, nunca una acusacion.
//!
//! Lo que no se puede juzgar tampoco acusa ni se calla: un exec cuyo padre no se
//! conoce (el padre arranco antes que el agente y /proc ya no lo tiene) o una
//! conexion de un proceso sin imagen conocida se cuentan y se publican. No van
//! como `SinDatos` por evento: inundarian el arbitro de expedientes mudos, uno
//! por proceso corto, para decir lo mismo que un contador.
//!
//! # Diverso no es nuevo
//!
//! Un padre que en la ventana lanza mas de `diverso_hijos` ejecutables distintos
//! (bash, systemd, cron) o un ejecutable que habla con mas de
//! `diverso_destinos` redes (un navegador) no tiene un rol que aprender: se
//! marca diverso, se suelta su conjunto y lo que haga despues no es «nuevo».
//!
//! # Memoria acotada y persistencia opcional
//!
//! Topes de pares, destinos y procesos seguidos, con lo descartado contado. La
//! linea base se guarda (opcional) en `/var/lib/aegiscore/rol-linea-base.txt`
//! al cerrar la ventana y cada diez minutos si cambio, con escritura atomica y
//! modo 0600; al arrancar se recupera, y el tiempo aprendido se suma: la ventana
//! cuenta tiempo OBSERVADO, no de reloj (un agente parado no aprende).
//!
//! # Nace en solo-auditoria
//!
//! Nunca impone ni acusa. Cuanto ruido da lo nuevo en un host real lo mide la
//! FASE 4 antes de que pese en nada.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use aegis_entidad::{Confianza, Eid, Juicio, Motor as Firma, Senal, Severidad};
use aegis_motor::{Camino, Dictamen, Ficha, Motor, Plazo, Presupuesto, Requisito};

use crate::graph::ProcKey;
use crate::motores::EventoAgente;
use crate::triage::TelemetryEvent;

/// Donde se guarda la linea base en un host instalado (StateDirectory).
pub const RUTA_PERSISTENCIA: &str = "/var/lib/aegiscore/rol-linea-base.txt";
/// Primera linea del fichero: un formato que no se reconoce no se carga.
const CABECERA: &str = "aegis-rol 1";
/// Un fichero mayor que esto no es una linea base de este motor.
const MAX_FICHERO: u64 = 16 * 1024 * 1024;
/// Cada cuanto se guarda la linea base si cambio.
const GUARDAR_CADA_NS: u64 = 600_000_000_000;
/// Cada cuanto se rehace el informe.
const PUBLICAR_CADA_NS: u64 = 10_000_000_000;
/// Techo de memoria declarado.
const TECHO: usize = 12 * 1024 * 1024;
/// Coste aproximado de una entrada, ademas de su texto.
const ENTRADA: usize = 48;
const SEMANA_NS: u64 = 7 * 24 * 3_600_000_000_000;

/// Limites y ventana.
#[derive(Debug, Clone)]
pub struct ConfigRol {
    /// Tiempo observado que dura el aprendizaje.
    pub ventana_ns: u64,
    /// Procesos vivos cuya imagen se recuerda.
    pub max_procesos: usize,
    /// Pares (ejecutable, padre) en la linea base.
    pub max_pares: usize,
    /// Destinos (ejecutable, red y puerto) en la linea base.
    pub max_destinos: usize,
    /// Hijos distintos a partir de los cuales un padre es diverso.
    pub diverso_hijos: usize,
    /// Destinos distintos a partir de los cuales un ejecutable es diverso.
    pub diverso_destinos: usize,
    /// Donde guardar la linea base; `None`, en memoria.
    pub persistencia: Option<PathBuf>,
}

impl ConfigRol {
    /// La del agente instalado: una semana observada, que es lo que tarda en
    /// pasar el cron semanal, y persistencia en el directorio de estado.
    pub fn del_host() -> ConfigRol {
        ConfigRol {
            ventana_ns: SEMANA_NS,
            max_procesos: 32_768,
            max_pares: 16_384,
            max_destinos: 16_384,
            diverso_hijos: 48,
            diverso_destinos: 64,
            persistencia: Some(PathBuf::from(RUTA_PERSISTENCIA)),
        }
    }
}

/// Un conjunto aprendido. Diverso: crecio de mas y ya no sirve para decir que
/// algo es nuevo.
#[derive(Default)]
struct Conjunto {
    miembros: HashSet<Arc<str>>,
    diverso: bool,
}

/// Que paso al anotar algo en una linea base.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Anotado {
    Aprendido,
    Conocido,
    Diverso,
    Nuevo,
    Descartado,
}

#[derive(Default, Debug, Clone, Copy)]
struct Contadores {
    nuevos_pares: u64,
    nuevos_destinos: u64,
    sin_padre: u64,
    sin_imagen: u64,
    descartados: u64,
    procesos_descartados: u64,
}

/// De un pid a la ruta de su ejecutable.
type Resolutor = fn(u32) -> Option<String>;

/// Anomalia por rol.
pub struct MotorRol {
    config: ConfigRol,
    procesos: HashMap<ProcKey, Arc<str>>,
    hijos_por_padre: HashMap<Arc<str>, Conjunto>,
    destinos_por_exe: HashMap<Arc<str>, Conjunto>,
    pares: usize,
    destinos: usize,
    bytes: usize,
    /// Tiempo aprendido en ejecuciones anteriores (de la linea base guardada).
    previo_ns: u64,
    /// Primer instante visto en esta ejecucion.
    inicio_ns: Option<u64>,
    ventana_cerrada: bool,
    guardado_ns: u64,
    publicado_ns: Option<u64>,
    sucio: bool,
    contadores: Contadores,
    persistencia: String,
    informe: Arc<Mutex<Vec<String>>>,
    exe_de: Resolutor,
    exe_del_padre: Resolutor,
}

/// El ejecutable de un pid, por /proc.
fn exe_en_proc(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

/// El ejecutable del PADRE de un pid, por /proc: para los padres que
/// arrancaron antes que el agente y nunca produjeron un exec que ver.
fn exe_del_padre_en_proc(pid: u32) -> Option<String> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // El nombre va entre parentesis y puede contenerlos: se corta en el ultimo.
    let ppid: u32 = stat
        .rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    if ppid == 0 {
        return None;
    }
    exe_en_proc(ppid)
}

/// La red y el puerto de un destino, que es lo que se aprende.
fn clase_destino(d: &[u8; 16], familia: u16, puerto: u16) -> String {
    const AF_INET: u16 = 2;
    let v4 = if familia == AF_INET {
        Some([d[0], d[1], d[2]])
    } else if d[..10].iter().all(|b| *b == 0) && d[10] == 0xff && d[11] == 0xff {
        // IPv4 mapeada en IPv6: es la misma red.
        Some([d[12], d[13], d[14]])
    } else {
        None
    };
    match v4 {
        Some([a, b, c]) => format!("{a}.{b}.{c}.0/24:{puerto}"),
        None => format!(
            "{:x}:{:x}:{:x}::/48:{puerto}",
            u16::from_be_bytes([d[0], d[1]]),
            u16::from_be_bytes([d[2], d[3]]),
            u16::from_be_bytes([d[4], d[5]])
        ),
    }
}

/// Anota `valor` en el conjunto de `clave`.
#[allow(clippy::too_many_arguments)]
fn anotar(
    mapa: &mut HashMap<Arc<str>, Conjunto>,
    clave: &Arc<str>,
    valor: &Arc<str>,
    aprendiendo: bool,
    umbral: usize,
    total: &mut usize,
    tope: usize,
    bytes: &mut usize,
) -> Anotado {
    if let Some(c) = mapa.get(&**clave) {
        if c.diverso {
            return Anotado::Diverso;
        }
        if c.miembros.contains(&**valor) {
            return Anotado::Conocido;
        }
    }
    if *total >= tope {
        return Anotado::Descartado;
    }
    let c = mapa.entry(Arc::clone(clave)).or_insert_with(|| {
        *bytes += clave.len() + ENTRADA;
        Conjunto::default()
    });
    c.miembros.insert(Arc::clone(valor));
    *total += 1;
    *bytes += valor.len() + ENTRADA;
    if !aprendiendo {
        return Anotado::Nuevo;
    }
    if c.miembros.len() > umbral {
        let liberados: usize = c.miembros.iter().map(|m| m.len() + ENTRADA).sum();
        *total -= c.miembros.len();
        *bytes = bytes.saturating_sub(liberados);
        c.miembros = HashSet::new();
        c.diverso = true;
    }
    Anotado::Aprendido
}

/// Un texto que no se puede guardar en una linea separada por tabuladores.
fn guardable(s: &str) -> bool {
    !s.contains('\t') && !s.contains('\n')
}

impl MotorRol {
    /// Con la configuracion dada; recupera la linea base guardada si la hay.
    pub fn nuevo(config: ConfigRol, informe: Arc<Mutex<Vec<String>>>) -> MotorRol {
        MotorRol::con_resolutores(config, informe, exe_en_proc, exe_del_padre_en_proc)
    }

    fn con_resolutores(
        config: ConfigRol,
        informe: Arc<Mutex<Vec<String>>>,
        exe_de: Resolutor,
        exe_del_padre: Resolutor,
    ) -> MotorRol {
        let mut m = MotorRol {
            config,
            procesos: HashMap::new(),
            hijos_por_padre: HashMap::new(),
            destinos_por_exe: HashMap::new(),
            pares: 0,
            destinos: 0,
            bytes: 0,
            previo_ns: 0,
            inicio_ns: None,
            ventana_cerrada: false,
            guardado_ns: 0,
            publicado_ns: None,
            sucio: false,
            contadores: Contadores::default(),
            persistencia: "desactivada".to_string(),
            informe,
            exe_de,
            exe_del_padre,
        };
        if let Some(ruta) = m.config.persistencia.clone() {
            m.persistencia = match m.cargar(&ruta) {
                Ok(true) => format!(
                    "recuperada de {} ({} pares, {} destinos, {} s aprendidos)",
                    ruta.display(),
                    m.pares,
                    m.destinos,
                    m.previo_ns / 1_000_000_000
                ),
                Ok(false) => format!("sin linea base previa en {}", ruta.display()),
                Err(e) => {
                    // Se empieza de cero: una linea base a medias aprenderia
                    // lo que falta como si fuera nuevo.
                    m.vaciar();
                    format!("descartada {}: {e}; se aprende de cero", ruta.display())
                }
            };
        }
        m
    }

    /// Una linea para el registro de arranque.
    pub fn resumen(&self) -> String {
        format!(
            "ventana {} h, {} pares y {} destinos aprendidos, persistencia: {}",
            self.config.ventana_ns / 3_600_000_000_000,
            self.pares,
            self.destinos,
            self.persistencia
        )
    }

    fn vaciar(&mut self) {
        self.hijos_por_padre.clear();
        self.destinos_por_exe.clear();
        self.pares = 0;
        self.destinos = 0;
        self.previo_ns = 0;
        self.bytes = self.procesos.values().map(|v| v.len() + ENTRADA).sum();
    }

    fn aprendido(&self, ahora_ns: u64) -> u64 {
        self.previo_ns
            .saturating_add(self.inicio_ns.map_or(0, |i| ahora_ns.saturating_sub(i)))
    }

    fn aprendiendo(&self, ahora_ns: u64) -> bool {
        self.aprendido(ahora_ns) < self.config.ventana_ns
    }

    fn recordar(&mut self, clave: ProcKey, imagen: Arc<str>) {
        if clave == ProcKey::NONE {
            return;
        }
        let nuevo = imagen.len() + ENTRADA;
        if let Some(v) = self.procesos.get_mut(&clave) {
            self.bytes = self.bytes.saturating_sub(v.len() + ENTRADA) + nuevo;
            *v = imagen;
        } else if self.procesos.len() >= self.config.max_procesos {
            self.contadores.procesos_descartados += 1;
        } else {
            self.bytes += nuevo;
            self.procesos.insert(clave, imagen);
        }
    }

    fn olvidar(&mut self, clave: ProcKey) {
        if let Some(v) = self.procesos.remove(&clave) {
            self.bytes = self.bytes.saturating_sub(v.len() + ENTRADA);
        }
    }

    fn senal(&self, ev: &EventoAgente, porque: String) -> Dictamen {
        Dictamen::Senales(vec![Senal::nueva(
            Firma::Conductual,
            ev.entidad.clone(),
            Juicio::NoConcluyente,
            Severidad::Baja,
            Confianza::BAJA,
            porque,
            ev.evento.ts_ns(),
        )])
    }

    fn horas(&self, ahora_ns: u64) -> u64 {
        self.aprendido(ahora_ns) / 3_600_000_000_000
    }

    fn exec(
        &mut self,
        ev: &EventoAgente,
        actor: ProcKey,
        pid: u32,
        parent: ProcKey,
        imagen: &Arc<str>,
        ts: u64,
    ) -> Dictamen {
        self.recordar(actor, Arc::clone(imagen));
        let conocido = self.procesos.get(&parent).cloned();
        let padre = match conocido {
            Some(p) => Some(p),
            None => (self.exe_del_padre)(pid).map(|p| {
                let p: Arc<str> = Arc::from(p);
                self.recordar(parent, Arc::clone(&p));
                p
            }),
        };
        let Some(padre) = padre else {
            self.contadores.sin_padre += 1;
            return Dictamen::NoAplica;
        };
        let aprendiendo = self.aprendiendo(ts);
        let r = anotar(
            &mut self.hijos_por_padre,
            &padre,
            imagen,
            aprendiendo,
            self.config.diverso_hijos,
            &mut self.pares,
            self.config.max_pares,
            &mut self.bytes,
        );
        match r {
            Anotado::Aprendido => {
                self.sucio = true;
                Dictamen::NoAplica
            }
            Anotado::Conocido | Anotado::Diverso => Dictamen::NoAplica,
            Anotado::Descartado => {
                self.contadores.descartados += 1;
                Dictamen::NoAplica
            }
            Anotado::Nuevo => {
                self.sucio = true;
                self.contadores.nuevos_pares += 1;
                let hijos = self
                    .hijos_por_padre
                    .get(&*padre)
                    .map_or(0, |c| c.miembros.len().saturating_sub(1));
                self.senal(
                    ev,
                    format!(
                        "rol: {imagen} lanzado por {padre}, par nuevo en este host tras {} h de \
                         linea base ({hijos} hijo(s) conocido(s) de ese padre); no acusa solo: \
                         queda como evidencia si otro motor acusa",
                        self.horas(ts)
                    ),
                )
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn conexion(
        &mut self,
        ev: &EventoAgente,
        actor: ProcKey,
        pid: u32,
        daddr: &[u8; 16],
        family: u16,
        dport: u16,
        ts: u64,
    ) -> Dictamen {
        let conocido = self.procesos.get(&actor).cloned();
        let exe = match conocido {
            Some(e) => e,
            None => match (self.exe_de)(pid) {
                Some(e) => {
                    let e: Arc<str> = Arc::from(e);
                    self.recordar(actor, Arc::clone(&e));
                    e
                }
                None => {
                    self.contadores.sin_imagen += 1;
                    return Dictamen::NoAplica;
                }
            },
        };
        let destino: Arc<str> = Arc::from(clase_destino(daddr, family, dport));
        let aprendiendo = self.aprendiendo(ts);
        let r = anotar(
            &mut self.destinos_por_exe,
            &exe,
            &destino,
            aprendiendo,
            self.config.diverso_destinos,
            &mut self.destinos,
            self.config.max_destinos,
            &mut self.bytes,
        );
        match r {
            Anotado::Aprendido => {
                self.sucio = true;
                Dictamen::NoAplica
            }
            Anotado::Conocido | Anotado::Diverso => Dictamen::NoAplica,
            Anotado::Descartado => {
                self.contadores.descartados += 1;
                Dictamen::NoAplica
            }
            Anotado::Nuevo => {
                self.sucio = true;
                self.contadores.nuevos_destinos += 1;
                let conocidos = self
                    .destinos_por_exe
                    .get(&*exe)
                    .map_or(0, |c| c.miembros.len().saturating_sub(1));
                self.senal(
                    ev,
                    format!(
                        "rol: {exe} conecta a {destino}, destino nuevo para ese ejecutable tras \
                         {} h de linea base ({conocidos} destino(s) conocido(s)); no acusa solo: \
                         queda como evidencia si otro motor acusa",
                        self.horas(ts)
                    ),
                )
            }
        }
    }

    fn serializar(&self, ahora_ns: u64) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "{CABECERA}");
        let _ = writeln!(s, "aprendido_ns\t{}", self.aprendido(ahora_ns));
        for (etiqueta, etiqueta_div, mapa) in [
            ("par", "padre_diverso", &self.hijos_por_padre),
            ("destino", "destino_diverso", &self.destinos_por_exe),
        ] {
            // Orden estable: el mismo estado da el mismo fichero.
            let mut claves: Vec<&Arc<str>> = mapa.keys().collect();
            claves.sort();
            for clave in claves {
                if !guardable(clave) {
                    continue;
                }
                let c = &mapa[clave];
                if c.diverso {
                    let _ = writeln!(s, "{etiqueta_div}\t{clave}");
                    continue;
                }
                let mut miembros: Vec<&Arc<str>> = c.miembros.iter().collect();
                miembros.sort();
                for m in miembros {
                    if guardable(m) {
                        let _ = writeln!(s, "{etiqueta}\t{clave}\t{m}");
                    }
                }
            }
        }
        s
    }

    fn guardar(&mut self, ahora_ns: u64) {
        let Some(ruta) = self.config.persistencia.clone() else {
            return;
        };
        self.guardado_ns = ahora_ns;
        let texto = self.serializar(ahora_ns);
        match escribir_atomico(&ruta, &texto) {
            Ok(()) => {
                self.sucio = false;
                self.persistencia = format!("guardada en {}", ruta.display());
            }
            Err(e) => {
                self.persistencia = format!("no se pudo guardar en {}: {e}", ruta.display());
            }
        }
    }

    /// `Ok(false)` si no hay fichero; `Err` si lo hay y no vale.
    fn cargar(&mut self, ruta: &Path) -> Result<bool, String> {
        let meta = match std::fs::metadata(ruta) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(e.to_string()),
        };
        if meta.len() > MAX_FICHERO {
            return Err(format!("{} bytes, mas de {MAX_FICHERO}", meta.len()));
        }
        let texto = std::fs::read_to_string(ruta).map_err(|e| e.to_string())?;
        let mut lineas = texto.lines();
        if lineas.next() != Some(CABECERA) {
            return Err(format!("cabecera desconocida (se esperaba «{CABECERA}»)"));
        }
        for (i, l) in lineas.enumerate() {
            let n = i + 2;
            let campos: Vec<&str> = l.split('\t').collect();
            match campos.as_slice() {
                ["aprendido_ns", v] => {
                    self.previo_ns = v
                        .parse()
                        .map_err(|_| format!("linea {n}: aprendido_ns ininteligible"))?;
                }
                ["par", padre, hijo] => self.cargar_entrada(true, padre, Some(*hijo)),
                ["padre_diverso", padre] => self.cargar_entrada(true, padre, None),
                ["destino", exe, destino] => self.cargar_entrada(false, exe, Some(*destino)),
                ["destino_diverso", exe] => self.cargar_entrada(false, exe, None),
                _ => return Err(format!("linea {n} ininteligible")),
            }
        }
        Ok(true)
    }

    fn cargar_entrada(&mut self, de_pares: bool, clave: &str, valor: Option<&str>) {
        let (mapa, total, tope) = if de_pares {
            (
                &mut self.hijos_por_padre,
                &mut self.pares,
                self.config.max_pares,
            )
        } else {
            (
                &mut self.destinos_por_exe,
                &mut self.destinos,
                self.config.max_destinos,
            )
        };
        let clave: Arc<str> = Arc::from(clave);
        match valor {
            None => {
                let c = mapa.entry(clave).or_default();
                *total -= c.miembros.len();
                c.miembros.clear();
                c.diverso = true;
            }
            Some(v) => {
                if *total >= tope {
                    self.contadores.descartados += 1;
                    return;
                }
                let largo = clave.len() + v.len() + 2 * ENTRADA;
                let c = mapa.entry(clave).or_default();
                if !c.diverso && c.miembros.insert(Arc::from(v)) {
                    *total += 1;
                    self.bytes += largo;
                }
            }
        }
    }

    fn publicar(&self, ahora_ns: u64) {
        let fase = if self.aprendiendo(ahora_ns) {
            format!(
                "aprendiendo (quedan {} h)",
                self.config
                    .ventana_ns
                    .saturating_sub(self.aprendido(ahora_ns))
                    / 3_600_000_000_000
            )
        } else {
            "vigilando".to_string()
        };
        let diversos = |m: &HashMap<Arc<str>, Conjunto>| m.values().filter(|c| c.diverso).count();
        let c = &self.contadores;
        let lineas = vec![
            format!(
                "rol: fase={fase} aprendido_h={} pares={} padres={} ({} diversos) destinos={} \
                 ejecutables={} ({} diversos) nuevos_pares={} nuevos_destinos={} sin_padre={} \
                 sin_imagen={} descartados={} procesos={} procesos_descartados={} memoria={}",
                self.horas(ahora_ns),
                self.pares,
                self.hijos_por_padre.len(),
                diversos(&self.hijos_por_padre),
                self.destinos,
                self.destinos_por_exe.len(),
                diversos(&self.destinos_por_exe),
                c.nuevos_pares,
                c.nuevos_destinos,
                c.sin_padre,
                c.sin_imagen,
                c.descartados,
                self.procesos.len(),
                c.procesos_descartados,
                self.bytes
            ),
            format!("rol: persistencia: {}", self.persistencia),
        ];
        if let Ok(mut g) = self.informe.lock() {
            *g = lineas;
        }
    }
}

/// Escribe en un temporal y lo renombra: un corte a mitad deja el fichero
/// viejo entero, nunca uno a medias.
fn escribir_atomico(ruta: &Path, texto: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    let tmp = ruta.with_extension("tmp");
    let mut o = std::fs::OpenOptions::new();
    o.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(&tmp)?;
    f.write_all(texto.as_bytes())?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, ruta)
}

impl Motor<EventoAgente> for MotorRol {
    fn ficha(&self) -> Ficha {
        Ficha {
            nombre: "rol",
            firma: Firma::Conductual,
            camino: Camino::Caliente,
            // Dos busquedas en tablas hash; /proc solo la primera vez que se ve
            // un padre o un proceso sin exec conocido.
            presupuesto: Presupuesto::caliente(60, TECHO),
            requisitos: &[Requisito::TelemetriaKernel],
        }
    }

    fn evaluar(&mut self, ev: &EventoAgente, _plazo: &Plazo) -> Dictamen {
        let ts = ev.evento.ts_ns();
        if self.inicio_ns.is_none() {
            self.inicio_ns = Some(ts);
        }
        match &ev.evento {
            TelemetryEvent::Exec {
                actor,
                pid,
                parent,
                image,
                ..
            } => self.exec(ev, *actor, *pid, *parent, image, ts),
            TelemetryEvent::NetConnect {
                actor,
                pid,
                daddr,
                dport,
                family,
                loopback,
                ..
            } => {
                if *loopback {
                    return Dictamen::NoAplica;
                }
                self.conexion(ev, *actor, *pid, daddr, *family, *dport, ts)
            }
            TelemetryEvent::Exit { actor, .. } => {
                self.olvidar(*actor);
                Dictamen::NoAplica
            }
            _ => Dictamen::NoAplica,
        }
    }

    fn mantener(&mut self, ahora_ns: u64) -> Vec<(Eid, Dictamen)> {
        if self.inicio_ns.is_none() {
            self.inicio_ns = Some(ahora_ns);
        }
        let cierra = !self.ventana_cerrada && !self.aprendiendo(ahora_ns);
        if cierra {
            self.ventana_cerrada = true;
            self.sucio = true;
        }
        if self.sucio && (cierra || ahora_ns.saturating_sub(self.guardado_ns) >= GUARDAR_CADA_NS) {
            self.guardar(ahora_ns);
        }
        if cierra
            || self
                .publicado_ns
                .is_none_or(|t| ahora_ns.saturating_sub(t) >= PUBLICAR_CADA_NS)
        {
            self.publicado_ns = Some(ahora_ns);
            self.publicar(ahora_ns);
        }
        Vec::new()
    }

    fn memoria(&self) -> usize {
        self.bytes
    }

    fn aligerar(&mut self) {
        // Primero lo que se puede rehacer desde /proc: las imagenes de los
        // procesos vivos.
        let libres: usize = self.procesos.values().map(|v| v.len() + ENTRADA).sum();
        self.procesos.clear();
        self.bytes = self.bytes.saturating_sub(libres);
        if self.bytes <= TECHO / 2 {
            return;
        }
        // Despues, los conjuntos mas grandes pasan a diversos: se pierde poder
        // decir «nuevo» de ellos, no la vista del resto.
        for (mapa, total) in [
            (&mut self.hijos_por_padre, &mut self.pares),
            (&mut self.destinos_por_exe, &mut self.destinos),
        ] {
            for c in mapa.values_mut() {
                if c.miembros.len() > 16 {
                    let libres: usize = c.miembros.iter().map(|m| m.len() + ENTRADA).sum();
                    *total -= c.miembros.len();
                    self.bytes = self.bytes.saturating_sub(libres);
                    c.miembros = HashSet::new();
                    c.diverso = true;
                }
            }
        }
        self.sucio = true;
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::motores::Identidad;
    use aegis_motor::{Arbitro, ConfigArbitro, Host};

    const S: u64 = 1_000_000_000;
    const VENTANA: u64 = 60 * S;

    fn ninguno(_: u32) -> Option<String> {
        None
    }

    fn config(persistencia: Option<PathBuf>) -> ConfigRol {
        ConfigRol {
            ventana_ns: VENTANA,
            max_procesos: 1024,
            max_pares: 1024,
            max_destinos: 1024,
            diverso_hijos: 8,
            diverso_destinos: 8,
            persistencia,
        }
    }

    fn motor_con(c: ConfigRol) -> (MotorRol, Arc<Mutex<Vec<String>>>) {
        let informe: Arc<Mutex<Vec<String>>> = Arc::default();
        let m = MotorRol::con_resolutores(c, Arc::clone(&informe), ninguno, ninguno);
        (m, informe)
    }

    fn exec(clave: u64, padre: u64, imagen: &str, ts: u64) -> EventoAgente {
        EventoAgente::nuevo(
            TelemetryEvent::Exec {
                actor: ProcKey(clave),
                pid: clave as u32,
                parent: ProcKey(padre),
                image: Arc::from(imagen),
                cmdline: Arc::from(imagen),
                started_ns: ts,
                ts_ns: ts,
            },
            &Identidad::fija("m"),
        )
    }

    fn connect(clave: u64, ip: [u8; 4], puerto: u16, ts: u64) -> EventoAgente {
        let mut daddr = [0u8; 16];
        daddr[..4].copy_from_slice(&ip);
        EventoAgente::nuevo(
            TelemetryEvent::NetConnect {
                actor: ProcKey(clave),
                pid: clave as u32,
                daddr,
                dport: puerto,
                family: 2,
                loopback: false,
                private_dst: false,
                ts_ns: ts,
            },
            &Identidad::fija("m"),
        )
    }

    fn plazo() -> Plazo {
        Plazo::desde_ahora(std::time::Duration::from_secs(1))
    }

    fn porque(d: &Dictamen) -> String {
        match d {
            Dictamen::Senales(s) => {
                assert_eq!(s.len(), 1);
                assert_eq!(s[0].juicio, Juicio::NoConcluyente, "lo nuevo nunca acusa");
                assert!(!s[0].aporta());
                s[0].porque.clone()
            }
            otro => panic!("se esperaba una señal: {otro:?}"),
        }
    }

    /// nginx (clave 100) arranca, con un padre que el agente no conoce, y
    /// lanza su trabajador durante la ventana.
    fn nginx_aprendido(m: &mut MotorRol) {
        assert_eq!(
            m.evaluar(&exec(100, 1, "/usr/sbin/nginx", S), &plazo()),
            Dictamen::NoAplica
        );
        assert_eq!(
            m.evaluar(&exec(101, 100, "/usr/sbin/nginx", 2 * S), &plazo()),
            Dictamen::NoAplica
        );
    }

    #[test]
    fn lo_nuevo_tras_la_ventana_es_no_concluyente_con_evidencia_y_una_sola_vez() {
        let (mut m, informe) = motor_con(config(None));
        nginx_aprendido(&mut m);
        assert_eq!(m.contadores.sin_padre, 1, "el padre de nginx no se conoce");
        // En la ventana, un hijo distinto se aprende sin decir nada.
        assert_eq!(
            m.evaluar(&exec(102, 100, "/usr/bin/logrotate", 3 * S), &plazo()),
            Dictamen::NoAplica
        );

        let t = S + VENTANA + S;
        assert_eq!(
            m.evaluar(&exec(103, 100, "/usr/sbin/nginx", t), &plazo()),
            Dictamen::NoAplica,
            "lo conocido no dice nada"
        );
        let d = m.evaluar(&exec(104, 100, "/bin/sh", t + S), &plazo());
        let p = porque(&d);
        assert!(p.contains("/bin/sh lanzado por /usr/sbin/nginx"), "{p}");
        assert!(p.contains("2 hijo(s) conocido(s)"), "{p}");
        assert_eq!(
            m.evaluar(&exec(105, 100, "/bin/sh", t + 2 * S), &plazo()),
            Dictamen::NoAplica,
            "lo nuevo se dice una vez"
        );
        assert_eq!(m.contadores.nuevos_pares, 1);

        let _ = m.mantener(t + 3 * S);
        let g = informe.lock().unwrap().clone();
        assert!(g[0].contains("fase=vigilando"), "{g:?}");
        assert!(g[0].contains("nuevos_pares=1"), "{g:?}");
        assert!(g[1].contains("desactivada"), "{g:?}");
    }

    #[test]
    fn un_padre_diverso_en_la_ventana_no_hace_nuevo_a_ningun_hijo() {
        let (mut m, _) = motor_con(config(None));
        let _ = m.evaluar(&exec(200, 1, "/bin/bash", S), &plazo());
        for i in 0..9u64 {
            let _ = m.evaluar(
                &exec(300 + i, 200, &format!("/usr/bin/h{i}"), 2 * S),
                &plazo(),
            );
        }
        assert!(m.hijos_por_padre["/bin/bash"].diverso);
        assert_eq!(m.pares, 0, "un conjunto diverso se suelta");
        let d = m.evaluar(&exec(400, 200, "/tmp/x", S + VENTANA + S), &plazo());
        assert_eq!(d, Dictamen::NoAplica);
    }

    #[test]
    fn los_destinos_se_aprenden_por_red_y_puerto() {
        let (mut m, _) = motor_con(config(None));
        let _ = m.evaluar(&exec(500, 1, "/usr/bin/curl", S), &plazo());
        let _ = m.evaluar(&connect(500, [203, 0, 113, 9], 443, 2 * S), &plazo());
        let t = S + VENTANA + S;
        assert_eq!(
            m.evaluar(&connect(500, [203, 0, 113, 77], 443, t), &plazo()),
            Dictamen::NoAplica,
            "la misma /24 y el mismo puerto"
        );
        let p = porque(&m.evaluar(&connect(500, [198, 51, 100, 1], 443, t), &plazo()));
        assert!(
            p.contains("/usr/bin/curl conecta a 198.51.100.0/24:443"),
            "{p}"
        );
        let p = porque(&m.evaluar(&connect(500, [203, 0, 113, 9], 4444, t), &plazo()));
        assert!(p.contains("203.0.113.0/24:4444"), "{p}");
        // Un proceso sin imagen conocida no se juzga: se cuenta.
        assert_eq!(
            m.evaluar(&connect(999, [198, 51, 100, 1], 22, t), &plazo()),
            Dictamen::NoAplica
        );
        assert_eq!(m.contadores.sin_imagen, 1);
        // Al morir se olvida su imagen.
        let fin = EventoAgente::nuevo(
            TelemetryEvent::Exit {
                actor: ProcKey(500),
                ts_ns: t,
            },
            &Identidad::fija("m"),
        );
        let _ = m.evaluar(&fin, &plazo());
        assert!(!m.procesos.contains_key(&ProcKey(500)));
    }

    #[test]
    fn la_ipv4_mapeada_es_la_misma_red() {
        let mut d = [0u8; 16];
        d[10] = 0xff;
        d[11] = 0xff;
        d[12..].copy_from_slice(&[203, 0, 113, 9]);
        assert_eq!(clase_destino(&d, 10, 443), "203.0.113.0/24:443");
        let mut v6 = [0u8; 16];
        v6[..6].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01]);
        assert_eq!(clase_destino(&v6, 10, 80), "2001:db8:1::/48:80");
    }

    #[test]
    fn los_topes_se_respetan_y_se_cuentan() {
        let mut c = config(None);
        c.max_pares = 4;
        c.diverso_hijos = 100;
        c.max_procesos = 3;
        let (mut m, _) = motor_con(c);
        let _ = m.evaluar(&exec(600, 1, "/usr/sbin/cron", S), &plazo());
        for i in 0..10u64 {
            let _ = m.evaluar(
                &exec(700 + i, 600, &format!("/usr/bin/t{i}"), 2 * S),
                &plazo(),
            );
        }
        assert_eq!(m.pares, 4);
        assert_eq!(m.contadores.descartados, 6);
        assert_eq!(m.procesos.len(), 3);
        assert!(m.contadores.procesos_descartados > 0);
        assert!(m.memoria() > 0);
    }

    #[test]
    fn la_linea_base_persiste_y_se_recupera() {
        let dir = std::env::temp_dir().join(format!("aegis-rol-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ruta = dir.join("rol-linea-base.txt");

        let (mut m, _) = motor_con(config(Some(ruta.clone())));
        nginx_aprendido(&mut m);
        let _ = m.evaluar(&exec(102, 100, "/usr/bin/curl", 3 * S), &plazo());
        let _ = m.evaluar(&connect(102, [192, 0, 2, 1], 443, 3 * S), &plazo());
        assert!(!ruta.exists(), "no se guarda a cada evento");
        let _ = m.mantener(S + VENTANA);
        let texto = std::fs::read_to_string(&ruta).unwrap();
        assert!(texto.starts_with(CABECERA), "{texto}");
        assert!(
            texto.contains("par\t/usr/sbin/nginx\t/usr/bin/curl"),
            "{texto}"
        );
        assert!(
            texto.contains("destino\t/usr/bin/curl\t192.0.2.0/24:443"),
            "{texto}"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let modo = std::fs::metadata(&ruta).unwrap().permissions().mode() & 0o777;
            assert_eq!(modo, 0o600);
        }

        // Otro arranque: la ventana ya esta cumplida y lo aprendido vale.
        let (mut m2, _) = motor_con(config(Some(ruta.clone())));
        assert!(
            m2.persistencia.contains("recuperada"),
            "{}",
            m2.persistencia
        );
        assert!(!m2.aprendiendo(5 * S));
        let _ = m2.evaluar(&exec(100, 1, "/usr/sbin/nginx", 5 * S), &plazo());
        assert_eq!(
            m2.evaluar(&exec(101, 100, "/usr/bin/curl", 6 * S), &plazo()),
            Dictamen::NoAplica
        );
        let p = porque(&m2.evaluar(&exec(103, 100, "/bin/sh", 7 * S), &plazo()));
        assert!(p.contains("/bin/sh"), "{p}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn una_linea_base_corrupta_se_descarta_diciendolo() {
        let dir = std::env::temp_dir().join(format!("aegis-rol-corrupta-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ruta = dir.join("rol-linea-base.txt");
        std::fs::write(
            &ruta,
            format!("{CABECERA}\naprendido_ns\t999999999999999\nbasura\n"),
        )
        .unwrap();
        let (mut m, informe) = motor_con(config(Some(ruta)));
        assert!(m.persistencia.contains("descartada"), "{}", m.persistencia);
        assert!(
            m.aprendiendo(S),
            "se aprende de cero, sin el tiempo de la corrupta"
        );
        let _ = m.mantener(S);
        assert!(informe.lock().unwrap()[1].contains("descartada"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    struct TodoVale;
    impl Host for TodoVale {
        fn ofrece(&self, _: Requisito) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn el_arbitro_no_emite_veredicto_por_una_novedad_sola() {
        let mut a: Arbitro<EventoAgente> = Arbitro::nuevo(ConfigArbitro::default());
        let informe: Arc<Mutex<Vec<String>>> = Arc::default();
        a.registrar(
            Box::new(MotorRol::con_resolutores(
                config(None),
                informe,
                ninguno,
                ninguno,
            )),
            &TodoVale,
        )
        .unwrap();
        assert!(a.procesar(&exec(100, 1, "/usr/sbin/nginx", S)).is_none());
        assert!(a
            .procesar(&exec(101, 100, "/usr/sbin/nginx", 2 * S))
            .is_none());
        assert!(a
            .procesar(&exec(104, 100, "/bin/sh", S + VENTANA + S))
            .is_none());
        let rol = a.estado().into_iter().find(|e| e.nombre == "rol").unwrap();
        assert_eq!(rol.senales, 1, "la novedad llega al arbitro como evidencia");
    }
}
