//! Autodiagnostico para soporte: `aegis-agent --diagnostico [--json]`.
//!
//! # Para que
//!
//! En un piloto, la primera pregunta de soporte es siempre la misma: «que le
//! pasa a este equipo». Responderla pidiendo cinco comandos, tres ficheros y el
//! diario de systemd cuesta un dia por incidencia y llega incompleto. Esta orden
//! reune en un solo informe, legible o en JSON, lo que soporte necesita:
//!
//! - version del binario, version del paquete y HUELLA del arbol con el que se
//!   construyo (el fichero que graban `tools/ci/hermetico.sh` y el paquete junto
//!   al binario), y el SHA-256 del binario en ejecucion;
//! - capacidades del kernel y degradaciones, con su efecto y su remedio;
//! - estado de cada motor con su ultimo motivo de «sin datos», y los motores que
//!   no se registraron y por que;
//! - el trabajador confinado: si arranco, con que confinamiento, y sus muertes;
//! - perdidas de eventos del kernel por familia;
//! - presupuesto de memoria aplicado (cgroup del servicio y drop-in) y uso;
//! - conexion al plano de control (configuracion y, si el agente lo enlaza, el
//!   estado del enlace);
//! - los ultimos veredictos.
//!
//! # Como, sin parar al agente
//!
//! Esta orden NO arranca el agente: es otro proceso. Lo estatico (version,
//! capacidades, ficheros) lo lee ella misma; lo vivo se lo pregunta al agente en
//! marcha por su canal de control (`status`), cuyo detalle ya trae las lineas del
//! ultimo informe periodico, mas lo que este modulo anota en el arranque y en
//! cada veredicto ([`anotar_arranque`], [`anotar_veredicto`]). Si el agente no
//! responde, el informe lo dice y sigue con lo que si puede ver: un diagnostico
//! que solo funciona cuando todo va bien no diagnostica nada.
//!
//! # Sin datos sensibles, por construccion
//!
//! Ningun texto llega a la salida sin pasar por [`Redaccion`]: el arbol del
//! informe ([`Valor`]) solo admite texto como [`Texto`], y `Texto` solo se
//! construye con [`Redaccion::limpiar`]. Es la misma idea que `Limpio` en
//! `aegis-captura`, cuyo redactor se usa aqui para las credenciales en claro. A
//! eso se suma lo propio de un diagnostico: el nombre del equipo, las rutas de
//! usuario, los correos y las direcciones IPv4. Lo que se tapa se cuenta y se
//! publica en el propio informe (seccion `redaccion`).
//!
//! Lo que NO tapa, dicho: argumentos de linea de ordenes con forma propia
//! (`-pSECRETO`), direcciones IPv6 y nombres de otros equipos. Por eso el informe
//! no copia lineas de ordenes ni rutas de ficheros analizados mas que dentro de
//! los motivos que dan los motores, y estos van recortados.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use aegis_ctl::redaccion::{nombre_del_host, Cuentas, Redaccion, Texto};

use crate::capacidades::{plan_degradacion, salida_maquina, Capacidades};

/// Version del formato del informe. Cambia si cambia el significado de un campo.
pub const FORMATO: &str = "aegis-diagnostico/1";
/// Nombre, en la boveda de cadenas del agente (`aegis-harden`), del socket de
/// control por defecto: el que pasa la unidad del paquete.
///
/// La ruta viaja CIFRADA en el binario. Una copia en claro aqui la delataria a
/// cualquier `strings` del ejecutable, que es justo lo que el escenario 1 del
/// Red Team comprueba.
pub const CADENA_SOCKET: &str = "ipc_socket_path";
/// Latido por defecto (el que vigila `aegis-watchdog`).
pub const LATIDO_POR_DEFECTO: &str = "/run/aegiscore/agent.heartbeat";
/// Marca de parada autorizada: si existe, el watchdog no relanza al agente.
pub const MARCA_PARADA: &str = "/run/aegiscore/agent.shutdown";
/// Cgroup del servicio del paquete.
pub const CGROUP_SERVICIO: &str = "/sys/fs/cgroup/system.slice/aegis-agent.service";
/// Drop-in con el techo de memoria de este host (lo escribe el paquete).
pub const DROPIN_PRESUPUESTO: &str =
    "/etc/systemd/system/aegis-agent.service.d/10-presupuesto.conf";
/// Configuracion del enlace con el plano de control (H-23): la misma ruta que
/// lee el agente.
pub const CONFIG_PLANO: &str = crate::plano::CONFIG_POR_DEFECTO;
/// Veredictos que se recuerdan para el diagnostico.
pub const MAX_VEREDICTOS: usize = 16;
/// Lineas de arranque que se recuerdan.
pub const MAX_ARRANQUE: usize = 64;
/// Edad a partir de la cual el latido se da por viejo (la del watchdog).
pub const LATIDO_VIEJO_S: u64 = 15;

const USO: &str = "uso: aegis-agent --diagnostico [--json] [--control-socket RUTA] [--latido RUTA]";

/// La redaccion compartida por las anotaciones del agente en marcha.
fn redaccion_global() -> &'static Redaccion {
    static R: OnceLock<Redaccion> = OnceLock::new();
    R.get_or_init(Redaccion::del_host)
}

/// Lo que va entre comillas angulares no puede cerrarlas: se cambia `»`.
fn sin_comillas(s: &str) -> String {
    s.replace('»', "\"").replace(['\n', '\r'], " ")
}

// ── Anotaciones del agente en marcha ────────────────────────────────────────

struct Anotado {
    cuando: Instant,
    linea: String,
}

static VEREDICTOS: Mutex<VecDeque<Anotado>> = Mutex::new(VecDeque::new());
static ARRANQUE: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Recuerda un hecho del arranque (trabajador, motor no registrado) para el
/// diagnostico. Ya redactado. Barato y sin panico: un cerrojo envenenado se
/// ignora.
pub fn anotar_arranque(linea: impl AsRef<str>) {
    let limpia =
        redaccion_global().redactar(&sin_comillas(linea.as_ref()), &mut Cuentas::default());
    if let Ok(mut g) = ARRANQUE.lock() {
        if g.len() < MAX_ARRANQUE {
            g.push(limpia);
        }
    }
}

/// Recuerda un veredicto para el diagnostico: solo los [`MAX_VEREDICTOS`]
/// ultimos, y ya redactados. Se llama una vez por veredicto emitido, que solo
/// ocurre cuando el de una entidad cambia: no esta en el camino de cada evento.
pub fn anotar_veredicto(v: &aegis_entidad::Veredicto) {
    let r = redaccion_global();
    let mut c = Cuentas::default();
    let senales: Vec<String> = v
        .senales
        .iter()
        .map(|s| format!("{}/{}", s.motor.nombre(), s.severidad.nombre()))
        .collect();
    let porque = r.redactar(&sin_comillas(&v.porque), &mut c);
    let linea = linea_veredicto(
        &v.entidad.texto(),
        v.resultado.nombre(),
        v.severidad.nombre(),
        &v.confianza.to_string(),
        v.planos.len(),
        &senales.join("; "),
        &porque,
    );
    if let Ok(mut g) = VEREDICTOS.lock() {
        if g.len() >= MAX_VEREDICTOS {
            g.pop_front();
        }
        g.push_back(Anotado {
            cuando: Instant::now(),
            linea,
        });
    }
}

/// La linea de un veredicto, sin la edad (que se calcula al pedirla).
fn linea_veredicto(
    entidad: &str,
    resultado: &str,
    severidad: &str,
    confianza: &str,
    planos: usize,
    senales: &str,
    porque: &str,
) -> String {
    format!(
        "entidad={} resultado={} severidad={} confianza=«{}» planos={planos} senales=«{}» porque=«{}»",
        sin_comillas(entidad).replace(' ', "_"),
        resultado,
        severidad,
        sin_comillas(confianza),
        sin_comillas(senales),
        sin_comillas(porque)
    )
}

/// Las lineas que el agente en marcha añade al detalle de `status`: el
/// arranque y los ultimos veredictos, del mas reciente al mas antiguo.
#[must_use]
pub fn lineas_registradas() -> Vec<String> {
    let mut v: Vec<String> = ARRANQUE
        .lock()
        .map(|g| g.iter().map(|l| format!("arranque: {l}")).collect())
        .unwrap_or_default();
    if let Ok(g) = VEREDICTOS.lock() {
        for a in g.iter().rev() {
            v.push(format!(
                "veredicto: hace_s={} {}",
                a.cuando.elapsed().as_secs(),
                a.linea
            ));
        }
    }
    v
}

// ── El arbol del informe ────────────────────────────────────────────────────

/// Un valor del informe. El texto solo entra como [`Texto`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Valor {
    /// No hay dato.
    Nulo,
    /// Si o no.
    Bool(bool),
    /// Un numero.
    Num(u64),
    /// Texto ya redactado.
    Texto(Texto),
    /// Una lista.
    Lista(Vec<Valor>),
    /// Un objeto.
    Objeto(Objeto),
}

/// Un objeto con claves en orden. Las claves solo admiten `[a-z0-9_]`: lo
/// demas se sustituye, para que ningun texto libre llegue como clave.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Objeto(Vec<(String, Valor)>);

impl Objeto {
    /// Objeto vacio.
    #[must_use]
    pub fn nuevo() -> Objeto {
        Objeto::default()
    }

    /// Añade un campo.
    pub fn poner(&mut self, k: &str, v: Valor) {
        self.0.push((clave(k), v));
    }

    /// Añade un campo y devuelve el objeto.
    #[must_use]
    pub fn con(mut self, k: &str, v: Valor) -> Objeto {
        self.poner(k, v);
        self
    }

    /// El valor de un campo.
    #[must_use]
    pub fn obtener(&self, k: &str) -> Option<&Valor> {
        self.0.iter().find(|(c, _)| c == k).map(|(_, v)| v)
    }

    /// Los campos, en orden.
    #[must_use]
    pub fn campos(&self) -> &[(String, Valor)] {
        &self.0
    }

    /// Si no tiene campos.
    #[must_use]
    pub fn vacio(&self) -> bool {
        self.0.is_empty()
    }
}

/// Clave saneada: minusculas, cifras y `_`.
fn clave(k: &str) -> String {
    let s: String = k
        .chars()
        .take(64)
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    if s.is_empty() {
        "_".into()
    } else {
        s
    }
}

/// Una clave leida de una linea solo se acepta si ya es una clave valida.
fn clave_valida(k: &str) -> bool {
    !k.is_empty()
        && k.len() <= 48
        && k.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// Numero, si o no, «-» como nulo, o texto redactado.
fn tipar(v: &str, r: &mut Redaccion) -> Valor {
    if let Ok(n) = v.parse::<u64>() {
        return Valor::Num(n);
    }
    match v {
        "true" => Valor::Bool(true),
        "false" => Valor::Bool(false),
        "-" | "" => Valor::Nulo,
        _ => Valor::Texto(r.limpiar(v)),
    }
}

// ── Lectura de las lineas del informe del agente ────────────────────────────

/// Los pares `clave=valor` de una linea. Un valor puede ir entre «» o entre
/// llaves (`{..}` del `Debug` de un mapa), y `ultimo_error` llega hasta el final
/// de la linea. Lo que no es `clave=valor` se ignora.
fn pares(linea: &str) -> Vec<(String, String)> {
    let cs: Vec<(usize, char)> = linea.char_indices().collect();
    let byte = |j: usize| cs.get(j).map_or(linea.len(), |c| c.0);
    let mut out = Vec::new();
    let mut i = 0;
    while i < cs.len() {
        if cs[i].1.is_whitespace() {
            i += 1;
            continue;
        }
        let ini = i;
        while i < cs.len() && cs[i].1 != '=' && !cs[i].1.is_whitespace() {
            i += 1;
        }
        if i >= cs.len() || cs[i].1 != '=' {
            continue;
        }
        let k = linea[byte(ini)..byte(i)].trim_start_matches('(').to_owned();
        i += 1;
        let (v, sig) = match cs.get(i).map(|c| c.1) {
            Some('«') => {
                let mut j = i + 1;
                while j < cs.len() && cs[j].1 != '»' {
                    j += 1;
                }
                (
                    linea[byte(i + 1)..byte(j)].to_owned(),
                    (j + 1).min(cs.len()),
                )
            }
            Some('{') => {
                let mut j = i;
                let mut prof = 0i32;
                while j < cs.len() {
                    match cs[j].1 {
                        '{' => prof += 1,
                        '}' => prof -= 1,
                        _ => {}
                    }
                    j += 1;
                    if prof == 0 {
                        break;
                    }
                }
                (linea[byte(i)..byte(j)].to_owned(), j)
            }
            _ if k == "ultimo_error" => (linea[byte(i)..].trim_end().to_owned(), cs.len()),
            _ => {
                let mut j = i;
                while j < cs.len() && !cs[j].1.is_whitespace() {
                    j += 1;
                }
                (linea[byte(i)..byte(j)].trim_end_matches(')').to_owned(), j)
            }
        };
        i = sig;
        if clave_valida(&k) {
            out.push((k, v));
        }
    }
    out
}

/// Los pares de una linea, tipados y redactados.
fn objeto_de(linea: &str, r: &mut Redaccion) -> Objeto {
    let mut o = Objeto::nuevo();
    for (k, v) in pares(linea) {
        let val = tipar(&v, r);
        o.poner(&k, val);
    }
    o
}

/// `exec=3,red=2` o `ninguna`.
fn por_familia(v: &str) -> Objeto {
    let mut o = Objeto::nuevo();
    if v == "ninguna" || v.is_empty() {
        return o;
    }
    for parte in v.split(',') {
        if let Some((f, n)) = parte.split_once('=') {
            if clave_valida(f) {
                if let Ok(n) = n.parse::<u64>() {
                    o.poner(f, Valor::Num(n));
                }
            }
        }
    }
    o
}

/// Lo que el agente en marcha cuenta de si mismo, ya clasificado.
#[derive(Debug, Default)]
struct Vivo {
    pipeline: Objeto,
    arbitro: Objeto,
    motores: Vec<Valor>,
    trabajador: Objeto,
    kernel: Objeto,
    perdidas: Objeto,
    plano: Option<Objeto>,
    veredictos: Vec<Valor>,
    otros: Vec<Valor>,
    avisos: Vec<String>,
}

/// Clasifica las lineas de detalle de `status`.
fn clasificar(lineas: &[String], r: &mut Redaccion) -> Vivo {
    let mut v = Vivo::default();
    for l in lineas {
        if let Some(resto) = l.strip_prefix("pipeline:") {
            v.pipeline = objeto_de(resto, r);
        } else if let Some(resto) = l.strip_prefix("arbitro:") {
            v.arbitro = objeto_de(resto, r);
        } else if let Some(resto) = l.strip_prefix("kernel:") {
            v.kernel = objeto_de(resto, r);
            if let Some((_, fam)) = pares(resto)
                .into_iter()
                .find(|(k, _)| k == "perdidas_por_familia")
            {
                v.perdidas = por_familia(&fam);
            }
            if let Some(Valor::Num(n)) = v.kernel.obtener("perdidos") {
                if *n > 0 {
                    v.avisos.push(format!(
                        "el kernel perdio {n} eventos por ring lleno: punto ciego de deteccion"
                    ));
                }
            }
        } else if let Some(resto) = l.strip_prefix("trabajador:") {
            let o = objeto_de(resto, r);
            for (k, val) in o.campos() {
                v.trabajador.poner(k, val.clone());
            }
        } else if let Some(resto) = l.strip_prefix("plano de control:") {
            let o = objeto_de(resto, r);
            if o.obtener("conectado") == Some(&Valor::Bool(false)) {
                v.avisos
                    .push("el enlace con el plano de control esta desconectado".into());
            }
            if o.obtener("cuadra") == Some(&Valor::Bool(false)) {
                v.avisos
                    .push("las cuentas del enlace con el plano de control no cuadran".into());
            }
            v.plano = Some(o);
        } else if let Some(resto) = l.strip_prefix("motor ") {
            let Some((nombre, campos)) = resto.split_once(':') else {
                v.otros.push(Valor::Texto(r.limpiar(l)));
                continue;
            };
            let mut o = Objeto::nuevo()
                .con("nombre", Valor::Texto(r.limpiar(nombre.trim())))
                .con("registrado", Valor::Bool(true));
            for (k, val) in objeto_de(campos, r).campos() {
                o.poner(k, val.clone());
            }
            if let Some(Valor::Texto(t)) = o.obtener("ultimo_sin_datos") {
                v.avisos.push(format!(
                    "motor {}: sin datos alguna vez; ultimo motivo: {}",
                    nombre.trim(),
                    t.como_str()
                ));
            }
            v.motores.push(Valor::Objeto(o));
        } else if let Some(resto) = l.strip_prefix("arranque: ") {
            clasificar_arranque(resto, &mut v, r);
        } else if let Some(resto) = l.strip_prefix("veredicto:") {
            v.veredictos.push(Valor::Objeto(objeto_de(resto, r)));
        } else {
            v.otros.push(Valor::Texto(r.limpiar(l)));
        }
    }
    v
}

fn clasificar_arranque(resto: &str, v: &mut Vivo, r: &mut Redaccion) {
    if let Some(t) = resto.strip_prefix("trabajador: ") {
        let disponible = !t.starts_with("NO disponible");
        v.trabajador.poner("disponible", Valor::Bool(disponible));
        v.trabajador
            .poner("al_arrancar", Valor::Texto(r.limpiar(t)));
        if !disponible {
            v.avisos.push(
                "el trabajador confinado no arranco: los motores que lo necesitan no analizan"
                    .into(),
            );
        }
    } else if let Some(t) = resto.strip_prefix("motor ") {
        // «motor NOMBRE DEGRADADO: requisito=R motivo=«M»»
        let (nombre, campos) = t.split_once(" DEGRADADO:").unwrap_or((t, ""));
        let mut o = Objeto::nuevo()
            .con("nombre", Valor::Texto(r.limpiar(nombre.trim())))
            .con("registrado", Valor::Bool(false));
        for (k, val) in objeto_de(campos, r).campos() {
            o.poner(k, val.clone());
        }
        v.avisos.push(format!(
            "motor {} no registrado en este host",
            nombre.trim()
        ));
        v.motores.push(Valor::Objeto(o));
    } else {
        v.otros.push(Valor::Texto(r.limpiar(resto)));
    }
}

// ── Lo que se recoge (sin redactar todavia) ─────────────────────────────────

/// Una degradacion del plan, en texto.
#[derive(Debug, Clone, Default)]
pub struct DegradacionVista {
    /// Capacidad que falta.
    pub capacidad: String,
    /// Que se pierde.
    pub efecto: String,
    /// Como se remedia.
    pub remedio: String,
    /// Familias de eventos afectadas.
    pub familias: Vec<String>,
    /// Si deja al agente sin telemetria de kernel.
    pub bloquea_telemetria: bool,
}

/// La configuracion del plano de control, vista desde fuera del agente.
#[derive(Debug, Clone, Default)]
pub struct PlanoVisto {
    /// Ruta del fichero.
    pub ruta: String,
    /// Error al leerlo, si lo hubo.
    pub error: Option<String>,
    /// `servidor = ...`.
    pub servidor: Option<String>,
    /// `(clave, ruta, modo)` de `ca`, `certificado` y `clave`. Nunca el contenido.
    pub ficheros: Vec<(String, String, Option<u32>)>,
}

/// Todo lo que el diagnostico lee, antes de redactar. Separado de la lectura
/// para poder probar el formato y la redaccion sin un sistema real.
#[derive(Debug, Clone)]
pub struct Entradas {
    /// Segundos Unix al generar.
    pub generado_unix: u64,
    /// Seudonimo estable del equipo (no su nombre).
    pub seudonimo: Option<String>,
    /// Version del crate.
    pub version: String,
    /// Contenido de VERSION junto al binario (la del paquete).
    pub version_paquete: Option<String>,
    /// Contenido de HUELLA junto al binario.
    pub huella_arbol: Option<String>,
    /// Ruta del binario.
    pub binario: Option<String>,
    /// SHA-256 del binario.
    pub sha256_binario: Result<String, String>,
    /// Pares `AEGIS-CAP` del kernel.
    pub capacidades: Vec<(String, String)>,
    /// El plan de degradacion.
    pub degradaciones: Vec<DegradacionVista>,
    /// Ruta del latido.
    pub latido_ruta: String,
    /// Edad del latido en segundos, o por que no se sabe.
    pub latido: Result<u64, String>,
    /// Si existe la marca de parada autorizada.
    pub marca_parada: bool,
    /// Socket de control consultado.
    pub socket: String,
    /// Respuesta de `status`, o por que no la hubo.
    pub estado: Result<aegis_ctl::StatusInfo, String>,
    /// Ficheros del cgroup del servicio: (nombre, contenido).
    pub cgroup: Vec<(String, String)>,
    /// Drop-in del presupuesto, si existe.
    pub dropin: Option<String>,
    /// Configuracion del plano de control, si existe el fichero.
    pub plano: Option<PlanoVisto>,
}

// ── Composicion del informe ─────────────────────────────────────────────────

/// Compone el informe redactado. Todo texto pasa por `r`.
pub fn componer(e: &Entradas, r: &mut Redaccion) -> Valor {
    let mut avisos: Vec<String> = Vec::new();

    // Agente (binario).
    let mut agente = Objeto::nuevo().con("version", Valor::Texto(r.limpiar(&e.version)));
    agente.poner(
        "version_paquete",
        texto_o_nulo(e.version_paquete.as_deref(), r),
    );
    agente.poner("huella_arbol", texto_o_nulo(e.huella_arbol.as_deref(), r));
    agente.poner("binario", texto_o_nulo(e.binario.as_deref(), r));
    match &e.sha256_binario {
        Ok(h) => agente.poner("sha256_binario", Valor::Texto(r.limpiar(h))),
        Err(m) => {
            agente.poner("sha256_binario", Valor::Nulo);
            agente.poner("sha256_error", Valor::Texto(r.limpiar(m)));
        }
    }
    if e.huella_arbol.is_none() {
        avisos.push("no hay fichero HUELLA junto al binario: no se sabe de que arbol salio".into());
    }

    // Kernel.
    let mut caps = Objeto::nuevo();
    for (k, v) in &e.capacidades {
        caps.poner(k, Valor::Texto(r.limpiar(v)));
    }
    let mut degs = Vec::new();
    for d in &e.degradaciones {
        if d.bloquea_telemetria {
            avisos.push(format!("sin telemetria de kernel: falta {}", d.capacidad));
        }
        degs.push(Valor::Objeto(
            Objeto::nuevo()
                .con("capacidad", Valor::Texto(r.limpiar(&d.capacidad)))
                .con("efecto", Valor::Texto(r.limpiar(&d.efecto)))
                .con("remedio", Valor::Texto(r.limpiar(&d.remedio)))
                .con(
                    "familias",
                    Valor::Lista(
                        d.familias
                            .iter()
                            .map(|f| Valor::Texto(r.limpiar(f)))
                            .collect(),
                    ),
                )
                .con("bloquea_telemetria", Valor::Bool(d.bloquea_telemetria)),
        ));
    }
    let kernel = Objeto::nuevo()
        .con("capacidades", Valor::Objeto(caps))
        .con("degradaciones", Valor::Lista(degs));

    // Servicio.
    let mut latido = Objeto::nuevo().con("ruta", Valor::Texto(r.limpiar(&e.latido_ruta)));
    match &e.latido {
        Ok(s) => {
            latido.poner("edad_s", Valor::Num(*s));
            if *s > LATIDO_VIEJO_S {
                avisos.push(format!(
                    "el latido tiene {s} s (el watchdog reinicia pasados {LATIDO_VIEJO_S}): agente colgado o parado"
                ));
            }
        }
        Err(m) => {
            latido.poner("edad_s", Valor::Nulo);
            latido.poner("error", Valor::Texto(r.limpiar(m)));
            avisos.push("no hay latido: el agente no esta en marcha o no puede escribirlo".into());
        }
    }
    if e.marca_parada {
        avisos.push(format!(
            "existe {MARCA_PARADA}: el watchdog NO relanzara al agente (parada autorizada o manipulacion, H-31)"
        ));
    }
    let mut servicio = Objeto::nuevo()
        .con("latido", Valor::Objeto(latido))
        .con("marca_parada", Valor::Bool(e.marca_parada))
        .con("socket", Valor::Texto(r.limpiar(&e.socket)))
        .con("responde", Valor::Bool(e.estado.is_ok()));
    let (en_marcha, vivo) = match &e.estado {
        Ok(s) => {
            let o = Objeto::nuevo()
                .con("estado", Valor::Texto(r.limpiar(&s.state)))
                .con("rss_kb", Valor::Num(s.rss_kb))
                .con("en_marcha_s", Valor::Num(s.uptime_s))
                .con("eventos_recibidos", Valor::Num(s.events_received))
                .con("eventos_escalados", Valor::Num(s.events_escalated));
            (Valor::Objeto(o), clasificar(&s.detalle, r))
        }
        Err(m) => {
            servicio.poner("error", Valor::Texto(r.limpiar(m)));
            avisos.push(
                "el agente no responde por su canal de control: lo vivo (motores, perdidas, veredictos) no esta en este informe"
                    .into(),
            );
            (Valor::Nulo, Vivo::default())
        }
    };
    avisos.extend(vivo.avisos.iter().cloned());

    // Memoria.
    let mut cg = Objeto::nuevo();
    for (f, contenido) in &e.cgroup {
        let k = f.trim_start_matches("memory.");
        if k == "events" {
            let mut ev = Objeto::nuevo();
            for l in contenido.lines() {
                if let Some((n, c)) = l.split_once(' ') {
                    if clave_valida(n) {
                        if let Ok(c) = c.trim().parse::<u64>() {
                            ev.poner(n, Valor::Num(c));
                            if (n == "oom_kill" || n == "oom") && c > 0 {
                                avisos.push(format!(
                                    "el cgroup del servicio registra {n}={c}: el techo de memoria mato procesos"
                                ));
                            }
                        }
                    }
                }
            }
            cg.poner("events", Valor::Objeto(ev));
        } else {
            cg.poner(k, tipar(contenido.trim(), r));
        }
    }
    let mut dropin = Objeto::nuevo();
    if let Some(d) = &e.dropin {
        for l in d.lines() {
            for k in ["MemoryHigh", "MemoryMax", "MemorySwapMax"] {
                if let Some(v) = l.strip_prefix(k).and_then(|x| x.strip_prefix('=')) {
                    dropin.poner(&k.to_lowercase(), tipar(v.trim(), r));
                }
            }
        }
    } else {
        avisos.push(
            "no hay drop-in de presupuesto: el servicio corre sin techo de memoria calculado"
                .into(),
        );
    }
    let mut memoria = Objeto::nuevo();
    memoria.poner(
        "rss_kb_agente",
        match &e.estado {
            Ok(s) => Valor::Num(s.rss_kb),
            Err(_) => Valor::Nulo,
        },
    );
    memoria.poner("cgroup_servicio", Valor::Objeto(cg));
    memoria.poner(
        "presupuesto_dropin",
        if e.dropin.is_some() {
            Valor::Objeto(dropin)
        } else {
            Valor::Nulo
        },
    );

    // Plano de control.
    let mut config = Objeto::nuevo().con("ruta", Valor::Texto(r.limpiar(CONFIG_PLANO)));
    match &e.plano {
        None => config.poner("existe", Valor::Bool(false)),
        Some(p) => {
            config.poner("existe", Valor::Bool(true));
            if let Some(m) = &p.error {
                config.poner("error", Valor::Texto(r.limpiar(m)));
                avisos.push(
                    "la configuracion del plano de control no se puede leer o no es valida: el \
                     agente no enlaza (plano_control.configuracion.error dice por que)"
                        .into(),
                );
            }
            config.poner("servidor", texto_o_nulo(p.servidor.as_deref(), r));
            let mut fs = Vec::new();
            for (k, ruta, modo) in &p.ficheros {
                let modo_txt = modo.map(|m| format!("{m:04o}"));
                // La misma regla que el enlace (aegis-fleet, EmisorFichero): una
                // clave que pueda leer alguien mas que su dueno se rechaza.
                if k == "clave" && modo.is_some_and(|m| m & 0o077 != 0) {
                    avisos.push(
                        "la clave del agente la puede leer alguien mas que root (tiene que ser \
                         0600): el enlace la rechazara"
                            .into(),
                    );
                }
                if modo.is_none() {
                    avisos.push(format!(
                        "la configuracion del plano cita un fichero «{k}» que no existe"
                    ));
                }
                fs.push(Valor::Objeto(
                    Objeto::nuevo()
                        .con("clave", Valor::Texto(r.limpiar(k)))
                        .con("ruta", Valor::Texto(r.limpiar(ruta)))
                        .con("modo", texto_o_nulo(modo_txt.as_deref(), r)),
                ));
            }
            config.poner("ficheros", Valor::Lista(fs));
            if p.error.is_none() && e.estado.is_ok() && vivo.plano.is_none() {
                avisos.push(
                    "la configuracion del plano de control es valida pero el agente no publica \
                     su enlace: no lo pudo arrancar (journalctl -u aegis-agent, «plano de \
                     control») o aun no ha emitido su primer informe"
                        .into(),
                );
            }
        }
    }
    let plano = Objeto::nuevo()
        .con("configuracion", Valor::Objeto(config))
        .con(
            "enlace",
            vivo.plano.clone().map_or(Valor::Nulo, Valor::Objeto),
        );

    let perdidas = Objeto::nuevo()
        .con("kernel", Valor::Objeto(vivo.kernel.clone()))
        .con("por_familia", Valor::Objeto(vivo.perdidas.clone()));

    // El resumen va arriba, pero se calcula al final.
    let resumen = Objeto::nuevo()
        .con(
            "estado",
            Valor::Texto(r.limpiar(if avisos.is_empty() {
                "sano"
            } else {
                "atencion"
            })),
        )
        .con(
            "avisos",
            Valor::Lista(avisos.iter().map(|a| Valor::Texto(r.limpiar(a))).collect()),
        );

    let mut raiz = Objeto::nuevo()
        .con("formato", Valor::Texto(r.limpiar(FORMATO)))
        .con("generado_unix", Valor::Num(e.generado_unix))
        .con("seudonimo_equipo", texto_o_nulo(e.seudonimo.as_deref(), r))
        .con("resumen", Valor::Objeto(resumen))
        .con("agente", Valor::Objeto(agente))
        .con("kernel", Valor::Objeto(kernel))
        .con("servicio", Valor::Objeto(servicio))
        .con("agente_en_ejecucion", en_marcha)
        .con("motores", Valor::Lista(vivo.motores))
        .con("trabajador", Valor::Objeto(vivo.trabajador))
        .con("perdidas", Valor::Objeto(perdidas))
        .con("memoria", Valor::Objeto(memoria))
        .con("plano_control", Valor::Objeto(plano))
        .con("arbitro", Valor::Objeto(vivo.arbitro))
        .con("pipeline", Valor::Objeto(vivo.pipeline))
        .con("ultimos_veredictos", Valor::Lista(vivo.veredictos))
        .con("otros", Valor::Lista(vivo.otros));
    let c = r.cuentas();
    raiz.poner(
        "redaccion",
        Valor::Objeto(
            Objeto::nuevo()
                .con("credenciales", Valor::Num(c.credenciales))
                .con("rutas_de_usuario", Valor::Num(c.rutas_de_usuario))
                .con("correos", Valor::Num(c.correos))
                .con("direcciones_ipv4", Valor::Num(c.direcciones))
                .con("nombre_de_equipo", Valor::Num(c.anfitrion))
                .con("recortes", Valor::Num(c.recortes)),
        ),
    );
    Valor::Objeto(raiz)
}

fn texto_o_nulo(s: Option<&str>, r: &mut Redaccion) -> Valor {
    s.map_or(Valor::Nulo, |t| Valor::Texto(r.limpiar(t)))
}

// ── Salida ──────────────────────────────────────────────────────────────────

/// JSON con sangria de dos espacios y un salto de linea final.
#[must_use]
pub fn a_json(v: &Valor) -> String {
    let mut s = String::new();
    json(v, 0, &mut s);
    s.push('\n');
    s
}

fn json(v: &Valor, nivel: usize, s: &mut String) {
    let sangria = |n: usize| "  ".repeat(n);
    match v {
        Valor::Nulo => s.push_str("null"),
        Valor::Bool(b) => s.push_str(if *b { "true" } else { "false" }),
        Valor::Num(n) => {
            let _ = write!(s, "{n}");
        }
        Valor::Texto(t) => cadena_json(t.como_str(), s),
        Valor::Lista(l) => {
            if l.is_empty() {
                s.push_str("[]");
                return;
            }
            s.push_str("[\n");
            for (i, x) in l.iter().enumerate() {
                s.push_str(&sangria(nivel + 1));
                json(x, nivel + 1, s);
                s.push_str(if i + 1 < l.len() { ",\n" } else { "\n" });
            }
            s.push_str(&sangria(nivel));
            s.push(']');
        }
        Valor::Objeto(o) => {
            if o.vacio() {
                s.push_str("{}");
                return;
            }
            s.push_str("{\n");
            for (i, (k, x)) in o.campos().iter().enumerate() {
                s.push_str(&sangria(nivel + 1));
                cadena_json(&clave(k), s);
                s.push_str(": ");
                json(x, nivel + 1, s);
                s.push_str(if i + 1 < o.campos().len() {
                    ",\n"
                } else {
                    "\n"
                });
            }
            s.push_str(&sangria(nivel));
            s.push('}');
        }
    }
}

fn cadena_json(t: &str, s: &mut String) {
    s.push('"');
    for c in t.chars() {
        match c {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            '\n' => s.push_str("\\n"),
            '\r' => s.push_str("\\r"),
            '\t' => s.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(s, "\\u{:04x}", c as u32);
            }
            c => s.push(c),
        }
    }
    s.push('"');
}

/// El informe legible: una seccion por campo de primer nivel.
#[must_use]
pub fn a_texto(v: &Valor) -> String {
    let mut s = String::from("AegisCore · autodiagnostico\n");
    let Valor::Objeto(raiz) = v else {
        texto(v, 0, &mut s);
        return s;
    };
    for (k, x) in raiz.campos() {
        match x {
            Valor::Objeto(_) | Valor::Lista(_) => {
                let _ = writeln!(s, "\n== {k} ==");
                texto(x, 1, &mut s);
            }
            _ => {
                let _ = write!(s, "{k}: ");
                escalar(x, &mut s);
                s.push('\n');
            }
        }
    }
    s
}

fn escalar(v: &Valor, s: &mut String) {
    match v {
        Valor::Nulo => s.push('-'),
        Valor::Bool(b) => s.push_str(if *b { "si" } else { "no" }),
        Valor::Num(n) => {
            let _ = write!(s, "{n}");
        }
        Valor::Texto(t) => s.push_str(&t.como_str().replace(['\n', '\r'], " ")),
        Valor::Lista(_) | Valor::Objeto(_) => {}
    }
}

fn texto(v: &Valor, nivel: usize, s: &mut String) {
    let sangria = "  ".repeat(nivel);
    match v {
        Valor::Objeto(o) => {
            if o.vacio() {
                let _ = writeln!(s, "{sangria}(nada)");
            }
            for (k, x) in o.campos() {
                match x {
                    Valor::Objeto(_) | Valor::Lista(_) => {
                        let _ = writeln!(s, "{sangria}{k}:");
                        texto(x, nivel + 1, s);
                    }
                    _ => {
                        let _ = write!(s, "{sangria}{k}: ");
                        escalar(x, s);
                        s.push('\n');
                    }
                }
            }
        }
        Valor::Lista(l) => {
            if l.is_empty() {
                let _ = writeln!(s, "{sangria}(nada)");
            }
            for x in l {
                match x {
                    Valor::Objeto(_) | Valor::Lista(_) => {
                        let _ = writeln!(s, "{sangria}-");
                        texto(x, nivel + 1, s);
                    }
                    _ => {
                        let _ = write!(s, "{sangria}- ");
                        escalar(x, s);
                        s.push('\n');
                    }
                }
            }
        }
        _ => {
            s.push_str(&sangria);
            escalar(v, s);
            s.push('\n');
        }
    }
}

// ── La orden ────────────────────────────────────────────────────────────────

/// Opciones de `--diagnostico`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpcionesDiagnostico {
    /// Salida en JSON.
    pub json: bool,
    /// Socket de control del agente en marcha.
    pub socket: String,
    /// Latido que se mira.
    pub latido: PathBuf,
}

/// El socket de control por defecto, descifrado de la boveda del agente.
///
/// Si la boveda no se abre es un fallo de integridad del binario: no hay ruta de
/// reserva en claro, y el error pide `--control-socket`.
pub fn socket_por_defecto() -> Result<String, String> {
    let boveda = aegis_harden::unseal_builtin().map_err(|e| {
        format!("no se descifra la ruta del socket de control ({e}); pasa --control-socket")
    })?;
    boveda
        .get(CADENA_SOCKET)
        .map(str::to_owned)
        .ok_or_else(|| format!("la boveda no trae «{CADENA_SOCKET}»; pasa --control-socket"))
}

/// Interpreta lo que sigue a `--diagnostico`, y rechaza lo que no conoce.
pub fn analizar_opciones(args: &[String]) -> Result<OpcionesDiagnostico, String> {
    let mut socket = None;
    let mut o = OpcionesDiagnostico {
        json: false,
        socket: String::new(),
        latido: LATIDO_POR_DEFECTO.into(),
    };
    let mut i = 0;
    while i < args.len() {
        let valor = |i: usize| {
            args.get(i + 1)
                .cloned()
                .ok_or_else(|| format!("{} necesita un valor", args[i]))
        };
        match args[i].as_str() {
            "--json" => {
                o.json = true;
                i += 1;
            }
            "--control-socket" => {
                socket = Some(valor(i)?);
                i += 2;
            }
            "--latido" => {
                o.latido = valor(i)?.into();
                i += 2;
            }
            otra => return Err(format!("opcion desconocida: {otra}")),
        }
    }
    // La boveda solo se abre si hace falta: con --control-socket no se toca.
    o.socket = match socket {
        Some(s) => s,
        None => socket_por_defecto()?,
    };
    Ok(o)
}

/// `aegis-agent --diagnostico ...`: recoge, redacta e imprime. Sale con 0 si
/// pudo escribir el informe (aunque el informe diga que hay problemas: ese es
/// su trabajo), 2 si las opciones no valen y 1 si no pudo escribir.
pub fn orden(args: &[String], capacidades: impl FnOnce() -> Capacidades) -> std::process::ExitCode {
    use std::io::Write as _;
    let o = match analizar_opciones(args) {
        Ok(o) => o,
        Err(m) => {
            eprintln!("aegis-agent --diagnostico: {m}\n{USO}");
            return std::process::ExitCode::from(2);
        }
    };
    let entradas = recoger(&o, &capacidades());
    let mut r = Redaccion::del_host();
    let informe = componer(&entradas, &mut r);
    let salida = if o.json {
        a_json(&informe)
    } else {
        a_texto(&informe)
    };
    let mut out = std::io::stdout().lock();
    if out
        .write_all(salida.as_bytes())
        .and_then(|()| out.flush())
        .is_err()
    {
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}

// ── Lectura del sistema ─────────────────────────────────────────────────────

fn leer_corto(ruta: &Path) -> Option<String> {
    let t = std::fs::read_to_string(ruta).ok()?;
    let t = t.lines().next().unwrap_or("").trim().to_owned();
    (!t.is_empty()).then_some(t)
}

/// Seudonimo estable del equipo: BLAKE3 de su machine-id (o de su nombre) con
/// separacion de dominio, recortado. Sirve para juntar los informes de un mismo
/// equipo sin escribir su nombre; NO es anonimo frente a quien ya conoce el
/// machine-id.
fn seudonimo() -> Option<String> {
    let base = leer_corto(Path::new("/etc/machine-id")).or_else(nombre_del_host)?;
    let h = blake3::hash(format!("{FORMATO}\0{base}").as_bytes());
    Some(format!("equipo-{}", &h.to_hex().as_str()[..12]))
}

fn sha256_de(ruta: &Path) -> Result<String, String> {
    use sha2::Digest as _;
    use std::io::Read as _;
    let error = |e: std::io::Error| format!("{}: {e}", ruta.display());
    let mut f = std::fs::File::open(ruta).map_err(error)?;
    let mut h = sha2::Sha256::new();
    let mut trozo = [0u8; 64 * 1024];
    loop {
        match f.read(&mut trozo) {
            Ok(0) => break,
            Ok(n) => h.update(&trozo[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(error(e)),
        }
    }
    Ok(format!("{:x}", h.finalize()))
}

#[cfg(unix)]
fn modo_de(ruta: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(ruta)
        .ok()
        .map(|m| m.permissions().mode() & 0o7777)
}

#[cfg(not(unix))]
fn modo_de(ruta: &Path) -> Option<u32> {
    std::fs::metadata(ruta).ok().map(|_| 0)
}

/// Lee `plano-control.toml` con el MISMO analizador estricto que el agente
/// ([`crate::plano::analizar`]): si el agente lo rechaza al arrancar, el
/// diagnostico dice por que. Del fichero solo salen el servidor y que ficheros
/// cita, con su modo; nunca el contenido de la clave ni del certificado.
fn leer_plano(ruta: &Path) -> Option<PlanoVisto> {
    let mut p = PlanoVisto {
        ruta: ruta.display().to_string(),
        ..PlanoVisto::default()
    };
    let texto = match std::fs::read_to_string(ruta) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => {
            p.error = Some(e.to_string());
            return Some(p);
        }
    };
    match crate::plano::analizar(&texto) {
        Ok(cfg) => {
            p.servidor = Some(cfg.servidor);
            for (k, f) in [
                ("ca", cfg.ca),
                ("certificado", cfg.certificado),
                ("clave", cfg.clave),
            ] {
                let modo = modo_de(&f);
                p.ficheros
                    .push((k.to_owned(), f.display().to_string(), modo));
            }
            return Some(p);
        }
        // Rechazado: se dice por que, y se sigue con una lectura tolerante
        // para que soporte vea al menos que servidor y que ficheros cita.
        Err(m) => p.error = Some(m),
    }
    for linea in texto.lines() {
        let l = linea.split('#').next().unwrap_or("").trim();
        let Some((k, v)) = l.split_once('=') else {
            continue;
        };
        let k = k.trim();
        let v = v.trim().trim_matches('"').to_owned();
        match k {
            "servidor" => p.servidor = Some(v),
            "ca" | "certificado" | "clave" => {
                let modo = modo_de(Path::new(&v));
                p.ficheros.push((k.to_owned(), v, modo));
            }
            _ => {}
        }
    }
    Some(p)
}

fn edad_s(ruta: &Path) -> Result<u64, String> {
    let m = std::fs::metadata(ruta)
        .and_then(|m| m.modified())
        .map_err(|e| format!("{}: {e}", ruta.display()))?;
    Ok(SystemTime::now()
        .duration_since(m)
        .map(|d| d.as_secs())
        .unwrap_or(0))
}

/// Recoge todo lo que el informe necesita.
#[must_use]
pub fn recoger(o: &OpcionesDiagnostico, caps: &Capacidades) -> Entradas {
    let plan = plan_degradacion(caps);
    let capacidades = salida_maquina(caps, &plan)
        .lines()
        .filter_map(|l| {
            let mut it = l.split('|');
            (it.next() == Some("AEGIS-CAP")).then_some(())?;
            Some((it.next()?.to_owned(), it.collect::<Vec<_>>().join("|")))
        })
        .collect();
    let degradaciones = plan
        .iter()
        .map(|d| DegradacionVista {
            capacidad: d.capacidad.to_owned(),
            efecto: d.efecto.clone(),
            remedio: d.remedio.to_owned(),
            familias: d.familias.iter().map(|f| f.nombre().to_owned()).collect(),
            bloquea_telemetria: d.bloquea_telemetria,
        })
        .collect();

    let exe = std::env::current_exe().ok();
    let dir = exe.as_deref().and_then(Path::parent);
    let estado = match aegis_ctl::ControlClient::request(&o.socket, &aegis_ctl::Request::Status) {
        Ok(aegis_ctl::Response::Status(s)) => Ok(s),
        Ok(aegis_ctl::Response::Error(m)) => Err(format!("el agente respondio con error: {m}")),
        Ok(_) => Err("respuesta inesperada a status".to_owned()),
        Err(e) => Err(format!("{}: {e}", o.socket)),
    };
    let cgroup = [
        "memory.max",
        "memory.high",
        "memory.current",
        "memory.peak",
        "memory.events",
    ]
    .iter()
    .filter_map(|f| {
        std::fs::read_to_string(Path::new(CGROUP_SERVICIO).join(f))
            .ok()
            .map(|c| ((*f).to_owned(), c))
    })
    .collect();

    Entradas {
        generado_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        seudonimo: seudonimo(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        version_paquete: dir.and_then(|d| leer_corto(&d.join("VERSION"))),
        huella_arbol: dir.and_then(|d| leer_corto(&d.join("HUELLA"))),
        binario: exe.as_ref().map(|p| p.display().to_string()),
        sha256_binario: exe.as_deref().map_or_else(
            || Err("ruta del ejecutable desconocida".to_owned()),
            sha256_de,
        ),
        capacidades,
        degradaciones,
        latido_ruta: o.latido.display().to_string(),
        latido: edad_s(&o.latido),
        marca_parada: Path::new(MARCA_PARADA).exists(),
        socket: o.socket.clone(),
        estado,
        cgroup,
        dropin: std::fs::read_to_string(DROPIN_PRESUPUESTO).ok(),
        plano: leer_plano(Path::new(CONFIG_PLANO)),
    }
}

// ── Pruebas ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Validador minimo de JSON (RFC 8259) para no depender de serde_json en
    /// el agente. Devuelve el resto sin consumir.
    fn valor_json(s: &[u8], mut i: usize) -> Option<usize> {
        let blanco = |s: &[u8], mut i: usize| {
            while i < s.len() && matches!(s[i], b' ' | b'\n' | b'\r' | b'\t') {
                i += 1;
            }
            i
        };
        i = blanco(s, i);
        match *s.get(i)? {
            b'{' => {
                i = blanco(s, i + 1);
                if s.get(i) == Some(&b'}') {
                    return Some(i + 1);
                }
                loop {
                    i = blanco(s, i);
                    if s.get(i) != Some(&b'"') {
                        return None;
                    }
                    i = cadena(s, i)?;
                    i = blanco(s, i);
                    if s.get(i) != Some(&b':') {
                        return None;
                    }
                    i = valor_json(s, i + 1)?;
                    i = blanco(s, i);
                    match s.get(i)? {
                        b',' => i += 1,
                        b'}' => return Some(i + 1),
                        _ => return None,
                    }
                }
            }
            b'[' => {
                i = blanco(s, i + 1);
                if s.get(i) == Some(&b']') {
                    return Some(i + 1);
                }
                loop {
                    i = valor_json(s, i)?;
                    i = blanco(s, i);
                    match s.get(i)? {
                        b',' => i += 1,
                        b']' => return Some(i + 1),
                        _ => return None,
                    }
                }
            }
            b'"' => cadena(s, i),
            b't' => s[i..].starts_with(b"true").then_some(i + 4),
            b'f' => s[i..].starts_with(b"false").then_some(i + 5),
            b'n' => s[i..].starts_with(b"null").then_some(i + 4),
            b'0'..=b'9' => {
                while i < s.len() && s[i].is_ascii_digit() {
                    i += 1;
                }
                Some(i)
            }
            _ => None,
        }
    }

    fn cadena(s: &[u8], mut i: usize) -> Option<usize> {
        i += 1;
        while i < s.len() {
            match s[i] {
                b'"' => return Some(i + 1),
                b'\\' => i += 2,
                c if c < 0x20 => return None,
                _ => i += 1,
            }
        }
        None
    }

    fn json_valido(t: &str) -> bool {
        let b = t.as_bytes();
        valor_json(b, 0).is_some_and(|fin| b[fin..].iter().all(u8::is_ascii_whitespace))
    }

    const EQUIPO: &str = "pc-contabilidad-07";

    fn entradas_de_prueba() -> Entradas {
        let detalle = vec![
            "pipeline: recibidos=120 descartados=100 registrados=15 escalados=5 malformados=0 desconocidos=0 | nodos=40 ptrace_sesiones=0".to_owned(),
            "arbitro: eventos=120 p50_ns=800 p99_ns=5000 max_ns=9000 veredictos=2 expedientes=3 expulsados=0".to_owned(),
            "motor triaje: camino=caliente evaluaciones=120 senales=2 p99_ns=900 excesos=0 suspensiones=0 sin_datos={} memoria=4096".to_owned(),
            "motor memoria: camino=frio evaluaciones=4 senales=0 p99_ns=70000 excesos=0 suspensiones=0 sin_datos={\"proc-ilegible\": 2} memoria=0 ultimo_sin_datos=«no se pudo leer /home/ana/.cache/x: permiso denegado»".to_owned(),
            "trabajador: arranques=1 muertes=0 por_memoria=0 plazos=0 analisis=3 no_pudo=0 enfriamientos=0 p99_ns=40000 | analista: encargos=3 aciertos=3 ilegibles=0 enormes=0 perdidos=0 ultimo_ilegible=-".to_owned(),
            "kernel: emitidos=500 perdidos=7 cedidos=0 perdidas_por_familia=exec=4,red=3".to_owned(),
            "plano de control: conectado=false ofrecidos=3 enviados=1 en_cola=2 bytes_en_cola=900 capacidad=65536 perdidos=0 (tope=0 prioridad=0 memoria=0 enormes=0 servidor=0) reenviados=0 conexiones=1 fallos_conexion=4 latidos=9 comandos_ignorados=0 cuadra=true ultimo_error=conectar a 10.20.30.40:8443: conexion rehusada".to_owned(),
            "arranque: trabajador: confinado: seccomp+landlock+netns; cgroup /sys/fs/cgroup/aegis-trabajador-1".to_owned(),
            "arranque: motor nucleo DEGRADADO: requisito=kfuncs-tareas motivo=«el BTF de este kernel no publica bpf_iter_task_new»".to_owned(),
            format!(
                "veredicto: hace_s=30 {}",
                linea_veredicto(
                    "proc:0a1b2c",
                    "sospechoso",
                    "alta",
                    "60 % (media)",
                    2,
                    "conducta/alta; secuestro/media",
                    "desde pc-contabilidad-07 escribio a ana@empresa.es con password=hunter2 y curl -H Authorization: Bearer abc.def.ghi",
                )
            ),
            "una linea que nadie espera desde 192.168.1.20 y 127.0.0.1".to_owned(),
        ];
        Entradas {
            generado_unix: 1_790_000_000,
            seudonimo: Some("equipo-0123456789ab".into()),
            version: "0.1.0".into(),
            version_paquete: Some("0.1.0-1".into()),
            huella_arbol: Some("f".repeat(64)),
            binario: Some("/usr/libexec/aegis/aegis-agent".into()),
            sha256_binario: Ok("a".repeat(64)),
            capacidades: vec![
                ("kernel".into(), "6.8.0-45-generic".into()),
                ("bpf-lsm".into(), "no".into()),
            ],
            degradaciones: vec![DegradacionVista {
                capacidad: "bpf-lsm".into(),
                efecto: "sin autoproteccion en el kernel".into(),
                remedio: "lsm=...,bpf en la linea de arranque".into(),
                familias: vec![],
                bloquea_telemetria: false,
            }],
            latido_ruta: LATIDO_POR_DEFECTO.into(),
            latido: Ok(2),
            marca_parada: false,
            socket: socket_por_defecto().expect("la boveda trae el socket"),
            estado: Ok(aegis_ctl::StatusInfo {
                rss_kb: 51_200,
                uptime_s: 3600,
                events_received: 120,
                events_escalated: 5,
                state: "running".into(),
                detalle,
            }),
            cgroup: vec![
                ("memory.max".into(), "167772160\n".into()),
                ("memory.high".into(), "134217728\n".into()),
                ("memory.current".into(), "60000000\n".into()),
                (
                    "memory.events".into(),
                    "low 0\nhigh 3\nmax 0\noom 0\noom_kill 0\n".into(),
                ),
            ],
            dropin: Some(
                "[Service]\nMemoryAccounting=yes\nMemoryHigh=128M\nMemoryMax=160M\n".into(),
            ),
            plano: Some(PlanoVisto {
                ruta: CONFIG_PLANO.into(),
                error: None,
                servidor: Some("mtls://aegis-flota.empresa.local:8443".into()),
                ficheros: vec![
                    (
                        "ca".into(),
                        "/etc/aegiscore/pki/flota-ca.crt".into(),
                        Some(0o644),
                    ),
                    (
                        "clave".into(),
                        "/etc/aegiscore/pki/agente.key".into(),
                        Some(0o640),
                    ),
                ],
            }),
        }
    }

    fn informe() -> Valor {
        let mut r = Redaccion::nueva(Some(EQUIPO));
        componer(&entradas_de_prueba(), &mut r)
    }

    #[test]
    fn el_json_es_valido_y_tiene_todas_las_secciones_en_orden() {
        let j = a_json(&informe());
        assert!(json_valido(&j), "JSON invalido:\n{j}");
        let secciones = [
            "\"formato\"",
            "\"resumen\"",
            "\"agente\"",
            "\"kernel\"",
            "\"servicio\"",
            "\"agente_en_ejecucion\"",
            "\"motores\"",
            "\"trabajador\"",
            "\"perdidas\"",
            "\"memoria\"",
            "\"plano_control\"",
            "\"arbitro\"",
            "\"pipeline\"",
            "\"ultimos_veredictos\"",
            "\"otros\"",
            "\"redaccion\"",
        ];
        let mut desde = 0;
        for s in secciones {
            let p = j[desde..]
                .find(s)
                .unwrap_or_else(|| panic!("falta {s} (o fuera de orden)"));
            desde += p;
        }
        assert!(j.contains("\"formato\": \"aegis-diagnostico/1\""));
    }

    #[test]
    fn lee_motores_perdidas_trabajador_plano_y_veredictos() {
        let Valor::Objeto(raiz) = informe() else {
            panic!("raiz")
        };
        let Some(Valor::Lista(motores)) = raiz.obtener("motores") else {
            panic!("motores")
        };
        assert_eq!(motores.len(), 3, "dos registrados y uno degradado");
        let Valor::Objeto(memoria) = &motores[1] else {
            panic!()
        };
        assert_eq!(memoria.obtener("evaluaciones"), Some(&Valor::Num(4)));
        let Some(Valor::Texto(u)) = memoria.obtener("ultimo_sin_datos") else {
            panic!("ultimo_sin_datos")
        };
        assert!(
            u.como_str().contains("/home/<usuario>/.cache"),
            "{}",
            u.como_str()
        );
        let Some(Valor::Texto(sd)) = memoria.obtener("sin_datos") else {
            panic!("sin_datos")
        };
        assert!(sd.como_str().contains("proc-ilegible"));
        let Valor::Objeto(nucleo) = &motores[2] else {
            panic!()
        };
        assert_eq!(nucleo.obtener("registrado"), Some(&Valor::Bool(false)));
        assert!(
            matches!(nucleo.obtener("requisito"), Some(Valor::Texto(t)) if t.como_str() == "kfuncs-tareas")
        );

        let Some(Valor::Objeto(perdidas)) = raiz.obtener("perdidas") else {
            panic!()
        };
        let Some(Valor::Objeto(fam)) = perdidas.obtener("por_familia") else {
            panic!()
        };
        assert_eq!(fam.obtener("exec"), Some(&Valor::Num(4)));
        assert_eq!(fam.obtener("red"), Some(&Valor::Num(3)));

        let Some(Valor::Objeto(t)) = raiz.obtener("trabajador") else {
            panic!()
        };
        assert_eq!(t.obtener("disponible"), Some(&Valor::Bool(true)));
        assert_eq!(t.obtener("arranques"), Some(&Valor::Num(1)));

        let Some(Valor::Objeto(pc)) = raiz.obtener("plano_control") else {
            panic!()
        };
        let Some(Valor::Objeto(enlace)) = pc.obtener("enlace") else {
            panic!("enlace")
        };
        assert_eq!(enlace.obtener("conectado"), Some(&Valor::Bool(false)));
        assert_eq!(
            enlace.obtener("tope"),
            Some(&Valor::Num(0)),
            "(tope=0 sin parentesis"
        );
        assert_eq!(
            enlace.obtener("servidor"),
            Some(&Valor::Num(0)),
            "servidor=0) sin parentesis"
        );
        let Some(Valor::Texto(err)) = enlace.obtener("ultimo_error") else {
            panic!()
        };
        assert!(
            err.como_str().ends_with("conexion rehusada"),
            "hasta el final de la linea"
        );

        let Some(Valor::Lista(vs)) = raiz.obtener("ultimos_veredictos") else {
            panic!()
        };
        let Valor::Objeto(v) = &vs[0] else { panic!() };
        assert_eq!(v.obtener("hace_s"), Some(&Valor::Num(30)));
        assert_eq!(v.obtener("planos"), Some(&Valor::Num(2)));
        assert!(
            matches!(v.obtener("senales"), Some(Valor::Texto(t)) if t.como_str() == "conducta/alta; secuestro/media")
        );
    }

    #[test]
    fn la_redaccion_no_deja_salir_nada_sensible_en_ninguno_de_los_dos_formatos() {
        let v = informe();
        for salida in [a_json(&v), a_texto(&v)] {
            for secreto in [
                "hunter2",
                "abc.def.ghi",
                "ana@empresa.es",
                "/home/ana",
                EQUIPO,
                "192.168.1.20",
                "10.20.30.40",
            ] {
                assert!(
                    !salida.contains(secreto),
                    "se escapo «{secreto}»:\n{salida}"
                );
            }
            assert!(
                salida.contains("127.0.0.1"),
                "el bucle local no es un dato sensible"
            );
            assert!(salida.contains("<anfitrion>") && salida.contains("<correo>"));
            assert!(salida.contains("<ip>") && salida.contains("/home/<usuario>"));
        }
        let Valor::Objeto(raiz) = v else { panic!() };
        let Some(Valor::Objeto(red)) = raiz.obtener("redaccion") else {
            panic!()
        };
        for k in [
            "credenciales",
            "rutas_de_usuario",
            "correos",
            "direcciones_ipv4",
            "nombre_de_equipo",
        ] {
            assert!(
                matches!(red.obtener(k), Some(Valor::Num(n)) if *n > 0),
                "la redaccion no conto {k}"
            );
        }
    }

    #[test]
    fn los_avisos_dicen_lo_que_hay_que_mirar() {
        let j = a_json(&informe());
        assert!(j.contains("\"estado\": \"atencion\""));
        for aviso in [
            "perdio 7 eventos",
            "desconectado",
            "motor memoria: sin datos",
            "motor nucleo no registrado",
            "tiene que ser 0600",
        ] {
            assert!(j.contains(aviso), "falta el aviso «{aviso}»");
        }
    }

    #[test]
    fn sin_agente_el_informe_sigue_y_lo_dice() {
        let mut e = entradas_de_prueba();
        e.estado = Err("/run/aegiscore/agent.sock: Connection refused".into());
        e.latido = Err("no existe".into());
        e.marca_parada = true;
        let mut r = Redaccion::nueva(None);
        let v = componer(&e, &mut r);
        let j = a_json(&v);
        assert!(json_valido(&j));
        assert!(j.contains("\"responde\": false"));
        assert!(j.contains("\"agente_en_ejecucion\": null"));
        assert!(j.contains("no responde por su canal de control"));
        assert!(j.contains("NO relanzara"));
        let t = a_texto(&v);
        assert!(t.starts_with("AegisCore · autodiagnostico\n"));
        assert!(t.contains("\n== resumen ==\n"));
        assert!(t.contains("  responde: no\n"));
    }

    #[test]
    fn el_texto_tiene_secciones_y_campos_legibles() {
        let t = a_texto(&informe());
        assert!(t.contains("formato: aegis-diagnostico/1\n"));
        assert!(t.contains("\n== agente ==\n  version: 0.1.0\n"));
        assert!(t.contains("\n== memoria ==\n"));
        assert!(t.contains("    memory_max") || t.contains("    max: 167772160"));
        assert!(!t.contains("\"formato\":"), "el texto no es JSON");
    }

    #[test]
    fn json_escapa_comillas_barras_y_controles() {
        let mut r = Redaccion::nueva(None);
        let v =
            Valor::Objeto(Objeto::nuevo().con("x", Valor::Texto(r.limpiar("a\"b\\c\nd\u{1}e"))));
        let j = a_json(&v);
        assert!(json_valido(&j), "{j}");
        assert!(j.contains(r#""a\"b\\c\nd\u0001e""#), "{j}");
    }

    #[test]
    fn las_claves_no_admiten_texto_libre() {
        let o = Objeto::nuevo().con("/home/ana x", Valor::Nulo);
        assert_eq!(o.campos()[0].0, "_home_ana_x");
        assert!(!clave_valida("Ruta"));
        assert!(pares("Ruta=1 bien=2").iter().all(|(k, _)| k == "bien"));
    }

    #[test]
    fn opciones_estrictas() {
        let a =
            |v: &[&str]| analizar_opciones(&v.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>());
        let defecto = socket_por_defecto().expect("la boveda trae el socket de control");
        assert!(defecto.ends_with(".sock"), "{defecto}");
        assert!(a(&[]).is_ok_and(|o| !o.json && o.socket == defecto));
        assert!(a(&["--json", "--control-socket", "/tmp/s"])
            .is_ok_and(|o| o.json && o.socket == "/tmp/s"));
        assert!(a(&["--config", "x"]).is_err());
        assert!(a(&["--control-socket"]).is_err());
    }

    #[test]
    fn las_lineas_registradas_salen_redactadas_y_se_leen() {
        anotar_arranque("trabajador: NO disponible: sin cgroup v2 para password=x");
        let l = lineas_registradas();
        let arr = l
            .iter()
            .find(|x| x.starts_with("arranque: trabajador: NO"))
            .expect("anotada");
        assert!(!arr.contains("password=x"), "{arr}");
        let mut r = Redaccion::nueva(None);
        let v = clasificar(&l, &mut r);
        assert_eq!(
            v.trabajador.obtener("disponible"),
            Some(&Valor::Bool(false))
        );
    }
}
