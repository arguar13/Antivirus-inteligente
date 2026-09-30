//! Analisis estatico de lo que se ejecuta, en el trabajador confinado.
//!
//! Camino FRIO: en el bucle de eventos solo se encola la ruta de la imagen que
//! se acaba de ejecutar (una insercion en un canal acotado). Un hilo aparte —el
//! analista— la lee del disco, la manda al trabajador confinado y devuelve lo
//! que dijo; el bucle lo entrega al arbitro con [`aegis_motor::Arbitro::aportar`].
//!
//! Dos motores, porque son dos firmas con topes distintos: [`MotorEstatico`]
//! (estructura y desensamblado, tope 80) y [`MotorModelo`] (el modelo de
//! clasificacion, tope 70). El segundo no recibe eventos: solo firma lo que el
//! analista trae de su analizador. Juntar los dos en uno obligaria a firmar lo
//! del modelo como estatico, con mas confianza de la que su plano permite.
//!
//! # El orden de los riesgos
//!
//! - **Leer del disco en el bucle de eventos**: nunca. Lo hace el analista.
//! - **La misma imagen mil veces por segundo** (`/usr/bin/true` en un script):
//!   el bucle no la vuelve a encolar si la encolo hace poco, y el analista
//!   guarda el resultado por `(dispositivo, inodo, tamaño, fecha)`.
//! - **Cola llena**: el encargo se pierde y se DICE (`SinDatos` por cola llena);
//!   el bucle no espera nunca al analista.
//! - **El fichero cambia entre la ejecucion y la lectura**: el analisis es del
//!   contenido que habia al leerlo, no necesariamente del que se ejecuto. Cerrar
//!   esa ventana exige leer por el inodo en el momento del `exec`, que es trabajo
//!   del gancho LSM (paso 5 de esta fase).

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aegis_entidad::{Eid, Motor as Firma, Senal};
use aegis_motor::{Camino, Causa, Dictamen, Ficha, Motor, Plazo, Presupuesto, Requisito};
use aegis_trabajador::protocolo::MAX_DATOS;
use aegis_trabajador::{para_ejecutable, FalloAnalisis, Trabajador};

use crate::motores::EventoAgente;
use crate::triage::TelemetryEvent;

/// Encargos en cola, como mucho.
const COLA: usize = 256;
/// Imagenes recien encoladas que el bucle recuerda para no repetir.
const RECIENTES: usize = 4096;
/// Cuanto tarda en volver a encolarse la misma ruta.
const REPETIR_NS: u64 = 60_000_000_000;
/// Resultados que el analista recuerda por inodo.
const CACHE: usize = 8192;
/// Plazo de cada analisis en el trabajador.
const PLAZO_ANALISIS: Duration = Duration::from_secs(3);

/// Nombre del motor estatico, con el que se entregan sus resultados.
pub const NOMBRE_ESTATICO: &str = "estatico";
/// Nombre del motor del modelo.
pub const NOMBRE_MODELO: &str = "modelo";

struct Encargo {
    entidad: Eid,
    ruta: Arc<str>,
    cuando_ns: u64,
}

/// Lo que el analista devuelve, para entregarlo al arbitro.
pub struct Resultado {
    /// El motor en cuyo nombre se entrega.
    pub motor: &'static str,
    /// Sobre que.
    pub entidad: Eid,
    /// Lo dictaminado.
    pub dictamen: Dictamen,
    /// Cuando se ejecuto lo analizado.
    pub cuando_ns: u64,
}

/// Contadores del analista.
#[derive(Debug, Clone, Default)]
pub struct EstadoAnalista {
    /// Encargos atendidos.
    pub encargos: u64,
    /// Resueltos por la cache, sin volver a analizar.
    pub aciertos: u64,
    /// Ficheros que no se pudieron leer (borrados tras ejecutarse, sin permiso).
    pub ilegibles: u64,
    /// Ficheros por encima del tope de tamaño.
    pub enormes: u64,
    /// Encargos perdidos por cola llena.
    pub perdidos: u64,
    /// El ultimo fichero que no se pudo leer, y por que: sin el motivo, un
    /// «ilegible» repetido no se puede diagnosticar.
    pub ultimo_ilegible: Option<String>,
    /// El estado del trabajador confinado.
    pub trabajador: aegis_trabajador::EstadoTrabajador,
}

/// Clave de la cache: el contenido que habia en disco.
type Clave = (u64, u64, u64, i64);

fn clave(m: &std::fs::Metadata) -> Clave {
    (
        m.dev(),
        m.ino(),
        m.size(),
        m.mtime_nsec() + m.mtime() * 1_000_000_000,
    )
}

fn causa_de(f: &FalloAnalisis) -> Causa {
    match f {
        FalloAnalisis::Plazo(d) => Causa::PlazoAgotado {
            gastado: *d,
            tope: *d,
        },
        FalloAnalisis::Murio(m) | FalloAnalisis::NoDisponible(m) => {
            Causa::TrabajadorCaido(m.clone())
        }
        FalloAnalisis::NoPudo(m) => Causa::Otra(m.clone()),
    }
}

/// Lo que dijo cada motor sobre un fichero: `(estatico, modelo)`.
type Dictamenes = (Dictamen, Dictamen);

fn analizar(
    t: &mut Trabajador,
    entidad: &Eid,
    ruta: &str,
    bytes: &[u8],
    cuando_ns: u64,
) -> Dictamenes {
    let mut por_firma: [(Vec<Senal>, Option<Causa>); 2] = [(Vec::new(), None), (Vec::new(), None)];
    for a in para_ejecutable(bytes.get(..4).unwrap_or(bytes)) {
        let i = usize::from(a == aegis_trabajador::Analizador::Modelo);
        match t.analizar(a, bytes, PLAZO_ANALISIS) {
            Ok(informe) => {
                for h in informe.hallazgos {
                    let j = usize::from(h.firma == Firma::Aprendizaje);
                    por_firma[j].0.push(Senal::nueva(
                        h.firma,
                        entidad.clone(),
                        h.juicio,
                        h.severidad,
                        h.confianza,
                        format!("{ruta}: {}", h.porque),
                        cuando_ns,
                    ));
                }
            }
            Err(f) => {
                por_firma[i].1.get_or_insert(causa_de(&f));
            }
        }
    }
    let [(s0, c0), (s1, c1)] = por_firma;
    let a_dictamen = |s: Vec<Senal>, c: Option<Causa>| match (s.is_empty(), c) {
        (false, _) => Dictamen::Senales(s),
        (true, Some(c)) => Dictamen::SinDatos(c),
        (true, None) => Dictamen::NoAplica,
    };
    (a_dictamen(s0, c0), a_dictamen(s1, c1))
}

/// Si un resultado se puede reutilizar para el mismo contenido.
///
/// Solo lo definitivo. Un «no pude mirar» porque el trabajador murio o no llego
/// a tiempo es del MOMENTO, no del fichero: recordarlo repetia el fallo en cada
/// ejecucion posterior del mismo binario aunque el trabajador ya estuviera sano
/// (visto en vivo: una muerte, ocho «trabajador caido»; FASE 1 del MP-16). Que
/// el formato no se pueda leer si es del fichero, y se recuerda.
fn se_puede_recordar(d: &Dictamenes) -> bool {
    let transitorio = |x: &Dictamen| {
        matches!(
            x,
            Dictamen::SinDatos(Causa::TrabajadorCaido(_) | Causa::PlazoAgotado { .. })
        )
    };
    !transitorio(&d.0) && !transitorio(&d.1)
}

fn analista(
    mut t: Trabajador,
    encargos: Receiver<Encargo>,
    resultados: mpsc::Sender<Resultado>,
    estado: Arc<Mutex<EstadoAnalista>>,
) {
    let mut cache: HashMap<Clave, (Dictamen, Dictamen)> = HashMap::new();
    while let Ok(e) = encargos.recv() {
        let (estatico, modelo) = match std::fs::metadata(&*e.ruta) {
            Err(err) => {
                let motivo = format!("{}: no se pudo leer ({err})", e.ruta);
                if let Ok(mut s) = estado.lock() {
                    s.ilegibles += 1;
                    s.ultimo_ilegible = Some(motivo.clone());
                }
                let c = Causa::Otra(motivo);
                (Dictamen::SinDatos(c.clone()), Dictamen::SinDatos(c))
            }
            Ok(m) => {
                let k = clave(&m);
                if let Some((a, b)) = cache.get(&k) {
                    if let Ok(mut s) = estado.lock() {
                        s.aciertos += 1;
                    }
                    (a.clone(), b.clone())
                } else if m.size() as usize > MAX_DATOS {
                    if let Ok(mut s) = estado.lock() {
                        s.enormes += 1;
                    }
                    let c = Causa::Otra(format!(
                        "{}: {} MiB, por encima del tope de analisis",
                        e.ruta,
                        m.size() / (1024 * 1024)
                    ));
                    (Dictamen::SinDatos(c.clone()), Dictamen::SinDatos(c))
                } else {
                    match std::fs::read(&*e.ruta) {
                        Ok(bytes) => {
                            let d = analizar(&mut t, &e.entidad, &e.ruta, &bytes, e.cuando_ns);
                            if se_puede_recordar(&d) {
                                if cache.len() >= CACHE {
                                    cache.clear();
                                }
                                cache.insert(k, d.clone());
                            }
                            d
                        }
                        Err(err) => {
                            let c = Causa::Otra(format!("{}: no se pudo leer ({err})", e.ruta));
                            (Dictamen::SinDatos(c.clone()), Dictamen::SinDatos(c))
                        }
                    }
                }
            }
        };
        if let Ok(mut s) = estado.lock() {
            s.encargos += 1;
            s.trabajador = t.estado().clone();
        }
        for (motor, dictamen) in [(NOMBRE_ESTATICO, estatico), (NOMBRE_MODELO, modelo)] {
            if dictamen == Dictamen::NoAplica {
                continue;
            }
            let r = Resultado {
                motor,
                entidad: e.entidad.clone(),
                dictamen,
                cuando_ns: e.cuando_ns,
            };
            if resultados.send(r).is_err() {
                return;
            }
        }
    }
}

/// El camino frio arrancado: el motor, por donde vuelven sus resultados, su
/// estado y su hilo.
///
/// Al soltar el motor, el analista se queda sin encargos y termina, y con el el
/// trabajador y su cgroup. Hay que esperar a [`Analista::hilo`] antes de salir:
/// sin esperar, el proceso terminaba antes y el cgroup quedaba huerfano.
pub struct Analista {
    /// El motor, para registrarlo en el arbitro.
    pub motor: MotorEstatico,
    /// Por donde llegan los resultados, para entregarlos al arbitro.
    pub resultados: Receiver<Resultado>,
    /// Contadores del analista y del trabajador.
    pub estado: Arc<Mutex<EstadoAnalista>>,
    /// El hilo analista.
    pub hilo: std::thread::JoinHandle<()>,
}

/// El analisis estatico de las imagenes que se ejecutan.
pub struct MotorEstatico {
    encargos: SyncSender<Encargo>,
    recientes: HashMap<Arc<str>, u64>,
    estado: Arc<Mutex<EstadoAnalista>>,
}

impl MotorEstatico {
    /// Arranca el hilo analista sobre un trabajador ya confinado.
    ///
    /// # Errores
    ///
    /// Si no se puede crear el hilo.
    pub fn arrancar(t: Trabajador) -> std::io::Result<Analista> {
        let (tx, rx) = mpsc::sync_channel(COLA);
        let (tx_res, rx_res) = mpsc::channel();
        let estado = Arc::new(Mutex::new(EstadoAnalista::default()));
        let e = Arc::clone(&estado);
        let hilo = std::thread::Builder::new()
            .name("analista".into())
            .spawn(move || analista(t, rx, tx_res, e))?;
        Ok(Analista {
            motor: MotorEstatico {
                encargos: tx,
                recientes: HashMap::new(),
                estado: Arc::clone(&estado),
            },
            resultados: rx_res,
            estado,
            hilo,
        })
    }
}

/// Si este proceso se lanzo como trabajador (`--trabajador` como primer
/// argumento), sirve peticiones y NO vuelve.
///
/// El agente lo llama lo primero de todo: antes de blindarse o de sondear el
/// kernel, porque todo eso son llamadas que el confinamiento del trabajador no
/// permite.
pub fn servir_si_es_trabajador(args: &[String]) {
    if args.get(1).map(String::as_str) == Some("--trabajador") {
        aegis_trabajador::servidor::servir();
    }
}

impl MotorEstatico {
    /// Arranca el trabajador confinado —este mismo binario con `--trabajador`—
    /// y el analista sobre el.
    ///
    /// Devuelve el camino frio arrancado y lo que el trabajador declaro de su
    /// confinamiento, para publicarlo al arrancar.
    ///
    /// # Errores
    ///
    /// Por que no hay trabajador: el motor que lo necesita se declara como no
    /// disponible en este host, y el resto del agente protege igual.
    pub fn arrancar_con_trabajador() -> Result<(Analista, String), String> {
        let config = aegis_trabajador::ConfigTrabajador::este_binario()
            .map_err(|e| format!("ruta del ejecutable: {e}"))?;
        let t = Trabajador::arrancar(config)?;
        let declarado = format!("{}; cgroup {}", t.estado().confinamiento, t.estado().cgroup);
        let a = MotorEstatico::arrancar(t)
            .map_err(|e| format!("no se pudo crear el hilo analista: {e}"))?;
        Ok((a, declarado))
    }

    /// Un motor sin trabajador, solo para declararlo: su registro se rechaza
    /// porque el host no ofrece el trabajador confinado, y el arbitro lo
    /// publica como omitido con el motivo.
    pub fn inerte() -> MotorEstatico {
        let (encargos, _) = mpsc::sync_channel(0);
        MotorEstatico {
            encargos,
            recientes: HashMap::new(),
            estado: Arc::default(),
        }
    }
}

impl Motor<EventoAgente> for MotorEstatico {
    fn ficha(&self) -> Ficha {
        Ficha {
            nombre: NOMBRE_ESTATICO,
            firma: Firma::Estatico,
            camino: Camino::Frio,
            // En el bucle solo se encola: unos microsegundos.
            presupuesto: Presupuesto::caliente(100, RECIENTES * 160),
            requisitos: &[Requisito::TelemetriaKernel, Requisito::TrabajadorConfinado],
        }
    }

    fn evaluar(&mut self, ev: &EventoAgente, _plazo: &Plazo) -> Dictamen {
        let TelemetryEvent::Exec { image, ts_ns, .. } = &ev.evento else {
            return Dictamen::NoAplica;
        };
        if let Some(&antes) = self.recientes.get(image) {
            if ts_ns.saturating_sub(antes) < REPETIR_NS {
                return Dictamen::NoAplica;
            }
        }
        if self.recientes.len() >= RECIENTES {
            self.recientes.clear();
        }
        self.recientes.insert(Arc::clone(image), *ts_ns);
        match self.encargos.try_send(Encargo {
            entidad: ev.entidad.clone(),
            ruta: Arc::clone(image),
            cuando_ns: *ts_ns,
        }) {
            Ok(()) => Dictamen::NoAplica,
            Err(TrySendError::Full(_)) => {
                if let Ok(mut s) = self.estado.lock() {
                    s.perdidos += 1;
                }
                Dictamen::SinDatos(Causa::Otra("cola del analista llena".into()))
            }
            Err(TrySendError::Disconnected(_)) => Dictamen::SinDatos(Causa::TrabajadorCaido(
                "el hilo analista no responde".into(),
            )),
        }
    }

    fn memoria(&self) -> usize {
        self.recientes.len() * 160
    }
}

/// El modelo estatico de clasificacion. No recibe eventos: firma lo que el
/// analista trae de su analizador en el trabajador.
pub struct MotorModelo;

impl Motor<EventoAgente> for MotorModelo {
    fn ficha(&self) -> Ficha {
        Ficha {
            nombre: NOMBRE_MODELO,
            firma: Firma::Aprendizaje,
            camino: Camino::Frio,
            presupuesto: Presupuesto::caliente(10, 0),
            requisitos: &[Requisito::TelemetriaKernel, Requisito::TrabajadorConfinado],
        }
    }

    fn evaluar(&mut self, _ev: &EventoAgente, _plazo: &Plazo) -> Dictamen {
        Dictamen::NoAplica
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn un_fallo_del_momento_no_se_recuerda_y_uno_del_fichero_si() {
        let caido = Dictamen::SinDatos(Causa::TrabajadorCaido("murio".into()));
        let plazo = Dictamen::SinDatos(Causa::PlazoAgotado {
            gastado: Duration::from_secs(3),
            tope: Duration::from_secs(3),
        });
        let ilegible = Dictamen::SinDatos(Causa::Otra("ELF ilegible".into()));
        assert!(!se_puede_recordar(&(Dictamen::NoAplica, caido.clone())));
        assert!(!se_puede_recordar(&(plazo, Dictamen::NoAplica)));
        assert!(se_puede_recordar(&(ilegible, Dictamen::NoAplica)));
        assert!(se_puede_recordar(&(Dictamen::NoAplica, Dictamen::NoAplica)));
    }
}
