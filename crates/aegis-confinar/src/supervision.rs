//! Aprender, ensayar e imponer, sobre un proceso real.
//!
//! # El aprendizaje es una ejecucion dedicada
//!
//! Mientras se aprende, CADA llamada del proceso se suspende hasta que el
//! supervisor la deja seguir. Eso tiene un coste (un viaje de ida y vuelta al
//! supervisor por llamada) y una consecuencia: el filtro no se puede quitar de un
//! proceso vivo, asi que cuando la ventana de aprendizaje se acaba, ese proceso
//! se termina. Aprender es arrancar el programa en un entorno de ensayo durante
//! una ventana, no espiar a la instancia de produccion.
//!
//! # El ensayo no bloquea nada
//!
//! En modo permisivo el supervisor deja seguir TODO y anota lo que el perfil
//! habria bloqueado. El programa hace exactamente lo mismo que sin perfil; lo que
//! se gana es saber, antes de imponer, si el perfil lo habria roto.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use aegis_sandbox::error::SandboxError;
use aegis_sandbox::supervisor::{Evento, Fin, Notificacion, Respuesta, Supervisado};
use aegis_sandbox::syscalls;

use crate::compilar;
use crate::modo::Confirmacion;
use crate::objetivo::ObjetivoConfinable;
use crate::observacion::{decodificar, LectorProceso, Observacion};
use crate::perfil::Perfil;

/// Tope de lo que se lee de una ruta en la memoria del proceso.
pub const TOPE_RUTA: usize = 4096;

/// Error de supervision.
#[derive(Debug, thiserror::Error)]
pub enum ErrorConfinar {
    /// Fallo del kernel o de la supervision.
    #[error(transparent)]
    Sandbox(#[from] SandboxError),
    /// El proceso no se pudo lanzar confinado.
    #[error("no se pudo lanzar el proceso confinado: {0}")]
    Lanzamiento(#[source] std::io::Error),
}

/// Adaptador: la memoria y el estado de un proceso supervisado.
struct Lector<'a>(&'a Supervisado);

impl LectorProceso for Lector<'_> {
    fn cadena(&self, hilo: u32, direccion: u64) -> Option<Vec<u8>> {
        self.0.leer_cadena(hilo, direccion, TOPE_RUTA)
    }
    fn bytes(&self, hilo: u32, direccion: u64, n: usize) -> Option<Vec<u8>> {
        self.0.leer(hilo, direccion, n).ok()
    }
    fn directorio_actual(&self, hilo: u32) -> Option<PathBuf> {
        std::fs::read_link(format!("/proc/{hilo}/cwd")).ok()
    }
    fn ruta_de_descriptor(&self, hilo: u32, fd: i32) -> Option<PathBuf> {
        std::fs::read_link(format!("/proc/{hilo}/fd/{fd}")).ok()
    }
}

/// Si el proceso corre como root (uid efectivo 0).
fn es_root(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|t| {
            t.lines()
                .find_map(|l| l.strip_prefix("Uid:"))
                .and_then(|v| v.split_whitespace().nth(1).map(|e| e == "0"))
        })
        .unwrap_or(false)
}

/// Lee los hechos de una notificacion y comprueba que siguen siendo del mismo
/// hilo: si murio y otro proceso heredo el pid mientras se leia, lo leido no se
/// anota.
fn hechos(s: &Supervisado, n: &Notificacion) -> Vec<Observacion> {
    let v = decodificar(n, &Lector(s));
    if s.sigue_valida(n.id) {
        v
    } else {
        vec![Observacion::Llamada(n.nr)]
    }
}

/// El resultado de aprender.
#[derive(Debug, Clone)]
pub struct Aprendizaje {
    /// El perfil aprendido.
    pub perfil: Perfil,
    /// Como termino el proceso.
    pub fin: Option<Fin>,
    /// Su salida.
    pub salida: Vec<u8>,
    /// Llamadas vistas en total.
    pub llamadas_vistas: u64,
    /// Si se acabo la ventana antes de que el proceso terminara solo.
    pub ventana_agotada: bool,
    /// Cuanto duro.
    pub duracion: Duration,
}

/// Aprende el perfil de un programa ejecutandolo durante una ventana.
///
/// # Errores
/// Si no se puede supervisar.
pub fn aprender(
    objetivo: &ObjetivoConfinable,
    argumentos: &[String],
    ventana: Duration,
) -> Result<Aprendizaje, ErrorConfinar> {
    let inicio = Instant::now();
    let s = Supervisado::lanzar(
        objetivo.ejecutable(),
        argumentos,
        &compilar::filtro_aprendizaje(),
    )?;
    let mut perfil = Perfil::nuevo(objetivo.ejecutable());
    perfil.ejecuciones = 1;
    let mut vistas = 0u64;
    let mut root_comprobado = false;
    let mut ventana_agotada = false;
    loop {
        let quedan = ventana.saturating_sub(inicio.elapsed());
        if quedan.is_zero() {
            ventana_agotada = true;
            break;
        }
        match s.recibir(quedan.min(Duration::from_millis(500)))? {
            Evento::Llamada(n) => {
                vistas += 1;
                // El uid se mira despues del primer execve: antes es el del
                // supervisor, no el del programa.
                if !root_comprobado && Some(n.nr) != syscalls::numero("execve") {
                    perfil.root = es_root(s.pid());
                    root_comprobado = true;
                }
                for o in hechos(&s, &n) {
                    perfil.anotar(&o);
                }
                s.responder(n.id, Respuesta::Continuar)?;
            }
            Evento::Terminado => break,
            Evento::SinNovedad => {}
        }
    }
    let (fin, salida) = if ventana_agotada {
        // El filtro no se puede quitar de un proceso vivo: la ventana acaba con
        // el proceso. Al soltar el supervisor sin esperar, se termina.
        drop(s);
        (None, Vec::new())
    } else {
        let (f, sal) = s.esperar()?;
        (Some(f), sal)
    };
    Ok(Aprendizaje {
        perfil,
        fin,
        salida,
        llamadas_vistas: vistas,
        ventana_agotada,
        duracion: inicio.elapsed(),
    })
}

/// Algo que el perfil habria bloqueado.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Desviacion {
    /// Una llamada que el perfil no contiene.
    Llamada(String),
    /// Un fichero fuera de las reglas.
    Fichero(PathBuf, crate::observacion::Acceso),
    /// Un socket de una familia no aprendida.
    Familia(u32),
}

impl Desviacion {
    /// Una linea legible.
    #[must_use]
    pub fn frase(&self) -> String {
        match self {
            Desviacion::Llamada(n) => format!("llamada {n}"),
            Desviacion::Fichero(r, a) => format!("{a:?} de {}", r.display()),
            Desviacion::Familia(f) => format!("socket de la familia {f}"),
        }
    }
}

/// El resultado de un ensayo en modo permisivo.
#[derive(Debug, Clone)]
pub struct Ensayo {
    /// Lo que el perfil habria bloqueado, sin repetir y en orden.
    pub habria_bloqueado: Vec<Desviacion>,
    /// Como termino el proceso.
    pub fin: Option<Fin>,
    /// Su salida.
    pub salida: Vec<u8>,
    /// Si se acabo la ventana.
    pub ventana_agotada: bool,
}

/// Compara un hecho con el perfil.
fn desviacion(p: &Perfil, o: &Observacion) -> Option<Desviacion> {
    match o {
        Observacion::Llamada(nr) if !p.llamadas.contains(nr) => Some(Desviacion::Llamada(
            syscalls::nombre(*nr).map_or_else(|| format!("#{nr}"), str::to_string),
        )),
        Observacion::Fichero { ruta, acceso } if !p.permite_ruta(ruta, *acceso) => {
            Some(Desviacion::Fichero(ruta.clone(), *acceso))
        }
        Observacion::Socket { dominio, .. } if !p.dominios.contains(dominio) => {
            Some(Desviacion::Familia(*dominio))
        }
        _ => None,
    }
}

/// Ensaya un perfil en modo permisivo: el programa corre sin restricciones y se
/// anota lo que el perfil habria bloqueado.
///
/// # Errores
/// Si no se puede supervisar.
pub fn ensayar(
    objetivo: &ObjetivoConfinable,
    perfil: &Perfil,
    argumentos: &[String],
    ventana: Duration,
) -> Result<Ensayo, ErrorConfinar> {
    let inicio = Instant::now();
    let s = Supervisado::lanzar(
        objetivo.ejecutable(),
        argumentos,
        &compilar::filtro_permisivo(perfil),
    )?;
    let mut habria: std::collections::BTreeSet<Desviacion> = std::collections::BTreeSet::new();
    let mut ventana_agotada = false;
    loop {
        let quedan = ventana.saturating_sub(inicio.elapsed());
        if quedan.is_zero() {
            ventana_agotada = true;
            break;
        }
        match s.recibir(quedan.min(Duration::from_millis(500)))? {
            Evento::Llamada(n) => {
                for o in hechos(&s, &n) {
                    if let Some(d) = desviacion(perfil, &o) {
                        habria.insert(d);
                    }
                }
                // PERMISIVO: se deja seguir siempre.
                s.responder(n.id, Respuesta::Continuar)?;
            }
            Evento::Terminado => break,
            Evento::SinNovedad => {}
        }
    }
    let (fin, salida) = if ventana_agotada {
        drop(s);
        (None, Vec::new())
    } else {
        let (f, sal) = s.esperar()?;
        (Some(f), sal)
    };
    Ok(Ensayo {
        habria_bloqueado: habria.into_iter().collect(),
        fin,
        salida,
        ventana_agotada,
    })
}

/// Ejecuta el programa con el perfil IMPUESTO. Exige la confirmacion.
///
/// # Errores
/// Si el perfil no se puede compilar o el proceso no se puede lanzar.
pub fn ejecutar_obligatorio(
    objetivo: &ObjetivoConfinable,
    perfil: &Perfil,
    confirmacion: &Confirmacion,
    argumentos: &[String],
) -> Result<(Fin, Vec<u8>), ErrorConfinar> {
    let sandbox = std::sync::Arc::new(compilar::obligatorio(perfil, confirmacion)?);
    let mut cmd = std::process::Command::new(objetivo.ejecutable());
    cmd.args(argumentos);
    sandbox.confine(&mut cmd);
    let salida = cmd.output().map_err(ErrorConfinar::Lanzamiento)?;
    let fin = match salida.status.code() {
        Some(c) => Fin::Codigo(c),
        None => {
            use std::os::unix::process::ExitStatusExt;
            Fin::Senal(salida.status.signal().unwrap_or(0))
        }
    };
    let mut todo = salida.stdout;
    todo.extend_from_slice(&salida.stderr);
    Ok((fin, todo))
}

/// Ejecuta el programa SIN perfil (lo que hace el despliegue cuando el perfil se
/// retiro).
///
/// # Errores
/// Si el proceso no se puede lanzar.
pub fn ejecutar_libre(
    objetivo: &ObjetivoConfinable,
    argumentos: &[String],
) -> Result<(Fin, Vec<u8>), ErrorConfinar> {
    let salida = std::process::Command::new(objetivo.ejecutable())
        .args(argumentos)
        .output()
        .map_err(ErrorConfinar::Lanzamiento)?;
    let fin = match salida.status.code() {
        Some(c) => Fin::Codigo(c),
        None => {
            use std::os::unix::process::ExitStatusExt;
            Fin::Senal(salida.status.signal().unwrap_or(0))
        }
    };
    let mut todo = salida.stdout;
    todo.extend_from_slice(&salida.stderr);
    Ok((fin, todo))
}
