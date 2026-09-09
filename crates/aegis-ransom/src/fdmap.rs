//! Resolucion de descriptor a ruta.
//!
//! # Por que hace falta
//!
//! El sondeo de `sys_enter_write` recibe un descriptor, no una ruta. Resolverlo
//! en el kernel exigiria recorrer la tabla de ficheros del proceso y de ahi al
//! dentry y sus padres, un recorrido de profundidad variable que el verificador
//! no admite en el camino caliente y que ademas anadiria decenas de
//! nanosegundos a **cada** `write` del sistema.
//!
//! La alternativa es hacerlo en Ring 3 y una sola vez por apertura: el sondeo de
//! salida de `openat` emite la asociacion `(pid, fd) -> ruta`, y aqui se guarda
//! para que las escrituras posteriores la encuentren en O(1).
//!
//! # Por que no se lee `/proc/[pid]/fd`
//!
//! Porque para cuando el agente mire, el proceso ya cerro el descriptor. Un
//! cifrador abre, escribe y cierra en microsegundos; la carrera se pierde
//! siempre. La asociacion tiene que capturarse en el momento de la apertura.
//!
//! # La cota
//!
//! Un descriptor se reutiliza en cuanto se cierra, asi que una entrada obsoleta
//! atribuye escrituras a la ruta equivocada. Se acota por proceso y se expulsa
//! por antiguedad, y el conjunto entero se descarta al terminar el proceso.
//!
//! # Por que la clave es el actor y no el PID
//!
//! Los PID se reutilizan. Si el proceso 4242 abre `/etc/shadow`, muere, y el
//! kernel asigna el 4242 a otro proceso, una tabla indexada por PID le
//! atribuiria al recien llegado los descriptores del muerto. La clave de actor
//! del ABI incluye el instante de arranque, asi que no colisiona jamas.

use std::collections::HashMap;
use std::sync::Arc;

/// Descriptores recordados por proceso.
///
/// 256 cubre de sobra el uso real: un cifrador trabaja con unos pocos
/// descriptores a la vez, y un servidor con miles no es a quien vigila esto.
pub const FD_POR_PROCESO: usize = 256;

/// Procesos con descriptores en seguimiento.
pub const PROCESOS_MAX: usize = 4096;

#[derive(Debug)]
struct Entrada {
    ruta: Arc<str>,
    ts_ns: u64,
}

/// Tabla `(actor, fd) -> ruta`.
#[derive(Debug, Default)]
pub struct FdMap {
    por_actor: HashMap<u64, HashMap<i32, Entrada>>,
}

impl FdMap {
    /// Crea una tabla vacia.
    pub fn new() -> FdMap {
        FdMap::default()
    }

    /// Registra la ruta asociada a un descriptor recien abierto.
    pub fn bind(&mut self, actor: u64, fd: i32, ruta: &str, ts_ns: u64) {
        // Un descriptor negativo es un `openat` fallido: no abrio nada.
        if fd < 0 {
            return;
        }
        if self.por_actor.len() >= PROCESOS_MAX && !self.por_actor.contains_key(&actor) {
            self.expulsar_proceso_mas_antiguo();
        }
        let tabla = self.por_actor.entry(actor).or_default();
        if tabla.len() >= FD_POR_PROCESO && !tabla.contains_key(&fd) {
            if let Some(v) = tabla.iter().min_by_key(|(_, e)| e.ts_ns).map(|(k, _)| *k) {
                tabla.remove(&v);
            }
        }
        tabla.insert(
            fd,
            Entrada {
                ruta: Arc::from(ruta),
                ts_ns,
            },
        );
    }

    /// Ruta asociada a un descriptor, si se conoce.
    pub fn resolve(&self, actor: u64, fd: i32) -> Option<&str> {
        self.por_actor
            .get(&actor)?
            .get(&fd)
            .map(|e| e.ruta.as_ref())
    }

    /// Olvida un descriptor concreto.
    pub fn unbind(&mut self, actor: u64, fd: i32) {
        if let Some(t) = self.por_actor.get_mut(&actor) {
            t.remove(&fd);
            if t.is_empty() {
                self.por_actor.remove(&actor);
            }
        }
    }

    /// Olvida todos los descriptores de un proceso terminado.
    pub fn forget_process(&mut self, actor: u64) {
        self.por_actor.remove(&actor);
    }

    /// Procesos con descriptores recordados.
    pub fn tracked_processes(&self) -> usize {
        self.por_actor.len()
    }

    /// Descriptores recordados en total.
    pub fn tracked_fds(&self) -> usize {
        self.por_actor.values().map(HashMap::len).sum()
    }

    /// Descarta los procesos cuya ultima apertura sea anterior al limite.
    ///
    /// Existe porque el evento de fin de proceso puede perderse: si el ring se
    /// lleno, `forget_process` no llega nunca y la tabla creceria hasta la cota
    /// dura reteniendo rutas de procesos muertos.
    pub fn prune(&mut self, now_ns: u64, max_edad_ns: u64) -> usize {
        let antes = self.por_actor.len();
        self.por_actor.retain(|_, t| {
            t.retain(|_, e| now_ns.saturating_sub(e.ts_ns) < max_edad_ns);
            !t.is_empty()
        });
        antes - self.por_actor.len()
    }

    fn expulsar_proceso_mas_antiguo(&mut self) {
        let victima = self
            .por_actor
            .iter()
            .map(|(a, t)| (*a, t.values().map(|e| e.ts_ns).max().unwrap_or(0)))
            .min_by_key(|(_, ts)| *ts)
            .map(|(a, _)| a);
        if let Some(a) = victima {
            self.por_actor.remove(&a);
        }
    }
}
