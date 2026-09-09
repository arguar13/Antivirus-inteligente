//! Modelo e interfaz del ciclo de vida de procesos, sin dependencias del SO.
//!
//! La pieza que hace que este modelo valga en los tres sistemas es
//! [`ProcessKey`]: un PID SOLO no identifica a un proceso. Los PID se reciclan,
//! y en una maquina con mucha rotacion se reciclan en segundos. Cualquier
//! estructura que indexe por PID a secas acaba atribuyendo las acciones de un
//! proceso nuevo al historial del que ocupaba ese numero antes, que es como se
//! fabrican tanto los falsos positivos como los puntos ciegos.
//!
//! Por eso la identidad lleva SIEMPRE el instante de arranque. Los tres
//! sistemas lo exponen: Linux en el campo 22 de `/proc/<pid>/stat`, Windows en
//! el `CreateTime` del proceso y macOS en `p_starttime` de `KERN_PROC`.

use std::path::PathBuf;
use std::time::Duration;

use crate::error::ScalError;
use crate::platform::Platform;

/// Identidad estable de un proceso, a prueba de reciclado de PID.
///
/// La comparacion incluye las dos partes a proposito: dos procesos con el
/// mismo PID y distinto arranque son procesos DISTINTOS, y tratarlos como uno
/// es exactamente el error que este tipo existe para impedir.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProcessKey {
    /// Identificador de proceso del sistema.
    pub pid: u32,
    /// Marca de arranque, en las unidades que da la plataforma.
    ///
    /// No se normaliza a nanosegundos: el valor solo se usa para comparar dos
    /// lecturas del MISMO sistema, y convertirlo introduciria redondeos que
    /// pueden hacer que dos procesos distintos parezcan el mismo.
    pub start_stamp: u64,
}

impl ProcessKey {
    /// Crea una identidad.
    pub const fn new(pid: u32, start_stamp: u64) -> ProcessKey {
        ProcessKey { pid, start_stamp }
    }
}

/// Estado de ejecucion, unificado entre plataformas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// Ejecutandose o listo para ejecutarse.
    Running,
    /// Bloqueado en una espera interrumpible.
    Sleeping,
    /// Bloqueado en una espera no interrumpible (E/S de disco).
    Uninterruptible,
    /// Detenido por una senal o por un depurador.
    Stopped,
    /// Termino pero su padre no lo ha recolectado.
    Zombie,
    /// La plataforma reporto un estado que no encaja en los anteriores.
    Other,
}

/// Retrato de un proceso en un instante.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    /// Identidad estable.
    pub key: ProcessKey,
    /// PID del padre. Puede haber muerto ya: es una pista de linaje, no una
    /// referencia viva.
    pub parent_pid: u32,
    /// Ruta de la imagen ejecutada, si se pudo resolver.
    ///
    /// Es `None` con frecuencia legitima: hilos de kernel, procesos de otro
    /// usuario sin permiso sobre `exe`, o un binario ya borrado del disco.
    pub image: Option<PathBuf>,
    /// Linea de comandos, ya troceada en argumentos.
    pub cmdline: Vec<String>,
    /// Usuario efectivo.
    pub uid: u32,
    /// Grupo efectivo.
    pub gid: u32,
    /// Numero de hilos.
    pub threads: u32,
    /// Estado de ejecucion.
    pub state: ProcessState,
}

impl ProcessInfo {
    /// Nombre del ejecutable sin ruta, util para reglas y para registros.
    pub fn image_name(&self) -> Option<&str> {
        self.image.as_ref()?.file_name()?.to_str()
    }

    /// Indica si el proceso no tiene memoria de usuario que inspeccionar.
    ///
    /// En Linux son los hilos de kernel; en Windows, `System` y los procesos
    /// protegidos minimos. Pedir un volcado de memoria de uno de ellos no es un
    /// error del llamante, simplemente no hay nada que leer.
    pub fn is_system_thread(&self) -> bool {
        self.image.is_none() && self.cmdline.is_empty()
    }
}

/// Cambio observado en el ciclo de vida de un proceso.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessEvent {
    /// Un proceso empezo a existir.
    Started(Box<ProcessInfo>),
    /// Un proceso termino.
    Exited {
        /// Identidad del que termino.
        key: ProcessKey,
        /// Codigo de salida, si la plataforma lo entrega en el evento.
        exit_code: Option<i32>,
    },
}

impl ProcessEvent {
    /// Identidad del proceso al que se refiere el evento.
    pub fn key(&self) -> ProcessKey {
        match self {
            ProcessEvent::Started(i) => i.key,
            ProcessEvent::Exited { key, .. } => *key,
        }
    }
}

/// Origen de telemetria de ciclo de vida de procesos.
///
/// El contrato tiene dos mitades deliberadamente separadas:
///
/// - **Consulta** (`list`, `info`, `children_of`): responde sobre el estado
///   actual. Es cara y sirve para el camino lento.
/// - **Eventos** (`poll`): entrega los cambios desde la ultima llamada. Es el
///   camino caliente.
///
/// Un backend puede tener la primera mitad nativa y la segunda degradada (por
/// ejemplo, sondeando `/proc`), y por eso [`Capabilities`](crate::Capabilities)
/// las declara por separado.
pub trait ProcessLifecycleProvider {
    /// Plataforma que implementa este proveedor.
    fn platform(&self) -> Platform;

    /// Enumera los procesos vivos.
    ///
    /// Los que desaparecen durante la enumeracion se omiten en vez de abortar
    /// la lista: en un sistema vivo eso pasa constantemente.
    fn list(&self) -> Result<Vec<ProcessInfo>, ScalError>;

    /// Retrato de un proceso concreto.
    fn info(&self, pid: u32) -> Result<ProcessInfo, ScalError>;

    /// Identidad estable de un PID, sin construir el retrato completo.
    ///
    /// Es la operacion mas usada del rasgo —cada evento necesita resolver su
    /// actor— y por eso existe aparte: leer la linea de comandos y los
    /// permisos para quedarse solo con la clave es gasto puro.
    fn key_of(&self, pid: u32) -> Result<ProcessKey, ScalError>;

    /// PID de los hijos directos.
    fn children_of(&self, pid: u32) -> Result<Vec<u32>, ScalError>;

    /// Indica si el proceso identificado por `key` sigue vivo.
    ///
    /// Comprueba tambien la marca de arranque: un PID reciclado NO cuenta como
    /// vivo, que es justo la trampa que este metodo evita.
    fn is_alive(&self, key: ProcessKey) -> bool;

    /// Entrega los cambios de ciclo de vida ocurridos desde la ultima llamada.
    ///
    /// Espera como mucho `timeout`. Devolver un vector vacio es normal y no es
    /// un error.
    fn poll(&mut self, timeout: Duration) -> Result<Vec<ProcessEvent>, ScalError>;
}
