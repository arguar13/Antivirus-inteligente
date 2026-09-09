//! Ciclo de vida de procesos en Linux, sobre `procfs`.
//!
//! Este backend es la via UNIVERSAL: funciona en cualquier kernel, sin BTF, sin
//! privilegios especiales y dentro de un contenedor. No es la via rapida —los
//! eventos se obtienen comparando dos censos de `/proc`, con la latencia y el
//! punto ciego que eso implica— y por eso [`Capabilities`] la declara como
//! degradada. Cuando hay eBPF, el agente sustituye la mitad de eventos por la
//! nativa y conserva esta para las consultas.
//!
//! El punto ciego es concreto y hay que decirlo: un proceso que nace y muere
//! entre dos censos no se ve. Con el intervalo por defecto son 250 ms, que
//! bastan para un `curl` de un atacante pero no para un `id` en un script.
//!
//! [`Capabilities`]: crate::Capabilities

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

use crate::error::ScalError;
use crate::platform::Platform;
use crate::process::{
    ProcessEvent, ProcessInfo, ProcessKey, ProcessLifecycleProvider, ProcessState,
};

/// Intervalo por defecto entre censos de `/proc`.
///
/// 250 ms es el compromiso medido: por debajo, el censo de una maquina con
/// cientos de procesos empieza a notarse en la CPU del agente; por encima, se
/// pierden cadenas cortas de shell, que son justo las que interesan.
pub const CENSO_POR_DEFECTO: Duration = Duration::from_millis(250);

/// Analiza `/proc/<pid>/stat` y devuelve `(estado, ppid, hilos, arranque)`.
///
/// El nombre del ejecutable va entre parentesis en el segundo campo y PUEDE
/// contener espacios y parentesis: `(my (weird) proc)` es un nombre valido.
/// Trocear la linea por espacios desde el principio es el error clasico de este
/// analizador, y produce un `ppid` aleatorio en cuanto alguien nombra asi un
/// binario. Por eso se busca el ULTIMO `)` y se trocea a partir de ahi.
pub fn parse_stat(linea: &str) -> Option<(ProcessState, u32, u32, u64)> {
    let cierre = linea.rfind(')')?;
    let resto = linea.get(cierre + 1..)?;
    let campos: Vec<&str> = resto.split_whitespace().collect();
    // Tras el `)` el primer campo es `state`, que es el numero 3 del formato:
    // el indice de un campo N del manual es N - 3.
    let estado = match campos.first()?.as_bytes().first() {
        Some(b'R') => ProcessState::Running,
        Some(b'S') => ProcessState::Sleeping,
        Some(b'D') => ProcessState::Uninterruptible,
        Some(b'T') | Some(b't') => ProcessState::Stopped,
        Some(b'Z') => ProcessState::Zombie,
        _ => ProcessState::Other,
    };
    let ppid = campos.get(1)?.parse::<u32>().ok()?;
    let hilos = campos
        .get(17)
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(1);
    let arranque = campos.get(19)?.parse::<u64>().ok()?;
    Some((estado, ppid, hilos, arranque))
}

/// Trocea `/proc/<pid>/cmdline`, que va separado por NUL.
///
/// Un proceso puede tener la linea de comandos vacia (hilos de kernel) o
/// haberla reescrito a un solo bloque sin NUL (lo hacen los servidores que
/// cambian su titulo); ambos casos se devuelven tal cual en vez de inventar
/// argumentos.
pub fn parse_cmdline(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

fn leer_stat(pid: u32) -> Result<(ProcessState, u32, u32, u64), ScalError> {
    let texto = std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            ScalError::NoSuchProcess(pid)
        } else {
            ScalError::Os {
                op: "leer /proc/<pid>/stat",
                source: e,
            }
        }
    })?;
    parse_stat(&texto).ok_or(ScalError::NoSuchProcess(pid))
}

/// Proveedor de ciclo de vida basado en `procfs`.
///
/// Guarda el censo anterior para poder entregar diferencias. El censo se toma
/// YA en la construccion, de modo que la primera llamada a
/// [`ProcessLifecycleProvider::poll`] no reporte como "arrancados" los cientos
/// de procesos que ya existian: un motor conductual que reciba esa avalancha en
/// el arranque escala todo lo que hay en la maquina.
#[derive(Debug)]
pub struct ProcFsProcesses {
    censo: HashMap<u32, u64>,
    intervalo: Duration,
}

impl ProcFsProcesses {
    /// Crea el proveedor tomando el censo inicial.
    pub fn new() -> ProcFsProcesses {
        ProcFsProcesses::con_intervalo(CENSO_POR_DEFECTO)
    }

    /// Crea el proveedor con un intervalo de censo concreto.
    pub fn con_intervalo(intervalo: Duration) -> ProcFsProcesses {
        let mut p = ProcFsProcesses {
            censo: HashMap::new(),
            intervalo,
        };
        p.censo = p.censar();
        p
    }

    /// Numero de procesos en el ultimo censo.
    pub fn censados(&self) -> usize {
        self.censo.len()
    }

    /// Da por censado un proceso cuya existencia se supo por OTRA via.
    ///
    /// Existe para que un origen mas rapido —la sonda de eBPF del agente—
    /// pueda adelantarse al censo sin que el censo vuelva a reportar el mismo
    /// nacimiento unos milisegundos despues. Sin esta reconciliacion, combinar
    /// las dos fuentes duplica cada evento, y un motor conductual que cuente
    /// dos veces la misma cadena escala el doble de rapido de lo calibrado.
    pub fn reconciliar_alta(&mut self, key: ProcessKey) {
        self.censo.insert(key.pid, key.start_stamp);
    }

    /// Retira del censo un proceso cuya muerte se supo por OTRA via.
    ///
    /// Solo retira si la marca de arranque coincide: si el PID ya fue
    /// reutilizado por un proceso nuevo, borrarlo del censo haria que el
    /// siguiente censo lo reportara como recien nacido por segunda vez.
    pub fn reconciliar_baja(&mut self, key: ProcessKey) {
        if self.censo.get(&key.pid) == Some(&key.start_stamp) {
            self.censo.remove(&key.pid);
        }
    }

    /// PID de todos los procesos vivos, sin construir sus retratos.
    fn pids(&self) -> Vec<u32> {
        let Ok(dir) = std::fs::read_dir("/proc") else {
            return Vec::new();
        };
        dir.flatten()
            .filter_map(|e| e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()))
            .collect()
    }

    /// Censo actual: PID -> marca de arranque.
    fn censar(&self) -> HashMap<u32, u64> {
        let mut m = HashMap::new();
        for pid in self.pids() {
            // Un proceso que muere entre listar `/proc` y leer su `stat` es la
            // condicion normal; se omite y ya esta.
            if let Ok((_, _, _, arranque)) = leer_stat(pid) {
                m.insert(pid, arranque);
            }
        }
        m
    }

    /// Toma un censo y devuelve las diferencias contra el anterior.
    fn diferencias(&mut self) -> Vec<ProcessEvent> {
        let nuevo = self.censar();
        let mut eventos = Vec::new();

        for (pid, arranque) in &nuevo {
            // Un PID que estaba pero con OTRA marca de arranque no es el mismo
            // proceso: es un reciclado, y hay que emitir la muerte del viejo y
            // el nacimiento del nuevo. Tratarlo como continuidad es como se
            // hereda el historial de un proceso a otro.
            match self.censo.get(pid) {
                Some(anterior) if anterior == arranque => continue,
                Some(anterior) => eventos.push(ProcessEvent::Exited {
                    key: ProcessKey::new(*pid, *anterior),
                    exit_code: None,
                }),
                None => {}
            }
            if let Ok(info) = self.info(*pid) {
                // Se comprueba que el retrato corresponde al proceso censado:
                // si murio y otro ocupo el PID entre ambas lecturas, el retrato
                // seria del intruso.
                if info.key.start_stamp == *arranque {
                    eventos.push(ProcessEvent::Started(Box::new(info)));
                }
            }
        }

        for (pid, arranque) in &self.censo {
            if !nuevo.contains_key(pid) {
                eventos.push(ProcessEvent::Exited {
                    key: ProcessKey::new(*pid, *arranque),
                    exit_code: None,
                });
            }
        }

        self.censo = nuevo;
        eventos
    }
}

impl Default for ProcFsProcesses {
    fn default() -> Self {
        ProcFsProcesses::new()
    }
}

impl ProcessLifecycleProvider for ProcFsProcesses {
    fn platform(&self) -> Platform {
        Platform::Linux
    }

    fn list(&self) -> Result<Vec<ProcessInfo>, ScalError> {
        Ok(self
            .pids()
            .into_iter()
            .filter_map(|p| self.info(p).ok())
            .collect())
    }

    fn info(&self, pid: u32) -> Result<ProcessInfo, ScalError> {
        let (state, parent_pid, threads, arranque) = leer_stat(pid)?;

        // El propietario se toma de los metadatos del directorio `/proc/<pid>`,
        // que el kernel mantiene con el uid/gid EFECTIVOS. Sale de una llamada
        // en vez de analizar `status`, que son cincuenta lineas de texto.
        let (uid, gid) = match std::fs::metadata(format!("/proc/{pid}")) {
            Ok(m) => (m.uid(), m.gid()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(ScalError::NoSuchProcess(pid))
            }
            Err(_) => (0, 0),
        };

        // `exe` falta de forma legitima en hilos de kernel y en procesos de
        // otro usuario sin permiso: es `None`, no un error.
        let image = std::fs::read_link(format!("/proc/{pid}/exe")).ok();

        let cmdline = std::fs::read(format!("/proc/{pid}/cmdline"))
            .map(|b| parse_cmdline(&b))
            .unwrap_or_default();

        Ok(ProcessInfo {
            key: ProcessKey::new(pid, arranque),
            parent_pid,
            image,
            cmdline,
            uid,
            gid,
            threads,
            state,
        })
    }

    fn key_of(&self, pid: u32) -> Result<ProcessKey, ScalError> {
        let (_, _, _, arranque) = leer_stat(pid)?;
        Ok(ProcessKey::new(pid, arranque))
    }

    fn children_of(&self, pid: u32) -> Result<Vec<u32>, ScalError> {
        // Se recorre el censo entero y no `/proc/<pid>/task/*/children`: ese
        // fichero solo existe con CONFIG_PROC_CHILDREN y no lista los hijos que
        // ya fueron reasignados a init, que son justo los que un atacante deja
        // atras al desligar su proceso.
        let mut hijos = Vec::new();
        for candidato in self.pids() {
            if candidato == pid {
                continue;
            }
            if let Ok((_, ppid, _, _)) = leer_stat(candidato) {
                if ppid == pid {
                    hijos.push(candidato);
                }
            }
        }
        hijos.sort_unstable();
        Ok(hijos)
    }

    fn is_alive(&self, key: ProcessKey) -> bool {
        matches!(leer_stat(key.pid), Ok((_, _, _, a)) if a == key.start_stamp)
    }

    fn poll(&mut self, timeout: Duration) -> Result<Vec<ProcessEvent>, ScalError> {
        let limite = Instant::now() + timeout;
        loop {
            let eventos = self.diferencias();
            if !eventos.is_empty() {
                return Ok(eventos);
            }
            let ahora = Instant::now();
            if ahora >= limite {
                return Ok(Vec::new());
            }
            std::thread::sleep(self.intervalo.min(limite - ahora));
        }
    }
}
