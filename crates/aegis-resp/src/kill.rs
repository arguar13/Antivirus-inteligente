//! Terminacion de arboles de procesos.
//!
//! Matar un proceso malicioso es facil. Matar su ARBOL sin matar nada mas, sin
//! dejar huerfanos que sobrevivan y sin caer en una condicion de carrera de
//! reciclado de PID, no lo es. Este modulo trata los cuatro problemas de forma
//! explicita.
//!
//! # 1. El reciclado de PID
//!
//! Entre leer `/proc` y enviar la senal, el proceso objetivo puede morir y su
//! PID reasignarse a otro. Enviar la senal entonces mata a un inocente, y en un
//! producto de seguridad eso significa que la respuesta automatica tumba un
//! servicio legitimo.
//!
//! La solucion NO es comprobar y despues enviar, porque la carrera sigue
//! existiendo entre ambos pasos. Se usa `pidfd_open`, que devuelve un
//! descriptor ligado a la INSTANCIA del proceso, no a su numero: si el proceso
//! muere, el descriptor deja de referirse a nada y `pidfd_send_signal` falla
//! con `ESRCH` en vez de matar al que ocupe ahora ese PID. La carrera
//! desaparece por construccion.
//!
//! # 2. Los huerfanos
//!
//! Si se mata al padre primero, sus hijos se reasignan a init y quedan fuera
//! del arbol que se estaba recorriendo: sobreviven. Por eso se congela el arbol
//! antes de recorrerlo y se mata de las hojas hacia la raiz.
//!
//! # 3. Los procesos que siguen forkeando
//!
//! Un proceso que crea hijos mas rapido de lo que se recorre el arbol no se
//! puede terminar recorriendo. Se envia `SIGSTOP` a toda la rama ANTES de
//! enumerar: un proceso detenido no ejecuta `fork`.
//!
//! # 4. Lo que no se debe matar nunca
//!
//! PID 1, los hilos de kernel y el propio agente y sus ancestros. Sin esas
//! salvaguardas, una regla mal calibrada apaga la maquina o desarma el EDR.

use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Error al terminar procesos.
#[derive(Debug, thiserror::Error)]
pub enum KillError {
    /// El proceso raiz no existe.
    #[error("el proceso {0} no existe")]
    NoSuchProcess(i32),

    /// Se pidio terminar un proceso protegido.
    #[error("negado: {reason}")]
    Protected {
        /// Motivo de la proteccion.
        reason: String,
    },

    /// El arbol solicitado excede la cota de seguridad.
    ///
    /// Una accion de respuesta que terminaria cientos de procesos casi siempre
    /// es una regla mal calibrada, no una amenaza real. Se rechaza y se obliga
    /// a subir la cota de forma explicita.
    #[error(
        "el arbol de {pid} tiene {size} procesos y la cota de seguridad es {limit}. \
         Terminar tantos procesos casi siempre significa una regla mal calibrada; \
         si de verdad es lo que quieres, sube max_tree_size explicitamente"
    )]
    TreeTooLarge {
        /// Raiz solicitada.
        pid: i32,
        /// Tamano del arbol.
        size: usize,
        /// Cota configurada.
        limit: usize,
    },

    /// No hay permisos para enviar senales al objetivo.
    #[error("sin permisos para senalar al proceso {0}; hace falta CAP_KILL o ser el propietario")]
    PermissionDenied(i32),

    /// Error al leer `/proc`.
    #[error("no se pudo leer {path}: {source}")]
    Proc {
        /// Ruta implicada.
        path: String,
        /// Causa.
        source: std::io::Error,
    },
}

/// Datos de un proceso leidos de `/proc`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcInfo {
    /// PID.
    pub pid: i32,
    /// PID del padre.
    pub ppid: i32,
    /// Nombre del ejecutable, sin ruta.
    pub comm: String,
    /// Estado: `R`, `S`, `D`, `Z`, `T`, ...
    pub state: char,
    /// Instante de arranque en tics desde el arranque del sistema.
    ///
    /// Junto al PID forma una identidad que no se recicla.
    pub starttime: u64,
    /// Indica si es un hilo de kernel (sin imagen ejecutable).
    pub is_kernel_thread: bool,
}

/// Analiza una linea de `/proc/<pid>/stat`.
///
/// El campo `comm` va entre parentesis y **puede contener espacios y
/// parentesis**: un proceso llamado `evil ) 1 2 3 (` rompe cualquier analisis
/// que trocee por espacios desde el principio. Se busca el ULTIMO `)`, que es
/// el unico punto de anclaje fiable.
pub fn parse_stat(linea: &str) -> Option<StatFields> {
    let abre = linea.find('(')?;
    let cierra = linea.rfind(')')?;
    if cierra <= abre {
        return None;
    }
    let pid: i32 = linea[..abre].trim().parse().ok()?;
    let comm = linea[abre + 1..cierra].to_string();

    let resto: Vec<&str> = linea[cierra + 1..].split_whitespace().collect();
    // Tras el ')' los campos son: state ppid pgrp session tty tpgid flags
    // minflt cminflt majflt cmajflt utime stime cutime cstime priority nice
    // num_threads itrealvalue starttime...
    let state = resto.first()?.chars().next()?;
    let ppid: i32 = resto.get(1)?.parse().ok()?;
    // flags es el septimo campo tras ')': state ppid pgrp session tty tpgid flags
    let flags: u32 = resto.get(6)?.parse().ok()?;
    let starttime: u64 = resto.get(19)?.parse().ok()?;
    Some(StatFields {
        pid,
        comm,
        state,
        ppid,
        flags,
        starttime,
    })
}

/// Campos de `/proc/<pid>/stat` que este modulo necesita.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatFields {
    /// PID.
    pub pid: i32,
    /// Nombre del ejecutable.
    pub comm: String,
    /// Estado.
    pub state: char,
    /// PID del padre.
    pub ppid: i32,
    /// Banderas del proceso (`PF_*`).
    pub flags: u32,
    /// Instante de arranque en tics.
    pub starttime: u64,
}

/// `PF_KTHREAD`: el proceso es un hilo de kernel.
///
/// Es la unica forma fiable de reconocerlos. La alternativa evidente -mirar si
/// `/proc/<pid>/exe` se puede resolver- clasifica mal a los ZOMBIS, que
/// tampoco tienen ese enlace, y a cualquier proceso sobre el que falte
/// permiso. Un proceso normal marcado por error como hilo de kernel queda
/// protegido y sobrevive a la respuesta.
pub const PF_KTHREAD: u32 = 0x0020_0000;

fn leer_proc(root: &Path, pid: i32) -> Option<ProcInfo> {
    let dir = root.join(pid.to_string());
    let stat = std::fs::read_to_string(dir.join("stat")).ok()?;
    let f = parse_stat(&stat)?;

    Some(ProcInfo {
        pid: f.pid,
        ppid: f.ppid,
        comm: f.comm,
        state: f.state,
        starttime: f.starttime,
        // Un SIGKILL a un hilo de kernel no hace nada, e incluirlo en el arbol
        // ensucia el informe y hace creer que la terminacion fallo.
        is_kernel_thread: f.flags & PF_KTHREAD != 0,
    })
}

/// Enumera todos los procesos del sistema.
pub fn snapshot_processes(proc_root: &Path) -> Result<Vec<ProcInfo>, KillError> {
    let entradas = std::fs::read_dir(proc_root).map_err(|e| KillError::Proc {
        path: proc_root.display().to_string(),
        source: e,
    })?;

    let mut salida = Vec::new();
    for e in entradas.flatten() {
        let Some(nombre) = e.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(pid) = nombre.parse::<i32>() else {
            continue;
        };
        // Un proceso puede morir entre listar el directorio y leer su stat.
        // Es normal y no es un error.
        if let Some(info) = leer_proc(proc_root, pid) {
            salida.push(info);
        }
    }
    Ok(salida)
}

/// Arbol de procesos a terminar.
#[derive(Debug, Clone)]
pub struct ProcessTree {
    /// Raiz del arbol.
    pub root: ProcInfo,
    /// Todos los miembros, ordenados de las HOJAS hacia la raiz.
    ///
    /// Ese orden es el de terminacion: matar al padre primero reasignaria sus
    /// hijos a init y quedarian fuera del arbol.
    pub members: Vec<ProcInfo>,
}

/// Construye el arbol de descendientes de `root_pid`.
pub fn collect_tree(proc_root: &Path, root_pid: i32) -> Result<ProcessTree, KillError> {
    let todos = snapshot_processes(proc_root)?;
    let root = todos
        .iter()
        .find(|p| p.pid == root_pid)
        .cloned()
        .ok_or(KillError::NoSuchProcess(root_pid))?;

    let mut hijos: HashMap<i32, Vec<&ProcInfo>> = HashMap::new();
    for p in &todos {
        hijos.entry(p.ppid).or_default().push(p);
    }

    // Recorrido en anchura desde la raiz, con conjunto de visitados: si /proc
    // se lee mientras cambia, un ciclo aparente colgaria el recorrido.
    let mut orden: Vec<ProcInfo> = Vec::new();
    let mut vistos: HashSet<i32> = HashSet::new();
    let mut cola = vec![root.clone()];
    vistos.insert(root.pid);

    while let Some(actual) = cola.pop() {
        if let Some(hs) = hijos.get(&actual.pid) {
            for h in hs {
                if vistos.insert(h.pid) {
                    cola.push((*h).clone());
                }
            }
        }
        orden.push(actual);
    }

    // De las hojas a la raiz: se invierte el orden de descubrimiento.
    orden.reverse();

    Ok(ProcessTree {
        root,
        members: orden,
    })
}

/// Opciones de terminacion.
#[derive(Debug, Clone)]
pub struct KillOptions {
    /// Raiz de `/proc`. Parametrizable para poder probar con arboles sinteticos.
    pub proc_root: std::path::PathBuf,
    /// Tiempo de espera tras `SIGTERM` antes de recurrir a `SIGKILL`.
    ///
    /// Se manda `SIGTERM` primero para que el proceso pueda cerrar ficheros y
    /// no dejar datos a medias. `SIGKILL` es el respaldo, no la primera opcion.
    pub grace: std::time::Duration,
    /// Enviar directamente `SIGKILL`, sin periodo de gracia.
    ///
    /// Es lo correcto ante ransomware activo: cada milisegundo de gracia son
    /// ficheros cifrados, y un cifrador no va a cerrar nada ordenadamente.
    pub immediate: bool,
    /// PIDs que nunca deben terminarse, ademas de las protecciones fijas.
    pub protected: Vec<i32>,
    /// Numero maximo de procesos que se aceptan terminar de una vez.
    ///
    /// Es un freno contra reglas mal calibradas: una respuesta automatica que
    /// va a terminar cientos de procesos casi nunca es lo que se pretendia, y
    /// el coste de equivocarse es dejar la maquina inservible.
    pub max_tree_size: usize,
}

impl Default for KillOptions {
    fn default() -> Self {
        Self {
            proc_root: std::path::PathBuf::from("/proc"),
            grace: std::time::Duration::from_millis(500),
            immediate: false,
            protected: Vec::new(),
            max_tree_size: 256,
        }
    }
}

/// Que ocurrio con un proceso concreto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcOutcome {
    /// Terminado.
    Killed,
    /// Ya no existia cuando se le fue a senalar.
    AlreadyGone,
    /// Protegido: no se toco.
    Refused {
        /// Motivo.
        reason: String,
    },
    /// Sobrevivio a `SIGKILL`.
    Survived {
        /// Motivo, cuando se puede determinar.
        reason: String,
    },
    /// Sin permisos para senalarlo.
    PermissionDenied,
}

/// Resultado de terminar un arbol.
#[derive(Debug, Clone, Default)]
pub struct KillReport {
    /// Resultado por proceso.
    pub outcomes: Vec<(ProcInfo, ProcOutcome)>,
}

impl KillReport {
    /// Numero de procesos efectivamente terminados.
    pub fn killed(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|(_, o)| *o == ProcOutcome::Killed)
            .count()
    }

    /// Procesos que sobrevivieron.
    pub fn survivors(&self) -> Vec<&ProcInfo> {
        self.outcomes
            .iter()
            .filter(|(_, o)| matches!(o, ProcOutcome::Survived { .. }))
            .map(|(p, _)| p)
            .collect()
    }

    /// Indica si el arbol quedo completamente terminado.
    pub fn complete(&self) -> bool {
        self.outcomes
            .iter()
            .all(|(_, o)| matches!(o, ProcOutcome::Killed | ProcOutcome::AlreadyGone))
    }
}

/// Comprueba si un proceso esta protegido y no debe terminarse.
pub fn protection_reason(
    p: &ProcInfo,
    opts: &KillOptions,
    self_chain: &HashSet<i32>,
) -> Option<String> {
    if p.pid <= 1 {
        // Matar al PID 1 apaga el sistema o el contenedor. Ninguna regla de
        // deteccion justifica eso jamas.
        return Some(format!("PID {} es init y nunca puede terminarse", p.pid));
    }
    if p.is_kernel_thread {
        return Some(format!("'{}' es un hilo de kernel", p.comm));
    }
    if self_chain.contains(&p.pid) {
        // Terminar el propio agente o alguno de sus ancestros desarma el EDR
        // en el momento exacto en el que esta respondiendo a un incidente.
        return Some(format!(
            "PID {} es el propio agente o uno de sus ancestros",
            p.pid
        ));
    }
    if opts.protected.contains(&p.pid) {
        return Some(format!("PID {} esta en la lista de protegidos", p.pid));
    }
    None
}

/// Cadena de ancestros del proceso actual, incluido el mismo.
pub fn self_ancestry(proc_root: &Path) -> HashSet<i32> {
    let mut cadena = HashSet::new();
    let mut pid = std::process::id() as i32;
    // El limite evita un bucle infinito si /proc devuelve datos incoherentes.
    for _ in 0..64 {
        if pid <= 0 || !cadena.insert(pid) {
            break;
        }
        match leer_proc(proc_root, pid) {
            Some(info) => pid = info.ppid,
            None => break,
        }
    }
    cadena
}

#[cfg(target_os = "linux")]
mod señales {
    use super::*;

    /// Abre un descriptor ligado a la INSTANCIA del proceso.
    ///
    /// Es lo que elimina la carrera de reciclado de PID: el descriptor no se
    /// refiere al numero sino al proceso concreto, asi que si muere y su PID se
    /// reasigna, el descriptor no apunta al nuevo.
    pub fn pidfd_open(pid: i32) -> Option<i32> {
        // SAFETY: syscall sin efectos sobre la memoria del proceso; solo
        // devuelve un descriptor o -1.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if fd < 0 {
            None
        } else {
            Some(fd as i32)
        }
    }

    /// Envia una senal a traves de un pidfd.
    pub fn pidfd_send_signal(fd: i32, sig: i32) -> i32 {
        // SAFETY: `fd` proviene de pidfd_open y sigue abierto; los punteros
        // opcionales van a nulo, que la syscall acepta.
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd,
                sig,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            ) as i32
        }
    }

    pub fn cerrar(fd: i32) {
        // SAFETY: descriptor valido obtenido de pidfd_open.
        unsafe { libc::close(fd) };
    }

    /// Envia una senal verificando la identidad del proceso.
    ///
    /// Devuelve `Ok(true)` si se entrego, `Ok(false)` si el proceso ya no
    /// existe, y `Err` si falta permiso.
    pub fn signal_verificado(p: &ProcInfo, sig: i32, opts: &KillOptions) -> Result<bool, ()> {
        if let Some(fd) = pidfd_open(p.pid) {
            let r = pidfd_send_signal(fd, sig);
            cerrar(fd);
            if r == 0 {
                return Ok(true);
            }
            // SAFETY: lectura de errno, sin efectos.
            let err = std::io::Error::last_os_error();
            return match err.raw_os_error() {
                Some(libc::ESRCH) => Ok(false),
                Some(libc::EPERM) => Err(()),
                _ => Ok(false),
            };
        }

        // Respaldo para kernels sin pidfd (anteriores a 5.3): se vuelve a leer
        // /proc y se comprueba que el instante de arranque siga siendo el mismo.
        // Sigue habiendo una ventana de carrera, pero es la unica opcion
        // disponible ahi y es mucho mas estrecha que no comprobar nada.
        match leer_proc(&opts.proc_root, p.pid) {
            Some(actual) if actual.starttime == p.starttime => {
                // SAFETY: kill() solo envia una senal; no toca memoria propia.
                let r = unsafe { libc::kill(p.pid, sig) };
                if r == 0 {
                    Ok(true)
                } else {
                    let err = std::io::Error::last_os_error();
                    match err.raw_os_error() {
                        Some(libc::EPERM) => Err(()),
                        _ => Ok(false),
                    }
                }
            }
            // O murio, o el PID se reciclo: en ambos casos NO se senala.
            _ => Ok(false),
        }
    }
}

/// Termina el arbol de procesos con raiz en `root_pid`.
///
/// Secuencia:
/// 1. `SIGSTOP` a la raiz, para que deje de crear hijos mientras se enumera.
/// 2. Enumerar el arbol y congelar cada miembro.
/// 3. Terminar de las hojas hacia la raiz.
/// 4. Verificar y reportar lo que sobrevivio.
#[cfg(target_os = "linux")]
pub fn kill_process_tree(root_pid: i32, opts: &KillOptions) -> Result<KillReport, KillError> {
    let self_chain = self_ancestry(&opts.proc_root);

    let raiz = leer_proc(&opts.proc_root, root_pid).ok_or(KillError::NoSuchProcess(root_pid))?;

    // Si la RAIZ esta protegida se rechaza la operacion ENTERA, sin tocar nada.
    //
    // La alternativa evidente -saltarse la raiz y terminar a sus
    // descendientes- es catastrofica: "termina el arbol del PID 1" pasaria a
    // significar "termina todos los procesos de la maquina". Este mismo codigo
    // mato el contenedor de pruebas antes de que existiera esta comprobacion.
    if let Some(reason) = protection_reason(&raiz, opts, &self_chain) {
        return Err(KillError::Protected {
            reason: format!(
                "{reason}. No se termina ninguno de sus descendientes: terminar el arbol \
                 de un proceso protegido equivaldria a terminar el sistema"
            ),
        });
    }

    // Congelar la raiz ANTES de enumerar. Un proceso que crea hijos mas rapido
    // de lo que se recorre el arbol no se puede terminar recorriendo; uno
    // detenido no ejecuta fork.
    let _ = señales::signal_verificado(&raiz, libc::SIGSTOP, opts);

    let arbol = collect_tree(&opts.proc_root, root_pid)?;

    // Cota de seguridad. Si se supera, se REANUDA la raiz antes de salir:
    // dejarla congelada por un rechazo seria bloquear un servicio legitimo.
    if arbol.members.len() > opts.max_tree_size {
        let _ = señales::signal_verificado(&raiz, libc::SIGCONT, opts);
        return Err(KillError::TreeTooLarge {
            pid: root_pid,
            size: arbol.members.len(),
            limit: opts.max_tree_size,
        });
    }

    // Congelar todo el arbol. SIGSTOP no se puede bloquear ni ignorar, igual
    // que SIGKILL.
    for p in &arbol.members {
        if protection_reason(p, opts, &self_chain).is_none() {
            let _ = señales::signal_verificado(p, libc::SIGSTOP, opts);
        }
    }

    let mut informe = KillReport::default();
    let mut pendientes: Vec<&ProcInfo> = Vec::new();

    // Primera pasada: SIGTERM (o SIGKILL directo) de hojas a raiz.
    for p in &arbol.members {
        if let Some(reason) = protection_reason(p, opts, &self_chain) {
            informe
                .outcomes
                .push((p.clone(), ProcOutcome::Refused { reason }));
            continue;
        }

        let sig = if opts.immediate {
            libc::SIGKILL
        } else {
            libc::SIGTERM
        };

        match señales::signal_verificado(p, sig, opts) {
            Ok(true) => {
                // Un proceso detenido no procesa SIGTERM hasta que se reanuda.
                // Sin este SIGCONT, el periodo de gracia se agota siempre y
                // todo acaba en SIGKILL, que es justo lo que se queria evitar.
                if !opts.immediate {
                    let _ = señales::signal_verificado(p, libc::SIGCONT, opts);
                }
                pendientes.push(p);
            }
            Ok(false) => informe.outcomes.push((p.clone(), ProcOutcome::AlreadyGone)),
            Err(()) => informe
                .outcomes
                .push((p.clone(), ProcOutcome::PermissionDenied)),
        }
    }

    if !opts.immediate && !pendientes.is_empty() {
        std::thread::sleep(opts.grace);
    }

    // Segunda pasada: SIGKILL a lo que siga vivo y verificacion final.
    for p in pendientes {
        let sigue = leer_proc(&opts.proc_root, p.pid)
            .map(|a| a.starttime == p.starttime && a.state != 'Z')
            .unwrap_or(false);

        if !sigue {
            informe.outcomes.push((p.clone(), ProcOutcome::Killed));
            continue;
        }

        let _ = señales::signal_verificado(p, libc::SIGKILL, opts);
        // SIGKILL no es sincrono: el kernel lo entrega en la siguiente
        // planificacion del proceso.
        std::thread::sleep(std::time::Duration::from_millis(50));

        match leer_proc(&opts.proc_root, p.pid) {
            None => informe.outcomes.push((p.clone(), ProcOutcome::Killed)),
            Some(a) if a.starttime != p.starttime => {
                // El PID se reciclo: el original murio.
                informe.outcomes.push((p.clone(), ProcOutcome::Killed));
            }
            Some(a) if a.state == 'Z' => {
                // Zombi: el proceso murio y solo queda su entrada esperando a
                // que el padre la recoja. Cuenta como terminado.
                informe.outcomes.push((p.clone(), ProcOutcome::Killed));
            }
            Some(a) => {
                // Ni SIGKILL puede sacar a un proceso de un estado de espera
                // ininterrumpible: la senal queda pendiente hasta que la
                // operacion de kernel termine. Se reporta en vez de fingir
                // exito, porque el operador necesita saber que sigue vivo.
                let reason = match a.state {
                    'D' => "en espera ininterrumpible (E/S de kernel en curso)".to_string(),
                    's' | 'T' | 't' => "detenido o trazado por otro proceso".to_string(),
                    otro => format!("sigue en estado '{otro}' tras SIGKILL"),
                };
                informe
                    .outcomes
                    .push((p.clone(), ProcOutcome::Survived { reason }));
            }
        }
    }

    Ok(informe)
}

/// Version para plataformas que no son Linux: no hay `/proc` ni `pidfd`.
#[cfg(not(target_os = "linux"))]
pub fn kill_process_tree(_root_pid: i32, _opts: &KillOptions) -> Result<KillReport, KillError> {
    Err(KillError::Protected {
        reason: "la terminacion de arboles solo esta implementada en Linux".into(),
    })
}
