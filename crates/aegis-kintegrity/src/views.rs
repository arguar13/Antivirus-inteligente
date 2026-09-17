//! Las tres vistas del conjunto de tareas.
//!
//! # Por que tres y no dos
//!
//! Cada vista se obtiene de una estructura DISTINTA, y esa es toda la potencia
//! del metodo. Un rootkit tiene que manipular las tres de forma coherente para
//! esconderse, y manipular las tres es mucho mas dificil que manipular una:
//!
//! | Vista | De donde sale | Que la manipula |
//! |---|---|---|
//! | A `procfs` | `/proc/<pid>/task/<tid>` en Ring 3 | un hook de `getdents`, un `LD_PRELOAD`, un montaje encima de `/proc` |
//! | B lista de tareas | `bpf_iter_task_*` en Ring 0 | DKOM: desenlazar el `task_struct` |
//! | C espacio de PID | `bpf_task_from_pid()` en Ring 0 | borrar la entrada del `idr`, que dejaria al proceso sin poder recibir senales |
//!
//! # La trampa de la granularidad
//!
//! Las tres vistas tienen que ser de HILOS, no de procesos. `/proc/<pid>` de
//! primer nivel lista solo lideres de grupo de hilos, mientras que la lista de
//! tareas y el espacio de PID contienen una entrada por HILO. Comparar la
//! primera con las otras dos reportaria como oculto cada hilo de cada proceso
//! multihilo: cientos de falsos positivos criticos en la primera ejecucion, que
//! es la forma mas rapida de que alguien desinstale el producto.
//!
//! Por eso la vista A se construye recorriendo `/proc/<pid>/task/<tid>`.
//!
//! # La trampa del espacio de nombres
//!
//! Hay una segunda trampa, y se descubrio midiendo contra un kernel de verdad.
//! Las vistas B y C numeran en el espacio de nombres de PID **inicial**
//! —`bpf_iter_task` publica `task_struct.pid` y `bpf_task_from_pid()` busca en
//! `init_pid_ns`—; la vista A numera en el espacio de nombres del proceso que
//! lee `/proc`. Cuando no son el mismo, las tres dejan de hablar del mismo
//! conjunto de numeros, y **cada tarea aparece como una entrada de `/proc` que
//! el kernel no conoce**: un agente dentro de un contenedor acusaria a la
//! maquina entera de estar falsificada.
//!
//! El desempate es [`resuelve_el_kernel`], que pregunta por un tercer camino
//! —una llamada al sistema que resuelve el TID en el **mismo** espacio de
//! nombres que `/proc`— y separa «los dos lados numeran distinto» de «la entrada
//! esta falsificada».

use std::collections::BTreeMap;

/// Una tarea tal y como la ve una de las vistas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRecord {
    /// Identificador de hilo. Es la clave en las tres vistas.
    pub tid: u32,
    /// Grupo de hilos al que pertenece.
    pub tgid: u32,
    /// Instante de arranque en nanosegundos monotonos, si la vista lo conoce.
    ///
    /// Solo las vistas de KERNEL lo traen. `procfs` publica el arranque en
    /// tics de reloj, que es otra unidad y otra resolucion: mezclarlos daria
    /// diferencias de identidad falsas, asi que la vista A deja este campo a
    /// `None` y la comparacion entre A y las demas solo mira presencia.
    pub start_boottime: Option<u64>,
    /// Nombre corto, si la vista lo conoce.
    pub comm: Option<String>,
}

impl TaskRecord {
    /// Indica si la tarea es el lider de su grupo de hilos.
    pub fn es_lider(&self) -> bool {
        self.tid == self.tgid
    }
}

/// Conjunto de tareas visto desde un angulo.
pub type Vista = BTreeMap<u32, TaskRecord>;

/// Las tres vistas de un mismo instante.
#[derive(Debug, Clone, Default)]
pub struct ViewSet {
    /// Vista A: `/proc`, en espacio de usuario.
    pub procfs: Vista,
    /// Vista B: la lista de tareas del kernel.
    pub task_list: Vista,
    /// Vista C: el espacio de PID del kernel.
    pub pid_space: Vista,
    /// Entradas que no cupieron en los mapas del kernel.
    ///
    /// Distinto de cero significa que el barrido esta INCOMPLETO: cualquier
    /// ausencia podria deberse al desborde y no a una ocultacion, asi que el
    /// motor rebaja los veredictos en vez de acusar sobre datos truncados.
    pub desbordes: u32,
}

impl ViewSet {
    /// Indica si alguna vista de kernel se pudo tomar.
    pub fn tiene_vista_de_kernel(&self) -> bool {
        !self.task_list.is_empty() || !self.pid_space.is_empty()
    }
}

/// Lee la vista A recorriendo `/proc/<pid>/task/<tid>`.
///
/// Las desapariciones a mitad del recorrido se ignoran: en un sistema vivo los
/// hilos mueren constantemente, y un `ENOENT` al abrir un directorio que existia
/// hace un microsegundo es la condicion normal, no un error.
pub fn leer_procfs() -> Vista {
    let mut v = Vista::new();
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return v;
    };
    for entrada in dir.flatten() {
        let Some(nombre) = entrada.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(tgid) = nombre.parse::<u32>() else {
            continue;
        };
        let Ok(hilos) = std::fs::read_dir(format!("/proc/{tgid}/task")) else {
            continue;
        };
        for h in hilos.flatten() {
            let Some(n) = h.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Ok(tid) = n.parse::<u32>() else {
                continue;
            };
            v.insert(
                tid,
                TaskRecord {
                    tid,
                    tgid,
                    start_boottime: None,
                    comm: leer_comm(tgid, tid),
                },
            );
        }
    }
    v
}

/// Indica si el kernel resuelve `tid` **en el espacio de nombres de PID de este
/// proceso**, que es el mismo en el que `/proc` numera sus entradas.
///
/// # Por que hace falta una tercera forma de preguntar
///
/// Las dos vistas de kernel de este crate llegan por eBPF, y las dos numeran en
/// el espacio de nombres INICIAL: `bpf_iter_task` publica `task_struct.pid` y
/// `bpf_task_from_pid()` busca en `init_pid_ns`. La vista de `/proc`, en cambio,
/// numera en el espacio de nombres del proceso que lee. Cuando los dos no son el
/// mismo, las tres vistas dejan de hablar del mismo conjunto de numeros y **toda
/// comparacion pierde sentido**: un agente dentro de un contenedor acusaria a la
/// maquina entera de estar llena de procesos falsificados.
///
/// Esta funcion pregunta por el tercer camino: una llamada al sistema que
/// resuelve el TID con `find_task_by_vpid()`, es decir, en el MISMO espacio de
/// nombres que `/proc`. La respuesta separa dos cosas que hasta ahora se
/// confundian:
///
/// - `/proc` lo publica, el kernel lo resuelve por `vpid` y las vistas de eBPF
///   no lo tienen: los dos lados numeran distinto. No hay nada que concluir.
/// - `/proc` lo publica y el kernel **no lo conoce por ningun camino**: la
///   entrada de `/proc` esta falsificada. Eso si es una deteccion.
///
/// # Por que `sched_getscheduler` y no `kill(tid, 0)`
///
/// `kill` con senal 0 tambien resolveria el TID, pero pide permiso para senalar
/// —y con el, la posibilidad de equivocarse y senalar de verdad—. Consultar la
/// politica de planificacion no necesita privilegios, no tiene efecto sobre la
/// tarea y distingue `ESRCH` de cualquier otro error, que es exactamente lo que
/// se necesita.
pub fn resuelve_el_kernel(tid: u32) -> bool {
    // SAFETY: `sched_getscheduler` recibe un entero y no toca memoria del
    // proceso. El caso de `tid` = 0 —"yo mismo"— no llega aqui: el TID 0 esta
    // exento en `VerdictConfig` porque son las tareas ociosas por CPU.
    let r = unsafe { libc::sched_getscheduler(tid as libc::pid_t) };
    if r >= 0 {
        return true;
    }
    // Solo `ESRCH` significa "no existe". Un `EPERM` o cualquier otro fallo
    // significa que no se pudo saber, y no saber nunca se cuenta como ausencia:
    // seria construir una deteccion sobre un error de permisos.
    std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

/// Nombre corto de un hilo, de `/proc/<tgid>/task/<tid>/comm`.
pub(crate) fn leer_comm(tgid: u32, tid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{tgid}/task/{tid}/comm"))
        .ok()
        .map(|s| s.trim_end().to_owned())
}

/// Convierte un mapa del kernel en una vista.
pub fn desde_mapa(entradas: impl IntoIterator<Item = (u32, crate::abi::KiTask)>) -> Vista {
    entradas
        .into_iter()
        .map(|(tid, t)| {
            (
                tid,
                TaskRecord {
                    tid,
                    tgid: t.tgid,
                    start_boottime: Some(t.start_boottime),
                    comm: Some(t.comm_str()),
                },
            )
        })
        .collect()
}
