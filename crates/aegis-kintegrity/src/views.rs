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

/// Nombre corto de un hilo, de `/proc/<tgid>/task/<tid>/comm`.
fn leer_comm(tgid: u32, tid: u32) -> Option<String> {
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
