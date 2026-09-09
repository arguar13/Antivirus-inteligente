//! Espejo en Rust del contrato de `aegis_kintegrity.h`.
//!
//! La disposicion en memoria es parte del contrato: el programa eBPF escribe
//! directamente en estas estructuras. Un campo desplazado no da un error de
//! compilacion, da veredictos de rootkit sobre procesos inocentes, asi que los
//! tamanos y desplazamientos se comprueban en tiempo de COMPILACION aqui y se
//! cotejan contra el compilador de C en `tools/abi-check.sh`.

/// Longitud de `comm` en el kernel, incluido el terminador.
pub const COMM_LEN: usize = 16;

/// Capacidad de los mapas de vista.
pub const MAX_TAREAS: u32 = 65_536;

/// Iteraciones maximas del barrido de PID en una invocacion.
pub const MAX_BARRIDO: u32 = 65_536;

/// `bpf_iter_task_new`: solo lideres de grupo de hilos.
pub const ITER_SOLO_PROCESOS: u32 = 0;
/// `bpf_iter_task_new`: todas las tareas, hilos incluidos.
pub const ITER_TODOS_LOS_HILOS: u32 = 1;

/// El programa recibio un puntero nulo.
pub const ERR_ARGS: i32 = -1;
/// El iterador de tareas no se pudo crear.
pub const ERR_ITERADOR: i32 = -2;

/// Retrato de una tarea vista por el kernel.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KiTask {
    /// Nanosegundos monotonos desde el arranque del sistema.
    pub start_boottime: u64,
    /// Grupo de hilos: el PID en terminologia de espacio de usuario.
    pub tgid: u32,
    /// Generacion del barrido que escribio la entrada.
    pub gen: u32,
    /// Reservado.
    pub flags: u32,
    /// Nombre corto de la tarea, terminado en NUL.
    pub comm: [u8; COMM_LEN],
    /// Relleno explicito.
    pub _pad: u32,
}

impl KiTask {
    /// Nombre corto como texto, sin el terminador.
    ///
    /// El kernel garantiza que `comm` es imprimible, pero no que sea UTF-8
    /// valido en todos los casos; se sustituye lo invalido en vez de fallar,
    /// porque el nombre es contexto para el analista, no una clave.
    pub fn comm_str(&self) -> String {
        let fin = self.comm.iter().position(|b| *b == 0).unwrap_or(COMM_LEN);
        String::from_utf8_lossy(&self.comm[..fin]).into_owned()
    }
}

/// Argumentos y resultados del barrido.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KiArgs {
    /// Primer PID del barrido.
    pub primero: i32,
    /// Ultimo PID del barrido, inclusive.
    pub ultimo: i32,
    /// Generacion; descarta entradas de barridos anteriores.
    pub gen: u32,
    /// Tareas vistas en la lista de tareas.
    pub en_lista: u32,
    /// Tareas halladas en el espacio de PID.
    pub en_pidmap: u32,
    /// Entradas que no cupieron en los mapas.
    pub desbordes: u32,
    /// 0, o uno de los `ERR_*`.
    pub error: i32,
    /// Relleno explicito.
    pub _pad: u32,
}

/// Confirmacion de un solo TID por los dos caminos.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KiConfirm {
    /// TID a confirmar.
    pub tid: i32,
    /// 1 si aparece en la lista de tareas.
    pub en_lista: u32,
    /// 1 si aparece en el espacio de PID.
    pub en_pidmap: u32,
    /// Grupo de hilos, si se pudo leer.
    pub tgid: u32,
    /// Instante de arranque, si se pudo leer.
    pub start_boottime: u64,
}

// Comprobaciones de disposicion. Si alguna falla, el programa eBPF y este
// espejo han divergido y la deteccion estaria leyendo campos equivocados.
const _: () = {
    use std::mem::{align_of, size_of};

    assert!(size_of::<KiTask>() == 40);
    assert!(align_of::<KiTask>() == 8);
    assert!(size_of::<KiArgs>() == 32);
    assert!(align_of::<KiArgs>() == 4);
    assert!(size_of::<KiConfirm>() == 24);
    assert!(align_of::<KiConfirm>() == 8);
};

/// Desplazamientos declarados, para que `tools/abi-check.sh` los coteje contra
/// los que calcula el compilador de C sobre la misma cabecera.
pub const OFFSETS: [(&str, &str, usize); 12] = [
    ("aegis_ki_task", "start_boottime", 0),
    ("aegis_ki_task", "tgid", 8),
    ("aegis_ki_task", "gen", 12),
    ("aegis_ki_task", "flags", 16),
    ("aegis_ki_task", "comm", 20),
    ("aegis_ki_args", "primero", 0),
    ("aegis_ki_args", "ultimo", 4),
    ("aegis_ki_args", "gen", 8),
    ("aegis_ki_args", "en_lista", 12),
    ("aegis_ki_confirm", "tid", 0),
    ("aegis_ki_confirm", "tgid", 12),
    ("aegis_ki_confirm", "start_boottime", 16),
];
