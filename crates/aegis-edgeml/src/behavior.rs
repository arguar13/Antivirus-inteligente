//! Extraccion de features de comportamiento a partir de una traza.
//!
//! El modelo no ve syscalls: ve un vector de 64 numeros que resume el
//! comportamiento. Este modulo construye ese vector, y su disposicion es un
//! ESPEJO EXACTO del generador del modelo (`tools/build_behavior_model.py`): si
//! un indice aqui no significa lo que alli, el modelo puntua sobre la feature
//! equivocada y el veredicto es basura sin dar ningun error. Por eso los indices
//! tienen nombre en los dos lados.

/// Dimension del vector de comportamiento. Debe coincidir con `DIM` del
/// generador del modelo.
pub const DIM: usize = 64;

// Frecuencias de categoria (normalizadas por el total de syscalls).
const F_OPEN: usize = 0;
const F_READ: usize = 1;
const F_WRITE: usize = 2;
const F_UNLINK: usize = 3;
const F_RENAME: usize = 4;
const F_PROC_CREATE: usize = 5;
const F_PTRACE: usize = 6;
const F_PROC_VM: usize = 7;
const F_MMAP_EXEC: usize = 8;
const F_MEMFD: usize = 9;
const F_NET: usize = 10;
const F_CHMOD: usize = 11;
const F_GETRANDOM: usize = 12;
// Ratios de comportamiento.
const R_WRITE_READ: usize = 16;
const R_UNLINK: usize = 17;
const R_WRITE_ENTROPY: usize = 18;
const R_BURST: usize = 19;
const R_DISTINCT_FILES: usize = 20;
// N-gramas caracteristicos (presencia 0/1).
const NG_ORWC: usize = 24;
const NG_ORW_UNLINK: usize = 25;
const NG_PTRACE_VMREAD: usize = 26;
const NG_MEMFD_EXECVE: usize = 27;
const NG_MPROTECT_EXEC: usize = 28;
const NG_SOCKET_EXECVE: usize = 29;
// Grafo de procesos.
const DAG_FANOUT: usize = 32;
const DAG_DEPTH: usize = 33;
const DAG_ORPHANS: usize = 34;
const DAG_SHORTLIVED: usize = 35;

/// La categoria de una syscall observada. Se agrupan por lo que SIGNIFICAN para
/// el comportamiento, no por el numero: `open` y `openat` cuentan igual.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatSyscall {
    /// Abrir un fichero (`open`/`openat`).
    Open,
    /// Leer.
    Read,
    /// Escribir.
    Write,
    /// Borrar (`unlink`/`unlinkat`).
    Unlink,
    /// Renombrar.
    Rename,
    /// Crear proceso (`fork`/`clone`/`execve`).
    ProcCreate,
    /// `ptrace`.
    Ptrace,
    /// Leer/escribir memoria de otro proceso (`process_vm_readv/writev`).
    ProcVm,
    /// Hacer memoria ejecutable (`mprotect` a `PROT_EXEC`, `mmap` con exec).
    MmapExec,
    /// `memfd_create`: memoria anonima ejecutable, sin fichero en disco.
    Memfd,
    /// Red (`socket`/`connect`/`send`).
    Net,
    /// Cambiar permisos (`chmod`/`chown`).
    Chmod,
    /// `getrandom` (en rafaga, senal de generacion de claves de cifrado).
    GetRandom,
    /// Cualquier otra: cuenta para el total pero no para ninguna categoria.
    Otra,
}

/// Una syscall observada.
#[derive(Debug, Clone, Copy)]
pub struct EventoSyscall {
    /// Su categoria de comportamiento.
    pub cat: CatSyscall,
    /// Para una escritura, la entropia normalizada [0,1] de los datos escritos;
    /// `None` para otras. Alta entropia en las escrituras es la firma del cifrado.
    pub entropia: Option<f32>,
}

impl EventoSyscall {
    /// Un evento de la categoria dada, sin dato de entropia.
    pub fn de(cat: CatSyscall) -> EventoSyscall {
        EventoSyscall {
            cat,
            entropia: None,
        }
    }
}

/// Rasgos del grafo de procesos (DAG) durante la ventana observada.
#[derive(Debug, Clone, Copy, Default)]
pub struct Dag {
    /// Maximo numero de hijos directos de un mismo proceso.
    pub fanout_max: u32,
    /// Profundidad maxima del arbol.
    pub profundidad: u32,
    /// Procesos reparentados a init (huerfanos): a menudo, desligarse para
    /// sobrevivir a la muerte del padre.
    pub huerfanos: u32,
    /// Procesos que vivieron muy poco (rafaga de spawns efimeros).
    pub efimeros: u32,
}

/// Una ventana de comportamiento observada de un proceso o arbol de procesos.
#[derive(Debug, Clone)]
pub struct Traza {
    /// Las syscalls, en orden temporal.
    pub eventos: Vec<EventoSyscall>,
    /// El grafo de procesos.
    pub dag: Dag,
    /// Duracion de la ventana en segundos (para la tasa de rafaga).
    pub duracion_seg: f32,
    /// Cuantos ficheros distintos se tocaron.
    pub ficheros_distintos: u32,
}

/// Construye el vector de 64 features a partir de una traza.
pub fn extraer(t: &Traza) -> [f32; DIM] {
    let mut v = [0.0f32; DIM];
    let n = t.eventos.len().max(1) as f32;

    // Conteos por categoria.
    let c = |cat: CatSyscall| t.eventos.iter().filter(|e| e.cat == cat).count() as f32;
    let n_read = c(CatSyscall::Read);
    let n_write = c(CatSyscall::Write);
    let n_unlink = c(CatSyscall::Unlink);

    v[F_OPEN] = c(CatSyscall::Open) / n;
    v[F_READ] = n_read / n;
    v[F_WRITE] = n_write / n;
    v[F_UNLINK] = n_unlink / n;
    v[F_RENAME] = c(CatSyscall::Rename) / n;
    v[F_PROC_CREATE] = c(CatSyscall::ProcCreate) / n;
    v[F_PTRACE] = c(CatSyscall::Ptrace) / n;
    v[F_PROC_VM] = c(CatSyscall::ProcVm) / n;
    v[F_MMAP_EXEC] = c(CatSyscall::MmapExec) / n;
    v[F_MEMFD] = c(CatSyscall::Memfd) / n;
    v[F_NET] = c(CatSyscall::Net) / n;
    v[F_CHMOD] = c(CatSyscall::Chmod) / n;
    v[F_GETRANDOM] = c(CatSyscall::GetRandom) / n;

    // Ratios.
    v[R_WRITE_READ] = if n_read > 0.0 {
        (n_write / n_read).min(2.0) / 2.0
    } else if n_write > 0.0 {
        1.0
    } else {
        0.0
    };
    v[R_UNLINK] = if n_write > 0.0 {
        (n_unlink / n_write).min(1.0)
    } else {
        0.0
    };
    // Entropia media de las escrituras: la firma del cifrado masivo.
    let entropias: Vec<f32> = t.eventos.iter().filter_map(|e| e.entropia).collect();
    v[R_WRITE_ENTROPY] = if entropias.is_empty() {
        0.0
    } else {
        entropias.iter().sum::<f32>() / entropias.len() as f32
    };
    v[R_BURST] = if t.duracion_seg > 0.0 {
        // Normalizado: mas de ~5000 syscalls/seg satura a 1.
        ((n / t.duracion_seg) / 5000.0).min(1.0)
    } else {
        0.0
    };
    v[R_DISTINCT_FILES] = (t.ficheros_distintos as f32 / 500.0).min(1.0);

    // N-gramas.
    let cats: Vec<CatSyscall> = t.eventos.iter().map(|e| e.cat).collect();
    v[NG_ORWC] = presencia(
        hay_secuencia(
            &cats,
            &[CatSyscall::Open, CatSyscall::Read, CatSyscall::Write],
        ) && n_unlink == 0.0,
    );
    v[NG_ORW_UNLINK] = presencia(hay_secuencia(
        &cats,
        &[
            CatSyscall::Open,
            CatSyscall::Read,
            CatSyscall::Write,
            CatSyscall::Unlink,
        ],
    ));
    v[NG_PTRACE_VMREAD] = presencia(hay_secuencia(
        &cats,
        &[CatSyscall::Ptrace, CatSyscall::ProcVm],
    ));
    v[NG_MEMFD_EXECVE] = presencia(hay_secuencia(
        &cats,
        &[CatSyscall::Memfd, CatSyscall::ProcCreate],
    ));
    v[NG_MPROTECT_EXEC] = presencia(cats.contains(&CatSyscall::MmapExec));
    v[NG_SOCKET_EXECVE] = presencia(hay_secuencia(
        &cats,
        &[CatSyscall::Net, CatSyscall::ProcCreate],
    ));

    // Grafo de procesos, normalizado.
    v[DAG_FANOUT] = (t.dag.fanout_max as f32 / 50.0).min(1.0);
    v[DAG_DEPTH] = (t.dag.profundidad as f32 / 20.0).min(1.0);
    v[DAG_ORPHANS] = (t.dag.huerfanos as f32 / 10.0).min(1.0);
    v[DAG_SHORTLIVED] = (t.dag.efimeros as f32 / 50.0).min(1.0);

    v
}

fn presencia(b: bool) -> f32 {
    if b {
        1.0
    } else {
        0.0
    }
}

/// `true` si `patron` aparece como subsecuencia EN ORDEN (no necesariamente
/// contigua) dentro de `cats`. Un ransomware intercala otras syscalls entre el
/// read y el unlink; lo que delata es el orden, no la contiguidad.
fn hay_secuencia(cats: &[CatSyscall], patron: &[CatSyscall]) -> bool {
    let mut i = 0;
    for &c in cats {
        if i < patron.len() && c == patron[i] {
            i += 1;
            if i == patron.len() {
                return true;
            }
        }
    }
    false
}
