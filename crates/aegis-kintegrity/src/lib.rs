//! # aegis-kintegrity
//!
//! Verificacion cruzada de la integridad del kernel: deteccion de rootkits que
//! esconden procesos.
//!
//! # El problema
//!
//! Un rootkit de kernel que hace DKOM (*Direct Kernel Object Manipulation*)
//! desenlaza el `task_struct` de su proceso de la lista global de tareas. Desde
//! ese momento el proceso es invisible para todo lo que recorra esa lista
//! —`/proc`, `ps`, `top` y cualquier EDR que pregunte al sistema— pero **sigue
//! ejecutandose**, porque el planificador no usa esa lista.
//!
//! Preguntarle mejor al sistema no sirve: el sistema es justo lo que esta
//! comprometido. Lo que sirve es preguntar por CAMINOS DISTINTOS y comparar.
//!
//! # Las tres vistas
//!
//! | Vista | De donde sale | Que la manipula |
//! |---|---|---|
//! | **A** `procfs` | `/proc/<pid>/task/<tid>`, Ring 3 | hook de `getdents`, `LD_PRELOAD`, montaje sobre `/proc` |
//! | **B** lista de tareas | `bpf_iter_task_*`, Ring 0 | DKOM: desenlazar el `task_struct` |
//! | **C** espacio de PID | `bpf_task_from_pid()`, Ring 0 | borrar del `idr`, que deja al proceso sin recibir senales |
//!
//! Las dos vistas de kernel se toman en **una sola invocacion** del programa
//! eBPF, separadas por microsegundos: tomarlas en dos llamadas distintas deja
//! una ventana de milisegundos que produce discrepancias falsas en cada barrido.
//! Cada invocacion abarca un tramo de 65536 PID, y el espacio entero —hasta
//! 4194304 con el `pid_max` de Ubuntu y Fedora— se cubre por tramos, con
//! presupuesto y rotacion: ver [`tramos`].
//!
//! # Las tres trampas que hacen inutil a un detector asi
//!
//! 1. **La granularidad.** `/proc/<pid>` de primer nivel lista solo lideres de
//!    grupo de hilos; las vistas de kernel traen una entrada por HILO. Comparar
//!    la una con las otras reporta como oculto cada hilo de cada proceso
//!    multihilo: cientos de falsos positivos criticos en el primer barrido. Las
//!    tres vistas son de hilos.
//! 2. **La carrera.** Entre vista y vista los procesos mueren. Cada
//!    discrepancia se CONFIRMA volviendo a mirar ese TID por los dos caminos
//!    antes de acusar a nadie, y ademas tiene que repetirse en barridos
//!    consecutivos.
//! 3. **Las tareas ociosas.** Tienen PID 0, no salen en `/proc` y
//!    `bpf_task_from_pid(0)` no las resuelve: sin excluirlas, cada barrido
//!    reporta una anomalia por CPU.
//!
//! # Que se prueba sin kernel
//!
//! Todo lo que DECIDE. [`verdict`] y [`engine`] reciben vistas ya tomadas, asi
//! que las manipulaciones que se quieren detectar se reproducen construyendo
//! las vistas a mano. Montar un rootkit DKOM de verdad en la maquina de
//! integracion no es una opcion, y esperar a tener uno para probar la logica
//! que acusa seria dejarla sin probar.

#![deny(missing_docs)]

pub mod abi;
pub mod engine;
pub mod error;
pub mod tramos;
pub mod verdict;
pub mod views;

#[cfg(all(target_os = "linux", feature = "bpf"))]
pub mod bpf;

pub use engine::{KernelIntegrity, KernelViews, KiConfig, ScanReport};
pub use error::KiError;
pub use verdict::{Anomaly, AnomalyKind, Candidate, Confirmation, VerdictConfig};
pub use views::{TaskRecord, ViewSet, Vista};

#[cfg(all(target_os = "linux", feature = "bpf"))]
pub use bpf::BpfViews;

/// Indica si esta maquina puede sostener la verificacion cruzada.
///
/// Es una comprobacion barata y previa: sin BTF no hay CO-RE, y sin CO-RE los
/// kfuncs de tareas no se pueden resolver.
pub fn soportado() -> bool {
    std::path::Path::new("/sys/kernel/btf/vmlinux").exists()
}
