//! Politicas de aislamiento.
//!
//! Una politica describe QUE se prohibe, no COMO. El "como" —seccomp para las
//! llamadas, Landlock para las rutas— lo resuelve [`crate::CompiledSandbox`]
//! segun lo que el kernel de la maquina admita.

use std::path::PathBuf;

use crate::landlock;
use crate::seccomp::DeniedAction;
use crate::syscalls::{self, Syscall};

/// Que se le permite a un proceso sobre el sistema de ficheros.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FsPolicy {
    /// Rutas legibles y ejecutables.
    pub read_only: Vec<PathBuf>,
    /// Rutas donde ademas se puede escribir.
    pub read_write: Vec<PathBuf>,
}

impl FsPolicy {
    /// Indica si la politica dice algo del sistema de ficheros.
    ///
    /// Una politica vacia NO significa "todo permitido": significa que no se
    /// aplica Landlock. Prohibirlo todo dejaria al proceso sin poder ni
    /// ejecutarse.
    pub fn is_empty(&self) -> bool {
        self.read_only.is_empty() && self.read_write.is_empty()
    }

    /// Rutas de solo lectura minimas para que un binario dinamico arranque.
    ///
    /// Sin ellas, el enlazador dinamico no encuentra `libc` y el proceso muere
    /// antes de ejecutar su primera instruccion propia. Es el error mas comun al
    /// estrenar Landlock, y por eso esta lista existe en vez de dejarla al
    /// llamante.
    pub fn base_del_sistema() -> Vec<PathBuf> {
        [
            "/usr",
            "/lib",
            "/lib64",
            "/bin",
            "/sbin",
            "/etc/ld.so.cache",
        ]
        .iter()
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .collect()
    }
}

/// Politica completa de aislamiento.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPolicy {
    /// Nombre, para registros y para el informe de aplicacion.
    pub name: &'static str,
    /// Prohibir toda la red.
    pub deny_network: bool,
    /// Prohibir el control de otros procesos (`ptrace`, memoria ajena).
    pub deny_process_control: bool,
    /// Prohibir la superficie de kernel (modulos, `kexec`, eBPF, `perf`).
    pub deny_kernel_surface: bool,
    /// Prohibir cambios de privilegio y de espacio de nombres.
    pub deny_privilege_change: bool,
    /// Llamadas adicionales que la politica prohibe.
    pub extra_denied: Vec<Syscall>,
    /// Que hacer con una llamada prohibida.
    pub denied_action: DeniedAction,
    /// Restriccion de rutas.
    pub fs: FsPolicy,
}

impl SandboxPolicy {
    /// Politica vacia con un nombre, para construir a medida.
    pub fn named(name: &'static str) -> SandboxPolicy {
        SandboxPolicy {
            name,
            deny_network: false,
            deny_process_control: false,
            deny_kernel_surface: false,
            deny_privilege_change: false,
            extra_denied: Vec::new(),
            denied_action: DeniedAction::Errno(libc::EPERM),
            fs: FsPolicy::default(),
        }
    }

    /// Confinamiento de un binario en el que NO se confia.
    ///
    /// Es la politica de la fase: sin red, sin control de otros procesos, sin
    /// tocar el kernel, sin cambiar privilegios, y con acceso de lectura solo a
    /// lo imprescindible para ejecutarse. **`/tmp` no esta**: es el directorio
    /// donde acaba todo lo que se descarga, y un binario sospechoso que puede
    /// escribir ahi puede dejar su segunda etapa.
    ///
    /// La accion es MATAR y no devolver `EPERM`: si un binario en el que no se
    /// confia intenta algo que la politica prohibe, no hay conversacion posible,
    /// y la muerte por `SIGSYS` queda registrada de forma inconfundible.
    pub fn untrusted_binary() -> SandboxPolicy {
        SandboxPolicy {
            name: "binario-no-confiable",
            deny_network: true,
            deny_process_control: true,
            deny_kernel_surface: true,
            deny_privilege_change: true,
            extra_denied: vec![Syscall::Personality, Syscall::Userfaultfd],
            denied_action: DeniedAction::Kill,
            fs: FsPolicy {
                read_only: FsPolicy::base_del_sistema(),
                read_write: Vec::new(),
            },
        }
    }

    /// Confinamiento de un proceso auxiliar del propio agente.
    ///
    /// Recorta la superficie sin matar: un auxiliar legitimo que recibe `EPERM`
    /// informa y sigue, mientras que matarlo produce un fallo incomprensible en
    /// un componente propio.
    pub fn agent_helper() -> SandboxPolicy {
        SandboxPolicy {
            name: "auxiliar-del-agente",
            deny_network: true,
            deny_process_control: false,
            deny_kernel_surface: true,
            deny_privilege_change: true,
            extra_denied: Vec::new(),
            denied_action: DeniedAction::Errno(libc::EPERM),
            fs: FsPolicy::default(),
        }
    }

    /// Llamadas que esta politica prohibe, ordenadas y sin repetir.
    pub fn denied_syscalls(&self) -> Vec<Syscall> {
        let mut v: Vec<Syscall> = Vec::new();
        if self.deny_network {
            v.extend_from_slice(syscalls::RED);
        }
        if self.deny_process_control {
            v.extend_from_slice(syscalls::CONTROL_DE_PROCESOS);
        }
        if self.deny_kernel_surface {
            v.extend_from_slice(syscalls::SUPERFICIE_DE_KERNEL);
        }
        if self.deny_privilege_change {
            v.extend_from_slice(syscalls::CAMBIO_DE_PRIVILEGIOS);
        }
        v.extend_from_slice(&self.extra_denied);
        v.sort_unstable();
        v.dedup();
        v
    }

    /// Derechos de fichero que la politica gobierna.
    ///
    /// Se gobiernan TODOS los que la ABI conozca: lo que no se gobierna queda
    /// permitido, y una politica que solo gobierna la escritura deja al binario
    /// leer cualquier cosa de la maquina.
    ///
    /// Con una excepcion que no es un matiz: **una politica sin rutas no
    /// gobierna nada del sistema de ficheros**. Landlock es una lista blanca, de
    /// modo que gobernar los derechos sin anadir ni una regla que los conceda
    /// prohibe el sistema de ficheros ENTERO, y el proceso ni siquiera llega a
    /// ejecutarse: `execve` devuelve `EACCES` antes de su primera instruccion.
    ///
    /// Importa porque es la forma exacta de [`SandboxPolicy::agent_helper`], que
    /// prohibe la red y no dice nada de rutas: sin esta condicion, todo proceso
    /// auxiliar del agente muere al arrancar en cuanto el kernel trae Landlock.
    pub fn handled_fs(&self, abi: landlock::Abi) -> u64 {
        if self.fs.is_empty() {
            0
        } else {
            abi.supported_fs()
        }
    }

    /// Derechos de red que la politica gobierna con Landlock.
    ///
    /// Solo tiene efecto en ABI 4 o superior. No sustituye al filtro de
    /// seccomp: Landlock cubre TCP, y seccomp cubre todo lo demas —UDP, sockets
    /// de dominio Unix, `netlink`, paquetes en crudo—.
    pub fn handled_net(&self) -> u64 {
        if self.deny_network {
            landlock::NET_BIND_TCP | landlock::NET_CONNECT_TCP
        } else {
            0
        }
    }
}
