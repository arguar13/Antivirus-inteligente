//! # aegis-sandbox
//!
//! Aislamiento preventivo de procesos con **Landlock** y **seccomp-bpf**.
//!
//! # Que problema resuelve
//!
//! Detectar y responder llega, por definicion, DESPUES: entre que el binario
//! sospechoso empieza a correr y que el motor decide cortarlo hay una ventana en
//! la que el atacante ya ha hecho su trabajo. El aislamiento preventivo cierra
//! esa ventana quitando de antemano lo que un binario no confiable no deberia
//! poder hacer nunca: hablar por la red, tocar otros procesos, cargar codigo en
//! el kernel o escribir donde deja su segunda etapa.
//!
//! # Dos mecanismos, porque ninguno basta solo
//!
//! - **seccomp-bpf** filtra por NUMERO de llamada. Es universal —esta en
//!   cualquier kernel de la ultima decada— y muy barato, pero no puede mirar una
//!   ruta: el argumento es un puntero al espacio del proceso, y aunque el filtro
//!   pudiera leerlo, entre comprobarlo y usarlo la ruta puede cambiar.
//! - **Landlock** aplica la restriccion en el VFS, sobre el objeto ya resuelto,
//!   asi que expresa "este binario no lee `/etc/shadow`" sin carreras posibles.
//!   A cambio, es reciente (Linux 5.13) y su superficie depende de la version de
//!   ABI del kernel.
//!
//! Se usan los dos. Cuando falta Landlock, [`CompiledSandbox::compile`] no
//! falla: aplica seccomp y **lo dice** en [`Applied`]. Callarselo seria lo
//! peligroso, porque quien despliega creeria tener una proteccion que no tiene.
//!
//! # Confianza cero, y por que la lista negra
//!
//! Landlock se usa como lista BLANCA de rutas: todo derecho gobernado queda
//! prohibido salvo donde una regla lo permita. seccomp, en cambio, se usa como
//! lista NEGRA de llamadas. No es una incoherencia: una lista blanca de llamadas
//! rompe cualquier programa no escrito para ella —otra version de `libc` usa
//! otras—, y un sandbox que rompe el software legitimo se desactiva a la semana
//! de desplegarlo. La lista negra cubre exactamente las capacidades que la
//! politica niega, y el resto del comportamiento normal sigue funcionando.
//!
//! # Aplicar sin romper el `fork`
//!
//! Un sandbox se aplica al hijo entre `fork` y `exec`, donde solo valen
//! funciones seguras en contexto de senal. Por eso todo lo que reserva memoria o
//! abre ficheros ocurre en [`CompiledSandbox::compile`], antes de bifurcar, y en
//! el hijo solo quedan llamadas al sistema.

#![deny(missing_docs)]

#[cfg(not(target_os = "linux"))]
compile_error!(
    "aegis-sandbox usa Landlock y seccomp, que son de Linux. El equivalente en \
     Windows es AppContainer con capacidades y en macOS el Sandbox de Seatbelt; \
     ninguno de los dos se puede fingir desde aqui."
);

pub mod error;
pub mod landlock;
pub mod policy;
pub mod sandbox;
pub mod seccomp;
pub mod syscalls;

pub use error::SandboxError;
pub use policy::{FsPolicy, SandboxPolicy};
pub use sandbox::{Applied, CompiledSandbox};
pub use seccomp::DeniedAction;
pub use syscalls::Syscall;

/// Capacidades de aislamiento de esta maquina.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Support {
    /// El kernel admite filtros de seccomp.
    pub seccomp: bool,
    /// Version de ABI de Landlock, si esta disponible.
    pub landlock_abi: Option<u32>,
}

impl Support {
    /// Consulta lo que la maquina ofrece.
    pub fn detect() -> Support {
        Support {
            seccomp: seccomp::available(),
            landlock_abi: landlock::Abi::detect().map(|a| a.0),
        }
    }

    /// Indica si se puede restringir por rutas.
    pub fn can_restrict_paths(&self) -> bool {
        self.landlock_abi.is_some()
    }

    /// Indica si se puede restringir la red por puertos con Landlock.
    ///
    /// Que sea falso no significa que la red no se pueda cortar: seccomp la
    /// corta entera. Significa que no se puede cortar de forma selectiva.
    pub fn can_restrict_ports(&self) -> bool {
        self.landlock_abi.is_some_and(|a| a >= 4)
    }
}
