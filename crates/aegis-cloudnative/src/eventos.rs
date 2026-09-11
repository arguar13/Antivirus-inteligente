//! El vocabulario de la deteccion y el contrato binario con el programa eBPF.
//!
//! El programa eBPF (que corre en el kernel, el muro) engancha las syscalls
//! sensibles al escape de contenedor —`setns`, `unshare`, `capset`, `bpf`,
//! `mount`, y la escritura de rutas peligrosas— y emite por un ring buffer una
//! estructura [`EventoBpf`] de layout fijo. Aqui se refleja esa estructura con su
//! tamano verificado EN COMPILACION (si el eBPF y esto se desincronizan, el
//! decisor leeria basura), y se traduce al [`EventoNucleo`] idiomatico que el
//! decisor de [`crate::deteccion`] entiende.

use core::mem::size_of;

// --- Flags de namespaces (CLONE_NEW*) de `unshare(2)`/`clone(2)` ---------------

/// Nuevo namespace de montaje (`CLONE_NEWNS`).
pub const CLONE_NEWNS: u64 = 0x0002_0000;
/// Nuevo namespace de cgroup (`CLONE_NEWCGROUP`).
pub const CLONE_NEWCGROUP: u64 = 0x0200_0000;
/// Nuevo namespace UTS (`CLONE_NEWUTS`).
pub const CLONE_NEWUTS: u64 = 0x0400_0000;
/// Nuevo namespace IPC (`CLONE_NEWIPC`).
pub const CLONE_NEWIPC: u64 = 0x0800_0000;
/// Nuevo namespace de usuario (`CLONE_NEWUSER`): la palanca clasica para ganar
/// capacidades dentro de un contenedor.
pub const CLONE_NEWUSER: u64 = 0x1000_0000;
/// Nuevo namespace de PID (`CLONE_NEWPID`).
pub const CLONE_NEWPID: u64 = 0x2000_0000;
/// Nuevo namespace de red (`CLONE_NEWNET`).
pub const CLONE_NEWNET: u64 = 0x4000_0000;

// --- Capacidades (indice de bit dentro de la mascara de capacidades) -----------

/// `CAP_DAC_OVERRIDE`.
pub const CAP_DAC_OVERRIDE: u8 = 1;
/// `CAP_SYS_MODULE`: cargar modulos del kernel.
pub const CAP_SYS_MODULE: u8 = 16;
/// `CAP_SYS_PTRACE`.
pub const CAP_SYS_PTRACE: u8 = 19;
/// `CAP_SYS_ADMIN`: la "casi-root" que casi todos los escapes necesitan.
pub const CAP_SYS_ADMIN: u8 = 21;

// --- El modelo idiomatico que consume el decisor -------------------------------

/// La operacion sensible que se observo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operacion {
    /// `setns(2)`: entrar a un namespace ya existente.
    Setns,
    /// `unshare(2)`: crear namespaces nuevos y pasarse a ellos.
    Unshare,
    /// `capset(2)`: cambiar el conjunto de capacidades.
    Capset,
    /// `bpf(2)`: cargar u operar programas/mapas eBPF.
    Bpf,
    /// `mount(2)`: montar un sistema de ficheros.
    Montar,
    /// Escritura sobre una ruta sensible del sistema.
    Escritura,
}

impl Operacion {
    /// Codigo numerico del contrato con el eBPF.
    #[must_use]
    pub const fn codigo(self) -> u32 {
        match self {
            Operacion::Setns => 1,
            Operacion::Unshare => 2,
            Operacion::Capset => 3,
            Operacion::Bpf => 4,
            Operacion::Montar => 5,
            Operacion::Escritura => 6,
        }
    }

    /// Reconstruye desde el codigo del contrato.
    #[must_use]
    pub const fn desde_codigo(c: u32) -> Option<Operacion> {
        match c {
            1 => Some(Operacion::Setns),
            2 => Some(Operacion::Unshare),
            3 => Some(Operacion::Capset),
            4 => Some(Operacion::Bpf),
            5 => Some(Operacion::Montar),
            6 => Some(Operacion::Escritura),
            _ => None,
        }
    }
}

/// La ruta sensible sobre la que se escribio (si la operacion fue [`Operacion::Escritura`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RutaSensible {
    /// Ninguna ruta sensible.
    Ninguna,
    /// `.../release_agent` de un cgroup v1: el kernel ejecuta ese programa EN EL
    /// HOST cuando el cgroup queda vacio. Palanca de escape clasica.
    ReleaseAgentCgroup,
    /// `/proc/sys/kernel/core_pattern`: un `|/ruta` hace que el kernel ejecute
    /// ese programa en el host al volcar un core.
    CorePattern,
    /// `/proc/sys/kernel/modprobe`: el binario que el kernel invoca para cargar
    /// modulos; reescribirlo ejecuta codigo en el host.
    Modprobe,
}

impl RutaSensible {
    /// Codigo numerico del contrato con el eBPF.
    #[must_use]
    pub const fn codigo(self) -> u32 {
        match self {
            RutaSensible::Ninguna => 0,
            RutaSensible::ReleaseAgentCgroup => 1,
            RutaSensible::CorePattern => 2,
            RutaSensible::Modprobe => 3,
        }
    }

    /// Reconstruye desde el codigo del contrato (un codigo desconocido es
    /// [`RutaSensible::Ninguna`]).
    #[must_use]
    pub const fn desde_codigo(c: u32) -> Self {
        match c {
            1 => RutaSensible::ReleaseAgentCgroup,
            2 => RutaSensible::CorePattern,
            3 => RutaSensible::Modprobe,
            _ => RutaSensible::Ninguna,
        }
    }
}

/// El contexto del proceso que hizo la operacion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextoProceso {
    /// Identificador del proceso.
    pub pid: u32,
    /// El proceso corre dentro de un contenedor (no en el host).
    pub en_contenedor: bool,
    /// Mascara de capacidades efectivas del proceso.
    pub capacidades: u64,
}

impl ContextoProceso {
    /// `true` si el proceso tiene la capacidad cuyo indice de bit es `cap`.
    #[must_use]
    pub const fn tiene(&self, cap: u8) -> bool {
        (self.capacidades >> cap) & 1 == 1
    }
}

/// Bit de [`EventoNucleo::banderas`]: el namespace destino de un `setns` pertenece
/// al host (p. ej. `/proc/1/ns/*`), no al contenedor.
pub const BANDERA_DESTINO_NS_HOST: u64 = 1 << 0;
/// Bit de [`EventoNucleo::banderas`]: la fuente de un `mount` es un dispositivo de
/// bloque del host (montar el disco del anfitrion desde el contenedor).
pub const BANDERA_MONTAJE_DISPOSITIVO_HOST: u64 = 1 << 1;

/// Un evento de seguridad ya normalizado: que operacion, con que argumentos
/// relevantes, y en que contexto de proceso.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventoNucleo {
    /// La operacion observada.
    pub operacion: Operacion,
    /// El contexto del proceso.
    pub ctx: ContextoProceso,
    /// Para `unshare`: los flags `CLONE_NEW*`. Para `capset`: la mascara pedida.
    pub flags: u64,
    /// Bits de contexto de la operacion (ver `BANDERA_*`).
    pub banderas: u64,
    /// Para una escritura: la ruta sensible tocada.
    pub ruta: RutaSensible,
}

impl EventoNucleo {
    /// `true` si el `setns` apunta a un namespace del host.
    #[must_use]
    pub const fn destino_ns_host(&self) -> bool {
        self.banderas & BANDERA_DESTINO_NS_HOST != 0
    }

    /// `true` si el `mount` usa un dispositivo de bloque del host como fuente.
    #[must_use]
    pub const fn montaje_dispositivo_host(&self) -> bool {
        self.banderas & BANDERA_MONTAJE_DISPOSITIVO_HOST != 0
    }
}

// --- El contrato binario con el programa eBPF ----------------------------------

/// Espejo `repr(C)` del evento que el programa eBPF emite por el ring buffer.
///
/// Su tamano y disposicion se verifican en compilacion: son el contrato con el
/// codigo del kernel. Un campo desalineado haria que el decisor leyera basura.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EventoBpf {
    /// Codigo de [`Operacion`].
    pub operacion: u32,
    /// `1` si el proceso esta en un contenedor.
    pub en_contenedor: u32,
    /// PID del proceso.
    pub pid: u32,
    /// Codigo de [`RutaSensible`].
    pub ruta: u32,
    /// Capacidades efectivas.
    pub capacidades: u64,
    /// Flags (`CLONE_NEW*` o mascara de `capset`).
    pub flags: u64,
    /// Bits de contexto (`BANDERA_*`).
    pub banderas: u64,
}

const _: () = assert!(size_of::<EventoBpf>() == 40, "EventoBpf ABI = 40 bytes");

impl EventoNucleo {
    /// Traduce un [`EventoBpf`] crudo del ring buffer al modelo idiomatico.
    ///
    /// Devuelve `None` si el codigo de operacion es desconocido (un evento que el
    /// decisor no sabe interpretar se descarta, no se adivina).
    #[must_use]
    pub fn desde_bpf(e: &EventoBpf) -> Option<EventoNucleo> {
        Some(EventoNucleo {
            operacion: Operacion::desde_codigo(e.operacion)?,
            ctx: ContextoProceso {
                pid: e.pid,
                en_contenedor: e.en_contenedor != 0,
                capacidades: e.capacidades,
            },
            flags: e.flags,
            banderas: e.banderas,
            ruta: RutaSensible::desde_codigo(e.ruta),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn los_codigos_de_operacion_van_y_vuelven() {
        for op in [
            Operacion::Setns,
            Operacion::Unshare,
            Operacion::Capset,
            Operacion::Bpf,
            Operacion::Montar,
            Operacion::Escritura,
        ] {
            assert_eq!(Operacion::desde_codigo(op.codigo()), Some(op));
        }
        assert_eq!(Operacion::desde_codigo(0), None);
        assert_eq!(Operacion::desde_codigo(99), None);
    }

    #[test]
    fn la_mascara_de_capacidades_se_lee_por_bit() {
        let ctx = ContextoProceso {
            pid: 1,
            en_contenedor: true,
            capacidades: 1 << CAP_SYS_ADMIN,
        };
        assert!(ctx.tiene(CAP_SYS_ADMIN));
        assert!(!ctx.tiene(CAP_SYS_PTRACE));
    }

    #[test]
    fn un_evento_bpf_crudo_se_traduce() {
        let crudo = EventoBpf {
            operacion: Operacion::Unshare.codigo(),
            en_contenedor: 1,
            pid: 42,
            ruta: RutaSensible::Ninguna.codigo(),
            capacidades: 1 << CAP_SYS_ADMIN,
            flags: CLONE_NEWUSER,
            banderas: 0,
        };
        let ev = EventoNucleo::desde_bpf(&crudo).expect("operacion valida");
        assert_eq!(ev.operacion, Operacion::Unshare);
        assert_eq!(ev.ctx.pid, 42);
        assert!(ev.ctx.en_contenedor);
        assert_eq!(ev.flags, CLONE_NEWUSER);

        // Una operacion desconocida se descarta.
        let malo = EventoBpf {
            operacion: 0,
            ..crudo
        };
        assert!(EventoNucleo::desde_bpf(&malo).is_none());
    }
}
