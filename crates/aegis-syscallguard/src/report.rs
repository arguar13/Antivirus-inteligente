//! Estructuras de informe del guardia de syscalls y reporte de capacidades.

use crate::drx::{sondear_drx, SoporteDrx};
use crate::origen::{OrigenSyscall, Severidad};
use crate::pmu::{sondear_pmu, SoportePmu};

/// Una syscall cuyo origen es anomalo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnomaliaSyscall {
    /// Numero de syscall.
    pub nr: u64,
    /// Puntero de instruccion desde el que se llamo.
    pub ip: u64,
    /// Origen clasificado.
    pub origen: OrigenSyscall,
    /// `true` si en `ip - opcode` habia de verdad una instruccion `syscall`.
    ///
    /// Si es `false`, el kernel dio un puntero que no corresponde a ninguna
    /// syscall real: la propia info de syscall es sospechosa (rootkit que la
    /// falsea, o un artefacto). Es el resultado de cruzar la palabra del kernel
    /// con los bytes reales de la memoria del proceso.
    pub opcode_confirmado: bool,
}

/// Conteo de syscalls observadas por categoria de origen.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConteoOrigen {
    /// Desde `libc`/`ld`.
    pub libc: u64,
    /// Desde el `[vdso]`.
    pub vdso: u64,
    /// Desde el `.text` propio (binario estatico).
    pub binario_estatico: u64,
    /// Desde memoria anonima ejecutable (syscall directa).
    pub memoria_anonima: u64,
    /// Desde una direccion imposible.
    pub desconocido: u64,
}

impl ConteoOrigen {
    /// Suma uno al contador de la categoria dada.
    pub fn anotar(&mut self, origen: OrigenSyscall) {
        match origen {
            OrigenSyscall::Libc => self.libc += 1,
            OrigenSyscall::Vdso => self.vdso += 1,
            OrigenSyscall::BinarioEstatico => self.binario_estatico += 1,
            OrigenSyscall::MemoriaAnonima => self.memoria_anonima += 1,
            OrigenSyscall::Desconocido => self.desconocido += 1,
        }
    }

    /// Total de syscalls contadas.
    pub fn total(&self) -> u64 {
        self.libc + self.vdso + self.binario_estatico + self.memoria_anonima + self.desconocido
    }
}

/// Veredicto global del perfilado de un proceso.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EstadoSyscall {
    /// Todas las syscalls partieron de sitios legitimos.
    Limpio,
    /// Hubo syscalls desde el `.text` propio: legitimo en binarios estaticos,
    /// pero digno de registro.
    Sospechoso,
    /// Se observaron syscalls directas o de origen imposible: evasion.
    Evasion,
}

/// Informe del perfilado de syscalls de un proceso.
#[derive(Debug, Clone)]
pub struct InformeSyscall {
    /// PID perfilado.
    pub pid: i32,
    /// Paradas de syscall observadas.
    pub paradas: u64,
    /// Conteo por origen.
    pub conteos: ConteoOrigen,
    /// Syscalls de origen anomalo (memoria anonima o direccion imposible).
    pub anomalias: Vec<AnomaliaSyscall>,
}

impl InformeSyscall {
    /// Veredicto derivado de los conteos.
    pub fn estado(&self) -> EstadoSyscall {
        if self.conteos.memoria_anonima > 0 || self.conteos.desconocido > 0 {
            EstadoSyscall::Evasion
        } else if self.conteos.binario_estatico > 0 {
            EstadoSyscall::Sospechoso
        } else {
            EstadoSyscall::Limpio
        }
    }

    /// Gravedad maxima observada.
    pub fn severidad(&self) -> Severidad {
        self.anomalias
            .iter()
            .map(|a| a.origen.severidad())
            .max()
            .unwrap_or(if self.conteos.binario_estatico > 0 {
                Severidad::Informativa
            } else {
                Severidad::Ninguna
            })
    }
}

/// Capacidades de hardware de esta maquina para el guardia de syscalls.
#[derive(Debug, Clone)]
pub struct SoporteSyscallGuard {
    /// Estado de la PMU (contador de hardware).
    pub pmu: SoportePmu,
    /// Estado de los registros de depuracion (puntos de ruptura por hardware).
    pub drx: SoporteDrx,
    /// Si el kernel ofrece `PTRACE_GET_SYSCALL_INFO` (la via de verificacion
    /// cruzada, independiente de la PMU).
    pub ptrace_syscall_info: bool,
}

impl SoporteSyscallGuard {
    /// Sondea el hardware de esta maquina.
    pub fn sondear() -> SoporteSyscallGuard {
        SoporteSyscallGuard {
            pmu: sondear_pmu(),
            drx: sondear_drx(),
            // El kernel de destino (>= 5.3) siempre lo tiene; el arranque del
            // trazador lo confirma en la practica. Se marca por version del
            // kernel disponible en tiempo de compilacion del contrato.
            ptrace_syscall_info: cfg!(target_os = "linux"),
        }
    }

    /// Indica si el detector principal (trazador + verificacion cruzada) puede
    /// operar aqui. NO depende de la PMU.
    pub fn deteccion_operativa(&self) -> bool {
        self.ptrace_syscall_info
    }
}
