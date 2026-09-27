//! Las familias de syscalls que el sensor cubre, con su valor y su motor.
//!
//! # Por que familias y no una lista de syscalls sueltas
//!
//! Falco publica una lista de llamadas al sistema. Aqui la unidad es la FAMILIA:
//! proceso, fichero, red, memoria... Una familia se enciende o se apaga entera, y
//! su perdida se cuenta entera. Razonar por familias es lo que permite una
//! degradacion por presupuesto que se pueda explicar («se apago la familia de
//! menor valor»), en vez de una lista de excepciones que nadie entiende.

use aegis_entidad::escala::{Motor, Plano};

/// Una familia de eventos del sensor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Familia {
    /// Creacion y ejecucion de procesos (`execve`, `fork`, `exit`).
    Proceso,
    /// Sistema de ficheros (`open`, `write`, `rename`, `unlink`).
    Fichero,
    /// Red (conexiones, sockets, cambios de estado).
    Red,
    /// Memoria (`mmap`, `mprotect`, mapeos anonimos ejecutables).
    Memoria,
    /// Comunicacion entre procesos (tuberias, colas, memoria compartida).
    Ipc,
    /// Credenciales y capacidades (`setuid`, `capset`).
    Credenciales,
    /// Espacios de nombres (`unshare`, `setns`, `clone` con banderas).
    EspaciosNombres,
    /// Modulos del kernel (`init_module`, `finit_module`).
    Modulos,
    /// La propia `bpf`: cargar programas y mapas.
    Bpf,
    /// `ptrace`: la via clasica de inyeccion y evasion.
    Ptrace,
    /// `perf`: contadores y trazas que tambien sirven para evadir.
    Perf,
    /// `keyctl`: el llavero del kernel.
    Keyctl,
    /// `io_uring`: la evasion moderna favorita, porque sus operaciones no pasan
    /// por la ruta de syscall que casi todos los sensores vigilan.
    IoUring,
}

impl Familia {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Familia::Proceso => "proceso",
            Familia::Fichero => "fichero",
            Familia::Red => "red",
            Familia::Memoria => "memoria",
            Familia::Ipc => "ipc",
            Familia::Credenciales => "credenciales",
            Familia::EspaciosNombres => "espacios-de-nombres",
            Familia::Modulos => "modulos",
            Familia::Bpf => "bpf",
            Familia::Ptrace => "ptrace",
            Familia::Perf => "perf",
            Familia::Keyctl => "keyctl",
            Familia::IoUring => "io_uring",
        }
    }

    /// El VALOR de deteccion de la familia, de 0 a 100. La degradacion por
    /// presupuesto apaga las de MENOR valor primero: perder la ejecucion de
    /// procesos ciega casi todo; perder `perf` cuesta mucho menos.
    ///
    /// Los numeros estan puestos a mano y son discutibles, como los de
    /// `aegis-predict`: estan aqui, a la vista, y no dentro de un modelo.
    #[must_use]
    pub fn valor(self) -> u8 {
        match self {
            Familia::Proceso => 100,
            Familia::Memoria => 90,
            Familia::Credenciales => 88,
            Familia::Modulos => 86,
            Familia::Bpf => 84,
            Familia::Ptrace => 82,
            Familia::Fichero => 80,
            Familia::Red => 78,
            Familia::EspaciosNombres => 70,
            Familia::IoUring => 68,
            Familia::Keyctl => 60,
            Familia::Ipc => 55,
            Familia::Perf => 50,
        }
    }

    /// El COSTE declarado de la familia, en unidades relativas de CPU por sonda.
    ///
    /// Es lo que se somete al presupuesto de `aegis-presupuesto`: las familias de
    /// alto volumen —fichero, red— cuestan mas que las raras —modulos, keyctl—. El
    /// coste esta declarado, a la vista, no medido en tiempo de ejecucion, para que
    /// la degradacion sea reproducible.
    #[must_use]
    pub fn costo(self) -> u32 {
        match self {
            Familia::Fichero => 40,
            Familia::Red => 35,
            Familia::Proceso => 20,
            Familia::Memoria => 25,
            Familia::Ipc => 15,
            Familia::IoUring => 15,
            Familia::EspaciosNombres => 8,
            Familia::Ptrace => 6,
            Familia::Perf => 6,
            Familia::Credenciales => 5,
            Familia::Bpf => 4,
            Familia::Keyctl => 3,
            Familia::Modulos => 2,
        }
    }

    /// El motor que consume esta familia. La perdida de la familia se traduce en un
    /// `NoConcluyente` de ESTE motor: quien mira ese plano no tuvo datos.
    #[must_use]
    pub fn motor(self) -> Motor {
        match self {
            Familia::Proceso
            | Familia::Fichero
            | Familia::Ipc
            | Familia::EspaciosNombres
            | Familia::Modulos
            | Familia::Bpf => Motor::Conductual,
            Familia::Memoria => Motor::MemHunter,
            Familia::Red => Motor::Wire,
            Familia::Credenciales | Familia::Keyctl => Motor::Itdr,
            Familia::Ptrace | Familia::Perf | Familia::IoUring => Motor::SyscallGuard,
        }
    }

    /// El plano en el que observa el motor de esta familia.
    #[must_use]
    pub fn plano(self) -> Plano {
        self.motor().plano()
    }

    /// Todas las familias, en orden estable.
    #[must_use]
    pub fn todas() -> &'static [Familia] {
        &[
            Familia::Proceso,
            Familia::Fichero,
            Familia::Red,
            Familia::Memoria,
            Familia::Ipc,
            Familia::Credenciales,
            Familia::EspaciosNombres,
            Familia::Modulos,
            Familia::Bpf,
            Familia::Ptrace,
            Familia::Perf,
            Familia::Keyctl,
            Familia::IoUring,
        ]
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn la_ejecucion_de_procesos_vale_mas_que_perf() {
        // La degradacion apaga lo de menor valor primero: perder proceso ciega
        // casi todo; perder perf cuesta poco.
        assert!(Familia::Proceso.valor() > Familia::Perf.valor());
        assert!(Familia::Memoria.valor() > Familia::Ipc.valor());
    }

    #[test]
    fn cada_familia_tiene_motor_y_plano() {
        for f in Familia::todas() {
            // El motor y su plano existen en el modelo unico.
            let _ = f.motor();
            let _ = f.plano();
        }
        assert_eq!(Familia::Red.motor(), Motor::Wire);
        assert_eq!(Familia::Memoria.motor(), Motor::MemHunter);
        assert_eq!(Familia::IoUring.motor(), Motor::SyscallGuard);
    }

    #[test]
    fn no_hay_familias_con_el_mismo_nombre() {
        let mut n: Vec<&str> = Familia::todas().iter().map(|f| f.nombre()).collect();
        let antes = n.len();
        n.sort_unstable();
        n.dedup();
        assert_eq!(antes, n.len());
    }
}
