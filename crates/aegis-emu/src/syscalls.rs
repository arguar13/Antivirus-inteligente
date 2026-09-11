//! Traduccion de la frontera con el sistema a eventos de comportamiento.
//!
//! Cuando el binario emulado ejecuta `syscall` (o `int 0x80`), el emulador NO
//! realiza la llamada —eso seria darle al malware exactamente lo que quiere—.
//! La intercepta y la convierte en un [`EventoComportamiento`] observable, que
//! es lo que alimenta la heuristica. El numero de syscall llega en `rax` y los
//! argumentos en `rdi, rsi, rdx, r10, r8, r9` (la ABI de Linux x86-64).

/// La categoria de comportamiento de una llamada al sistema, que es lo que la
/// heuristica necesita (el numero exacto da igual; importa QUE hace).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Categoria {
    /// Abre un fichero (`open`, `openat`).
    AperturaArchivo,
    /// Lee de un descriptor (`read`).
    LecturaArchivo,
    /// Escribe en un descriptor (`write`) —un cifrador de ransomware escribe
    /// mucho—.
    EscrituraArchivo,
    /// Reserva o reprotege memoria como EJECUTABLE (`mmap`/`mprotect` con
    /// `PROT_EXEC`): el paso previo de casi toda inyeccion o desempaquetado.
    MemoriaEjecutable,
    /// Actividad de red (`socket`, `connect`, `sendto`, ...): posible C2.
    Red,
    /// Ejecuta otro programa (`execve`, `execveat`).
    EjecucionPrograma,
    /// Manipula otro proceso (`ptrace`, `process_vm_writev`): inyeccion.
    ManipulacionProceso,
    /// Crea un proceso o hilo (`fork`, `clone`, `vfork`).
    CreacionProceso,
    /// Termina (`exit`, `exit_group`): fin natural de la emulacion.
    Salida,
    /// Cualquier otra: se registra pero no pesa en la heuristica.
    Otra,
}

/// Un evento observable durante la emulacion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventoComportamiento {
    /// El binario hizo una llamada al sistema.
    LlamadaSistema {
        /// Numero de syscall (en `rax`).
        numero: u64,
        /// Nombre legible de la syscall.
        nombre: &'static str,
        /// Categoria de comportamiento.
        categoria: Categoria,
    },
    /// El binario salto a ejecutar codigo que el mismo escribio en tiempo de
    /// ejecucion: el momento en que un empaquetador despliega su carga real.
    Desempaquetado {
        /// Inicio de la region desempaquetada.
        base: u64,
        /// Fin (exclusivo) de la region.
        fin: u64,
    },
}

/// `PROT_EXEC` de Linux (bit del argumento `prot` de `mmap`/`mprotect`).
const PROT_EXEC: u64 = 0x4;

/// Clasifica una syscall de Linux x86-64 por su numero y sus argumentos.
///
/// `args` son `[rdi, rsi, rdx, r10, r8, r9]`. Se usan solo para `mmap`/`mprotect`,
/// donde el argumento `prot` (el tercero) decide si la memoria se hace
/// ejecutable.
#[must_use]
pub fn clasificar(numero: u64, args: &[u64; 6]) -> EventoComportamiento {
    let (nombre, categoria) = match numero {
        0 => ("read", Categoria::LecturaArchivo),
        1 => ("write", Categoria::EscrituraArchivo),
        2 => ("open", Categoria::AperturaArchivo),
        257 => ("openat", Categoria::AperturaArchivo),
        9 => ("mmap", prot_categoria(args[2])),
        10 => ("mprotect", prot_categoria(args[2])),
        11 => ("munmap", Categoria::Otra),
        41 => ("socket", Categoria::Red),
        42 => ("connect", Categoria::Red),
        43 => ("accept", Categoria::Red),
        44 => ("sendto", Categoria::Red),
        45 => ("recvfrom", Categoria::Red),
        49 => ("bind", Categoria::Red),
        59 => ("execve", Categoria::EjecucionPrograma),
        322 => ("execveat", Categoria::EjecucionPrograma),
        101 => ("ptrace", Categoria::ManipulacionProceso),
        310 => ("process_vm_readv", Categoria::ManipulacionProceso),
        311 => ("process_vm_writev", Categoria::ManipulacionProceso),
        56 => ("clone", Categoria::CreacionProceso),
        57 => ("fork", Categoria::CreacionProceso),
        58 => ("vfork", Categoria::CreacionProceso),
        60 => ("exit", Categoria::Salida),
        231 => ("exit_group", Categoria::Salida),
        _ => ("desconocida", Categoria::Otra),
    };
    EventoComportamiento::LlamadaSistema {
        numero,
        nombre,
        categoria,
    }
}

/// Clasifica una llamada por `int 0x80`, la ABI heredada de 32 bits, cuyos
/// NUMEROS son distintos a los de 64 bits (por eso no se puede reutilizar
/// [`clasificar`]). Se mapean solo las de mas senal; el resto es `Otra`. El
/// numero llega en `eax`.
#[must_use]
pub fn clasificar_int80(numero: u64) -> EventoComportamiento {
    let (nombre, categoria) = match numero {
        1 => ("exit(32)", Categoria::Salida),
        252 => ("exit_group(32)", Categoria::Salida),
        3 => ("read(32)", Categoria::LecturaArchivo),
        4 => ("write(32)", Categoria::EscrituraArchivo),
        5 => ("open(32)", Categoria::AperturaArchivo),
        11 => ("execve(32)", Categoria::EjecucionPrograma),
        102 => ("socketcall(32)", Categoria::Red),
        _ => ("int80", Categoria::Otra),
    };
    EventoComportamiento::LlamadaSistema {
        numero,
        nombre,
        categoria,
    }
}

/// `MemoriaEjecutable` si `prot` incluye `PROT_EXEC`; si no, `Otra`.
fn prot_categoria(prot: u64) -> Categoria {
    if prot & PROT_EXEC != 0 {
        Categoria::MemoriaEjecutable
    } else {
        Categoria::Otra
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clasifica_syscalls_por_comportamiento() {
        let sin_args = [0u64; 6];
        assert!(matches!(
            clasificar(59, &sin_args),
            EventoComportamiento::LlamadaSistema {
                categoria: Categoria::EjecucionPrograma,
                nombre: "execve",
                ..
            }
        ));
        assert!(matches!(
            clasificar(42, &sin_args),
            EventoComportamiento::LlamadaSistema {
                categoria: Categoria::Red,
                ..
            }
        ));
    }

    #[test]
    fn mmap_es_ejecutable_solo_con_prot_exec() {
        // prot = PROT_READ|PROT_WRITE|PROT_EXEC (0x7) -> memoria ejecutable.
        let rwx = [0, 0x1000, 0x7, 0, 0, 0];
        assert!(matches!(
            clasificar(9, &rwx),
            EventoComportamiento::LlamadaSistema {
                categoria: Categoria::MemoriaEjecutable,
                ..
            }
        ));
        // prot = PROT_READ|PROT_WRITE (0x3) -> no ejecutable.
        let rw = [0, 0x1000, 0x3, 0, 0, 0];
        assert!(matches!(
            clasificar(9, &rw),
            EventoComportamiento::LlamadaSistema {
                categoria: Categoria::Otra,
                ..
            }
        ));
    }
}
