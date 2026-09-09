//! Clasificacion del ORIGEN de una syscall: la verificacion cruzada.
//!
//! # La idea
//!
//! Una syscall legitima nace en un sitio muy concreto: el trampolin de `libc`
//! (o del enlazador dinamico durante el arranque). Todo el codigo de una
//! aplicacion normal llega al kernel por ahi, y ahi es donde un EDR —este
//! producto incluido— coloca sus enganches para vigilar.
//!
//! El malware moderno lo sabe y lo evita: incrusta su PROPIA instruccion
//! `syscall` (`0F 05` en x86-64) en su codigo y salta al kernel sin pasar por
//! `libc`. Es la tecnica de "syscall directa" (y su prima, la "syscall
//! indirecta", que salta al `0F 05` de `libc` pero con la pila preparada por el
//! atacante). Ninguna de las dos toca el trampolin vigilado.
//!
//! # Por que es verificacion cruzada
//!
//! El kernel, al atender la syscall, sabe la direccion EXACTA desde la que se
//! le llamo: el hardware la captura en el puntero de instruccion. Esa es una
//! vista. La otra es el mapa de memoria del proceso (`/proc/<pid>/maps`), que
//! dice que hay en cada direccion. Se cruzan:
//!
//! - La direccion cae en el `.text` de `libc`/`ld` → syscall legitima.
//! - La direccion cae en memoria ANONIMA ejecutable → no hay fichero detras;
//!   ese codigo lo genero el proceso al vuelo. Es la firma de la syscall
//!   directa: nadie compila asi.
//! - La direccion no cae en ninguna region, o cae en memoria no ejecutable →
//!   el puntero que dio el kernel es imposible para una syscall real. O el
//!   kernel miente (rootkit que falsea la info de syscall) o es un artefacto
//!   raro; en ambos casos, anomalo.
//!
//! El codigo estaticamente enlazado (Go, Rust con musl) llama al kernel desde
//! su propio `.text`, que es de fichero pero no es `libc`. Es legitimo y
//! comun, asi que se distingue como categoria propia y se informa sin alarmar:
//! la senal fuerte, la que no puede ser un binario estatico, es la memoria
//! anonima.

use aegis_scal::memory::{MemoryRegion, RegionClass};

/// De donde parte una syscall observada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrigenSyscall {
    /// Desde el trampolin de una biblioteca del sistema (`libc`, `ld`). Legitima.
    Libc,
    /// Desde el `[vdso]`. Legitima: es codigo que el propio kernel mapea.
    Vdso,
    /// Desde el `.text` de un fichero que no es biblioteca del sistema.
    ///
    /// Es lo que hace un binario estatico. Legitimo, pero se informa: tambien
    /// es lo que haria una carga util con su propio `.text` en un `.so` suelto.
    BinarioEstatico,
    /// Desde memoria ANONIMA ejecutable: la firma de la syscall directa.
    MemoriaAnonima,
    /// Desde una direccion imposible para una syscall (sin region, o no
    /// ejecutable, o un dispositivo). Puede ser info de syscall falseada.
    Desconocido,
}

/// Gravedad que se asigna a un origen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severidad {
    /// Sin relevancia: origen legitimo.
    Ninguna,
    /// Informativa: legitimo pero digno de registro.
    Informativa,
    /// Alta: firma de evasion.
    Alta,
}

impl OrigenSyscall {
    /// Gravedad de este origen.
    pub fn severidad(self) -> Severidad {
        match self {
            OrigenSyscall::Libc | OrigenSyscall::Vdso => Severidad::Ninguna,
            OrigenSyscall::BinarioEstatico => Severidad::Informativa,
            OrigenSyscall::MemoriaAnonima | OrigenSyscall::Desconocido => Severidad::Alta,
        }
    }

    /// Indica si este origen es, por si mismo, senal de evasion.
    pub fn es_evasion(self) -> bool {
        matches!(
            self,
            OrigenSyscall::MemoriaAnonima | OrigenSyscall::Desconocido
        )
    }

    /// Etiqueta legible.
    pub fn etiqueta(self) -> &'static str {
        match self {
            OrigenSyscall::Libc => "biblioteca del sistema (libc/ld)",
            OrigenSyscall::Vdso => "vDSO del kernel",
            OrigenSyscall::BinarioEstatico => "fichero propio (binario estatico)",
            OrigenSyscall::MemoriaAnonima => "memoria anonima ejecutable (syscall directa)",
            OrigenSyscall::Desconocido => "direccion imposible para una syscall",
        }
    }
}

/// Indica si una ruta de `/proc/<pid>/maps` es una biblioteca del sistema desde
/// la que las syscalls son legitimas: `libc` y el enlazador dinamico.
///
/// Se compara el nombre de fichero, no la ruta entera, porque la ubicacion
/// cambia entre distribuciones (`/lib`, `/usr/lib`, `/lib/x86_64-linux-gnu`,
/// musl en `/lib/ld-musl-*`) pero el nombre no.
pub fn es_biblioteca_sistema(ruta: &str) -> bool {
    let base = ruta.rsplit('/').next().unwrap_or(ruta);
    const PREFIJOS: &[&str] = &[
        "libc.so",
        "libc-",
        "libc.musl",
        "ld-linux",
        "ld-musl",
        "ld.so",
        "ld-2.",
        "libpthread",
        "librt.so",
        "libdl.so",
    ];
    PREFIJOS.iter().any(|p| base.starts_with(p))
}

/// Clasifica el origen de una syscall dado su puntero de instruccion y el mapa
/// de memoria del proceso.
///
/// El mapa se pasa ya leido —el llamante lo obtiene una vez por parada, con el
/// proceso detenido, para que no cambie bajo los pies del analisis—.
pub fn clasificar(ip: u64, regiones: &[MemoryRegion]) -> OrigenSyscall {
    let Some(region) = regiones.iter().find(|r| ip >= r.start && ip < r.end) else {
        // El puntero no cae en ninguna region mapeada: imposible para una
        // syscall real.
        return OrigenSyscall::Desconocido;
    };

    // El [vdso] lo etiqueta el kernel; su clase CO-RE es "Kernel", asi que se
    // reconoce por el nombre antes de mirar la clase.
    if region.path.as_deref() == Some("[vdso]") {
        return OrigenSyscall::Vdso;
    }

    match region.class() {
        RegionClass::AnonymousExec => OrigenSyscall::MemoriaAnonima,
        RegionClass::FileExec => match region.path.as_deref() {
            Some(ruta) if es_biblioteca_sistema(ruta) => OrigenSyscall::Libc,
            _ => OrigenSyscall::BinarioEstatico,
        },
        // Una syscall desde memoria no ejecutable, de datos o de dispositivo es
        // imposible sin que algo mienta.
        _ => OrigenSyscall::Desconocido,
    }
}
