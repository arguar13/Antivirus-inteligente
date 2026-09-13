//! Tabla de llamadas al sistema de x86-64 y su significado para el analisis.
//!
//! # Por que hay una tabla y no se resuelve por nombre en tiempo de ejecucion
//!
//! El invitado no tiene bibliotecas de simbolos ni acceso a nada del anfitrion:
//! es una imagen minima a proposito, porque cada cosa que se mete dentro es una
//! cosa que el malware puede usar. La tabla va compilada.
//!
//! # Lo que decide que entra en la tabla
//!
//! No estan las 350 llamadas de Linux, estan las que **cambian el informe**. Una
//! llamada que no distingue un comportamiento de otro solo anade ruido a una
//! traza que ya es enorme, y el ruido en un informe de comportamiento no es
//! neutro: entierra la linea que importaba.
//!
//! El criterio es que la llamada responda a una de estas preguntas:
//!
//! - **Que ejecuto** (`execve`, `clone`, `ptrace`)
//! - **Que toco** (`openat`, `unlinkat`, `renameat`, `chmod`)
//! - **Con quien hablo** (`socket`, `connect`, `sendto`)
//! - **Como se escondio** (`memfd_create`, `mprotect`, `finit_module`, `unshare`)
//!
//! La cuarta categoria es la que suele faltar en los sandboxes de juguete, y es
//! justo la que separa una muestra vulgar de una que sabe donde esta.

use crate::protocolo::{AccionFichero, AccionRed};

/// Que clase de comportamiento revela una llamada.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Interes {
    /// Ejecucion o creacion de procesos.
    Proceso,
    /// Acceso a ficheros, con la accion que implica.
    Fichero(AccionFichero),
    /// Actividad de red, con la accion que implica.
    Red(AccionRed),
    /// Tecnica de evasion, ocultacion o escalada.
    ///
    /// Se registra como llamada generica pero se marca aparte en el informe: son
    /// las que dicen que la muestra **sabe** que la estan mirando.
    Evasion,
    /// Interesa registrarla, sin mas.
    Generico,
}

/// Una entrada de la tabla.
#[derive(Debug, Clone, Copy)]
pub struct Entrada {
    /// Numero de llamada en x86-64.
    pub numero: u64,
    /// Nombre.
    pub nombre: &'static str,
    /// Que revela.
    pub interes: Interes,
    /// Indice del argumento que lleva la ruta o el destino, si lo hay.
    pub arg_ruta: Option<usize>,
}

/// Construye una entrada de forma compacta.
const fn e(
    numero: u64,
    nombre: &'static str,
    interes: Interes,
    arg_ruta: Option<usize>,
) -> Entrada {
    Entrada {
        numero,
        nombre,
        interes,
        arg_ruta,
    }
}

/// Las llamadas que cambian el informe, en x86-64.
///
/// Ordenada por numero: [`buscar`] hace busqueda binaria, y una prueba comprueba
/// que el orden se mantiene cuando alguien anade una.
pub static TABLA: &[Entrada] = &[
    e(0, "read", Interes::Fichero(AccionFichero::Lee), None),
    e(1, "write", Interes::Fichero(AccionFichero::Escribe), None),
    e(2, "open", Interes::Fichero(AccionFichero::Lee), Some(0)),
    e(9, "mmap", Interes::Generico, None),
    // mprotect con PROT_EXEC sobre memoria que ya estaba escrita es el patron de
    // shellcode desempaquetado en memoria. El argumento que lo delata es el
    // tercero, y el trazador lo mira.
    e(10, "mprotect", Interes::Evasion, None),
    e(17, "pread64", Interes::Fichero(AccionFichero::Lee), None),
    e(
        18,
        "pwrite64",
        Interes::Fichero(AccionFichero::Escribe),
        None,
    ),
    e(41, "socket", Interes::Red(AccionRed::Socket), None),
    e(42, "connect", Interes::Red(AccionRed::Conecta), None),
    e(43, "accept", Interes::Red(AccionRed::Escucha), None),
    e(44, "sendto", Interes::Red(AccionRed::Envia), None),
    e(45, "recvfrom", Interes::Red(AccionRed::Envia), None),
    e(46, "sendmsg", Interes::Red(AccionRed::Envia), None),
    e(49, "bind", Interes::Red(AccionRed::Escucha), None),
    e(50, "listen", Interes::Red(AccionRed::Escucha), None),
    e(56, "clone", Interes::Proceso, None),
    e(57, "fork", Interes::Proceso, None),
    e(58, "vfork", Interes::Proceso, None),
    e(59, "execve", Interes::Proceso, Some(0)),
    e(60, "exit", Interes::Proceso, None),
    e(62, "kill", Interes::Generico, None),
    e(
        82,
        "rename",
        Interes::Fichero(AccionFichero::Renombra),
        Some(0),
    ),
    e(
        83,
        "mkdir",
        Interes::Fichero(AccionFichero::Escribe),
        Some(0),
    ),
    e(
        85,
        "creat",
        Interes::Fichero(AccionFichero::Escribe),
        Some(0),
    ),
    e(
        87,
        "unlink",
        Interes::Fichero(AccionFichero::Borra),
        Some(0),
    ),
    e(
        90,
        "chmod",
        Interes::Fichero(AccionFichero::Permisos),
        Some(0),
    ),
    e(
        91,
        "fchmod",
        Interes::Fichero(AccionFichero::Permisos),
        None,
    ),
    e(
        92,
        "chown",
        Interes::Fichero(AccionFichero::Permisos),
        Some(0),
    ),
    // La muestra trazandose a si misma para que nadie mas pueda: el truco
    // anti-depuracion mas viejo y todavia el mas usado.
    e(101, "ptrace", Interes::Evasion, None),
    e(105, "setuid", Interes::Evasion, None),
    e(106, "setgid", Interes::Evasion, None),
    e(
        133,
        "mknod",
        Interes::Fichero(AccionFichero::Escribe),
        Some(0),
    ),
    e(155, "pivot_root", Interes::Evasion, None),
    e(161, "chroot", Interes::Evasion, Some(0)),
    e(165, "mount", Interes::Evasion, Some(1)),
    e(166, "umount2", Interes::Evasion, Some(0)),
    e(169, "reboot", Interes::Evasion, None),
    // Cargar un modulo es pasar a ring 0: el final del juego para el sandbox.
    e(175, "init_module", Interes::Evasion, None),
    e(176, "delete_module", Interes::Evasion, Some(0)),
    e(231, "exit_group", Interes::Proceso, None),
    e(257, "openat", Interes::Fichero(AccionFichero::Lee), Some(1)),
    e(
        260,
        "fchownat",
        Interes::Fichero(AccionFichero::Permisos),
        Some(1),
    ),
    e(
        263,
        "unlinkat",
        Interes::Fichero(AccionFichero::Borra),
        Some(1),
    ),
    e(
        264,
        "renameat",
        Interes::Fichero(AccionFichero::Renombra),
        Some(1),
    ),
    e(
        268,
        "fchmodat",
        Interes::Fichero(AccionFichero::Permisos),
        Some(1),
    ),
    e(272, "unshare", Interes::Evasion, None),
    e(
        280,
        "utimensat",
        Interes::Fichero(AccionFichero::Permisos),
        Some(1),
    ),
    e(
        285,
        "fallocate",
        Interes::Fichero(AccionFichero::Escribe),
        None,
    ),
    e(304, "open_by_handle_at", Interes::Evasion, None),
    e(313, "finit_module", Interes::Evasion, None),
    e(
        316,
        "renameat2",
        Interes::Fichero(AccionFichero::Renombra),
        Some(1),
    ),
    // Un fichero que solo existe en memoria: ejecucion sin tocar el disco, y por
    // tanto sin nada que un escaner de ficheros pueda mirar.
    e(319, "memfd_create", Interes::Evasion, Some(0)),
    e(322, "execveat", Interes::Proceso, Some(1)),
    e(435, "clone3", Interes::Proceso, None),
    e(
        437,
        "openat2",
        Interes::Fichero(AccionFichero::Lee),
        Some(1),
    ),
];

/// Busca una llamada por su numero.
#[must_use]
pub fn buscar(numero: u64) -> Option<&'static Entrada> {
    TABLA
        .binary_search_by_key(&numero, |x| x.numero)
        .ok()
        .map(|i| &TABLA[i])
}

/// Nombre de una llamada, o su numero si no esta en la tabla.
///
/// Nunca devuelve vacio: una llamada desconocida en el informe es informacion
/// —dice que la muestra usa algo que no se esta clasificando— y borrarla seria
/// perderla.
#[must_use]
pub fn nombre(numero: u64) -> String {
    match buscar(numero) {
        Some(x) => x.nombre.to_string(),
        None => format!("syscall_{numero}"),
    }
}

/// Banderas de `open`/`openat` que significan escritura.
///
/// `O_WRONLY` (1), `O_RDWR` (2), `O_CREAT` (0o100), `O_TRUNC` (0o1000) y
/// `O_APPEND` (0o2000). Se mira porque la diferencia entre leer un fichero y
/// reescribirlo es la diferencia entre mirar y cifrar.
#[must_use]
pub fn abre_para_escribir(banderas: u64) -> bool {
    const O_WRONLY: u64 = 0o1;
    const O_RDWR: u64 = 0o2;
    const O_CREAT: u64 = 0o100;
    const O_TRUNC: u64 = 0o1000;
    const O_APPEND: u64 = 0o2000;
    banderas & (O_WRONLY | O_RDWR) != 0 || banderas & (O_CREAT | O_TRUNC | O_APPEND) != 0
}

/// `PROT_EXEC` de `mprotect`.
pub const PROT_EXEC: u64 = 0x4;
/// `PROT_WRITE` de `mprotect`.
pub const PROT_WRITE: u64 = 0x2;

/// Si una proteccion de memoria pide a la vez escritura y ejecucion.
///
/// Es la firma del desempaquetado en memoria. No prueba que haya malware —un JIT
/// legitimo hace lo mismo— pero es un hecho que el informe tiene que llevar.
#[must_use]
pub fn memoria_escribible_y_ejecutable(proteccion: u64) -> bool {
    proteccion & PROT_EXEC != 0 && proteccion & PROT_WRITE != 0
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn la_tabla_esta_ordenada_y_sin_repetidos() {
        // La busqueda es binaria: si alguien anade una entrada fuera de orden, la
        // tabla deja de funcionar en silencio y el informe pierde llamadas sin
        // que nadie se entere.
        for par in TABLA.windows(2) {
            assert!(
                par[0].numero < par[1].numero,
                "desordenada o repetida: {} antes de {}",
                par[0].numero,
                par[1].numero
            );
        }
    }

    #[test]
    fn las_llamadas_que_importan_estan_y_se_encuentran() {
        for (numero, esperado) in [
            (59u64, "execve"),
            (257, "openat"),
            (42, "connect"),
            (319, "memfd_create"),
            (101, "ptrace"),
            (313, "finit_module"),
        ] {
            let x = buscar(numero).unwrap_or_else(|| panic!("falta {esperado}"));
            assert_eq!(x.nombre, esperado);
        }
    }

    #[test]
    fn una_llamada_desconocida_no_se_pierde() {
        // Que una muestra use algo que no clasificamos es informacion, no un
        // motivo para borrarlo del informe.
        assert!(buscar(9999).is_none());
        assert_eq!(nombre(9999), "syscall_9999");
        assert_eq!(nombre(59), "execve");
    }

    #[test]
    fn las_tecnicas_de_evasion_estan_marcadas_como_tales() {
        for numero in [101u64, 319, 313, 10, 272, 161] {
            let x = buscar(numero).unwrap();
            assert_eq!(
                x.interes,
                Interes::Evasion,
                "{} tendria que contar como evasion",
                x.nombre
            );
        }
    }

    #[test]
    fn abrir_para_escribir_se_distingue_de_abrir_para_leer() {
        // La diferencia entre mirar un fichero y cifrarlo.
        assert!(!abre_para_escribir(0)); // O_RDONLY
        assert!(abre_para_escribir(0o1)); // O_WRONLY
        assert!(abre_para_escribir(0o2)); // O_RDWR
        assert!(abre_para_escribir(0o100)); // O_CREAT
        assert!(abre_para_escribir(0o1001)); // O_WRONLY|O_TRUNC
        assert!(abre_para_escribir(0o2000)); // O_APPEND
    }

    #[test]
    fn la_memoria_escribible_y_ejecutable_se_reconoce() {
        assert!(memoria_escribible_y_ejecutable(PROT_WRITE | PROT_EXEC));
        assert!(!memoria_escribible_y_ejecutable(PROT_EXEC));
        assert!(!memoria_escribible_y_ejecutable(PROT_WRITE));
        assert!(!memoria_escribible_y_ejecutable(0));
    }

    #[test]
    fn las_rutas_se_leen_del_argumento_correcto() {
        // El fallo clasico: `open` lleva la ruta en el argumento 0 y `openat` en
        // el 1, porque el 0 es el descriptor del directorio. Confundirlos hace
        // que el informe ensene numeros de descriptor como si fueran rutas.
        assert_eq!(buscar(2).unwrap().arg_ruta, Some(0)); // open
        assert_eq!(buscar(257).unwrap().arg_ruta, Some(1)); // openat
        assert_eq!(buscar(87).unwrap().arg_ruta, Some(0)); // unlink
        assert_eq!(buscar(263).unwrap().arg_ruta, Some(1)); // unlinkat
        assert_eq!(buscar(59).unwrap().arg_ruta, Some(0)); // execve
        assert_eq!(buscar(322).unwrap().arg_ruta, Some(1)); // execveat
    }
}
