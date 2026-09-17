//! Tablas de ficheros anadidas por la FASE 81.
//!
//! # Por que casi todas son peligrosas
//!
//! El coste de recorrer procesos lo acota el numero de procesos, que en la
//! maquina mas cargada son unas decenas de miles. El de recorrer ficheros no lo
//! acota nada: lo decide el disco del cliente, y un servidor de ficheros tiene
//! cientos de millones de inodos. `SELECT * FROM files` difundido a una flota
//! es, literalmente, un barrido completo de todos los discos de la empresa a la
//! vez.
//!
//! Por eso [`FILES`], [`SUID_BINARIES`] y [`FILE_CAPABILITIES`] declaran
//! [`Coste::Peligroso`]: sin acotar no se ejecutan. Acotadas por `path` o por
//! `mountpoint` siguen respondiendo a todo lo que un analista necesita
//! preguntar de verdad.
//!
//! # La union con el resto del producto
//!
//! Las filas de [`FILES`] llevan `Eid` de clase `Ubicacion`, y su columna
//! `sha256` produce ademas la `Eid` de clase `Contenido` con la que el fichero
//! se une a lo que sepan de el la inteligencia, la detonacion y el modelo. Es
//! la razon de que el hash sea SHA-256 y no el BLAKE3 que usa el FIM:
//! `aegis_entidad::contenido` exige SHA-256 porque es el nombre del contenido en
//! todo el producto.

use super::{Columna, Coste, Tabla, Tipo};

/// Columna `path`, que es la clave de casi todas estas tablas.
const RUTA: Columna = Columna {
    nombre: "path",
    tipo: Tipo::Texto,
    coste: Coste::Trivial,
    descripcion: "ruta absoluta del fichero",
};

// ---------------------------------------------------------------------------
// files
// ---------------------------------------------------------------------------
const COLUMNAS_FICHEROS: &[Columna] = &[
    RUTA,
    Columna {
        nombre: "directory",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "directorio que lo contiene",
    },
    Columna {
        nombre: "filename",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "nombre sin la ruta",
    },
    Columna {
        nombre: "size",
        tipo: Tipo::Entero,
        coste: Coste::Barato,
        descripcion: "tamano en bytes",
    },
    Columna {
        nombre: "mode",
        tipo: Tipo::Entero,
        coste: Coste::Barato,
        descripcion: "permisos en octal, incluidos setuid, setgid y sticky",
    },
    Columna {
        nombre: "uid",
        tipo: Tipo::Entero,
        coste: Coste::Barato,
        descripcion: "dueno",
    },
    Columna {
        nombre: "gid",
        tipo: Tipo::Entero,
        coste: Coste::Barato,
        descripcion: "grupo",
    },
    Columna {
        nombre: "inode",
        tipo: Tipo::Entero,
        coste: Coste::Barato,
        descripcion: "inodo",
    },
    Columna {
        nombre: "hard_links",
        tipo: Tipo::Entero,
        coste: Coste::Barato,
        descripcion: "enlaces duros; mas de uno en un binario de sistema es raro y se mira",
    },
    Columna {
        nombre: "mtime",
        tipo: Tipo::Entero,
        coste: Coste::Barato,
        descripcion: "ultima modificacion del contenido, en segundos desde la epoca",
    },
    Columna {
        nombre: "ctime",
        tipo: Tipo::Entero,
        coste: Coste::Barato,
        descripcion: "ultimo cambio del inodo; lo que un atacante NO puede falsificar con touch",
    },
    Columna {
        nombre: "atime",
        tipo: Tipo::Entero,
        coste: Coste::Barato,
        descripcion: "ultimo acceso, si el montaje lo registra",
    },
    Columna {
        nombre: "kind",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "file, dir, symlink, socket, fifo, char, block u other",
    },
    Columna {
        nombre: "symlink_target",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "a donde apunta, si es un enlace simbolico",
    },
    Columna {
        nombre: "setuid",
        tipo: Tipo::Booleano,
        coste: Coste::Barato,
        descripcion: "tiene el bit setuid",
    },
    Columna {
        nombre: "setgid",
        tipo: Tipo::Booleano,
        coste: Coste::Barato,
        descripcion: "tiene el bit setgid",
    },
    Columna {
        nombre: "sha256",
        tipo: Tipo::Texto,
        coste: Coste::Caro,
        descripcion: "hash del contenido; es el nombre de la entidad de contenido del producto",
    },
];

/// Un fichero del sistema.
///
/// PELIGROSA: sin acotar recorre el disco entero. Ver la cabecera del modulo.
pub const FILES: Tabla = Tabla {
    nombre: "files",
    columnas: COLUMNAS_FICHEROS,
    descripcion: "un fichero del disco, con sus metadatos y su hash bajo demanda",
};

// ---------------------------------------------------------------------------
// file_xattrs
// ---------------------------------------------------------------------------
const COLUMNAS_XATTR: &[Columna] = &[
    RUTA,
    Columna {
        nombre: "name",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "nombre del atributo, por ejemplo security.capability",
    },
    Columna {
        nombre: "value_hex",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "valor en hexadecimal; son datos binarios, no texto",
    },
    Columna {
        nombre: "size",
        tipo: Tipo::Entero,
        coste: Coste::Barato,
        descripcion: "tamano del valor en bytes",
    },
    Columna {
        nombre: "sensitive",
        tipo: Tipo::Booleano,
        coste: Coste::Trivial,
        descripcion: "el atributo pertenece a un espacio que no conviene difundir",
    },
];

/// Un atributo extendido de un fichero.
///
/// El valor sale en hexadecimal a proposito: `security.capability` y
/// `system.posix_acl_access` son estructuras binarias, y convertirlas a texto
/// con reemplazo de lo no imprimible perderia justo los bytes que importan.
pub const FILE_XATTRS: Tabla = Tabla {
    nombre: "file_xattrs",
    columnas: COLUMNAS_XATTR,
    descripcion: "un atributo extendido de un fichero, con su valor en hexadecimal",
};

// ---------------------------------------------------------------------------
// file_acls
// ---------------------------------------------------------------------------
const COLUMNAS_ACL: &[Columna] = &[
    RUTA,
    Columna {
        nombre: "kind",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "access (la que se aplica) o default (la que heredan los hijos)",
    },
    Columna {
        nombre: "who",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "a quien aplica, en la forma de getfacl: user::, user:1000:, group::...",
    },
    Columna {
        nombre: "perms",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "permisos en la forma rwx",
    },
];

/// Una entrada de la ACL POSIX de un fichero.
///
/// Existe porque el modo de un fichero MIENTE cuando hay ACL: un fichero `600`
/// puede ser legible por otro usuario a traves de una entrada de ACL, y ninguna
/// tabla que mire solo los permisos lo vera. Un `ls -l` normal solo deja una
/// pista —un `+` al final del modo— que ningun analisis automatico mira.
pub const FILE_ACLS: Tabla = Tabla {
    nombre: "file_acls",
    columnas: COLUMNAS_ACL,
    descripcion: "una entrada de la ACL POSIX de un fichero, que el modo no enseña",
};

// ---------------------------------------------------------------------------
// suid_binaries
// ---------------------------------------------------------------------------
const COLUMNAS_SUID: &[Columna] = &[
    RUTA,
    Columna {
        nombre: "mode",
        tipo: Tipo::Entero,
        coste: Coste::Barato,
        descripcion: "permisos en octal",
    },
    Columna {
        nombre: "uid",
        tipo: Tipo::Entero,
        coste: Coste::Barato,
        descripcion: "dueno al que se eleva",
    },
    Columna {
        nombre: "gid",
        tipo: Tipo::Entero,
        coste: Coste::Barato,
        descripcion: "grupo al que se eleva",
    },
    Columna {
        nombre: "setuid",
        tipo: Tipo::Booleano,
        coste: Coste::Barato,
        descripcion: "eleva al dueno",
    },
    Columna {
        nombre: "setgid",
        tipo: Tipo::Booleano,
        coste: Coste::Barato,
        descripcion: "eleva al grupo",
    },
    Columna {
        nombre: "size",
        tipo: Tipo::Entero,
        coste: Coste::Barato,
        descripcion: "tamano en bytes",
    },
    Columna {
        nombre: "sha256",
        tipo: Tipo::Texto,
        coste: Coste::Caro,
        descripcion: "hash del binario",
    },
];

/// Un binario con el bit setuid o setgid.
///
/// PELIGROSA: encontrarlos exige recorrer el arbol. Acotada por `path` con un
/// prefijo —`/usr/%`, `/tmp/%`— responde en un instante, y acotar por `/tmp/` es
/// exactamente la pregunta que un analista hace cuando sospecha de una escalada.
pub const SUID_BINARIES: Tabla = Tabla {
    nombre: "suid_binaries",
    columnas: COLUMNAS_SUID,
    descripcion: "un binario con setuid o setgid, que es una via de escalada de privilegios",
};

// ---------------------------------------------------------------------------
// file_capabilities
// ---------------------------------------------------------------------------
const COLUMNAS_CAP_FICHERO: &[Columna] = &[
    RUTA,
    Columna {
        nombre: "capability",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "nombre de la capacidad que el binario obtiene al ejecutarse",
    },
    Columna {
        nombre: "set",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "permitted o inheritable",
    },
    Columna {
        nombre: "effective",
        tipo: Tipo::Booleano,
        coste: Coste::Barato,
        descripcion: "las permitidas se activan solas al ejecutar, sin que el programa las pida",
    },
];

/// Una capacidad concedida a un fichero ejecutable.
///
/// PELIGROSA por lo mismo que [`SUID_BINARIES`], y mas importante que ella: un
/// binario con `CAP_SYS_ADMIN` en su atributo extendido es tan peligroso como
/// uno `setuid root` y NO aparece en un `find -perm -4000`, que es lo que casi
/// todo el mundo busca. Es el `setuid` que nadie audita.
pub const FILE_CAPABILITIES: Tabla = Tabla {
    nombre: "file_capabilities",
    columnas: COLUMNAS_CAP_FICHERO,
    descripcion: "una capacidad concedida a un ejecutable por su atributo extendido",
};

// ---------------------------------------------------------------------------
// mounts
// ---------------------------------------------------------------------------
const COLUMNAS_MONTAJES: &[Columna] = &[
    Columna {
        nombre: "mountpoint",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "donde esta montado",
    },
    Columna {
        nombre: "device",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "origen: dispositivo, red o nombre del sistema virtual",
    },
    Columna {
        nombre: "fstype",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "tipo de sistema de ficheros",
    },
    Columna {
        nombre: "options",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "opciones del montaje, separadas por comas",
    },
    Columna {
        nombre: "propagation",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "shared, master, slave o private; decide si un montaje se propaga",
    },
    Columna {
        nombre: "root",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "que parte del sistema de ficheros de origen se monto; '/' salvo en bind",
    },
    Columna {
        nombre: "major",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "numero mayor de dispositivo",
    },
    Columna {
        nombre: "minor",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "numero menor de dispositivo",
    },
    Columna {
        nombre: "mount_id",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "identificador del montaje; unico mientras exista",
    },
    Columna {
        nombre: "writable",
        tipo: Tipo::Booleano,
        coste: Coste::Trivial,
        descripcion: "se monto para escritura",
    },
    Columna {
        nombre: "executable",
        tipo: Tipo::Booleano,
        coste: Coste::Trivial,
        descripcion: "permite ejecutar; un /tmp ejecutable es media escalada hecha",
    },
    Columna {
        nombre: "setuid_allowed",
        tipo: Tipo::Booleano,
        coste: Coste::Trivial,
        descripcion: "honra los bits setuid; nosuid en un montaje de datos es lo esperable",
    },
];

/// Un montaje del sistema de ficheros.
///
/// Se lee de `/proc/self/mountinfo` y no de `/proc/mounts`, que es lo que casi
/// todo el mundo hace y pierde tres cosas: el `root` del montaje —que es lo
/// unico que distingue un bind mount de un montaje normal—, la propagacion, y
/// los numeros de dispositivo que unen un montaje con su superbloque.
pub const MOUNTS: Tabla = Tabla {
    nombre: "mounts",
    columnas: COLUMNAS_MONTAJES,
    descripcion: "un montaje del sistema de ficheros, con su propagacion y sus opciones",
};

// ---------------------------------------------------------------------------
// superblocks
// ---------------------------------------------------------------------------
const COLUMNAS_SUPERBLOQUES: &[Columna] = &[
    Columna {
        nombre: "device",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "origen del sistema de ficheros",
    },
    Columna {
        nombre: "fstype",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "tipo de sistema de ficheros",
    },
    Columna {
        nombre: "options",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "opciones del SUPERBLOQUE, que son distintas de las del montaje",
    },
    Columna {
        nombre: "major",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "numero mayor de dispositivo",
    },
    Columna {
        nombre: "minor",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "numero menor de dispositivo",
    },
    Columna {
        nombre: "mountpoints",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "en cuantos sitios esta montado este mismo superbloque",
    },
];

/// Un superbloque, es decir, un sistema de ficheros montado una o mas veces.
///
/// La diferencia con [`MOUNTS`] no es academica: las opciones del superbloque
/// —`ro` del sistema de ficheros— y las del montaje —`ro` de ESE punto— pueden
/// contradecirse, y un bind mount de solo lectura sobre un superbloque de
/// escritura sigue siendo escribible desde el otro punto de montaje. Un
/// analista que mire solo `mounts` concluye que algo es inmutable cuando no lo
/// es.
pub const SUPERBLOCKS: Tabla = Tabla {
    nombre: "superblocks",
    columnas: COLUMNAS_SUPERBLOQUES,
    descripcion: "un sistema de ficheros montado, con las opciones de su superbloque",
};
