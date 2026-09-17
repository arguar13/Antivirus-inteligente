//! Tablas de procesos anadidas por la FASE 81.
//!
//! `processes` y `memory_regions` ya existian y estan en [`super::nucleo`].
//! Estas ocho son lo que cuelga de un proceso y que AegisQL no podia preguntar:
//! sus argumentos uno a uno, su entorno, lo que tiene abierto, sus hilos, sus
//! capacidades, sus espacios de nombres, su cgroup y su contexto de SELinux.
//!
//! # Por que casi todas llevan `pid` y por que importa
//!
//! Todas se leen de `/proc/<pid>/algo`. Sin acotar por `pid`, cada una recorre
//! los miles de procesos de la maquina abriendo un fichero por cada uno; con
//! `WHERE pid = N`, abre exactamente uno. Esa diferencia es la razon de que el
//! empuje de predicados exista, y la columna `pid` esta declarada `Trivial` en
//! todas para que el planificador la evalue siempre la primera.

use super::{Columna, Coste, Tabla, Tipo};

/// Columna `pid`, identica en las ocho tablas.
const PID: Columna = Columna {
    nombre: "pid",
    tipo: Tipo::Entero,
    coste: Coste::Trivial,
    descripcion: "proceso al que pertenece la fila",
};

// ---------------------------------------------------------------------------
// process_arguments
// ---------------------------------------------------------------------------
const COLUMNAS_ARGUMENTOS: &[Columna] = &[
    PID,
    Columna {
        nombre: "position",
        tipo: Tipo::Entero,
        coste: Coste::Barato,
        descripcion: "posicion del argumento, siendo 0 el propio programa",
    },
    Columna {
        nombre: "value",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "el argumento tal cual, sin recortar ni reunir",
    },
];

/// Un argumento suelto de la linea de comandos de un proceso.
///
/// `processes.cmdline` da la linea entera reunida con espacios, que es comoda
/// de leer y MIENTE cuando un argumento contiene un espacio: `sh -c "rm -rf /"`
/// y `sh -c rm -rf /` se escriben igual. Un analista que caza por argumentos
/// necesita verlos separados como los recibio el `execve`.
pub const PROCESS_ARGUMENTS: Tabla = Tabla {
    nombre: "process_arguments",
    columnas: COLUMNAS_ARGUMENTOS,
    descripcion: "un argumento de la linea de comandos de un proceso, sin reunir",
};

// ---------------------------------------------------------------------------
// process_environment
// ---------------------------------------------------------------------------
const COLUMNAS_ENTORNO: &[Columna] = &[
    PID,
    Columna {
        nombre: "key",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "nombre de la variable",
    },
    Columna {
        nombre: "value",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "valor; puede contener credenciales, ver la descripcion de la tabla",
    },
];

/// El entorno de un proceso.
///
/// ES LA TABLA MAS SENSIBLE DEL CATALOGO y conviene que su descripcion lo diga,
/// porque la ve el analista antes de ejecutar: el entorno de un proceso lleva
/// rutinariamente tokens de nube, contrasenas de base de datos y claves de API.
/// Consultarla a la flota entera y devolver el resultado al plano de control
/// mueve esos secretos de una maquina a otra.
///
/// Por eso `LD_PRELOAD` —que es lo que casi siempre se busca aqui— tiene su
/// propia tabla en [`super::super::esquema`]: `preload`, que devuelve UNA
/// variable y no el saco entero.
pub const PROCESS_ENVIRONMENT: Tabla = Tabla {
    nombre: "process_environment",
    columnas: COLUMNAS_ENTORNO,
    descripcion: "una variable de entorno de un proceso (contiene secretos: acotar siempre)",
};

// ---------------------------------------------------------------------------
// process_open_files
// ---------------------------------------------------------------------------
const COLUMNAS_ABIERTOS: &[Columna] = &[
    PID,
    Columna {
        nombre: "fd",
        tipo: Tipo::Entero,
        coste: Coste::Barato,
        descripcion: "numero de descriptor",
    },
    Columna {
        nombre: "path",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "a donde apunta el descriptor, resuelto",
    },
    Columna {
        nombre: "kind",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "file, socket, pipe, anon_inode, dir, char, block o unknown",
    },
    Columna {
        nombre: "inode",
        tipo: Tipo::Entero,
        coste: Coste::Barato,
        descripcion: "inodo del objeto abierto; es la clave que une un socket con su proceso",
    },
    Columna {
        nombre: "deleted",
        tipo: Tipo::Booleano,
        coste: Coste::Barato,
        descripcion: "el fichero abierto ya no tiene nombre en el disco",
    },
];

/// Un descriptor abierto por un proceso.
///
/// La columna `deleted` es la que gana su sitio: un binario borrado del disco
/// pero todavia mapeado y en ejecucion es una de las tecnicas de persistencia
/// mas viejas que hay, y es INVISIBLE para cualquier tabla que mire el sistema
/// de ficheros. Solo se ve desde el lado del proceso.
pub const PROCESS_OPEN_FILES: Tabla = Tabla {
    nombre: "process_open_files",
    columnas: COLUMNAS_ABIERTOS,
    descripcion: "un descriptor de fichero abierto por un proceso, con su destino resuelto",
};

// ---------------------------------------------------------------------------
// process_threads
// ---------------------------------------------------------------------------
const COLUMNAS_HILOS: &[Columna] = &[
    PID,
    Columna {
        nombre: "tid",
        tipo: Tipo::Entero,
        coste: Coste::Barato,
        descripcion: "identificador del hilo",
    },
    Columna {
        nombre: "name",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "nombre del hilo, que el proceso puede cambiar a voluntad",
    },
    Columna {
        nombre: "state",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "estado del planificador para este hilo",
    },
    Columna {
        nombre: "start_ticks",
        tipo: Tipo::Entero,
        coste: Coste::Barato,
        descripcion: "arranque del hilo en tics de reloj desde el arranque del sistema",
    },
];

/// Un hilo de un proceso.
///
/// El nombre de un hilo lo escribe el propio proceso y no vale como identidad
/// —un implante se llama `kworker/0:2` sin ningun esfuerzo—, pero un hilo cuyo
/// arranque es MUY posterior al del proceso que lo aloja es exactamente lo que
/// deja una inyeccion por `CreateRemoteThread` y sus equivalentes.
pub const PROCESS_THREADS: Tabla = Tabla {
    nombre: "process_threads",
    columnas: COLUMNAS_HILOS,
    descripcion: "un hilo de un proceso, con su instante de arranque propio",
};

// ---------------------------------------------------------------------------
// process_capabilities
// ---------------------------------------------------------------------------
const COLUMNAS_CAPACIDADES: &[Columna] = &[
    PID,
    Columna {
        nombre: "set",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "permitted, effective, inheritable, bounding o ambient",
    },
    Columna {
        nombre: "capability",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "nombre de la capacidad, por ejemplo CAP_SYS_ADMIN",
    },
];

/// Una capacidad de un proceso, por conjunto.
///
/// Se devuelve UNA FILA POR CAPACIDAD Y CONJUNTO en vez de la mascara
/// hexadecimal de `/proc/<pid>/status`, y es la decision que hace util la
/// tabla: `WHERE capability = 'CAP_SYS_ADMIN'` es una pregunta que un analista
/// escribe; `WHERE capeff = '000001ffffffffff'` no la escribe nadie, y ademas
/// la mascara cambia de longitud entre versiones del nucleo.
pub const PROCESS_CAPABILITIES: Tabla = Tabla {
    nombre: "process_capabilities",
    columnas: COLUMNAS_CAPACIDADES,
    descripcion: "una capacidad concedida a un proceso, con el conjunto al que pertenece",
};

// ---------------------------------------------------------------------------
// process_namespaces
// ---------------------------------------------------------------------------
const COLUMNAS_ESPACIOS: &[Columna] = &[
    PID,
    Columna {
        nombre: "kind",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "mnt, net, pid, uts, ipc, user, cgroup o time",
    },
    Columna {
        nombre: "inode",
        tipo: Tipo::Entero,
        coste: Coste::Barato,
        descripcion: "inodo del espacio de nombres: dos procesos con el mismo inodo lo comparten",
    },
    Columna {
        nombre: "shared_with_init",
        tipo: Tipo::Booleano,
        coste: Coste::Barato,
        descripcion: "comparte este espacio con el proceso 1, es decir, no esta aislado en el",
    },
];

/// Un espacio de nombres de un proceso.
///
/// `shared_with_init` es lo que convierte esta tabla en deteccion y no en
/// inventario: un proceso DENTRO de un contenedor que comparte el espacio de
/// nombres de red o de PID con el proceso 1 del anfitrion no esta contenido, y
/// esa es la forma que tiene un escape de contenedor de verse desde fuera.
pub const PROCESS_NAMESPACES: Tabla = Tabla {
    nombre: "process_namespaces",
    columnas: COLUMNAS_ESPACIOS,
    descripcion: "un espacio de nombres de un proceso, y si lo comparte con el proceso 1",
};

// ---------------------------------------------------------------------------
// process_cgroups
// ---------------------------------------------------------------------------
const COLUMNAS_CGROUPS: &[Columna] = &[
    PID,
    Columna {
        nombre: "hierarchy",
        tipo: Tipo::Entero,
        coste: Coste::Barato,
        descripcion: "numero de jerarquia; 0 es la unificada de cgroup v2",
    },
    Columna {
        nombre: "controllers",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "controladores de esta jerarquia, separados por comas; vacio en v2",
    },
    Columna {
        nombre: "path",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "ruta dentro de la jerarquia; es de donde sale la identidad del contenedor",
    },
];

/// El cgroup de un proceso.
pub const PROCESS_CGROUPS: Tabla = Tabla {
    nombre: "process_cgroups",
    columnas: COLUMNAS_CGROUPS,
    descripcion: "la pertenencia de un proceso a una jerarquia de cgroups",
};

// ---------------------------------------------------------------------------
// process_selinux
// ---------------------------------------------------------------------------
const COLUMNAS_SELINUX: &[Columna] = &[
    PID,
    Columna {
        nombre: "context",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "contexto completo, tal y como lo escribe el nucleo",
    },
    Columna {
        nombre: "user",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "usuario SELinux",
    },
    Columna {
        nombre: "role",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "rol",
    },
    Columna {
        nombre: "type",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "tipo o dominio, que es lo que de verdad decide lo que el proceso puede hacer",
    },
    Columna {
        nombre: "level",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "nivel MLS/MCS, si lo hay",
    },
];

/// El contexto de seguridad obligatoria de un proceso.
///
/// La tabla existe tambien —y sobre todo— para poder decir que NO hay: en una
/// maquina sin SELinux devuelve su motivo, no cero filas. Un informe que dice
/// «ningun proceso en dominio `unconfined_t`» es tranquilizador y es falso si lo
/// que pasaba es que SELinux no estaba puesto.
pub const PROCESS_SELINUX: Tabla = Tabla {
    nombre: "process_selinux",
    columnas: COLUMNAS_SELINUX,
    descripcion: "el contexto SELinux de un proceso, descompuesto en sus cuatro partes",
};
