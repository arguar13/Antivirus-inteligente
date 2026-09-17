//! Las cinco tablas con las que nacio AegisQL (FASES 34, 38 y 57).
//!
//! Estan aparte de las que anadio la FASE 81 por una razon que no es de orden:
//! estas cinco las sirve el ejecutor de `aegis-hunt` con codigo escrito a mano
//! antes de que existiera el rasgo `Tabla`, y `processes` ademas expone
//! COLUMNAS CUALIFICADAS (`network.port`, `memory.entropy`, `graph.depth`) que
//! ninguna otra tabla tiene: cuantificadores existenciales sobre la coleccion
//! asociada a cada fila, que el ejecutor resuelve recorriendola.
//!
//! Esa forma no se ha extendido a las tablas nuevas, y conviene decir por que:
//! una columna cualificada es un `JOIN` implicito con el coste escondido en el
//! esquema. Funciona bien para las tres colecciones que cuelgan de un proceso y
//! seria un desastre generalizarla —`files.systemd_unit.enabled` no tendria
//! ninguna cota—. Las tablas de la FASE 81 se unen por `Eid`, que es explicito.

use super::{Columna, Coste, Tabla, Tipo};

// ---------------------------------------------------------------------------
// processes
// ---------------------------------------------------------------------------
const COLUMNAS_PROCESOS: &[Columna] = &[
    Columna {
        nombre: "pid",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "identificador del proceso",
    },
    Columna {
        nombre: "ppid",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "identificador del padre",
    },
    Columna {
        nombre: "start_ns",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "instante de arranque; con el pid forma la identidad estable",
    },
    Columna {
        nombre: "name",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "nombre del ejecutable, sin ruta",
    },
    Columna {
        nombre: "path",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "ruta completa de la imagen ejecutada",
    },
    Columna {
        nombre: "cmdline",
        tipo: Tipo::Texto,
        coste: Coste::Barato,
        descripcion: "linea de comandos completa",
    },
    Columna {
        nombre: "uid",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "usuario efectivo",
    },
    Columna {
        nombre: "gid",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "grupo efectivo",
    },
    Columna {
        nombre: "threads",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "numero de hilos",
    },
    Columna {
        nombre: "state",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "estado del planificador: running, sleeping, zombie...",
    },
    Columna {
        nombre: "sha256",
        tipo: Tipo::Texto,
        coste: Coste::Caro,
        descripcion: "hash del ejecutable en disco",
    },
    // Columnas cualificadas: cuantificadores existenciales sobre la coleccion
    // asociada al proceso. Ver la nota de cabecera sobre por que no hay JOIN.
    Columna {
        nombre: "network.port",
        tipo: Tipo::Entero,
        coste: Coste::Medio,
        descripcion: "alguna conexion del proceso usa este puerto remoto",
    },
    Columna {
        nombre: "network.local_port",
        tipo: Tipo::Entero,
        coste: Coste::Medio,
        descripcion: "alguna conexion del proceso escucha o sale por este puerto local",
    },
    Columna {
        nombre: "network.remote_ip",
        tipo: Tipo::Texto,
        coste: Coste::Medio,
        descripcion: "alguna conexion del proceso va a esta direccion",
    },
    Columna {
        nombre: "network.state",
        tipo: Tipo::Texto,
        coste: Coste::Medio,
        descripcion: "alguna conexion del proceso esta en este estado TCP",
    },
    Columna {
        nombre: "memory.entropy",
        tipo: Tipo::Real,
        coste: Coste::Caro,
        descripcion: "entropia maxima entre las regiones privadas y ejecutables",
    },
    Columna {
        nombre: "memory.rwx",
        tipo: Tipo::Booleano,
        coste: Coste::Medio,
        descripcion: "el proceso tiene alguna region legible, escribible y ejecutable",
    },
    Columna {
        nombre: "memory.private_exec",
        tipo: Tipo::Entero,
        coste: Coste::Medio,
        descripcion: "cuantas regiones privadas y ejecutables tiene (indicio de inyeccion)",
    },
    Columna {
        nombre: "graph.techniques",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "tecnicas ATT&CK observadas sobre este proceso",
    },
    Columna {
        nombre: "graph.depth",
        tipo: Tipo::Entero,
        coste: Coste::Barato,
        descripcion: "profundidad en el arbol de linaje",
    },
    Columna {
        nombre: "graph.injected_by",
        tipo: Tipo::Entero,
        coste: Coste::Barato,
        descripcion: "pid que inyecto codigo en este proceso, o 0",
    },
];

/// Un proceso vivo del endpoint.
pub const PROCESSES: Tabla = Tabla {
    nombre: "processes",
    columnas: COLUMNAS_PROCESOS,
    descripcion: "un proceso vivo del endpoint",
};

// ---------------------------------------------------------------------------
// connections
// ---------------------------------------------------------------------------
const COLUMNAS_CONEXIONES: &[Columna] = &[
    Columna {
        nombre: "pid",
        tipo: Tipo::Entero,
        coste: Coste::Barato,
        descripcion: "proceso propietario del socket",
    },
    Columna {
        nombre: "protocol",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "tcp o udp",
    },
    Columna {
        nombre: "local_port",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "puerto local",
    },
    Columna {
        nombre: "remote_ip",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "direccion remota",
    },
    Columna {
        nombre: "remote_port",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "puerto remoto",
    },
    Columna {
        nombre: "state",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "estado TCP: established, listen, syn_sent...",
    },
];

/// Un socket con su proceso propietario.
pub const CONNECTIONS: Tabla = Tabla {
    nombre: "connections",
    columnas: COLUMNAS_CONEXIONES,
    descripcion: "un socket con su proceso propietario",
};

// ---------------------------------------------------------------------------
// memory_regions
// ---------------------------------------------------------------------------
const COLUMNAS_MEMORIA: &[Columna] = &[
    Columna {
        nombre: "pid",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "proceso dueno de la region",
    },
    Columna {
        nombre: "start",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "direccion inicial",
    },
    Columna {
        nombre: "size",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "tamano en bytes",
    },
    Columna {
        nombre: "perms",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "permisos en formato rwxp",
    },
    Columna {
        nombre: "private",
        tipo: Tipo::Booleano,
        coste: Coste::Trivial,
        descripcion: "region privada, no respaldada por un fichero compartido",
    },
    Columna {
        nombre: "path",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "fichero que respalda la region, vacio si es anonima",
    },
    Columna {
        nombre: "entropy",
        tipo: Tipo::Real,
        coste: Coste::Caro,
        descripcion: "entropia de Shannon del contenido; alta sugiere cifrado o empaquetado",
    },
];

/// Una region del mapa de memoria de un proceso.
pub const MEMORY_REGIONS: Tabla = Tabla {
    nombre: "memory_regions",
    columnas: COLUMNAS_MEMORIA,
    descripcion: "una region del mapa de memoria de un proceso",
};

// ---------------------------------------------------------------------------
// graph_edges
// ---------------------------------------------------------------------------
const COLUMNAS_ARISTAS: &[Columna] = &[
    Columna {
        nombre: "src_pid",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "proceso origen de la relacion",
    },
    Columna {
        nombre: "dst_pid",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "proceso destino",
    },
    Columna {
        nombre: "kind",
        tipo: Tipo::Texto,
        coste: Coste::Trivial,
        descripcion: "spawned, injected, traced o wrote",
    },
    Columna {
        nombre: "ts_ns",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "instante en que se observo",
    },
];

/// Una relacion causal del grafo de comportamiento.
pub const GRAPH_EDGES: Tabla = Tabla {
    nombre: "graph_edges",
    columnas: COLUMNAS_ARISTAS,
    descripcion: "una relacion causal del grafo de comportamiento",
};

// ---------------------------------------------------------------------------
// memory (escaneo YARA sobre la memoria del proceso, FASE 57)
// ---------------------------------------------------------------------------
const COLUMNAS_MEMORIA_YARA: &[Columna] = &[
    Columna {
        nombre: "pid",
        tipo: Tipo::Entero,
        coste: Coste::Trivial,
        descripcion: "proceso cuya memoria se escaneo",
    },
    Columna {
        nombre: "yara_match",
        tipo: Tipo::Texto,
        // Caro a proposito: escanear la memoria con YARA lee y procesa contenido,
        // como el hash o la entropia. El planificador lo evalua el ultimo, solo
        // sobre las filas que ya pasaron los predicados baratos.
        coste: Coste::Caro,
        descripcion: "alguna region de la memoria del proceso coincide con esta regla YARA",
    },
];

/// Un proceso cuya memoria se escanea con reglas YARA.
pub const MEMORY: Tabla = Tabla {
    nombre: "memory",
    columnas: COLUMNAS_MEMORIA_YARA,
    descripcion: "un proceso cuya memoria se escanea con reglas YARA (RAM hunting de la flota)",
};
