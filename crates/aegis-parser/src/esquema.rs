//! Esquema de AegisQL: que tablas hay, que columnas tienen y cuanto cuesta cada
//! una.
//!
//! POR QUE EL ESQUEMA ES FIJO Y VIVE EN EL PARSER
//! ----------------------------------------------
//! Una consulta de caza se difunde a decenas de miles de endpoints. Si el
//! nombre de una columna se validara en el endpoint, un error de escritura del
//! operador se convertiria en decenas de miles de fallos remotos, cada uno con
//! su registro y su alerta, para un problema que se podia haber visto en la
//! consola antes de pulsar "ejecutar". Validando contra este esquema al
//! parsear, una columna inexistente es un error inmediato con su posicion.
//!
//! POR QUE NO HAY JOIN
//! -------------------
//! Un JOIN sin restricciones tiene coste cuadratico, y aqui el que paga ese
//! coste es el endpoint de un cliente: un portatil con bateria, o un servidor
//! de produccion. En vez de JOIN, las tablas exponen columnas CUALIFICADAS
//! (`network.port`, `memory.entropy`) que el ejecutor resuelve recorriendo la
//! coleccion asociada a cada fila. Semanticamente es un cuantificador
//! existencial: `network.port = 4444` significa "este proceso tiene ALGUNA
//! conexion por el puerto 4444".
//!
//! Esa decision hace tambien que el coste de cualquier consulta sea acotable:
//! filas de la tabla x tamano de la coleccion, y las dos cosas tienen limite.

/// Tipo de un valor de AegisQL.
///
/// Deliberadamente pocos. Cada tipo que se anade es una tabla de conversiones
/// que hay que definir, y una manera mas de que dos endpoints con arquitecturas
/// distintas respondan cosas distintas a la misma consulta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tipo {
    /// Entero con signo de 64 bits.
    Entero,
    /// Real de doble precision.
    Real,
    /// Texto.
    Texto,
    /// Booleano.
    Booleano,
}

impl Tipo {
    /// Nombre para los mensajes de error.
    pub fn nombre(self) -> &'static str {
        match self {
            Tipo::Entero => "entero",
            Tipo::Real => "real",
            Tipo::Texto => "texto",
            Tipo::Booleano => "booleano",
        }
    }

    /// Indica si los dos tipos se pueden comparar entre si.
    ///
    /// Entero y real si, porque escribir `memory.entropy > 7` en vez de `7.0`
    /// es lo que hace cualquiera y rechazarlo seria pedanteria. Texto con
    /// numero no: eso siempre es un error de quien escribe la consulta.
    pub fn comparable_con(self, otro: Tipo) -> bool {
        use Tipo::*;
        matches!(
            (self, otro),
            (Entero, Entero)
                | (Real, Real)
                | (Entero, Real)
                | (Real, Entero)
                | (Texto, Texto)
                | (Booleano, Booleano)
        )
    }
}

/// Cuanto cuesta obtener una columna.
///
/// No es informacion decorativa: el planificador ordena los predicados de menor
/// a mayor coste para que los caros se evaluen solo sobre las filas que ya
/// pasaron los baratos. La diferencia entre hacerlo y no hacerlo, en una flota
/// de diez mil maquinas, es la diferencia entre una caceria de segundos y una
/// que tumba la produccion del cliente.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Coste {
    /// Ya esta en memoria: leerla es mirar un campo.
    Trivial,
    /// Una o dos lecturas de /proc por fila.
    Barato,
    /// Recorre una coleccion por fila (conexiones, regiones de memoria).
    Medio,
    /// Lee y procesa contenido: hashes, entropia de memoria ajena.
    Caro,
}

/// Descripcion de una columna.
#[derive(Debug, Clone, Copy)]
pub struct Columna {
    /// Nombre tal y como se escribe en la consulta.
    pub nombre: &'static str,
    /// Tipo del valor.
    pub tipo: Tipo,
    /// Coste de obtenerlo.
    pub coste: Coste,
    /// Que significa. Se usa en la ayuda de la consola y en los errores.
    pub descripcion: &'static str,
}

/// Descripcion de una tabla.
#[derive(Debug, Clone, Copy)]
pub struct Tabla {
    /// Nombre en la consulta.
    pub nombre: &'static str,
    /// Columnas disponibles.
    pub columnas: &'static [Columna],
    /// Que representa cada fila.
    pub descripcion: &'static str,
}

impl Tabla {
    /// Busca una columna por nombre.
    pub fn columna(&self, nombre: &str) -> Option<&'static Columna> {
        self.columnas.iter().find(|c| c.nombre == nombre)
    }
}

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

/// Todas las tablas que AegisQL conoce.
pub const TABLAS: &[Tabla] = &[
    Tabla {
        nombre: "processes",
        columnas: COLUMNAS_PROCESOS,
        descripcion: "un proceso vivo del endpoint",
    },
    Tabla {
        nombre: "connections",
        columnas: COLUMNAS_CONEXIONES,
        descripcion: "un socket con su proceso propietario",
    },
    Tabla {
        nombre: "memory_regions",
        columnas: COLUMNAS_MEMORIA,
        descripcion: "una region del mapa de memoria de un proceso",
    },
    Tabla {
        nombre: "graph_edges",
        columnas: COLUMNAS_ARISTAS,
        descripcion: "una relacion causal del grafo de comportamiento",
    },
    Tabla {
        nombre: "memory",
        columnas: COLUMNAS_MEMORIA_YARA,
        descripcion: "un proceso cuya memoria se escanea con reglas YARA (RAM hunting de la flota)",
    },
];

/// Busca una tabla por nombre.
pub fn tabla(nombre: &str) -> Option<&'static Tabla> {
    TABLAS.iter().find(|t| t.nombre == nombre)
}

/// Nombres de tabla parecidos a uno dado, para sugerir en un error.
pub fn tablas_parecidas(nombre: &str) -> Vec<&'static str> {
    TABLAS
        .iter()
        .filter(|t| parecidos(t.nombre, nombre))
        .map(|t| t.nombre)
        .collect()
}

/// Nombres de columna parecidos a uno dado dentro de una tabla.
pub fn columnas_parecidas(t: &Tabla, nombre: &str) -> Vec<&'static str> {
    t.columnas
        .iter()
        .filter(|c| parecidos(c.nombre, nombre))
        .map(|c| c.nombre)
        .collect()
}

/// Heuristica de parecido para sugerencias.
///
/// Distancia de edicion acotada a 2, que cubre el error de tecleo tipico (una
/// letra de mas, de menos o cambiada) sin proponer disparates. No se usa una
/// biblioteca por una dependencia de veinte lineas.
fn parecidos(a: &str, b: &str) -> bool {
    if a.eq_ignore_ascii_case(b) {
        return true;
    }
    distancia_edicion(&a.to_ascii_lowercase(), &b.to_ascii_lowercase()) <= 2
}

/// Distancia de Levenshtein por programacion dinamica con una sola fila.
fn distancia_edicion(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }
    let mut fila: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut diagonal = fila[0];
        fila[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let anterior = fila[j + 1];
            let coste = usize::from(ca != cb);
            fila[j + 1] = (fila[j] + 1).min(anterior + 1).min(diagonal + coste);
            diagonal = anterior;
        }
    }
    fila[b.len()]
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn las_tablas_y_columnas_no_tienen_nombres_repetidos() {
        // Un duplicado haria que `columna()` devolviera el primero en silencio
        // y la consulta leyera algo distinto de lo que su autor cree.
        for t in TABLAS {
            for (i, c) in t.columnas.iter().enumerate() {
                let repetida = t.columnas[i + 1..].iter().any(|o| o.nombre == c.nombre);
                assert!(!repetida, "columna {} repetida en {}", c.nombre, t.nombre);
            }
        }
        for (i, t) in TABLAS.iter().enumerate() {
            let repetida = TABLAS[i + 1..].iter().any(|o| o.nombre == t.nombre);
            assert!(!repetida, "tabla {} repetida", t.nombre);
        }
    }

    #[test]
    fn toda_columna_tiene_descripcion() {
        // La consola la muestra como ayuda: una vacia es una columna que nadie
        // sabra usar.
        for t in TABLAS {
            assert!(!t.descripcion.is_empty(), "tabla {}", t.nombre);
            for c in t.columnas {
                assert!(
                    !c.descripcion.is_empty(),
                    "columna {}.{}",
                    t.nombre,
                    c.nombre
                );
            }
        }
    }

    #[test]
    fn entero_y_real_se_comparan_entre_si_pero_no_con_texto() {
        assert!(Tipo::Entero.comparable_con(Tipo::Real));
        assert!(Tipo::Real.comparable_con(Tipo::Entero));
        assert!(!Tipo::Texto.comparable_con(Tipo::Entero));
        assert!(!Tipo::Booleano.comparable_con(Tipo::Texto));
    }

    #[test]
    fn el_coste_ordena_de_trivial_a_caro() {
        assert!(Coste::Trivial < Coste::Barato);
        assert!(Coste::Barato < Coste::Medio);
        assert!(Coste::Medio < Coste::Caro);
    }

    #[test]
    fn se_sugiere_la_columna_cuando_hay_un_error_de_tecleo() {
        let t = tabla("processes").unwrap();
        assert!(columnas_parecidas(t, "pdi").contains(&"pid"));
        assert!(columnas_parecidas(t, "paht").contains(&"path"));
        // Un disparate no genera sugerencias inventadas.
        assert!(columnas_parecidas(t, "xyzzyzzy").is_empty());
    }

    #[test]
    fn la_distancia_de_edicion_es_correcta() {
        assert_eq!(distancia_edicion("", ""), 0);
        assert_eq!(distancia_edicion("pid", "pid"), 0);
        assert_eq!(distancia_edicion("pid", "pdi"), 2);
        assert_eq!(distancia_edicion("", "abc"), 3);
        assert_eq!(distancia_edicion("kitten", "sitting"), 3);
    }
}
