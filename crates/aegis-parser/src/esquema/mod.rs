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
    /// Su coste NO esta acotado por el tamano de la tabla (FASE 81).
    ///
    /// Los cuatro niveles anteriores comparten una propiedad: el trabajo crece
    /// con el numero de filas, y el numero de filas tiene techo —los procesos
    /// de una maquina, sus conexiones, sus regiones—. Hay estado del sistema
    /// que no cumple eso: recorrer el arbol de ficheros entero para encontrar
    /// los `suid`, o abrir cada inodo para leer sus capacidades, depende del
    /// disco del cliente y puede tardar minutos o no terminar.
    ///
    /// La diferencia no es de grado sino de clase, y por eso tiene nivel
    /// propio: una consulta que toca una tabla peligrosa SIN FILTRO no se
    /// ejecuta. Ver `validar_coste` en [`crate::plan`]. No es una recomendacion
    /// que el operador pueda saltarse con una opcion «avanzada»: esa opcion no
    /// existe, porque quien paga el error son cien mil maquinas de un cliente.
    Peligroso,
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

/// Contenedores vistos desde el nucleo del anfitrion (FASE 81).
pub mod contenedores;
/// Ficheros, atributos extendidos, ACL y montajes (FASE 81).
pub mod ficheros;
/// Usuarios, grupos, sesiones y credenciales (FASE 81).
pub mod identidad;
/// Las cinco tablas originales de AegisQL (FASES 34, 38 y 57).
pub mod nucleo;
/// Arranque, servicios, tareas, modulos y precarga (FASE 81).
pub mod persistencia;
/// CPU, memoria, buses, firmware y paquetes (FASE 81).
pub mod plataforma;
/// Procesos y todo lo que cuelga de ellos (FASE 81).
pub mod procesos;
/// Rutas, interfaces, vecinos, cortafuegos y sockets locales (FASE 81).
pub mod red;

/// Todas las tablas que AegisQL conoce.
///
/// Una sola lista, construida a partir de las constantes de cada submodulo. No
/// es un `Vec` que se rellene al arrancar: es una constante, asi que el catalogo
/// del lenguaje esta completo antes de que el programa ejecute una instruccion y
/// el plano de control lo puede consultar sin inicializar nada.
pub const TABLAS: &[Tabla] = &[
    // Las cinco originales.
    nucleo::PROCESSES,
    nucleo::CONNECTIONS,
    nucleo::MEMORY_REGIONS,
    nucleo::GRAPH_EDGES,
    nucleo::MEMORY,
    // FASE 81 — procesos.
    procesos::PROCESS_ARGUMENTS,
    procesos::PROCESS_ENVIRONMENT,
    procesos::PROCESS_OPEN_FILES,
    procesos::PROCESS_THREADS,
    procesos::PROCESS_CAPABILITIES,
    procesos::PROCESS_NAMESPACES,
    procesos::PROCESS_CGROUPS,
    procesos::PROCESS_SELINUX,
    // FASE 81 — ficheros.
    ficheros::FILES,
    ficheros::FILE_XATTRS,
    ficheros::FILE_ACLS,
    ficheros::SUID_BINARIES,
    ficheros::FILE_CAPABILITIES,
    ficheros::MOUNTS,
    ficheros::SUPERBLOCKS,
    // FASE 81 — red.
    red::ROUTES,
    red::INTERFACES,
    red::ARP_CACHE,
    red::FIREWALL_RULES,
    red::UNIX_SOCKETS,
    // FASE 81 — identidad.
    identidad::USERS,
    identidad::GROUPS,
    identidad::SESSIONS,
    identidad::SUDOERS,
    identidad::AUTHORIZED_KEYS,
    identidad::KERBEROS_TICKETS,
    // FASE 81 — persistencia.
    persistencia::SYSTEMD_UNITS,
    persistencia::SYSTEMD_TIMERS,
    persistencia::CRON_JOBS,
    persistencia::KERNEL_MODULES,
    persistencia::BOOT_IMAGES,
    persistencia::BOOT_ENTRIES,
    persistencia::SHELL_PROFILES,
    persistencia::PRELOAD,
    // FASE 81 — plataforma y paquetes.
    plataforma::PACKAGES,
    plataforma::CPU_INFO,
    plataforma::CPU_MITIGATIONS,
    plataforma::MEMORY_INFO,
    plataforma::BLOCK_DEVICES,
    plataforma::PCI_DEVICES,
    plataforma::USB_DEVICES,
    plataforma::FIRMWARE_INFO,
    plataforma::TPM_PCRS,
    // FASE 81 — contenedores.
    contenedores::CONTAINERS,
    contenedores::CONTAINER_IMAGES,
    contenedores::CONTAINER_MOUNTS,
    contenedores::CONTAINER_CAPABILITIES,
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
    fn el_coste_ordena_de_trivial_a_peligroso() {
        assert!(Coste::Trivial < Coste::Barato);
        assert!(Coste::Barato < Coste::Medio);
        assert!(Coste::Medio < Coste::Caro);
        // El orden importa de verdad: el planificador evalua por coste
        // creciente, asi que lo peligroso tiene que quedar el ultimo.
        assert!(Coste::Caro < Coste::Peligroso);
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
