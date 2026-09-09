//! Deteccion de cadenas de ataque sobre el grafo.
//!
//! # Por que hace falta esto y no basta con sumar tecnicas
//!
//! Las tecnicas de una intrusion real, por separado, son todas defendibles: un
//! servidor web lanza procesos, un interprete de comandos se ejecuta, alguien
//! descarga un fichero, alguien le pone permisos de ejecucion. Cada una vista
//! sola no justifica cortar nada. **Juntas y en ese orden** son un compromiso
//! por ejecucion remota de codigo, y no hay una lectura benigna.
//!
//! Eso es lo que este modulo puntua: la FORMA de la cadena, no la suma de sus
//! partes.
//!
//! # Como se empareja
//!
//! Un patron es una secuencia ordenada de pasos que tiene que aparecer como
//! **subsecuencia** del camino causal raiz -> nodo. Dos decisiones concretas:
//!
//! - El ULTIMO paso se ancla en el nodo que se esta puntuando. Un patron
//!   describe una cadena que CULMINA en ese nodo, asi que dejar que el paso
//!   final case en un nodo intermedio marcaria la cadena en sitios donde
//!   todavia no ha pasado nada. Ademas evita un fallo real del emparejamiento
//!   voraz: sin anclaje, un nodo intermedio que cumple por casualidad el paso
//!   final —un interprete que tambien vive en `/tmp`— consume ese paso y la
//!   cadena de verdad deja de reconocerse. Un atacante puede provocar eso a
//!   proposito.
//! - Los pasos anteriores pueden satisfacerse en el MISMO nodo unos y otros.
//!   Hace falta porque la cadena real se reparte entre hermanos: el interprete
//!   no descarga ni cambia permisos, lanza a quien lo hace. Para que eso no
//!   degenere en "un nodo cumple el patron entero", cada patron declara un
//!   minimo de nodos DISTINTOS que tiene que abarcar.
//! - Los pasos que hablan de lo que un nodo *provoco* miran solo a sus hijos
//!   DIRECTOS, no a todo su subarbol. Mirar el subarbol entero haria que el
//!   servidor de la raiz cumpliera cualquier paso, porque debajo de el acaba
//!   estando todo lo que pasa en la maquina.

use std::collections::HashSet;

use aegis_scal::process::ProcessKey;

use crate::dag::BehaviorGraph;
use crate::technique::Technique;

/// Nombres de servidores expuestos a Internet.
///
/// Un proceso de esta lista lanzando un interprete es la firma de una ejecucion
/// remota de codigo: los servidores atienden peticiones, no abren shells.
pub const SERVIDORES: &[&str] = &[
    "nginx",
    "httpd",
    "apache2",
    "php-fpm",
    "php-fpm7.4",
    "php-fpm8.1",
    "php-fpm8.2",
    "tomcat",
    "java",
    "node",
    "gunicorn",
    "uwsgi",
    "haproxy",
    "lighttpd",
    "caddy",
];

/// Interpretes de comandos.
pub const INTERPRETES: &[&str] = &[
    "sh", "bash", "dash", "zsh", "ksh", "ash", "fish", "csh", "tcsh", "busybox",
];

/// Herramientas de transferencia, la forma habitual de traer la segunda etapa.
pub const DESCARGADORES: &[&str] = &[
    "curl", "wget", "nc", "ncat", "netcat", "socat", "tftp", "ftp", "scp", "sftp", "rsync",
];

/// Prefijos de directorios escribibles por cualquiera.
///
/// Ejecutar desde aqui no es ilegal, pero es donde acaba todo lo que se
/// descarga: un binario que se ejecuta desde `/tmp` al final de una cadena de
/// descarga no tiene lectura benigna.
pub const DIRECTORIOS_ESCRIBIBLES: &[&str] =
    &["/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/var/lock/"];

/// Un paso de un patron de cadena.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// El nodo es un servidor expuesto.
    Server,
    /// El nodo es un interprete de comandos.
    Shell,
    /// El nodo lanzo directamente una herramienta de transferencia.
    SpawnedDownloader,
    /// El nodo, o alguno de sus hijos directos, ejecuto la tecnica.
    CausedTechnique(Technique),
    /// El propio nodo ejecuto la tecnica.
    Observed(Technique),
    /// El nodo se ejecuta desde un directorio escribible por cualquiera.
    ExecFromWritable,
}

/// Un patron de cadena de ataque.
#[derive(Debug, Clone, Copy)]
pub struct ChainPattern {
    /// Identificador estable, para registros y para la consola.
    pub name: &'static str,
    /// Que describe la cadena.
    pub description: &'static str,
    /// Pasos en orden.
    pub steps: &'static [Step],
    /// Nodos distintos que la cadena tiene que abarcar como minimo.
    pub min_nodes: usize,
    /// Puntos que aporta al riesgo del nodo final.
    pub bonus: u8,
    /// Tecnicas de ATT&CK que la cadena cubre, para el informe.
    pub techniques: &'static [Technique],
}

/// Patrones que el motor evalua por defecto.
pub const PATRONES: &[ChainPattern] = &[
    ChainPattern {
        name: "web-rce",
        description: "servidor expuesto -> interprete -> descarga -> permisos -> ejecucion desde directorio escribible",
        steps: &[
            Step::Server,
            Step::Shell,
            Step::SpawnedDownloader,
            Step::CausedTechnique(Technique::PermissionsModification),
            Step::ExecFromWritable,
        ],
        min_nodes: 3,
        // El bono es alto —por si solo cruza el umbral de aislamiento— porque
        // el patron es muy especifico: cinco pasos, tres nodos distintos y un
        // servidor en la raiz. Un servidor web que abre un interprete que
        // descarga algo, lo hace ejecutable y lo ejecuta desde /tmp no tiene
        // lectura benigna en ningun despliegue.
        bonus: 80,
        techniques: &[
            Technique::CommandInterpreter,
            Technique::IngressToolTransfer,
            Technique::PermissionsModification,
        ],
    },
    ChainPattern {
        name: "inyeccion-a-c2",
        description: "inyeccion en otro proceso y salida a red desde el proceso inyectado",
        steps: &[
            Step::Observed(Technique::ProcessInjection),
            Step::Observed(Technique::ApplicationLayerProtocol),
        ],
        min_nodes: 2,
        // Inyectar sirve precisamente para que el trafico salga de un proceso
        // que no levanta sospechas. Ver las dos mitades unidas por la arista de
        // inyeccion es ver la tecnica completa.
        bonus: 50,
        techniques: &[
            Technique::ProcessInjection,
            Technique::ApplicationLayerProtocol,
        ],
    },
    ChainPattern {
        name: "cifrado-desde-interprete",
        description: "interprete de comandos que acaba cifrando ficheros del usuario",
        steps: &[
            Step::Shell,
            Step::Observed(Technique::DataEncryptedForImpact),
        ],
        min_nodes: 2,
        bonus: 35,
        techniques: &[
            Technique::CommandInterpreter,
            Technique::DataEncryptedForImpact,
        ],
    },
    ChainPattern {
        name: "descarga-y-persistencia",
        description: "se trae una herramienta y acto seguido se instala una tarea programada",
        steps: &[
            Step::SpawnedDownloader,
            Step::CausedTechnique(Technique::ScheduledTask),
        ],
        min_nodes: 2,
        bonus: 40,
        techniques: &[Technique::IngressToolTransfer, Technique::ScheduledTask],
    },
    ChainPattern {
        name: "impacto-y-borrado",
        description: "cifrado de datos seguido de borrado de rastros",
        steps: &[
            Step::Observed(Technique::DataEncryptedForImpact),
            Step::Observed(Technique::IndicatorRemoval),
        ],
        min_nodes: 1,
        // Un solo nodo basta: el mismo proceso que cifra y luego borra los
        // registros es el caso tipico, y ahi no hay ambiguedad ninguna.
        bonus: 45,
        techniques: &[
            Technique::DataEncryptedForImpact,
            Technique::IndicatorRemoval,
        ],
    },
];

/// Indica si el nombre de la imagen esta en una lista.
fn en_lista(nombre: Option<&str>, lista: &[&str]) -> bool {
    match nombre {
        Some(n) => lista.contains(&n),
        None => false,
    }
}

/// Evalua un paso sobre un nodo del camino.
fn cumple(g: &BehaviorGraph, key: ProcessKey, step: Step) -> bool {
    let Some(n) = g.node(key) else { return false };
    match step {
        Step::Server => en_lista(n.image_name(), SERVIDORES),
        Step::Shell => en_lista(n.image_name(), INTERPRETES),
        Step::SpawnedDownloader => g
            .children(key)
            .iter()
            .filter_map(|c| g.node(*c))
            .any(|c| en_lista(c.image_name(), DESCARGADORES)),
        Step::Observed(t) => n.techniques.contains_key(&t),
        Step::CausedTechnique(t) => {
            n.techniques.contains_key(&t)
                || g.children(key)
                    .iter()
                    .filter_map(|c| g.node(*c))
                    .any(|c| c.techniques.contains_key(&t))
        }
        Step::ExecFromWritable => n
            .image
            .as_ref()
            .and_then(|p| p.to_str())
            .map(|p| DIRECTORIOS_ESCRIBIBLES.iter().any(|d| p.starts_with(d)))
            .unwrap_or(false),
    }
}

/// Empareja un patron contra un camino causal.
///
/// Devuelve `true` si el ultimo paso se cumple en el nodo final del camino, los
/// anteriores aparecen en orden a lo largo de el, y la cadena abarca al menos
/// `min_nodes` nodos distintos.
pub fn matches(g: &BehaviorGraph, camino: &[ProcessKey], p: &ChainPattern) -> bool {
    let (Some(&ultimo), Some((final_, previos))) = (camino.last(), p.steps.split_last()) else {
        return false;
    };

    // El paso final se ancla en el nodo puntuado. Ver la nota del modulo.
    if !cumple(g, ultimo, *final_) {
        return false;
    }

    let mut usados: HashSet<ProcessKey> = HashSet::new();
    usados.insert(ultimo);

    let mut i = 0usize;
    for step in previos {
        let mut encontrado = false;
        while i < camino.len() {
            if cumple(g, camino[i], *step) {
                usados.insert(camino[i]);
                encontrado = true;
                break;
            }
            i += 1;
        }
        if !encontrado {
            return false;
        }
    }
    usados.len() >= p.min_nodes
}

/// Patrones que casan con el camino causal de un nodo.
pub fn matching<'a>(
    g: &BehaviorGraph,
    key: ProcessKey,
    patrones: &'a [ChainPattern],
) -> Vec<&'a ChainPattern> {
    let camino = g.causal_path(key);
    patrones.iter().filter(|p| matches(g, &camino, p)).collect()
}
