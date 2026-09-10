//! Grafo dirigido aciclico de procesos.
//!
//! # Por que un DAG y no un arbol
//!
//! El linaje de procesos por si solo es un arbol: cada proceso tiene un padre.
//! Pero la causalidad que interesa a la deteccion no es solo quien lanzo a
//! quien. Cuando un proceso **inyecta** codigo en otro, o lo **traza**, la
//! actividad del segundo es responsabilidad del primero aunque no sea su hijo:
//! esa es toda la gracia de inyectar, romper el linaje para que el analista vea
//! un `gnome-calculator` conectando a Internet en vez de la macro que lo hizo.
//!
//! Modelar esas aristas convierte el arbol en un grafo dirigido, y obliga a
//! garantizar que sigue siendo **aciclico**: dos procesos que se inyectan
//! mutuamente crearian un ciclo, y cualquier recorrido de ancestros —que es la
//! operacion mas usada del motor— se colgaria. Por eso [`BehaviorGraph::link`]
//! rechaza la arista que cerraria un ciclo en vez de confiar en que no pase.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::path::PathBuf;

use aegis_scal::process::{ProcessInfo, ProcessKey};

use crate::technique::Technique;

/// Error al modificar el grafo.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GraphError {
    /// El nodo no existe.
    #[error("el proceso {0:?} no esta en el grafo")]
    UnknownNode(ProcessKey),
    /// La arista cerraria un ciclo.
    #[error("la arista {from:?} -> {to:?} cerraria un ciclo")]
    WouldCycle {
        /// Origen.
        from: ProcessKey,
        /// Destino.
        to: ProcessKey,
    },
    /// Un nodo no puede tener una arista a si mismo.
    #[error("un proceso no puede ser causa de si mismo: {0:?}")]
    SelfEdge(ProcessKey),
}

/// Naturaleza de una arista causal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdgeKind {
    /// El origen lanzo al destino. Es el linaje clasico.
    Spawned,
    /// El origen inyecto codigo en el destino.
    Injected,
    /// El origen traza al destino con `ptrace` o equivalente.
    Traced,
    /// El origen escribio el fichero que el destino ejecuta.
    Wrote,
}

impl EdgeKind {
    /// Fraccion del riesgo del origen que se propaga por esta arista.
    ///
    /// Inyectar es una relacion mucho mas fuerte que lanzar: un servidor lanza
    /// procesos legitimos todo el dia, pero nadie inyecta codigo en otro proceso
    /// por accidente.
    pub fn propagation(self) -> f32 {
        match self {
            EdgeKind::Injected => 0.95,
            EdgeKind::Wrote => 0.8,
            EdgeKind::Traced => 0.75,
            EdgeKind::Spawned => 0.6,
        }
    }
}

/// Una arista del grafo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Edge {
    /// Otro extremo de la arista.
    pub peer: ProcessKey,
    /// Naturaleza.
    pub kind: EdgeKind,
    /// Instante en que se observo.
    pub ts_ns: u64,
}

/// Un proceso dentro del grafo.
#[derive(Debug, Clone)]
pub struct Node {
    /// Identidad estable.
    pub key: ProcessKey,
    /// Ruta de la imagen, si se conoce.
    pub image: Option<PathBuf>,
    /// Linea de comandos.
    pub cmdline: Vec<String>,
    /// Instante en que el grafo lo dio de alta.
    pub seen_ns: u64,
    /// Instante de muerte, si ya murio.
    pub dead_ns: Option<u64>,
    /// Tecnicas observadas sobre ESTE proceso, con cuantas veces.
    pub techniques: BTreeMap<Technique, u32>,
    /// Aristas salientes: procesos de los que este es causa.
    pub out: Vec<Edge>,
    /// Aristas entrantes: procesos que son causa de este.
    pub incoming: Vec<Edge>,
}

impl Node {
    /// Nombre del ejecutable sin ruta.
    pub fn image_name(&self) -> Option<&str> {
        self.image.as_ref()?.file_name()?.to_str()
    }

    /// Indica si el proceso sigue vivo segun el grafo.
    pub fn alive(&self) -> bool {
        self.dead_ns.is_none()
    }
}

/// Limites de tamano del grafo.
#[derive(Debug, Clone, Copy)]
pub struct GraphLimits {
    /// Numero maximo de nodos.
    pub max_nodes: usize,
    /// Tiempo que se conserva un nodo muerto.
    ///
    /// No es cero: una deteccion puede llegar despues de que el proceso haya
    /// salido, y sin su nodo se pierde el linaje entero del incidente.
    pub dead_grace_ns: u64,
    /// Profundidad maxima al recorrer ancestros.
    pub max_depth: u16,
}

impl Default for GraphLimits {
    fn default() -> Self {
        Self {
            max_nodes: 16_384,
            dead_grace_ns: 5 * 60 * 1_000_000_000,
            max_depth: 64,
        }
    }
}

/// Grafo dirigido aciclico de procesos y su causalidad.
#[derive(Debug)]
pub struct BehaviorGraph {
    nodes: HashMap<ProcessKey, Node>,
    /// PID -> identidad viva, para resolver eventos que solo traen el PID.
    por_pid: HashMap<u32, ProcessKey>,
    /// Cola de muertos por antiguedad, para expirar en O(1) amortizado.
    muertos: VecDeque<(u64, ProcessKey)>,
    limits: GraphLimits,
}

impl BehaviorGraph {
    /// Crea un grafo vacio.
    pub fn new(limits: GraphLimits) -> BehaviorGraph {
        BehaviorGraph {
            nodes: HashMap::new(),
            por_pid: HashMap::new(),
            muertos: VecDeque::new(),
            limits,
        }
    }

    /// Numero de nodos.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Indica si el grafo esta vacio.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Limites configurados.
    pub fn limits(&self) -> GraphLimits {
        self.limits
    }

    /// Recorre los nodos del grafo, en orden no especificado.
    ///
    /// Es de SOLO LECTURA a proposito: quien consulta el grafo —el ejecutor de
    /// AegisQL, el informe de linaje que sube al plano de control— necesita
    /// enumerarlo, pero nadie de fuera puede modificarlo. Las mutaciones pasan
    /// todas por `insert`, `link`, `observe` y `mark_dead`, que son las que
    /// mantienen los indices y los limites de tamano coherentes.
    pub fn nodos(&self) -> impl Iterator<Item = (&ProcessKey, &Node)> {
        self.nodes.iter()
    }

    /// Nodo por identidad.
    pub fn node(&self, key: ProcessKey) -> Option<&Node> {
        self.nodes.get(&key)
    }

    /// Identidad viva asociada a un PID, si el grafo la conoce.
    pub fn key_of_pid(&self, pid: u32) -> Option<ProcessKey> {
        self.por_pid.get(&pid).copied()
    }

    /// Da de alta un proceso y lo enlaza con su padre si esta en el grafo.
    ///
    /// Es idempotente sobre la identidad: volver a insertar la misma clave
    /// actualiza el retrato sin duplicar aristas.
    pub fn insert(&mut self, info: &ProcessInfo, now_ns: u64) {
        let key = info.key;
        let padre = self.por_pid.get(&info.parent_pid).copied();

        let entrada = self.nodes.entry(key).or_insert_with(|| Node {
            key,
            image: info.image.clone(),
            cmdline: info.cmdline.clone(),
            seen_ns: now_ns,
            dead_ns: None,
            techniques: BTreeMap::new(),
            out: Vec::new(),
            incoming: Vec::new(),
        });
        // Un proceso que reaparece tras un `exec` cambia de imagen conservando
        // su identidad: el retrato se refresca, el historial no se pierde.
        if info.image.is_some() {
            entrada.image = info.image.clone();
        }
        if !info.cmdline.is_empty() {
            entrada.cmdline = info.cmdline.clone();
        }
        entrada.dead_ns = None;

        self.por_pid.insert(info.key.pid, key);

        if let Some(p) = padre {
            if p != key {
                // El linaje no puede cerrar ciclos —un hijo es siempre nuevo—,
                // asi que se ignora el error por construccion.
                let _ = self.link(p, key, EdgeKind::Spawned, now_ns);
            }
        }
    }

    /// Marca un proceso como muerto. El nodo se conserva durante la gracia.
    pub fn mark_dead(&mut self, key: ProcessKey, now_ns: u64) {
        if let Some(n) = self.nodes.get_mut(&key) {
            if n.dead_ns.is_none() {
                n.dead_ns = Some(now_ns);
                self.muertos.push_back((now_ns, key));
            }
        }
        // El PID queda libre para que lo reclame otro proceso. No borrarlo aqui
        // es como una identidad muerta acaba capturando los eventos del proceso
        // que reutilice su numero.
        if self.por_pid.get(&key.pid) == Some(&key) {
            self.por_pid.remove(&key.pid);
        }
    }

    /// Anota una observacion de tecnica sobre un proceso.
    pub fn observe(&mut self, key: ProcessKey, t: Technique) -> Result<(), GraphError> {
        let n = self
            .nodes
            .get_mut(&key)
            .ok_or(GraphError::UnknownNode(key))?;
        *n.techniques.entry(t).or_insert(0) += 1;
        Ok(())
    }

    /// Anade una arista causal, garantizando que el grafo sigue siendo aciclico.
    pub fn link(
        &mut self,
        from: ProcessKey,
        to: ProcessKey,
        kind: EdgeKind,
        ts_ns: u64,
    ) -> Result<(), GraphError> {
        if from == to {
            return Err(GraphError::SelfEdge(from));
        }
        if !self.nodes.contains_key(&from) {
            return Err(GraphError::UnknownNode(from));
        }
        if !self.nodes.contains_key(&to) {
            return Err(GraphError::UnknownNode(to));
        }
        // Duplicar una arista no es un error: la misma inyeccion se puede
        // observar por dos sondas distintas.
        if self.nodes[&from]
            .out
            .iter()
            .any(|e| e.peer == to && e.kind == kind)
        {
            return Ok(());
        }
        // Si `from` ya es alcanzable desde `to`, anadir la arista cerraria un
        // ciclo y el recorrido de ancestros dejaria de terminar.
        if self.reachable(to, from) {
            return Err(GraphError::WouldCycle { from, to });
        }

        self.nodes.get_mut(&from).unwrap().out.push(Edge {
            peer: to,
            kind,
            ts_ns,
        });
        self.nodes.get_mut(&to).unwrap().incoming.push(Edge {
            peer: from,
            kind,
            ts_ns,
        });
        Ok(())
    }

    /// Indica si `objetivo` es alcanzable desde `origen` siguiendo aristas
    /// salientes.
    pub fn reachable(&self, origen: ProcessKey, objetivo: ProcessKey) -> bool {
        if origen == objetivo {
            return true;
        }
        let mut vistos = HashSet::new();
        let mut cola = VecDeque::new();
        cola.push_back(origen);
        vistos.insert(origen);
        while let Some(k) = cola.pop_front() {
            let Some(n) = self.nodes.get(&k) else {
                continue;
            };
            for e in &n.out {
                if e.peer == objetivo {
                    return true;
                }
                if vistos.insert(e.peer) {
                    cola.push_back(e.peer);
                }
            }
        }
        false
    }

    /// Cadena causal desde la raiz hasta `key`, ambos incluidos.
    ///
    /// Cuando un nodo tiene varias causas —fue lanzado por uno e inyectado por
    /// otro— se sigue la de MAYOR propagacion: la inyeccion explica mejor lo que
    /// el proceso hace que el hecho de que alguien lo lanzara.
    pub fn causal_path(&self, key: ProcessKey) -> Vec<ProcessKey> {
        let mut camino = Vec::new();
        let mut visitados = HashSet::new();
        let mut actual = Some(key);
        let mut profundidad = 0u16;

        while let Some(k) = actual {
            if !visitados.insert(k) || profundidad >= self.limits.max_depth {
                break;
            }
            camino.push(k);
            profundidad += 1;
            actual = self.nodes.get(&k).and_then(|n| {
                n.incoming
                    .iter()
                    .filter(|e| !visitados.contains(&e.peer))
                    .max_by(|a, b| {
                        a.kind
                            .propagation()
                            .partial_cmp(&b.kind.propagation())
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .map(|e| e.peer)
            });
        }
        camino.reverse();
        camino
    }

    /// Descendientes causales directos de un nodo.
    pub fn children(&self, key: ProcessKey) -> Vec<ProcessKey> {
        self.nodes
            .get(&key)
            .map(|n| n.out.iter().map(|e| e.peer).collect())
            .unwrap_or_default()
    }

    /// Tecnicas observadas en el subarbol causal de un nodo, el propio incluido.
    ///
    /// Un interprete que lanza un descargador y un `chmod` no ejecuta ninguna
    /// tecnica por si mismo, pero **es responsable** de las de sus hijos: sin
    /// esta atribucion hacia arriba, una cadena repartida entre hermanos no se
    /// ve como una cadena.
    pub fn subtree_techniques(&self, key: ProcessKey) -> HashSet<Technique> {
        let mut salida = HashSet::new();
        let mut vistos = HashSet::new();
        let mut cola = VecDeque::new();
        cola.push_back((key, 0u16));
        vistos.insert(key);
        while let Some((k, d)) = cola.pop_front() {
            let Some(n) = self.nodes.get(&k) else {
                continue;
            };
            salida.extend(n.techniques.keys().copied());
            if d >= self.limits.max_depth {
                continue;
            }
            for e in &n.out {
                if vistos.insert(e.peer) {
                    cola.push_back((e.peer, d + 1));
                }
            }
        }
        salida
    }

    /// Expira nodos muertos y aplica el limite de tamano.
    ///
    /// Devuelve cuantos se eliminaron.
    pub fn reap(&mut self, now_ns: u64) -> usize {
        let mut fuera = 0;

        while let Some(&(muerte, key)) = self.muertos.front() {
            if now_ns.saturating_sub(muerte) < self.limits.dead_grace_ns {
                break; // la cola esta ordenada por instante de muerte
            }
            self.muertos.pop_front();
            if self.remove(key) {
                fuera += 1;
            }
        }

        // Presion de memoria: se expulsan los muertos mas antiguos aunque no
        // hayan cumplido la gracia. Perder contexto historico es preferible a
        // que el motor crezca sin limite en un servidor que crea miles de
        // procesos por minuto.
        while self.nodes.len() > self.limits.max_nodes {
            match self.muertos.pop_front() {
                Some((_, key)) => {
                    if self.remove(key) {
                        fuera += 1;
                    }
                }
                // Solo quedan vivos: expulsarlos dejaria ciego al motor sobre
                // procesos que estan corriendo AHORA, que es lo unico que puede
                // contener. Se prefiere pasarse del limite y que se vea.
                None => break,
            }
        }
        fuera
    }

    /// Elimina un nodo y todas las aristas que lo mencionan.
    ///
    /// Dejar aristas colgando seria peor que perder el nodo: un recorrido las
    /// seguiria hacia un nodo inexistente y la cadena se cortaria en silencio.
    fn remove(&mut self, key: ProcessKey) -> bool {
        let Some(n) = self.nodes.remove(&key) else {
            return false;
        };
        for e in &n.out {
            if let Some(v) = self.nodes.get_mut(&e.peer) {
                v.incoming.retain(|x| x.peer != key);
            }
        }
        for e in &n.incoming {
            if let Some(v) = self.nodes.get_mut(&e.peer) {
                v.out.retain(|x| x.peer != key);
            }
        }
        if self.por_pid.get(&key.pid) == Some(&key) {
            self.por_pid.remove(&key.pid);
        }
        true
    }
}
