//! Reconciliacion diferencial entre la base local y la del servidor.
//!
//! El servidor expone su arbol como un [`MerkleView`]: da el hash de la raiz, el
//! hash de cualquier nodo, y el contenido de un cubo. El cliente desciende
//! comparando hashes y solo pide el contenido de los cubos que difieren. Se
//! cuenta cada peticion para poder demostrar que el trafico es proporcional a lo
//! que cambio, no al tamano de la base.

use std::collections::BTreeMap;

use crate::ioc::Ioc;
use crate::merkle::{MerkleTree, CUBOS};

/// Vista del arbol remoto (el servidor). Se modela como un rasgo para poder
/// reconciliar contra un servidor real, contra un fichero, o contra otro arbol
/// en memoria en las pruebas, y para poder CONTAR el trafico.
pub trait MerkleView {
    /// Hash de la raiz.
    fn root(&self) -> [u8; 32];
    /// Hash de un nodo del monticulo (1 = raiz).
    fn node(&self, idx: usize) -> [u8; 32];
    /// Indicadores de un cubo.
    fn bucket_iocs(&self, bucket: usize) -> Vec<Ioc>;
}

/// Un arbol en memoria es una vista trivial de si mismo. Envuelve al arbol y
/// cuenta las peticiones para medir el trafico en las pruebas.
pub struct CountingView<'a> {
    tree: &'a MerkleTree,
    /// Hashes de nodo solicitados.
    pub node_requests: std::cell::Cell<usize>,
    /// Cubos cuyo contenido se ha transferido.
    pub bucket_requests: std::cell::Cell<usize>,
    /// Indicadores transferidos en total.
    pub iocs_transferred: std::cell::Cell<usize>,
}

impl<'a> CountingView<'a> {
    /// Crea la vista sobre un arbol.
    pub fn new(tree: &'a MerkleTree) -> CountingView<'a> {
        CountingView {
            tree,
            node_requests: std::cell::Cell::new(0),
            bucket_requests: std::cell::Cell::new(0),
            iocs_transferred: std::cell::Cell::new(0),
        }
    }
}

impl MerkleView for CountingView<'_> {
    fn root(&self) -> [u8; 32] {
        // La raiz es un unico hash: la sincronizacion siempre empieza pidiendolo.
        self.node_requests.set(self.node_requests.get() + 1);
        self.tree.root()
    }
    fn node(&self, idx: usize) -> [u8; 32] {
        self.node_requests.set(self.node_requests.get() + 1);
        self.tree.node(idx)
    }
    fn bucket_iocs(&self, bucket: usize) -> Vec<Ioc> {
        self.bucket_requests.set(self.bucket_requests.get() + 1);
        let v: Vec<Ioc> = self.tree.bucket(bucket).iocs().cloned().collect();
        self.iocs_transferred
            .set(self.iocs_transferred.get() + v.len());
        v
    }
}

/// Diferencia a aplicar sobre la base local para igualarla a la remota.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncDiff {
    /// Indicadores que el servidor tiene y el cliente no: hay que anadirlos.
    pub to_add: Vec<Ioc>,
    /// Indicadores que el cliente tiene y el servidor no: hay que quitarlos
    /// (revocados).
    pub to_remove: Vec<Ioc>,
    /// Cubos que resultaron distintos.
    pub differing_buckets: usize,
}

impl SyncDiff {
    /// Indica si las bases ya estaban sincronizadas.
    pub fn is_empty(&self) -> bool {
        self.to_add.is_empty() && self.to_remove.is_empty()
    }
}

/// Reconcilia la base local `local` con la remota `remote`.
///
/// Devuelve lo que hay que anadir y quitar localmente. Si las raices coinciden,
/// termina con una sola comparacion de hash y sin transferir nada.
pub fn reconcile(local: &MerkleTree, remote: &dyn MerkleView) -> SyncDiff {
    let mut diff = SyncDiff::default();
    if local.root() == remote.root() {
        return diff; // en sincronia: un hash y hemos terminado
    }

    // Se recorre el arbol comparando hashes de nodo; solo se baja a los
    // subarboles que difieren, hasta llegar a los cubos.
    let mut pila = vec![1usize]; // raiz
    while let Some(idx) = pila.pop() {
        if idx >= CUBOS {
            // Es una hoja: el cubo `idx - CUBOS` difiere.
            let bucket = idx - CUBOS;
            reconciliar_cubo(local, remote, bucket, &mut diff);
            diff.differing_buckets += 1;
            continue;
        }
        let izq = 2 * idx;
        let der = 2 * idx + 1;
        if local.node(izq) != remote.node(izq) {
            pila.push(izq);
        }
        if local.node(der) != remote.node(der) {
            pila.push(der);
        }
    }
    diff
}

fn reconciliar_cubo(
    local: &MerkleTree,
    remote: &dyn MerkleView,
    bucket: usize,
    diff: &mut SyncDiff,
) {
    // Se transfiere el contenido del cubo remoto y se compara con el local por
    // id. Los ids son la clave; el valor viaja para poder anadir el indicador.
    let remotos: BTreeMap<[u8; 32], Ioc> = remote
        .bucket_iocs(bucket)
        .into_iter()
        .map(|i| (i.id(), i))
        .collect();
    let locales: BTreeMap<[u8; 32], Ioc> = local
        .bucket(bucket)
        .iocs()
        .map(|i| (i.id(), i.clone()))
        .collect();

    for (id, ioc) in &remotos {
        if !locales.contains_key(id) {
            diff.to_add.push(ioc.clone());
        }
    }
    for (id, ioc) in &locales {
        if !remotos.contains_key(id) {
            diff.to_remove.push(ioc.clone());
        }
    }
}
