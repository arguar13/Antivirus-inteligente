//! Arbol de Merkle sobre cubos de indicadores, para sincronizacion diferencial.
//!
//! # El problema que resuelve
//!
//! El agente tiene una base local de indicadores de compromiso y el servidor
//! otra; hay que ponerlas al dia. Descargar la lista entera en cada
//! sincronizacion es prohibitivo cuando son cientos de miles de indicadores y
//! solo cambian unos pocos al dia. La sincronizacion **diferencial** transfiere
//! solo lo que difiere.
//!
//! # Como
//!
//! Los indicadores se reparten en `2^profundidad` **cubos** por los bits altos
//! de su identificador. El hash de un cubo resume su contenido; sobre esos
//! hashes se construye un arbol de Merkle. El hash de la raiz resume TODA la
//! base: si coincide con el del servidor, las bases son identicas y no se
//! transfiere nada mas que ese hash.
//!
//! Si difieren, se desciende por el arbol comparando hashes de nodo, y solo se
//! baja a los subarboles que difieren. Se llega asi a los cubos concretos que
//! cambiaron, y solo el contenido de ESOS cubos se transfiere. Un cambio en un
//! indicador altera un cubo y el camino de `profundidad` hashes hasta la raiz,
//! nada mas.
//!
//! # Por que cubos por prefijo y no un arbol sobre la lista ordenada
//!
//! Un arbol sobre la lista ordenada se desbarata al insertar: un indicador nuevo
//! desplaza a todos los siguientes y cambia media rama. Repartir por prefijo del
//! id fija la posicion de cada indicador independientemente de los demas: una
//! insercion toca un unico cubo y su camino a la raiz, que es lo que hace la
//! diferencia realmente barata.

use sha2::{Digest, Sha256};

use crate::ioc::Ioc;

/// Profundidad del arbol: hay `2^profundidad` cubos.
///
/// 8 da 256 cubos. Con cientos de miles de indicadores, cada cubo tiene unos
/// cientos, y un cubo que difiere transfiere esos cientos, no la base entera.
pub const PROFUNDIDAD: usize = 8;
/// Numero de cubos.
pub const CUBOS: usize = 1 << PROFUNDIDAD;

/// Un cubo: los indicadores cuyo id empieza por su prefijo, ordenados por id.
#[derive(Debug, Clone, Default)]
pub struct Bucket {
    /// Indicadores del cubo, ordenados por id.
    entradas: Vec<([u8; 32], Ioc)>,
}

impl Bucket {
    /// Indicadores del cubo.
    pub fn iocs(&self) -> impl Iterator<Item = &Ioc> {
        self.entradas.iter().map(|(_, i)| i)
    }

    /// Numero de indicadores.
    pub fn len(&self) -> usize {
        self.entradas.len()
    }

    /// Indica si esta vacio.
    pub fn is_empty(&self) -> bool {
        self.entradas.is_empty()
    }

    /// Hash del cubo: `SHA-256` de sus ids en orden. Un cubo vacio tiene un hash
    /// fijo (el de la cadena vacia) para que dos bases sin ese cubo coincidan.
    pub fn hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"aegis-bucket-v1");
        for (id, _) in &self.entradas {
            h.update(id);
        }
        h.finalize().into()
    }
}

/// Arbol de Merkle sobre los cubos de indicadores.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    buckets: Vec<Bucket>,
    /// Hashes de todos los nodos, en un array de monticulo: `nodos[1]` es la
    /// raiz, los hijos de `i` son `2i` y `2i+1`, y las hojas son
    /// `nodos[CUBOS..2*CUBOS]`.
    nodos: Vec<[u8; 32]>,
}

impl MerkleTree {
    /// Construye el arbol a partir de una coleccion de indicadores.
    pub fn build<I: IntoIterator<Item = Ioc>>(iocs: I) -> MerkleTree {
        let mut buckets: Vec<Bucket> = vec![Bucket::default(); CUBOS];
        for ioc in iocs {
            let id = ioc.id();
            let idx = bucket_index(&id);
            buckets[idx].entradas.push((id, ioc));
        }
        for b in &mut buckets {
            b.entradas.sort_by(|a, c| a.0.cmp(&c.0));
            b.entradas.dedup_by(|a, c| a.0 == c.0);
        }
        let nodos = Self::calcular_nodos(&buckets);
        MerkleTree { buckets, nodos }
    }

    fn calcular_nodos(buckets: &[Bucket]) -> Vec<[u8; 32]> {
        let mut nodos = vec![[0u8; 32]; 2 * CUBOS];
        // Hojas.
        for (i, b) in buckets.iter().enumerate() {
            nodos[CUBOS + i] = b.hash();
        }
        // Internos, de abajo arriba.
        for i in (1..CUBOS).rev() {
            let mut h = Sha256::new();
            h.update(b"aegis-node-v1");
            h.update(nodos[2 * i]);
            h.update(nodos[2 * i + 1]);
            nodos[i] = h.finalize().into();
        }
        nodos
    }

    /// Hash de la raiz: resume toda la base.
    pub fn root(&self) -> [u8; 32] {
        self.nodos[1]
    }

    /// Hash de un nodo del monticulo (1 = raiz).
    pub fn node(&self, idx: usize) -> [u8; 32] {
        self.nodos[idx]
    }

    /// Cubo por indice.
    pub fn bucket(&self, idx: usize) -> &Bucket {
        &self.buckets[idx]
    }

    /// Numero total de indicadores.
    pub fn len(&self) -> usize {
        self.buckets.iter().map(Bucket::len).sum()
    }

    /// Indica si la base esta vacia.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Indice de cubo de un identificador: sus `PROFUNDIDAD` bits mas altos.
pub fn bucket_index(id: &[u8; 32]) -> usize {
    // PROFUNDIDAD = 8, asi que el primer byte basta. Si se sube la profundidad,
    // hay que tomar mas bits; el const assert de abajo garantiza que caben en 16.
    const _: () = assert!(PROFUNDIDAD <= 16);
    let bits = ((id[0] as usize) << 8) | id[1] as usize;
    bits >> (16 - PROFUNDIDAD)
}
