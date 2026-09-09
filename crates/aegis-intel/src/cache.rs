//! Cache LRU con caducidad por veredicto.
//!
//! # Por que la cache es parte de la privacidad y no solo del rendimiento
//!
//! El k-anonimato protege una consulta aislada. Lo que no protege es la
//! REPETICION: si el mismo prefijo se pregunta mil veces al dia desde la misma
//! sesion, el servidor puede intersecar los cubos de consultas correlacionadas
//! y estrechar el conjunto de candidatos hasta identificarlo. Cada consulta que
//! la cache evita es informacion que el servidor no recibe.
//!
//! Por eso hay cache **negativa**: sin ella, un fichero desconocido que se
//! ejecuta cada minuto genera una consulta por minuto para siempre, que es el
//! peor caso posible para la correlacion.
//!
//! # Por que LRU y no solo caducidad
//!
//! El presupuesto de memoria del agente es de 50 MB para todo. Una cache que
//! solo caduca crece hasta el numero de ficheros distintos que ha visto la
//! maquina, que en un servidor de compilacion son cientos de miles. La cota
//! dura es lo que hace que el presupuesto se cumpla siempre y no casi siempre.

use std::collections::HashMap;

use crate::hash::Digest256;
use crate::verdict::Record;

/// Entradas por defecto.
///
/// 4096 entradas son ~400 KB. Con la distribucion real de ejecuciones de un
/// equipo (unos cientos de binarios distintos que se repiten sin parar) la tasa
/// de acierto pasa del 95%.
pub const CAPACIDAD_POR_DEFECTO: usize = 4096;

#[derive(Debug, Clone, Copy)]
struct Entrada {
    record: Record,
    /// Instante en que caduca.
    expira_s: u64,
    /// Contador de uso para el desalojo LRU.
    usado: u64,
}

/// Resultado de consultar la cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheLookup {
    /// Habia entrada valida.
    Hit(Record),
    /// Habia entrada pero habia caducado.
    Expired,
    /// No habia entrada.
    Miss,
}

impl CacheLookup {
    /// Registro si lo hay.
    pub fn record(self) -> Option<Record> {
        match self {
            CacheLookup::Hit(r) => Some(r),
            _ => None,
        }
    }

    /// Indica si hay que preguntar al servidor.
    pub fn needs_query(self) -> bool {
        !matches!(self, CacheLookup::Hit(_))
    }
}

/// Contadores de la cache.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CacheStats {
    /// Aciertos.
    pub hits: u64,
    /// Fallos por ausencia.
    pub misses: u64,
    /// Fallos por caducidad.
    pub expired: u64,
    /// Entradas desalojadas por presion.
    pub evicted: u64,
}

impl CacheStats {
    /// Tasa de acierto en `[0, 1]`.
    ///
    /// Es la metrica que dice cuanta informacion se le esta dando al servidor:
    /// una tasa baja significa muchas consultas y por tanto mas superficie de
    /// correlacion.
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses + self.expired;
        if total == 0 {
            return 0.0;
        }
        self.hits as f64 / total as f64
    }
}

/// Cache de reputaciones acotada y con caducidad.
#[derive(Debug)]
pub struct ReputationCache {
    entradas: HashMap<Digest256, Entrada>,
    capacidad: usize,
    reloj_uso: u64,
    stats: CacheStats,
}

impl ReputationCache {
    /// Crea una cache con la capacidad indicada.
    ///
    /// Una capacidad de cero se eleva a uno: una cache que no cachea nada
    /// convierte cada consulta en trafico, que es justo lo que hay que evitar.
    pub fn new(capacidad: usize) -> ReputationCache {
        ReputationCache {
            entradas: HashMap::new(),
            capacidad: capacidad.max(1),
            reloj_uso: 0,
            stats: CacheStats::default(),
        }
    }

    /// Entradas almacenadas.
    pub fn len(&self) -> usize {
        self.entradas.len()
    }

    /// Indica si esta vacia.
    pub fn is_empty(&self) -> bool {
        self.entradas.is_empty()
    }

    /// Contadores.
    pub fn stats(&self) -> CacheStats {
        self.stats
    }

    /// Consulta la cache.
    ///
    /// `ahora_s` es tiempo monotono en segundos. Se pasa en vez de leerlo aqui
    /// para que el comportamiento de caducidad sea comprobable sin esperar
    /// siete dias.
    pub fn get(&mut self, d: &Digest256, ahora_s: u64) -> CacheLookup {
        self.reloj_uso += 1;
        let reloj = self.reloj_uso;
        match self.entradas.get_mut(d) {
            None => {
                self.stats.misses += 1;
                CacheLookup::Miss
            }
            Some(e) if ahora_s >= e.expira_s => {
                self.stats.expired += 1;
                CacheLookup::Expired
            }
            Some(e) => {
                e.usado = reloj;
                self.stats.hits += 1;
                CacheLookup::Hit(e.record)
            }
        }
    }

    /// Guarda un registro, con el tiempo de vida que le corresponde.
    pub fn put(&mut self, d: Digest256, record: Record, ahora_s: u64) {
        self.reloj_uso += 1;
        if !self.entradas.contains_key(&d) && self.entradas.len() >= self.capacidad {
            self.desalojar();
        }
        self.entradas.insert(
            d,
            Entrada {
                record,
                expira_s: ahora_s.saturating_add(record.ttl_s()),
                usado: self.reloj_uso,
            },
        );
    }

    /// Elimina las entradas caducadas.
    ///
    /// El desalojo LRU ya mantiene la cota, pero una entrada caducada ocupa
    /// sitio sin poder acertar nunca; retirarla libera espacio para una util.
    pub fn purge(&mut self, ahora_s: u64) -> usize {
        let antes = self.entradas.len();
        self.entradas.retain(|_, e| ahora_s < e.expira_s);
        antes - self.entradas.len()
    }

    /// Olvida una entrada, por ejemplo al revocarse un veredicto.
    pub fn invalidate(&mut self, d: &Digest256) -> bool {
        self.entradas.remove(d).is_some()
    }

    fn desalojar(&mut self) {
        if let Some(v) = self
            .entradas
            .iter()
            .min_by_key(|(_, e)| e.usado)
            .map(|(k, _)| *k)
        {
            self.entradas.remove(&v);
            self.stats.evicted += 1;
        }
    }
}

impl Default for ReputationCache {
    fn default() -> Self {
        ReputationCache::new(CAPACIDAD_POR_DEFECTO)
    }
}
