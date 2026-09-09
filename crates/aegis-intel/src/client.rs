//! Cliente de reputacion: cache primero, red despues, decision local siempre.

use crate::cache::{CacheLookup, ReputationCache};
use crate::hash::Digest256;
use crate::protocol::{self, BucketEntry};
use crate::transport::{Transport, TransportError};
use crate::verdict::Record;

/// De donde salio un veredicto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// De la cache local, sin tocar la red.
    Cache,
    /// De una consulta al servicio.
    Network,
    /// De ninguna parte: la consulta fallo y se responde lo unico honesto.
    Offline,
}

/// Veredicto con su procedencia.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Answer {
    /// Registro.
    pub record: Record,
    /// Procedencia.
    pub origin: Origin,
}

/// Contadores del cliente.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClientStats {
    /// Consultas atendidas.
    pub lookups: u64,
    /// Consultas que salieron a la red.
    pub queries: u64,
    /// Consultas de red fallidas.
    pub failures: u64,
    /// Entradas de cubo recibidas.
    pub bucket_entries: u64,
    /// Lineas de respuesta descartadas por no entenderse.
    pub discarded_lines: u64,
}

impl ClientStats {
    /// Fraccion de consultas que NO salieron del equipo.
    ///
    /// Es la metrica de privacidad del modulo: cada consulta evitada es
    /// informacion que el servidor no recibe y no puede correlacionar.
    pub fn local_fraction(&self) -> f64 {
        if self.lookups == 0 {
            return 0.0;
        }
        (self.lookups - self.queries) as f64 / self.lookups as f64
    }
}

/// Cliente de reputacion con k-anonimato.
#[derive(Debug)]
pub struct ReputationClient<T: Transport> {
    transport: T,
    cache: ReputationCache,
    stats: ClientStats,
}

impl<T: Transport> ReputationClient<T> {
    /// Crea un cliente.
    pub fn new(transport: T, cache: ReputationCache) -> ReputationClient<T> {
        ReputationClient {
            transport,
            cache,
            stats: ClientStats::default(),
        }
    }

    /// Contadores.
    pub fn stats(&self) -> ClientStats {
        self.stats
    }

    /// Cache, para inspeccion y mantenimiento.
    pub fn cache_mut(&mut self) -> &mut ReputationCache {
        &mut self.cache
    }

    /// Cache.
    pub fn cache(&self) -> &ReputationCache {
        &self.cache
    }

    /// Consulta la reputacion de una huella.
    ///
    /// Del hash sale del equipo unicamente el prefijo de cinco caracteres. La
    /// comparacion contra el cubo devuelto ocurre aqui, en memoria.
    ///
    /// Un fallo de red **no es un error para el llamante**: devuelve
    /// `Origin::Offline` con veredicto desconocido. Convertirlo en `Err`
    /// empujaria a quien llama a tratar la ausencia de nube como una anomalia,
    /// cuando la arquitectura entera esta construida para que la nube sea
    /// opcional. Un endpoint sin red se defiende con YARA, el modelo local y
    /// las reglas conductuales.
    pub fn lookup(&mut self, d: Digest256, ahora_s: u64) -> Answer {
        self.stats.lookups += 1;

        if let CacheLookup::Hit(r) = self.cache.get(&d, ahora_s) {
            return Answer {
                record: r,
                origin: Origin::Cache,
            };
        }

        self.stats.queries += 1;
        let ruta = protocol::request_path(d.prefix());
        match self.transport.fetch(&ruta) {
            Ok(cuerpo) => {
                let (entradas, descartadas) = protocol::parse_bucket(&cuerpo);
                self.stats.bucket_entries += entradas.len() as u64;
                self.stats.discarded_lines += descartadas as u64;
                let record = protocol::resolve(d, &entradas);
                // Se cachea TAMBIEN el desconocido: sin cache negativa, un
                // fichero que se ejecuta cada minuto genera una consulta por
                // minuto para siempre, y la repeticion es justo lo que rompe
                // el k-anonimato.
                self.cache.put(d, record, ahora_s);
                Answer {
                    record,
                    origin: Origin::Network,
                }
            }
            Err(_) => {
                self.stats.failures += 1;
                // Sin cachear: la proxima vez hay que volver a intentarlo.
                Answer {
                    record: Record::unknown(),
                    origin: Origin::Offline,
                }
            }
        }
    }

    /// Consulta varias huellas, agrupando por prefijo.
    ///
    /// Agrupar no es solo eficiencia: dos ficheros que comparten prefijo se
    /// resuelven con **una** consulta, de modo que el servidor ve menos
    /// peticiones y con menos estructura temporal que correlacionar.
    pub fn lookup_many(&mut self, huellas: &[Digest256], ahora_s: u64) -> Vec<Answer> {
        use std::collections::HashMap;

        let mut salida: Vec<Option<Answer>> = vec![None; huellas.len()];
        let mut pendientes: HashMap<String, Vec<usize>> = HashMap::new();

        for (i, d) in huellas.iter().enumerate() {
            self.stats.lookups += 1;
            if let CacheLookup::Hit(r) = self.cache.get(d, ahora_s) {
                salida[i] = Some(Answer {
                    record: r,
                    origin: Origin::Cache,
                });
            } else {
                pendientes
                    .entry(d.prefix().as_str().to_string())
                    .or_default()
                    .push(i);
            }
        }

        let mut claves: Vec<String> = pendientes.keys().cloned().collect();
        claves.sort();

        for p in claves {
            let indices = &pendientes[&p];
            self.stats.queries += 1;
            let cuerpo = match self.transport.fetch(&format!("/v1/rep/{p}")) {
                Ok(c) => c,
                Err(_) => {
                    self.stats.failures += 1;
                    for &i in indices {
                        salida[i] = Some(Answer {
                            record: Record::unknown(),
                            origin: Origin::Offline,
                        });
                    }
                    continue;
                }
            };
            let (entradas, descartadas) = protocol::parse_bucket(&cuerpo);
            self.stats.bucket_entries += entradas.len() as u64;
            self.stats.discarded_lines += descartadas as u64;
            for &i in indices {
                let record = protocol::resolve(huellas[i], &entradas);
                self.cache.put(huellas[i], record, ahora_s);
                salida[i] = Some(Answer {
                    record,
                    origin: Origin::Network,
                });
            }
        }

        salida
            .into_iter()
            .map(|a| {
                a.unwrap_or(Answer {
                    record: Record::unknown(),
                    origin: Origin::Offline,
                })
            })
            .collect()
    }

    /// Introduce un cubo obtenido por otro medio, sin consultar.
    ///
    /// Sirve para precargar la cache con los ficheros mas comunes en el
    /// despliegue: cuantos menos ficheros corrientes haya que preguntar, menos
    /// consultas ve el servidor.
    pub fn preload(&mut self, huella: Digest256, entradas: &[BucketEntry], ahora_s: u64) {
        let r = protocol::resolve(huella, entradas);
        self.cache.put(huella, r, ahora_s);
    }

    /// Ultimo error de transporte, para diagnostico.
    pub fn probe(&self, path: &str) -> Result<String, TransportError> {
        self.transport.fetch(path)
    }
}
