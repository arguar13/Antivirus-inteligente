//! El grafo: el conocimiento STIX 2.1 y lo observado, en una sola estructura.
//!
//! # Nodos y aristas
//!
//! Cada objeto STIX es un nodo —los 19 SDO, los 18 SCO y cualquier tipo que
//! este nodo no conozca, que se conserva igual—. Las aristas salen de DOS
//! sitios, y los dos cuentan:
//!
//! - las relaciones de primer orden (`relationship`): una arista por objeto, con
//!   su tipo y su [`Admision`] frente al canon de la especificacion;
//! - las relaciones EMBEBIDAS: toda propiedad `*_ref` o `*_refs` de cualquier
//!   objeto (`created_by_ref`, `object_refs` de un informe, `sighting_of_ref`,
//!   `resolves_to_refs` de un dominio…) es una arista con el nombre de la
//!   propiedad. La especificacion las llama relaciones (seccion 3.3) y un
//!   grafo que solo mirara las SRO no veria quien publico que.
//!
//! Lo observado entra como nodos `local` (ver [`crate::observado`]), enlazados a
//! los objetos del conocimiento que declaran el mismo observable. No hay un
//! segundo grafo: [`Grafo::alrededor`] recorre los dos a la vez.
//!
//! # Versiones
//!
//! STIX versiona por `modified`: de un mismo `id` manda la version mas reciente.
//! Una version anterior que llega despues no pisa la actual, pero su fuente SI
//! queda en la procedencia: la fuente dijo algo sobre ese objeto.
//!
//! # Procedencia
//!
//! Todo —objeto, relacion y observacion— lleva su ficha de procedencia de la
//! FASE 78 (`aegis_share::procedencia`). Revocar una fuente retira lo que solo
//! ella sostenia, con sus aristas, y deja en pie lo que sostenian las demas.

use std::collections::{BTreeMap, BTreeSet};

use aegis_share::procedencia::{Aporte, Fiabilidad, Registro};
use aegis_share::stix::{Objeto, Tipo};
use serde_json::Value;

use crate::catalogo::{self, Admision, Triple};
use crate::observado::{Avistamiento, Local, Observable};

/// Tope de objetos de un grafo. ATT&CK entero son unos 31 000; con un orden de
/// magnitud de margen para inteligencia propia y federada. Pasado el tope, lo
/// nuevo se rechaza y se dice: un grafo que crece sin limite por un canal
/// hostil es una denegacion de servicio con forma de inteligencia.
pub const MAX_OBJETOS: usize = 500_000;

/// Tope de observaciones distintas por observable.
pub const MAX_AVISTAMIENTOS_POR_OBSERVABLE: usize = 256;

/// Prefijo de las fichas de procedencia de lo observado: no puede chocar con un
/// identificador STIX (que es `tipo--uuid`).
const PREFIJO_LOCAL: &str = "local:";

/// Una arista del grafo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arista {
    /// Su identificador: el de la SRO, o `objeto#propiedad#destino` si es
    /// embebida.
    pub id: String,
    /// Origen.
    pub origen: String,
    /// Tipo: el `relationship_type`, o el nombre de la propiedad embebida.
    pub tipo: String,
    /// Destino.
    pub destino: String,
    /// El objeto que la declara (la SRO, o el objeto con la propiedad).
    pub declarada_por: String,
    /// Si es embebida.
    pub embebida: bool,
    /// Como encaja en la especificacion.
    pub admision: Admision,
}

/// Que paso al absorber un objeto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Absorcion {
    /// No estaba.
    Nuevo,
    /// Estaba, y esta version es mas reciente.
    Actualizado,
    /// Estaba en una version igual o mas reciente: se anota la fuente y nada mas.
    Anotado,
    /// El grafo esta lleno.
    Lleno,
}

/// Lo que dejo revocar una fuente.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Retirada {
    /// Objetos que solo sostenia esa fuente, y que se han retirado.
    pub objetos: Vec<String>,
    /// Aristas que se fueron con ellos.
    pub aristas: usize,
    /// Observaciones retiradas.
    pub observaciones: Vec<String>,
    /// Lo que sigue en pie con menos confianza: (id, antes, despues).
    pub rebajados: Vec<(String, u8, u8)>,
}

/// Lo que se ve alrededor de un objeto: conocimiento y observacion juntos.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Vista {
    /// Los objetos alcanzados.
    pub nodos: BTreeSet<String>,
    /// Las aristas recorridas.
    pub aristas: BTreeSet<String>,
    /// Lo observado en este despliegue, por el objeto del conocimiento que lo
    /// declara.
    pub observado: BTreeMap<String, BTreeSet<Local>>,
}

impl Vista {
    /// Todo lo observado alcanzado, sin repetir.
    #[must_use]
    pub fn locales(&self) -> BTreeSet<&Local> {
        self.observado.values().flatten().collect()
    }
}

/// El grafo de conocimiento.
#[derive(Debug, Default)]
pub struct Grafo {
    canon: BTreeSet<Triple>,
    objetos: BTreeMap<String, Objeto>,
    aristas: BTreeMap<String, Arista>,
    salen: BTreeMap<String, BTreeSet<String>>,
    entran: BTreeMap<String, BTreeSet<String>>,
    /// Aristas que declara cada objeto, para retirarlas con el.
    declaradas: BTreeMap<String, BTreeSet<String>>,
    /// Que objetos del conocimiento declaran cada observable.
    declarantes: BTreeMap<Local, BTreeSet<String>>,
    /// Lo que se vio de verdad.
    vistos: BTreeMap<Local, Vec<Avistamiento>>,
    procedencia: Registro,
}

impl Grafo {
    /// Un grafo vacio, con el canon de la especificacion.
    #[must_use]
    pub fn nuevo() -> Grafo {
        Grafo {
            canon: catalogo::canon_stix21(),
            ..Grafo::default()
        }
    }

    /// Cuantos objetos tiene.
    #[must_use]
    pub fn cuantos(&self) -> usize {
        self.objetos.len()
    }

    /// Un objeto.
    #[must_use]
    pub fn objeto(&self, id: &str) -> Option<&Objeto> {
        self.objetos.get(id)
    }

    /// Todos los objetos.
    pub fn objetos(&self) -> impl Iterator<Item = &Objeto> {
        self.objetos.values()
    }

    /// Una arista.
    #[must_use]
    pub fn arista(&self, id: &str) -> Option<&Arista> {
        self.aristas.get(id)
    }

    /// Todas las aristas.
    pub fn aristas(&self) -> impl Iterator<Item = &Arista> {
        self.aristas.values()
    }

    /// La procedencia de todo.
    #[must_use]
    pub fn procedencia(&self) -> &Registro {
        &self.procedencia
    }

    /// La confianza recalculada de un objeto o de una arista (la de la SRO que
    /// la declara), en centesimas; 0 si no esta.
    #[must_use]
    pub fn confianza(&self, id: &str, ahora_ns: u64) -> u8 {
        let clave = self
            .aristas
            .get(id)
            .map_or(id, |a| a.declarada_por.as_str());
        self.procedencia
            .ficha(clave)
            .map_or(0, |f| f.confianza(ahora_ns))
    }

    /// Absorbe un objeto que entrega una fuente.
    pub fn absorber(&mut self, o: Objeto, aporte: Aporte) -> Absorcion {
        let id = o.id.clone();
        let resultado = match self.objetos.get(&id) {
            Some(actual) if actual.modificado_ns >= o.modificado_ns => Absorcion::Anotado,
            Some(_) => Absorcion::Actualizado,
            None if self.objetos.len() >= MAX_OBJETOS => return Absorcion::Lleno,
            None => Absorcion::Nuevo,
        };
        self.procedencia.anotar(&id, aporte);
        if resultado != Absorcion::Anotado {
            // Una version nueva sustituye ENTERA a la anterior: sus aristas y
            // sus observables pueden haber cambiado.
            if resultado == Absorcion::Actualizado {
                self.retirar_aristas_de(&id);
                self.retirar_declaraciones_de(&id);
            }
            for obs in Observable::de_objeto(&o) {
                self.declarantes
                    .entry(obs.local())
                    .or_default()
                    .insert(id.clone());
            }
            for a in self.aristas_de(&o) {
                self.poner_arista(a);
            }
            self.objetos.insert(id, o);
        }
        resultado
    }

    /// Registra algo que un agente vio de verdad.
    pub fn observar(&mut self, av: Avistamiento) {
        let local = av.observable.local();
        self.procedencia.anotar(
            &format!("{PREFIJO_LOCAL}{}", local.texto()),
            Aporte {
                fuente: av.fuente(),
                fiabilidad: Fiabilidad::Propia,
                cadena: Vec::new(),
                cuando_ns: av.cuando_ns,
                confianza_declarada: 100,
                id_en_origen: local.texto(),
            },
        );
        let v = self.vistos.entry(local).or_default();
        if !v.iter().any(|x| x.maquina == av.maquina) && v.len() < MAX_AVISTAMIENTOS_POR_OBSERVABLE
        {
            v.push(av);
        }
    }

    /// Lo que se vio de un observable.
    #[must_use]
    pub fn vistos(&self, local: &Local) -> &[Avistamiento] {
        self.vistos.get(local).map_or(&[], Vec::as_slice)
    }

    /// Lo observado en este despliegue que sostiene un objeto del conocimiento.
    #[must_use]
    pub fn enlaces(&self, id: &str) -> BTreeSet<Local> {
        self.objetos
            .get(id)
            .map(|o| {
                Observable::de_objeto(o)
                    .into_iter()
                    .map(|x| x.local())
                    .filter(|l| self.vistos.contains_key(l))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Los objetos del conocimiento que declaran un observable local.
    #[must_use]
    pub fn declarantes(&self, local: &Local) -> Vec<&str> {
        self.declarantes
            .get(local)
            .map(|s| {
                s.iter()
                    .filter(|id| self.objetos.contains_key(*id))
                    .map(String::as_str)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Todo lo observado que el grafo conoce.
    pub fn observados(&self) -> impl Iterator<Item = (&Local, &Vec<Avistamiento>)> {
        self.vistos.iter()
    }

    /// Si una arista se puede recorrer: la declara un objeto presente y no
    /// revocado, y sus dos extremos estan.
    #[must_use]
    pub fn vigente(&self, a: &Arista) -> bool {
        self.objetos
            .get(&a.declarada_por)
            .is_some_and(|o| !o.revocado)
            && self.objetos.contains_key(&a.origen)
            && self.objetos.contains_key(&a.destino)
    }

    /// Las aristas vigentes que salen de un objeto.
    pub fn salientes<'a>(&'a self, id: &str) -> impl Iterator<Item = &'a Arista> + 'a {
        self.salen
            .get(id)
            .into_iter()
            .flatten()
            .filter_map(|i| self.aristas.get(i))
            .filter(|a| self.vigente(a))
    }

    /// Las aristas vigentes que entran en un objeto.
    pub fn entrantes<'a>(&'a self, id: &str) -> impl Iterator<Item = &'a Arista> + 'a {
        self.entran
            .get(id)
            .into_iter()
            .flatten()
            .filter_map(|i| self.aristas.get(i))
            .filter(|a| self.vigente(a))
    }

    /// Lo que hay alrededor de un objeto, a `saltos` de distancia por aristas
    /// vigentes en los dos sentidos, CON lo observado de cada nodo alcanzado.
    ///
    /// Es la respuesta a «que se de este actor» y, a la vez, a «que he visto yo
    /// de este actor»: el mismo recorrido del mismo grafo. Las aristas de
    /// autoria y marcado (`created_by_ref`, `object_marking_refs`) no se
    /// siguen: unen a todo lo que publico la misma organizacion y convertirian
    /// cualquier vecindario en la base entera.
    #[must_use]
    pub fn alrededor(&self, id: &str, saltos: usize) -> Vista {
        const NO_SE_SIGUEN: [&str; 2] = ["created_by_ref", "object_marking_refs"];
        let mut v = Vista::default();
        if !self.objetos.contains_key(id) {
            return v;
        }
        v.nodos.insert(id.to_string());
        let mut frontera = vec![id.to_string()];
        for _ in 0..saltos {
            let mut siguiente = Vec::new();
            for n in &frontera {
                for a in self.salientes(n).chain(self.entrantes(n)) {
                    if NO_SE_SIGUEN.contains(&a.tipo.as_str()) {
                        continue;
                    }
                    v.aristas.insert(a.id.clone());
                    for extremo in [&a.origen, &a.destino] {
                        if v.nodos.insert(extremo.clone()) {
                            siguiente.push(extremo.clone());
                        }
                    }
                }
            }
            frontera = siguiente;
        }
        for n in &v.nodos {
            let e = self.enlaces(n);
            if !e.is_empty() {
                v.observado.insert(n.clone(), e);
            }
        }
        v
    }

    /// Revoca una fuente: retira lo que solo ella sostenia —objetos, sus aristas
    /// y observaciones— y recalcula la confianza de lo demas.
    pub fn revocar_fuente(&mut self, fuente: &str, ahora_ns: u64) -> Retirada {
        let r = self.procedencia.revocar_fuente(fuente, ahora_ns);
        let mut ret = Retirada {
            rebajados: r.rebajados,
            ..Retirada::default()
        };
        for id in r.caidos {
            if let Some(texto) = id.strip_prefix(PREFIJO_LOCAL) {
                self.vistos.retain(|l, _| l.texto() != texto);
                ret.observaciones.push(texto.to_string());
            } else if self.objetos.remove(&id).is_some() {
                ret.aristas += self.retirar_aristas_de(&id);
                self.retirar_declaraciones_de(&id);
                ret.objetos.push(id);
            }
        }
        ret
    }

    /// Estadisticas de cobertura: tipos de objeto y relaciones presentes.
    #[must_use]
    pub fn cobertura(&self) -> Cobertura {
        let mut c = Cobertura::default();
        for o in self.objetos.values() {
            *c.tipos.entry(o.tipo.nombre().to_string()).or_insert(0) += 1;
        }
        for a in self.aristas.values().filter(|a| !a.embebida) {
            let (Some(o), Some(d)) = (self.objetos.get(&a.origen), self.objetos.get(&a.destino))
            else {
                continue;
            };
            *c.relaciones
                .entry((
                    o.tipo.nombre().to_string(),
                    a.tipo.clone(),
                    d.tipo.nombre().to_string(),
                ))
                .or_insert(0) += 1;
        }
        c
    }

    fn aristas_de(&self, o: &Objeto) -> Vec<Arista> {
        let mut v = Vec::new();
        let tipo_de = |id: &str| id.split_once("--").map_or("", |(t, _)| t).to_string();
        if o.tipo == Tipo::Relationship {
            if let (Some(s), Some(t), Some(r)) = (
                o.texto("source_ref"),
                o.texto("target_ref"),
                o.texto("relationship_type"),
            ) {
                v.push(Arista {
                    id: o.id.clone(),
                    origen: s.to_string(),
                    tipo: r.to_string(),
                    destino: t.to_string(),
                    declarada_por: o.id.clone(),
                    embebida: false,
                    admision: catalogo::admision(&self.canon, &tipo_de(s), r, &tipo_de(t)),
                });
            }
        }
        for (clave, valor) in &o.crudo {
            let es_ref = clave.ends_with("_ref") || clave.ends_with("_refs");
            // Las de la SRO ya son la arista de arriba.
            let de_la_sro =
                o.tipo == Tipo::Relationship && (clave == "source_ref" || clave == "target_ref");
            if !es_ref || de_la_sro {
                continue;
            }
            let destinos: Vec<&str> = match valor {
                Value::String(s) => vec![s.as_str()],
                Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
                _ => continue,
            };
            for d in destinos {
                // Solo identificadores STIX: `tipo--uuid`.
                if !d.contains("--") {
                    continue;
                }
                v.push(Arista {
                    id: format!("{}#{clave}#{d}", o.id),
                    origen: o.id.clone(),
                    tipo: clave.clone(),
                    destino: d.to_string(),
                    declarada_por: o.id.clone(),
                    embebida: true,
                    admision: if clave.starts_with("x_") {
                        Admision::Personalizada
                    } else {
                        Admision::Especificacion
                    },
                });
            }
        }
        v
    }

    fn poner_arista(&mut self, a: Arista) {
        self.salen
            .entry(a.origen.clone())
            .or_default()
            .insert(a.id.clone());
        self.entran
            .entry(a.destino.clone())
            .or_default()
            .insert(a.id.clone());
        self.declaradas
            .entry(a.declarada_por.clone())
            .or_default()
            .insert(a.id.clone());
        self.aristas.insert(a.id.clone(), a);
    }

    fn retirar_aristas_de(&mut self, declarante: &str) -> usize {
        let Some(ids) = self.declaradas.remove(declarante) else {
            return 0;
        };
        let n = ids.len();
        for i in ids {
            if let Some(a) = self.aristas.remove(&i) {
                if let Some(s) = self.salen.get_mut(&a.origen) {
                    s.remove(&i);
                }
                if let Some(s) = self.entran.get_mut(&a.destino) {
                    s.remove(&i);
                }
            }
        }
        n
    }

    fn retirar_declaraciones_de(&mut self, id: &str) {
        for s in self.declarantes.values_mut() {
            s.remove(id);
        }
        self.declarantes.retain(|_, s| !s.is_empty());
    }
}

/// Lo que hay en el grafo, por tipo de objeto y por relacion entre tipos.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cobertura {
    /// Objetos por tipo.
    pub tipos: BTreeMap<String, usize>,
    /// Relaciones de primer orden por (origen, relacion, destino).
    pub relaciones: BTreeMap<Triple, usize>,
}
