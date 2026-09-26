//! Inferencia acotada y explicable: se PROPONE, nunca se afirma.
//!
//! # La regla
//!
//! Si el conocimiento dice que un actor usa una herramienta (o un malware, o
//! una infraestructura), y ese despliegue ha visto de verdad un observable que
//! el conocimiento asocia a esa herramienta, se propone la hipotesis «ese actor
//! esta activo aqui», con su confianza y su cadena de razonamiento completa:
//!
//! ```text
//!   observacion   cont:9f86… se vio en 3 maquinas            (100, observado)
//!   declara       indicator «Carbanak dropper» declara ese hash (80, feed-A)
//!   indica        el indicador indica malware «Carbanak»      (80, feed-A)
//!   usa           intrusion-set «FIN7» usa «Carbanak»         (64, feed-B)
//! ```
//!
//! # Acotada
//!
//! Solo se recorre: observado → objeto que lo declara → lo que ese objeto
//! indica o lo que lo contiene → quien lo usa → hasta [`MAX_SALTOS_ATRIBUCION`]
//! atribuciones (`attributed-to`). Nada mas. Una inferencia sin cota sobre un
//! grafo de medio millon de objetos acaba atribuyendo todo a todos.
//!
//! # Explicable, y rebatible
//!
//! - La confianza es la del eslabon MAS DEBIL, no la media: una cadena es tan
//!   fuerte como su peor eslabon.
//! - Se reparte entre las alternativas: si veinte actores usan Mimikatz, ver
//!   Mimikatz dice poco de cual de ellos es, y la hipotesis lo dice con su cifra
//!   y con la lista de los otros diecinueve ([`Hipotesis::alternativas`]).
//! - Cada eslabon lleva su apoyo —el objeto, la relacion o la observacion— y
//!   las fuentes que lo sostienen. [`Hipotesis::depende_de`] dice que fuentes
//!   la tumbarian solas si se revocaran: es lo que aisla un envenenamiento.
//! - [`Hipotesis::rebatir`] la vuelve a comprobar contra el grafo de AHORA.
//!
//! # La diferencia esta en el tipo
//!
//! Una [`Hipotesis`] no es un objeto STIX: el grafo no la absorbe y la
//! exportacion no la ve. Sus campos son privados y no se puede fabricar:
//!
//! ```compile_fail,E0451
//! let h = aegis_conocimiento::inferencia::Hipotesis {
//!     actor: String::new(), confianza: 100, cadena: Vec::new(),
//!     alternativas: Vec::new(), depende_de: Default::default(), caminos: 1, saltos: 0,
//!     nombres: Default::default(),
//! };
//! ```
//!
//! Ni hacerla pasar por un hecho:
//!
//! ```compile_fail,E0308
//! fn meter(g: &mut aegis_conocimiento::grafo::Grafo, h: aegis_conocimiento::inferencia::Hipotesis,
//!          a: aegis_share::procedencia::Aporte) {
//!     g.absorber(h, a);
//! }
//! ```
//!
//! La unica forma de que salga es [`Hipotesis::confirmar`]: una persona la
//! firma con su nombre, y lo que sale es un `sighting` de ESTA organizacion con
//! la cadena en su descripcion, no una relacion de atribucion anonima.

use std::collections::{BTreeMap, BTreeSet};

use aegis_entidad::Eid;
use aegis_share::stix::{Objeto, Paquete, Rechazo, Tipo};
use sha2::{Digest, Sha256};

use crate::grafo::{Arista, Grafo};
use crate::observado::Local;

/// Cuantas atribuciones (`attributed-to`) se siguen desde el primer actor.
pub const MAX_SALTOS_ATRIBUCION: usize = 2;

/// Cuanto conserva la confianza en cada atribucion encadenada, en centesimas.
pub const RETENCION_POR_ATRIBUCION: u32 = 80;

/// En que se apoya un eslabon.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Apoyo {
    /// Un objeto del conocimiento.
    Objeto(String),
    /// Una relacion (su identificador de arista).
    Arista(String),
    /// Lo que se vio en este despliegue.
    Observacion {
        /// Que.
        local: Local,
        /// Donde.
        maquinas: Vec<Eid>,
    },
}

/// Un paso del razonamiento.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eslabon {
    /// Que afirma, en una frase.
    pub texto: String,
    /// En que se apoya.
    pub apoyo: Apoyo,
    /// Su confianza, en centesimas, recalculada de la procedencia.
    pub confianza: u8,
    /// Las raices que lo sostienen.
    pub fuentes: Vec<String>,
}

/// Una hipotesis de atribucion: PROPUESTA, no afirmada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hipotesis {
    actor: String,
    confianza: u8,
    cadena: Vec<Eslabon>,
    alternativas: Vec<String>,
    depende_de: BTreeSet<String>,
    caminos: usize,
    saltos: usize,
    /// Nombres legibles del actor y de las alternativas, tomados al proponer.
    nombres: BTreeMap<String, String>,
}

/// El resultado de volver a comprobar una hipotesis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rebatida {
    /// Sigue en pie, con esta confianza.
    Sostenida {
        /// La confianza de ahora.
        confianza: u8,
    },
    /// Cae: un eslabon ya no se sostiene.
    Cae {
        /// Cual (indice en la cadena).
        eslabon: usize,
        /// Por que.
        motivo: String,
    },
}

/// Por que una confirmacion no sale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoConfirmada {
    /// Sin autor: una confirmacion anonima es una afirmacion sin responsable.
    SinAutor,
    /// El `sighting` resultante no valida (una identidad mal formada, por
    /// ejemplo).
    Invalida(Rechazo),
}

impl Hipotesis {
    /// El actor propuesto.
    #[must_use]
    pub fn actor(&self) -> &str {
        &self.actor
    }

    /// Su confianza, en centesimas.
    #[must_use]
    pub fn confianza(&self) -> u8 {
        self.confianza
    }

    /// La cadena de razonamiento, de lo observado al actor.
    #[must_use]
    pub fn cadena(&self) -> &[Eslabon] {
        &self.cadena
    }

    /// Los otros actores que explicarian lo mismo.
    #[must_use]
    pub fn alternativas(&self) -> &[String] {
        &self.alternativas
    }

    /// Las fuentes que, revocadas SOLAS, tumbarian la hipotesis: las raices de
    /// las que depende algun eslabon en exclusiva.
    #[must_use]
    pub fn depende_de(&self) -> &BTreeSet<String> {
        &self.depende_de
    }

    /// Cuantos caminos distintos llegan al mismo actor (se guarda el mas
    /// fuerte).
    #[must_use]
    pub fn caminos(&self) -> usize {
        self.caminos
    }

    /// La explicacion entera, legible.
    #[must_use]
    pub fn explicacion(&self) -> String {
        let mut s = format!(
            "HIPOTESIS (propuesta, no afirmada): {} activo en este despliegue, confianza {}/100",
            self.nombre_de(&self.actor),
            self.confianza
        );
        for (i, e) in self.cadena.iter().enumerate() {
            s.push_str(&format!(
                "\n  {}. {} [{}/100; {}]",
                i + 1,
                e.texto,
                e.confianza,
                e.fuentes.join(", ")
            ));
        }
        if !self.alternativas.is_empty() {
            // Los primeros por nombre y el resto contado: con cuarenta
            // alternativas, lo que importa es la cifra.
            const MOSTRADAS: usize = 8;
            let mut nombres: Vec<String> = self
                .alternativas
                .iter()
                .take(MOSTRADAS)
                .map(|a| self.nombre_de(a))
                .collect();
            if self.alternativas.len() > MOSTRADAS {
                nombres.push(format!("y {} mas", self.alternativas.len() - MOSTRADAS));
            }
            s.push_str(&format!(
                "\n  explicarian lo mismo {} otros: {} (por eso la confianza se reparte)",
                self.alternativas.len(),
                nombres.join(", ")
            ));
        }
        if !self.depende_de.is_empty() {
            s.push_str(&format!(
                "\n  cae si se revoca solo: {}",
                self.depende_de
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        s
    }

    fn nombre_de(&self, id: &str) -> String {
        self.nombres
            .get(id)
            .cloned()
            .unwrap_or_else(|| id.to_string())
    }

    /// La vuelve a comprobar contra el grafo de ahora: cada eslabon tiene que
    /// seguir en pie.
    #[must_use]
    pub fn rebatir(&self, g: &Grafo, ahora_ns: u64) -> Rebatida {
        for (i, e) in self.cadena.iter().enumerate() {
            let motivo = match &e.apoyo {
                Apoyo::Objeto(id) => match g.objeto(id) {
                    None => Some(format!("«{id}» ya no esta en el grafo")),
                    Some(o) if o.revocado => Some(format!("«{id}» esta revocado")),
                    Some(_) => None,
                },
                Apoyo::Arista(id) => match g.arista(id) {
                    Some(a) if g.vigente(a) => None,
                    _ => Some(format!("la relacion «{id}» ya no se sostiene")),
                },
                Apoyo::Observacion { local, .. } => g
                    .vistos(local)
                    .is_empty()
                    .then(|| format!("«{}» ya no consta como observado", local.texto())),
            };
            if let Some(motivo) = motivo {
                return Rebatida::Cae { eslabon: i, motivo };
            }
        }
        // Con los eslabones en pie, la confianza de ahora: la procedencia pudo
        // cambiar (una fuente revocada que no era la unica rebaja, no tumba).
        let (cadena, _) = recalcular(&self.cadena, g, ahora_ns);
        Rebatida::Sostenida {
            confianza: confianza_de(&cadena, self.alternativas.len(), self.saltos),
        }
    }

    /// Una persona la confirma: sale como un `sighting` de su organizacion.
    ///
    /// El `sighting` dice «esta organizacion vio esto», que es lo que se sabe;
    /// no dice «X es responsable», que es lo que no se sabe. La cadena va en la
    /// descripcion y quien confirmo, en `x_aegis_confirmado_por`.
    ///
    /// # Errors
    ///
    /// [`NoConfirmada::SinAutor`] si `autor` esta vacio: una confirmacion
    /// anonima es una afirmacion sin responsable, que es justo lo que el tipo
    /// existe para impedir. [`NoConfirmada::Invalida`] si el resultado no valida.
    pub fn confirmar(
        self,
        autor: &str,
        identidad: &str,
        ahora_ns: u64,
    ) -> Result<Objeto, NoConfirmada> {
        if autor.trim().is_empty() {
            return Err(NoConfirmada::SinAutor);
        }
        let cuando = aegis_share::stix::ns_a_rfc3339(ahora_ns);
        let id = format!(
            "sighting--{}",
            uuid_derivado(&format!("{}|{autor}|{ahora_ns}", self.actor))
        );
        let doc = serde_json::json!({
            "type": "bundle",
            "id": format!("bundle--{}", uuid_derivado(&id)),
            "objects": [{
                "type": "sighting",
                "spec_version": "2.1",
                "id": id,
                "created": cuando,
                "modified": cuando,
                "created_by_ref": identidad,
                "sighting_of_ref": self.actor,
                "where_sighted_refs": [identidad],
                "confidence": self.confianza,
                "description": self.explicacion(),
                "x_aegis_confirmado_por": autor,
            }]
        });
        Paquete::validar(&doc.to_string())
            .map_err(NoConfirmada::Invalida)?
            .objetos
            .into_values()
            .next()
            .ok_or(NoConfirmada::Invalida(Rechazo::NoEsJson {
                detalle: "el sighting no produjo ningun objeto".into(),
            }))
    }
}

/// Un UUID con forma valida, derivado de un texto (version 5 por formato).
fn uuid_derivado(s: &str) -> String {
    let d: [u8; 32] = Sha256::digest(s.as_bytes()).into();
    let mut b = [0u8; 16];
    b.copy_from_slice(&d[..16]);
    b[6] = (b[6] & 0x0f) | 0x50;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

fn es_actor(t: &Tipo) -> bool {
    matches!(t, Tipo::IntrusionSet | Tipo::ThreatActor | Tipo::Campaign)
}

fn es_capacidad(t: &Tipo) -> bool {
    matches!(t, Tipo::Malware | Tipo::Tool | Tipo::Infrastructure)
}

fn nombre(g: &Grafo, id: &str) -> String {
    let n = g.objeto(id).and_then(|o| o.texto("name")).unwrap_or(id);
    let t = g.objeto(id).map_or("?", |o| o.tipo.nombre());
    format!("{t} «{n}»")
}

fn raices(g: &Grafo, clave: &str, ahora_ns: u64) -> Vec<String> {
    let mut v: Vec<String> = g
        .procedencia()
        .ficha(clave)
        .map(|f| {
            f.vivos(ahora_ns)
                .iter()
                .map(|a| a.raiz().to_string())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v.dedup();
    v
}

fn eslabon_objeto(g: &Grafo, id: &str, texto: String, ahora_ns: u64) -> Eslabon {
    Eslabon {
        texto,
        apoyo: Apoyo::Objeto(id.to_string()),
        confianza: g.confianza(id, ahora_ns),
        fuentes: raices(g, id, ahora_ns),
    }
}

fn eslabon_arista(g: &Grafo, a: &Arista, ahora_ns: u64) -> Eslabon {
    Eslabon {
        texto: format!(
            "{} {} {}",
            nombre(g, &a.origen),
            a.tipo,
            nombre(g, &a.destino)
        ),
        apoyo: Apoyo::Arista(a.id.clone()),
        confianza: g.confianza(&a.id, ahora_ns),
        fuentes: raices(g, &a.declarada_por, ahora_ns),
    }
}

/// Recalcula la confianza y las fuentes de cada eslabon con la procedencia de
/// ahora. Devuelve la cadena y las fuentes de las que algun eslabon depende en
/// exclusiva.
fn recalcular(cadena: &[Eslabon], g: &Grafo, ahora_ns: u64) -> (Vec<Eslabon>, BTreeSet<String>) {
    let mut unicas = BTreeSet::new();
    let v = cadena
        .iter()
        .map(|e| {
            let mut e = e.clone();
            let clave = match &e.apoyo {
                Apoyo::Objeto(id) => Some(id.clone()),
                Apoyo::Arista(id) => g.arista(id).map(|a| a.declarada_por.clone()),
                Apoyo::Observacion { .. } => None,
            };
            if let Some(c) = clave {
                e.confianza = g.confianza(&c, ahora_ns);
                e.fuentes = raices(g, &c, ahora_ns);
                if e.fuentes.len() == 1 {
                    unicas.insert(e.fuentes[0].clone());
                }
            }
            e
        })
        .collect();
    (v, unicas)
}

/// La confianza de una cadena: la del eslabon mas debil, repartida entre las
/// alternativas y rebajada por cada atribucion encadenada.
fn confianza_de(cadena: &[Eslabon], alternativas: usize, saltos: usize) -> u8 {
    let mut c = u32::from(cadena.iter().map(|e| e.confianza).min().unwrap_or(0));
    c /= alternativas as u32 + 1;
    for _ in 0..saltos {
        c = c * RETENCION_POR_ATRIBUCION / 100;
    }
    u8::try_from(c.min(100)).unwrap_or(100)
}

/// Propone las hipotesis que el grafo de ahora sostiene, de la mas a la menos
/// confiada.
#[must_use]
pub fn proponer(g: &Grafo, ahora_ns: u64) -> Vec<Hipotesis> {
    let mut por_actor: BTreeMap<String, Hipotesis> = BTreeMap::new();
    let mut emitir =
        |actor: &str, cadena: Vec<Eslabon>, alternativas: Vec<String>, saltos: usize| {
            let (cadena, depende_de) = recalcular(&cadena, g, ahora_ns);
            let confianza = confianza_de(&cadena, alternativas.len(), saltos);
            let nombres = std::iter::once(actor)
                .chain(alternativas.iter().map(String::as_str))
                .map(|i| (i.to_string(), nombre(g, i)))
                .collect();
            let h = Hipotesis {
                actor: actor.to_string(),
                confianza,
                cadena,
                alternativas,
                depende_de,
                caminos: 1,
                saltos,
                nombres,
            };
            por_actor
                .entry(actor.to_string())
                .and_modify(|previa| {
                    let caminos = previa.caminos + 1;
                    if h.confianza > previa.confianza {
                        *previa = h.clone();
                    }
                    previa.caminos = caminos;
                })
                .or_insert(h);
        };

    for (local, vistos) in g.observados() {
        let maquinas: Vec<Eid> = vistos.iter().map(|a| a.maquina.clone()).collect();
        let observacion = Eslabon {
            texto: format!(
                "{} se vio en {} maquina(s) de este despliegue",
                local.texto(),
                maquinas.len()
            ),
            apoyo: Apoyo::Observacion {
                local: local.clone(),
                maquinas: maquinas.clone(),
            },
            confianza: 100,
            fuentes: vistos.iter().map(|a| a.fuente()).collect(),
        };
        for k in g.declarantes(local) {
            let Some(ko) = g.objeto(k) else { continue };
            let mut base = vec![
                observacion.clone(),
                eslabon_objeto(
                    g,
                    k,
                    format!("{} declara ese observable", nombre(g, k)),
                    ahora_ns,
                ),
            ];
            // Lo que el declarante senala: un indicador lo que indica; un
            // observable, quien lo contiene o se comunica con el.
            let senalados: Vec<&Arista> = if ko.tipo == Tipo::Indicator {
                g.salientes(k).filter(|a| a.tipo == "indicates").collect()
            } else {
                g.entrantes(k).filter(|a| !a.embebida).collect()
            };
            for a in senalados {
                let t = if ko.tipo == Tipo::Indicator {
                    &a.destino
                } else {
                    &a.origen
                };
                let Some(to) = g.objeto(t) else { continue };
                base.push(eslabon_arista(g, a, ahora_ns));
                if es_actor(&to.tipo) {
                    atribuir(g, t, base.clone(), Vec::new(), ahora_ns, &mut emitir, 0);
                } else if es_capacidad(&to.tipo) {
                    // Quien la usa (o la escribio): cada uno es una alternativa
                    // de los demas.
                    let usuarios: Vec<(&str, &Arista)> = g
                        .entrantes(t)
                        .filter(|u| u.tipo == "uses")
                        .map(|u| (u.origen.as_str(), u))
                        .chain(
                            g.salientes(t)
                                .filter(|u| u.tipo == "authored-by")
                                .map(|u| (u.destino.as_str(), u)),
                        )
                        .filter(|(actor, _)| g.objeto(actor).is_some_and(|o| es_actor(&o.tipo)))
                        .collect();
                    let nombres: BTreeSet<&str> = usuarios.iter().map(|(u, _)| *u).collect();
                    for (u, arista) in &usuarios {
                        let mut c = base.clone();
                        c.push(eslabon_arista(g, arista, ahora_ns));
                        let otros = nombres
                            .iter()
                            .filter(|n| **n != *u)
                            .map(|n| (*n).to_string())
                            .collect();
                        atribuir(g, u, c, otros, ahora_ns, &mut emitir, 0);
                    }
                }
                base.pop();
            }
        }
    }
    let mut v: Vec<Hipotesis> = por_actor.into_values().collect();
    v.sort_by(|a, b| {
        b.confianza
            .cmp(&a.confianza)
            .then_with(|| a.actor.cmp(&b.actor))
    });
    v
}

/// Emite la hipotesis para `actor` y sigue sus atribuciones, acotadas.
fn atribuir(
    g: &Grafo,
    actor: &str,
    cadena: Vec<Eslabon>,
    alternativas: Vec<String>,
    ahora_ns: u64,
    emitir: &mut impl FnMut(&str, Vec<Eslabon>, Vec<String>, usize),
    saltos: usize,
) {
    emitir(actor, cadena.clone(), alternativas.clone(), saltos);
    if saltos >= MAX_SALTOS_ATRIBUCION {
        return;
    }
    for a in g.salientes(actor).filter(|a| a.tipo == "attributed-to") {
        if !g.objeto(&a.destino).is_some_and(|o| es_actor(&o.tipo)) {
            continue;
        }
        let mut c = cadena.clone();
        c.push(eslabon_arista(g, a, ahora_ns));
        atribuir(
            g,
            &a.destino,
            c,
            alternativas.clone(),
            ahora_ns,
            emitir,
            saltos + 1,
        );
    }
}
