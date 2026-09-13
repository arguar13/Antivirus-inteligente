//! STIX 2.1: los objetos, y la validacion estricta de lo que entra.
//!
//! # Un paquete STIX es entrada controlada por el atacante
//!
//! Llega por TAXII desde una comunidad, o por federacion desde otra instancia, y
//! lo procesa el plano de control. No es un formato de intercambio entre amigos:
//! es JSON de un desconocido, y hay que tratarlo como tal.
//!
//! # La extensibilidad del formato ES la superficie de ataque
//!
//! STIX **obliga** a aceptar propiedades que no se conocen —es lo que permite que
//! el formato crezca—, y eso significa que un paquete puede traer carga
//! arbitraria en campos que nadie mira. La respuesta no es prohibirlo, porque
//! entonces se deja de hablar STIX: es **acotarlo**. Tope de bytes, de objetos,
//! de propiedades por objeto, de longitud de cada texto y de profundidad.
//!
//! # Las tres comprobaciones que casi nadie hace, y lo que cada una impide
//!
//! | Comprobacion | Sin ella |
//! |---|---|
//! | El **prefijo del identificador** coincide con el `type` | Un objeto dice `type: "indicator"` y lleva un `id` de `malware--…`; quien indexe por el prefijo y pinte por el tipo guarda una cosa y enseña otra |
//! | Una **referencia de marcado que no resuelve** restringe mas, no menos | El caso clasico: el objeto trae `object_marking_refs` apuntando a un marcado que no viaja en el paquete, no se encuentra, y se pinta **sin marcar** — es decir, publico |
//! | `modified >= created` | Un objeto «modificado antes de crearse» gana cualquier resolucion de conflictos por fecha, para siempre |
//!
//! La segunda es la que mas veces se ha visto filtrar en sistemas reales, y es
//! silenciosa: el documento es valido, el objeto se ve entero, y lo unico que
//! falta es la etiqueta que decia que no se podia enseñar.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use crate::marcado::{parcial_de_etiquetas, Marcado, Parcial};

/// Bytes maximos de un paquete.
///
/// Ocho megabytes. Un paquete legitimo grande —un informe con miles de
/// indicadores— cabe de sobra; uno de un gigabyte es una denegacion de servicio
/// que entra por la puerta que nosotros abrimos.
pub const MAX_PAQUETE: usize = 8 * 1024 * 1024;

/// Objetos maximos en un paquete.
pub const MAX_OBJETOS: usize = 50_000;

/// Propiedades maximas por objeto.
///
/// Acota la via de la extensibilidad: un objeto con cien mil propiedades
/// desconocidas es valido segun el formato y no lo es aqui.
pub const MAX_PROPIEDADES: usize = 256;

/// Longitud maxima de cualquier texto, en bytes.
pub const MAX_TEXTO: usize = 64 * 1024;

/// Profundidad maxima de anidamiento del JSON.
///
/// Sin esto, un documento con cien mil llaves abiertas desborda la pila **al
/// analizarlo**, antes de que ninguna validacion llegue a ejecutarse.
pub const MAX_PROFUNDIDAD: usize = 32;

/// Tipos de objeto de dominio que se reconocen.
///
/// La lista es cerrada y se declara: un tipo que no esta aqui se conserva como
/// [`Tipo::Otro`] con su nombre, **no se descarta**. Descartarlo perderia
/// informacion que otra instancia si entiende, y este nodo seria un agujero en la
/// federacion.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tipo {
    // --- Objetos de dominio (SDO) ---
    /// Un patron que detecta algo.
    Indicator,
    /// Una familia de codigo malicioso.
    Malware,
    /// El resultado de analizar una muestra.
    MalwareAnalysis,
    /// Un actor.
    ThreatActor,
    /// Un conjunto de intrusiones atribuido.
    IntrusionSet,
    /// Una campana.
    Campaign,
    /// Una tecnica de ATT&CK.
    AttackPattern,
    /// Una herramienta.
    Tool,
    /// Una vulnerabilidad.
    Vulnerability,
    /// Una identidad: persona, organizacion, sector.
    Identity,
    /// Infraestructura del adversario o propia.
    Infrastructure,
    /// Una accion de respuesta.
    CourseOfAction,
    /// Un lugar.
    Location,
    /// Datos observados.
    ObservedData,
    /// Un informe.
    Report,
    /// Una agrupacion sin la semantica de informe.
    Grouping,
    /// Un incidente.
    Incident,
    /// Una nota.
    Note,
    /// Una opinion sobre otro objeto.
    Opinion,
    // --- Objetos de relacion (SRO) ---
    /// Una relacion entre dos objetos.
    Relationship,
    /// Un avistamiento.
    Sighting,
    // --- Objetos de metadatos ---
    /// Una definicion de marcado.
    MarkingDefinition,
    /// Un paquete.
    Bundle,
    /// Un tipo que este nodo no conoce.
    Otro(String),
}

impl Tipo {
    /// El nombre tal y como va en el documento.
    #[must_use]
    pub fn nombre(&self) -> &str {
        match self {
            Tipo::Indicator => "indicator",
            Tipo::Malware => "malware",
            Tipo::MalwareAnalysis => "malware-analysis",
            Tipo::ThreatActor => "threat-actor",
            Tipo::IntrusionSet => "intrusion-set",
            Tipo::Campaign => "campaign",
            Tipo::AttackPattern => "attack-pattern",
            Tipo::Tool => "tool",
            Tipo::Vulnerability => "vulnerability",
            Tipo::Identity => "identity",
            Tipo::Infrastructure => "infrastructure",
            Tipo::CourseOfAction => "course-of-action",
            Tipo::Location => "location",
            Tipo::ObservedData => "observed-data",
            Tipo::Report => "report",
            Tipo::Grouping => "grouping",
            Tipo::Incident => "incident",
            Tipo::Note => "note",
            Tipo::Opinion => "opinion",
            Tipo::Relationship => "relationship",
            Tipo::Sighting => "sighting",
            Tipo::MarkingDefinition => "marking-definition",
            Tipo::Bundle => "bundle",
            Tipo::Otro(s) => s,
        }
    }

    /// Interpreta un nombre de tipo.
    #[must_use]
    pub fn de_nombre(s: &str) -> Tipo {
        match s {
            "indicator" => Tipo::Indicator,
            "malware" => Tipo::Malware,
            "malware-analysis" => Tipo::MalwareAnalysis,
            "threat-actor" => Tipo::ThreatActor,
            "intrusion-set" => Tipo::IntrusionSet,
            "campaign" => Tipo::Campaign,
            "attack-pattern" => Tipo::AttackPattern,
            "tool" => Tipo::Tool,
            "vulnerability" => Tipo::Vulnerability,
            "identity" => Tipo::Identity,
            "infrastructure" => Tipo::Infrastructure,
            "course-of-action" => Tipo::CourseOfAction,
            "location" => Tipo::Location,
            "observed-data" => Tipo::ObservedData,
            "report" => Tipo::Report,
            "grouping" => Tipo::Grouping,
            "incident" => Tipo::Incident,
            "note" => Tipo::Note,
            "opinion" => Tipo::Opinion,
            "relationship" => Tipo::Relationship,
            "sighting" => Tipo::Sighting,
            "marking-definition" => Tipo::MarkingDefinition,
            "bundle" => Tipo::Bundle,
            otro => Tipo::Otro(otro.to_string()),
        }
    }

    /// Si este nodo entiende la semantica de este tipo.
    #[must_use]
    pub fn conocido(&self) -> bool {
        !matches!(self, Tipo::Otro(_))
    }

    /// Las propiedades que el formato exige para este tipo.
    ///
    /// Es una tabla y no una cadena de `if` por la misma razon de siempre: la
    /// lista crece y una cadena de `if` crece con ella hasta que nadie sabe cual
    /// gana.
    #[must_use]
    pub fn obligatorias(&self) -> &'static [&'static str] {
        match self {
            Tipo::Indicator => &["pattern", "pattern_type", "valid_from"],
            Tipo::Malware => &["is_family"],
            Tipo::MalwareAnalysis => &["product"],
            Tipo::ThreatActor | Tipo::IntrusionSet | Tipo::Campaign | Tipo::AttackPattern => {
                &["name"]
            }
            Tipo::Tool | Tipo::Infrastructure | Tipo::CourseOfAction | Tipo::Grouping => &["name"],
            Tipo::Identity => &["name"],
            Tipo::Location => &[],
            Tipo::Vulnerability => &["name"],
            Tipo::ObservedData => &["first_observed", "last_observed", "number_observed"],
            Tipo::Report => &["name", "published", "object_refs"],
            Tipo::Incident => &["name"],
            Tipo::Note => &["content", "object_refs"],
            Tipo::Opinion => &["opinion", "object_refs"],
            Tipo::Relationship => &["relationship_type", "source_ref", "target_ref"],
            Tipo::Sighting => &["sighting_of_ref"],
            Tipo::MarkingDefinition => &[],
            Tipo::Bundle | Tipo::Otro(_) => &[],
        }
    }
}

/// Un objeto STIX ya validado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Objeto {
    /// Su tipo.
    pub tipo: Tipo,
    /// Su identificador, `tipo--uuid`.
    pub id: String,
    /// Cuando se creo, en nanosegundos Unix.
    pub creado_ns: u64,
    /// Cuando se modifico por ultima vez.
    pub modificado_ns: u64,
    /// El marcado efectivo, ya resuelto.
    ///
    /// **No es lo que decia el documento**: es lo que queda tras resolver las
    /// referencias de marcado y aplicar la regla de lo que no resuelve. Ver
    /// [`Paquete::validar`].
    pub marcado: Marcado,
    /// Si el objeto esta revocado.
    pub revocado: bool,
    /// Etiquetas.
    pub etiquetas: Vec<String>,
    /// Referencias a otros objetos que este declara.
    pub referencias: Vec<String>,
    /// El documento completo, tal y como llego.
    ///
    /// Se conserva entero **a proposito**: reemitir un objeto reconstruyendolo de
    /// los campos que este nodo entiende perderia todo lo que no entiende, y este
    /// nodo seria un agujero en la federacion. Ver [`Tipo::Otro`].
    pub crudo: Map<String, Value>,
}

impl Objeto {
    /// El valor de una propiedad como texto.
    #[must_use]
    pub fn texto(&self, clave: &str) -> Option<&str> {
        self.crudo.get(clave)?.as_str()
    }

    /// Si es un indicador con patron.
    #[must_use]
    pub fn patron(&self) -> Option<&str> {
        (self.tipo == Tipo::Indicator).then(|| self.texto("pattern"))?
    }
}

/// Por que un paquete o un objeto no pasa.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rechazo {
    /// El documento no es JSON, o no es un objeto.
    NoEsJson {
        /// Que paso.
        detalle: String,
    },
    /// Paso de algun tope.
    Desmesurado {
        /// Cual.
        que: &'static str,
        /// Valor visto.
        visto: usize,
        /// Tope.
        tope: usize,
    },
    /// Falta una propiedad obligatoria.
    FaltaPropiedad {
        /// En que objeto.
        id: String,
        /// Cual.
        propiedad: &'static str,
    },
    /// El identificador no tiene la forma `tipo--uuid`.
    IdMalformado {
        /// El que se vio.
        id: String,
    },
    /// El prefijo del identificador no coincide con el `type`.
    ///
    /// Es una comprobacion que el formato exige y casi nadie hace.
    IdNoCuadraConTipo {
        /// El identificador.
        id: String,
        /// El tipo declarado.
        tipo: String,
    },
    /// Version del formato que no es 2.1.
    VersionInesperada {
        /// La que venia.
        version: String,
    },
    /// Una marca de tiempo mal escrita.
    TiempoMalformado {
        /// En que objeto.
        id: String,
        /// Que campo.
        campo: &'static str,
    },
    /// `modified` es anterior a `created`.
    TiempoImposible {
        /// En que objeto.
        id: String,
    },
    /// Una propiedad personalizada que no empieza por `x_`.
    ///
    /// El formato lo exige, y no es burocracia: sin el prefijo, una propiedad
    /// inventada hoy choca con una del estandar de mañana y el significado cambia
    /// sin que nadie toque el codigo.
    PersonalizadaSinPrefijo {
        /// En que objeto.
        id: String,
        /// Cual.
        propiedad: String,
    },
    /// Dos objetos con el mismo identificador y la misma version.
    Duplicado {
        /// Cual.
        id: String,
    },
}

impl Rechazo {
    /// Texto para el informe.
    #[must_use]
    pub fn texto(&self) -> String {
        match self {
            Rechazo::NoEsJson { detalle } => format!("no es un documento JSON valido: {detalle}"),
            Rechazo::Desmesurado { que, visto, tope } => {
                format!("{que}: {visto} pasa del tope de {tope}")
            }
            Rechazo::FaltaPropiedad { id, propiedad } => {
                format!("«{id}» no trae «{propiedad}», que su tipo exige")
            }
            Rechazo::IdMalformado { id } => {
                format!("«{id}» no tiene la forma tipo--uuid")
            }
            Rechazo::IdNoCuadraConTipo { id, tipo } => format!(
                "«{id}» dice ser de tipo «{tipo}»: quien indexe por el prefijo del identificador y \
                 pinte por el tipo guardaria una cosa y enseñaria otra"
            ),
            Rechazo::VersionInesperada { version } => {
                format!("version de formato «{version}»; este nodo habla 2.1")
            }
            Rechazo::TiempoMalformado { id, campo } => {
                format!("«{id}» trae un «{campo}» que no es una marca de tiempo valida")
            }
            Rechazo::TiempoImposible { id } => format!(
                "«{id}» dice haberse modificado antes de crearse: asi ganaria cualquier resolucion \
                 de conflictos por fecha, para siempre"
            ),
            Rechazo::PersonalizadaSinPrefijo { id, propiedad } => format!(
                "«{id}» trae la propiedad personalizada «{propiedad}» sin el prefijo x_: sin el, \
                 choca con una del estandar de mañana y el significado cambia sin tocar el codigo"
            ),
            Rechazo::Duplicado { id } => format!("«{id}» aparece dos veces con la misma version"),
        }
    }
}

/// Un paquete STIX validado.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Paquete {
    /// Identificador del paquete.
    pub id: String,
    /// Los objetos, por identificador.
    pub objetos: BTreeMap<String, Objeto>,
}

impl Paquete {
    /// Valida un documento y produce el paquete.
    ///
    /// # Errors
    ///
    /// Devuelve el primer [`Rechazo`]. El primero y no todos a proposito: un
    /// documento hostil puede tener un millon de errores, y acumularlos es otra
    /// via de agotar la memoria.
    pub fn validar(texto: &str) -> Result<Paquete, Rechazo> {
        if texto.len() > MAX_PAQUETE {
            return Err(Rechazo::Desmesurado {
                que: "bytes del paquete",
                visto: texto.len(),
                tope: MAX_PAQUETE,
            });
        }
        // La profundidad se mide ANTES de analizar: un documento con cien mil
        // llaves abiertas desborda la pila al analizarlo, antes de que ninguna
        // validacion llegue a ejecutarse.
        comprobar_profundidad(texto)?;

        let raiz: Value = serde_json::from_str(texto).map_err(|e| Rechazo::NoEsJson {
            detalle: recortar(&e.to_string(), 200),
        })?;
        let Value::Object(mapa) = raiz else {
            return Err(Rechazo::NoEsJson {
                detalle: "la raiz no es un objeto".into(),
            });
        };

        let id = mapa
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("bundle--sin-id")
            .to_string();

        let objetos_json = match mapa.get("objects") {
            Some(Value::Array(v)) => v.clone(),
            // Un documento con un solo objeto y sin envoltorio tambien se acepta:
            // circula asi por TAXII, donde la coleccion ya es el envoltorio.
            None if mapa.contains_key("type") => vec![Value::Object(mapa.clone())],
            _ => {
                return Err(Rechazo::NoEsJson {
                    detalle: "no trae «objects» ni es un objeto suelto".into(),
                })
            }
        };

        if objetos_json.len() > MAX_OBJETOS {
            return Err(Rechazo::Desmesurado {
                que: "objetos del paquete",
                visto: objetos_json.len(),
                tope: MAX_OBJETOS,
            });
        }

        // PRIMERA PASADA: validar cada objeto por separado y recoger los marcados
        // que viajan dentro del paquete.
        let mut crudos: Vec<(String, Tipo, Map<String, Value>)> = Vec::new();
        let mut marcados: BTreeMap<String, Parcial> = BTreeMap::new();
        let mut vistos: BTreeSet<String> = BTreeSet::new();

        for v in objetos_json {
            let Value::Object(o) = v else {
                return Err(Rechazo::NoEsJson {
                    detalle: "un elemento de «objects» no es un objeto".into(),
                });
            };
            let (id_obj, tipo) = validar_cabecera(&o)?;
            validar_propiedades(&o, &id_obj, &tipo)?;

            if !vistos.insert(clave_version(&o, &id_obj)) {
                return Err(Rechazo::Duplicado { id: id_obj });
            }
            if tipo == Tipo::MarkingDefinition {
                marcados.insert(id_obj.clone(), marcado_de_definicion(&o));
            }
            crudos.push((id_obj, tipo, o));
        }

        // SEGUNDA PASADA: resolver el marcado efectivo de cada objeto.
        let mut objetos = BTreeMap::new();
        for (id_obj, tipo, o) in crudos {
            let creado_ns = tiempo_de(&o, "created", &id_obj)?.unwrap_or(0);
            let modificado_ns = tiempo_de(&o, "modified", &id_obj)?.unwrap_or(creado_ns);
            if modificado_ns < creado_ns {
                return Err(Rechazo::TiempoImposible { id: id_obj });
            }

            let marcado = if tipo == Tipo::MarkingDefinition {
                // UNA DEFINICION DE MARCADO ES PUBLICA SALVO QUE DIGA OTRA COSA.
                //
                // Parece contradecir la regla de que lo no marcado es lo mas
                // restrictivo, y en realidad es lo que la hace funcionar: la
                // definicion TIENE que viajar con los objetos que marca, porque si
                // no llega, su referencia no resuelve y —por nuestra propia
                // regla— esos objetos acaban en RED en el otro extremo.
                //
                // Una definicion que no se puede distribuir hace que nada se
                // pueda distribuir. Y no abre ningun agujero: una definicion no
                // lleva inteligencia, lleva el nombre de una etiqueta, y los
                // marcados TLP son constantes publicas conocidas por todos.
                let propio = resolver_marcado_parcial(&o, &marcados);
                Marcado {
                    tlp: propio.tlp.unwrap_or(crate::marcado::Tlp::Clear),
                    pap: propio.pap.unwrap_or(crate::marcado::Pap::Clear),
                }
            } else {
                resolver_marcado(&o, &marcados)
            };
            let etiquetas = lista_de_textos(&o, "labels");
            let referencias = referencias_de(&o);
            let revocado = o.get("revoked").and_then(Value::as_bool).unwrap_or(false);

            objetos.insert(
                id_obj.clone(),
                Objeto {
                    tipo,
                    id: id_obj,
                    creado_ns,
                    modificado_ns,
                    marcado,
                    revocado,
                    etiquetas,
                    referencias,
                    crudo: o,
                },
            );
        }

        Ok(Paquete { id, objetos })
    }

    /// El marcado efectivo del paquete entero: el mas restrictivo de sus objetos.
    ///
    /// Un informe que cita una fuente `TLP:RED` es `TLP:RED`, por mucho que lo
    /// demas fuera publico.
    #[must_use]
    pub fn marcado(&self) -> Marcado {
        self.objetos
            .values()
            .map(|o| o.marcado)
            .reduce(Marcado::combinar)
            .unwrap_or_else(Marcado::publico)
    }

    /// Los objetos de un tipo.
    #[must_use]
    pub fn de_tipo(&self, tipo: &Tipo) -> Vec<&Objeto> {
        self.objetos.values().filter(|o| &o.tipo == tipo).collect()
    }

    /// Serializa el paquete.
    #[must_use]
    pub fn a_json(&self) -> String {
        let objetos: Vec<Value> = self
            .objetos
            .values()
            .map(|o| Value::Object(o.crudo.clone()))
            .collect();
        let mut raiz = Map::new();
        raiz.insert("type".into(), Value::String("bundle".into()));
        raiz.insert("id".into(), Value::String(self.id.clone()));
        raiz.insert("objects".into(), Value::Array(objetos));
        Value::Object(raiz).to_string()
    }

    /// Referencias que apuntan fuera del paquete.
    ///
    /// No es un error —los objetos se reparten entre paquetes a proposito— pero
    /// si un dato: una relacion cuyos dos extremos faltan no aporta nada hasta
    /// que lleguen, y saber cuantas hay dice si una federacion esta llegando
    /// entera o a trozos.
    #[must_use]
    pub fn referencias_colgando(&self) -> Vec<&str> {
        let mut fuera: Vec<&str> = Vec::new();
        for o in self.objetos.values() {
            for r in &o.referencias {
                if !self.objetos.contains_key(r) {
                    fuera.push(r.as_str());
                }
            }
        }
        fuera.sort_unstable();
        fuera.dedup();
        fuera
    }
}

/// Valida `type` e `id`, y que cuadren entre si.
fn validar_cabecera(o: &Map<String, Value>) -> Result<(String, Tipo), Rechazo> {
    let tipo_txt = o
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| Rechazo::NoEsJson {
            detalle: "un objeto no trae «type»".into(),
        })?;
    let id = o
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| Rechazo::NoEsJson {
            detalle: format!("un objeto «{tipo_txt}» no trae «id»"),
        })?
        .to_string();

    // Forma `tipo--uuid`.
    let Some((prefijo, resto)) = id.split_once("--") else {
        return Err(Rechazo::IdMalformado { id });
    };
    if prefijo.is_empty() || !uuid_plausible(resto) {
        return Err(Rechazo::IdMalformado { id });
    }
    // LA COMPROBACION QUE CASI NADIE HACE.
    if prefijo != tipo_txt {
        return Err(Rechazo::IdNoCuadraConTipo {
            id,
            tipo: tipo_txt.to_string(),
        });
    }

    if let Some(v) = o.get("spec_version").and_then(Value::as_str) {
        if v != "2.1" {
            return Err(Rechazo::VersionInesperada {
                version: recortar(v, 32),
            });
        }
    }
    Ok((id, Tipo::de_nombre(tipo_txt)))
}

/// Valida las propiedades obligatorias, los topes y el prefijo `x_`.
fn validar_propiedades(o: &Map<String, Value>, id: &str, tipo: &Tipo) -> Result<(), Rechazo> {
    if o.len() > MAX_PROPIEDADES {
        return Err(Rechazo::Desmesurado {
            que: "propiedades de un objeto",
            visto: o.len(),
            tope: MAX_PROPIEDADES,
        });
    }
    for p in tipo.obligatorias() {
        if !o.contains_key(*p) {
            return Err(Rechazo::FaltaPropiedad {
                id: id.to_string(),
                propiedad: p,
            });
        }
    }
    for (clave, valor) in o {
        if let Some(s) = valor.as_str() {
            if s.len() > MAX_TEXTO {
                return Err(Rechazo::Desmesurado {
                    que: "longitud de un texto",
                    visto: s.len(),
                    tope: MAX_TEXTO,
                });
            }
        }
        // Una propiedad que no es del estandar ni empieza por `x_` es un choque de
        // nombres esperando a ocurrir.
        if !clave.starts_with("x_") && !propiedad_conocida(clave) && !tipo.conocido() {
            continue;
        }
        if !clave.starts_with("x_") && !propiedad_conocida(clave) {
            return Err(Rechazo::PersonalizadaSinPrefijo {
                id: id.to_string(),
                propiedad: recortar(clave, 64),
            });
        }
    }
    Ok(())
}

/// Resuelve el marcado efectivo de un objeto.
///
/// # La regla que impide la fuga silenciosa
///
/// Si el objeto declara `object_marking_refs` y **alguna no resuelve**, el
/// resultado es [`Marcado::desconocido`] —lo mas restrictivo— y no «sin marcar».
///
/// Es el caso que mas veces se ha visto filtrar en sistemas reales: el objeto
/// trae una referencia a un marcado que no viaja en el paquete, no se encuentra,
/// y se pinta sin etiqueta. El documento es valido, el objeto se ve entero, y lo
/// unico que falta es justo la etiqueta que decia que no se podia enseñar.
fn resolver_marcado(o: &Map<String, Value>, conocidos: &BTreeMap<String, Parcial>) -> Marcado {
    match resolver_parcial(o, conocidos) {
        Some(p) => p.resolver(),
        // LA REGLA QUE IMPIDE LA FUGA SILENCIOSA. Una referencia que no resuelve
        // no deja el objeto «sin marcar»: lo deja en lo mas restrictivo.
        None => Marcado::desconocido(),
    }
}

/// Lo mismo, pero sin resolver lo que se calla.
///
/// Lo usa la definicion de marcado, que tiene su propio valor por defecto.
fn resolver_marcado_parcial(
    o: &Map<String, Value>,
    conocidos: &BTreeMap<String, Parcial>,
) -> Parcial {
    resolver_parcial(o, conocidos).unwrap_or(Parcial {
        tlp: Some(crate::marcado::Tlp::Red),
        pap: Some(crate::marcado::Pap::Red),
    })
}

/// Combina etiquetas y referencias. `None` si alguna referencia no resuelve.
fn resolver_parcial(
    o: &Map<String, Value>,
    conocidos: &BTreeMap<String, Parcial>,
) -> Option<Parcial> {
    let refs = lista_de_textos(o, "object_marking_refs");
    // Se combinan las partes ANTES de resolver lo que callan. Un objeto puede
    // declarar su TLP por etiqueta y su PAP por referencia, o al reves; si cada
    // parte resolviera por su cuenta «lo que no dice es RED», la parte que si
    // venia por la otra via quedaria pisada. Eso no filtra, pero deja todo en el
    // nivel mas restrictivo y el sistema se vuelve inservible.
    let mut acumulado = parcial_de_etiquetas(&lista_de_textos(o, "labels"));
    for r in &refs {
        acumulado = acumulado.combinar(*conocidos.get(r)?);
    }
    Some(acumulado)
}

/// El marcado que declara una `marking-definition`.
fn marcado_de_definicion(o: &Map<String, Value>) -> Parcial {
    // TLP 2.0 usa `marking-definition` con `name`; el 1.0 usaba `definition`.
    // Se miran los dos, porque los dos circulan.
    let mut etiquetas = lista_de_textos(o, "labels");
    if let Some(n) = o.get("name").and_then(Value::as_str) {
        etiquetas.push(n.to_string());
    }
    if let Some(d) = o.get("definition").and_then(Value::as_object) {
        for v in d.values() {
            if let Some(s) = v.as_str() {
                etiquetas.push(s.to_string());
            }
        }
    }
    if let Some(t) = o.get("definition_type").and_then(Value::as_str) {
        if let Some(d) = o.get("definition").and_then(Value::as_object) {
            if let Some(s) = d.get(t).and_then(Value::as_str) {
                etiquetas.push(format!("{}:{}", t.to_ascii_uppercase(), s));
            }
        }
    }
    // Parcial y no completo: una definicion de marcado que solo habla de TLP no
    // dice nada del PAP, y resolverlo aqui a RED pisaria el PAP que el objeto si
    // declaro por etiqueta.
    parcial_de_etiquetas(&etiquetas)
}

/// Las referencias a otros objetos que un objeto declara.
fn referencias_de(o: &Map<String, Value>) -> Vec<String> {
    const CAMPOS: &[&str] = &[
        "source_ref",
        "target_ref",
        "sighting_of_ref",
        "created_by_ref",
        "sample_ref",
        "host_vm_ref",
        "operating_system_ref",
    ];
    const LISTAS: &[&str] = &[
        "object_refs",
        "where_sighted_refs",
        "observed_data_refs",
        "analysis_sco_refs",
    ];
    let mut r = Vec::new();
    for c in CAMPOS {
        if let Some(s) = o.get(*c).and_then(Value::as_str) {
            r.push(s.to_string());
        }
    }
    for l in LISTAS {
        r.extend(lista_de_textos(o, l));
    }
    r.sort();
    r.dedup();
    r
}

fn lista_de_textos(o: &Map<String, Value>, clave: &str) -> Vec<String> {
    o.get(clave)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(|s| recortar(s, 512))
                .collect()
        })
        .unwrap_or_default()
}

/// Una marca de tiempo STIX en nanosegundos Unix.
fn tiempo_de(
    o: &Map<String, Value>,
    campo: &'static str,
    id: &str,
) -> Result<Option<u64>, Rechazo> {
    let Some(v) = o.get(campo) else {
        return Ok(None);
    };
    let Some(s) = v.as_str() else {
        return Err(Rechazo::TiempoMalformado {
            id: id.to_string(),
            campo,
        });
    };
    rfc3339_a_ns(s)
        .map(Some)
        .ok_or_else(|| Rechazo::TiempoMalformado {
            id: id.to_string(),
            campo,
        })
}

/// Convierte `YYYY-MM-DDTHH:MM:SS[.ffffff]Z` a nanosegundos Unix.
///
/// Escrito a mano y sin dependencias, con el algoritmo de Howard Hinnant, igual
/// que en `aegis-ingest::tiempo`: dos calendarios distintos en el mismo producto
/// es la forma de que un dia dos modulos ordenen el mismo suceso al reves.
#[must_use]
pub fn rfc3339_a_ns(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' {
        return None;
    }
    let num = |i: usize, n: usize| -> Option<i64> { s.get(i..i + n)?.parse::<i64>().ok() };
    let anio = num(0, 4)?;
    let mes = num(5, 2)?;
    let dia = num(8, 2)?;
    let hora = num(11, 2)?;
    let min = num(14, 2)?;
    let seg = num(17, 2)?;
    if !(1..=12).contains(&mes) || !(1..=31).contains(&dia) {
        return None;
    }
    if hora > 23 || min > 59 || seg > 60 {
        return None;
    }
    // Fraccion opcional, y despues la `Z`. STIX exige UTC con `Z`: un desfase
    // horario aqui seria una hora distinta de la que el documento dice.
    let resto = &s[19..];
    let (frac_ns, cola) = if let Some(sin_punto) = resto.strip_prefix('.') {
        let fin = sin_punto
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(sin_punto.len());
        let digitos = &sin_punto[..fin];
        if digitos.is_empty() || digitos.len() > 9 {
            return None;
        }
        let mut v: u64 = digitos.parse().ok()?;
        for _ in digitos.len()..9 {
            v *= 10;
        }
        (v, &sin_punto[fin..])
    } else {
        (0, resto)
    };
    if cola != "Z" {
        return None;
    }
    let dias = dias_desde_civil(anio, mes, dia)?;
    let segundos = dias.checked_mul(86_400)? + hora * 3600 + min * 60 + seg;
    if segundos < 0 {
        return None;
    }
    u64::try_from(segundos)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(frac_ns)
}

/// Dias desde 1970-01-01, algoritmo de Hinnant.
fn dias_desde_civil(a: i64, m: i64, d: i64) -> Option<i64> {
    let a = if m <= 2 { a - 1 } else { a };
    let era = if a >= 0 { a } else { a - 399 } / 400;
    let yoe = a - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

/// Escribe nanosegundos Unix como marca de tiempo STIX.
#[must_use]
pub fn ns_a_rfc3339(ns: u64) -> String {
    let seg = (ns / 1_000_000_000) as i64;
    let milis = (ns % 1_000_000_000) / 1_000_000;
    let dias = seg.div_euclid(86_400);
    let resto = seg.rem_euclid(86_400);
    let (a, m, d) = civil_desde_dias(dias);
    format!(
        "{a:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{milis:03}Z",
        resto / 3600,
        (resto % 3600) / 60,
        resto % 60
    )
}

fn civil_desde_dias(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Si una cadena tiene forma de UUID.
fn uuid_plausible(s: &str) -> bool {
    s.len() == 36
        && s.as_bytes().iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// Mide la profundidad de anidamiento sin analizar el documento.
///
/// Se hace **antes** de `serde_json::from_str` a proposito: un documento con cien
/// mil llaves abiertas desborda la pila al analizarlo, y entonces no hay
/// validacion que valga porque el proceso ya no esta.
fn comprobar_profundidad(texto: &str) -> Result<(), Rechazo> {
    let mut nivel = 0usize;
    let mut maximo = 0usize;
    let mut en_texto = false;
    let mut escapado = false;
    for c in texto.bytes() {
        if en_texto {
            if escapado {
                escapado = false;
            } else if c == b'\\' {
                escapado = true;
            } else if c == b'"' {
                en_texto = false;
            }
            continue;
        }
        match c {
            b'"' => en_texto = true,
            b'{' | b'[' => {
                nivel += 1;
                maximo = maximo.max(nivel);
                if nivel > MAX_PROFUNDIDAD {
                    return Err(Rechazo::Desmesurado {
                        que: "profundidad de anidamiento",
                        visto: nivel,
                        tope: MAX_PROFUNDIDAD,
                    });
                }
            }
            b'}' | b']' => nivel = nivel.saturating_sub(1),
            _ => {}
        }
    }
    let _ = maximo;
    Ok(())
}

/// La clave que distingue dos versiones del mismo objeto.
fn clave_version(o: &Map<String, Value>, id: &str) -> String {
    let m = o.get("modified").and_then(Value::as_str).unwrap_or("");
    format!("{id}@{m}")
}

/// Si una propiedad es del estandar.
fn propiedad_conocida(clave: &str) -> bool {
    const COMUNES: &[&str] = &[
        "type",
        "id",
        "spec_version",
        "created",
        "modified",
        "created_by_ref",
        "revoked",
        "labels",
        "confidence",
        "lang",
        "external_references",
        "object_marking_refs",
        "granular_markings",
        "extensions",
        "defanged",
        "name",
        "description",
        "aliases",
        "first_seen",
        "last_seen",
        "objective",
        "pattern",
        "pattern_type",
        "pattern_version",
        "valid_from",
        "valid_until",
        "indicator_types",
        "kill_chain_phases",
        "is_family",
        "malware_types",
        "capabilities",
        "sample_refs",
        "operating_system_refs",
        "architecture_execution_envs",
        "implementation_languages",
        "product",
        "version",
        "analysis_engine_version",
        "analysis_definition_version",
        "submitted",
        "analysis_started",
        "analysis_ended",
        "result",
        "result_name",
        "analysis_sco_refs",
        "sample_ref",
        "host_vm_ref",
        "operating_system_ref",
        "installed_software_refs",
        "configuration_version",
        "modules",
        "threat_actor_types",
        "roles",
        "goals",
        "sophistication",
        "resource_level",
        "primary_motivation",
        "secondary_motivations",
        "personal_motivations",
        "tool_types",
        "tool_version",
        "identity_class",
        "sectors",
        "contact_information",
        "infrastructure_types",
        "action",
        "latitude",
        "longitude",
        "precision",
        "region",
        "country",
        "administrative_area",
        "city",
        "street_address",
        "postal_code",
        "first_observed",
        "last_observed",
        "number_observed",
        "objects",
        "object_refs",
        "published",
        "report_types",
        "context",
        "incident_types",
        "abstract",
        "content",
        "authors",
        "opinion",
        "explanation",
        "relationship_type",
        "source_ref",
        "target_ref",
        "start_time",
        "stop_time",
        "sighting_of_ref",
        "observed_data_refs",
        "where_sighted_refs",
        "summary",
        "count",
        "definition_type",
        "definition",
        "definition_version",
        "extension_type",
    ];
    COMUNES.contains(&clave)
}

fn recortar(s: &str, tope: usize) -> String {
    if s.len() <= tope {
        return s.to_string();
    }
    let mut n = tope;
    while n > 0 && !s.is_char_boundary(n) {
        n -= 1;
    }
    s[..n].to_string()
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::marcado::{Pap, Tlp};

    fn indicador(id: &str, etiquetas: &str) -> String {
        format!(
            r#"{{"type":"indicator","spec_version":"2.1","id":"{id}",
            "created":"2025-01-13T08:00:00.000Z","modified":"2025-01-13T08:00:00.000Z",
            "pattern":"[file:hashes.'SHA-256' = '7f1e']","pattern_type":"stix",
            "valid_from":"2025-01-13T08:00:00.000Z","labels":[{etiquetas}]}}"#
        )
    }

    fn paquete(cuerpo: &str) -> String {
        format!(
            r#"{{"type":"bundle","id":"bundle--{}","objects":[{cuerpo}]}}"#,
            UUID_A
        )
    }

    const UUID_A: &str = "11111111-2222-3333-4444-555555555555";
    const UUID_B: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

    #[test]
    fn un_indicador_correcto_pasa_y_conserva_lo_que_no_entendemos() {
        let doc = paquete(&format!(
            r#"{{"type":"indicator","spec_version":"2.1","id":"indicator--{UUID_A}",
            "created":"2025-01-13T08:00:00.000Z","modified":"2025-01-13T09:00:00.000Z",
            "pattern":"[domain-name:value = 'malo.example']","pattern_type":"stix",
            "valid_from":"2025-01-13T08:00:00.000Z",
            "labels":["TLP:GREEN","PAP:AMBER"],
            "x_comunidad_confianza":"alta"}}"#
        ));
        let p = Paquete::validar(&doc).expect("valido");
        assert_eq!(p.objetos.len(), 1);
        let o = p.objetos.values().next().expect("hay uno");
        assert_eq!(o.tipo, Tipo::Indicator);
        assert_eq!(o.marcado, Marcado::nuevo(Tlp::Green, Pap::Amber));
        // Lo que este nodo no entiende se conserva: reconstruir el objeto de los
        // campos conocidos haria de este nodo un agujero en la federacion.
        assert_eq!(o.texto("x_comunidad_confianza"), Some("alta"));
    }

    #[test]
    fn el_prefijo_del_id_tiene_que_cuadrar_con_el_tipo() {
        // Quien indexe por el prefijo y pinte por el tipo guarda una cosa y
        // enseña otra.
        let doc = paquete(&format!(
            r#"{{"type":"indicator","spec_version":"2.1","id":"malware--{UUID_A}",
            "created":"2025-01-13T08:00:00.000Z","modified":"2025-01-13T08:00:00.000Z",
            "pattern":"[x = 1]","pattern_type":"stix","valid_from":"2025-01-13T08:00:00.000Z"}}"#
        ));
        assert!(matches!(
            Paquete::validar(&doc),
            Err(Rechazo::IdNoCuadraConTipo { .. })
        ));
    }

    #[test]
    fn una_referencia_de_marcado_que_no_resuelve_restringe_mas() {
        // El caso que mas veces se ha visto filtrar: la referencia apunta a un
        // marcado que no viaja en el paquete, no se encuentra, y el objeto se
        // pinta SIN marcar — es decir, publico.
        let doc = paquete(&format!(
            r#"{{"type":"indicator","spec_version":"2.1","id":"indicator--{UUID_A}",
            "created":"2025-01-13T08:00:00.000Z","modified":"2025-01-13T08:00:00.000Z",
            "pattern":"[x = 1]","pattern_type":"stix","valid_from":"2025-01-13T08:00:00.000Z",
            "labels":["TLP:CLEAR","PAP:CLEAR"],
            "object_marking_refs":["marking-definition--{UUID_B}"]}}"#
        ));
        let p = Paquete::validar(&doc).expect("valido");
        let o = p.objetos.values().next().expect("hay uno");
        assert_eq!(
            o.marcado,
            Marcado::desconocido(),
            "una referencia que no resuelve dejo el objeto publico"
        );
    }

    #[test]
    fn una_referencia_de_marcado_que_si_resuelve_se_aplica() {
        let doc = format!(
            r#"{{"type":"bundle","id":"bundle--{UUID_A}","objects":[
            {{"type":"marking-definition","spec_version":"2.1",
             "id":"marking-definition--{UUID_B}","created":"2025-01-13T08:00:00.000Z",
             "name":"TLP:AMBER"}},
            {{"type":"indicator","spec_version":"2.1","id":"indicator--{UUID_A}",
             "created":"2025-01-13T08:00:00.000Z","modified":"2025-01-13T08:00:00.000Z",
             "pattern":"[x = 1]","pattern_type":"stix","valid_from":"2025-01-13T08:00:00.000Z",
             "labels":["PAP:GREEN"],
             "object_marking_refs":["marking-definition--{UUID_B}"]}}]}}"#
        );
        let p = Paquete::validar(&doc).expect("valido");
        let ind = &p.objetos[&format!("indicator--{UUID_A}")];
        assert_eq!(ind.marcado.tlp, Tlp::AmberStrict);
        assert_eq!(ind.marcado.pap, Pap::Green);
        // Y el marcado del paquete entero es el mas restrictivo de sus objetos.
        assert_eq!(p.marcado().tlp, Tlp::AmberStrict);
    }

    #[test]
    fn un_objeto_modificado_antes_de_crearse_se_rechaza() {
        // Asi ganaria cualquier resolucion de conflictos por fecha, para siempre.
        let doc = paquete(&format!(
            r#"{{"type":"indicator","spec_version":"2.1","id":"indicator--{UUID_A}",
            "created":"2025-01-13T08:00:00.000Z","modified":"2020-01-01T00:00:00.000Z",
            "pattern":"[x = 1]","pattern_type":"stix","valid_from":"2025-01-13T08:00:00.000Z"}}"#
        ));
        assert!(matches!(
            Paquete::validar(&doc),
            Err(Rechazo::TiempoImposible { .. })
        ));
    }

    #[test]
    fn falta_una_propiedad_obligatoria_y_se_dice_cual() {
        let doc = paquete(&format!(
            r#"{{"type":"indicator","spec_version":"2.1","id":"indicator--{UUID_A}",
            "created":"2025-01-13T08:00:00.000Z","modified":"2025-01-13T08:00:00.000Z",
            "pattern_type":"stix","valid_from":"2025-01-13T08:00:00.000Z"}}"#
        ));
        let e = Paquete::validar(&doc).expect_err("falta pattern");
        assert!(e.texto().contains("pattern"));
    }

    #[test]
    fn una_propiedad_personalizada_sin_x_se_rechaza() {
        let doc = paquete(&format!(
            r#"{{"type":"indicator","spec_version":"2.1","id":"indicator--{UUID_A}",
            "created":"2025-01-13T08:00:00.000Z","modified":"2025-01-13T08:00:00.000Z",
            "pattern":"[x = 1]","pattern_type":"stix","valid_from":"2025-01-13T08:00:00.000Z",
            "confianza_propia":"alta"}}"#
        ));
        assert!(matches!(
            Paquete::validar(&doc),
            Err(Rechazo::PersonalizadaSinPrefijo { .. })
        ));
    }

    #[test]
    fn un_tipo_desconocido_se_conserva_en_vez_de_descartarse() {
        // Descartarlo perderia informacion que otra instancia si entiende, y este
        // nodo seria un agujero en la federacion.
        let doc = paquete(&format!(
            r#"{{"type":"x-cosa-nueva","spec_version":"2.1","id":"x-cosa-nueva--{UUID_A}",
            "created":"2025-01-13T08:00:00.000Z","modified":"2025-01-13T08:00:00.000Z",
            "algo":"que no conocemos"}}"#
        ));
        let p = Paquete::validar(&doc).expect("valido");
        let o = p.objetos.values().next().expect("hay uno");
        assert_eq!(o.tipo, Tipo::Otro("x-cosa-nueva".into()));
        assert!(!o.tipo.conocido());
        assert_eq!(o.texto("algo"), Some("que no conocemos"));
    }

    #[test]
    fn la_ida_y_vuelta_no_pierde_nada() {
        let doc = format!(
            r#"{{"type":"bundle","id":"bundle--{UUID_A}","objects":[
            {{"type":"malware","spec_version":"2.1","id":"malware--{UUID_A}",
             "created":"2025-01-13T08:00:00.000Z","modified":"2025-01-13T08:00:00.000Z",
             "name":"LockBit","is_family":true,"malware_types":["ransomware"],
             "x_privado":{{"anidado":[1,2,3]}},"labels":["TLP:GREEN","PAP:GREEN"]}},
            {{"type":"relationship","spec_version":"2.1","id":"relationship--{UUID_B}",
             "created":"2025-01-13T08:00:00.000Z","modified":"2025-01-13T08:00:00.000Z",
             "relationship_type":"uses","source_ref":"malware--{UUID_A}",
             "target_ref":"attack-pattern--{UUID_B}"}}]}}"#
        );
        let uno = Paquete::validar(&doc).expect("valido");
        let dos = Paquete::validar(&uno.a_json()).expect("la vuelta tambien vale");
        assert_eq!(uno, dos, "la ida y vuelta perdio informacion");
        // Incluido lo anidado que este nodo no interpreta.
        let m = &dos.objetos[&format!("malware--{UUID_A}")];
        assert!(m.crudo.get("x_privado").is_some());
    }

    #[test]
    fn las_relaciones_declaran_sus_extremos_y_se_ve_lo_que_cuelga() {
        let doc = paquete(&format!(
            r#"{{"type":"relationship","spec_version":"2.1","id":"relationship--{UUID_A}",
            "created":"2025-01-13T08:00:00.000Z","modified":"2025-01-13T08:00:00.000Z",
            "relationship_type":"indicates","source_ref":"indicator--{UUID_B}",
            "target_ref":"malware--{UUID_B}"}}"#
        ));
        let p = Paquete::validar(&doc).expect("valido");
        let colgando = p.referencias_colgando();
        assert_eq!(colgando.len(), 2);
        assert!(colgando.contains(&format!("indicator--{UUID_B}").as_str()));
    }

    #[test]
    fn un_documento_demasiado_profundo_se_corta_antes_de_analizarlo() {
        // Cien mil llaves abiertas desbordan la pila al analizar, y entonces no
        // hay validacion que valga porque el proceso ya no esta.
        let hostil = format!(
            r#"{{"type":"bundle","id":"bundle--{UUID_A}","objects":[{}]}}"#,
            "[".repeat(5000)
        );
        assert!(matches!(
            Paquete::validar(&hostil),
            Err(Rechazo::Desmesurado {
                que: "profundidad de anidamiento",
                ..
            })
        ));
    }

    #[test]
    fn un_documento_enorme_se_rechaza_por_bytes() {
        let hostil = format!(r#"{{"type":"bundle","x":"{}"}}"#, "a".repeat(MAX_PAQUETE));
        assert!(matches!(
            Paquete::validar(&hostil),
            Err(Rechazo::Desmesurado {
                que: "bytes del paquete",
                ..
            })
        ));
    }

    #[test]
    fn un_texto_enorme_dentro_de_un_objeto_se_rechaza() {
        let doc = paquete(&format!(
            r#"{{"type":"indicator","spec_version":"2.1","id":"indicator--{UUID_A}",
            "created":"2025-01-13T08:00:00.000Z","modified":"2025-01-13T08:00:00.000Z",
            "pattern":"[x = 1]","pattern_type":"stix","valid_from":"2025-01-13T08:00:00.000Z",
            "description":"{}"}}"#,
            "a".repeat(MAX_TEXTO + 1)
        ));
        assert!(matches!(
            Paquete::validar(&doc),
            Err(Rechazo::Desmesurado {
                que: "longitud de un texto",
                ..
            })
        ));
    }

    #[test]
    fn entrada_hostil_arbitraria_no_provoca_panico() {
        // Barrido determinista: ninguna entrada puede tumbar el plano de control.
        let semillas = [
            "",
            "null",
            "[]",
            "{}",
            "{\"type\":\"bundle\"}",
            "{\"objects\":[]}",
            "{\"objects\":[null]}",
            "{\"objects\":[{}]}",
            "{\"objects\":[{\"type\":\"indicator\"}]}",
            "{\"type\":\"indicator\",\"id\":\"indicator--\"}",
            "{\"type\":\"indicator\",\"id\":\"indicator--xx\"}",
            "{\"type\":\"\",\"id\":\"--00000000-0000-0000-0000-000000000000\"}",
            "\u{feff}{}",
            "{\"type\":\"bundle\",\"objects\":{}}",
        ];
        for s in semillas {
            let _ = Paquete::validar(s);
        }
        // Y mutaciones sistematicas de un documento valido.
        let base = paquete(&indicador(
            &format!("indicator--{UUID_A}"),
            r#""TLP:GREEN""#,
        ));
        let bytes = base.as_bytes();
        for i in (0..bytes.len()).step_by(7) {
            let mut v = bytes.to_vec();
            v[i] = b'\xff';
            let _ = Paquete::validar(&String::from_utf8_lossy(&v));
            let mut v = bytes.to_vec();
            v[i] = b'{';
            let _ = Paquete::validar(&String::from_utf8_lossy(&v));
            let mut v = bytes.to_vec();
            v[i] = b'"';
            let _ = Paquete::validar(&String::from_utf8_lossy(&v));
        }
    }

    #[test]
    fn las_marcas_de_tiempo_se_leen_y_se_escriben_igual() {
        // Dos calendarios distintos en el mismo producto es la forma de que un
        // dia dos modulos ordenen el mismo suceso al reves.
        for s in [
            "2025-01-13T08:00:00.000Z",
            "1970-01-01T00:00:00.000Z",
            "2024-02-29T23:59:59.999Z",
            "2000-12-31T12:34:56.789Z",
        ] {
            let ns = rfc3339_a_ns(s).unwrap_or_else(|| panic!("{s} deberia valer"));
            assert_eq!(ns_a_rfc3339(ns), s, "ida y vuelta de {s}");
        }
        // Y lo mal escrito no cuela.
        for s in [
            "2025-01-13 08:00:00Z",
            "2025-13-01T08:00:00.000Z",
            "2025-01-13T25:00:00.000Z",
            "2025-01-13T08:00:00.000+01:00",
            "2025-01-13T08:00:00",
            "",
        ] {
            assert!(rfc3339_a_ns(s).is_none(), "{s} no deberia valer");
        }
    }

    #[test]
    fn dos_objetos_identicos_con_la_misma_version_se_rechazan() {
        let uno = indicador(&format!("indicator--{UUID_A}"), r#""TLP:GREEN""#);
        let doc = format!(r#"{{"type":"bundle","id":"bundle--{UUID_A}","objects":[{uno},{uno}]}}"#);
        assert!(matches!(
            Paquete::validar(&doc),
            Err(Rechazo::Duplicado { .. })
        ));
    }

    #[test]
    fn todo_rechazo_se_explica() {
        let casos = [
            Rechazo::NoEsJson {
                detalle: "x".into(),
            },
            Rechazo::Desmesurado {
                que: "objetos del paquete",
                visto: 1,
                tope: 0,
            },
            Rechazo::FaltaPropiedad {
                id: "a".into(),
                propiedad: "pattern",
            },
            Rechazo::IdMalformado { id: "a".into() },
            Rechazo::IdNoCuadraConTipo {
                id: "a".into(),
                tipo: "b".into(),
            },
            Rechazo::VersionInesperada {
                version: "2.0".into(),
            },
            Rechazo::TiempoMalformado {
                id: "a".into(),
                campo: "created",
            },
            Rechazo::TiempoImposible { id: "a".into() },
            Rechazo::PersonalizadaSinPrefijo {
                id: "a".into(),
                propiedad: "b".into(),
            },
            Rechazo::Duplicado { id: "a".into() },
        ];
        for c in &casos {
            assert!(c.texto().len() > 15, "{c:?} no se explica");
        }
    }
}
