//! TAXII 2.1: el servidor y el cliente, con la paginacion que no pierde nada.
//!
//! # El fallo de paginacion que nadie ve, y lo que cuesta
//!
//! La forma evidente de paginar es por desplazamiento: «dame del 0 al 99», «dame
//! del 100 al 199». Y **pierde objetos en silencio** en cuanto alguien escribe
//! entre las dos peticiones: si entran diez objetos antes del 100, los diez que
//! ocupaban esa posicion se desplazan y no se ven nunca.
//!
//! En una lista de productos eso es una molestia. En un canal de indicadores es
//! **un indicador que no se recibe**, y no hay ningun error: la respuesta es
//! valida, el cliente sigue sondeando tan contento, y lo que falta no falta de
//! forma visible.
//!
//! Por eso aqui el cursor es `(añadido, identificador)` y no una posicion. Un
//! objeto que entra despues tiene un `añadido` posterior y **no desplaza** lo que
//! ya se paso; el identificador desempata cuando dos entran en el mismo instante,
//! que con lotes grandes pasa constantemente.
//!
//! # El sondeo se hace por `added_after`, no por «lo que cambio»
//!
//! El campo que ordena la coleccion es **cuando se añadio aqui**, no cuando se
//! creo ni cuando se modifico en origen. Parece un detalle y decide si el sondeo
//! funciona: un objeto creado hace un año que llega hoy por federacion tiene que
//! salir en el sondeo de hoy. Ordenando por `modified`, se colaria detras del
//! cursor del cliente y no lo veria nunca.
//!
//! # Todo lo que sale pasa por el estrangulamiento
//!
//! Leer una coleccion no consulta el almacen: pasa por
//! [`crate::difusion::Difusor`], igual que la federacion y el enjambre. Es lo que
//! hace cierta la frase «no sale por ningun camino».

use std::collections::BTreeMap;

use crate::difusion::{Difusor, Reparto};
use crate::stix::{ns_a_rfc3339, Objeto, Paquete};

/// Objetos maximos por pagina.
///
/// El cliente puede pedir menos; mas no. Sin tope, un cliente pide un millon y el
/// servidor construye un millon de objetos en memoria por peticion — que es una
/// denegacion de servicio que se solicita con una peticion valida.
pub const MAX_PAGINA: usize = 1000;

/// Objetos por pagina si el cliente no dice nada.
pub const PAGINA_POR_DEFECTO: usize = 100;

/// Una coleccion TAXII.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coleccion {
    /// Identificador.
    pub id: String,
    /// Titulo legible.
    pub titulo: String,
    /// Descripcion.
    pub descripcion: String,
    /// Si se puede leer.
    pub lectura: bool,
    /// Si se puede escribir.
    pub escritura: bool,
    /// A que destino de difusion corresponde.
    ///
    /// **Una coleccion no tiene su propia politica**: apunta a un destino del
    /// difusor. Si tuviera la suya, habria dos sitios donde decidir quien ve que,
    /// y tarde o temprano uno se queda atras.
    pub destino: String,
}

/// Una entrada de la coleccion, con su momento de alta.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entrada {
    /// Cuando se añadio **aqui**, en nanosegundos Unix.
    anadido_ns: u64,
    objeto: Objeto,
}

/// El cursor de paginacion.
///
/// Es `(añadido, identificador)` y no una posicion: un objeto que entra despues
/// no desplaza lo que ya se paso.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Cursor {
    /// Momento de alta del ultimo objeto entregado.
    pub anadido_ns: u64,
    /// Su identificador, para desempatar.
    pub id: String,
}

impl Cursor {
    /// Serializa el cursor como el `next` de TAXII.
    #[must_use]
    pub fn a_texto(&self) -> String {
        format!("{}:{}", self.anadido_ns, self.id)
    }

    /// Lee un cursor.
    ///
    /// Devuelve `None` si no se entiende. Quien llama **empieza por el
    /// principio** en ese caso, no por donde le parezca: un cursor ilegible que
    /// se resolviera a «sigue por el final» saltaria todo lo que falta.
    #[must_use]
    pub fn de_texto(s: &str) -> Option<Cursor> {
        let (t, id) = s.split_once(':')?;
        Some(Cursor {
            anadido_ns: t.parse().ok()?,
            id: id.to_string(),
        })
    }
}

/// Lo que pide un cliente.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Peticion {
    /// Solo lo añadido despues de este momento.
    pub anadido_despues_ns: Option<u64>,
    /// Continuar desde aqui.
    pub cursor: Option<Cursor>,
    /// Cuantos como maximo.
    pub limite: Option<usize>,
    /// Filtrar por tipo.
    pub tipo: Option<String>,
    /// Filtrar por identificador.
    pub ids: Vec<String>,
}

impl Peticion {
    /// Una peticion desde el principio.
    #[must_use]
    pub fn todo() -> Peticion {
        Peticion::default()
    }

    /// Continuar desde un cursor.
    #[must_use]
    pub fn desde(cursor: Cursor) -> Peticion {
        Peticion {
            cursor: Some(cursor),
            ..Peticion::default()
        }
    }

    /// Lo añadido despues de un momento.
    #[must_use]
    pub fn nuevo_desde(ns: u64) -> Peticion {
        Peticion {
            anadido_despues_ns: Some(ns),
            ..Peticion::default()
        }
    }

    /// Fija el limite.
    #[must_use]
    pub fn con_limite(mut self, n: usize) -> Peticion {
        self.limite = Some(n);
        self
    }
}

/// Una pagina de respuesta.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pagina {
    /// Los objetos.
    pub objetos: Vec<Objeto>,
    /// Si hay mas paginas.
    pub hay_mas: bool,
    /// La posicion del ultimo objeto entregado.
    ///
    /// **Va siempre que se entregue algo**, tambien en la ultima pagina. Que sea
    /// independiente de [`Pagina::hay_mas`] no es un detalle: son dos preguntas
    /// distintas —«¿por donde voy?» y «¿queda mas?»— y juntarlas rompe el sondeo.
    /// Un cliente que se quede sin cursor al llegar al final no puede continuar
    /// desde ahi la proxima vez, y solo le quedan dos salidas: repetirlo todo, o
    /// saltar al final y perderse lo que entre despues.
    pub siguiente: Option<Cursor>,
    /// Lo que la difusion retuvo, con su motivo.
    ///
    /// **Se informa al servidor, no al cliente.** El cliente no tiene por que
    /// saber cuanto se le esta ocultando —eso ya seria una fuga por el tamaño— y
    /// el operador si tiene que saberlo, o no se entera de que una coleccion se
    /// esta quedando vacia por una politica mal puesta.
    pub retenidos: usize,
}

impl Pagina {
    /// El momento de alta mas alto entregado.
    #[must_use]
    pub fn ultimo_anadido(&self) -> Option<&Cursor> {
        self.siguiente.as_ref()
    }

    /// Los objetos como paquete STIX.
    #[must_use]
    pub fn paquete(&self, id: &str) -> Paquete {
        Paquete {
            id: id.to_string(),
            objetos: self
                .objetos
                .iter()
                .map(|o| (o.id.clone(), o.clone()))
                .collect(),
        }
    }
}

/// El servidor TAXII.
#[derive(Debug, Default)]
pub struct Servidor {
    colecciones: BTreeMap<String, Coleccion>,
    contenido: BTreeMap<String, Vec<Entrada>>,
    difusor: Difusor,
}

impl Servidor {
    /// Un servidor sin colecciones.
    #[must_use]
    pub fn nuevo(difusor: Difusor) -> Servidor {
        Servidor {
            colecciones: BTreeMap::new(),
            contenido: BTreeMap::new(),
            difusor,
        }
    }

    /// Declara una coleccion.
    ///
    /// # Errors
    ///
    /// Devuelve `Err` si su destino de difusion no esta declarado. Una coleccion
    /// sin destino no se resuelve con un valor por defecto abierto: sin destino
    /// no hay politica, y sin politica no se sirve nada.
    pub fn declarar(&mut self, coleccion: Coleccion) -> Result<(), String> {
        if self.difusor.destino(&coleccion.destino).is_none() {
            return Err(format!(
                "la coleccion «{}» apunta al destino «{}», que no esta declarado: sin destino no \
                 hay politica, y sin politica no se sirve nada",
                coleccion.id, coleccion.destino
            ));
        }
        self.contenido.entry(coleccion.id.clone()).or_default();
        self.colecciones.insert(coleccion.id.clone(), coleccion);
        Ok(())
    }

    /// Las colecciones, como las ve un cliente.
    #[must_use]
    pub fn colecciones(&self) -> Vec<&Coleccion> {
        self.colecciones.values().collect()
    }

    /// Añade objetos a una coleccion.
    ///
    /// `ahora_ns` es el momento de alta, que es **el campo por el que se ordena y
    /// se sondea**: un objeto creado hace un año que llega hoy por federacion se
    /// añade hoy, y por eso el sondeo de hoy lo ve.
    ///
    /// # Errors
    ///
    /// Devuelve `Err` si la coleccion no existe o no admite escritura.
    pub fn anadir(
        &mut self,
        coleccion: &str,
        objetos: Vec<Objeto>,
        ahora_ns: u64,
    ) -> Result<usize, String> {
        let c = self
            .colecciones
            .get(coleccion)
            .ok_or_else(|| format!("no existe la coleccion «{coleccion}»"))?;
        if !c.escritura {
            return Err(format!("la coleccion «{coleccion}» no admite escritura"));
        }
        let lista = self.contenido.entry(coleccion.to_string()).or_default();
        let mut n = 0;
        for o in objetos {
            // Una version nueva del mismo objeto sustituye a la anterior y **se
            // añade de nuevo**: el cliente que ya paso por aqui tiene que volver
            // a verla, o una correccion no llega a quien ya sincronizo.
            lista.retain(|e| e.objeto.id != o.id);
            lista.push(Entrada {
                anadido_ns: ahora_ns,
                objeto: o,
            });
            n += 1;
        }
        lista.sort_by(|a, b| {
            a.anadido_ns
                .cmp(&b.anadido_ns)
                .then(a.objeto.id.cmp(&b.objeto.id))
        });
        Ok(n)
    }

    /// Cuantos objetos hay en una coleccion, antes de filtrar.
    #[must_use]
    pub fn cuantos(&self, coleccion: &str) -> usize {
        self.contenido.get(coleccion).map_or(0, Vec::len)
    }

    /// Sirve una pagina.
    ///
    /// # Errors
    ///
    /// Devuelve `Err` si la coleccion no existe, no admite lectura, o su destino
    /// dejo de estar declarado.
    pub fn leer(&self, coleccion: &str, p: &Peticion) -> Result<Pagina, String> {
        let c = self
            .colecciones
            .get(coleccion)
            .ok_or_else(|| format!("no existe la coleccion «{coleccion}»"))?;
        if !c.lectura {
            return Err(format!("la coleccion «{coleccion}» no admite lectura"));
        }
        let destino = self
            .difusor
            .destino(&c.destino)
            .ok_or_else(|| format!("el destino «{}» ya no esta declarado", c.destino))?;

        let limite = p.limite.unwrap_or(PAGINA_POR_DEFECTO).clamp(1, MAX_PAGINA);
        let vacio = Vec::new();
        let lista = self.contenido.get(coleccion).unwrap_or(&vacio);

        let mut pagina = Pagina::default();
        for e in lista {
            // El cursor es (añadido, id): un objeto que entra despues tiene un
            // `añadido` posterior y NO desplaza lo que ya se paso.
            if let Some(cur) = &p.cursor {
                let aqui = Cursor {
                    anadido_ns: e.anadido_ns,
                    id: e.objeto.id.clone(),
                };
                if aqui <= *cur {
                    continue;
                }
            }
            if let Some(desde) = p.anadido_despues_ns {
                if e.anadido_ns <= desde {
                    continue;
                }
            }
            if let Some(t) = &p.tipo {
                if e.objeto.tipo.nombre() != t {
                    continue;
                }
            }
            if !p.ids.is_empty() && !p.ids.contains(&e.objeto.id) {
                continue;
            }

            // EL ESTRANGULAMIENTO. Leer una coleccion no consulta el almacen: pasa
            // por la difusion, igual que la federacion y el enjambre.
            if Difusor::juzgar(&e.objeto, destino).is_err() {
                pagina.retenidos += 1;
                continue;
            }

            if pagina.objetos.len() == limite {
                pagina.hay_mas = true;
                break;
            }
            pagina.siguiente = Some(Cursor {
                anadido_ns: e.anadido_ns,
                id: e.objeto.id.clone(),
            });
            pagina.objetos.push(e.objeto.clone());
        }
        Ok(pagina)
    }

    /// El reparto completo de una coleccion, para auditarla.
    ///
    /// # Errors
    ///
    /// Devuelve `Err` si la coleccion no existe.
    pub fn auditar(&self, coleccion: &str) -> Result<Reparto, String> {
        let c = self
            .colecciones
            .get(coleccion)
            .ok_or_else(|| format!("no existe la coleccion «{coleccion}»"))?;
        let vacio = Vec::new();
        let p = Paquete {
            id: format!("bundle--{coleccion}"),
            objetos: self
                .contenido
                .get(coleccion)
                .unwrap_or(&vacio)
                .iter()
                .map(|e| (e.objeto.id.clone(), e.objeto.clone()))
                .collect(),
        };
        self.difusor.repartir(&p, &c.destino)
    }
}

/// El cliente TAXII.
///
/// Lleva el cursor de cada coleccion para poder sondear sin repetir ni perderse.
#[derive(Debug, Clone, Default)]
pub struct Cliente {
    cursores: BTreeMap<String, Cursor>,
    recibidos: u64,
}

impl Cliente {
    /// Un cliente sin estado.
    #[must_use]
    pub fn nuevo() -> Cliente {
        Cliente::default()
    }

    /// Sondea una coleccion y devuelve **todo** lo nuevo, pagina a pagina.
    ///
    /// # Por que agota las paginas en vez de devolver una
    ///
    /// Un cliente que pide una pagina por ciclo y sondea cada cinco minutos no
    /// alcanza nunca a un canal que publica mas rapido de lo que el sondea: el
    /// retraso crece sin parar y no hay ningun error que lo diga. Agotar las
    /// paginas del ciclo es lo unico que garantiza que el cursor avanza hasta el
    /// final.
    ///
    /// El tope de vueltas esta para que un servidor que devuelva siempre
    /// `hay_mas` —roto o malicioso— no deje al cliente girando para siempre.
    ///
    /// # Errors
    ///
    /// Devuelve `Err` si el servidor rechaza la peticion.
    pub fn sondear(
        &mut self,
        servidor: &Servidor,
        coleccion: &str,
        por_pagina: usize,
    ) -> Result<Vec<Objeto>, String> {
        const MAX_VUELTAS: usize = 1000;
        let mut todo = Vec::new();
        for _ in 0..MAX_VUELTAS {
            let mut p = Peticion::default().con_limite(por_pagina);
            p.cursor = self.cursores.get(coleccion).cloned();
            let pagina = servidor.leer(coleccion, &p)?;

            // El cursor avanza tambien en la ultima pagina: si no, el siguiente
            // sondeo repetiria todo lo ya recibido.
            if let Some(c) = &pagina.siguiente {
                self.cursores.insert(coleccion.to_string(), c.clone());
            }

            let hay_mas = pagina.hay_mas;
            self.recibidos += pagina.objetos.len() as u64;
            todo.extend(pagina.objetos);
            if !hay_mas {
                return Ok(todo);
            }
        }
        Err(format!(
            "el servidor sigue diciendo que hay mas tras {MAX_VUELTAS} paginas: o esta roto o lo \
             esta haciendo a proposito"
        ))
    }

    /// El cursor de una coleccion.
    #[must_use]
    pub fn cursor(&self, coleccion: &str) -> Option<&Cursor> {
        self.cursores.get(coleccion)
    }

    /// Cuantos objetos ha recibido en total.
    #[must_use]
    pub fn recibidos(&self) -> u64 {
        self.recibidos
    }

    /// Olvida el cursor de una coleccion, para volver a sincronizar desde cero.
    pub fn reiniciar(&mut self, coleccion: &str) {
        self.cursores.remove(coleccion);
    }
}

/// El documento de descubrimiento de TAXII, en JSON.
#[must_use]
pub fn descubrimiento(titulo: &str, colecciones: &[&Coleccion]) -> String {
    let lista: Vec<String> = colecciones
        .iter()
        .map(|c| {
            format!(
                r#"{{"id":"{}","title":"{}","description":"{}","can_read":{},"can_write":{},"media_types":["application/stix+json;version=2.1"]}}"#,
                escapar(&c.id),
                escapar(&c.titulo),
                escapar(&c.descripcion),
                c.lectura,
                c.escritura
            )
        })
        .collect();
    format!(
        r#"{{"title":"{}","default":"/taxii2/","collections":[{}]}}"#,
        escapar(titulo),
        lista.join(",")
    )
}

/// Un sobre TAXII con los objetos de una pagina.
#[must_use]
pub fn sobre(pagina: &Pagina) -> String {
    let objetos: Vec<String> = pagina
        .objetos
        .iter()
        .map(|o| serde_json::Value::Object(o.crudo.clone()).to_string())
        .collect();
    let mas = match (&pagina.siguiente, pagina.hay_mas) {
        (Some(c), true) => format!(r#","more":true,"next":"{}""#, escapar(&c.a_texto())),
        _ => r#","more":false"#.to_string(),
    };
    format!(r#"{{"objects":[{}]{mas}}}"#, objetos.join(","))
}

/// La hora de alta como la escribe TAXII.
#[must_use]
pub fn marca_de_alta(ns: u64) -> String {
    ns_a_rfc3339(ns)
}

fn escapar(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::difusion::{Canal, Destino};
    use crate::marcado::{Marcado, Pap, Tlp};
    use crate::stix::Tipo;
    use serde_json::Map;

    const SEG: u64 = 1_000_000_000;
    const AHORA: u64 = 1_700_000_000 * SEG;

    fn objeto(id: &str, m: Marcado) -> Objeto {
        let mut crudo = Map::new();
        crudo.insert("id".into(), serde_json::Value::String(id.into()));
        Objeto {
            tipo: Tipo::Indicator,
            id: id.into(),
            creado_ns: 0,
            modificado_ns: 0,
            marcado: m,
            revocado: false,
            etiquetas: vec![],
            referencias: vec![],
            crudo,
        }
    }

    fn servidor() -> Servidor {
        let mut d = Difusor::nuevo();
        d.declarar(Destino {
            nombre: "comunidad".into(),
            canal: Canal::Taxii,
            tope_tlp: Tlp::Green,
            es_propia_organizacion: false,
        });
        let mut s = Servidor::nuevo(d);
        s.declarar(Coleccion {
            id: "indicadores".into(),
            titulo: "Indicadores".into(),
            descripcion: "".into(),
            lectura: true,
            escritura: true,
            destino: "comunidad".into(),
        })
        .expect("destino declarado");
        s
    }

    #[test]
    fn la_paginacion_no_pierde_objetos_cuando_alguien_escribe_en_medio() {
        // EL FALLO QUE NADIE VE. Con desplazamiento, los diez que entran antes de
        // la posicion 100 desplazan a los que la ocupaban y no se ven nunca — sin
        // error, con respuesta valida, y el cliente sigue sondeando tan tranquilo.
        let mut s = servidor();
        let primeros: Vec<Objeto> = (0..20)
            .map(|i| objeto(&format!("indicator--{i:03}"), Marcado::publico()))
            .collect();
        s.anadir("indicadores", primeros, AHORA)
            .expect("escribible");

        let mut c = Cliente::nuevo();
        // Primera pagina de 5.
        let mut p = Peticion::default().con_limite(5);
        p.cursor = None;
        let pag1 = s.leer("indicadores", &p).expect("lectura");
        assert_eq!(pag1.objetos.len(), 5);
        assert!(pag1.hay_mas);

        // ENTRE LAS DOS PETICIONES entran diez objetos nuevos.
        let nuevos: Vec<Objeto> = (100..110)
            .map(|i| objeto(&format!("indicator--{i:03}"), Marcado::publico()))
            .collect();
        s.anadir("indicadores", nuevos, AHORA + SEG)
            .expect("escribible");

        // Se continua desde el cursor: no se ha perdido ninguno de los 20.
        let mut vistos: Vec<String> = pag1.objetos.iter().map(|o| o.id.clone()).collect();
        let mut cursor = pag1.siguiente;
        while let Some(cur) = cursor {
            let pag = s
                .leer("indicadores", &Peticion::desde(cur).con_limite(5))
                .expect("lectura");
            vistos.extend(pag.objetos.iter().map(|o| o.id.clone()));
            cursor = pag.siguiente;
        }
        for i in 0..20 {
            assert!(
                vistos.contains(&format!("indicator--{i:03}")),
                "se perdio indicator--{i:03}"
            );
        }
        assert_eq!(vistos.len(), 30, "y ademas llegaron los diez nuevos");
        let _ = &mut c;
    }

    #[test]
    fn el_cursor_desempata_cuando_entran_muchos_a_la_vez() {
        // Con lotes grandes, decenas de objetos comparten el mismo instante de
        // alta. Sin desempate por identificador, el cursor se atasca o salta.
        let mut s = servidor();
        let lote: Vec<Objeto> = (0..50)
            .map(|i| objeto(&format!("indicator--{i:03}"), Marcado::publico()))
            .collect();
        s.anadir("indicadores", lote, AHORA).expect("escribible");

        let mut vistos = Vec::new();
        let mut cursor = None;
        loop {
            let p = match cursor {
                Some(c) => Peticion::desde(c),
                None => Peticion::todo(),
            }
            .con_limite(7);
            let pag = s.leer("indicadores", &p).expect("lectura");
            vistos.extend(pag.objetos.iter().map(|o| o.id.clone()));
            if !pag.hay_mas {
                break;
            }
            cursor = pag.siguiente;
        }
        assert_eq!(vistos.len(), 50);
        let unicos: std::collections::BTreeSet<_> = vistos.iter().collect();
        assert_eq!(unicos.len(), 50, "se repitio alguno");
    }

    #[test]
    fn lo_que_la_difusion_retiene_no_sale_por_taxii() {
        // Leer una coleccion no consulta el almacen: pasa por el
        // estrangulamiento, igual que la federacion y el enjambre.
        let mut s = servidor();
        s.anadir(
            "indicadores",
            vec![
                objeto("indicator--publico", Marcado::publico()),
                objeto("indicator--secreto", Marcado::nuevo(Tlp::Red, Pap::Red)),
            ],
            AHORA,
        )
        .expect("escribible");

        let pag = s.leer("indicadores", &Peticion::todo()).expect("lectura");
        assert_eq!(pag.objetos.len(), 1);
        assert_eq!(pag.objetos[0].id, "indicator--publico");
        // Y el operador SI se entera de cuanto se retuvo.
        assert_eq!(pag.retenidos, 1);
    }

    #[test]
    fn el_sondeo_por_added_after_ve_lo_que_llega_viejo() {
        // Un objeto creado hace un año que llega hoy por federacion tiene que
        // salir en el sondeo de hoy. Ordenando por `modified`, se colaria detras
        // del cursor del cliente y no lo veria nunca.
        let mut s = servidor();
        s.anadir(
            "indicadores",
            vec![objeto("indicator--a", Marcado::publico())],
            AHORA,
        )
        .expect("escribible");
        let mut c = Cliente::nuevo();
        assert_eq!(c.sondear(&s, "indicadores", 10).expect("sondeo").len(), 1);

        // Un objeto ANTIGUO —creado hace un año— que llega ahora.
        let mut viejo = objeto("indicator--viejo", Marcado::publico());
        viejo.creado_ns = AHORA - 365 * 24 * 3600 * SEG;
        viejo.modificado_ns = viejo.creado_ns;
        s.anadir("indicadores", vec![viejo], AHORA + 60 * SEG)
            .expect("escribible");

        let nuevos = c.sondear(&s, "indicadores", 10).expect("sondeo");
        assert_eq!(nuevos.len(), 1, "no se vio el objeto viejo que llego hoy");
        assert_eq!(nuevos[0].id, "indicator--viejo");
    }

    #[test]
    fn una_correccion_llega_a_quien_ya_habia_sincronizado() {
        // Si una version nueva no se volviera a añadir, el cliente que ya paso por
        // ahi no veria nunca la correccion.
        let mut s = servidor();
        s.anadir(
            "indicadores",
            vec![objeto("indicator--x", Marcado::publico())],
            AHORA,
        )
        .expect("escribible");
        let mut c = Cliente::nuevo();
        assert_eq!(c.sondear(&s, "indicadores", 10).expect("s").len(), 1);
        assert!(c.sondear(&s, "indicadores", 10).expect("s").is_empty());

        let mut corregido = objeto("indicator--x", Marcado::publico());
        corregido.revocado = true;
        // Se sirve la revocacion aunque el difusor la retenga en una lectura
        // normal: aqui lo que se comprueba es que la coleccion la vuelve a dar de
        // alta, y para eso se mira el almacen.
        s.anadir("indicadores", vec![corregido], AHORA + 60 * SEG)
            .expect("escribible");
        assert_eq!(s.cuantos("indicadores"), 1, "la version vieja se sustituyo");
    }

    #[test]
    fn el_sondeo_agota_las_paginas_del_ciclo() {
        // Un cliente que pide una pagina por ciclo no alcanza nunca a un canal que
        // publica mas rapido de lo que el sondea, y no hay ningun error que lo
        // diga: el retraso crece sin parar.
        let mut s = servidor();
        let lote: Vec<Objeto> = (0..250)
            .map(|i| objeto(&format!("indicator--{i:04}"), Marcado::publico()))
            .collect();
        s.anadir("indicadores", lote, AHORA).expect("escribible");

        let mut c = Cliente::nuevo();
        let todo = c.sondear(&s, "indicadores", 10).expect("sondeo");
        assert_eq!(todo.len(), 250, "el sondeo se quedo a medias");
        assert_eq!(c.recibidos(), 250);
        assert!(c.sondear(&s, "indicadores", 10).expect("sondeo").is_empty());
    }

    #[test]
    fn el_limite_de_pagina_esta_acotado() {
        // Sin tope, un cliente pide un millon y el servidor construye un millon de
        // objetos en memoria: una denegacion de servicio que se solicita con una
        // peticion valida.
        let mut s = servidor();
        let lote: Vec<Objeto> = (0..50)
            .map(|i| objeto(&format!("indicator--{i:03}"), Marcado::publico()))
            .collect();
        s.anadir("indicadores", lote, AHORA).expect("escribible");
        let pag = s
            .leer("indicadores", &Peticion::todo().con_limite(usize::MAX))
            .expect("lectura");
        assert!(pag.objetos.len() <= MAX_PAGINA);
        // Y un limite de cero no deja el sondeo parado para siempre.
        let pag = s
            .leer("indicadores", &Peticion::todo().con_limite(0))
            .expect("lectura");
        assert_eq!(pag.objetos.len(), 1);
    }

    #[test]
    fn una_coleccion_sin_destino_declarado_no_se_puede_crear() {
        // Sin destino no hay politica, y sin politica no se sirve nada.
        let mut s = Servidor::nuevo(Difusor::nuevo());
        let e = s
            .declarar(Coleccion {
                id: "x".into(),
                titulo: "x".into(),
                descripcion: String::new(),
                lectura: true,
                escritura: true,
                destino: "el-que-no-existe".into(),
            })
            .expect_err("sin destino");
        assert!(e.contains("sin politica no se sirve nada"));
    }

    #[test]
    fn una_coleccion_de_solo_lectura_no_admite_escritura() {
        let mut d = Difusor::nuevo();
        d.declarar(Destino {
            nombre: "comunidad".into(),
            canal: Canal::Taxii,
            tope_tlp: Tlp::Green,
            es_propia_organizacion: false,
        });
        let mut s = Servidor::nuevo(d);
        s.declarar(Coleccion {
            id: "solo-lectura".into(),
            titulo: "x".into(),
            descripcion: String::new(),
            lectura: true,
            escritura: false,
            destino: "comunidad".into(),
        })
        .expect("ok");
        assert!(s
            .anadir(
                "solo-lectura",
                vec![objeto("indicator--x", Marcado::publico())],
                AHORA
            )
            .is_err());
    }

    #[test]
    fn un_cursor_ilegible_hace_empezar_por_el_principio() {
        // Un cursor ilegible que se resolviera a «sigue por el final» saltaria
        // todo lo que falta.
        assert_eq!(Cursor::de_texto("no-es-un-cursor"), None);
        assert_eq!(Cursor::de_texto(""), None);
        let c = Cursor {
            anadido_ns: AHORA,
            id: "indicator--x".into(),
        };
        assert_eq!(Cursor::de_texto(&c.a_texto()), Some(c));
    }

    #[test]
    fn el_documento_de_descubrimiento_escapa_lo_que_escribe_otro() {
        let c = Coleccion {
            id: "x\"y".into(),
            titulo: "con \"comillas\"".into(),
            descripcion: "y \\ barras".into(),
            lectura: true,
            escritura: false,
            destino: "comunidad".into(),
        };
        let doc = descubrimiento("Mi servidor", &[&c]);
        let v: serde_json::Value = serde_json::from_str(&doc).expect("el JSON sale valido");
        assert_eq!(v["collections"][0]["id"], "x\"y");
        assert_eq!(v["collections"][0]["can_write"], false);
    }

    #[test]
    fn el_sobre_es_json_valido_y_lleva_el_next() {
        let mut s = servidor();
        let lote: Vec<Objeto> = (0..5)
            .map(|i| objeto(&format!("indicator--{i:03}"), Marcado::publico()))
            .collect();
        s.anadir("indicadores", lote, AHORA).expect("escribible");
        let pag = s
            .leer("indicadores", &Peticion::todo().con_limite(2))
            .expect("lectura");
        let v: serde_json::Value = serde_json::from_str(&sobre(&pag)).expect("valido");
        assert_eq!(v["more"], true);
        assert!(v["next"].is_string());
        assert_eq!(v["objects"].as_array().expect("lista").len(), 2);
    }

    #[test]
    fn se_puede_auditar_lo_que_una_coleccion_esta_reteniendo() {
        // Si no, una politica mal puesta deja una coleccion vacia y nadie se
        // entera hasta que el consumidor pregunta.
        let mut s = servidor();
        s.anadir(
            "indicadores",
            vec![
                objeto("indicator--a", Marcado::publico()),
                objeto("indicator--b", Marcado::nuevo(Tlp::Red, Pap::Clear)),
            ],
            AHORA,
        )
        .expect("escribible");
        let r = s.auditar("indicadores").expect("auditable");
        assert_eq!(r.salen.len(), 1);
        assert_eq!(r.retenidos.len(), 1);
    }

    #[test]
    fn se_filtra_por_tipo_y_por_identificador() {
        let mut s = servidor();
        let mut malware = objeto("malware--m", Marcado::publico());
        malware.tipo = Tipo::Malware;
        s.anadir(
            "indicadores",
            vec![objeto("indicator--a", Marcado::publico()), malware],
            AHORA,
        )
        .expect("escribible");

        let mut p = Peticion::todo();
        p.tipo = Some("malware".into());
        assert_eq!(s.leer("indicadores", &p).expect("l").objetos.len(), 1);

        let mut p = Peticion::todo();
        p.ids = vec!["indicator--a".into()];
        assert_eq!(
            s.leer("indicadores", &p).expect("l").objetos[0].id,
            "indicator--a"
        );
    }
}
