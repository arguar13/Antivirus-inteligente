//! El camino del ataque, como UNA cadena consultable.
//!
//! # Lo que esto hace posible, y no lo era
//!
//! Un ataque real atraviesa planos: llega un paquete, se extrae un fichero, lo
//! ejecuta un proceso, que actua como una cuenta, que toca otra maquina. Con nueve
//! subsistemas y nueve nociones de entidad, eso son **nueve sucesos sin relacion**
//! y el analista hace de pegamento a mano, de memoria, a las tres de la mañana.
//!
//! Con un identificador unico recorriendo la cadena, la pregunta «¿de donde salio
//! esto?» tiene respuesta, y es la misma respuesta la conteste quien la conteste.
//!
//! # Por que el recorrido esta acotado, y no es prudencia
//!
//! El grafo lo llena **lo que hace el atacante**. Un proceso que lanza diez mil
//! hijos, o una cadena de cien mil ficheros escritos, no es una hipotesis: es un
//! borrador de discos haciendo su trabajo. Un recorrido sin tope convierte esa
//! actividad en una parada del plano de control justo cuando mas falta hace.
//!
//! Y los ciclos existen de verdad: A escribe B, B se ejecuta y escribe A. Sin
//! deteccion de ciclos, el recorrido no termina.
//!
//! Por eso [`Linaje::recorrer`] lleva tope de nodos, tope de profundidad y
//! conjunto de visitados, y **dice si se quedo corto** en vez de devolver un
//! resultado parcial que parece completo. Un camino truncado sin avisar es peor
//! que no tenerlo: se lee como «hasta aqui llego el ataque».

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::entidad::{Clase, Eid};

/// Nodos maximos que devuelve un recorrido.
///
/// Cinco mil. Lo llena el atacante: un proceso que lanza diez mil hijos no es una
/// hipotesis, es un borrador de discos trabajando. Sin tope, esa actividad para el
/// plano de control justo cuando mas falta hace.
pub const MAX_NODOS: usize = 5_000;

/// Profundidad maxima de un recorrido.
///
/// Veinte saltos. Una cadena de ataque real —paquete, fichero, proceso, cuenta,
/// maquina, respuesta— tiene media docena; veinte deja margen de sobra y corta la
/// exploracion de un grafo que alguien inflo a proposito.
pub const MAX_PROFUNDIDAD: usize = 20;

/// Aristas maximas por nodo.
///
/// Acota el otro eje: un solo proceso con cien mil ficheros escritos.
pub const MAX_ARISTAS_POR_NODO: usize = 1_000;

/// Que relacion hay entre dos entidades.
///
/// Las relaciones son **dirigidas y con sentido**: `A ejecuto B` no es `B ejecuto
/// A`, y el recorrido hacia atras —«¿de donde salio esto?»— es distinto del
/// recorrido hacia delante —«¿hasta donde llego?»—. Un grafo sin direccion
/// contesta mal las dos.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Relacion {
    /// Un proceso lanzo a otro.
    Lanzo,
    /// Un proceso ejecuto un contenido.
    Ejecuto,
    /// Un proceso escribio en una ubicacion.
    Escribio,
    /// Un proceso leyo una ubicacion.
    Leyo,
    /// Una ubicacion tiene este contenido.
    Contiene,
    /// Un proceso abrio un flujo.
    Abrio,
    /// De un flujo se extrajo un contenido.
    ///
    /// Es la arista que une el plano de red con el de fichero, y la que no existia
    /// antes de esta fase.
    Extrajo,
    /// Un proceso actuo con las credenciales de una cuenta.
    ActuoComo,
    /// Una cuenta se autentico contra una maquina.
    SeAutentico,
    /// Una entidad vive en una maquina.
    ResideEn,
    /// Un contenido se detono y produjo un artefacto.
    SeDetono,
    /// Una regla señalo a una entidad.
    Senalo,
    /// Sobre una entidad se ejecuto una contencion.
    SeContuvo,
}

impl Relacion {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Relacion::Lanzo => "lanzo",
            Relacion::Ejecuto => "ejecuto",
            Relacion::Escribio => "escribio",
            Relacion::Leyo => "leyo",
            Relacion::Contiene => "contiene",
            Relacion::Abrio => "abrio",
            Relacion::Extrajo => "extrajo",
            Relacion::ActuoComo => "actuo-como",
            Relacion::SeAutentico => "se-autentico",
            Relacion::ResideEn => "reside-en",
            Relacion::SeDetono => "se-detono",
            Relacion::Senalo => "senalo",
            Relacion::SeContuvo => "se-contuvo",
        }
    }

    /// Si esta relacion **propaga la causa**: lo que le pasa al origen explica al
    /// destino.
    ///
    /// Se usa para el recorrido de causa. `ResideEn` no propaga: que dos ficheros
    /// esten en la misma maquina no relaciona lo que hacen, y si propagara, el
    /// recorrido de cualquier cosa devolveria la maquina entera.
    #[must_use]
    pub fn propaga_causa(self) -> bool {
        !matches!(self, Relacion::ResideEn | Relacion::Senalo)
    }

    /// Todas las relaciones.
    #[must_use]
    pub fn todas() -> &'static [Relacion] {
        &[
            Relacion::Lanzo,
            Relacion::Ejecuto,
            Relacion::Escribio,
            Relacion::Leyo,
            Relacion::Contiene,
            Relacion::Abrio,
            Relacion::Extrajo,
            Relacion::ActuoComo,
            Relacion::SeAutentico,
            Relacion::ResideEn,
            Relacion::SeDetono,
            Relacion::Senalo,
            Relacion::SeContuvo,
        ]
    }
}

/// Una arista del grafo.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Arista {
    /// De donde sale.
    pub origen: Eid,
    /// A donde va.
    pub destino: Eid,
    /// Que relacion.
    pub relacion: Relacion,
    /// Cuando se observo, en nanosegundos Unix.
    pub cuando_ns: u64,
    /// Que subsistema lo observo.
    ///
    /// Va en la arista y no aparte porque cuando un camino resulta ser falso, lo
    /// primero que hay que saber es **quien lo dibujo**.
    pub observador: String,
}

/// Un paso del camino recorrido.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paso {
    /// La entidad a la que se llego.
    pub entidad: Eid,
    /// A que distancia del origen.
    pub profundidad: usize,
    /// Por que arista se llego. `None` para el origen.
    pub por: Option<Arista>,
}

/// El resultado de recorrer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Camino {
    /// Los pasos, en orden de descubrimiento.
    pub pasos: Vec<Paso>,
    /// Si el recorrido se quedo corto por algun tope.
    ///
    /// # Por que esto no puede faltar
    ///
    /// Un camino truncado **sin avisar** se lee como «hasta aqui llego el ataque»,
    /// y esa lectura cierra incidentes que siguen abiertos. Si se corto, se dice, y
    /// se dice por que.
    pub truncado: Option<Truncado>,
}

impl Camino {
    /// Las entidades alcanzadas.
    #[must_use]
    pub fn entidades(&self) -> Vec<&Eid> {
        self.pasos.iter().map(|p| &p.entidad).collect()
    }

    /// Cuantas entidades de cada clase se alcanzaron.
    #[must_use]
    pub fn por_clase(&self) -> BTreeMap<&'static str, usize> {
        let mut m = BTreeMap::new();
        for p in &self.pasos {
            *m.entry(p.entidad.clase().prefijo()).or_insert(0) += 1;
        }
        m
    }

    /// Si el camino atraviesa mas de un plano de observacion.
    ///
    /// Es la pregunta que justifica el modulo: un camino que se queda en un solo
    /// tipo de entidad no es una cadena de ataque, es una lista.
    #[must_use]
    pub fn cruza_planos(&self) -> bool {
        self.pasos
            .iter()
            .map(|p| p.entidad.clase())
            .collect::<BTreeSet<Clase>>()
            .len()
            > 1
    }

    /// Resumen legible.
    #[must_use]
    pub fn resumen(&self) -> String {
        let clases: Vec<String> = self
            .por_clase()
            .iter()
            .map(|(k, v)| format!("{k}×{v}"))
            .collect();
        let aviso = match &self.truncado {
            Some(t) => format!(" — SE CORTO: {}", t.texto()),
            None => String::new(),
        };
        format!(
            "{} entidad(es) en {} clase(s) [{}]{aviso}",
            self.pasos.len(),
            self.por_clase().len(),
            clases.join(", ")
        )
    }
}

/// Por que se corto un recorrido.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Truncado {
    /// Se alcanzo el tope de nodos.
    PorNodos {
        /// El tope.
        tope: usize,
    },
    /// Se alcanzo el tope de profundidad.
    PorProfundidad {
        /// El tope.
        tope: usize,
    },
    /// Algun nodo tenia mas aristas de las que se recorren.
    PorGrado {
        /// El tope.
        tope: usize,
    },
}

impl Truncado {
    /// Texto para el informe.
    #[must_use]
    pub fn texto(self) -> String {
        match self {
            Truncado::PorNodos { tope } => format!(
                "se alcanzo el tope de {tope} entidades. El grafo lo llena el atacante: un proceso \
                 que lanza diez mil hijos es un borrador de discos trabajando, no una hipotesis"
            ),
            Truncado::PorProfundidad { tope } => format!(
                "se alcanzo el tope de {tope} saltos; una cadena de ataque real tiene media docena"
            ),
            Truncado::PorGrado { tope } => {
                format!("algun nodo tenia mas de {tope} aristas y no se recorrieron todas")
            }
        }
    }
}

/// El grafo de linaje.
///
/// Guarda las aristas en los dos sentidos, porque las dos preguntas que importan
/// van en direcciones contrarias: «¿de donde salio esto?» y «¿hasta donde llego?».
#[derive(Debug, Clone, Default)]
pub struct Linaje {
    salientes: BTreeMap<Eid, Vec<Arista>>,
    entrantes: BTreeMap<Eid, Vec<Arista>>,
    total: usize,
}

impl Linaje {
    /// Un grafo vacio.
    #[must_use]
    pub fn nuevo() -> Linaje {
        Linaje::default()
    }

    /// Añade una arista.
    ///
    /// Las repetidas —la misma relacion entre los mismos extremos en el mismo
    /// instante— se descartan: dos subsistemas que observan el mismo hecho no
    /// deben duplicarlo, o el grado de un nodo crece con el numero de
    /// observadores en vez de con lo que paso.
    pub fn anadir(&mut self, arista: Arista) {
        let ya = self.salientes.get(&arista.origen).is_some_and(|v| {
            v.iter().any(|a| {
                a.destino == arista.destino
                    && a.relacion == arista.relacion
                    && a.cuando_ns == arista.cuando_ns
            })
        });
        if ya {
            return;
        }
        self.salientes
            .entry(arista.origen.clone())
            .or_default()
            .push(arista.clone());
        self.entrantes
            .entry(arista.destino.clone())
            .or_default()
            .push(arista);
        self.total += 1;
    }

    /// Cuantas aristas hay.
    #[must_use]
    pub fn aristas(&self) -> usize {
        self.total
    }

    /// Cuantas entidades distintas aparecen.
    #[must_use]
    pub fn entidades(&self) -> usize {
        self.salientes
            .keys()
            .chain(self.entrantes.keys())
            .collect::<BTreeSet<_>>()
            .len()
    }

    /// Lo que sale de una entidad.
    #[must_use]
    pub fn desde(&self, e: &Eid) -> &[Arista] {
        self.salientes.get(e).map_or(&[], Vec::as_slice)
    }

    /// Lo que llega a una entidad.
    #[must_use]
    pub fn hacia(&self, e: &Eid) -> &[Arista] {
        self.entrantes.get(e).map_or(&[], Vec::as_slice)
    }

    /// Recorre hacia delante: **hasta donde llego**.
    #[must_use]
    pub fn adelante(&self, origen: &Eid) -> Camino {
        self.recorrer(origen, true, false)
    }

    /// Recorre hacia atras: **de donde salio**.
    #[must_use]
    pub fn atras(&self, origen: &Eid) -> Camino {
        self.recorrer(origen, false, false)
    }

    /// Recorre hacia atras siguiendo solo lo que **explica la causa**.
    ///
    /// Es lo que contesta «¿de donde salio esto?» sin arrastrar la maquina entera:
    /// `ResideEn` no propaga causa, porque que dos ficheros esten en la misma
    /// maquina no relaciona lo que hacen.
    #[must_use]
    pub fn causa(&self, origen: &Eid) -> Camino {
        self.recorrer(origen, false, true)
    }

    /// El recorrido, acotado y con deteccion de ciclos.
    fn recorrer(&self, origen: &Eid, adelante: bool, solo_causa: bool) -> Camino {
        let mut pasos = Vec::new();
        let mut visitados: BTreeSet<Eid> = BTreeSet::new();
        let mut cola: VecDeque<(Eid, usize, Option<Arista>)> = VecDeque::new();
        let mut truncado = None;

        cola.push_back((origen.clone(), 0, None));
        visitados.insert(origen.clone());

        while let Some((actual, profundidad, por)) = cola.pop_front() {
            pasos.push(Paso {
                entidad: actual.clone(),
                profundidad,
                por,
            });
            if pasos.len() >= MAX_NODOS {
                truncado = Some(Truncado::PorNodos { tope: MAX_NODOS });
                break;
            }
            if profundidad >= MAX_PROFUNDIDAD {
                truncado.get_or_insert(Truncado::PorProfundidad {
                    tope: MAX_PROFUNDIDAD,
                });
                continue;
            }

            let vecinas = if adelante {
                self.desde(&actual)
            } else {
                self.hacia(&actual)
            };
            if vecinas.len() > MAX_ARISTAS_POR_NODO {
                truncado.get_or_insert(Truncado::PorGrado {
                    tope: MAX_ARISTAS_POR_NODO,
                });
            }
            for a in vecinas.iter().take(MAX_ARISTAS_POR_NODO) {
                if solo_causa && !a.relacion.propaga_causa() {
                    continue;
                }
                let siguiente = if adelante { &a.destino } else { &a.origen };
                // La deteccion de ciclos NO es prudencia: A escribe B, B se
                // ejecuta y escribe A es una cadena que ocurre de verdad.
                if visitados.insert(siguiente.clone()) {
                    cola.push_back((siguiente.clone(), profundidad + 1, Some(a.clone())));
                }
            }
        }

        // Orden estable: dos recorridos sobre el mismo grafo tienen que dar
        // exactamente lo mismo, o el informe no se puede comparar.
        pasos.sort_by(|a, b| {
            a.profundidad
                .cmp(&b.profundidad)
                .then(a.entidad.texto().cmp(&b.entidad.texto()))
        });
        Camino { pasos, truncado }
    }

    /// El camino mas corto entre dos entidades, si lo hay.
    ///
    /// Contesta la pregunta que un informe necesita: «¿como llego esto de aqui a
    /// alli?». Devuelve las aristas en orden, no solo los nodos — porque «el
    /// proceso toco el fichero» y «el proceso lo ejecuto» son cosas distintas y el
    /// informe tiene que decir cual.
    #[must_use]
    pub fn camino_entre(&self, desde: &Eid, hasta: &Eid) -> Option<Vec<Arista>> {
        let mut previo: BTreeMap<Eid, Arista> = BTreeMap::new();
        let mut visitados: BTreeSet<Eid> = BTreeSet::new();
        let mut cola: VecDeque<(Eid, usize)> = VecDeque::new();
        cola.push_back((desde.clone(), 0));
        visitados.insert(desde.clone());

        while let Some((actual, prof)) = cola.pop_front() {
            if &actual == hasta {
                let mut ruta = Vec::new();
                let mut cursor = hasta.clone();
                while let Some(a) = previo.get(&cursor) {
                    ruta.push(a.clone());
                    cursor = a.origen.clone();
                }
                ruta.reverse();
                return Some(ruta);
            }
            if prof >= MAX_PROFUNDIDAD || visitados.len() >= MAX_NODOS {
                continue;
            }
            for a in self.desde(&actual).iter().take(MAX_ARISTAS_POR_NODO) {
                if visitados.insert(a.destino.clone()) {
                    previo.insert(a.destino.clone(), a.clone());
                    cola.push_back((a.destino.clone(), prof + 1));
                }
            }
        }
        None
    }

    /// Qué subsistemas dibujaron el grafo.
    ///
    /// Cuando un camino resulta ser falso, lo primero que hay que saber es quien lo
    /// dibujo.
    #[must_use]
    pub fn observadores(&self) -> BTreeMap<String, usize> {
        let mut m = BTreeMap::new();
        for v in self.salientes.values() {
            for a in v {
                *m.entry(a.observador.clone()).or_insert(0) += 1;
            }
        }
        m
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::entidad;

    const SEG: u64 = 1_000_000_000;
    const AHORA: u64 = 1_700_000_000 * SEG;

    fn arista(o: &Eid, d: &Eid, r: Relacion, quien: &str) -> Arista {
        Arista {
            origen: o.clone(),
            destino: d.clone(),
            relacion: r,
            cuando_ns: AHORA,
            observador: quien.to_string(),
        }
    }

    /// La cadena completa de un ataque real, de la red a la respuesta.
    fn cadena() -> (Linaje, Eid, Eid) {
        let maq = entidad::maquina("m-1");
        let flujo = entidad::flujo(&maq, ("10.0.0.5", 51234), ("93.184.216.34", 443), 6, AHORA);
        let cont = entidad::contenido("7f1e3c9b");
        let ubic = entidad::ubicacion(&maq, "C:\\Users\\ana\\Downloads\\factura.exe");
        let proc = entidad::proceso(&maq, 1, 4242, AHORA);
        let cta = entidad::cuenta("S-1-5-21-AAA-1104");
        let arte = entidad::artefacto("7f1e3c9b", "red=simulada");

        let mut l = Linaje::nuevo();
        l.anadir(arista(&flujo, &cont, Relacion::Extrajo, "wire"));
        l.anadir(arista(&cont, &ubic, Relacion::Contiene, "fim"));
        l.anadir(arista(&proc, &cont, Relacion::Ejecuto, "conductual"));
        l.anadir(arista(&proc, &cta, Relacion::ActuoComo, "itdr"));
        l.anadir(arista(&cont, &arte, Relacion::SeDetono, "detonate"));
        l.anadir(arista(&proc, &maq, Relacion::ResideEn, "agente"));
        (l, flujo, arte)
    }

    #[test]
    fn la_cadena_atraviesa_red_fichero_proceso_identidad_y_respuesta() {
        // La propiedad que justifica el modulo: con nueve nociones de entidad esto
        // serian nueve sucesos sin relacion, y el analista haria de pegamento a
        // mano, de memoria, a las tres de la mañana.
        let (l, flujo, _) = cadena();
        let c = l.adelante(&flujo);
        assert!(c.cruza_planos());
        assert!(c.por_clase().len() >= 3, "{}", c.resumen());
        assert!(c.truncado.is_none());
    }

    #[test]
    fn de_donde_salio_esto_tiene_respuesta() {
        // Partiendo del artefacto detonado se llega hasta el flujo de red del que
        // se extrajo el fichero. Es la pregunta que un analista hace primero.
        let (l, flujo, arte) = cadena();
        let c = l.atras(&arte);
        assert!(
            c.entidades().iter().any(|e| **e == flujo),
            "no se llego al flujo de red: {}",
            c.resumen()
        );
    }

    #[test]
    fn el_camino_entre_dos_entidades_dice_por_que_aristas() {
        // «El proceso toco el fichero» y «el proceso lo ejecuto» son cosas
        // distintas, y el informe tiene que decir cual.
        let (l, flujo, arte) = cadena();
        let ruta = l.camino_entre(&flujo, &arte).expect("hay camino");
        let nombres: Vec<&str> = ruta.iter().map(|a| a.relacion.nombre()).collect();
        assert_eq!(nombres, vec!["extrajo", "se-detono"]);
    }

    #[test]
    fn residir_en_la_misma_maquina_no_explica_nada() {
        // Si `ResideEn` propagara causa, el recorrido de cualquier cosa devolveria
        // la maquina entera — y entonces el linaje no distingue.
        let maq = entidad::maquina("m-1");
        let a = entidad::proceso(&maq, 1, 1, AHORA);
        let b = entidad::proceso(&maq, 1, 2, AHORA);
        let mut l = Linaje::nuevo();
        l.anadir(arista(&a, &maq, Relacion::ResideEn, "agente"));
        l.anadir(arista(&b, &maq, Relacion::ResideEn, "agente"));

        // Hacia atras sin filtro, desde la maquina se llega a los dos.
        assert_eq!(l.atras(&maq).pasos.len(), 3);
        // Siguiendo solo la causa, no.
        assert_eq!(l.causa(&maq).pasos.len(), 1);
        assert!(!Relacion::ResideEn.propaga_causa());
    }

    #[test]
    fn un_ciclo_no_deja_el_recorrido_dando_vueltas() {
        // A escribe B, B se ejecuta y escribe A. Es una cadena que ocurre de
        // verdad, no un caso de laboratorio.
        let maq = entidad::maquina("m-1");
        let a = entidad::contenido("aaa");
        let b = entidad::contenido("bbb");
        let p = entidad::proceso(&maq, 1, 1, AHORA);
        let mut l = Linaje::nuevo();
        l.anadir(arista(&a, &p, Relacion::Ejecuto, "x"));
        l.anadir(arista(&p, &b, Relacion::Escribio, "x"));
        l.anadir(arista(&b, &p, Relacion::Ejecuto, "x"));
        l.anadir(arista(&p, &a, Relacion::Escribio, "x"));

        let c = l.adelante(&a);
        assert_eq!(c.pasos.len(), 3, "se repitio algun nodo");
        assert!(c.truncado.is_none());
    }

    #[test]
    fn un_grafo_inflado_se_corta_y_se_dice() {
        // Un camino truncado sin avisar se lee como «hasta aqui llego el ataque»,
        // y esa lectura cierra incidentes que siguen abiertos.
        let maq = entidad::maquina("m-1");
        let raiz = entidad::proceso(&maq, 1, 1, AHORA);
        let mut l = Linaje::nuevo();
        for i in 0..(MAX_NODOS + 500) {
            let hijo = entidad::proceso(&maq, 1, 2 + u32::try_from(i).unwrap_or(0), AHORA);
            l.anadir(arista(&raiz, &hijo, Relacion::Lanzo, "conductual"));
        }
        let c = l.adelante(&raiz);
        assert!(c.pasos.len() <= MAX_NODOS);
        assert!(c.truncado.is_some(), "se corto en silencio");
        assert!(c.resumen().contains("SE CORTO"));
        let t = c.truncado.expect("hay motivo");
        assert!(t.texto().len() > 30);
    }

    #[test]
    fn una_cadena_muy_larga_se_corta_por_profundidad() {
        let maq = entidad::maquina("m-1");
        let mut l = Linaje::nuevo();
        let mut anterior = entidad::proceso(&maq, 1, 0, AHORA);
        let raiz = anterior.clone();
        for i in 1..(MAX_PROFUNDIDAD + 10) {
            let siguiente = entidad::proceso(&maq, 1, u32::try_from(i).unwrap_or(0), AHORA);
            l.anadir(arista(&anterior, &siguiente, Relacion::Lanzo, "conductual"));
            anterior = siguiente;
        }
        let c = l.adelante(&raiz);
        assert!(matches!(c.truncado, Some(Truncado::PorProfundidad { .. })));
        assert!(c.pasos.iter().all(|p| p.profundidad <= MAX_PROFUNDIDAD));
    }

    #[test]
    fn dos_observadores_del_mismo_hecho_no_lo_duplican() {
        // Si no, el grado de un nodo crece con el numero de observadores en vez de
        // con lo que paso — y el tope de aristas se agota por observar mejor.
        let maq = entidad::maquina("m-1");
        let p = entidad::proceso(&maq, 1, 1, AHORA);
        let c = entidad::contenido("aaa");
        let mut l = Linaje::nuevo();
        l.anadir(arista(&p, &c, Relacion::Ejecuto, "conductual"));
        l.anadir(arista(&p, &c, Relacion::Ejecuto, "syscallguard"));
        assert_eq!(l.aristas(), 1);
    }

    #[test]
    fn se_sabe_quien_dibujo_cada_tramo() {
        // Cuando un camino resulta ser falso, lo primero que hay que saber es
        // quien lo dibujo.
        let (l, _, _) = cadena();
        let obs = l.observadores();
        assert!(obs.contains_key("wire"));
        assert!(obs.contains_key("detonate"));
        assert_eq!(obs.values().sum::<usize>(), l.aristas());
    }

    #[test]
    fn el_recorrido_es_determinista() {
        // Dos recorridos sobre el mismo grafo tienen que dar exactamente lo mismo,
        // o el informe no se puede comparar con el del dia anterior.
        let (l, flujo, _) = cadena();
        assert_eq!(l.adelante(&flujo), l.adelante(&flujo));
        assert_eq!(l.causa(&flujo), l.causa(&flujo));
    }

    #[test]
    fn un_camino_que_no_existe_devuelve_nada_en_vez_de_inventarlo() {
        let (l, flujo, _) = cadena();
        let suelta = entidad::contenido("no-conectado");
        assert!(l.camino_entre(&flujo, &suelta).is_none());
        assert_eq!(l.adelante(&suelta).pasos.len(), 1);
    }

    #[test]
    fn las_relaciones_son_dirigidas() {
        // Un grafo sin direccion contesta mal «de donde salio» y «hasta donde
        // llego», que son las dos preguntas que importan.
        let maq = entidad::maquina("m-1");
        let p = entidad::proceso(&maq, 1, 1, AHORA);
        let c = entidad::contenido("aaa");
        let mut l = Linaje::nuevo();
        l.anadir(arista(&p, &c, Relacion::Ejecuto, "x"));
        assert_eq!(l.desde(&p).len(), 1);
        assert_eq!(l.desde(&c).len(), 0);
        assert_eq!(l.hacia(&c).len(), 1);
    }

    #[test]
    fn toda_relacion_tiene_nombre_y_no_se_repiten() {
        let mut n: Vec<&str> = Relacion::todas().iter().map(|r| r.nombre()).collect();
        assert_eq!(n.len(), 13);
        n.sort_unstable();
        let antes = n.len();
        n.dedup();
        assert_eq!(antes, n.len(), "dos relaciones comparten nombre");
    }

    #[test]
    fn todo_truncamiento_se_explica() {
        for t in [
            Truncado::PorNodos { tope: 1 },
            Truncado::PorProfundidad { tope: 1 },
            Truncado::PorGrado { tope: 1 },
        ] {
            assert!(t.texto().len() > 25, "{t:?} no se explica");
        }
    }
}
