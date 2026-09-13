//! La cronologia se construye sola.
//!
//! # El analista no teclea lo que el sistema ya sabe
//!
//! En la mayoria de las herramientas, la cronologia de un incidente la escribe
//! una persona copiando y pegando de otras pantallas. Eso tiene tres costes, y el
//! tercero es el que duele:
//!
//! 1. Cuesta tiempo justo cuando no sobra.
//! 2. Se copia mal: horas en el huso de quien mira, nombres aproximados.
//! 3. **Se copia lo que encaja con la hipotesis.** No por mala fe: quien ya cree
//!    saber lo que paso copia los diez hechos que lo confirman y no ve los tres
//!    que no. La cronologia acaba siendo un resumen de la conclusion en vez de la
//!    evidencia que la sostiene.
//!
//! Aqui se construye del **grafo de linaje** y de las **remediaciones ya
//! registradas**, que son datos que el sistema tiene. Lo que escribe una persona
//! entra tambien, pero **marcado como tal**.
//!
//! # Por que separar lo observado de lo dicho
//!
//! Un caso de seguridad puede acabar en un juzgado, en un informe a un regulador
//! o en una discusion con el cliente. «El sistema vio que el proceso 4211 creo
//! /tmp/x» y «el analista cree que el proceso 4211 creo /tmp/x» son afirmaciones
//! de distinto valor, y en una cronologia plana se leen igual.
//!
//! [`Origen`] las separa, y la separacion se conserva hasta el informe.
//!
//! # Los huecos se dicen, no se cosen
//!
//! Si el linaje tiene un salto —un proceso cuyo padre no se observo, un tramo en
//! el que el agente estuvo sin telemetria— la cronologia **lo marca**. La
//! tentacion es unir los dos extremos, y produce una cadena causal que no existio:
//! el informe dice que A llevo a B cuando lo unico que consta es que A ocurrio
//! antes que B.
//!
//! Es la misma regla que el tri-estado de todo el producto: «no se pudo mirar» no
//! es «no habia nada».

use std::collections::BTreeSet;

use crate::modelo::{Caso, Observable};

/// De donde salio una linea de la cronologia.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Origen {
    /// Lo observo un sensor del producto.
    Sensor,
    /// Se dedujo del grafo de linaje de procesos.
    Linaje,
    /// Lo registro el orquestador de remediacion.
    Remediacion,
    /// Lo escribio una persona.
    ///
    /// Se distingue de lo observado porque «el sistema vio X» y «el analista cree
    /// X» son afirmaciones de distinto valor, y en una cronologia plana se leen
    /// igual.
    Analista,
    /// El sistema **no pudo** observar este tramo.
    ///
    /// No es una linea de relleno: es la marca de un hueco. Ver el encabezado.
    Hueco,
}

impl Origen {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Origen::Sensor => "sensor",
            Origen::Linaje => "linaje",
            Origen::Remediacion => "remediacion",
            Origen::Analista => "analista",
            Origen::Hueco => "hueco",
        }
    }

    /// Si la linea es evidencia del sistema o afirmacion de una persona.
    #[must_use]
    pub fn es_evidencia(self) -> bool {
        matches!(self, Origen::Sensor | Origen::Linaje | Origen::Remediacion)
    }
}

/// Que clase de hecho.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Hito {
    /// Llego una alerta.
    Alerta,
    /// Se creo un proceso.
    Proceso,
    /// Se toco un fichero.
    Fichero,
    /// Se abrio una conexion.
    Red,
    /// Alguien inicio sesion.
    Sesion,
    /// Se ordeno una remediacion.
    RemediacionOrdenada,
    /// Se confirmo una remediacion.
    RemediacionAplicada,
    /// Cambio el estado del caso.
    Estado,
    /// Una nota.
    Nota,
    /// Un tramo sin observacion.
    SinObservacion,
}

impl Hito {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Hito::Alerta => "alerta",
            Hito::Proceso => "proceso",
            Hito::Fichero => "fichero",
            Hito::Red => "red",
            Hito::Sesion => "sesion",
            Hito::RemediacionOrdenada => "remediacion-ordenada",
            Hito::RemediacionAplicada => "remediacion-aplicada",
            Hito::Estado => "estado",
            Hito::Nota => "nota",
            Hito::SinObservacion => "sin-observacion",
        }
    }
}

/// Una linea de la cronologia.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Linea {
    /// Cuando ocurrio, en nanosegundos Unix.
    pub cuando_ns: u64,
    /// Que clase de hecho.
    pub hito: Hito,
    /// De donde salio.
    pub origen: Origen,
    /// Quien, si lo hay.
    pub actor: Option<String>,
    /// Texto legible.
    pub texto: String,
    /// Identificador estable, para desduplicar y para desempatar el orden.
    pub clave: String,
}

/// Un nodo del grafo de linaje.
///
/// Es la vista minima que necesita la cronologia; el grafo completo vive en
/// `aegis-server`. Traerlo entero aqui acoplaria este crate a su representacion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodoLinaje {
    /// Identificador del proceso.
    pub id: String,
    /// Identificador del padre, si se observo.
    ///
    /// `None` **no** significa que sea el primero: puede ser que el padre no se
    /// observara. La diferencia la marca [`NodoLinaje::padre_desconocido`].
    pub padre: Option<String>,
    /// Si el padre existio pero no se llego a observar.
    pub padre_desconocido: bool,
    /// Nombre del ejecutable.
    pub imagen: String,
    /// Linea de ordenes.
    pub orden: String,
    /// Cuando arranco.
    pub cuando_ns: u64,
    /// Usuario.
    pub usuario: String,
    /// Ficheros que toco, con su hora.
    pub ficheros: Vec<(u64, String)>,
    /// Conexiones que abrio, con su hora.
    pub conexiones: Vec<(u64, String)>,
}

/// Una remediacion ya registrada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remediacion {
    /// Identificador.
    pub id: String,
    /// Que se ordeno.
    pub accion: String,
    /// Sobre que.
    pub objetivo: String,
    /// Quien la ordeno.
    pub actor: String,
    /// Cuando se ordeno.
    pub ordenada_ns: u64,
    /// Cuando se confirmo, si se confirmo.
    ///
    /// `None` es un dato, no un hueco: una remediacion ordenada y no confirmada
    /// es exactamente lo que hay que ver en la cronologia, porque significa que
    /// la contencion **puede no haber ocurrido**.
    pub aplicada_ns: Option<u64>,
}

/// La cronologia de un caso.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cronologia {
    lineas: Vec<Linea>,
}

impl Cronologia {
    /// Construye la cronologia de un caso.
    ///
    /// Todo lo que entra aqui es dato que el sistema tiene. Lo que escribe una
    /// persona se anade despues con [`Cronologia::anotar`], y queda marcado.
    #[must_use]
    pub fn construir(
        caso: &Caso,
        linaje: &[NodoLinaje],
        remediaciones: &[Remediacion],
    ) -> Cronologia {
        let mut c = Cronologia::default();

        for a in &caso.alertas {
            c.lineas.push(Linea {
                cuando_ns: a.ocurrio_ns,
                hito: Hito::Alerta,
                origen: Origen::Sensor,
                actor: None,
                texto: format!("[{}] {} en {}", a.regla, a.resumen, a.anfitrion),
                clave: format!("alerta:{}", a.id),
            });
        }

        for n in linaje {
            let padre = match (&n.padre, n.padre_desconocido) {
                (Some(p), _) => format!(" (hijo de {p})"),
                // EL HUECO SE DICE. Unir los dos extremos produce una cadena
                // causal que no existio: el informe diria que A llevo a B cuando
                // lo unico que consta es que A ocurrio antes que B.
                (None, true) => " (padre NO observado)".to_string(),
                (None, false) => String::new(),
            };
            c.lineas.push(Linea {
                cuando_ns: n.cuando_ns,
                hito: Hito::Proceso,
                origen: Origen::Linaje,
                actor: Some(n.usuario.clone()),
                texto: format!("{} arranco: {}{padre}", n.imagen, n.orden),
                clave: format!("proceso:{}", n.id),
            });
            if n.padre_desconocido {
                c.lineas.push(Linea {
                    cuando_ns: n.cuando_ns,
                    hito: Hito::SinObservacion,
                    origen: Origen::Hueco,
                    actor: None,
                    texto: format!(
                        "no consta quien lanzo {}: el tramo anterior no se observo",
                        n.imagen
                    ),
                    clave: format!("hueco:{}", n.id),
                });
            }
            for (cuando, ruta) in &n.ficheros {
                c.lineas.push(Linea {
                    cuando_ns: *cuando,
                    hito: Hito::Fichero,
                    origen: Origen::Linaje,
                    actor: Some(n.usuario.clone()),
                    texto: format!("{} toco {ruta}", n.imagen),
                    clave: format!("fichero:{}:{ruta}", n.id),
                });
            }
            for (cuando, destino) in &n.conexiones {
                c.lineas.push(Linea {
                    cuando_ns: *cuando,
                    hito: Hito::Red,
                    origen: Origen::Linaje,
                    actor: Some(n.usuario.clone()),
                    texto: format!("{} conecto con {destino}", n.imagen),
                    clave: format!("red:{}:{destino}", n.id),
                });
            }
        }

        for r in remediaciones {
            c.lineas.push(Linea {
                cuando_ns: r.ordenada_ns,
                hito: Hito::RemediacionOrdenada,
                origen: Origen::Remediacion,
                actor: Some(r.actor.clone()),
                texto: format!("se ordeno {} sobre {}", r.accion, r.objetivo),
                clave: format!("rem-ord:{}", r.id),
            });
            match r.aplicada_ns {
                Some(cuando) => c.lineas.push(Linea {
                    cuando_ns: cuando,
                    hito: Hito::RemediacionAplicada,
                    origen: Origen::Remediacion,
                    actor: None,
                    texto: format!("el endpoint confirmo {} sobre {}", r.accion, r.objetivo),
                    clave: format!("rem-apl:{}", r.id),
                }),
                None => c.lineas.push(Linea {
                    cuando_ns: r.ordenada_ns,
                    hito: Hito::SinObservacion,
                    origen: Origen::Hueco,
                    actor: None,
                    // Ordenado y aplicado son dos hechos distintos, y confundirlos
                    // en un informe de contencion es decir que la maquina esta
                    // aislada cuando lo unico que consta es que se pidio.
                    texto: format!(
                        "{} sobre {} se ORDENO pero el endpoint no lo ha confirmado",
                        r.accion, r.objetivo
                    ),
                    clave: format!("rem-sin:{}", r.id),
                }),
            }
        }

        c.ordenar();
        c
    }

    /// Anade una linea escrita por una persona.
    pub fn anotar(&mut self, actor: &str, texto: &str, cuando_ns: u64) {
        self.lineas.push(Linea {
            cuando_ns,
            hito: Hito::Nota,
            origen: Origen::Analista,
            actor: Some(actor.to_string()),
            texto: texto.to_string(),
            clave: format!("nota:{actor}:{cuando_ns}"),
        });
        self.ordenar();
    }

    /// Anade un cambio de estado del caso.
    pub fn estado(&mut self, actor: &str, texto: &str, cuando_ns: u64) {
        self.lineas.push(Linea {
            cuando_ns,
            hito: Hito::Estado,
            origen: Origen::Sensor,
            actor: Some(actor.to_string()),
            texto: texto.to_string(),
            clave: format!("estado:{cuando_ns}:{texto}"),
        });
        self.ordenar();
    }

    /// Lineas, en orden.
    #[must_use]
    pub fn lineas(&self) -> &[Linea] {
        &self.lineas
    }

    /// Solo lo que el sistema observo.
    ///
    /// Es la vista que va a un informe que alguien puede tener que defender.
    #[must_use]
    pub fn evidencia(&self) -> Vec<&Linea> {
        self.lineas
            .iter()
            .filter(|l| l.origen.es_evidencia())
            .collect()
    }

    /// Los huecos declarados.
    #[must_use]
    pub fn huecos(&self) -> Vec<&Linea> {
        self.lineas
            .iter()
            .filter(|l| l.origen == Origen::Hueco)
            .collect()
    }

    /// Si la cronologia tiene tramos sin observar.
    #[must_use]
    pub fn tiene_huecos(&self) -> bool {
        self.lineas.iter().any(|l| l.origen == Origen::Hueco)
    }

    /// Cuando empieza y cuando acaba.
    #[must_use]
    pub fn intervalo(&self) -> Option<(u64, u64)> {
        let primera = self.lineas.first()?.cuando_ns;
        let ultima = self.lineas.last()?.cuando_ns;
        Some((primera, ultima))
    }

    /// Observables que aparecen en la cronologia y no estaban en el caso.
    ///
    /// Es lo que convierte la cronologia en algo accionable: el linaje descubre
    /// ficheros y destinos que la alerta no traia, y son justo los que hay que
    /// enriquecer y compartir.
    #[must_use]
    pub fn observables_nuevos(&self, caso: &Caso) -> Vec<Observable> {
        let ya: BTreeSet<String> = caso
            .observables
            .iter()
            .map(|o| o.valor().to_string())
            .collect();
        let mut salida = Vec::new();
        for l in &self.lineas {
            let Some(valor) = l.texto.split(' ').next_back() else {
                continue;
            };
            if ya.contains(valor) {
                continue;
            }
            let o = match l.hito {
                Hito::Fichero => Observable::Ruta(valor.to_string()),
                Hito::Red => Observable::Ip(valor.to_string()),
                _ => continue,
            };
            if !salida.contains(&o) {
                salida.push(o);
            }
        }
        salida
    }

    /// Ordena por ocurrencia, desempatando por clave.
    ///
    /// El desempate NO es cosmetico: sin el, dos hechos con la misma marca de
    /// tiempo —que son muchisimos, porque los sensores fechan con la resolucion
    /// que fechan— salen en un orden que depende de como estuvieran en memoria, y
    /// dos ejecuciones del mismo caso producen informes distintos. Un informe que
    /// cambia entre ejecuciones no se puede defender.
    fn ordenar(&mut self) {
        self.lineas.sort_by(|a, b| {
            a.cuando_ns
                .cmp(&b.cuando_ns)
                .then_with(|| a.clave.cmp(&b.clave))
        });
        self.lineas.dedup_by(|a, b| a.clave == b.clave);
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::modelo::{Alerta, Caso, Severidad};

    const SEG: u64 = 1_000_000_000;
    const AHORA: u64 = 1_700_000_000 * SEG;

    fn caso() -> Caso {
        Caso::abrir(
            "C-1",
            Alerta {
                id: "A-1".into(),
                inquilino: "c".into(),
                anfitrion: "maquina-17".into(),
                sujeto: "pid:4211".into(),
                tecnica: Some("T1059.001".into()),
                regla: "powershell-codificado".into(),
                severidad: Severidad::Alta,
                ocurrio_ns: AHORA,
                observables: vec![Observable::Anfitrion("maquina-17".into())],
                resumen: "PowerShell con orden codificada".into(),
            },
        )
    }

    fn linaje() -> Vec<NodoLinaje> {
        vec![
            NodoLinaje {
                id: "p1".into(),
                padre: None,
                padre_desconocido: false,
                imagen: "explorer.exe".into(),
                orden: "explorer.exe".into(),
                cuando_ns: AHORA - 60 * SEG,
                usuario: "operador".into(),
                ficheros: Vec::new(),
                conexiones: Vec::new(),
            },
            NodoLinaje {
                id: "p2".into(),
                padre: Some("p1".into()),
                padre_desconocido: false,
                imagen: "powershell.exe".into(),
                orden: "powershell -enc SQBFAFgA".into(),
                cuando_ns: AHORA,
                usuario: "operador".into(),
                ficheros: vec![(AHORA + 5 * SEG, "/tmp/.cache-x".into())],
                conexiones: vec![(AHORA + 10 * SEG, "203.0.113.9:443".into())],
            },
        ]
    }

    #[test]
    fn la_cronologia_se_construye_sola_del_linaje() {
        // El analista no teclea lo que el sistema ya sabe.
        let c = Cronologia::construir(&caso(), &linaje(), &[]);
        let textos: Vec<&str> = c.lineas().iter().map(|l| l.texto.as_str()).collect();
        assert!(textos.iter().any(|t| t.contains("explorer.exe arranco")));
        assert!(textos.iter().any(|t| t.contains("hijo de p1")));
        assert!(textos.iter().any(|t| t.contains("/tmp/.cache-x")));
        assert!(textos.iter().any(|t| t.contains("203.0.113.9:443")));
    }

    #[test]
    fn sale_en_orden_de_ocurrencia() {
        let c = Cronologia::construir(&caso(), &linaje(), &[]);
        for par in c.lineas().windows(2) {
            assert!(par[0].cuando_ns <= par[1].cuando_ns);
        }
        assert_eq!(c.lineas()[0].texto, "explorer.exe arranco: explorer.exe");
    }

    #[test]
    fn un_hueco_en_el_linaje_se_dice_en_vez_de_coserse() {
        // Unir los dos extremos produce una cadena causal que no existio: el
        // informe diria que A llevo a B cuando lo unico que consta es que A
        // ocurrio antes que B.
        let mut l = linaje();
        l[1].padre = None;
        l[1].padre_desconocido = true;
        let c = Cronologia::construir(&caso(), &l, &[]);
        assert!(c.tiene_huecos());
        assert_eq!(c.huecos().len(), 1);
        assert!(c.huecos()[0].texto.contains("no consta quien lanzo"));
    }

    #[test]
    fn una_remediacion_ordenada_y_no_confirmada_sale_como_hueco() {
        // Ordenado y aplicado son dos hechos distintos, y confundirlos en un
        // informe de contencion es decir que la maquina esta aislada cuando lo
        // unico que consta es que se pidio.
        let rem = vec![Remediacion {
            id: "R-1".into(),
            accion: "aislamiento".into(),
            objetivo: "maquina-17".into(),
            actor: "ana".into(),
            ordenada_ns: AHORA + 60 * SEG,
            aplicada_ns: None,
        }];
        let c = Cronologia::construir(&caso(), &linaje(), &rem);
        assert!(c.tiene_huecos());
        assert!(c
            .huecos()
            .iter()
            .any(|l| l.texto.contains("no lo ha confirmado")));
    }

    #[test]
    fn una_remediacion_confirmada_no_deja_hueco() {
        let rem = vec![Remediacion {
            id: "R-1".into(),
            accion: "aislamiento".into(),
            objetivo: "maquina-17".into(),
            actor: "ana".into(),
            ordenada_ns: AHORA + 60 * SEG,
            aplicada_ns: Some(AHORA + 62 * SEG),
        }];
        let c = Cronologia::construir(&caso(), &linaje(), &rem);
        assert!(!c.tiene_huecos());
        assert!(c
            .lineas()
            .iter()
            .any(|l| l.hito == Hito::RemediacionAplicada));
    }

    #[test]
    fn lo_que_escribe_una_persona_queda_separado_de_lo_observado() {
        // «El sistema vio X» y «el analista cree X» son afirmaciones de distinto
        // valor, y en una cronologia plana se leen igual.
        let mut c = Cronologia::construir(&caso(), &linaje(), &[]);
        c.anotar("ana", "creo que entro por el correo", AHORA + 300 * SEG);
        let evidencia = c.evidencia();
        assert!(
            !evidencia.iter().any(|l| l.texto.contains("creo que")),
            "la opinion se colo en la evidencia"
        );
        assert!(c.lineas().iter().any(|l| l.origen == Origen::Analista));
    }

    #[test]
    fn el_mismo_caso_produce_siempre_la_misma_cronologia() {
        // Sin desempate, dos hechos con la misma marca de tiempo salen en un
        // orden que depende de como estuvieran en memoria, y un informe que
        // cambia entre ejecuciones no se puede defender.
        let a = Cronologia::construir(&caso(), &linaje(), &[]);
        let b = Cronologia::construir(&caso(), &linaje(), &[]);
        assert_eq!(a, b);
    }

    #[test]
    fn dos_hechos_en_el_mismo_instante_salen_en_orden_estable() {
        let mut l = linaje();
        // Tres ficheros en el mismo nanosegundo: pasa constantemente porque los
        // sensores fechan con la resolucion que fechan.
        l[1].ficheros = vec![
            (AHORA, "/tmp/c".into()),
            (AHORA, "/tmp/a".into()),
            (AHORA, "/tmp/b".into()),
        ];
        let a = Cronologia::construir(&caso(), &l, &[]);
        let mut l2 = l.clone();
        l2[1].ficheros.reverse();
        let b = Cronologia::construir(&caso(), &l2, &[]);
        assert_eq!(a, b);
    }

    #[test]
    fn no_se_repite_una_linea_aunque_llegue_dos_veces() {
        let mut l = linaje();
        let repetido = l[1].clone();
        l.push(repetido);
        let c = Cronologia::construir(&caso(), &l, &[]);
        let procesos = c
            .lineas()
            .iter()
            .filter(|x| x.clave == "proceso:p2")
            .count();
        assert_eq!(procesos, 1);
    }

    #[test]
    fn el_linaje_descubre_observables_que_la_alerta_no_traia() {
        // Es lo que convierte la cronologia en algo accionable: son justo los que
        // hay que enriquecer y compartir.
        let c = Cronologia::construir(&caso(), &linaje(), &[]);
        let nuevos = c.observables_nuevos(&caso());
        assert!(nuevos.contains(&Observable::Ruta("/tmp/.cache-x".into())));
        assert!(nuevos.contains(&Observable::Ip("203.0.113.9:443".into())));
    }

    #[test]
    fn el_intervalo_cubre_de_lo_primero_a_lo_ultimo() {
        let c = Cronologia::construir(&caso(), &linaje(), &[]);
        let (desde, hasta) = c.intervalo().unwrap();
        assert_eq!(desde, AHORA - 60 * SEG);
        assert_eq!(hasta, AHORA + 10 * SEG);
    }

    #[test]
    fn una_cronologia_vacia_no_miente_sobre_su_intervalo() {
        let c = Cronologia::default();
        assert!(c.intervalo().is_none());
        assert!(!c.tiene_huecos());
    }

    #[test]
    fn un_proceso_raiz_de_verdad_no_es_un_hueco() {
        // `padre: None` no significa que el padre no se observara: el primer
        // proceso de la cadena no tiene padre. Confundirlos llenaria de huecos
        // falsos cualquier cronologia.
        let c = Cronologia::construir(&caso(), &linaje(), &[]);
        assert!(!c.tiene_huecos());
    }
}
