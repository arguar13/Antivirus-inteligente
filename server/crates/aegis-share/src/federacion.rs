//! Sincronizacion entre instancias: ciclos, conflictos y lo que no se puede
//! confiar.
//!
//! # El ciclo, y por que «ya he visto ese identificador» no vale
//!
//! A comparte con B, B con C, y C con A. Es la topologia normal de una comunidad
//! —nadie la diseña, sale sola— y sin defensa produce un bucle que no para.
//!
//! La solucion evidente es recordar los identificadores ya vistos y descartarlos.
//! Y rompe el sistema: un objeto **se actualiza**, y la version nueva lleva el
//! mismo identificador. Con esa defensa, la primera version de un indicador es la
//! unica que circula, y una correccion —«este resumen era un falso positivo, lo
//! retiro»— no llega nunca. Se cambia un bucle por un sistema que no se puede
//! corregir, que es peor.
//!
//! Lo que si funciona es el **vector de camino**: cada objeto lleva por donde ha
//! pasado, y una instancia rechaza lo que ya lleva su propio nombre. Es la
//! solucion de BGP al mismo problema, y es correcta por la misma razon: no mira
//! *que* es el objeto, mira *por donde ha venido*.
//!
//! # Lo que el vector de camino NO puede hacer, dicho aqui
//!
//! Una instancia maliciosa **puede mentir sobre el camino**: quitarse a si misma
//! para que el objeto vuelva a circular. Lo que hay contra eso:
//!
//! - Cada salto **añade su propia identidad**, y quien recibe comprueba que el
//!   ultimo salto es el par autenticado por el canal. Eso hace el ultimo salto
//!   infalsificable, y solo el ultimo.
//! - Los saltos anteriores los puede falsear un par malicioso. Contra eso esta el
//!   **tope de saltos**, que no depende de que nadie diga la verdad.
//!
//! De modo que la defensa son las dos cosas, y ninguna sobra: el vector evita el
//! bucle entre pares honestos —que es el caso normal—, y el tope acota el daño de
//! uno que miente.
//!
//! # Los conflictos no se resuelven por hora de llegada
//!
//! Dos versiones del mismo objeto llegan por caminos distintos. Resolver por
//! «la ultima que llego» hace que el resultado dependa de la latencia de la red:
//! dos instancias de la misma federacion acabarian con contenidos distintos, y
//! ninguna de las dos sabria cual es el bueno. Se resuelve por
//! `(modified, fiabilidad, id)`, que es igual en todas partes.

use std::collections::{BTreeMap, BTreeSet};

use crate::procedencia::{Aporte, Fiabilidad};
use crate::stix::{Objeto, Paquete};

/// Saltos maximos que puede dar un objeto.
///
/// Seis. Es el tope que **no depende de que nadie diga la verdad**: un par
/// malicioso puede falsear los saltos anteriores del vector, pero no puede
/// impedir que el contador llegue al limite. Seis cubre de sobra cualquier
/// topologia de comunidad real —las federaciones sanas son casi planas— y acota
/// el bucle de una mentirosa a seis vueltas en vez de infinitas.
pub const MAX_SALTOS: usize = 6;

/// Objetos maximos por lote de sincronizacion.
pub const MAX_LOTE: usize = 10_000;

/// Una instancia de la federacion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Par {
    /// Nombre estable. Es lo que va en el vector de camino.
    pub nombre: String,
    /// Que fiabilidad se le concede a lo que manda.
    pub fiabilidad: Fiabilidad,
    /// Si se acepta lo que reemite de terceros, o solo lo suyo.
    ///
    /// Un par que solo reemite lo suyo es mucho mas facil de auditar: lo que
    /// llega por el es suyo y se le puede pedir cuentas. Aceptar lo que reemite
    /// mete en la base cosas de instancias con las que no hay ninguna relacion,
    /// y la procedencia lo refleja pero la responsabilidad se diluye.
    pub acepta_reemitido: bool,
}

/// Un objeto viajando por la federacion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnTransito {
    /// El objeto.
    pub objeto: Objeto,
    /// Por donde ha pasado, del origen al ultimo salto.
    pub camino: Vec<String>,
}

impl EnTransito {
    /// Un objeto que sale de su origen.
    #[must_use]
    pub fn desde(objeto: Objeto, origen: &str) -> EnTransito {
        EnTransito {
            objeto,
            camino: vec![origen.to_string()],
        }
    }

    /// El ultimo salto: quien nos lo entrego.
    #[must_use]
    pub fn ultimo_salto(&self) -> Option<&str> {
        self.camino.last().map(String::as_str)
    }

    /// El origen declarado.
    #[must_use]
    pub fn origen(&self) -> Option<&str> {
        self.camino.first().map(String::as_str)
    }

    /// Añade un salto al reemitir.
    #[must_use]
    pub fn con_salto(mut self, quien: &str) -> EnTransito {
        self.camino.push(quien.to_string());
        self
    }
}

/// Por que no se acepta algo que llega por federacion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Descarte {
    /// El camino ya pasa por esta instancia.
    CicloDetectado {
        /// El camino completo.
        camino: Vec<String>,
    },
    /// Paso del tope de saltos.
    DemasiadosSaltos {
        /// Cuantos traia.
        saltos: usize,
    },
    /// El ultimo salto no es el par que habla.
    ///
    /// Es lo unico del vector que se puede comprobar, y comprobarlo es lo que
    /// hace infalsificable **ese** salto.
    UltimoSaltoNoCuadra {
        /// El que dice el vector.
        declarado: String,
        /// El par autenticado por el canal.
        autenticado: String,
    },
    /// Es un reemitido y este par no tiene permiso para reemitir.
    ReemitidoNoAceptado {
        /// El par.
        par: String,
        /// El origen que trae.
        origen: String,
    },
    /// El par no esta declarado.
    ParDesconocido {
        /// Cual.
        par: String,
    },
    /// Ya tenemos una version igual o mejor.
    VersionNoMejor {
        /// El identificador.
        id: String,
    },
    /// El lote pasa del tope.
    LoteDesmesurado {
        /// Cuantos traia.
        objetos: usize,
    },
}

impl Descarte {
    /// Nombre estable, para agrupar en el panel.
    #[must_use]
    pub fn nombre(&self) -> &'static str {
        match self {
            Descarte::CicloDetectado { .. } => "ciclo-detectado",
            Descarte::DemasiadosSaltos { .. } => "demasiados-saltos",
            Descarte::UltimoSaltoNoCuadra { .. } => "ultimo-salto-no-cuadra",
            Descarte::ReemitidoNoAceptado { .. } => "reemitido-no-aceptado",
            Descarte::ParDesconocido { .. } => "par-desconocido",
            Descarte::VersionNoMejor { .. } => "version-no-mejor",
            Descarte::LoteDesmesurado { .. } => "lote-desmesurado",
        }
    }

    /// Si esto indica que un par se esta portando mal.
    ///
    /// Importa: un ciclo es topologia y se corta en silencio, pero un ultimo
    /// salto que no cuadra es un par mintiendo sobre su propia identidad, y eso
    /// tiene que verse.
    #[must_use]
    pub fn es_mala_conducta(&self) -> bool {
        matches!(
            self,
            Descarte::UltimoSaltoNoCuadra { .. }
                | Descarte::ReemitidoNoAceptado { .. }
                | Descarte::LoteDesmesurado { .. }
        )
    }

    /// Texto para el informe.
    #[must_use]
    pub fn texto(&self) -> String {
        match self {
            Descarte::CicloDetectado { camino } => format!(
                "el camino [{}] ya pasa por esta instancia: se corta aqui, que es lo que impide el \
                 bucle A->B->C->A",
                camino.join(" -> ")
            ),
            Descarte::DemasiadosSaltos { saltos } => format!(
                "traia {saltos} saltos y el tope es {MAX_SALTOS}; el tope es la defensa que NO \
                 depende de que nadie diga la verdad sobre su camino"
            ),
            Descarte::UltimoSaltoNoCuadra {
                declarado,
                autenticado,
            } => format!(
                "el vector dice que el ultimo salto fue «{declarado}» y quien habla es \
                 «{autenticado}»: un par mintiendo sobre su propia identidad"
            ),
            Descarte::ReemitidoNoAceptado { par, origen } => format!(
                "«{par}» reemite algo de «{origen}» y no tiene permiso para reemitir: lo que llega \
                 por el tiene que ser suyo, para poder pedirle cuentas"
            ),
            Descarte::ParDesconocido { par } => {
                format!("«{par}» no esta declarado como par de esta federacion")
            }
            Descarte::VersionNoMejor { id } => {
                format!("de «{id}» ya tenemos una version igual o posterior")
            }
            Descarte::LoteDesmesurado { objetos } => {
                format!("el lote traia {objetos} objetos y el tope es {MAX_LOTE}")
            }
        }
    }
}

/// Lo que resulta de aceptar un lote.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Absorcion {
    /// Objetos nuevos.
    pub nuevos: Vec<String>,
    /// Objetos que sustituyen a una version anterior.
    pub actualizados: Vec<String>,
    /// Lo que no entro, con su motivo.
    pub descartados: Vec<(String, Descarte)>,
}

impl Absorcion {
    /// Cuentas por motivo de descarte.
    #[must_use]
    pub fn por_motivo(&self) -> BTreeMap<&'static str, usize> {
        let mut m = BTreeMap::new();
        for (_, d) in &self.descartados {
            *m.entry(d.nombre()).or_insert(0) += 1;
        }
        m
    }

    /// Los pares que se han portado mal en este lote.
    #[must_use]
    pub fn mala_conducta(&self) -> Vec<&(String, Descarte)> {
        self.descartados
            .iter()
            .filter(|(_, d)| d.es_mala_conducta())
            .collect()
    }
}

/// Una instancia de esta federacion.
#[derive(Debug, Clone)]
pub struct Instancia {
    nombre: String,
    pares: BTreeMap<String, Par>,
    /// Lo que tenemos, por identificador.
    almacen: BTreeMap<String, Objeto>,
    /// De donde vino cada version, para no volver a mandarsela a quien la mando.
    caminos: BTreeMap<String, Vec<String>>,
    /// Hasta donde se ha enviado a cada destino.
    ///
    /// # Por que hace falta, y que pasa sin ello
    ///
    /// Sin cursor de salida, cada ciclo de sincronizacion manda la base **entera**
    /// a cada par. No produce un bucle —el vector de camino y la resolucion de
    /// conflictos rechazan lo repetido en el otro extremo— y aun asi hace inviable
    /// la federacion: con cuatrocientos mil indicadores y veinte pares, cada ciclo
    /// son ocho millones de objetos por la red para no cambiar nada.
    ///
    /// Y lo peor es que **funciona**: nadie se entera de que esta pasando hasta
    /// que la federacion crece lo suficiente para que el ciclo no termine antes
    /// del siguiente.
    ///
    /// El cursor es `(modificado, identificador)` y no una marca de tiempo suelta,
    /// por la misma razon que en TAXII: con lotes grandes, decenas de objetos
    /// comparten instante, y un cursor que solo mire el tiempo se los salta.
    enviado_hasta: BTreeMap<String, (u64, String)>,
}

impl Instancia {
    /// Crea una instancia.
    #[must_use]
    pub fn nueva(nombre: impl Into<String>) -> Instancia {
        Instancia {
            nombre: nombre.into(),
            pares: BTreeMap::new(),
            almacen: BTreeMap::new(),
            caminos: BTreeMap::new(),
            enviado_hasta: BTreeMap::new(),
        }
    }

    /// El nombre de esta instancia.
    #[must_use]
    pub fn nombre(&self) -> &str {
        &self.nombre
    }

    /// Declara un par.
    pub fn declarar_par(&mut self, par: Par) {
        self.pares.insert(par.nombre.clone(), par);
    }

    /// Cuantos objetos hay.
    #[must_use]
    pub fn cuantos(&self) -> usize {
        self.almacen.len()
    }

    /// Un objeto por identificador.
    #[must_use]
    pub fn objeto(&self, id: &str) -> Option<&Objeto> {
        self.almacen.get(id)
    }

    /// Mete un objeto propio, sin pasar por la federacion.
    pub fn anadir_propio(&mut self, objeto: Objeto) {
        let id = objeto.id.clone();
        self.caminos.insert(id.clone(), vec![self.nombre.clone()]);
        self.almacen.insert(id, objeto);
    }

    /// Absorbe un lote que llega de un par autenticado.
    ///
    /// `par_autenticado` es la identidad que el canal —mTLS, en la practica—
    /// confirmo. No se toma del documento: tomarla del documento seria creerse la
    /// identidad que dice quien habla.
    pub fn absorber(
        &mut self,
        lote: Vec<EnTransito>,
        par_autenticado: &str,
        aportes: &mut crate::procedencia::Registro,
        ahora_ns: u64,
    ) -> Absorcion {
        let mut a = Absorcion::default();

        if lote.len() > MAX_LOTE {
            a.descartados.push((
                String::new(),
                Descarte::LoteDesmesurado {
                    objetos: lote.len(),
                },
            ));
            return a;
        }
        let Some(par) = self.pares.get(par_autenticado).cloned() else {
            a.descartados.push((
                String::new(),
                Descarte::ParDesconocido {
                    par: par_autenticado.to_string(),
                },
            ));
            return a;
        };

        for t in lote {
            let id = t.objeto.id.clone();
            match self.juzgar(&t, &par) {
                Err(d) => a.descartados.push((id, d)),
                Ok(nuevo) => {
                    aportes.anotar(
                        &id,
                        Aporte {
                            fuente: par.nombre.clone(),
                            fiabilidad: par.fiabilidad,
                            // La cadena SIN el ultimo salto, que es el propio par:
                            // asi `raiz()` da el origen de verdad y dos pares que
                            // reemiten al mismo no cuentan como dos.
                            cadena: t.camino[..t.camino.len().saturating_sub(1)].to_vec(),
                            cuando_ns: ahora_ns,
                            confianza_declarada: t
                                .objeto
                                .crudo
                                .get("confidence")
                                .and_then(serde_json::Value::as_u64)
                                .map_or(50, |v| u8::try_from(v.min(100)).unwrap_or(50)),
                            id_en_origen: id.clone(),
                        },
                    );
                    self.caminos.insert(id.clone(), t.camino.clone());
                    self.almacen.insert(id.clone(), t.objeto);
                    if nuevo {
                        a.nuevos.push(id);
                    } else {
                        a.actualizados.push(id);
                    }
                }
            }
        }
        a.nuevos.sort();
        a.actualizados.sort();
        a.descartados.sort_by(|x, y| x.0.cmp(&y.0));
        a
    }

    /// Decide si un objeto en transito entra. `Ok(true)` si es nuevo.
    fn juzgar(&self, t: &EnTransito, par: &Par) -> Result<bool, Descarte> {
        // 1 · El ultimo salto tiene que ser quien habla. Es lo unico del vector
        //     que se puede comprobar, y comprobarlo hace ESE salto infalsificable.
        match t.ultimo_salto() {
            Some(u) if u == par.nombre => {}
            Some(u) => {
                return Err(Descarte::UltimoSaltoNoCuadra {
                    declarado: u.to_string(),
                    autenticado: par.nombre.clone(),
                })
            }
            None => {
                return Err(Descarte::UltimoSaltoNoCuadra {
                    declarado: String::new(),
                    autenticado: par.nombre.clone(),
                })
            }
        }

        // 2 · El ciclo. Se mira ANTES del tope de saltos porque un ciclo corto es
        //     topologia normal y no una anomalia que reportar.
        if t.camino.iter().any(|p| p == &self.nombre) {
            return Err(Descarte::CicloDetectado {
                camino: t.camino.clone(),
            });
        }

        // 3 · El tope, que no depende de que nadie diga la verdad.
        if t.camino.len() > MAX_SALTOS {
            return Err(Descarte::DemasiadosSaltos {
                saltos: t.camino.len(),
            });
        }

        // 4 · Reemitido.
        if t.camino.len() > 1 && !par.acepta_reemitido {
            return Err(Descarte::ReemitidoNoAceptado {
                par: par.nombre.clone(),
                origen: t.origen().unwrap_or("?").to_string(),
            });
        }

        // 5 · Conflicto. Por (modified, fiabilidad, id) y NUNCA por hora de
        //     llegada: si dependiera de la latencia, dos instancias de la misma
        //     federacion acabarian con contenidos distintos y ninguna sabria cual
        //     es el bueno.
        match self.almacen.get(&t.objeto.id) {
            None => Ok(true),
            Some(actual) => {
                if gana(&t.objeto, actual) {
                    Ok(false)
                } else {
                    Err(Descarte::VersionNoMejor {
                        id: t.objeto.id.clone(),
                    })
                }
            }
        }
    }

    /// Lo que le falta a un par, sin avanzar el cursor.
    ///
    /// Se separa de [`Instancia::a_enviar`] para poder mirar lo que se mandaria
    /// sin mandarlo: una sincronizacion que no se puede inspeccionar antes de
    /// lanzarla no se depura nunca.
    #[must_use]
    pub fn pendiente_para(&self, destino: &str, desde: Option<&(u64, String)>) -> Vec<EnTransito> {
        let mut v: Vec<EnTransito> = self
            .almacen
            .values()
            .filter_map(|o| {
                if let Some(c) = desde {
                    if (o.modificado_ns, o.id.clone()) <= *c {
                        return None;
                    }
                }
                // No se le devuelve lo que el mismo mando, ni lo que paso por el.
                // Es la mitad barata de la defensa contra el ciclo: el vector lo
                // cortaria igual al llegar, pero mandarlo gasta ancho de banda y
                // trabajo en los dos extremos.
                let camino = self.caminos.get(&o.id)?;
                if camino.iter().any(|p| p == destino) {
                    return None;
                }
                let mut c = camino.clone();
                if c.last().map(String::as_str) != Some(self.nombre.as_str()) {
                    c.push(self.nombre.clone());
                }
                if c.len() > MAX_SALTOS {
                    return None;
                }
                Some(EnTransito {
                    objeto: o.clone(),
                    camino: c,
                })
            })
            .collect();
        v.sort_by(|a, b| {
            a.objeto
                .modificado_ns
                .cmp(&b.objeto.modificado_ns)
                .then(a.objeto.id.cmp(&b.objeto.id))
        });
        v
    }

    /// Lo que hay que mandarle a un par, y avanza su cursor de salida.
    ///
    /// Manda **solo lo que le falta**. Ver [`Instancia::enviado_hasta`]: sin el
    /// cursor, cada ciclo reenvia la base entera a cada par — no produce un bucle,
    /// pero hace inviable la federacion en cuanto crece.
    pub fn a_enviar(&mut self, destino: &str) -> Vec<EnTransito> {
        let desde = self.enviado_hasta.get(destino).cloned();
        let lote = self.pendiente_para(destino, desde.as_ref());
        if let Some(ultimo) = lote.last() {
            self.enviado_hasta.insert(
                destino.to_string(),
                (ultimo.objeto.modificado_ns, ultimo.objeto.id.clone()),
            );
        }
        lote
    }

    /// Olvida lo enviado a un destino, para volver a sincronizar desde cero.
    ///
    /// Hace falta de verdad: cuando un par pierde su base y hay que repoblarlo, la
    /// alternativa sin esto es no poder.
    pub fn reiniciar_envio(&mut self, destino: &str) {
        self.enviado_hasta.remove(destino);
    }

    /// Los pares por los que llego algo.
    #[must_use]
    pub fn origenes(&self) -> BTreeSet<&str> {
        self.caminos
            .values()
            .filter_map(|c| c.first().map(String::as_str))
            .collect()
    }

    /// Todo lo que hay, como paquete.
    #[must_use]
    pub fn paquete(&self) -> Paquete {
        Paquete {
            id: format!("bundle--{}", self.nombre),
            objetos: self.almacen.clone(),
        }
    }
}

/// Si `nuevo` debe sustituir a `actual`.
///
/// Determinista y sin reloj local: `(modified, revocado, id)`. Que una revocacion
/// gane a igualdad de fecha no es un capricho — es la misma doctrina de siempre:
/// ante la duda, la version que **retira** protecciones equivocadas se aplica, y
/// la que las añade se puede volver a mandar.
fn gana(nuevo: &Objeto, actual: &Objeto) -> bool {
    match nuevo.modificado_ns.cmp(&actual.modificado_ns) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => nuevo.revocado && !actual.revocado,
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::marcado::Marcado;
    use crate::procedencia::Registro;
    use crate::stix::Tipo;
    use serde_json::Map;

    const SEG: u64 = 1_000_000_000;
    const AHORA: u64 = 1_700_000_000 * SEG;

    fn objeto(id: &str, modificado: u64) -> Objeto {
        Objeto {
            tipo: Tipo::Indicator,
            id: id.into(),
            creado_ns: 0,
            modificado_ns: modificado,
            marcado: Marcado::publico(),
            revocado: false,
            etiquetas: vec![],
            referencias: vec![],
            crudo: Map::new(),
        }
    }

    fn par(nombre: &str, reemite: bool) -> Par {
        Par {
            nombre: nombre.into(),
            fiabilidad: Fiabilidad::Comunidad,
            acepta_reemitido: reemite,
        }
    }

    #[test]
    fn un_ciclo_de_tres_no_produce_un_bucle_infinito() {
        // A -> B -> C -> A. Es la topologia normal de una comunidad: nadie la
        // diseña, sale sola.
        let mut a = Instancia::nueva("A");
        let mut b = Instancia::nueva("B");
        let mut c = Instancia::nueva("C");
        a.declarar_par(par("C", true));
        b.declarar_par(par("A", true));
        c.declarar_par(par("B", true));

        a.anadir_propio(objeto("indicator--x", AHORA));
        let mut reg = Registro::nuevo();

        // Una vuelta completa.
        let de_a = a.a_enviar("B");
        assert_eq!(de_a.len(), 1);
        b.absorber(de_a, "A", &mut reg, AHORA);
        let de_b = b.a_enviar("C");
        c.absorber(de_b, "B", &mut reg, AHORA);

        // Y ahora C se lo devuelve a A: aqui es donde el bucle se corta.
        let de_c = c.a_enviar("A");
        assert!(
            de_c.is_empty(),
            "C intenta devolver a A algo que ya paso por A"
        );

        // Aunque se fuerce el envio, A lo rechaza por ciclo.
        let forzado = vec![EnTransito {
            objeto: objeto("indicator--x", AHORA),
            camino: vec!["A".into(), "B".into(), "C".into()],
        }];
        let abs = a.absorber(forzado, "C", &mut reg, AHORA);
        assert!(matches!(
            abs.descartados[0].1,
            Descarte::CicloDetectado { .. }
        ));
        // Un ciclo es topologia, no mala conducta: no se reporta como tal.
        assert!(abs.mala_conducta().is_empty());
    }

    #[test]
    fn una_actualizacion_del_mismo_objeto_si_circula() {
        // La razon de que «ya he visto ese identificador» no sirva: una
        // correccion —«este resumen era un falso positivo»— no llegaria nunca.
        let mut b = Instancia::nueva("B");
        b.declarar_par(par("A", true));
        let mut reg = Registro::nuevo();

        let v1 = vec![EnTransito::desde(objeto("indicator--x", AHORA), "A")];
        assert_eq!(b.absorber(v1, "A", &mut reg, AHORA).nuevos.len(), 1);

        let mut v2_obj = objeto("indicator--x", AHORA + 3600 * SEG);
        v2_obj.revocado = true;
        let v2 = vec![EnTransito::desde(v2_obj, "A")];
        let abs = b.absorber(v2, "A", &mut reg, AHORA);
        assert_eq!(abs.actualizados, vec!["indicator--x".to_string()]);
        assert!(b.objeto("indicator--x").expect("esta").revocado);
    }

    #[test]
    fn una_version_anterior_no_pisa_a_la_que_hay() {
        let mut b = Instancia::nueva("B");
        b.declarar_par(par("A", true));
        let mut reg = Registro::nuevo();
        b.absorber(
            vec![EnTransito::desde(objeto("indicator--x", AHORA), "A")],
            "A",
            &mut reg,
            AHORA,
        );
        let abs = b.absorber(
            vec![EnTransito::desde(
                objeto("indicator--x", AHORA - 3600 * SEG),
                "A",
            )],
            "A",
            &mut reg,
            AHORA,
        );
        assert!(matches!(
            abs.descartados[0].1,
            Descarte::VersionNoMejor { .. }
        ));
    }

    #[test]
    fn el_conflicto_se_resuelve_igual_llegue_en_el_orden_que_llegue() {
        // Si dependiera de la hora de llegada, dos instancias de la misma
        // federacion acabarian con contenidos distintos y ninguna sabria cual es
        // el bueno.
        let viejo = objeto("indicator--x", AHORA);
        let nuevo = objeto("indicator--x", AHORA + 60 * SEG);

        let mut uno = Instancia::nueva("N1");
        uno.declarar_par(par("A", true));
        let mut dos = Instancia::nueva("N2");
        dos.declarar_par(par("A", true));
        let mut reg = Registro::nuevo();

        for o in [viejo.clone(), nuevo.clone()] {
            uno.absorber(vec![EnTransito::desde(o, "A")], "A", &mut reg, AHORA);
        }
        for o in [nuevo, viejo] {
            dos.absorber(vec![EnTransito::desde(o, "A")], "A", &mut reg, AHORA);
        }
        assert_eq!(
            uno.objeto("indicator--x").expect("esta").modificado_ns,
            dos.objeto("indicator--x").expect("esta").modificado_ns
        );
    }

    #[test]
    fn a_igualdad_de_fecha_gana_la_revocacion() {
        // Ante la duda, la version que RETIRA una proteccion equivocada se
        // aplica: la que la añade se puede volver a mandar.
        let mut b = Instancia::nueva("B");
        b.declarar_par(par("A", true));
        let mut reg = Registro::nuevo();
        b.absorber(
            vec![EnTransito::desde(objeto("indicator--x", AHORA), "A")],
            "A",
            &mut reg,
            AHORA,
        );
        let mut rev = objeto("indicator--x", AHORA);
        rev.revocado = true;
        let abs = b.absorber(vec![EnTransito::desde(rev, "A")], "A", &mut reg, AHORA);
        assert_eq!(abs.actualizados.len(), 1);
        assert!(b.objeto("indicator--x").expect("esta").revocado);
    }

    #[test]
    fn un_par_que_miente_sobre_el_ultimo_salto_se_detecta() {
        // Es lo unico del vector que se puede comprobar, y comprobarlo hace ESE
        // salto infalsificable.
        let mut b = Instancia::nueva("B");
        b.declarar_par(par("A", true));
        let mut reg = Registro::nuevo();
        let mentira = vec![EnTransito {
            objeto: objeto("indicator--x", AHORA),
            camino: vec!["Z".into()],
        }];
        let abs = b.absorber(mentira, "A", &mut reg, AHORA);
        assert!(matches!(
            abs.descartados[0].1,
            Descarte::UltimoSaltoNoCuadra { .. }
        ));
        // Y esto SI es mala conducta: un par mintiendo sobre su identidad.
        assert_eq!(abs.mala_conducta().len(), 1);
    }

    #[test]
    fn el_tope_de_saltos_acota_a_quien_miente_sobre_el_camino() {
        // Un par malicioso puede quitarse del vector para que algo vuelva a
        // circular. El tope no depende de que nadie diga la verdad.
        let mut b = Instancia::nueva("B");
        b.declarar_par(par("A", true));
        let mut reg = Registro::nuevo();
        let camino: Vec<String> = (0..MAX_SALTOS)
            .map(|i| format!("i{i}"))
            .chain(std::iter::once("A".to_string()))
            .collect();
        let largo = vec![EnTransito {
            objeto: objeto("indicator--x", AHORA),
            camino,
        }];
        let abs = b.absorber(largo, "A", &mut reg, AHORA);
        assert!(matches!(
            abs.descartados[0].1,
            Descarte::DemasiadosSaltos { .. }
        ));
    }

    #[test]
    fn un_par_que_no_reemite_no_puede_colar_lo_de_terceros() {
        // Lo que llega por el tiene que ser suyo, para poderle pedir cuentas.
        let mut b = Instancia::nueva("B");
        b.declarar_par(par("A", false));
        let mut reg = Registro::nuevo();
        let reemitido = vec![EnTransito {
            objeto: objeto("indicator--x", AHORA),
            camino: vec!["desconocido".into(), "A".into()],
        }];
        let abs = b.absorber(reemitido, "A", &mut reg, AHORA);
        assert!(matches!(
            abs.descartados[0].1,
            Descarte::ReemitidoNoAceptado { .. }
        ));
        assert_eq!(abs.mala_conducta().len(), 1);
    }

    #[test]
    fn un_par_no_declarado_no_mete_nada() {
        let mut b = Instancia::nueva("B");
        let mut reg = Registro::nuevo();
        let abs = b.absorber(
            vec![EnTransito::desde(objeto("indicator--x", AHORA), "X")],
            "X",
            &mut reg,
            AHORA,
        );
        assert!(matches!(
            abs.descartados[0].1,
            Descarte::ParDesconocido { .. }
        ));
        assert_eq!(b.cuantos(), 0);
    }

    #[test]
    fn un_lote_desmesurado_se_rechaza_entero() {
        let mut b = Instancia::nueva("B");
        b.declarar_par(par("A", true));
        let mut reg = Registro::nuevo();
        let lote: Vec<EnTransito> = (0..=MAX_LOTE)
            .map(|i| EnTransito::desde(objeto(&format!("indicator--{i}"), AHORA), "A"))
            .collect();
        let abs = b.absorber(lote, "A", &mut reg, AHORA);
        assert!(matches!(
            abs.descartados[0].1,
            Descarte::LoteDesmesurado { .. }
        ));
        assert_eq!(b.cuantos(), 0);
    }

    #[test]
    fn no_se_le_devuelve_a_un_par_lo_que_el_mismo_mando() {
        // La mitad barata de la defensa: el vector lo cortaria igual al llegar,
        // pero mandarlo gasta ancho de banda y trabajo en los dos extremos.
        let mut b = Instancia::nueva("B");
        b.declarar_par(par("A", true));
        let mut reg = Registro::nuevo();
        b.absorber(
            vec![EnTransito::desde(objeto("indicator--x", AHORA), "A")],
            "A",
            &mut reg,
            AHORA,
        );
        assert!(b.a_enviar("A").is_empty());
        // Pero a un tercero si se lo manda, con el salto añadido.
        let a_c = b.a_enviar("C");
        assert_eq!(a_c.len(), 1);
        assert_eq!(a_c[0].camino, vec!["A".to_string(), "B".to_string()]);
    }

    #[test]
    fn no_se_reenvia_la_base_entera_en_cada_ciclo() {
        // Sin cursor de salida no hay bucle —el otro extremo rechaza lo repetido—
        // pero cada ciclo manda la base entera: con cuatrocientos mil indicadores
        // y veinte pares son ocho millones de objetos por la red para no cambiar
        // nada. Y lo peor es que FUNCIONA, asi que nadie se entera hasta que la
        // federacion crece lo suficiente.
        let mut a = Instancia::nueva("A");
        for i in 0..50 {
            a.anadir_propio(objeto(&format!("indicator--{i:03}"), AHORA + i));
        }
        assert_eq!(a.a_enviar("B").len(), 50, "la primera vez van todos");
        assert!(a.a_enviar("B").is_empty(), "la segunda no va ninguno");

        // Y lo que cambia DESPUES si sale, porque el cursor va por (modificado, id).
        a.anadir_propio(objeto("indicator--nuevo", AHORA + 10_000));
        assert_eq!(a.a_enviar("B").len(), 1);

        // Una correccion del mismo objeto tambien: su `modificado` es posterior.
        let mut corregido = objeto("indicator--000", AHORA + 20_000);
        corregido.revocado = true;
        a.anadir_propio(corregido);
        let lote = a.a_enviar("B");
        assert_eq!(lote.len(), 1);
        assert!(lote[0].objeto.revocado);
    }

    #[test]
    fn se_puede_mirar_lo_pendiente_sin_mandarlo() {
        // Una sincronizacion que no se puede inspeccionar antes de lanzarla no se
        // depura nunca.
        let mut a = Instancia::nueva("A");
        a.anadir_propio(objeto("indicator--x", AHORA));
        assert_eq!(a.pendiente_para("B", None).len(), 1);
        assert_eq!(a.pendiente_para("B", None).len(), 1, "mirar no consume");
        assert_eq!(a.a_enviar("B").len(), 1);
        assert!(a.a_enviar("B").is_empty());
        // Y se puede volver a empezar cuando un par pierde su base.
        a.reiniciar_envio("B");
        assert_eq!(a.a_enviar("B").len(), 1);
    }

    #[test]
    fn la_procedencia_registra_la_cadena_sin_el_ultimo_salto() {
        // Asi `raiz()` da el origen de verdad, y dos pares que reemiten al mismo
        // no cuentan como dos fuentes independientes.
        let mut c = Instancia::nueva("C");
        c.declarar_par(par("B", true));
        let mut reg = Registro::nuevo();
        c.absorber(
            vec![EnTransito {
                objeto: objeto("indicator--x", AHORA),
                camino: vec!["A".into(), "B".into()],
            }],
            "B",
            &mut reg,
            AHORA,
        );
        let f = reg.ficha("indicator--x").expect("anotada");
        assert_eq!(f.aportes[0].fuente, "B");
        assert_eq!(f.aportes[0].raiz(), "A");
        assert_eq!(f.fuentes_independientes(AHORA), 1);
    }

    #[test]
    fn dos_pares_que_reemiten_al_mismo_no_son_dos_fuentes() {
        let mut d = Instancia::nueva("D");
        d.declarar_par(par("B", true));
        d.declarar_par(par("C", true));
        let mut reg = Registro::nuevo();
        d.absorber(
            vec![EnTransito {
                objeto: objeto("indicator--x", AHORA),
                camino: vec!["origen".into(), "B".into()],
            }],
            "B",
            &mut reg,
            AHORA,
        );
        d.absorber(
            vec![EnTransito {
                objeto: objeto("indicator--x", AHORA + SEG),
                camino: vec!["origen".into(), "C".into()],
            }],
            "C",
            &mut reg,
            AHORA,
        );
        let f = reg.ficha("indicator--x").expect("anotada");
        assert_eq!(f.aportes.len(), 2, "hay dos aportes");
        assert_eq!(f.fuentes_independientes(AHORA), 1, "pero una sola fuente");
    }

    #[test]
    fn todo_descarte_se_explica() {
        let casos = [
            Descarte::CicloDetectado {
                camino: vec!["A".into(), "B".into()],
            },
            Descarte::DemasiadosSaltos { saltos: 9 },
            Descarte::UltimoSaltoNoCuadra {
                declarado: "Z".into(),
                autenticado: "A".into(),
            },
            Descarte::ReemitidoNoAceptado {
                par: "A".into(),
                origen: "X".into(),
            },
            Descarte::ParDesconocido { par: "X".into() },
            Descarte::VersionNoMejor { id: "x".into() },
            Descarte::LoteDesmesurado { objetos: 99_999 },
        ];
        for c in &casos {
            assert!(c.texto().len() > 20, "{c:?} no se explica");
            assert!(!c.nombre().is_empty());
        }
    }
}
