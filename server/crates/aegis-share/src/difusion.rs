//! Quien ve que, y el unico sitio por donde algo sale.
//!
//! # La propiedad que hay que poder afirmar
//!
//! > Un indicador marcado como no compartible **no sale por ningun camino**.
//!
//! «Ningun camino» es la parte dificil, y es una decision de arquitectura antes
//! que de codigo: si la federacion tuviera su filtro, el servidor TAXII otro y el
//! puente del enjambre un tercero, tarde o temprano uno de los tres se queda
//! atras. Y el que se queda atras no falla ruidosamente: **comparte de mas**,
//! que es un fallo que nadie ve hasta que lo ve quien no debia.
//!
//! Por eso aqui hay **un solo estrangulamiento**: [`Difusor::repartir`]. Todo lo
//! que sale de esta instancia pasa por ahi, y la puerta de calidad enumera los
//! canales del enumerado [`Canal`] para comprobar que no queda ninguno sin
//! cubrir.
//!
//! # El enjambre no es un canal confidencial, y eso manda
//!
//! El enjambre llega a **todos los agentes de la flota**, incluidos los que
//! corren en maquinas que el atacante puede haber comprometido — que es
//! literalmente el supuesto de la FASE 68, donde el diseño entero parte de «¿que
//! consigue quien comprometa un endpoint?».
//!
//! De ahi salen dos topes que **no se pueden subir por configuracion**, porque
//! subirlos seria configurar una fuga:
//!
//! 1. **Nada por encima de `TLP:GREEN` viaja por el enjambre.** Mandar un
//!    `TLP:AMBER` por ahi es entregarselo a quien tenga un endpoint.
//! 2. **Nada que no permita bloqueo propio viaja por el enjambre.** Lo que llega
//!    a los agentes acaba en el motor de bloqueo: un `PAP:RED` repartido por la
//!    malla quema la operacion de quien lo compartio en cien mil maquinas a la
//!    vez.
//!
//! Y la doctrina del enjambre se conserva intacta: lo que este modulo deja pasar
//! sigue siendo **evidencia**, no una orden. Convertirlo en accion sigue
//! exigiendo la firma del plano de control. Ver [`crate::puente`].

use std::collections::BTreeMap;

use crate::marcado::{Marcado, Pap, Tlp};
use crate::stix::{Objeto, Paquete};

/// Por donde sale algo de esta instancia.
///
/// El enumerado es cerrado a proposito, y la puerta de calidad lo recorre entero:
/// un canal nuevo que no aparezca aqui no puede existir sin que la comprobacion
/// de cobertura lo note.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Canal {
    /// Una coleccion TAXII que otros leen.
    Taxii,
    /// Un empuje de federacion a otra instancia.
    Federacion,
    /// El puente hacia la malla del enjambre.
    Enjambre,
    /// Una exportacion manual a fichero.
    Exportacion,
}

impl Canal {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Canal::Taxii => "taxii",
            Canal::Federacion => "federacion",
            Canal::Enjambre => "enjambre",
            Canal::Exportacion => "exportacion",
        }
    }

    /// Todos los canales. La puerta de calidad los recorre.
    #[must_use]
    pub fn todos() -> &'static [Canal] {
        &[
            Canal::Taxii,
            Canal::Federacion,
            Canal::Enjambre,
            Canal::Exportacion,
        ]
    }

    /// El tope de TLP que este canal **no puede** superar, pase lo que pase.
    ///
    /// `None` significa que lo decide el destino. Para el enjambre no lo decide:
    /// ver el encabezado del modulo.
    #[must_use]
    pub fn tope_duro(self) -> Option<Tlp> {
        match self {
            // El enjambre llega a maquinas que el atacante puede haber
            // comprometido. Ese es el supuesto de la FASE 68, no una hipotesis.
            Canal::Enjambre => Some(Tlp::Green),
            Canal::Taxii | Canal::Federacion | Canal::Exportacion => None,
        }
    }

    /// El PAP minimo que este canal exige.
    ///
    /// `None` significa que no impone ninguno.
    #[must_use]
    pub fn pap_exigido(self) -> Option<Pap> {
        match self {
            // Lo que llega a los agentes acaba en el motor de bloqueo.
            Canal::Enjambre => Some(Pap::Green),
            Canal::Taxii | Canal::Federacion | Canal::Exportacion => None,
        }
    }
}

/// A quien se le entrega, y hasta donde.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destino {
    /// Nombre.
    pub nombre: String,
    /// Por que canal.
    pub canal: Canal,
    /// El TLP mas restrictivo que este destino puede recibir.
    pub tope_tlp: Tlp,
    /// Si este destino tiene acuerdo para recibir lo que exige acuerdo.
    ///
    /// `TLP:AMBER+STRICT` significa «solo mi organizacion»: entregarselo a un
    /// tercero es una fuga aunque su tope configurado lo permitiera. El tope de
    /// configuracion dice hasta donde **quiere** llegar; esto dice si **puede**.
    pub es_propia_organizacion: bool,
}

impl Destino {
    /// El tope efectivo, ya con el tope duro del canal aplicado.
    ///
    /// Se toma el **minimo** de los dos: configurar un tope mas alto que el duro
    /// del canal no lo sube, lo ignora.
    #[must_use]
    pub fn tope_efectivo(&self) -> Tlp {
        match self.canal.tope_duro() {
            Some(duro) => self.tope_tlp.min(duro),
            None => self.tope_tlp,
        }
    }
}

/// El TLP a partir del cual algo **no se distribuye por ningun canal**.
///
/// `TLP:RED` significa, literalmente, «solo para quien lo recibio en la reunion o
/// la conversacion en que se entrego». No es «solo dentro de mi organizacion»
/// —eso es `AMBER+STRICT`—: es **solo estas personas**.
///
/// De modo que no hay ningun canal de distribucion por el que pueda salir, y eso
/// incluye una exportacion a fichero dentro de casa: exportar es distribuir, y el
/// fichero acaba en un correo. Configurar un destino con tope `RED` no lo
/// habilita; lo unico que hace es no decir nada.
///
/// La consecuencia practica es la que importa: la frase «un indicador no
/// compartible no sale por ningun camino» es cierta **por construccion** y no por
/// haber configurado bien los cuatro destinos.
pub const NO_DISTRIBUIBLE: Tlp = Tlp::Red;

/// Por que algo no sale.
///
/// Cada variante lleva lo necesario para explicarlo. Un objeto retenido sin
/// motivo se lee como «no habia nada que mandar», y entonces nadie revisa un
/// reparto que se esta quedando corto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Retenido {
    /// Es `TLP:RED`: no se distribuye por ningun canal.
    ///
    /// Separado de todos los demas porque no depende del destino ni del canal:
    /// no hay configuracion que lo habilite. Ver [`NO_DISTRIBUIBLE`].
    NoDistribuible,
    /// El TLP pasa del tope del destino.
    PorTlp {
        /// El del objeto.
        objeto: Tlp,
        /// El tope efectivo del destino.
        tope: Tlp,
    },
    /// El canal tiene un tope duro que el objeto supera.
    ///
    /// Separado de [`Retenido::PorTlp`] porque **no se arregla configurando**, y
    /// quien lea el informe tiene que saberlo antes de intentarlo.
    PorTopeDuroDelCanal {
        /// El canal.
        canal: Canal,
        /// El del objeto.
        objeto: Tlp,
        /// El tope que el canal no deja superar.
        tope: Tlp,
    },
    /// El PAP no permite lo que ese canal hace con lo que recibe.
    PorPap {
        /// El canal.
        canal: Canal,
        /// El del objeto.
        objeto: Pap,
        /// El que el canal exige.
        exigido: Pap,
    },
    /// Es `TLP:AMBER+STRICT` y el destino no es la propia organizacion.
    FueraDeLaOrganizacion,
    /// El objeto esta revocado.
    Revocado,
}

impl Retenido {
    /// Nombre estable, para agrupar.
    #[must_use]
    pub fn nombre(&self) -> &'static str {
        match self {
            Retenido::NoDistribuible => "no-distribuible",
            Retenido::PorTlp { .. } => "por-tlp",
            Retenido::PorTopeDuroDelCanal { .. } => "por-tope-duro-del-canal",
            Retenido::PorPap { .. } => "por-pap",
            Retenido::FueraDeLaOrganizacion => "fuera-de-la-organizacion",
            Retenido::Revocado => "revocado",
        }
    }

    /// Si se puede arreglar cambiando la configuracion del destino.
    #[must_use]
    pub fn configurable(&self) -> bool {
        matches!(self, Retenido::PorTlp { .. })
    }

    /// Texto para el informe.
    #[must_use]
    pub fn texto(&self) -> String {
        match self {
            Retenido::NoDistribuible => format!(
                "es {}, que significa «solo quien lo recibio en persona» y no «solo mi \
                 organizacion»: no hay ningun canal de distribucion por el que pueda salir, ni \
                 siquiera una exportacion a fichero — exportar es distribuir, y el fichero acaba \
                 en un correo",
                NO_DISTRIBUIBLE.nombre()
            ),
            Retenido::PorTlp { objeto, tope } => format!(
                "es {} y este destino solo recibe hasta {}",
                objeto.nombre(),
                tope.nombre()
            ),
            Retenido::PorTopeDuroDelCanal {
                canal,
                objeto,
                tope,
            } => format!(
                "es {} y el canal «{}» no pasa de {} — y esto NO se arregla configurando: el \
                 enjambre llega a maquinas que el atacante puede haber comprometido",
                objeto.nombre(),
                canal.nombre(),
                tope.nombre()
            ),
            Retenido::PorPap {
                canal,
                objeto,
                exigido,
            } => format!(
                "es {} y el canal «{}» exige al menos {}: lo que sale por ahi acaba en un motor de \
                 bloqueo, y bloquearlo quemaria la operacion de quien lo compartio",
                objeto.nombre(),
                canal.nombre(),
                exigido.nombre()
            ),
            Retenido::FueraDeLaOrganizacion => {
                "es TLP:AMBER+STRICT, que significa «solo mi organizacion», y este destino no lo es"
                    .to_string()
            }
            Retenido::Revocado => "el objeto esta revocado".to_string(),
        }
    }
}

/// Lo que sale y lo que se queda, con su motivo.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reparto {
    /// Identificadores que salen.
    pub salen: Vec<String>,
    /// Los que no, con su motivo.
    pub retenidos: Vec<(String, Retenido)>,
}

impl Reparto {
    /// Si no sale nada.
    #[must_use]
    pub fn vacio(&self) -> bool {
        self.salen.is_empty()
    }

    /// Cuentas por motivo de retencion.
    #[must_use]
    pub fn por_motivo(&self) -> BTreeMap<&'static str, usize> {
        let mut m = BTreeMap::new();
        for (_, r) in &self.retenidos {
            *m.entry(r.nombre()).or_insert(0) += 1;
        }
        m
    }

    /// Resumen legible.
    #[must_use]
    pub fn resumen(&self, destino: &str) -> String {
        let motivos: Vec<String> = self
            .por_motivo()
            .iter()
            .map(|(k, v)| format!("{k}: {v}"))
            .collect();
        format!(
            "hacia «{destino}» salen {} objeto(s); se quedan {} ({})",
            self.salen.len(),
            self.retenidos.len(),
            if motivos.is_empty() {
                "ninguno".to_string()
            } else {
                motivos.join(", ")
            }
        )
    }
}

/// El unico sitio por donde algo sale de esta instancia.
#[derive(Debug, Clone, Default)]
pub struct Difusor {
    destinos: BTreeMap<String, Destino>,
}

impl Difusor {
    /// Un difusor sin destinos.
    #[must_use]
    pub fn nuevo() -> Difusor {
        Difusor::default()
    }

    /// Declara un destino.
    pub fn declarar(&mut self, destino: Destino) {
        self.destinos.insert(destino.nombre.clone(), destino);
    }

    /// Los destinos declarados.
    #[must_use]
    pub fn destinos(&self) -> Vec<&Destino> {
        self.destinos.values().collect()
    }

    /// Un destino por nombre.
    #[must_use]
    pub fn destino(&self, nombre: &str) -> Option<&Destino> {
        self.destinos.get(nombre)
    }

    /// Decide, objeto a objeto, que sale hacia ese destino.
    ///
    /// **Es el unico estrangulamiento.** Todo lo que sale de esta instancia pasa
    /// por aqui, sea por TAXII, por federacion, por el enjambre o por una
    /// exportacion a mano.
    ///
    /// # Errors
    ///
    /// Devuelve `Err` si el destino no esta declarado. Un destino desconocido NO
    /// se resuelve con un valor por defecto permisivo: se rechaza, porque un
    /// valor por defecto permisivo aqui es una fuga con una errata de por medio.
    pub fn repartir(&self, paquete: &Paquete, destino: &str) -> Result<Reparto, String> {
        let d = self
            .destinos
            .get(destino)
            .ok_or_else(|| format!("destino «{destino}» no declarado: no se reparte a ciegas"))?;

        let mut r = Reparto::default();
        for o in paquete.objetos.values() {
            match Difusor::juzgar(o, d) {
                Ok(()) => r.salen.push(o.id.clone()),
                Err(motivo) => r.retenidos.push((o.id.clone(), motivo)),
            }
        }
        r.salen.sort();
        r.retenidos.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(r)
    }

    /// Si un objeto suelto puede ir a un destino.
    ///
    /// # Errors
    ///
    /// Devuelve el motivo de la retencion.
    pub fn juzgar(o: &Objeto, d: &Destino) -> Result<(), Retenido> {
        Difusor::juzgar_marcado(o.marcado, o.revocado, d)
    }

    /// La decision, a partir del marcado y nada mas.
    ///
    /// Se separa de [`Difusor::juzgar`] para que el puente del enjambre y la
    /// federacion la puedan usar sobre cosas que no son objetos STIX —un
    /// descriptor de artefacto, por ejemplo— sin duplicar el criterio.
    ///
    /// # Errors
    ///
    /// Devuelve el motivo de la retencion.
    pub fn juzgar_marcado(m: Marcado, revocado: bool, d: &Destino) -> Result<(), Retenido> {
        if revocado {
            return Err(Retenido::Revocado);
        }
        // Lo primero, porque no depende de nada configurable: si esto se mirara
        // despues del tope del destino, el informe diria «sube el tope» sobre algo
        // que ningun tope habilita.
        if m.tlp >= NO_DISTRIBUIBLE {
            return Err(Retenido::NoDistribuible);
        }
        // El tope DURO del canal va primero, porque su incumplimiento no se
        // arregla configurando y el informe tiene que decir eso y no otra cosa.
        if let Some(duro) = d.canal.tope_duro() {
            if m.tlp > duro {
                return Err(Retenido::PorTopeDuroDelCanal {
                    canal: d.canal,
                    objeto: m.tlp,
                    tope: duro,
                });
            }
        }
        if let Some(exigido) = d.canal.pap_exigido() {
            if m.pap > exigido {
                return Err(Retenido::PorPap {
                    canal: d.canal,
                    objeto: m.pap,
                    exigido,
                });
            }
        }
        // `AMBER+STRICT` significa «solo mi organizacion». El tope configurado
        // dice hasta donde se QUIERE llegar; esto dice si se PUEDE.
        if m.tlp >= Tlp::Amber && !d.es_propia_organizacion {
            return Err(Retenido::FueraDeLaOrganizacion);
        }
        if m.tlp > d.tope_efectivo() {
            return Err(Retenido::PorTlp {
                objeto: m.tlp,
                tope: d.tope_efectivo(),
            });
        }
        Ok(())
    }

    /// Reparte hacia **todos** los destinos, para comprobar la propiedad entera.
    ///
    /// Es lo que la puerta de calidad usa: no basta con que un indicador no
    /// compartible no salga por el camino que se probo, tiene que no salir por
    /// ninguno.
    #[must_use]
    pub fn repartir_a_todos(&self, paquete: &Paquete) -> BTreeMap<String, Reparto> {
        self.destinos
            .keys()
            .filter_map(|n| self.repartir(paquete, n).ok().map(|r| (n.clone(), r)))
            .collect()
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::stix::Tipo;
    use serde_json::Map;

    fn objeto(id: &str, m: Marcado) -> Objeto {
        Objeto {
            tipo: Tipo::Indicator,
            id: id.into(),
            creado_ns: 0,
            modificado_ns: 0,
            marcado: m,
            revocado: false,
            etiquetas: vec![],
            referencias: vec![],
            crudo: Map::new(),
        }
    }

    fn paquete(objetos: Vec<Objeto>) -> Paquete {
        Paquete {
            id: "bundle--x".into(),
            objetos: objetos.into_iter().map(|o| (o.id.clone(), o)).collect(),
        }
    }

    fn destino(nombre: &str, canal: Canal, tope: Tlp, propia: bool) -> Destino {
        Destino {
            nombre: nombre.into(),
            canal,
            tope_tlp: tope,
            es_propia_organizacion: propia,
        }
    }

    fn difusor_completo() -> Difusor {
        let mut d = Difusor::nuevo();
        d.declarar(destino("comunidad", Canal::Taxii, Tlp::Green, false));
        d.declarar(destino("socio", Canal::Federacion, Tlp::AmberStrict, false));
        d.declarar(destino("interno", Canal::Federacion, Tlp::Red, true));
        d.declarar(destino("flota", Canal::Enjambre, Tlp::Red, true));
        d.declarar(destino("fichero", Canal::Exportacion, Tlp::Red, true));
        d
    }

    #[test]
    fn un_indicador_no_compartible_no_sale_por_ningun_camino() {
        // La propiedad entera de la fase. No basta con que no salga por el camino
        // que se probo: tiene que no salir por ninguno.
        let secreto = objeto("indicator--secreto", Marcado::nuevo(Tlp::Red, Pap::Red));
        let p = paquete(vec![secreto]);
        let d = difusor_completo();

        let repartos = d.repartir_a_todos(&p);
        assert_eq!(repartos.len(), 5, "no se probaron todos los destinos");
        for (nombre, r) in &repartos {
            assert!(
                r.salen.is_empty(),
                "el indicador TLP:RED salio por «{nombre}»"
            );
            assert_eq!(r.retenidos.len(), 1);
            // Y el motivo es el mismo en los cuatro: no lo retiene la
            // configuracion de cada destino, lo retiene que TLP:RED no se
            // distribuye. Eso hace la propiedad cierta POR CONSTRUCCION y no por
            // haber configurado bien los cuatro.
            assert_eq!(
                r.retenidos[0].1,
                Retenido::NoDistribuible,
                "en «{nombre}» lo retuvo otra cosa: la propiedad depende de la configuracion"
            );
            assert!(!r.retenidos[0].1.configurable());
        }
    }

    #[test]
    fn todos_los_canales_del_enumerado_tienen_destino_en_la_prueba() {
        // Si un canal nuevo no apareciera aqui, la comprobacion de arriba dejaria
        // de cubrirlo sin que nadie lo notara. Esto es lo que lo impide.
        let d = difusor_completo();
        let cubiertos: std::collections::BTreeSet<Canal> =
            d.destinos().iter().map(|x| x.canal).collect();
        for c in Canal::todos() {
            assert!(
                cubiertos.contains(c),
                "el canal «{}» no se prueba",
                c.nombre()
            );
        }
    }

    #[test]
    fn el_enjambre_no_pasa_de_verde_aunque_se_configure_al_maximo() {
        // El destino esta declarado con tope Tlp::Red y es la propia
        // organizacion: la configuracion pide lo maximo. El canal no lo permite,
        // porque el enjambre llega a maquinas que el atacante puede haber
        // comprometido — y eso no es una hipotesis, es el supuesto de la FASE 68.
        let d = difusor_completo();
        let flota = d.destino("flota").expect("declarado");
        assert_eq!(flota.tope_tlp, Tlp::Red, "la configuracion pide el maximo");
        assert_eq!(flota.tope_efectivo(), Tlp::Green, "y el canal lo baja");

        let ambar = objeto(
            "indicator--ambar",
            Marcado::nuevo(Tlp::AmberStrict, Pap::Clear),
        );
        let r = d.repartir(&paquete(vec![ambar]), "flota").expect("destino");
        assert!(r.salen.is_empty());
        let (_, motivo) = &r.retenidos[0];
        assert!(matches!(motivo, Retenido::PorTopeDuroDelCanal { .. }));
        // Y el informe dice que NO se arregla configurando.
        assert!(!motivo.configurable());
        assert!(motivo.texto().contains("NO se arregla configurando"));
    }

    #[test]
    fn el_enjambre_no_reparte_lo_que_no_se_puede_bloquear() {
        // Lo que llega a los agentes acaba en el motor de bloqueo: un PAP:RED
        // repartido por la malla quema la operacion de quien lo compartio en cien
        // mil maquinas a la vez.
        let d = difusor_completo();
        let no_tocar = objeto("indicator--c2", Marcado::nuevo(Tlp::Green, Pap::Red));
        let r = d
            .repartir(&paquete(vec![no_tocar]), "flota")
            .expect("destino");
        assert!(r.salen.is_empty());
        assert!(matches!(r.retenidos[0].1, Retenido::PorPap { .. }));

        // Y por TAXII el mismo objeto SI sale: compartirlo esta bien, bloquearlo
        // no. Son dos preguntas distintas y por eso hay dos ejes.
        let r = d
            .repartir(
                &paquete(vec![objeto(
                    "indicator--c2",
                    Marcado::nuevo(Tlp::Green, Pap::Red),
                )]),
                "comunidad",
            )
            .expect("destino");
        assert_eq!(r.salen.len(), 1);
    }

    #[test]
    fn amber_strict_no_sale_de_la_organizacion_aunque_el_tope_lo_permitiera() {
        let mut d = Difusor::nuevo();
        // Un socio configurado generosamente, pero que no es la propia
        // organizacion.
        d.declarar(destino("socio", Canal::Federacion, Tlp::Red, false));
        d.declarar(destino("nosotros", Canal::Federacion, Tlp::Red, true));

        let estricto = objeto("indicator--x", Marcado::nuevo(Tlp::Amber, Pap::Clear));
        let p = paquete(vec![estricto]);

        let fuera = d.repartir(&p, "socio").expect("destino");
        assert_eq!(fuera.retenidos[0].1, Retenido::FueraDeLaOrganizacion);
        let dentro = d.repartir(&p, "nosotros").expect("destino");
        assert_eq!(dentro.salen.len(), 1);
    }

    #[test]
    fn lo_verde_sale_a_la_comunidad_y_lo_ambar_no() {
        let d = difusor_completo();
        let p = paquete(vec![
            objeto("indicator--verde", Marcado::nuevo(Tlp::Green, Pap::Clear)),
            objeto(
                "indicator--ambar",
                Marcado::nuevo(Tlp::AmberStrict, Pap::Clear),
            ),
        ]);
        let r = d.repartir(&p, "comunidad").expect("destino");
        assert_eq!(r.salen, vec!["indicator--verde".to_string()]);
        assert_eq!(r.retenidos.len(), 1);
        assert!(matches!(r.retenidos[0].1, Retenido::PorTlp { .. }));
        assert!(r.retenidos[0].1.configurable());
    }

    #[test]
    fn un_destino_no_declarado_se_rechaza_en_vez_de_resolverse_a_permisivo() {
        // Un valor por defecto permisivo aqui es una fuga con una errata de por
        // medio.
        let d = difusor_completo();
        let e = d
            .repartir(&paquete(vec![]), "el-que-escribi-mal")
            .expect_err("no declarado");
        assert!(e.contains("no se reparte a ciegas"));
    }

    #[test]
    fn un_objeto_revocado_no_sale_ni_a_lo_mas_abierto() {
        let mut o = objeto("indicator--viejo", Marcado::publico());
        o.revocado = true;
        let d = difusor_completo();
        for nombre in ["comunidad", "socio", "interno", "flota", "fichero"] {
            let r = d
                .repartir(&paquete(vec![o.clone()]), nombre)
                .expect("destino");
            assert!(r.salen.is_empty(), "salio por {nombre}");
            assert_eq!(r.retenidos[0].1, Retenido::Revocado);
        }
    }

    #[test]
    fn lo_publico_sale_por_todos_los_caminos() {
        // La otra mitad del contrato: si no saliera nada, la propiedad se
        // cumpliria trivialmente y el modulo seria un tapon.
        let p = paquete(vec![objeto("indicator--abierto", Marcado::publico())]);
        let d = difusor_completo();
        for (nombre, r) in d.repartir_a_todos(&p) {
            assert_eq!(r.salen.len(), 1, "no salio por «{nombre}»");
        }
    }

    #[test]
    fn todo_motivo_de_retencion_se_explica() {
        // Un objeto retenido sin motivo se lee como «no habia nada que mandar», y
        // entonces nadie revisa un reparto que se esta quedando corto.
        let casos = [
            Retenido::PorTlp {
                objeto: Tlp::Red,
                tope: Tlp::Green,
            },
            Retenido::PorTopeDuroDelCanal {
                canal: Canal::Enjambre,
                objeto: Tlp::Amber,
                tope: Tlp::Green,
            },
            Retenido::PorPap {
                canal: Canal::Enjambre,
                objeto: Pap::Red,
                exigido: Pap::Green,
            },
            Retenido::FueraDeLaOrganizacion,
            Retenido::Revocado,
        ];
        for c in &casos {
            assert!(c.texto().len() > 20, "{c:?} no se explica");
            assert!(!c.nombre().is_empty());
        }
    }

    #[test]
    fn el_reparto_se_resume_con_sus_motivos() {
        let d = difusor_completo();
        let p = paquete(vec![
            objeto("indicator--a", Marcado::publico()),
            objeto("indicator--b", Marcado::nuevo(Tlp::Red, Pap::Clear)),
            objeto("indicator--c", Marcado::nuevo(Tlp::AmberStrict, Pap::Clear)),
        ]);
        let r = d.repartir(&p, "comunidad").expect("destino");
        assert_eq!(r.salen.len(), 1);
        // El TLP:RED no cuenta como «por-tlp» sino como «no-distribuible»: no lo
        // retiene el tope del destino, lo retiene que no hay canal que lo lleve.
        // Distinguirlos importa porque uno se arregla configurando y el otro no.
        assert_eq!(r.por_motivo().get("no-distribuible"), Some(&1));
        assert_eq!(r.por_motivo().get("por-tlp"), Some(&1));
        assert!(r.resumen("comunidad").contains("salen 1"));
    }

    #[test]
    fn el_reparto_es_determinista() {
        // Dos ejecuciones tienen que dar exactamente lo mismo, o un informe de
        // difusion no se puede comparar con el del dia anterior.
        let d = difusor_completo();
        let p = paquete(vec![
            objeto("indicator--a", Marcado::publico()),
            objeto("indicator--b", Marcado::nuevo(Tlp::Red, Pap::Clear)),
            objeto("indicator--c", Marcado::nuevo(Tlp::Green, Pap::Red)),
        ]);
        assert_eq!(
            d.repartir(&p, "flota").expect("d"),
            d.repartir(&p, "flota").expect("d")
        );
    }
}
