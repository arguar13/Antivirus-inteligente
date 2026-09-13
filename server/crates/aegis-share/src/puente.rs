//! El puente al enjambre: la inteligencia llega a los agentes aislados.
//!
//! # Aqui se cobra el trabajo de la FASE 68, sin tocar su doctrina
//!
//! El enjambre existe para cuando el plano de control **deja de estar**: un
//! adversario competente no ataca la flota de frente, le corta el habla. A partir
//! de ese momento cada endpoint esta solo, y lo que sepa es lo unico que tiene.
//!
//! Lo que este modulo hace es que lo que sabe sea **lo que llego por TAXII esta
//! mañana** y no lo de la ultima actualizacion completa. Nada mas, y nada menos.
//!
//! # La doctrina se conserva INTACTA, y esa es la mitad del modulo
//!
//! > **El enjambre transporta autoridad; no la concede.**
//!
//! Un indicador que llega por federacion, por muy fiable que sea su fuente, **no
//! se convierte en una orden**. Lo que cruza la malla es de dos clases y ninguna
//! manda nada:
//!
//! | Clase | Que es | Que hace falta para actuar |
//! |---|---|---|
//! | [`Carga::Observacion`] | Evidencia: «se ha visto esto» | K pares distintos corroborando ([`quorum`]) |
//! | [`Carga::Artefacto`] | Un conjunto de indicadores | Firma del plano de control sobre el descriptor |
//!
//! **No hay una tercera variante que sea una orden**, y esa ausencia es
//! deliberada: es la misma tecnica que en `aegis-detonate` —donde [`Salida`] no
//! tiene variante para «red de verdad»— y en `orden::Accion::gossipable`. Lo que
//! no se puede expresar no se puede configurar por error.
//!
//! Si un dia hiciera falta que un indicador federado provocara una contencion,
//! **no se haria aqui**: haria falta que el plano de control emitiera una orden
//! firmada, con su epoca y su ventana, igual que cualquier otra. Este puente no
//! es un atajo a eso, y no lo va a ser mientras la variante no exista.
//!
//! # Y los dos topes que no se pueden subir
//!
//! Estan en [`crate::difusion::Canal::Enjambre`] y se repiten aqui porque es
//! donde se entienden: el enjambre llega a **todos** los agentes, incluidos los
//! que corren en maquinas que el atacante puede haber comprometido. Nada por
//! encima de `TLP:GREEN` viaja por ahi, y nada que no permita bloqueo propio
//! tampoco.
//!
//! [`quorum`]: https://docs.rs/aegis-swarm
//! [`Salida`]: https://docs.rs/aegis-detonate

use std::collections::BTreeMap;

use crate::difusion::{Canal, Destino, Difusor, Retenido};
use crate::procedencia::{Fiabilidad, Registro};
use crate::stix::{Objeto, Paquete, Tipo};

/// Indicadores maximos en un artefacto que cruza la malla.
///
/// Dos mil. El enjambre reparte por trozos entre agentes con memoria acotada —el
/// presupuesto del agente va de 48 a 384 MiB segun la clase de maquina— y un
/// artefacto de un millon de indicadores no es un artefacto grande: es un
/// artefacto que la mitad de la flota no puede recibir.
pub const MAX_POR_ARTEFACTO: usize = 2000;

/// Confianza minima para que algo cruce la malla.
///
/// Setenta. Lo que cruza acaba en el motor de bloqueo de cada endpoint, y un
/// falso positivo repartido por la malla se convierte en una interrupcion de
/// servicio en toda la flota — con el plano de control caido, que es cuando el
/// enjambre se usa, y por tanto sin nadie a quien pedirle que lo retire.
pub const CONFIANZA_MINIMA: u8 = 70;

/// Fiabilidad minima de la fuente para que algo cruce.
///
/// Un canal abierto no reparte nada por la malla de la flota. Cualquiera puede
/// envenenar uno sin identificarse, y el coste de equivocarse aqui lo pagan cien
/// mil endpoints a la vez.
pub const FIABILIDAD_MINIMA: Fiabilidad = Fiabilidad::Comunidad;

/// Un indicador listo para cruzar, ya reducido a lo que un agente entiende.
///
/// Es deliberadamente pobre: el agente no necesita el objeto STIX entero, y
/// mandarselo gastaria memoria suya —que esta contada— en campos que no va a
/// mirar. Los tipos son los de `aegis-sync::IocKind`, para que el agente no tenga
/// que traducir nada.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Indicador {
    /// Que clase de cosa es: `file-sha256`, `domain`, `ip`, `yara-rule`.
    pub clase: &'static str,
    /// El valor.
    pub valor: String,
    /// Confianza, en centesimas.
    pub confianza: u8,
}

/// Lo que puede cruzar la malla.
///
/// **No hay variante que sea una orden.** Ver el encabezado del modulo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Carga {
    /// Evidencia: alguien ha visto esto.
    ///
    /// No manda nada. Lo que convierte evidencia en accion es el corroboro de K
    /// pares distintos, que decide el enjambre y no este modulo.
    Observacion {
        /// Los indicadores vistos.
        indicadores: Vec<Indicador>,
    },
    /// Un conjunto de indicadores que el plano de control **ya firmo**.
    ///
    /// La firma no se hace aqui: este modulo prepara el contenido y declara que
    /// exige firma. Quien la pone es el plano de control, cuya clave privada no
    /// esta en ningun agente — ni en este crate.
    Artefacto {
        /// Los indicadores.
        indicadores: Vec<Indicador>,
        /// Resumen del contenido, para que el descriptor firmado lo cubra.
        resumen: String,
    },
}

impl Carga {
    /// Cuantos indicadores lleva.
    #[must_use]
    pub fn cuantos(&self) -> usize {
        match self {
            Carga::Observacion { indicadores } | Carga::Artefacto { indicadores, .. } => {
                indicadores.len()
            }
        }
    }

    /// Si esto necesita la firma del plano de control para valer de algo.
    #[must_use]
    pub fn exige_firma(&self) -> bool {
        matches!(self, Carga::Artefacto { .. })
    }

    /// Nombre estable.
    #[must_use]
    pub fn nombre(&self) -> &'static str {
        match self {
            Carga::Observacion { .. } => "observacion",
            Carga::Artefacto { .. } => "artefacto",
        }
    }
}

/// Por que un objeto no cruza la malla.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoCruza {
    /// La difusion lo retuvo.
    Difusion(Retenido),
    /// No es un indicador con patron.
    NoEsIndicador,
    /// El patron no se puede reducir a algo que un agente entienda.
    PatronNoTraducible {
        /// El patron.
        patron: String,
    },
    /// Confianza por debajo del minimo.
    ConfianzaInsuficiente {
        /// La que tiene.
        confianza: u8,
    },
    /// Fuente por debajo de la fiabilidad minima.
    FuenteInsuficiente {
        /// La que tiene.
        fiabilidad: Option<Fiabilidad>,
    },
    /// Sin procedencia: no se sabe de donde vino.
    SinProcedencia,
}

impl NoCruza {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(&self) -> &'static str {
        match self {
            NoCruza::Difusion(_) => "difusion",
            NoCruza::NoEsIndicador => "no-es-indicador",
            NoCruza::PatronNoTraducible { .. } => "patron-no-traducible",
            NoCruza::ConfianzaInsuficiente { .. } => "confianza-insuficiente",
            NoCruza::FuenteInsuficiente { .. } => "fuente-insuficiente",
            NoCruza::SinProcedencia => "sin-procedencia",
        }
    }

    /// Texto para el informe.
    #[must_use]
    pub fn texto(&self) -> String {
        match self {
            NoCruza::Difusion(r) => r.texto(),
            NoCruza::NoEsIndicador => "no es un indicador con patron".to_string(),
            NoCruza::PatronNoTraducible { patron } => format!(
                "el patron «{patron}» no se reduce a algo que un agente entienda; mandarselo sin \
                 traducir le haria gastar memoria en algo que no puede evaluar"
            ),
            NoCruza::ConfianzaInsuficiente { confianza } => format!(
                "confianza {confianza} por debajo de {CONFIANZA_MINIMA}: lo que cruza acaba en el \
                 motor de bloqueo de cada endpoint, y un falso positivo repartido por la malla es \
                 una interrupcion en toda la flota — con el plano de control caido, que es cuando \
                 el enjambre se usa"
            ),
            NoCruza::FuenteInsuficiente { fiabilidad } => format!(
                "la fuente es «{}» y hace falta al menos «{}»: cualquiera puede envenenar un canal \
                 abierto sin identificarse, y el coste lo pagan cien mil endpoints a la vez",
                fiabilidad.map_or("ninguna", Fiabilidad::nombre),
                FIABILIDAD_MINIMA.nombre()
            ),
            NoCruza::SinProcedencia => {
                "no consta de donde vino, y sin procedencia no se puede revertir si resulta \
                 envenenado"
                    .to_string()
            }
        }
    }
}

/// Lo que el puente decidio.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Preparado {
    /// Las cargas listas para la malla.
    pub cargas: Vec<Carga>,
    /// Lo que no cruza, con su motivo.
    pub descartados: Vec<(String, NoCruza)>,
}

impl Preparado {
    /// Cuantos indicadores cruzan en total.
    #[must_use]
    pub fn indicadores(&self) -> usize {
        self.cargas.iter().map(Carga::cuantos).sum()
    }

    /// Cuentas por motivo.
    #[must_use]
    pub fn por_motivo(&self) -> BTreeMap<&'static str, usize> {
        let mut m = BTreeMap::new();
        for (_, d) in &self.descartados {
            *m.entry(d.nombre()).or_insert(0) += 1;
        }
        m
    }

    /// Resumen legible.
    #[must_use]
    pub fn resumen(&self) -> String {
        format!(
            "cruzan {} indicador(es) en {} carga(s); se quedan {} ({})",
            self.indicadores(),
            self.cargas.len(),
            self.descartados.len(),
            self.por_motivo()
                .iter()
                .map(|(k, v)| format!("{k}: {v}"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

/// El puente.
#[derive(Debug)]
pub struct Puente {
    destino: Destino,
}

impl Puente {
    /// Crea el puente hacia la flota.
    ///
    /// El destino se construye aqui y **no se recibe de fuera**: si se recibiera,
    /// alguien podria pasarle uno con canal `Taxii`, y entonces los topes duros
    /// del enjambre no se aplicarian. El canal lo fija el puente porque el puente
    /// sabe a donde va.
    #[must_use]
    pub fn nuevo(nombre_flota: &str) -> Puente {
        Puente {
            destino: Destino {
                nombre: nombre_flota.to_string(),
                canal: Canal::Enjambre,
                // Se pide el maximo a proposito: los topes duros del canal lo
                // bajan a TLP:GREEN, y que esten aqui puestos al maximo enseña que
                // el que manda es el canal y no la configuracion.
                tope_tlp: crate::marcado::Tlp::Red,
                es_propia_organizacion: true,
            },
        }
    }

    /// El destino, para poder auditarlo.
    #[must_use]
    pub fn destino(&self) -> &Destino {
        &self.destino
    }

    /// Prepara lo que puede cruzar la malla.
    ///
    /// `como_artefacto` decide la clase de carga. Si es `true`, lo que salga
    /// **exige la firma del plano de control** para valer de algo en el otro
    /// extremo; si es `false`, sale como evidencia y hace falta corroboro de K
    /// pares. Las dos son validas y ninguna es una orden.
    #[must_use]
    pub fn preparar(
        &self,
        paquete: &Paquete,
        procedencia: &Registro,
        ahora_ns: u64,
        como_artefacto: bool,
    ) -> Preparado {
        let mut p = Preparado::default();
        let mut indicadores: Vec<Indicador> = Vec::new();

        for o in paquete.objetos.values() {
            match self.juzgar(o, procedencia, ahora_ns) {
                Err(motivo) => p.descartados.push((o.id.clone(), motivo)),
                Ok(ind) => indicadores.push(ind),
            }
        }
        indicadores.sort();
        indicadores.dedup();

        // Se trocea: el enjambre reparte entre agentes con memoria contada, y un
        // artefacto de un millon de indicadores no es grande, es irrecibible para
        // media flota.
        for trozo in indicadores.chunks(MAX_POR_ARTEFACTO) {
            let v = trozo.to_vec();
            p.cargas.push(if como_artefacto {
                let resumen = resumen_de(&v);
                Carga::Artefacto {
                    indicadores: v,
                    resumen,
                }
            } else {
                Carga::Observacion { indicadores: v }
            });
        }
        p.descartados.sort_by(|a, b| a.0.cmp(&b.0));
        p
    }

    /// Si un objeto puede cruzar, y en que se convierte.
    ///
    /// # Errors
    ///
    /// Devuelve el motivo por el que no cruza.
    pub fn juzgar(
        &self,
        o: &Objeto,
        procedencia: &Registro,
        ahora_ns: u64,
    ) -> Result<Indicador, NoCruza> {
        // 1 · El estrangulamiento de difusion, el mismo que TAXII y la federacion.
        Difusor::juzgar(o, &self.destino).map_err(NoCruza::Difusion)?;

        // 2 · Tiene que ser algo que un agente pueda evaluar.
        if o.tipo != Tipo::Indicator {
            return Err(NoCruza::NoEsIndicador);
        }
        let patron = o.patron().ok_or(NoCruza::NoEsIndicador)?;
        let (clase, valor) = traducir(patron).ok_or_else(|| NoCruza::PatronNoTraducible {
            patron: patron.chars().take(120).collect(),
        })?;

        // 3 · La procedencia manda. Sin ella no cruza nada: no se puede revertir
        //     lo que no se sabe de donde vino.
        let ficha = procedencia.ficha(&o.id).ok_or(NoCruza::SinProcedencia)?;
        let fiabilidad = ficha.mejor_fiabilidad(ahora_ns);
        match fiabilidad {
            Some(f) if f <= FIABILIDAD_MINIMA => {}
            otra => return Err(NoCruza::FuenteInsuficiente { fiabilidad: otra }),
        }
        let confianza = ficha.confianza(ahora_ns);
        if confianza < CONFIANZA_MINIMA {
            return Err(NoCruza::ConfianzaInsuficiente { confianza });
        }

        Ok(Indicador {
            clase,
            valor,
            confianza,
        })
    }
}

/// Reduce un patron STIX a (clase, valor), o `None` si no se puede.
///
/// # Por que solo estas cuatro formas
///
/// El lenguaje de patrones de STIX es un lenguaje entero, con comparadores,
/// conjunciones y ventanas temporales. Un agente no lo evalua —no tiene sitio
/// para un interprete, y meterselo seria meterle un analizador de entrada hostil
/// en el proceso mas privilegiado del endpoint—.
///
/// Lo que si evalua son las cuatro comparaciones de igualdad que cubren la
/// practica totalidad de los indicadores compartidos. Lo demas **se declara no
/// traducible** en vez de traducirse a medias: un patron traducido a medias
/// detecta otra cosa que la que su autor escribio, y eso es peor que no
/// detectarlo.
#[must_use]
pub fn traducir(patron: &str) -> Option<(&'static str, String)> {
    let p = patron.trim();
    let p = p.strip_prefix('[')?.strip_suffix(']')?.trim();
    // Una conjuncion o disyuncion es un patron compuesto: no se traduce a medias.
    if p.contains(" AND ") || p.contains(" OR ") || p.contains(" FOLLOWEDBY ") {
        return None;
    }
    let (izq, der) = p.split_once('=')?;
    let valor = der.trim().trim_matches('\'').trim_matches('"').trim();
    if valor.is_empty() || valor.len() > 512 {
        return None;
    }
    let campo = izq.trim().to_ascii_lowercase().replace([' ', '\''], "");
    let clase = match campo.as_str() {
        "file:hashes.sha-256" | "file:hashes.sha256" => "file-sha256",
        "domain-name:value" => "domain",
        "ipv4-addr:value" | "ipv6-addr:value" => "ip",
        "url:value" => "url",
        _ => return None,
    };
    Some((clase, valor.to_string()))
}

/// Resumen del contenido de un artefacto, para que el descriptor firmado lo cubra.
fn resumen_de(indicadores: &[Indicador]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for i in indicadores {
        h.update(i.clase.as_bytes());
        h.update([0x1f]);
        h.update(i.valor.as_bytes());
        h.update([0x1f]);
    }
    let d = h.finalize();
    let mut s = String::with_capacity(64);
    use std::fmt::Write as _;
    for b in d.iter() {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::marcado::{Marcado, Pap, Tlp};
    use crate::procedencia::Aporte;
    use serde_json::{Map, Value};

    const SEG: u64 = 1_000_000_000;
    const AHORA: u64 = 1_700_000_000 * SEG;

    fn indicador(id: &str, patron: &str, m: Marcado) -> Objeto {
        let mut crudo = Map::new();
        crudo.insert("pattern".into(), Value::String(patron.into()));
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

    fn paquete(objetos: Vec<Objeto>) -> Paquete {
        Paquete {
            id: "bundle--x".into(),
            objetos: objetos.into_iter().map(|o| (o.id.clone(), o)).collect(),
        }
    }

    fn con_procedencia(ids: &[&str], f: Fiabilidad, confianza: u8) -> Registro {
        let mut r = Registro::nuevo();
        for id in ids {
            r.anotar(
                id,
                Aporte {
                    fuente: "socio".into(),
                    fiabilidad: f,
                    cadena: vec![],
                    cuando_ns: AHORA,
                    confianza_declarada: confianza,
                    id_en_origen: (*id).to_string(),
                },
            );
        }
        r
    }

    #[test]
    fn no_existe_ninguna_variante_que_sea_una_orden() {
        // LA MITAD DEL MODULO. El enjambre transporta autoridad; no la concede.
        // Lo que no se puede expresar no se puede configurar por error.
        let p = Puente::nuevo("flota");
        let obs = Carga::Observacion {
            indicadores: vec![],
        };
        let art = Carga::Artefacto {
            indicadores: vec![],
            resumen: String::new(),
        };
        // Solo hay dos clases, y la que pretende actuar exige firma del plano de
        // control — cuya clave no esta ni en el agente ni en este crate.
        assert!(!obs.exige_firma(), "una observacion es evidencia, no manda");
        assert!(art.exige_firma(), "un artefacto exige firma para valer");
        assert_eq!(p.destino().canal, Canal::Enjambre);
    }

    #[test]
    fn el_puente_fija_el_canal_y_no_lo_recibe() {
        // Si lo recibiera, alguien podria pasarle uno con canal Taxii y los topes
        // duros del enjambre no se aplicarian.
        let p = Puente::nuevo("flota");
        assert_eq!(
            p.destino().tope_tlp,
            Tlp::Red,
            "la configuracion pide el maximo"
        );
        assert_eq!(
            p.destino().tope_efectivo(),
            Tlp::Green,
            "y el canal lo baja"
        );
    }

    #[test]
    fn lo_que_pasa_de_verde_no_cruza_la_malla() {
        // El enjambre llega a maquinas que el atacante puede haber comprometido:
        // es el supuesto de la FASE 68, no una hipotesis.
        let p = Puente::nuevo("flota");
        let o = indicador(
            "indicator--a",
            "[domain-name:value = 'malo.example']",
            Marcado::nuevo(Tlp::Amber, Pap::Clear),
        );
        let reg = con_procedencia(&["indicator--a"], Fiabilidad::Propia, 99);
        let r = p.preparar(&paquete(vec![o]), &reg, AHORA, false);
        assert_eq!(r.indicadores(), 0);
        assert!(matches!(
            r.descartados[0].1,
            NoCruza::Difusion(Retenido::PorTopeDuroDelCanal { .. })
        ));
    }

    #[test]
    fn lo_que_no_se_puede_bloquear_no_cruza_la_malla() {
        // Un PAP:RED repartido por la malla quema la operacion de quien lo
        // compartio en cien mil maquinas a la vez.
        let p = Puente::nuevo("flota");
        let o = indicador(
            "indicator--c2",
            "[domain-name:value = 'c2.example']",
            Marcado::nuevo(Tlp::Green, Pap::Red),
        );
        let reg = con_procedencia(&["indicator--c2"], Fiabilidad::Propia, 99);
        let r = p.preparar(&paquete(vec![o]), &reg, AHORA, false);
        assert_eq!(r.indicadores(), 0);
        assert!(matches!(
            r.descartados[0].1,
            NoCruza::Difusion(Retenido::PorPap { .. })
        ));
    }

    #[test]
    fn un_canal_abierto_no_reparte_nada_por_la_flota() {
        // Cualquiera puede envenenar uno sin identificarse, y el coste de
        // equivocarse lo pagan cien mil endpoints a la vez.
        let p = Puente::nuevo("flota");
        let o = indicador(
            "indicator--a",
            "[domain-name:value = 'malo.example']",
            Marcado::nuevo(Tlp::Green, Pap::Clear),
        );
        let reg = con_procedencia(&["indicator--a"], Fiabilidad::Abierta, 100);
        let r = p.preparar(&paquete(vec![o]), &reg, AHORA, false);
        assert_eq!(r.indicadores(), 0);
        assert!(matches!(
            r.descartados[0].1,
            NoCruza::FuenteInsuficiente { .. }
        ));
    }

    #[test]
    fn sin_procedencia_no_cruza_nada() {
        // No se puede revertir lo que no se sabe de donde vino.
        let p = Puente::nuevo("flota");
        let o = indicador(
            "indicator--huerfano",
            "[domain-name:value = 'malo.example']",
            Marcado::nuevo(Tlp::Green, Pap::Clear),
        );
        let r = p.preparar(&paquete(vec![o]), &Registro::nuevo(), AHORA, false);
        assert_eq!(r.descartados[0].1, NoCruza::SinProcedencia);
    }

    #[test]
    fn la_confianza_baja_no_cruza() {
        let p = Puente::nuevo("flota");
        let o = indicador(
            "indicator--dudoso",
            "[domain-name:value = 'quiza.example']",
            Marcado::nuevo(Tlp::Green, Pap::Clear),
        );
        let reg = con_procedencia(&["indicator--dudoso"], Fiabilidad::Comunidad, 30);
        let r = p.preparar(&paquete(vec![o]), &reg, AHORA, false);
        assert!(matches!(
            r.descartados[0].1,
            NoCruza::ConfianzaInsuficiente { .. }
        ));
    }

    #[test]
    fn lo_que_cumple_todo_si_cruza() {
        // La otra mitad del contrato: si no cruzara nada, la propiedad se
        // cumpliria trivialmente y el puente seria un tapon.
        let p = Puente::nuevo("flota");
        let objetos = vec![
            indicador(
                "indicator--a",
                "[domain-name:value = 'malo.example']",
                Marcado::nuevo(Tlp::Green, Pap::Clear),
            ),
            indicador(
                "indicator--b",
                "[file:hashes.'SHA-256' = '7f1e3c9b']",
                Marcado::nuevo(Tlp::Clear, Pap::Green),
            ),
        ];
        let reg = con_procedencia(&["indicator--a", "indicator--b"], Fiabilidad::Propia, 95);
        let r = p.preparar(&paquete(objetos), &reg, AHORA, false);
        assert_eq!(r.indicadores(), 2);
        assert_eq!(r.cargas.len(), 1);
        assert_eq!(r.cargas[0].nombre(), "observacion");
    }

    #[test]
    fn un_artefacto_lleva_resumen_y_exige_firma() {
        let p = Puente::nuevo("flota");
        let o = indicador(
            "indicator--a",
            "[domain-name:value = 'malo.example']",
            Marcado::nuevo(Tlp::Green, Pap::Clear),
        );
        let reg = con_procedencia(&["indicator--a"], Fiabilidad::Propia, 95);
        let r = p.preparar(&paquete(vec![o]), &reg, AHORA, true);
        let Carga::Artefacto { resumen, .. } = &r.cargas[0] else {
            panic!("deberia ser artefacto");
        };
        assert_eq!(resumen.len(), 64, "el resumen cubre el contenido");
        assert!(r.cargas[0].exige_firma());
    }

    #[test]
    fn el_resumen_del_artefacto_cambia_si_cambia_el_contenido() {
        // Si no cambiara, una firma valida cubriria un contenido distinto.
        let a = resumen_de(&[Indicador {
            clase: "domain",
            valor: "a.example".into(),
            confianza: 90,
        }]);
        let b = resumen_de(&[Indicador {
            clase: "domain",
            valor: "b.example".into(),
            confianza: 90,
        }]);
        assert_ne!(a, b);
    }

    #[test]
    fn se_trocea_para_que_quepa_en_un_agente() {
        // El presupuesto del agente va de 48 a 384 MiB: un artefacto de un millon
        // de indicadores no es grande, es irrecibible para media flota.
        let p = Puente::nuevo("flota");
        let objetos: Vec<Objeto> = (0..(MAX_POR_ARTEFACTO * 2 + 10))
            .map(|i| {
                indicador(
                    &format!("indicator--{i:06}"),
                    &format!("[domain-name:value = 'd{i}.example']"),
                    Marcado::nuevo(Tlp::Green, Pap::Clear),
                )
            })
            .collect();
        let ids: Vec<String> = objetos.iter().map(|o| o.id.clone()).collect();
        let refs: Vec<&str> = ids.iter().map(String::as_str).collect();
        let reg = con_procedencia(&refs, Fiabilidad::Propia, 95);

        let r = p.preparar(&paquete(objetos), &reg, AHORA, true);
        assert_eq!(r.cargas.len(), 3);
        for c in &r.cargas {
            assert!(c.cuantos() <= MAX_POR_ARTEFACTO);
        }
        assert_eq!(r.indicadores(), MAX_POR_ARTEFACTO * 2 + 10);
    }

    #[test]
    fn un_patron_compuesto_se_declara_no_traducible_en_vez_de_traducirse_a_medias() {
        // Un patron traducido a medias detecta otra cosa que la que su autor
        // escribio, y eso es peor que no detectarlo.
        assert!(traducir("[domain-name:value = 'a.example' AND url:value = 'x']").is_none());
        assert!(traducir("[a:b = '1' OR c:d = '2']").is_none());
        assert!(traducir("[ipv4-addr:value = '1.2.3.4'] FOLLOWEDBY [x:y = 'z']").is_none());
        assert!(traducir("[file:size > 1024]").is_none());
        assert!(traducir("[proceso:raro = 'x']").is_none());
        assert!(traducir("").is_none());
        assert!(traducir("sin corchetes").is_none());
    }

    #[test]
    fn las_cuatro_formas_que_un_agente_entiende_se_traducen() {
        assert_eq!(
            traducir("[file:hashes.'SHA-256' = '7f1e']"),
            Some(("file-sha256", "7f1e".to_string()))
        );
        assert_eq!(
            traducir("[domain-name:value = 'malo.example']"),
            Some(("domain", "malo.example".to_string()))
        );
        assert_eq!(
            traducir("[ipv4-addr:value = '8.8.8.8']"),
            Some(("ip", "8.8.8.8".to_string()))
        );
        assert_eq!(
            traducir("[url:value = 'https://malo.example/a']"),
            Some(("url", "https://malo.example/a".to_string()))
        );
        // Y la forma IPv6 va a la misma clase: un agente no distingue.
        assert_eq!(
            traducir("[ipv6-addr:value = '2001:db8::1']"),
            Some(("ip", "2001:db8::1".to_string()))
        );
    }

    #[test]
    fn un_objeto_que_no_es_indicador_no_cruza() {
        let p = Puente::nuevo("flota");
        let mut o = indicador("malware--m", "", Marcado::nuevo(Tlp::Green, Pap::Clear));
        o.tipo = Tipo::Malware;
        o.id = "malware--m".into();
        let reg = con_procedencia(&["malware--m"], Fiabilidad::Propia, 95);
        let r = p.preparar(&paquete(vec![o]), &reg, AHORA, false);
        assert_eq!(r.descartados[0].1, NoCruza::NoEsIndicador);
    }

    #[test]
    fn todo_motivo_se_explica() {
        let casos = [
            NoCruza::Difusion(Retenido::Revocado),
            NoCruza::NoEsIndicador,
            NoCruza::PatronNoTraducible {
                patron: "[x > 1]".into(),
            },
            NoCruza::ConfianzaInsuficiente { confianza: 10 },
            NoCruza::FuenteInsuficiente {
                fiabilidad: Some(Fiabilidad::Abierta),
            },
            NoCruza::SinProcedencia,
        ];
        for c in &casos {
            assert!(c.texto().len() > 15, "{c:?} no se explica");
            assert!(!c.nombre().is_empty());
        }
    }

    #[test]
    fn el_preparado_se_resume() {
        let p = Puente::nuevo("flota");
        let objetos = vec![
            indicador(
                "indicator--ok",
                "[domain-name:value = 'a.example']",
                Marcado::nuevo(Tlp::Green, Pap::Clear),
            ),
            indicador(
                "indicator--no",
                "[domain-name:value = 'b.example']",
                Marcado::nuevo(Tlp::Red, Pap::Clear),
            ),
        ];
        let reg = con_procedencia(&["indicator--ok", "indicator--no"], Fiabilidad::Propia, 95);
        let r = p.preparar(&paquete(objetos), &reg, AHORA, false);
        assert!(r.resumen().contains("cruzan 1"));
        assert_eq!(r.por_motivo().get("difusion"), Some(&1));
    }
}
