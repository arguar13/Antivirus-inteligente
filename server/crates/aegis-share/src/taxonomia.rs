//! Etiquetado estructurado: taxonomias y galaxias.
//!
//! # Una etiqueta de texto libre no es una etiqueta, es una nota
//!
//! El valor de etiquetar no esta en poner la etiqueta: esta en poder **preguntar
//! por ella**. Y con texto libre, en seis meses la misma cosa esta escrita de
//! cuatro formas —`lockbit`, `LockBit`, `LockBit 3.0`, `familia:lockbit`— y
//! ninguna consulta las encuentra todas. El etiquetado deja de servir sin que
//! nadie lo note, porque las etiquetas siguen ahi.
//!
//! Por eso una etiqueta es `espacio:predicado="valor"` con los tres validados
//! contra una taxonomia declarada, y lo que no valida **se rechaza al entrar**.
//! Guardarlo «por si acaso» es exactamente como se llega a las cuatro formas.
//!
//! # Las galaxias, y el problema que resuelven
//!
//! El mismo actor se llama `APT29` en un informe, `Cozy Bear` en otro y
//! `Nobelium` en un tercero. Son el mismo, y una base que los trate como tres no
//! junta nunca lo que se sabe de el — que es justo lo que hace falta.
//!
//! Una galaxia es un conjunto de **grupos con sinonimos**: los tres nombres
//! resuelven al mismo identificador, y a partir de ahi las tres fuentes hablan de
//! lo mismo.

use std::collections::{BTreeMap, BTreeSet};

/// Longitud maxima de cualquier parte de una etiqueta.
pub const MAX_PARTE: usize = 128;

/// Una etiqueta estructurada.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Etiqueta {
    /// Espacio de nombres de la taxonomia.
    pub espacio: String,
    /// Predicado dentro de ese espacio.
    pub predicado: String,
    /// Valor, si el predicado lo lleva.
    pub valor: Option<String>,
}

impl Etiqueta {
    /// Escribe la etiqueta en su forma canonica.
    #[must_use]
    pub fn texto(&self) -> String {
        match &self.valor {
            Some(v) => format!("{}:{}=\"{}\"", self.espacio, self.predicado, v),
            None => format!("{}:{}", self.espacio, self.predicado),
        }
    }

    /// Lee una etiqueta escrita.
    ///
    /// Devuelve `None` si no tiene la forma. **No hay modo tolerante**: una
    /// etiqueta que no se entiende no se guarda como texto libre, porque guardarla
    /// «por si acaso» es exactamente como se llega a tener la misma cosa escrita
    /// de cuatro formas.
    #[must_use]
    pub fn de_texto(s: &str) -> Option<Etiqueta> {
        let s = s.trim();
        if s.is_empty() || s.len() > MAX_PARTE * 3 {
            return None;
        }
        let (espacio, resto) = s.split_once(':')?;
        let (predicado, valor) = match resto.split_once('=') {
            Some((p, v)) => {
                let v = v.trim().trim_matches('"');
                if v.is_empty() {
                    return None;
                }
                (p, Some(v.to_string()))
            }
            None => (resto, None),
        };
        let valido = |x: &str| {
            !x.is_empty()
                && x.len() <= MAX_PARTE
                && x.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
        };
        if !valido(espacio) || !valido(predicado) {
            return None;
        }
        if let Some(v) = &valor {
            if v.len() > MAX_PARTE {
                return None;
            }
        }
        Some(Etiqueta {
            espacio: espacio.to_ascii_lowercase(),
            predicado: predicado.to_ascii_lowercase(),
            valor,
        })
    }
}

/// Un predicado de una taxonomia.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Predicado {
    /// Nombre.
    pub nombre: String,
    /// Que significa.
    pub descripcion: String,
    /// Los valores admitidos. Vacio significa que el predicado no lleva valor.
    pub valores: Vec<String>,
}

/// Una taxonomia declarada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Taxonomia {
    /// Espacio de nombres.
    pub espacio: String,
    /// Para que sirve.
    pub descripcion: String,
    /// Sus predicados.
    pub predicados: Vec<Predicado>,
}

impl Taxonomia {
    /// Si una etiqueta es valida en esta taxonomia.
    #[must_use]
    pub fn admite(&self, e: &Etiqueta) -> bool {
        if e.espacio != self.espacio {
            return false;
        }
        let Some(p) = self.predicados.iter().find(|p| p.nombre == e.predicado) else {
            return false;
        };
        match (&e.valor, p.valores.is_empty()) {
            (None, true) => true,
            (Some(v), false) => p.valores.contains(v),
            // Un predicado con valores declarados exige valor, y uno sin ellos no
            // lo admite. Aceptar las dos formas es tener dos etiquetas distintas
            // que parecen la misma.
            _ => false,
        }
    }
}

/// Las taxonomias estandar que trae el producto.
///
/// Se incluyen y no se descargan: un producto de seguridad que necesita Internet
/// para validar una etiqueta no vale en una red aislada, que son justo las que
/// mas cuidado ponen en el etiquetado.
#[must_use]
pub fn estandar() -> Vec<Taxonomia> {
    let s = |x: &str| x.to_string();
    vec![
        Taxonomia {
            espacio: s("tlp"),
            descripcion: s("Protocolo del semaforo: quien puede verlo"),
            predicados: vec![Predicado {
                nombre: s("clasificacion"),
                descripcion: s("Nivel TLP 2.0"),
                valores: vec![
                    s("clear"),
                    s("green"),
                    s("amber"),
                    s("amber-strict"),
                    s("red"),
                ],
            }],
        },
        Taxonomia {
            espacio: s("pap"),
            descripcion: s("Acciones permitidas sin que el adversario lo note"),
            predicados: vec![Predicado {
                nombre: s("clasificacion"),
                descripcion: s("Nivel PAP"),
                valores: vec![s("clear"), s("green"), s("amber"), s("red")],
            }],
        },
        // La escala del Almirantazgo separa la FIABILIDAD DE LA FUENTE de la
        // CREDIBILIDAD DE LA INFORMACION, que es la distincion que un solo numero
        // de «confianza» borra. Una fuente pesima puede traer un dato comprobado,
        // y una fuente excelente puede traer un rumor.
        Taxonomia {
            espacio: s("admiralty-scale"),
            descripcion: s(
                "Fiabilidad de la fuente y credibilidad de la informacion, por separado",
            ),
            predicados: vec![
                Predicado {
                    nombre: s("source-reliability"),
                    descripcion: s("De la A (siempre fiable) a la F (no se puede juzgar)"),
                    valores: vec![s("a"), s("b"), s("c"), s("d"), s("e"), s("f")],
                },
                Predicado {
                    nombre: s("information-credibility"),
                    descripcion: s("Del 1 (confirmado) al 6 (no se puede juzgar)"),
                    valores: vec![s("1"), s("2"), s("3"), s("4"), s("5"), s("6")],
                },
            ],
        },
        // El lenguaje estimativo existe porque «probable» significa cosas
        // distintas para cada persona. Con rangos declarados, dos analistas que
        // escriben «probable» dicen lo mismo.
        Taxonomia {
            espacio: s("estimative-language"),
            descripcion: s("Grados de probabilidad con rango numerico declarado"),
            predicados: vec![Predicado {
                nombre: s("likelihood-probability"),
                descripcion: s("Probabilidad estimada"),
                valores: vec![
                    s("almost-no-chance"),
                    s("very-unlikely"),
                    s("unlikely"),
                    s("roughly-even-chance"),
                    s("likely"),
                    s("very-likely"),
                    s("almost-certain"),
                ],
            }],
        },
        Taxonomia {
            espacio: s("kill-chain"),
            descripcion: s("Fase de la cadena de intrusion"),
            predicados: vec![Predicado {
                nombre: s("fase"),
                descripcion: s("Fase"),
                valores: vec![
                    s("reconnaissance"),
                    s("weaponization"),
                    s("delivery"),
                    s("exploitation"),
                    s("installation"),
                    s("command-and-control"),
                    s("actions-on-objectives"),
                ],
            }],
        },
        Taxonomia {
            espacio: s("malware"),
            descripcion: s("Clasificacion del codigo malicioso"),
            predicados: vec![
                Predicado {
                    nombre: s("tipo"),
                    descripcion: s("Que hace"),
                    valores: vec![
                        s("ransomware"),
                        s("backdoor"),
                        s("downloader"),
                        s("dropper"),
                        s("infostealer"),
                        s("rootkit"),
                        s("wiper"),
                        s("miner"),
                        s("loader"),
                        s("rat"),
                    ],
                },
                Predicado {
                    nombre: s("plataforma"),
                    descripcion: s("Donde corre"),
                    valores: vec![s("windows"), s("linux"), s("macos"), s("android"), s("ios")],
                },
            ],
        },
        Taxonomia {
            espacio: s("aegis"),
            descripcion: s("Etiquetas propias del producto"),
            predicados: vec![
                Predicado {
                    nombre: s("origen"),
                    descripcion: s("De donde salio"),
                    valores: vec![
                        s("deteccion-propia"),
                        s("detonacion"),
                        s("caza-retroactiva"),
                        s("federacion"),
                        s("enjambre"),
                    ],
                },
                Predicado {
                    nombre: s("revisado"),
                    descripcion: s("Lo ha mirado una persona"),
                    valores: vec![],
                },
            ],
        },
    ]
}

/// Un grupo de una galaxia: el mismo actor bajo todos sus nombres.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grupo {
    /// Identificador estable.
    pub id: String,
    /// Nombre principal.
    pub nombre: String,
    /// Como lo llaman otros.
    pub sinonimos: Vec<String>,
    /// Descripcion.
    pub descripcion: String,
    /// Referencias a otros grupos del mismo actor.
    pub relacionados: Vec<String>,
}

/// Una galaxia: un conjunto de grupos con sus sinonimos.
#[derive(Debug, Clone, Default)]
pub struct Galaxia {
    /// Nombre de la galaxia.
    pub nombre: String,
    grupos: BTreeMap<String, Grupo>,
    /// Indice de nombre normalizado a identificador.
    indice: BTreeMap<String, String>,
}

impl Galaxia {
    /// Una galaxia vacia.
    #[must_use]
    pub fn nueva(nombre: impl Into<String>) -> Galaxia {
        Galaxia {
            nombre: nombre.into(),
            grupos: BTreeMap::new(),
            indice: BTreeMap::new(),
        }
    }

    /// Añade un grupo con todos sus nombres.
    ///
    /// # Errors
    ///
    /// Devuelve `Err` si alguno de sus nombres ya apunta a otro grupo. No se
    /// resuelve en silencio: dos grupos que comparten un sinonimo es un dato que
    /// alguien tiene que mirar —o son el mismo actor y hay que fusionarlos, o el
    /// sinonimo esta mal— y elegir uno automaticamente esconde las dos
    /// posibilidades.
    pub fn anadir(&mut self, grupo: Grupo) -> Result<(), String> {
        let nombres: Vec<String> = std::iter::once(grupo.nombre.clone())
            .chain(grupo.sinonimos.iter().cloned())
            .map(|n| normalizar(&n))
            .collect();
        for n in &nombres {
            if let Some(otro) = self.indice.get(n) {
                if otro != &grupo.id {
                    return Err(format!(
                        "«{n}» ya apunta a «{otro}» y ahora tambien a «{}»: o son el mismo actor y \
                         hay que fusionarlos, o el sinonimo esta mal — elegir uno automaticamente \
                         esconde las dos posibilidades",
                        grupo.id
                    ));
                }
            }
        }
        for n in nombres {
            self.indice.insert(n, grupo.id.clone());
        }
        self.grupos.insert(grupo.id.clone(), grupo);
        Ok(())
    }

    /// Resuelve un nombre a su grupo.
    ///
    /// Es lo que hace que `APT29`, `Cozy Bear` y `Nobelium` sean el mismo.
    #[must_use]
    pub fn resolver(&self, nombre: &str) -> Option<&Grupo> {
        let id = self.indice.get(&normalizar(nombre))?;
        self.grupos.get(id)
    }

    /// Un grupo por identificador.
    #[must_use]
    pub fn grupo(&self, id: &str) -> Option<&Grupo> {
        self.grupos.get(id)
    }

    /// Cuantos grupos hay.
    #[must_use]
    pub fn cuantos(&self) -> usize {
        self.grupos.len()
    }

    /// Todos los nombres conocidos de un actor, sea cual sea el que se dio.
    #[must_use]
    pub fn nombres_de(&self, nombre: &str) -> Vec<String> {
        match self.resolver(nombre) {
            Some(g) => {
                let mut v: Vec<String> = std::iter::once(g.nombre.clone())
                    .chain(g.sinonimos.iter().cloned())
                    .collect();
                v.sort();
                v.dedup();
                v
            }
            None => Vec::new(),
        }
    }
}

/// Normaliza un nombre para el indice: sin mayusculas, sin espacios ni guiones.
///
/// `Cozy Bear`, `cozy-bear` y `CozyBear` son el mismo nombre escrito por tres
/// personas distintas, y tratarlos como tres es exactamente el problema que la
/// galaxia existe para resolver.
fn normalizar(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// El validador de etiquetas contra las taxonomias declaradas.
#[derive(Debug, Clone, Default)]
pub struct Vocabulario {
    taxonomias: BTreeMap<String, Taxonomia>,
}

impl Vocabulario {
    /// Un vocabulario con las taxonomias estandar.
    #[must_use]
    pub fn estandar() -> Vocabulario {
        let mut v = Vocabulario::default();
        for t in estandar() {
            v.declarar(t);
        }
        v
    }

    /// Declara una taxonomia.
    pub fn declarar(&mut self, t: Taxonomia) {
        self.taxonomias.insert(t.espacio.clone(), t);
    }

    /// Valida una etiqueta escrita.
    ///
    /// # Errors
    ///
    /// Devuelve el motivo por el que no vale.
    pub fn validar(&self, texto: &str) -> Result<Etiqueta, String> {
        let e = Etiqueta::de_texto(texto)
            .ok_or_else(|| format!("«{texto}» no tiene la forma espacio:predicado=\"valor\""))?;
        let t = self.taxonomias.get(&e.espacio).ok_or_else(|| {
            format!(
                "«{}» no es una taxonomia declarada; las hay: {}",
                e.espacio,
                self.taxonomias
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;
        if !t.admite(&e) {
            return Err(format!(
                "«{texto}» no vale en la taxonomia «{}»: el predicado o el valor no estan \
                 declarados, y guardarlo «por si acaso» es como se llega a tener la misma cosa \
                 escrita de cuatro formas",
                e.espacio
            ));
        }
        Ok(e)
    }

    /// Valida una lista, separando lo bueno de lo malo.
    #[must_use]
    pub fn filtrar(&self, textos: &[String]) -> (Vec<Etiqueta>, Vec<(String, String)>) {
        let mut buenas = Vec::new();
        let mut malas = Vec::new();
        for t in textos {
            match self.validar(t) {
                Ok(e) => buenas.push(e),
                Err(m) => malas.push((t.clone(), m)),
            }
        }
        buenas.sort();
        buenas.dedup();
        (buenas, malas)
    }

    /// Las taxonomias declaradas.
    #[must_use]
    pub fn espacios(&self) -> BTreeSet<&str> {
        self.taxonomias.keys().map(String::as_str).collect()
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn grupo(id: &str, nombre: &str, sinonimos: &[&str]) -> Grupo {
        Grupo {
            id: id.into(),
            nombre: nombre.into(),
            sinonimos: sinonimos.iter().map(|s| (*s).to_string()).collect(),
            descripcion: String::new(),
            relacionados: vec![],
        }
    }

    #[test]
    fn el_mismo_actor_con_tres_nombres_es_uno() {
        // Una base que los trate como tres no junta nunca lo que se sabe de el,
        // que es justo lo que hace falta.
        let mut g = Galaxia::nueva("actores");
        g.anadir(grupo(
            "g-29",
            "APT29",
            &["Cozy Bear", "Nobelium", "Midnight Blizzard"],
        ))
        .expect("sin choque");

        for n in [
            "APT29",
            "apt29",
            "Cozy Bear",
            "cozy-bear",
            "COZYBEAR",
            "Nobelium",
        ] {
            assert_eq!(
                g.resolver(n).map(|x| x.id.as_str()),
                Some("g-29"),
                "«{n}» no resolvio"
            );
        }
        assert_eq!(g.nombres_de("nobelium").len(), 4);
    }

    #[test]
    fn dos_grupos_que_comparten_sinonimo_se_rechazan_en_vez_de_elegir_uno() {
        // O son el mismo actor y hay que fusionarlos, o el sinonimo esta mal:
        // elegir uno automaticamente esconde las dos posibilidades.
        let mut g = Galaxia::nueva("actores");
        g.anadir(grupo("g-a", "Grupo A", &["Oso"]))
            .expect("primero");
        let e = g
            .anadir(grupo("g-b", "Grupo B", &["Oso"]))
            .expect_err("choque");
        assert!(e.contains("esconde las dos posibilidades"));
        assert_eq!(g.cuantos(), 1);
    }

    #[test]
    fn volver_a_anadir_el_mismo_grupo_no_choca_consigo_mismo() {
        let mut g = Galaxia::nueva("actores");
        g.anadir(grupo("g-a", "Grupo A", &["Oso"]))
            .expect("primero");
        g.anadir(grupo("g-a", "Grupo A", &["Oso", "Oso Pardo"]))
            .expect("es el mismo, se actualiza");
        assert_eq!(g.nombres_de("oso").len(), 3);
    }

    #[test]
    fn una_etiqueta_que_no_valida_se_rechaza_y_no_se_guarda_como_texto() {
        // Guardarla «por si acaso» es exactamente como se llega a tener la misma
        // cosa escrita de cuatro formas.
        let v = Vocabulario::estandar();
        assert!(v.validar("malware:tipo=\"ransomware\"").is_ok());
        assert!(v.validar("malware:tipo=\"ransomwear\"").is_err());
        assert!(v.validar("malware:familia=\"lockbit\"").is_err());
        assert!(v.validar("inventada:cosa=\"x\"").is_err());
        assert!(v.validar("lockbit").is_err());
        assert!(v.validar("").is_err());
    }

    #[test]
    fn el_error_dice_que_taxonomias_hay() {
        // Un rechazo sin alternativa hace que la gente deje de etiquetar.
        let v = Vocabulario::estandar();
        let e = v.validar("inventada:cosa=\"x\"").expect_err("no existe");
        assert!(e.contains("malware") && e.contains("tlp"));
    }

    #[test]
    fn un_predicado_con_valores_exige_valor_y_uno_sin_ellos_no_lo_admite() {
        // Aceptar las dos formas es tener dos etiquetas distintas que parecen la
        // misma.
        let v = Vocabulario::estandar();
        assert!(v.validar("malware:tipo").is_err(), "tipo exige valor");
        assert!(v.validar("aegis:revisado").is_ok());
        assert!(
            v.validar("aegis:revisado=\"si\"").is_err(),
            "revisado no lleva valor"
        );
    }

    #[test]
    fn la_ida_y_vuelta_de_una_etiqueta_es_estable() {
        for s in [
            "malware:tipo=\"ransomware\"",
            "aegis:revisado",
            "kill-chain:fase=\"exploitation\"",
            "admiralty-scale:source-reliability=\"b\"",
        ] {
            let e = Etiqueta::de_texto(s).unwrap_or_else(|| panic!("{s} deberia leerse"));
            assert_eq!(e.texto(), s);
            assert_eq!(Etiqueta::de_texto(&e.texto()), Some(e));
        }
    }

    #[test]
    fn las_etiquetas_se_normalizan_a_minusculas() {
        let e = Etiqueta::de_texto("MALWARE:TIPO=\"ransomware\"").expect("se lee");
        assert_eq!(e.espacio, "malware");
        assert_eq!(e.predicado, "tipo");
        assert!(Vocabulario::estandar().validar(&e.texto()).is_ok());
    }

    #[test]
    fn una_etiqueta_desmesurada_no_pasa() {
        let larga = "a".repeat(MAX_PARTE + 1);
        assert!(Etiqueta::de_texto(&format!("{larga}:x")).is_none());
        assert!(Etiqueta::de_texto(&format!("x:{larga}")).is_none());
        assert!(Etiqueta::de_texto(&format!("x:y=\"{larga}\"")).is_none());
    }

    #[test]
    fn una_etiqueta_con_caracteres_raros_no_pasa() {
        for s in [
            "mal ware:tipo=\"x\"",
            "malware:ti po=\"x\"",
            "mal\"ware:tipo=\"x\"",
            "malware:tipo=\"\"",
            ":tipo=\"x\"",
            "malware:",
        ] {
            assert!(Etiqueta::de_texto(s).is_none(), "«{s}» no deberia pasar");
        }
    }

    #[test]
    fn filtrar_separa_lo_bueno_de_lo_malo_y_dice_por_que() {
        let v = Vocabulario::estandar();
        let (buenas, malas) = v.filtrar(&[
            "malware:tipo=\"ransomware\"".into(),
            "lockbit".into(),
            "aegis:origen=\"detonacion\"".into(),
            "malware:familia=\"x\"".into(),
        ]);
        assert_eq!(buenas.len(), 2);
        assert_eq!(malas.len(), 2);
        assert!(malas.iter().all(|(_, m)| m.len() > 20));
    }

    #[test]
    fn las_repetidas_se_juntan_en_una() {
        let v = Vocabulario::estandar();
        let (buenas, _) = v.filtrar(&[
            "malware:tipo=\"ransomware\"".into(),
            "MALWARE:TIPO=\"ransomware\"".into(),
        ]);
        assert_eq!(buenas.len(), 1);
    }

    #[test]
    fn la_escala_del_almirantazgo_separa_fuente_de_informacion() {
        // Es la distincion que un solo numero de «confianza» borra: una fuente
        // pesima puede traer un dato comprobado, y una excelente un rumor.
        let v = Vocabulario::estandar();
        assert!(v
            .validar("admiralty-scale:source-reliability=\"f\"")
            .is_ok());
        assert!(v
            .validar("admiralty-scale:information-credibility=\"1\"")
            .is_ok());
        assert!(v
            .validar("admiralty-scale:source-reliability=\"1\"")
            .is_err());
    }

    #[test]
    fn las_taxonomias_estandar_vienen_incluidas_y_no_se_descargan() {
        // Un producto que necesita Internet para validar una etiqueta no vale en
        // una red aislada, que son justo las que mas cuidado ponen en esto.
        let v = Vocabulario::estandar();
        for esperada in [
            "tlp",
            "pap",
            "admiralty-scale",
            "estimative-language",
            "kill-chain",
            "malware",
            "aegis",
        ] {
            assert!(v.espacios().contains(esperada), "falta «{esperada}»");
        }
    }

    #[test]
    fn toda_taxonomia_estandar_es_coherente() {
        // Un predicado sin descripcion, o dos con el mismo nombre, hacen
        // inutilizable la taxonomia justo cuando alguien intenta usarla.
        for t in estandar() {
            assert!(!t.descripcion.is_empty(), "«{}» sin descripcion", t.espacio);
            let mut nombres: Vec<&str> = t.predicados.iter().map(|p| p.nombre.as_str()).collect();
            nombres.sort_unstable();
            let antes = nombres.len();
            nombres.dedup();
            assert_eq!(antes, nombres.len(), "«{}» repite predicado", t.espacio);
            for p in &t.predicados {
                assert!(
                    !p.descripcion.is_empty(),
                    "«{}:{}» sin descripcion",
                    t.espacio,
                    p.nombre
                );
                // Y todo valor declarado tiene que validar contra su propia
                // taxonomia, o la tabla miente sobre lo que acepta.
                for v in &p.valores {
                    let e = Etiqueta {
                        espacio: t.espacio.clone(),
                        predicado: p.nombre.clone(),
                        valor: Some(v.clone()),
                    };
                    assert!(
                        t.admite(&e),
                        "«{}» no admite su propio valor «{v}»",
                        t.espacio
                    );
                }
            }
        }
    }
}
