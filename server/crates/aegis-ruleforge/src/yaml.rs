//! Lector del subconjunto de YAML que usan las reglas Sigma.
//!
//! # Por que un lector propio y no una biblioteca
//!
//! Lo que se lee aqui son ficheros del catalogo publico de Sigma. Es contenido
//! util, de otros, y si el feed se compromete lo escribe el atacante. La
//! invariante 2 de esta fase es explicita: los compiladores analizan ficheros
//! que pueden venir de un feed comprometido, asi que `#![forbid(unsafe_code)]` y
//! nada de arboles de dependencias sin auditar en ese camino.
//!
//! Ademas, YAML **completo** es un formato enorme —anclas, alias, etiquetas,
//! documentos multiples, cinco formas de escribir una cadena— y casi todo eso es
//! superficie de ataque que Sigma no usa. Un lector del subconjunto que Sigma sí
//! usa es mas pequeño que la lista de cosas que habria que desactivar de un
//! lector generico.
//!
//! # El subconjunto, declarado
//!
//! | Se soporta | No se soporta |
//! |---|---|
//! | Mapas anidados por indentacion | Anclas y alias (`&x`, `*x`) |
//! | Listas con `-` | Etiquetas (`!!str`) |
//! | Escalares sueltos y entrecomillados | Flujo JSON (`{a: 1}`) salvo listas simples |
//! | Listas en linea `[a, b]` | Documentos multiples en un fichero |
//! | Bloques literales `|` y plegados `>` | Claves complejas |
//! | Comentarios `#` | |
//!
//! Lo que no se soporta **se rechaza con nombre**, se cuenta, y aparece en el
//! informe. Nunca se ignora en silencio: una regla Sigma con un ancla que se
//! lee a medias es una regla que detecta otra cosa.

use std::collections::BTreeMap;

/// Un valor YAML del subconjunto soportado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Valor {
    /// Una cadena. Todos los escalares se guardan como texto: Sigma no
    /// distingue tipos numericos de forma que cambie la deteccion, y guardarlos
    /// como texto evita una clase entera de errores de conversion.
    Texto(String),
    /// Una lista.
    Lista(Vec<Valor>),
    /// Un mapa, ordenado para que el recorrido sea reproducible.
    Mapa(BTreeMap<String, Valor>),
}

impl Valor {
    /// El texto, si es un escalar.
    #[must_use]
    pub fn texto(&self) -> Option<&str> {
        match self {
            Valor::Texto(s) => Some(s),
            _ => None,
        }
    }

    /// El mapa, si lo es.
    #[must_use]
    pub fn mapa(&self) -> Option<&BTreeMap<String, Valor>> {
        match self {
            Valor::Mapa(m) => Some(m),
            _ => None,
        }
    }

    /// La lista, si lo es.
    #[must_use]
    pub fn lista(&self) -> Option<&[Valor]> {
        match self {
            Valor::Lista(v) => Some(v),
            _ => None,
        }
    }

    /// Los elementos, tanto si es lista como si es un escalar suelto.
    ///
    /// Sigma escribe indistintamente `campo: valor` y `campo: [valor]` con el
    /// mismo significado. Tratarlos distinto obligaria a duplicar cada regla de
    /// traduccion.
    #[must_use]
    pub fn como_lista(&self) -> Vec<&Valor> {
        match self {
            Valor::Lista(v) => v.iter().collect(),
            otro => vec![otro],
        }
    }
}

/// Por que no se pudo leer el documento.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorYaml {
    /// Se uso una construccion fuera del subconjunto soportado.
    FueraDelSubconjunto {
        /// Numero de linea, empezando en 1.
        linea: usize,
        /// Que construccion.
        que: String,
    },
    /// La indentacion no cuadra.
    IndentacionIncoherente {
        /// Numero de linea.
        linea: usize,
    },
    /// El documento pasa del anidamiento permitido.
    DemasiadoAnidado {
        /// Profundidad alcanzada.
        profundidad: usize,
        /// Tope.
        tope: usize,
    },
    /// El documento esta vacio.
    Vacio,
}

impl ErrorYaml {
    /// Codigo estable para el informe.
    #[must_use]
    pub fn codigo(&self) -> &'static str {
        match self {
            ErrorYaml::FueraDelSubconjunto { .. } => "yaml-fuera-del-subconjunto",
            ErrorYaml::IndentacionIncoherente { .. } => "yaml-indentacion",
            ErrorYaml::DemasiadoAnidado { .. } => "yaml-demasiado-anidado",
            ErrorYaml::Vacio => "yaml-vacio",
        }
    }

    /// Detalle legible.
    #[must_use]
    pub fn detalle(&self) -> String {
        match self {
            ErrorYaml::FueraDelSubconjunto { linea, que } => {
                format!("linea {linea}: {que} no esta en el subconjunto soportado")
            }
            ErrorYaml::IndentacionIncoherente { linea } => {
                format!("linea {linea}: la indentacion no cuadra con ningun nivel abierto")
            }
            ErrorYaml::DemasiadoAnidado { profundidad, tope } => {
                format!("anidamiento {profundidad}, por encima del tope de {tope}")
            }
            ErrorYaml::Vacio => "el documento esta vacio".to_string(),
        }
    }
}

/// Una linea util, ya despiezada.
#[derive(Debug, Clone)]
struct Linea {
    numero: usize,
    sangria: usize,
    contenido: String,
    es_elemento: bool,
}

/// Lee un documento del subconjunto soportado.
///
/// # Errores
/// [`ErrorYaml`] nombrando la construccion concreta que no se soporta. Nunca se
/// devuelve un documento a medias: una regla leida a medias detecta otra cosa.
pub fn leer(fuente: &str, max_anidamiento: usize) -> Result<Valor, ErrorYaml> {
    let lineas = despiezar(fuente)?;
    if lineas.is_empty() {
        return Err(ErrorYaml::Vacio);
    }
    let mut i = 0usize;
    let valor = leer_bloque(&lineas, &mut i, lineas[0].sangria, 0, max_anidamiento)?;
    Ok(valor)
}

/// Quita comentarios y lineas vacias, y mide la sangria de las utiles.
fn despiezar(fuente: &str) -> Result<Vec<Linea>, ErrorYaml> {
    let mut salida = Vec::new();
    for (idx, cruda) in fuente.lines().enumerate() {
        let numero = idx + 1;

        // El separador de documentos: se acepta el primero y se rechaza un
        // segundo documento, en vez de leer solo el primero en silencio.
        let sin_espacios = cruda.trim();
        if sin_espacios == "---" {
            if salida.is_empty() {
                continue;
            }
            return Err(ErrorYaml::FueraDelSubconjunto {
                linea: numero,
                que: "un segundo documento en el mismo fichero".to_string(),
            });
        }
        if sin_espacios == "..." {
            break;
        }
        if sin_espacios.is_empty() || sin_espacios.starts_with('#') {
            continue;
        }

        // Un tabulador en la sangria es ambiguo y YAML lo prohibe. Aceptarlo
        // «como si fueran espacios» hace que el mismo fichero se lea distinto
        // segun el ancho de tabulador de quien lo escribio.
        let sangria = cruda.len() - cruda.trim_start().len();
        if cruda[..sangria].contains('\t') {
            return Err(ErrorYaml::FueraDelSubconjunto {
                linea: numero,
                que: "un tabulador en la sangria".to_string(),
            });
        }

        let (contenido, es_elemento) = if let Some(resto) = sin_espacios.strip_prefix("- ") {
            (resto.trim().to_string(), true)
        } else if sin_espacios == "-" {
            (String::new(), true)
        } else {
            (sin_espacios.to_string(), false)
        };

        // Anclas, alias y etiquetas: se rechazan CON NOMBRE. Una regla con un
        // alias que se lee a medias detecta otra cosa.
        for (marca, que) in [
            ("&", "un ancla YAML"),
            ("*", "un alias YAML"),
            ("!!", "una etiqueta de tipo YAML"),
        ] {
            if contenido.starts_with(marca) {
                return Err(ErrorYaml::FueraDelSubconjunto {
                    linea: numero,
                    que: que.to_string(),
                });
            }
            if let Some((_, v)) = contenido.split_once(": ") {
                if v.trim().starts_with(marca) {
                    return Err(ErrorYaml::FueraDelSubconjunto {
                        linea: numero,
                        que: que.to_string(),
                    });
                }
            }
        }

        salida.push(Linea {
            numero,
            // Un elemento de lista abre un nivel propio: su contenido esta dos
            // caracteres a la derecha del guion.
            sangria: if es_elemento { sangria + 2 } else { sangria },
            contenido,
            es_elemento,
        });
    }
    Ok(salida)
}

/// Lee un bloque con la sangria dada.
fn leer_bloque(
    lineas: &[Linea],
    i: &mut usize,
    sangria: usize,
    profundidad: usize,
    tope: usize,
) -> Result<Valor, ErrorYaml> {
    if profundidad > tope {
        return Err(ErrorYaml::DemasiadoAnidado { profundidad, tope });
    }

    // Un bloque es una lista si su primera linea es un elemento.
    if lineas.get(*i).is_some_and(|l| l.es_elemento) {
        let mut items = Vec::new();
        while let Some(l) = lineas.get(*i) {
            if l.sangria < sangria || !l.es_elemento {
                break;
            }
            if l.contenido.is_empty() {
                // `-` solo: lo que sigue, mas sangrado, es el elemento.
                *i += 1;
                let valor = leer_bloque(lineas, i, sangria + 2, profundidad + 1, tope)?;
                items.push(valor);
                continue;
            }
            // Un elemento que es `clave: valor` abre un mapa dentro de la lista.
            if lleva_clave(&l.contenido) {
                let antes = *i;
                let valor = leer_mapa(lineas, i, l.sangria, profundidad + 1, tope, true)?;
                items.push(valor);
                // PROGRESO ESTRICTO. Si una vuelta no avanza, el bucle no
                // termina NUNCA, y un documento que cuelga al lector es
                // exactamente la denegacion de servicio que esta fase existe
                // para no sufrir: basta con un fichero de texto en un feed.
                //
                // Es la misma doctrina del reensamblado de la FASE 70 y del
                // bucle de mensajes del motor: ninguna vuelta puede quedarse
                // quieta, y la garantia se pone en el bucle, no en la confianza
                // de que la funcion de dentro siempre consuma algo.
                if *i == antes {
                    *i += 1;
                }
                continue;
            }
            items.push(Valor::Texto(escalar(&l.contenido)));
            *i += 1;
        }
        return Ok(Valor::Lista(items));
    }

    leer_mapa(lineas, i, sangria, profundidad, tope, false)
}

/// Lee un mapa con la sangria dada.
///
/// `abre_elemento` dice si la primera linea es el `- clave: valor` que abrio
/// este mapa dentro de una lista. Hace falta distinguirlo porque un `-` al mismo
/// nivel significa dos cosas OPUESTAS segun donde este: el primero **es** este
/// elemento, y cualquier otro es **ya el siguiente**, que no pertenece a este
/// mapa. Sin la distincion, o el mapa se traga los elementos de al lado, o no
/// consume nada y el bucle de arriba no avanza.
fn leer_mapa(
    lineas: &[Linea],
    i: &mut usize,
    sangria: usize,
    profundidad: usize,
    tope: usize,
    abre_elemento: bool,
) -> Result<Valor, ErrorYaml> {
    if profundidad > tope {
        return Err(ErrorYaml::DemasiadoAnidado { profundidad, tope });
    }
    let mut mapa = BTreeMap::new();

    while let Some(l) = lineas.get(*i) {
        if l.sangria < sangria {
            break;
        }
        if l.sangria > sangria {
            return Err(ErrorYaml::IndentacionIncoherente { linea: l.numero });
        }
        // Un `-` al mismo nivel CIERRA este mapa: es el siguiente elemento de la
        // lista, no una clave de este. La unica excepcion es la primera linea,
        // cuando este mapa lo abrio precisamente un elemento.
        if l.es_elemento && l.sangria == sangria && !(abre_elemento && mapa.is_empty()) {
            break;
        }

        let Some((clave, resto)) = partir_clave(&l.contenido) else {
            return Err(ErrorYaml::FueraDelSubconjunto {
                linea: l.numero,
                que: format!("«{}», que no es «clave: valor»", l.contenido),
            });
        };
        *i += 1;

        let valor = if !resto.is_empty() {
            // Bloques literal `|` y plegado `>`: el contenido va debajo.
            if resto == "|" || resto == ">" || resto.starts_with("|-") || resto.starts_with(">-") {
                leer_bloque_de_texto(lineas, i, sangria, resto.starts_with('>'))
            } else if resto.starts_with('[') {
                Valor::Lista(
                    lista_en_linea(&resto)
                        .into_iter()
                        .map(Valor::Texto)
                        .collect(),
                )
            } else if resto.starts_with('{') {
                return Err(ErrorYaml::FueraDelSubconjunto {
                    linea: l.numero,
                    que: "un mapa en flujo JSON".to_string(),
                });
            } else {
                Valor::Texto(escalar(&resto))
            }
        } else {
            // El valor va debajo, mas sangrado.
            match lineas.get(*i) {
                Some(sig) if sig.sangria > sangria => {
                    let antes = *i;
                    let v = leer_bloque(lineas, i, sig.sangria, profundidad + 1, tope)?;
                    // Progreso estricto, por el mismo motivo que en la lista.
                    if *i == antes {
                        *i += 1;
                    }
                    v
                }
                // Clave sin valor: se guarda como cadena vacia en vez de
                // fallar. En Sigma aparece y significa «nada».
                _ => Valor::Texto(String::new()),
            }
        };
        mapa.insert(clave, valor);
    }
    Ok(Valor::Mapa(mapa))
}

/// Lee un bloque de texto literal o plegado.
fn leer_bloque_de_texto(lineas: &[Linea], i: &mut usize, sangria: usize, plegado: bool) -> Valor {
    let mut partes = Vec::new();
    while let Some(l) = lineas.get(*i) {
        if l.sangria <= sangria {
            break;
        }
        partes.push(l.contenido.clone());
        *i += 1;
    }
    let unido = if plegado {
        partes.join(" ")
    } else {
        partes.join("\n")
    };
    Valor::Texto(unido)
}

/// Si el contenido tiene forma de `clave: valor`.
fn lleva_clave(contenido: &str) -> bool {
    partir_clave(contenido).is_some()
}

/// Parte `clave: valor` respetando comillas en la clave.
fn partir_clave(contenido: &str) -> Option<(String, String)> {
    let bytes = contenido.as_bytes();
    let mut en_comillas: Option<u8> = None;
    for (idx, b) in bytes.iter().enumerate() {
        match en_comillas {
            Some(q) if *b == q => en_comillas = None,
            Some(_) => {}
            None if *b == b'"' || *b == b'\'' => en_comillas = Some(*b),
            None if *b == b':' => {
                // Solo cuenta si va seguido de espacio o de final de linea: un
                // `http://x` dentro de un valor no es una clave.
                let siguiente = bytes.get(idx + 1);
                if siguiente.is_none() || siguiente == Some(&b' ') {
                    let clave = contenido[..idx].trim().trim_matches(['"', '\'']);
                    if clave.is_empty() {
                        return None;
                    }
                    return Some((clave.to_string(), contenido[idx + 1..].trim().to_string()));
                }
            }
            None => {}
        }
    }
    None
}

/// Quita las comillas de un escalar.
fn escalar(s: &str) -> String {
    let t = s.trim();
    if t.len() >= 2
        && ((t.starts_with('"') && t.ends_with('"')) || (t.starts_with('\'') && t.ends_with('\'')))
    {
        return t[1..t.len() - 1].to_string();
    }
    t.to_string()
}

/// Lee una lista en linea `[a, b, c]`.
fn lista_en_linea(s: &str) -> Vec<String> {
    let t = s.trim().trim_start_matches('[').trim_end_matches(']');
    if t.trim().is_empty() {
        return Vec::new();
    }
    let mut salida = Vec::new();
    let mut actual = String::new();
    let mut en_comillas: Option<char> = None;
    for c in t.chars() {
        match en_comillas {
            Some(q) if c == q => {
                en_comillas = None;
            }
            Some(_) => actual.push(c),
            None if c == '"' || c == '\'' => en_comillas = Some(c),
            None if c == ',' => salida.push(std::mem::take(&mut actual).trim().to_string()),
            None => actual.push(c),
        }
    }
    let cola = actual.trim().to_string();
    if !cola.is_empty() {
        salida.push(cola);
    }
    salida
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// UNA REGLA SIGMA DE VERDAD, del catalogo publico, escrita entera.
    const SIGMA_REAL: &str = r#"
title: Suspicious PowerShell Download
id: 3b6ab547-8ec2-4991-b9d2-2b06702a48d7
status: experimental
description: Detects suspicious PowerShell download cradle
author: Florian Roth
date: 2019/01/16
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - 'Net.WebClient'
            - 'DownloadString'
            - 'DownloadFile'
    filter:
        CommandLine|contains: 'update.microsoft.com'
    condition: selection and not filter
falsepositives:
    - Administrative scripts
level: high
tags:
    - attack.execution
    - attack.t1059.001
"#;

    #[test]
    fn una_regla_sigma_real_se_lee_entera() {
        let v = leer(SIGMA_REAL, 16).expect("la regla es del subconjunto soportado");
        let m = v.mapa().expect("el documento es un mapa");

        assert_eq!(m["title"].texto(), Some("Suspicious PowerShell Download"));
        assert_eq!(m["level"].texto(), Some("high"));

        let logsource = m["logsource"].mapa().expect("logsource es un mapa");
        assert_eq!(logsource["product"].texto(), Some("windows"));
        assert_eq!(logsource["category"].texto(), Some("process_creation"));

        let det = m["detection"].mapa().expect("detection es un mapa");
        assert_eq!(det["condition"].texto(), Some("selection and not filter"));

        let sel = det["selection"].mapa().expect("selection es un mapa");
        assert_eq!(sel["Image|endswith"].texto(), Some("\\powershell.exe"));

        let cmd = sel["CommandLine|contains"]
            .lista()
            .expect("la lista de contains");
        assert_eq!(cmd.len(), 3);
        assert_eq!(cmd[0].texto(), Some("Net.WebClient"));
        assert_eq!(cmd[2].texto(), Some("DownloadFile"));

        let tags = m["tags"].lista().expect("tags es una lista");
        assert_eq!(tags.len(), 2);
        assert_eq!(tags[1].texto(), Some("attack.t1059.001"));
    }

    /// `campo: valor` y `campo: [valor]` significan lo mismo en Sigma, y
    /// tratarlos distinto obligaria a duplicar cada regla de traduccion.
    #[test]
    fn un_escalar_y_una_lista_de_uno_se_recorren_igual() {
        let v = leer("a: solo\nb: [uno, dos]\n", 16).unwrap();
        let m = v.mapa().unwrap();
        assert_eq!(m["a"].como_lista().len(), 1);
        assert_eq!(m["a"].como_lista()[0].texto(), Some("solo"));
        assert_eq!(m["b"].como_lista().len(), 2);
    }

    /// LO QUE NO SE SOPORTA SE RECHAZA CON NOMBRE. Una regla con un ancla que se
    /// lee a medias es una regla que detecta otra cosa.
    #[test]
    fn las_construcciones_fuera_del_subconjunto_se_rechazan_con_nombre() {
        let casos = [
            ("base: &anchor\n  a: 1\n", "ancla"),
            ("uso: *anchor\n", "alias"),
            ("v: !!str 5\n", "etiqueta"),
            ("a: 1\n---\nb: 2\n", "segundo documento"),
            ("a: {b: 1}\n", "flujo JSON"),
        ];
        for (fuente, esperado) in casos {
            let e = leer(fuente, 16).unwrap_err();
            assert_eq!(e.codigo(), "yaml-fuera-del-subconjunto", "con «{fuente}»");
            assert!(
                e.detalle().contains(esperado),
                "«{fuente}» -> {}",
                e.detalle()
            );
        }
    }

    /// Un tabulador en la sangria hace que el mismo fichero se lea distinto
    /// segun el ancho de tabulador de quien lo escribio. YAML lo prohibe y aqui
    /// tambien.
    #[test]
    fn un_tabulador_en_la_sangria_se_rechaza() {
        let e = leer("a:\n\tb: 1\n", 16).unwrap_err();
        assert_eq!(e.codigo(), "yaml-fuera-del-subconjunto");
        assert!(e.detalle().contains("tabulador"), "{}", e.detalle());
    }

    /// Un documento anidado a proposito no puede agotar la pila: lo que se lee
    /// son ficheros de un feed que puede estar comprometido.
    #[test]
    fn un_anidamiento_desmesurado_se_corta() {
        let mut fuente = String::new();
        for n in 0..200 {
            fuente.push_str(&" ".repeat(n * 2));
            fuente.push_str(&format!("n{n}:\n"));
        }
        let e = leer(&fuente, 16).unwrap_err();
        assert_eq!(e.codigo(), "yaml-demasiado-anidado");
    }

    /// Los dos puntos de un `http://` dentro de un valor NO son un separador de
    /// clave. Si lo fueran, media regla se leeria partida por la mitad.
    #[test]
    fn los_dos_puntos_de_una_url_no_parten_la_clave() {
        let v = leer("url: http://ejemplo.com/x\n", 16).unwrap();
        assert_eq!(
            v.mapa().unwrap()["url"].texto(),
            Some("http://ejemplo.com/x")
        );
    }

    /// Los bloques literal y plegado conservan y unen las lineas, que es como
    /// Sigma escribe las descripciones largas.
    #[test]
    fn los_bloques_de_texto_se_leen_segun_su_marca() {
        let literal = leer("d: |\n  primera\n  segunda\n", 16).unwrap();
        assert_eq!(
            literal.mapa().unwrap()["d"].texto(),
            Some("primera\nsegunda")
        );

        let plegado = leer("d: >\n  primera\n  segunda\n", 16).unwrap();
        assert_eq!(
            plegado.mapa().unwrap()["d"].texto(),
            Some("primera segunda")
        );
    }

    /// Una lista de mapas —como los `falsepositives` estructurados— se lee.
    #[test]
    fn una_lista_de_mapas_se_lee() {
        let v = leer("items:\n  - a: 1\n    b: 2\n  - a: 3\n    b: 4\n", 16).unwrap();
        let items = v.mapa().unwrap()["items"].lista().unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].mapa().unwrap()["a"].texto(), Some("1"));
        assert_eq!(items[1].mapa().unwrap()["b"].texto(), Some("4"));
    }

    /// EL CASO QUE COLGABA EL LECTOR. Un documento que hace que el bucle no
    /// avance no da un error: se queda girando para siempre, y eso es una
    /// denegacion de servicio contra la fabrica servida en un fichero de texto.
    ///
    /// La garantia esta en el bucle —progreso estricto— y no en confiar en que
    /// la funcion de dentro siempre consuma algo.
    #[test]
    fn ninguna_forma_de_lista_deja_el_lector_girando() {
        for fuente in [
            "items:\n  - a: 1\n    b: 2\n  - a: 3\n    b: 4\n",
            "items:\n  -\n  -\n  -\n",
            "a:\n  - b:\n  - c:\n",
            "a:\n  - - x\n  - - y\n",
            "a:\n  -\n    b:\n      -\n        c:\n",
            "- a: 1\n- b: 2\n",
        ] {
            // Si esto no termina, la prueba no termina: ese ES el fallo.
            let r = leer(fuente, 16);
            assert!(r.is_ok() || r.is_err(), "con «{fuente}»");
        }
    }

    #[test]
    fn un_documento_vacio_se_dice_vacio() {
        assert_eq!(leer("", 16).unwrap_err().codigo(), "yaml-vacio");
        assert_eq!(
            leer("# solo comentarios\n", 16).unwrap_err().codigo(),
            "yaml-vacio"
        );
    }

    /// Ninguna entrada arbitraria puede tumbar el lector.
    #[test]
    fn ninguna_entrada_arbitraria_provoca_panico() {
        let piezas = [
            "a:", "- ", "  ", "\t", "|", ">", "[", "]", "{", "}", "&x", "*x", "!!str", "---", "'",
            "\"", "#", ":", "valor",
        ];
        let mut semilla = 0x1234_5678_9ABC_DEF0u64;
        for _ in 0..3_000 {
            semilla = semilla
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let n = (semilla % 20) as usize;
            let doc: String = (0..n)
                .map(|k| piezas[((semilla >> (k % 56)) as usize) % piezas.len()])
                .collect::<Vec<&str>>()
                .join("\n");
            let _ = leer(&doc, 16);
        }
    }
}
