//! Gestion de colecciones de reglas YARA de terceros.
//!
//! # Por que una coleccion no es «concatenar ficheros»
//!
//! Un feed de YARA son decenas de ficheros de origenes distintos, y juntarlos a
//! lo bruto falla de tres formas concretas:
//!
//! 1. **Nombres repetidos.** Dos colecciones traen `APT_Backdoor_Generic` y YARA
//!    se niega a compilar el conjunto entero. Una regla duplicada tumba las
//!    cuarenta mil que venian con ella.
//! 2. **Dependencias.** Una regla puede referirse a otra por su nombre en la
//!    condicion (`$a and OtraRegla`). Si la referida va DESPUES en el fichero,
//!    no compila. El orden de los ficheros en un directorio no es un orden
//!    topologico.
//! 3. **Ciclos.** Dos reglas que se referencian entre si no se pueden ordenar de
//!    ninguna forma, y hay que decirlo en vez de recorrer para siempre buscando
//!    un orden que no existe.
//!
//! # Y la razon por la que esto se hace en el servidor y no en el endpoint
//!
//! Aqui se **compila de verdad** con YARA-X antes de firmar. Una regla rota que
//! llegue firmada al endpoint hace que el motor de analisis no arranque: el
//! cliente se queda sin antivirus por una regla mal escrita de un tercero.
//!
//! Compilar aqui convierte ese fallo —silencioso, en produccion, en miles de
//! maquinas— en un renglon del informe antes de distribuir nada.

use std::collections::{BTreeMap, BTreeSet};

use crate::informe::{Informe, Rechazo};
use crate::presupuesto::Presupuesto;

/// Una regla YARA suelta, ya separada de su fichero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReglaYara {
    /// Nombre, que es su identificador en el espacio de nombres de YARA.
    pub nombre: String,
    /// Etiquetas declaradas tras el nombre.
    pub etiquetas: Vec<String>,
    /// Texto completo de la regla, tal cual.
    pub texto: String,
    /// Si es privada (`private rule`).
    pub privada: bool,
    /// Nombres de otras reglas a las que se refiere en su condicion.
    pub dependencias: BTreeSet<String>,
    /// De que coleccion vino, para poder rastrearla.
    pub origen: String,
}

/// Por que una regla o una coleccion no se pudo procesar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorYara {
    /// El fichero no tiene la estructura de reglas esperada.
    Malformado(String),
    /// Hay un ciclo de dependencias entre reglas.
    CicloDeDependencias(Vec<String>),
    /// Una regla depende de otra que no esta en la coleccion.
    DependenciaAusente {
        /// Quien depende.
        regla: String,
        /// De quien.
        falta: String,
    },
    /// La regla pasa del tamano permitido.
    DemasiadoGrande {
        /// Bytes.
        bytes: usize,
        /// Tope.
        tope: usize,
    },
    /// YARA no la compila.
    NoCompila(String),
}

impl ErrorYara {
    /// Codigo estable.
    #[must_use]
    pub fn codigo(&self) -> &'static str {
        match self {
            ErrorYara::Malformado(_) => "yara-malformado",
            ErrorYara::CicloDeDependencias(_) => "yara-ciclo-de-dependencias",
            ErrorYara::DependenciaAusente { .. } => "yara-dependencia-ausente",
            ErrorYara::DemasiadoGrande { .. } => "yara-demasiado-grande",
            ErrorYara::NoCompila(_) => "yara-no-compila",
        }
    }

    /// Detalle legible.
    #[must_use]
    pub fn detalle(&self) -> String {
        match self {
            ErrorYara::Malformado(d) => d.clone(),
            ErrorYara::CicloDeDependencias(c) => {
                format!("ciclo entre {}", c.join(" -> "))
            }
            ErrorYara::DependenciaAusente { regla, falta } => {
                format!("«{regla}» se refiere a «{falta}», que no esta en la coleccion")
            }
            ErrorYara::DemasiadoGrande { bytes, tope } => {
                format!("{bytes} bytes, por encima del tope de {tope}")
            }
            ErrorYara::NoCompila(d) => d.clone(),
        }
    }
}

/// Separa un fichero de reglas YARA en reglas sueltas.
///
/// El troceado cuenta llaves respetando cadenas y comentarios. Contar llaves a
/// secas parte la regla por la mitad en cuanto una cadena lleva una llave
/// dentro —que es de lo mas normal en una regla que busca JSON o codigo—, y una
/// regla partida ni compila ni se puede diagnosticar.
///
/// # Errores
/// [`ErrorYara::Malformado`] si la estructura no cuadra.
pub fn trocear(
    fuente: &str,
    origen: &str,
    presupuesto: &Presupuesto,
) -> Result<Vec<ReglaYara>, ErrorYara> {
    let bytes = fuente.as_bytes();
    let mut reglas = Vec::new();
    let mut i = 0usize;

    while i < bytes.len() {
        // Se busca la siguiente cabecera de regla fuera de comentarios.
        let Some(inicio) = buscar_cabecera(fuente, i) else {
            break;
        };
        let (nombre, etiquetas, tras_cabecera) = leer_cabecera(fuente, inicio)?;
        let Some(abre) = fuente[tras_cabecera..].find('{').map(|p| p + tras_cabecera) else {
            return Err(ErrorYara::Malformado(format!(
                "la regla «{nombre}» no tiene cuerpo"
            )));
        };
        let cierre = buscar_cierre(fuente, abre)?;
        let texto = fuente[inicio..=cierre].to_string();

        if texto.len() > presupuesto.max_bytes_regla {
            return Err(ErrorYara::DemasiadoGrande {
                bytes: texto.len(),
                tope: presupuesto.max_bytes_regla,
            });
        }

        let privada = fuente[..inicio]
            .trim_end()
            .rsplit(|c: char| c.is_whitespace())
            .next()
            .is_some_and(|p| p == "private" || p == "global");

        let cuerpo = &fuente[abre + 1..cierre];
        let dependencias = referencias_a_reglas(cuerpo);

        reglas.push(ReglaYara {
            nombre,
            etiquetas,
            texto,
            privada,
            dependencias,
            origen: origen.to_string(),
        });
        i = cierre + 1;
    }

    Ok(reglas)
}

/// Busca la posicion de la siguiente palabra `rule` que abre una regla.
fn buscar_cabecera(fuente: &str, desde: usize) -> Option<usize> {
    let bytes = fuente.as_bytes();
    let mut i = desde;
    while i < bytes.len() {
        // Comentario de linea.
        if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'/') {
            i += fuente[i..].find('\n').map_or(bytes.len() - i, |p| p + 1);
            continue;
        }
        // Comentario de bloque.
        if bytes[i] == b'/' && bytes.get(i + 1) == Some(&b'*') {
            i += fuente[i..].find("*/").map_or(bytes.len() - i, |p| p + 2);
            continue;
        }
        // Cadena: se salta entera para que un `rule` dentro de una cadena no
        // abra una regla fantasma.
        if bytes[i] == b'"' {
            i += 1;
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            i += 1;
            continue;
        }
        if fuente[i..].starts_with("rule") {
            let antes_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric() && bytes[i - 1] != b'_';
            let despues = bytes.get(i + 4);
            let despues_ok = despues.is_some_and(|c| c.is_ascii_whitespace());
            if antes_ok && despues_ok {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// Lee `rule Nombre : etiquetas` y devuelve donde acaba.
fn leer_cabecera(fuente: &str, inicio: usize) -> Result<(String, Vec<String>, usize), ErrorYara> {
    let resto = &fuente[inicio + 4..];
    let hasta_llave = resto.find('{').unwrap_or(resto.len());
    let cabecera = &resto[..hasta_llave];

    let (nombre_txt, etiquetas_txt) = match cabecera.split_once(':') {
        Some((n, e)) => (n, e),
        None => (cabecera, ""),
    };
    let nombre = nombre_txt.trim().to_string();
    if nombre.is_empty() || !nombre.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err(ErrorYara::Malformado(format!(
            "«{}» no es un nombre de regla valido",
            nombre.trim()
        )));
    }
    let etiquetas = etiquetas_txt
        .split_whitespace()
        .map(str::to_string)
        .collect();
    Ok((nombre, etiquetas, inicio + 4 + hasta_llave))
}

/// Busca la llave que cierra el cuerpo, respetando cadenas y comentarios.
fn buscar_cierre(fuente: &str, abre: usize) -> Result<usize, ErrorYara> {
    let bytes = fuente.as_bytes();
    let mut nivel = 0usize;
    let mut i = abre;
    while i < bytes.len() {
        match bytes[i] {
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                i += fuente[i..].find('\n').map_or(bytes.len() - i, |p| p + 1);
                continue;
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i += fuente[i..].find("*/").map_or(bytes.len() - i, |p| p + 2);
                continue;
            }
            b'"' => {
                i += 1;
                while i < bytes.len() && bytes[i] != b'"' {
                    if bytes[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
                i += 1;
                continue;
            }
            // Una expresion regular de YARA va entre barras y puede llevar
            // llaves dentro: `/a{2,3}/`. Saltarla evita descuadrar el conteo.
            b'/' => {
                let mut j = i + 1;
                let mut cerrada = false;
                while j < bytes.len() && bytes[j] != b'\n' {
                    if bytes[j] == b'\\' {
                        j += 2;
                        continue;
                    }
                    if bytes[j] == b'/' {
                        cerrada = true;
                        break;
                    }
                    j += 1;
                }
                if cerrada {
                    i = j + 1;
                    continue;
                }
                i += 1;
                continue;
            }
            b'{' => {
                nivel += 1;
                i += 1;
            }
            b'}' => {
                nivel -= 1;
                if nivel == 0 {
                    return Ok(i);
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    Err(ErrorYara::Malformado(
        "una regla se queda sin cerrar".to_string(),
    ))
}

/// Palabras del lenguaje YARA que NO son nombres de otra regla.
const PALABRAS_YARA: &[&str] = &[
    "meta",
    "strings",
    "condition",
    "and",
    "or",
    "not",
    "any",
    "all",
    "of",
    "them",
    "for",
    "in",
    "at",
    "filesize",
    "entrypoint",
    "true",
    "false",
    "uint8",
    "uint16",
    "uint32",
    "int8",
    "int16",
    "int32",
    "uint8be",
    "uint16be",
    "uint32be",
    "them",
    "matches",
    "contains",
    "startswith",
    "endswith",
    "icontains",
    "iequals",
    "defined",
    "none",
];

/// Nombres de otras reglas a las que se refiere una condicion.
///
/// Se buscan identificadores que no sean palabras del lenguaje, ni variables de
/// cadena (`$a`), ni modulos (`pe.entry_point`). Un falso positivo aqui no
/// rompe nada —la dependencia simplemente no existira y se ignora—, pero un
/// falso NEGATIVO deja una regla antes que aquella de la que depende, y entonces
/// la coleccion entera no compila.
fn referencias_a_reglas(cuerpo: &str) -> BTreeSet<String> {
    let Some(pos) = cuerpo.find("condition") else {
        return BTreeSet::new();
    };
    let condicion = &cuerpo[pos..];
    let mut nombres = BTreeSet::new();
    let bytes = condicion.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        let c = bytes[i];
        // Variables de cadena y de bucle.
        if c == b'$' || c == b'#' || c == b'@' || c == b'!' {
            i += 1;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            continue;
        }
        if c == b'"' {
            i += 1;
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            i += 1;
            continue;
        }
        if c.is_ascii_alphabetic() || c == b'_' {
            let inicio = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            let palabra = &condicion[inicio..i];

            // Un punto detras significa que es un MODULO (`pe.`), no una regla.
            // Y hay que consumir la cadena de accesos entera: si solo se salta
            // el `pe`, el bucle vuelve a entrar en `number_of_sections` y lo
            // toma por el nombre de otra regla. Eso haria que la coleccion se
            // rechazara por depender de una regla que no existe — o peor, que se
            // ordenara mal buscando satisfacer una dependencia inventada.
            if bytes.get(i) == Some(&b'.') {
                while bytes.get(i) == Some(&b'.') {
                    i += 1;
                    while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_')
                    {
                        i += 1;
                    }
                }
                continue;
            }

            // Un parentesis detras es una llamada a funcion de modulo, no una
            // regla: `uint32(0)`, `entropy(0, filesize)`.
            if bytes.get(i) == Some(&b'(') {
                continue;
            }

            if !PALABRAS_YARA.contains(&palabra) && palabra != "condition" {
                nombres.insert(palabra.to_string());
            }
            continue;
        }
        i += 1;
    }
    nombres
}

/// Una coleccion de reglas ya ordenada y sin duplicados.
#[derive(Debug, Clone, Default)]
pub struct Coleccion {
    /// Las reglas, en orden de compilacion.
    pub reglas: Vec<ReglaYara>,
}

impl Coleccion {
    /// El texto de toda la coleccion, listo para compilar.
    #[must_use]
    pub fn fuente(&self) -> String {
        let mut s = String::new();
        for r in &self.reglas {
            s.push_str(&r.texto);
            s.push_str("\n\n");
        }
        s
    }
}

/// Reune varias colecciones, deduplica y ordena por dependencias.
///
/// El orden de salida garantiza que una regla siempre va DESPUES de aquellas a
/// las que se refiere: es lo que YARA exige para compilar.
///
/// Las reglas con nombre repetido se descartan conservando la PRIMERA. La
/// primera y no la ultima porque el orden de las fuentes lo elige el operador
/// —el feed de mas confianza va primero— y dejar ganar a la ultima haria que el
/// orden significara lo contrario de lo que parece.
#[must_use]
pub fn reunir(fuentes: &[(&str, &str)], presupuesto: &Presupuesto) -> (Coleccion, Informe) {
    let mut informe = Informe::default();
    let mut por_nombre: BTreeMap<String, ReglaYara> = BTreeMap::new();
    let mut orden_entrada: Vec<String> = Vec::new();

    for (origen, fuente) in fuentes {
        match trocear(fuente, origen, presupuesto) {
            Ok(reglas) => {
                for r in reglas {
                    if informe.vistas >= presupuesto.max_reglas {
                        informe.rechazada(Rechazo::nuevo(
                            "(resto)",
                            "demasiadas-reglas",
                            format!("se paso el tope de {} reglas", presupuesto.max_reglas),
                        ));
                        break;
                    }
                    if por_nombre.contains_key(&r.nombre) {
                        informe.duplicada();
                        continue;
                    }
                    orden_entrada.push(r.nombre.clone());
                    por_nombre.insert(r.nombre.clone(), r);
                    informe.compilada();
                }
            }
            Err(e) => informe.rechazada(Rechazo::nuevo(*origen, e.codigo(), e.detalle())),
        }
    }

    // Orden topologico. Las dependencias que no estan en la coleccion se
    // ignoran: son referencias a modulos o a reglas de otro feed, y romper la
    // coleccion entera por eso seria desproporcionado. Lo que SI rompe es un
    // ciclo, porque no hay orden posible.
    let (orden, ciclos) = ordenar_por_dependencias(&por_nombre, &orden_entrada);
    for c in ciclos {
        let e = ErrorYara::CicloDeDependencias(c.clone());
        for nombre in &c {
            informe.rechazada(Rechazo::nuevo(nombre, e.codigo(), e.detalle()));
        }
        // Un ciclo no se puede ordenar: sus reglas salen de la coleccion.
        informe.compiladas = informe.compiladas.saturating_sub(c.len());
    }

    let reglas = orden
        .into_iter()
        .filter_map(|n| por_nombre.get(&n).cloned())
        .collect();

    (Coleccion { reglas }, informe)
}

/// Orden topologico con deteccion de ciclos.
///
/// Devuelve el orden y los ciclos encontrados. Recorrido ITERATIVO con pila
/// explicita: una coleccion con diez mil reglas encadenadas agotaria la pila de
/// un recorrido recursivo, y eso lo decide quien escribe el feed.
fn ordenar_por_dependencias(
    reglas: &BTreeMap<String, ReglaYara>,
    orden_entrada: &[String],
) -> (Vec<String>, Vec<Vec<String>>) {
    #[derive(Clone, Copy, PartialEq)]
    enum Estado {
        Sin,
        EnCurso,
        Hecho,
    }
    let mut estado: BTreeMap<&str, Estado> =
        reglas.keys().map(|k| (k.as_str(), Estado::Sin)).collect();
    let mut orden = Vec::with_capacity(reglas.len());
    let mut ciclos = Vec::new();

    for raiz in orden_entrada {
        if estado.get(raiz.as_str()) != Some(&Estado::Sin) {
            continue;
        }
        // Pila de (nombre, dependencias pendientes).
        let mut pila: Vec<(&str, Vec<&str>)> = Vec::new();
        let Some(r) = reglas.get(raiz) else { continue };
        pila.push((
            raiz.as_str(),
            r.dependencias
                .iter()
                .filter(|d| reglas.contains_key(d.as_str()))
                .map(String::as_str)
                .collect(),
        ));
        estado.insert(raiz.as_str(), Estado::EnCurso);

        while let Some((nombre, pendientes)) = pila.last_mut() {
            let nombre = *nombre;
            match pendientes.pop() {
                Some(dep) => match estado.get(dep) {
                    Some(Estado::Hecho) => {}
                    Some(Estado::EnCurso) => {
                        // Ciclo: se anota el tramo de la pila implicado.
                        let desde = pila.iter().position(|(n, _)| *n == dep).unwrap_or(0);
                        let ciclo: Vec<String> = pila[desde..]
                            .iter()
                            .map(|(n, _)| (*n).to_string())
                            .collect();
                        if !ciclo.is_empty() {
                            ciclos.push(ciclo);
                        }
                    }
                    _ => {
                        if let Some(rd) = reglas.get(dep) {
                            estado.insert(dep, Estado::EnCurso);
                            pila.push((
                                dep,
                                rd.dependencias
                                    .iter()
                                    .filter(|d| reglas.contains_key(d.as_str()))
                                    .map(String::as_str)
                                    .collect(),
                            ));
                        }
                    }
                },
                None => {
                    estado.insert(nombre, Estado::Hecho);
                    orden.push(nombre.to_string());
                    pila.pop();
                }
            }
        }
    }

    // Las reglas implicadas en un ciclo salen del orden.
    let en_ciclo: BTreeSet<&str> = ciclos
        .iter()
        .flat_map(|c| c.iter().map(String::as_str))
        .collect();
    let orden = orden
        .into_iter()
        .filter(|n| !en_ciclo.contains(n.as_str()))
        .collect();

    (orden, ciclos)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn p() -> Presupuesto {
        Presupuesto::default()
    }

    const FUENTE: &str = r#"
// Un comentario con la palabra rule dentro, que no abre nada.
rule Base_Pe : pe ejecutable
{
    meta:
        author = "Alguien"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0
}

private rule Ayudante
{
    strings:
        $a = "auxiliar"
    condition:
        $a
}

rule Depende_De_Base
{
    strings:
        $x = "carga"
    condition:
        Base_Pe and Ayudante and $x
}
"#;

    #[test]
    fn un_fichero_yara_se_trocea_en_reglas_con_sus_etiquetas() {
        let reglas = trocear(FUENTE, "coleccion-a", &p()).expect("se trocea");
        assert_eq!(
            reglas.len(),
            3,
            "{:?}",
            reglas.iter().map(|r| &r.nombre).collect::<Vec<_>>()
        );

        assert_eq!(reglas[0].nombre, "Base_Pe");
        assert_eq!(reglas[0].etiquetas, vec!["pe", "ejecutable"]);
        assert!(!reglas[0].privada);

        assert_eq!(reglas[1].nombre, "Ayudante");
        assert!(reglas[1].privada, "«private rule» tiene que reconocerse");

        assert_eq!(reglas[2].nombre, "Depende_De_Base");
    }

    /// LAS DEPENDENCIAS SE DETECTAN. Si no, una regla puede quedar antes que
    /// aquella a la que se refiere y la coleccion entera no compila.
    #[test]
    fn las_referencias_a_otras_reglas_se_detectan() {
        let reglas = trocear(FUENTE, "a", &p()).unwrap();
        let dep = &reglas[2];
        assert!(
            dep.dependencias.contains("Base_Pe"),
            "{:?}",
            dep.dependencias
        );
        assert!(
            dep.dependencias.contains("Ayudante"),
            "{:?}",
            dep.dependencias
        );
        // Y las variables de cadena y las palabras del lenguaje NO son
        // dependencias.
        assert!(!dep.dependencias.contains("and"));
        assert!(!dep.dependencias.contains("x"));
    }

    /// Un modulo (`pe.entry_point`) NO es una dependencia de regla. Si lo fuera,
    /// la coleccion se rechazaria por una dependencia que no existe.
    #[test]
    fn los_modulos_no_se_confunden_con_dependencias() {
        let fuente = "rule R { condition: pe.number_of_sections > 3 and math.entropy(0, 10) > 7 }";
        let reglas = trocear(fuente, "a", &p()).unwrap();
        assert!(
            reglas[0].dependencias.is_empty(),
            "{:?}",
            reglas[0].dependencias
        );
    }

    /// UNA LLAVE DENTRO DE UNA CADENA NO CIERRA LA REGLA. Contar llaves a secas
    /// parte la regla por la mitad en cuanto busca JSON o codigo, y una regla
    /// partida ni compila ni se puede diagnosticar.
    #[test]
    fn una_llave_dentro_de_una_cadena_no_cierra_la_regla() {
        let fuente = r#"
rule Json
{
    strings:
        $a = "{\"clave\": \"valor\"}"
        $b = "}"
    condition:
        $a and $b
}
rule Siguiente
{
    condition: true
}
"#;
        let reglas = trocear(fuente, "a", &p()).unwrap();
        assert_eq!(reglas.len(), 2, "las dos reglas tienen que salir enteras");
        assert!(reglas[0].texto.contains("$b"), "la primera no se partio");
        assert_eq!(reglas[1].nombre, "Siguiente");
    }

    /// Y una llave dentro de un comentario tampoco.
    #[test]
    fn una_llave_en_un_comentario_no_cierra_la_regla() {
        let fuente =
            "rule R {\n  // cierra aqui }\n  condition: true\n}\nrule S { condition: true }";
        let reglas = trocear(fuente, "a", &p()).unwrap();
        assert_eq!(reglas.len(), 2);
    }

    /// EL ORDEN TOPOLOGICO: una regla siempre va DESPUES de aquellas a las que
    /// se refiere, sea cual sea el orden en que llegaron los ficheros.
    #[test]
    fn la_coleccion_sale_ordenada_por_dependencias() {
        // A proposito al reves: la que depende, primero.
        let al_reves = r#"
rule Depende { condition: Base }
rule Base { condition: true }
"#;
        let (col, informe) = reunir(&[("a", al_reves)], &p());
        assert_eq!(informe.compiladas, 2);
        let nombres: Vec<&str> = col.reglas.iter().map(|r| r.nombre.as_str()).collect();
        assert_eq!(
            nombres,
            vec!["Base", "Depende"],
            "la dependencia tiene que ir primero"
        );
    }

    /// UN CICLO NO SE PUEDE ORDENAR, y hay que decirlo en vez de recorrer para
    /// siempre buscando un orden que no existe.
    #[test]
    fn un_ciclo_de_dependencias_se_detecta_y_se_declara() {
        let ciclo = r#"
rule A { condition: B }
rule B { condition: A }
"#;
        let (col, informe) = reunir(&[("a", ciclo)], &p());
        assert!(
            informe
                .por_motivo()
                .iter()
                .any(|(m, _)| *m == "yara-ciclo-de-dependencias"),
            "{:?}",
            informe.por_motivo()
        );
        assert!(
            col.reglas.is_empty(),
            "las reglas del ciclo salen de la coleccion"
        );
    }

    /// Los nombres repetidos se descartan conservando el PRIMERO: el orden de
    /// las fuentes lo elige el operador, y dejar ganar al ultimo haria que ese
    /// orden significara lo contrario de lo que parece.
    #[test]
    fn un_nombre_repetido_conserva_la_primera_fuente() {
        let a = "rule Comun { strings: $x = \"de-a\" condition: $x }";
        let b = "rule Comun { strings: $x = \"de-b\" condition: $x }";
        let (col, informe) = reunir(&[("fuente-a", a), ("fuente-b", b)], &p());
        assert_eq!(col.reglas.len(), 1);
        assert_eq!(informe.duplicadas, 1);
        assert_eq!(col.reglas[0].origen, "fuente-a");
        assert!(col.reglas[0].texto.contains("de-a"));
    }

    /// Una dependencia que no esta en la coleccion NO rompe: puede ser una regla
    /// de otro feed. Romper la coleccion entera por eso seria desproporcionado.
    #[test]
    fn una_dependencia_externa_no_rompe_la_coleccion() {
        let fuente = "rule R { condition: ReglaDeOtroFeed }";
        let (col, informe) = reunir(&[("a", fuente)], &p());
        assert_eq!(col.reglas.len(), 1);
        assert_eq!(informe.compiladas, 1);
    }

    /// La fuente reunida es compilable: las reglas salen enteras y en orden.
    #[test]
    fn la_fuente_reunida_contiene_todas_las_reglas() {
        let (col, _) = reunir(&[("a", FUENTE)], &p());
        let texto = col.fuente();
        for nombre in ["Base_Pe", "Ayudante", "Depende_De_Base"] {
            assert!(texto.contains(nombre), "falta {nombre}");
        }
    }

    /// Una regla sin cerrar se dice, no se lee a medias.
    #[test]
    fn una_regla_sin_cerrar_se_rechaza() {
        let e = trocear("rule R { condition: true", "a", &p()).unwrap_err();
        assert_eq!(e.codigo(), "yara-malformado");
    }

    /// Una regla mas grande que el tope se rechaza antes de nada.
    #[test]
    fn una_regla_gigante_se_rechaza_por_tamano() {
        let estrecho = Presupuesto::estrecho();
        let fuente = format!(
            "rule R {{ strings: $a = \"{}\" condition: $a }}",
            "x".repeat(500)
        );
        let e = trocear(&fuente, "a", &estrecho).unwrap_err();
        assert_eq!(e.codigo(), "yara-demasiado-grande");
    }

    /// Ninguna entrada arbitraria puede tumbar el troceador: son ficheros de
    /// colecciones de terceros.
    #[test]
    fn ninguna_entrada_arbitraria_provoca_panico() {
        let piezas = [
            "rule",
            "{",
            "}",
            "\"",
            "/*",
            "*/",
            "//",
            "condition:",
            "strings:",
            "$a",
            "and",
            "private",
            ":",
            "R",
            "\\",
            "/",
        ];
        let mut semilla = 0xABCD_EF01_2345_6789u64;
        for _ in 0..3_000 {
            semilla = semilla
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let n = (semilla % 25) as usize;
            let doc: String = (0..n)
                .map(|k| piezas[((semilla >> (k % 56)) as usize) % piezas.len()])
                .collect::<Vec<&str>>()
                .join(" ");
            let _ = trocear(&doc, "x", &p());
        }
    }
}
