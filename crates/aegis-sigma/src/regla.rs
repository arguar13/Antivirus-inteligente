//! Compilador de reglas Sigma a una representacion intermedia evaluable.
//!
//! Viene de `aegis-ruleforge/src/sigma.rs` (FASE 72), que se saca aqui para
//! que el agente lo use sin enlazar el plano de control (FASE 4 del MP-16).
//!
//! # La condicion es un lenguaje, y se analiza como tal
//!
//! `selection and not filter` es facil. El catalogo real trae cosas como
//! `(sel_a or sel_b) and not (filtro_1 or 1 of filtro_opcional_*)`, con
//! precedencia, parentesis, cuantificadores y comodines sobre los nombres. Se
//! analiza de forma descendente con la precedencia correcta —`not` por encima de
//! `and`, y `and` por encima de `or`—, porque buscar palabras clave invierte el
//! significado de una regla en cuanto aparece un parentesis.
//!
//! # Los cinco hallazgos que se arreglan al moverlo (causa raiz y prueba)
//!
//! 1. **Una seleccion que es una LISTA DE MAPAS se leia como conjuncion.** En
//!    Sigma, `- {a: 1}` / `- {b: 2}` es «a=1 O b=2»; se aplanaba a «a=1 Y b=2»:
//!    la regla pasaba a exigir las dos variantes a la vez y no disparaba nunca.
//!    Ahora una seleccion es una disyuncion de conjunciones ([`Seleccion`]).
//! 2. **Una seleccion de palabras clave (lista de cadenas) casaba SIEMPRE.** Se
//!    compilaba a cero condiciones, y «todas de ninguna» es verdadero: la regla
//!    disparaba sobre cada evento. Ahora se rechaza con nombre
//!    (`sigma-palabras-clave`): la telemetria no trae una linea de registro
//!    cruda sobre la que buscar.
//! 3. **`Campo: ''` casaba con todo MENOS con el vacio.** El valor vacio se
//!    marcaba como «negada» y la negacion se aplicaba tambien al comparar.
//!    Ahora es [`Comparacion::Vacio`]: el campo falta o esta vacio.
//! 4. **El tope de anidamiento declarado no se aplicaba a la condicion.** Solo
//!    llegaba al lector de YAML; `not not not ... x` o diez mil parentesis
//!    agotaban la pila del compilador. Ahora la condicion respeta
//!    [`Topes::max_anidamiento`] y [`Topes::max_piezas_condicion`].
//! 5. **`startswith` y `endswith` cortaban un `&str` por bytes**: un valor con
//!    un caracter multibyte en esa posicion provocaba un panico. En el agente,
//!    el valor es el nombre de un proceso que elige el atacante. Ahora se
//!    compara sobre bytes ([`crate::patron`]), y ademas los comodines `*` se
//!    evaluan como comodines (antes se comparaban como un caracter).

use std::collections::BTreeMap;

use crate::patron::{Anclaje, Patron};
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparacion {
    /// Igualdad, con comodines `*`, sin distinguir mayusculas (el defecto).
    Igual,
    /// El valor contiene la cadena.
    Contiene,
    /// El valor empieza por la cadena.
    Empieza,
    /// El valor acaba en la cadena.
    Acaba,
    /// El campo falta o esta vacio (`Campo: ''` o `Campo: null`).
    Vacio,
    /// El valor casa una expresion regular. Solo en la fabrica, aproximada por
    /// su literal mas largo; el agente rechaza la regla.
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

impl Comparacion {
    fn anclaje(self) -> Option<Anclaje> {
        match self {
            Comparacion::Igual => Some(Anclaje::Igual),
            Comparacion::Contiene => Some(Anclaje::Contiene),
            Comparacion::Empieza => Some(Anclaje::Empieza),
            Comparacion::Acaba => Some(Anclaje::Acaba),
            _ => None,
        }
    }

    fn es_numerica(self) -> bool {
        matches!(
            self,
            Comparacion::Mayor
                | Comparacion::MayorIgual
                | Comparacion::Menor
                | Comparacion::MenorIgual
        )
    }
}

/// Una condicion sobre un campo de un evento.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Condicion {
    /// Nombre del campo.
    pub campo: String,
    /// Como se compara.
    pub comparacion: Comparacion,
    /// Valores tal y como venian en la regla.
    ///
    /// En Sigma, una lista de valores bajo un campo significa **cualquiera de
    /// ellos**. Interpretarla como «todos» invierte la regla.
    pub valores: Vec<String>,
    /// Si se exigen TODOS los valores en vez de cualquiera (modificador `|all`).
    pub todos: bool,
    patrones: Vec<Patron>,
    numeros: Vec<i64>,
}

impl Condicion {
    /// Los patrones compilados de los valores (vacio si la comparacion no es
    /// de texto).
    #[must_use]
    pub fn patrones(&self) -> &[Patron] {
        &self.patrones
    }

    /// Los umbrales de una comparacion numerica (vacio si no lo es).
    #[must_use]
    pub fn numeros(&self) -> &[i64] {
        &self.numeros
    }

    /// Si el evento cumple la condicion.
    #[must_use]
    pub fn evalua(&self, evento: &BTreeMap<String, String>) -> bool {
        self.casa_valor(evento.get(&self.campo).map(String::as_bytes))
    }

    /// Si el valor de su campo (o su ausencia) cumple la condicion.
    ///
    /// Es EL evaluador: lo usan la fabrica y el agente.
    #[must_use]
    pub fn casa_valor(&self, valor: Option<&[u8]>) -> bool {
        if self.comparacion == Comparacion::Vacio {
            return valor.is_none_or(<[u8]>::is_empty);
        }
        // Un campo que el evento no trae NO cumple. Darlo por cumplido haria
        // que una regla disparara sobre eventos que ni siquiera tienen el campo
        // que la regla mira.
        let Some(v) = valor else {
            return false;
        };
        if self.comparacion.es_numerica() {
            let Some(n) = std::str::from_utf8(v)
                .ok()
                .and_then(|s| s.trim().parse::<i64>().ok())
            else {
                return false;
            };
            let cmp = |b: &i64| match self.comparacion {
                Comparacion::Mayor => n > *b,
                Comparacion::MayorIgual => n >= *b,
                Comparacion::Menor => n < *b,
                _ => n <= *b,
            };
            return if self.todos {
                self.numeros.iter().all(cmp)
            } else {
                self.numeros.iter().any(cmp)
            };
        }
        if self.comparacion == Comparacion::Expresion {
            // Solo la fabrica llega aqui: el agente rechaza la regla al cargar.
            let casa = |p: &String| {
                let lit = literal_aproximado(p);
                !lit.is_empty() && Patron::nuevo(Anclaje::Contiene, &lit).is_ok_and(|q| q.casa(v))
            };
            return if self.todos {
                self.valores.iter().all(casa)
            } else {
                self.valores.iter().any(casa)
            };
        }
        if self.todos {
            self.patrones.iter().all(|p| p.casa(v))
        } else {
            self.patrones.iter().any(|p| p.casa(v))
        }
    }
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
    // Se escapa para el patron de Sigma: la aproximacion es un literal puro, y
    // un `*` o un `?` que venian escapados en la expresion no son comodines.
    mejor
        .replace('\\', "\\\\")
        .replace('*', "\\*")
        .replace('?', "\\?")
}

/// Una seleccion: casa si casa CUALQUIERA de sus alternativas, y una
/// alternativa casa si se cumplen TODAS sus condiciones.
///
/// Una seleccion escrita como mapa tiene una sola alternativa; escrita como
/// lista de mapas, una por mapa.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seleccion {
    /// Alternativas, nunca vacias.
    pub alternativas: Vec<Vec<Condicion>>,
}

impl Seleccion {
    /// Si el evento cumple la seleccion.
    #[must_use]
    pub fn evalua(&self, evento: &BTreeMap<String, String>) -> bool {
        self.alternativas
            .iter()
            .any(|cs| cs.iter().all(|c| c.evalua(evento)))
    }

    /// Todas las condiciones, de todas las alternativas.
    pub fn condiciones(&self) -> impl Iterator<Item = &Condicion> {
        self.alternativas.iter().flatten()
    }
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
        /// Patron de nombre, con `*` al final, o `them`.
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
    /// Producto, categoria y servicio de la fuente de eventos.
    pub fuente: BTreeMap<String, String>,
    /// Selecciones por nombre.
    pub selecciones: BTreeMap<String, Seleccion>,
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
            Expresion::Seleccion(n) => self.selecciones.get(n).is_some_and(|s| s.evalua(ev)),
            Expresion::CuantosDe { cuantas, patron } => {
                let nombres = self.selecciones.keys().filter(|n| nombre_casa(n, patron));
                let total = nombres.clone().count();
                let casan = nombres
                    .filter(|n| self.selecciones.get(*n).is_some_and(|s| s.evalua(ev)))
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
pub(crate) fn nombre_casa(nombre: &str, patron: &str) -> bool {
    if patron == "them" || patron == "*" {
        return true;
    }
    match patron.strip_suffix('*') {
        Some(prefijo) => nombre.starts_with(prefijo),
        None => nombre == patron,
    }
}

/// Topes del compilador: lo que una regla hostil NO puede hacer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Topes {
    /// Profundidad maxima de anidamiento, en el YAML y en la condicion.
    pub max_anidamiento: usize,
    /// Piezas (nombres, operadores, parentesis) de una condicion.
    pub max_piezas_condicion: usize,
    /// Bytes de una regla.
    pub max_bytes_regla: usize,
}

impl Default for Topes {
    fn default() -> Topes {
        Topes {
            max_anidamiento: 16,
            max_piezas_condicion: 512,
            max_bytes_regla: 64 * 1024,
        }
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
    /// La condicion pasa de los topes de anidamiento o de piezas.
    CondicionDesmedida(String),
    /// Usa un modificador que no se soporta.
    ModificadorNoSoportado(String),
    /// Un valor que no se puede compilar (`?`, numero invalido, vacio...).
    ValorNoSoportado(String),
    /// Su expresion regular es patologica.
    RegexRechazada(String),
    /// La condicion nombra una seleccion que no existe.
    SeleccionDesconocida(String),
    /// Una seleccion de palabras clave sueltas.
    PalabrasClave(String),
    /// Una seleccion sin ninguna condicion.
    SeleccionVacia(String),
    /// La regla pasa del tope de bytes.
    Desmedida(usize),
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
            ErrorSigma::CondicionDesmedida(_) => "sigma-condicion-desmedida",
            ErrorSigma::ModificadorNoSoportado(_) => "sigma-modificador-no-soportado",
            ErrorSigma::ValorNoSoportado(_) => "sigma-valor-no-soportado",
            ErrorSigma::RegexRechazada(_) => "regex-patologica",
            ErrorSigma::SeleccionDesconocida(_) => "sigma-seleccion-desconocida",
            ErrorSigma::PalabrasClave(_) => "sigma-palabras-clave",
            ErrorSigma::SeleccionVacia(_) => "sigma-seleccion-vacia",
            ErrorSigma::Desmedida(_) => "sigma-regla-desmedida",
            ErrorSigma::Obsoleta => "sigma-obsoleta",
        }
    }

    /// Detalle legible.
    #[must_use]
    pub fn detalle(&self) -> String {
        match self {
            ErrorSigma::Yaml(d)
            | ErrorSigma::RegexRechazada(d)
            | ErrorSigma::ValorNoSoportado(d)
            | ErrorSigma::CondicionDesmedida(d) => d.clone(),
            ErrorSigma::FaltaCampo(c) => format!("falta «{c}»"),
            ErrorSigma::CondicionInvalida(d) => format!("condicion: {d}"),
            ErrorSigma::ModificadorNoSoportado(m) => format!("modificador «{m}»"),
            ErrorSigma::SeleccionDesconocida(s) => {
                format!("la condicion nombra «{s}», que no existe")
            }
            ErrorSigma::PalabrasClave(s) => format!(
                "la seleccion «{s}» son palabras clave sueltas: no hay linea de registro cruda \
                 sobre la que buscarlas"
            ),
            ErrorSigma::SeleccionVacia(s) => format!("la seleccion «{s}» no tiene condiciones"),
            ErrorSigma::Desmedida(n) => format!("la regla ocupa {n} bytes"),
            ErrorSigma::Obsoleta => "la propia regla se declara obsoleta".to_string(),
        }
    }
}

/// Compila una regla Sigma.
///
/// `validar_re` decide sobre cada expresion regular (`|re`): la fabrica pasa su
/// analizador de retroceso catastrofico; el agente las acepta aqui y rechaza la
/// regla entera al compactarla, porque no evalua expresiones.
///
/// # Errores
/// [`ErrorSigma`] nombrando lo concreto que falla.
pub fn compilar_regla(
    fuente: &str,
    topes: &Topes,
    validar_re: &dyn Fn(&str) -> Result<(), String>,
) -> Result<ReglaSigma, ErrorSigma> {
    if fuente.len() > topes.max_bytes_regla {
        return Err(ErrorSigma::Desmedida(fuente.len()));
    }
    let doc =
        yaml::leer(fuente, topes.max_anidamiento).map_err(|e| ErrorSigma::Yaml(e.detalle()))?;
    let mapa = doc.mapa().ok_or(ErrorSigma::FaltaCampo("documento"))?;

    // Una regla que su autor marco obsoleta NO se compila. Distribuirla seria
    // aplicar una deteccion que su propio autor ha retirado.
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
        .map_or_else(|| titulo.clone(), str::to_string);
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
        selecciones.insert(
            nombre.clone(),
            analizar_seleccion(nombre, valor, validar_re)?,
        );
    }

    let condicion = analizar_condicion(texto_condicion, topes)?;
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

/// Analiza una seleccion: un mapa de `campo|modificador: valor(es)`, o una lista
/// de mapas (alternativas).
fn analizar_seleccion(
    nombre: &str,
    valor: &Valor,
    validar_re: &dyn Fn(&str) -> Result<(), String>,
) -> Result<Seleccion, ErrorSigma> {
    let mapas: Vec<&BTreeMap<String, Valor>> = match valor {
        Valor::Mapa(m) => vec![m],
        Valor::Lista(v) => {
            let mapas: Vec<_> = v.iter().filter_map(Valor::mapa).collect();
            if mapas.len() != v.len() {
                return Err(ErrorSigma::PalabrasClave(nombre.to_string()));
            }
            mapas
        }
        Valor::Texto(_) => return Err(ErrorSigma::PalabrasClave(nombre.to_string())),
    };

    let mut alternativas = Vec::new();
    for mapa in mapas {
        let mut condiciones = Vec::new();
        for (clave, v) in mapa {
            condiciones.push(analizar_condicion_de_campo(clave, v, validar_re)?);
        }
        if condiciones.is_empty() {
            return Err(ErrorSigma::SeleccionVacia(nombre.to_string()));
        }
        alternativas.push(condiciones);
    }
    if alternativas.is_empty() {
        return Err(ErrorSigma::SeleccionVacia(nombre.to_string()));
    }
    Ok(Seleccion { alternativas })
}

fn analizar_condicion_de_campo(
    clave: &str,
    v: &Valor,
    validar_re: &dyn Fn(&str) -> Result<(), String>,
) -> Result<Condicion, ErrorSigma> {
    let (campo, modificadores) = partir_modificadores(clave);
    let mut comparacion = Comparacion::Igual;
    let mut todos = false;

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
            // `windash` acepta las dos formas de guion de Windows; se expande
            // abajo. `cased` pide distinguir mayusculas: se acepta y se sigue
            // sin distinguir, que es mas amplio y nunca calla un ataque.
            "windash" | "cased" => {}
            otro => {
                // Base64, CIDR, expansion de campos... Se rechazan CON NOMBRE en
                // vez de ignorarse, que daria una condicion que compara otra
                // cosa.
                return Err(ErrorSigma::ModificadorNoSoportado(otro.to_string()));
            }
        }
    }

    let mut valores: Vec<String> = v
        .como_lista()
        .iter()
        .filter_map(|x| x.texto().map(str::to_string))
        .collect();
    if valores.is_empty() {
        return Err(ErrorSigma::ValorNoSoportado(format!(
            "«{clave}» sin ningun valor"
        )));
    }

    if modificadores.iter().any(|m| m == "windash") {
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

    // `Campo: ''` o `Campo: null`: el campo falta o esta vacio. El lector de
    // YAML no distingue `null` de `'null'`; una regla que busque el texto
    // literal «null» no existe en el catalogo.
    if comparacion == Comparacion::Igual
        && valores.len() == 1
        && (valores[0].is_empty() || valores[0] == "null" || valores[0] == "~")
    {
        return Ok(Condicion {
            campo,
            comparacion: Comparacion::Vacio,
            valores,
            todos,
            patrones: Vec::new(),
            numeros: Vec::new(),
        });
    }

    let mut patrones = Vec::new();
    let mut numeros = Vec::new();
    if comparacion == Comparacion::Expresion {
        for val in &valores {
            validar_re(val).map_err(ErrorSigma::RegexRechazada)?;
        }
    } else if comparacion.es_numerica() {
        for val in &valores {
            let n = val.trim().parse::<i64>().map_err(|_| {
                ErrorSigma::ValorNoSoportado(format!("«{val}» no es un numero en «{clave}»"))
            })?;
            numeros.push(n);
        }
    } else if let Some(anclaje) = comparacion.anclaje() {
        for val in &valores {
            let p = Patron::nuevo(anclaje, val)
                .map_err(|e| ErrorSigma::ValorNoSoportado(format!("«{clave}»: {e}")))?;
            patrones.push(p);
        }
    }

    Ok(Condicion {
        campo,
        comparacion,
        valores,
        todos,
        patrones,
        numeros,
    })
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
/// Descendente recursivo con la precedencia correcta, y con la recursion
/// acotada: solo `not` y `(` bajan un nivel, y los dos cuentan contra
/// [`Topes::max_anidamiento`].
///
/// # Errores
/// [`ErrorSigma::CondicionInvalida`] o [`ErrorSigma::CondicionDesmedida`].
pub fn analizar_condicion(texto: &str, topes: &Topes) -> Result<Expresion, ErrorSigma> {
    let piezas = tokenizar(texto);
    if piezas.len() > topes.max_piezas_condicion {
        return Err(ErrorSigma::CondicionDesmedida(format!(
            "la condicion tiene {} piezas, por encima del tope de {}",
            piezas.len(),
            topes.max_piezas_condicion
        )));
    }
    let mut a = Analizador {
        p: &piezas,
        pos: 0,
        tope: topes.max_anidamiento,
    };
    let e = a.o(0)?;
    if a.pos != piezas.len() {
        return Err(ErrorSigma::CondicionInvalida(format!(
            "sobra «{}» al final",
            piezas[a.pos..].join(" ")
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

struct Analizador<'a> {
    p: &'a [String],
    pos: usize,
    tope: usize,
}

impl Analizador<'_> {
    fn pieza_es(&self, palabra: &str) -> bool {
        self.p
            .get(self.pos)
            .is_some_and(|t| t.eq_ignore_ascii_case(palabra))
    }

    fn o(&mut self, nivel: usize) -> Result<Expresion, ErrorSigma> {
        let mut izq = self.y(nivel)?;
        while self.pieza_es("or") {
            self.pos += 1;
            let der = self.y(nivel)?;
            izq = Expresion::O(Box::new(izq), Box::new(der));
        }
        Ok(izq)
    }

    fn y(&mut self, nivel: usize) -> Result<Expresion, ErrorSigma> {
        let mut izq = self.no(nivel)?;
        while self.pieza_es("and") {
            self.pos += 1;
            let der = self.no(nivel)?;
            izq = Expresion::Y(Box::new(izq), Box::new(der));
        }
        Ok(izq)
    }

    fn bajar(&self, nivel: usize) -> Result<usize, ErrorSigma> {
        if nivel >= self.tope {
            return Err(ErrorSigma::CondicionDesmedida(format!(
                "anidamiento por encima del tope de {}",
                self.tope
            )));
        }
        Ok(nivel + 1)
    }

    fn no(&mut self, nivel: usize) -> Result<Expresion, ErrorSigma> {
        if self.pieza_es("not") {
            self.pos += 1;
            let dentro = self.bajar(nivel)?;
            let e = self.no(dentro)?;
            return Ok(Expresion::No(Box::new(e)));
        }
        self.atomo(nivel)
    }

    fn atomo(&mut self, nivel: usize) -> Result<Expresion, ErrorSigma> {
        let Some(t) = self.p.get(self.pos) else {
            return Err(ErrorSigma::CondicionInvalida(
                "se acaba antes de tiempo".to_string(),
            ));
        };

        if t == "(" {
            self.pos += 1;
            let dentro = self.bajar(nivel)?;
            let e = self.o(dentro)?;
            if self.p.get(self.pos).map(String::as_str) != Some(")") {
                return Err(ErrorSigma::CondicionInvalida(
                    "falta el parentesis de cierre".to_string(),
                ));
            }
            self.pos += 1;
            return Ok(e);
        }

        // `1 of sel*`, `all of them`, `any of filtro_*`.
        let cuantificador = t.eq_ignore_ascii_case("all")
            || t.eq_ignore_ascii_case("any")
            || t.parse::<usize>().is_ok();
        if cuantificador
            && self
                .p
                .get(self.pos + 1)
                .is_some_and(|s| s.eq_ignore_ascii_case("of"))
        {
            let cuantas = if t.eq_ignore_ascii_case("all") {
                None
            } else if t.eq_ignore_ascii_case("any") {
                Some(1)
            } else {
                Some(t.parse::<usize>().unwrap_or(1))
            };
            let Some(patron) = self.p.get(self.pos + 2) else {
                return Err(ErrorSigma::CondicionInvalida(
                    "«of» sin patron detras".to_string(),
                ));
            };
            if patron == "(" || patron == ")" {
                return Err(ErrorSigma::CondicionInvalida(
                    "«of» seguido de un parentesis".to_string(),
                ));
            }
            self.pos += 3;
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
        for reservada in ["and", "or", "not", "of"] {
            if t.eq_ignore_ascii_case(reservada) {
                return Err(ErrorSigma::CondicionInvalida(format!(
                    "«{t}» donde se esperaba una seleccion"
                )));
            }
        }
        self.pos += 1;
        Ok(Expresion::Seleccion(t.clone()))
    }
}

/// Comprueba que la condicion solo nombre selecciones que existen.
///
/// Una condicion que nombra una seleccion inexistente se evaluaria siempre a
/// falso y la regla nunca dispararia: estaria contada como compilada sin
/// detectar jamas. Es el peor tipo de fallo, porque no se ve.
fn comprobar_selecciones(
    e: &Expresion,
    selecciones: &BTreeMap<String, Seleccion>,
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

#[cfg(test)]
mod pruebas {
    use super::*;

    fn t() -> Topes {
        Topes::default()
    }

    fn sin_re(_: &str) -> Result<(), String> {
        Ok(())
    }

    fn compilar(fuente: &str) -> Result<ReglaSigma, ErrorSigma> {
        compilar_regla(fuente, &t(), &sin_re)
    }

    fn evento(pares: &[(&str, &str)]) -> BTreeMap<String, String> {
        pares
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
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

    #[test]
    fn una_regla_sigma_real_se_compila_y_se_evalua() {
        let r = compilar(REAL).expect("la regla es valida");
        assert_eq!(r.titulo, "Suspicious PowerShell Download Cradle");
        assert_eq!(r.nivel, Nivel::High);
        assert_eq!(r.selecciones.len(), 2);
        assert!(r.evalua(&evento(&[
            ("Image", "C:\\Windows\\System32\\powershell.exe"),
            (
                "CommandLine",
                "powershell -c (New-Object Net.WebClient).DownloadString('x')"
            ),
        ])));
        assert!(!r.evalua(&evento(&[
            ("Image", "C:\\Windows\\System32\\powershell.exe"),
            (
                "CommandLine",
                "powershell -c DownloadString('https://update.microsoft.com/x')"
            ),
        ])));
        assert!(!r.evalua(&evento(&[
            ("Image", "C:\\Windows\\System32\\cmd.exe"),
            ("CommandLine", "cmd /c DownloadString"),
        ])));
    }

    #[test]
    fn la_precedencia_de_la_condicion_es_la_correcta() {
        let e = analizar_condicion("a or b and c", &t()).unwrap();
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
        let e2 = analizar_condicion("not a and b", &t()).unwrap();
        assert_eq!(
            e2,
            Expresion::Y(
                Box::new(Expresion::No(Box::new(Expresion::Seleccion("a".into())))),
                Box::new(Expresion::Seleccion("b".into()))
            )
        );
        assert_ne!(
            analizar_condicion("a or b and c", &t()).unwrap(),
            analizar_condicion("(a or b) and c", &t()).unwrap()
        );
    }

    #[test]
    fn los_cuantificadores_se_analizan_y_se_evaluan() {
        let fuente =
            "title: C\ndetection:\n    sel_a:\n        A: si\n    sel_b:\n        B: si\n    \
                      sel_c:\n        C: si\n    condition: 2 of sel_*\nlevel: medium\n";
        let r = compilar(fuente).unwrap();
        assert!(!r.evalua(&evento(&[("A", "si")])));
        assert!(r.evalua(&evento(&[("A", "si"), ("B", "si")])));
    }

    #[test]
    fn una_lista_de_valores_es_cualquiera_y_all_es_todos() {
        let cualquiera =
            "title: L\ndetection:\n    sel:\n        CommandLine|contains:\n            \
                          - 'uno'\n            - 'dos'\n    condition: sel\n";
        let r = compilar(cualquiera).unwrap();
        assert!(r.evalua(&evento(&[("CommandLine", "solo dos")])));
        assert!(!r.evalua(&evento(&[("CommandLine", "ni tres")])));
        let todos = cualquiera.replace("|contains:", "|contains|all:");
        let r = compilar(&todos).unwrap();
        assert!(!r.evalua(&evento(&[("CommandLine", "solo uno")])));
        assert!(r.evalua(&evento(&[("CommandLine", "uno y dos")])));
    }

    /// HALLAZGO 1: una lista de mapas es una DISYUNCION.
    #[test]
    fn una_seleccion_con_lista_de_mapas_es_cualquiera_de_ellos() {
        let fuente = r#"
title: Alternativas
detection:
    sel:
        - Image|endswith: '/ln'
          CommandLine|contains: '/dev/null'
        - Image|endswith: '/rm'
    condition: sel
"#;
        let r = compilar(fuente).unwrap();
        assert_eq!(r.selecciones["sel"].alternativas.len(), 2);
        assert!(r.evalua(&evento(&[
            ("Image", "/usr/bin/rm"),
            ("CommandLine", "rm x")
        ])));
        assert!(r.evalua(&evento(&[
            ("Image", "/usr/bin/ln"),
            ("CommandLine", "ln -sf /dev/null h")
        ])));
        assert!(!r.evalua(&evento(&[
            ("Image", "/usr/bin/ln"),
            ("CommandLine", "ln -s a b")
        ])));
    }

    /// HALLAZGO 2: las palabras clave sueltas casaban con todo.
    #[test]
    fn una_seleccion_de_palabras_clave_se_rechaza_con_nombre() {
        let fuente = "title: K\ndetection:\n    keywords:\n        - 'nc -e'\n        - 'x'\n    \
                      condition: keywords\n";
        let e = compilar(fuente).unwrap_err();
        assert_eq!(e.codigo(), "sigma-palabras-clave");
        assert!(e.detalle().contains("keywords"), "{}", e.detalle());
    }

    /// HALLAZGO 3: `Campo: ''` es «falta o esta vacio».
    #[test]
    fn un_valor_vacio_es_falta_o_vacio_y_no_su_contrario() {
        let fuente =
            "title: V\ndetection:\n    sel:\n        CommandLine: ''\n    condition: sel\n";
        let r = compilar(fuente).unwrap();
        assert!(r.evalua(&evento(&[])));
        assert!(r.evalua(&evento(&[("CommandLine", "")])));
        assert!(!r.evalua(&evento(&[("CommandLine", "bash -i")])));
    }

    /// HALLAZGO 4: el tope de anidamiento se aplica a la condicion.
    #[test]
    fn una_condicion_hostil_no_agota_la_pila() {
        let nots = format!("{}sel", "not ".repeat(100_000));
        let e = analizar_condicion(&nots, &t()).unwrap_err();
        assert_eq!(e.codigo(), "sigma-condicion-desmedida");
        let parentesis = format!("{}sel{}", "( ".repeat(20), " )".repeat(20));
        assert_eq!(
            analizar_condicion(&parentesis, &t()).unwrap_err().codigo(),
            "sigma-condicion-desmedida"
        );
        let cadena = ["a"; 300].join(" or ");
        assert_eq!(
            analizar_condicion(&cadena, &t()).unwrap_err().codigo(),
            "sigma-condicion-desmedida"
        );
        assert!(analizar_condicion(&["a"; 100].join(" or "), &t()).is_ok());
    }

    #[test]
    fn una_seleccion_inexistente_rechaza_la_regla() {
        let fuente =
            "title: F\ndetection:\n    sel:\n        A: 1\n    condition: sel and not fantasma\n";
        let e = compilar(fuente).unwrap_err();
        assert_eq!(e.codigo(), "sigma-seleccion-desconocida");
        assert!(e.detalle().contains("fantasma"), "{}", e.detalle());
    }

    #[test]
    fn obsoletas_modificadores_desconocidos_y_valores_imposibles_se_rechazan() {
        let obsoleta = "title: V\nstatus: deprecated\ndetection:\n    sel:\n        A: 1\n    condition: sel\n";
        assert_eq!(compilar(obsoleta).unwrap_err().codigo(), "sigma-obsoleta");
        let b64 =
            "title: B\ndetection:\n    sel:\n        CommandLine|base64offset|contains: 'x'\n    \
                   condition: sel\n";
        let e = compilar(b64).unwrap_err();
        assert_eq!(e.codigo(), "sigma-modificador-no-soportado");
        assert!(e.detalle().contains("base64offset"));
        let interrogacion =
            "title: Q\ndetection:\n    sel:\n        Image: '/tmp/?'\n    condition: sel\n";
        assert_eq!(
            compilar(interrogacion).unwrap_err().codigo(),
            "sigma-valor-no-soportado"
        );
        let numero = "title: N\ndetection:\n    sel:\n        DestinationPort|gt: 'mil'\n    condition: sel\n";
        assert_eq!(
            compilar(numero).unwrap_err().codigo(),
            "sigma-valor-no-soportado"
        );
    }

    #[test]
    fn el_validador_de_expresiones_decide_sobre_re() {
        let fuente = "title: R\ndetection:\n    sel:\n        CommandLine|re: '(a+)+$'\n    condition: sel\n";
        let rechazar = |_: &str| -> Result<(), String> { Err("patologica".into()) };
        let e = compilar_regla(fuente, &t(), &rechazar).unwrap_err();
        assert_eq!(e.codigo(), "regex-patologica");
        assert!(compilar(fuente).is_ok());
    }

    #[test]
    fn una_condicion_mal_formada_se_rechaza() {
        for cond in [
            "(a and b",
            "a and",
            "and b",
            "a)",
            "1 of",
            "1 of (",
            "a and or b",
        ] {
            assert!(analizar_condicion(cond, &t()).is_err(), "«{cond}»");
        }
    }

    #[test]
    fn ninguna_entrada_arbitraria_provoca_panico() {
        let piezas = [
            "title: t",
            "detection:",
            "  sel:",
            "    A|contains: '*x*'",
            "    - 'k'",
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
            "|re",
            "ñ",
        ];
        let mut semilla = 0xDEAD_BEEF_CAFE_1234u64;
        for _ in 0..2_000 {
            semilla = semilla
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let n = (semilla % 15) as usize;
            let doc: String = (0..n)
                .map(|k| piezas[((semilla >> (k % 56)) as usize) % piezas.len()])
                .collect::<Vec<&str>>()
                .join("\n");
            if let Ok(r) = compilar(&doc) {
                let _ = r.evalua(&evento(&[("A", "ñx"), ("B", "")]));
            }
            let _ = analizar_condicion(&doc, &t());
        }
    }
}
