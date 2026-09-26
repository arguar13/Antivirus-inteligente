//! AegisQL sobre el historico: el mismo lenguaje, con lo que solo tiene sentido
//! contra un almacen.
//!
//! # Por que no se amplia la gramatica del endpoint
//!
//! AegisQL corre con privilegios en cada maquina del cliente, y su gramatica no
//! tiene `JOIN`, subconsultas ni agregaciones A PROPOSITO (ver [`crate::ast`]):
//! su coste lo pagaria el endpoint. Contra el almacen del plano de control esas
//! mismas construcciones son lo que un SOC necesita, y su coste lo mide y lo
//! acota el planificador del almacen.
//!
//! Por eso son dos puntos de entrada y dos arboles:
//!
//! - [`crate::sintaxis::analizar`] produce [`Consulta`], lo unico que acepta el
//!   ejecutor del endpoint. Sigue rechazando todo lo de aqui.
//! - [`analizar`] produce [`ConsultaHistorica`], un superconjunto. Su arbol de
//!   condiciones ([`ExprH`]) puede contener una subconsulta; el del endpoint
//!   ([`Expr`]) no puede ni representarla, asi que no hay error de programacion
//!   que la haga llegar a una maquina.
//!
//! Lo que es comun se analiza con el MISMO codigo —los predicados, sus tipos y
//! sus mensajes de error son los de [`crate::sintaxis`]— y una prueba exige que
//! toda consulta del endpoint dé, por este camino, exactamente el mismo arbol
//! ([`desde_endpoint`]). Es lo que permite escribir una consulta una vez y
//! correrla contra el vivo y contra el historico.
//!
//! # Lo que se anade
//!
//! ```text
//! SELECT host, COUNT(*) FROM events
//!  WHERE class = 'autenticacion' AND outcome = 'fallo'
//!  DURING LAST 24 HOURS
//!  GROUP BY EVERY 1 HOURS, host
//!  LIMIT 50
//!
//! SELECT pid, path FROM processes
//!  WHERE entity IN (SELECT entity FROM verdicts WHERE result = 'malicioso' LIMIT 500)
//!  DURING LAST 7 DAYS
//! ```
//!
//! - **Ventana temporal** (`DURING LAST n UNIDAD` o `DURING 'desde' TO 'hasta'`,
//!   en RFC 3339): es lo que decide cuantas particiones se leen.
//! - **Agregaciones** (`COUNT(*)`, `SUM`, `MIN`, `MAX`, `AVG`) con `GROUP BY`, y
//!   cubos de tiempo (`GROUP BY EVERY n UNIDAD`).
//! - **Union por entidad**, como subconsulta acotada sobre la columna `entity`:
//!   se une por el identificador del modelo unico, no por texto.
//! - **Subconsultas acotadas**: con `LIMIT` obligatorio y tope propio, porque una
//!   subconsulta sin techo hace indecidible el coste de la de fuera. Una
//!   subconsulta sin `DURING` propio hereda la ventana de la de fuera.
//!
//! Y todas las tablas ganan dos columnas: `ts` y `entity` (ver
//! [`crate::esquema::historico`]).

use crate::ast::{Columna, Consulta, Expr, Orden, Proyeccion};
use crate::error::ErrorConsulta;
use crate::esquema::{self, historico as cat, Tabla, Tipo};
use crate::lexico::Token;
use crate::sintaxis::{Ambito, Analizador, LIMITE_POR_DEFECTO};

/// Filas maximas que puede devolver una subconsulta.
///
/// La subconsulta produce una lista que la consulta de fuera compara fila a
/// fila: su tamano multiplica el coste de la otra. Mil es la lista de
/// entidades que un analista revisa; mas que eso es una consulta que hay que
/// escribir de otra forma.
pub const SUBCONSULTA_LIMITE_MAXIMO: u32 = 1_000;

/// Subconsultas maximas en una consulta.
pub const SUBCONSULTAS_MAXIMAS: usize = 4;

/// Columnas maximas en `GROUP BY`.
pub const GRUPOS_MAXIMOS: usize = 4;

/// Cubo de tiempo minimo de `GROUP BY EVERY`.
///
/// Un cubo de un nanosegundo sobre un mes son dos billones de grupos.
pub const CUBO_MINIMO_NS: u64 = 1_000_000_000;

/// Ventana maxima de `DURING LAST`: diez anos. Mas alla no hay retencion que la
/// cubra, y un numero enorme solo sirve para desbordar la aritmetica.
pub const VENTANA_MAXIMA_NS: u64 = 10 * 366 * 86_400 * 1_000_000_000;

/// Una ventana temporal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ventana {
    /// Los ultimos `ns` nanosegundos respecto al momento de ejecutar.
    Ultimos {
        /// Anchura.
        ns: u64,
    },
    /// Un intervalo absoluto `[desde, hasta)`.
    Entre {
        /// Inicio, incluido.
        desde_ns: u64,
        /// Fin, excluido.
        hasta_ns: u64,
    },
}

impl Ventana {
    /// El intervalo `[desde, hasta)` concreto, respecto a `ahora_ns`.
    #[must_use]
    pub fn intervalo(&self, ahora_ns: u64) -> (u64, u64) {
        match *self {
            Ventana::Ultimos { ns } => (ahora_ns.saturating_sub(ns), ahora_ns.saturating_add(1)),
            Ventana::Entre { desde_ns, hasta_ns } => (desde_ns, hasta_ns),
        }
    }
}

/// Una funcion de agregacion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Agregado {
    /// `COUNT(*)`.
    Cuenta,
    /// `SUM(columna)`.
    Suma(Columna),
    /// `MIN(columna)`.
    Minimo(Columna),
    /// `MAX(columna)`.
    Maximo(Columna),
    /// `AVG(columna)`.
    Media(Columna),
}

impl Agregado {
    /// Nombre de la columna de salida.
    #[must_use]
    pub fn nombre(&self) -> String {
        match self {
            Agregado::Cuenta => "count".into(),
            Agregado::Suma(c) => format!("sum({})", c.nombre),
            Agregado::Minimo(c) => format!("min({})", c.nombre),
            Agregado::Maximo(c) => format!("max({})", c.nombre),
            Agregado::Media(c) => format!("avg({})", c.nombre),
        }
    }
}

/// Una columna de salida de una consulta agregada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Salida {
    /// Una columna de agrupacion.
    Grupo(Columna),
    /// El inicio del cubo de tiempo de `GROUP BY EVERY`.
    Cubo,
    /// Un agregado.
    Agregado(Agregado),
}

/// Que devuelve una consulta del historico.
#[derive(Debug, Clone, PartialEq)]
pub enum Seleccion {
    /// Igual que en el endpoint: filas, todas o solo la cuenta.
    Filas(Proyeccion),
    /// Filas agregadas por grupos.
    Agregada(Vec<Salida>),
}

/// Una condicion del historico.
#[derive(Debug, Clone, PartialEq)]
pub enum ExprH {
    /// Un predicado del endpoint (comparacion, LIKE, IN de literales, bandera).
    Hoja(Expr),
    /// `columna [NOT] IN (SELECT ...)`.
    EnSubconsulta {
        /// La columna comparada.
        columna: Columna,
        /// La subconsulta; devuelve una sola columna del mismo tipo.
        sub: Box<ConsultaHistorica>,
        /// Si va negada.
        negado: bool,
    },
    /// Conjuncion.
    Y(Box<ExprH>, Box<ExprH>),
    /// Disyuncion.
    O(Box<ExprH>, Box<ExprH>),
    /// Negacion.
    No(Box<ExprH>),
}

impl ExprH {
    /// Convierte un filtro del endpoint.
    #[must_use]
    pub fn desde(e: &Expr) -> ExprH {
        match e {
            Expr::Y(a, b) => ExprH::Y(Box::new(ExprH::desde(a)), Box::new(ExprH::desde(b))),
            Expr::O(a, b) => ExprH::O(Box::new(ExprH::desde(a)), Box::new(ExprH::desde(b))),
            Expr::No(a) => ExprH::No(Box::new(ExprH::desde(a))),
            hoja => ExprH::Hoja(hoja.clone()),
        }
    }

    /// Las subconsultas de este arbol.
    #[must_use]
    pub fn subconsultas(&self) -> Vec<&ConsultaHistorica> {
        let mut v = Vec::new();
        self.recoger(&mut v);
        v
    }

    fn recoger<'a>(&'a self, v: &mut Vec<&'a ConsultaHistorica>) {
        match self {
            ExprH::Hoja(_) => {}
            ExprH::EnSubconsulta { sub, .. } => v.push(sub),
            ExprH::Y(a, b) | ExprH::O(a, b) => {
                a.recoger(v);
                b.recoger(v);
            }
            ExprH::No(a) => a.recoger(v),
        }
    }
}

/// Una consulta del historico, validada.
#[derive(Debug, Clone, PartialEq)]
pub struct ConsultaHistorica {
    /// Que devuelve.
    pub seleccion: Seleccion,
    /// Sobre que tabla.
    pub tabla: &'static str,
    /// Filtro.
    pub filtro: Option<ExprH>,
    /// Ventana temporal.
    pub ventana: Option<Ventana>,
    /// Columnas de agrupacion.
    pub agrupar: Vec<Columna>,
    /// Anchura del cubo de tiempo, si se agrupa por tiempo.
    pub cada_ns: Option<u64>,
    /// Orden.
    pub orden: Option<Orden>,
    /// Techo de filas.
    pub limite: u32,
}

/// La consulta del endpoint, vista como consulta del historico.
///
/// Es la definicion de «la misma consulta»: toda consulta que el endpoint
/// acepta tiene que analizarse por [`analizar`] en EXACTAMENTE este arbol. Las
/// pruebas lo exigen sobre un corpus de consultas reales.
#[must_use]
pub fn desde_endpoint(c: &Consulta) -> ConsultaHistorica {
    ConsultaHistorica {
        seleccion: Seleccion::Filas(c.proyeccion.clone()),
        tabla: c.tabla,
        filtro: c.filtro.as_ref().map(ExprH::desde),
        ventana: None,
        agrupar: Vec::new(),
        cada_ns: None,
        orden: c.orden.clone(),
        limite: c.limite,
    }
}

/// Una tabla del historico con sus dos columnas virtuales.
struct AmbitoHistorico(&'static Tabla);

impl Ambito for AmbitoHistorico {
    fn nombre_tabla(&self) -> &'static str {
        self.0.nombre
    }
    fn columna(&self, nombre: &str) -> Option<&'static esquema::Columna> {
        self.0
            .columna(nombre)
            .or_else(|| cat::VIRTUALES.iter().copied().find(|c| c.nombre == nombre))
    }
    fn nombres(&self) -> Vec<&'static str> {
        self.0
            .columnas
            .iter()
            .map(|c| c.nombre)
            .chain(cat::VIRTUALES.iter().map(|c| c.nombre))
            .collect()
    }
}

/// Si el token actual es el identificador `palabra` (sin distinguir mayusculas).
///
/// Las palabras del historico son CONTEXTUALES: no se anaden al lexico, que
/// comparte el endpoint, asi que alli siguen siendo un identificador cualquiera
/// y la gramatica del endpoint las rechaza como hasta ahora.
fn es_palabra(a: &Analizador, palabra: &str) -> bool {
    matches!(a.actual().map(|s| &s.token), Some(Token::Ident(n)) if n.eq_ignore_ascii_case(palabra))
}

fn acepta_palabra(a: &mut Analizador, palabra: &str) -> bool {
    if es_palabra(a, palabra) {
        a.avanzar();
        true
    } else {
        false
    }
}

fn exigir_palabra(a: &mut Analizador, palabra: &str, que: &str) -> Result<(), ErrorConsulta> {
    if acepta_palabra(a, palabra) {
        Ok(())
    } else {
        let (i, f) = a.tramo_actual();
        Err(ErrorConsulta::nuevo(format!("aqui falta {que}"), i, f))
    }
}

/// Analiza una consulta del historico.
///
/// # Errors
///
/// [`ErrorConsulta`] con el tramo culpable y, cuando se puede, una sugerencia.
pub fn analizar(consulta: &str) -> Result<ConsultaHistorica, ErrorConsulta> {
    let mut a = Analizador::nuevo(consulta)?;
    let mut subconsultas = 0usize;
    let c = consulta_h(&mut a, &mut subconsultas, false)?;
    a.exigir_final()?;
    Ok(c)
}

/// Un elemento de la lista de `SELECT` antes de conocer la tabla.
enum Item {
    Columna(String, usize, usize),
    Agregado(String, Option<(String, usize, usize)>, usize, usize),
}

fn consulta_h(
    a: &mut Analizador,
    subconsultas: &mut usize,
    es_sub: bool,
) -> Result<ConsultaHistorica, ErrorConsulta> {
    a.exigir(&Token::Select, "la palabra SELECT")?;

    // `*` y `COUNT(*)` a solas se tratan como en el endpoint.
    let mut todo = false;
    let mut items: Vec<Item> = Vec::new();
    if a.acepta(&Token::Asterisco) {
        todo = true;
    } else {
        loop {
            items.push(item(a)?);
            if !a.acepta(&Token::Coma) {
                break;
            }
        }
    }

    a.exigir(&Token::From, "la palabra FROM")?;
    let tabla = tabla_h(a)?;
    let ambito = AmbitoHistorico(tabla);

    let filtro = if a.acepta(&Token::Where) {
        Some(expresion(a, &ambito, 0, subconsultas)?)
    } else {
        None
    };

    let ventana = if acepta_palabra(a, "during") {
        Some(ventana(a)?)
    } else {
        None
    };
    // Una subconsulta sin ventana propia HEREDA la de fuera: quien escribe
    // `entity IN (SELECT entity FROM verdicts ...) DURING LAST 7 DAYS` quiere los
    // veredictos de esos siete dias, no los de toda la retencion. Se resuelve
    // aqui, en el arbol, para que el coste que se declara sea el de lo que se
    // va a ejecutar. Una subconsulta que declara la suya la conserva.
    let mut filtro = filtro;
    if let (Some(v), Some(f)) = (ventana, filtro.as_mut()) {
        heredar_ventana(f, v);
    }

    let mut agrupar = Vec::new();
    let mut cada_ns = None;
    if acepta_palabra(a, "group") {
        a.exigir(&Token::By, "la palabra BY tras GROUP")?;
        loop {
            if acepta_palabra(a, "every") {
                if cada_ns.is_some() {
                    let (i, f) = a.tramo_actual();
                    return Err(ErrorConsulta::nuevo("EVERY solo puede ir una vez", i, f));
                }
                let (ns, i, f) = duracion(a)?;
                if ns < CUBO_MINIMO_NS {
                    return Err(ErrorConsulta::nuevo(
                        "el cubo de tiempo no puede ser menor que un segundo",
                        i,
                        f,
                    ));
                }
                cada_ns = Some(ns);
            } else {
                let (n, i, f) = a.identificador("una columna tras GROUP BY")?;
                let c = a.columna(&ambito, &n, i, f)?;
                if agrupar.len() >= GRUPOS_MAXIMOS {
                    return Err(ErrorConsulta::nuevo(
                        format!("no se puede agrupar por mas de {GRUPOS_MAXIMOS} columnas"),
                        i,
                        f,
                    ));
                }
                agrupar.push(Columna {
                    nombre: c.nombre,
                    tipo: c.tipo,
                });
            }
            if !a.acepta(&Token::Coma) {
                break;
            }
        }
    }

    let seleccion = resolver_seleccion(a, &ambito, todo, items, &agrupar, cada_ns.is_some())?;

    let orden = if a.acepta(&Token::Order) {
        a.exigir(&Token::By, "la palabra BY tras ORDER")?;
        let o = a.orden(&ambito)?;
        if let Seleccion::Agregada(_) = seleccion {
            if !agrupar.iter().any(|g| g.nombre == o.columna) {
                let (i, f) = a.tramo_actual();
                return Err(ErrorConsulta::nuevo(
                    "en una consulta agregada solo se ordena por una columna de GROUP BY",
                    i,
                    f,
                )
                .con_sugerencia(
                    "sin ORDER BY, los grupos salen de mayor a menor por su primer agregado",
                ));
            }
        }
        Some(o)
    } else {
        None
    };

    let limite = if a.acepta(&Token::Limit) {
        let (i, f) = a.tramo_actual();
        let n = a.limite()?;
        if es_sub && n > SUBCONSULTA_LIMITE_MAXIMO {
            return Err(ErrorConsulta::nuevo(
                format!(
                    "una subconsulta no puede devolver mas de {SUBCONSULTA_LIMITE_MAXIMO} filas"
                ),
                i,
                f,
            )
            .con_sugerencia("su resultado se compara con cada fila de la consulta de fuera"));
        }
        n
    } else if es_sub {
        let (i, f) = a.tramo_actual();
        return Err(ErrorConsulta::nuevo("una subconsulta tiene que llevar LIMIT", i, f)
            .con_sugerencia(format!(
                "sin techo, el coste de la consulta de fuera no se puede calcular; como mucho LIMIT {SUBCONSULTA_LIMITE_MAXIMO}"
            )));
    } else {
        LIMITE_POR_DEFECTO
    };

    Ok(ConsultaHistorica {
        seleccion,
        tabla: tabla.nombre,
        filtro,
        ventana,
        agrupar,
        cada_ns,
        orden,
        limite,
    })
}

/// Pone la ventana de fuera a las subconsultas que no tienen la suya.
fn heredar_ventana(e: &mut ExprH, v: Ventana) {
    match e {
        ExprH::Hoja(_) => {}
        ExprH::EnSubconsulta { sub, .. } => {
            if sub.ventana.is_none() {
                sub.ventana = Some(v);
            }
        }
        ExprH::Y(a, b) | ExprH::O(a, b) => {
            heredar_ventana(a, v);
            heredar_ventana(b, v);
        }
        ExprH::No(a) => heredar_ventana(a, v),
    }
}

fn tabla_h(a: &mut Analizador) -> Result<&'static Tabla, ErrorConsulta> {
    let (nombre, i, f) = a.identificador("un nombre de tabla")?;
    cat::tabla(&nombre).ok_or_else(|| {
        let todas = cat::nombres();
        let e = ErrorConsulta::nuevo(format!("no existe la tabla '{nombre}'"), i, f);
        match esquema::nombres_parecidos(&todas, &nombre).first() {
            Some(p) => e.con_sugerencia(format!("quiza querias decir '{p}'")),
            None => e.con_sugerencia(format!("tablas disponibles: {}", todas.join(", "))),
        }
    })
}

fn item(a: &mut Analizador) -> Result<Item, ErrorConsulta> {
    let (i, f) = a.tramo_actual();
    if a.acepta(&Token::Count) {
        a.exigir(&Token::ParenIzq, "un parentesis abierto tras COUNT")?;
        a.exigir(&Token::Asterisco, "un asterisco dentro de COUNT")
            .map_err(|e| e.con_sugerencia("AegisQL solo admite COUNT(*)"))?;
        a.exigir(&Token::ParenDer, "un parentesis cerrado tras COUNT(*")?;
        return Ok(Item::Agregado("count".into(), None, i, f));
    }
    let (n, ni, nf) = a.identificador("una columna o un agregado")?;
    let funcion = ["sum", "min", "max", "avg"]
        .iter()
        .find(|x| n.eq_ignore_ascii_case(x));
    if let (Some(fun), true) = (
        funcion,
        matches!(a.actual().map(|s| &s.token), Some(Token::ParenIzq)),
    ) {
        a.exigir(&Token::ParenIzq, "un parentesis abierto")?;
        let col = a.identificador("una columna dentro del agregado")?;
        a.exigir(&Token::ParenDer, "un parentesis cerrado")?;
        return Ok(Item::Agregado((*fun).to_string(), Some(col), ni, nf));
    }
    Ok(Item::Columna(n, ni, nf))
}

fn resolver_seleccion(
    a: &Analizador,
    ambito: &AmbitoHistorico,
    todo: bool,
    items: Vec<Item>,
    agrupar: &[Columna],
    por_tiempo: bool,
) -> Result<Seleccion, ErrorConsulta> {
    let hay_agregados = items.iter().any(|x| matches!(x, Item::Agregado(..)));
    let agrupada = hay_agregados || !agrupar.is_empty() || por_tiempo;
    if todo {
        if agrupada {
            let (i, f) = a.tramo_actual();
            return Err(ErrorConsulta::nuevo("SELECT * no se puede agrupar", i, f)
                .con_sugerencia("nombra las columnas de GROUP BY y los agregados"));
        }
        return Ok(Seleccion::Filas(Proyeccion::Todo));
    }
    // `SELECT COUNT(*) FROM t` sin agrupar es la cuenta del endpoint.
    if !agrupada || (items.len() == 1 && agrupar.is_empty() && !por_tiempo) {
        if let [Item::Agregado(nombre, None, ..)] = items.as_slice() {
            if nombre == "count" {
                return Ok(Seleccion::Filas(Proyeccion::Cuenta));
            }
        }
    }
    if !agrupada {
        let mut cols = Vec::with_capacity(items.len());
        for x in items {
            if let Item::Columna(n, i, f) = x {
                let c = a.columna(ambito, &n, i, f)?;
                cols.push(Columna {
                    nombre: c.nombre,
                    tipo: c.tipo,
                });
            }
        }
        return Ok(Seleccion::Filas(Proyeccion::Columnas(cols)));
    }
    let mut salidas = Vec::with_capacity(items.len());
    for x in items {
        match x {
            Item::Columna(n, i, f) => {
                if por_tiempo && n.eq_ignore_ascii_case("bucket") {
                    salidas.push(Salida::Cubo);
                    continue;
                }
                let c = a.columna(ambito, &n, i, f)?;
                if !agrupar.iter().any(|g| g.nombre == c.nombre) {
                    return Err(ErrorConsulta::nuevo(
                        format!("'{}' no esta en GROUP BY ni es un agregado", c.nombre),
                        i,
                        f,
                    )
                    .con_sugerencia(
                        "en una consulta agregada, cada columna suelta tiene que ir en GROUP BY",
                    ));
                }
                salidas.push(Salida::Grupo(Columna {
                    nombre: c.nombre,
                    tipo: c.tipo,
                }));
            }
            Item::Agregado(fun, col, i, f) => {
                let agregado = match col {
                    None => Agregado::Cuenta,
                    Some((n, ci, cf)) => {
                        let c = a.columna(ambito, &n, ci, cf)?;
                        let numerica = matches!(c.tipo, Tipo::Entero | Tipo::Real);
                        if !numerica && fun != "min" && fun != "max" {
                            return Err(ErrorConsulta::nuevo(
                                format!(
                                    "{} solo se aplica a columnas numericas, y '{}' es {}",
                                    fun.to_uppercase(),
                                    c.nombre,
                                    c.tipo.nombre()
                                ),
                                i,
                                f,
                            ));
                        }
                        let col = Columna {
                            nombre: c.nombre,
                            tipo: c.tipo,
                        };
                        match fun.as_str() {
                            "sum" => Agregado::Suma(col),
                            "min" => Agregado::Minimo(col),
                            "max" => Agregado::Maximo(col),
                            _ => Agregado::Media(col),
                        }
                    }
                };
                salidas.push(Salida::Agregado(agregado));
            }
        }
    }
    if !salidas.iter().any(|s| matches!(s, Salida::Agregado(_))) {
        salidas.push(Salida::Agregado(Agregado::Cuenta));
    }
    Ok(Seleccion::Agregada(salidas))
}

// --- Condiciones: Pratt sobre ExprH, con las hojas del endpoint -------------

fn expresion(
    a: &mut Analizador,
    ambito: &AmbitoHistorico,
    minimo: u8,
    subconsultas: &mut usize,
) -> Result<ExprH, ErrorConsulta> {
    a.entrar()?;
    let r = expresion_interna(a, ambito, minimo, subconsultas);
    a.salir();
    r
}

fn expresion_interna(
    a: &mut Analizador,
    ambito: &AmbitoHistorico,
    minimo: u8,
    subconsultas: &mut usize,
) -> Result<ExprH, ErrorConsulta> {
    let mut izq = prefijo(a, ambito, subconsultas)?;
    loop {
        let precedencia = match a.actual().map(|s| &s.token) {
            Some(Token::Or) => 0,
            Some(Token::And) => 1,
            _ => break,
        };
        if precedencia < minimo {
            break;
        }
        let op = a.avanzar().expect("el operador acaba de comprobarse").token;
        let der = expresion(a, ambito, precedencia + 1, subconsultas)?;
        izq = match op {
            Token::Or => ExprH::O(Box::new(izq), Box::new(der)),
            _ => ExprH::Y(Box::new(izq), Box::new(der)),
        };
    }
    Ok(izq)
}

fn prefijo(
    a: &mut Analizador,
    ambito: &AmbitoHistorico,
    subconsultas: &mut usize,
) -> Result<ExprH, ErrorConsulta> {
    if a.acepta(&Token::Not) {
        let e = expresion(a, ambito, 2, subconsultas)?;
        return Ok(ExprH::No(Box::new(e)));
    }
    if a.acepta(&Token::ParenIzq) {
        let e = expresion(a, ambito, 0, subconsultas)?;
        a.exigir(&Token::ParenDer, "un parentesis cerrado")?;
        return Ok(e);
    }
    if let Some(e) = subconsulta(a, ambito, subconsultas)? {
        return Ok(e);
    }
    Ok(ExprH::Hoja(a.predicado(ambito)?))
}

/// `columna [NOT] IN (SELECT ...)`, mirado sin consumir si no lo es.
fn subconsulta(
    a: &mut Analizador,
    ambito: &AmbitoHistorico,
    subconsultas: &mut usize,
) -> Result<Option<ExprH>, ErrorConsulta> {
    let guardado = a.posicion();
    let Ok((nombre, i, f)) = a.identificador("una columna") else {
        a.volver(guardado);
        return Ok(None);
    };
    let negado = a.acepta(&Token::Not);
    let es_sub = a.acepta(&Token::In)
        && a.acepta(&Token::ParenIzq)
        && matches!(a.actual().map(|s| &s.token), Some(Token::Select));
    if !es_sub {
        a.volver(guardado);
        return Ok(None);
    }
    let col = a.columna(ambito, &nombre, i, f)?;
    *subconsultas += 1;
    if *subconsultas > SUBCONSULTAS_MAXIMAS {
        return Err(ErrorConsulta::nuevo(
            format!("una consulta no puede tener mas de {SUBCONSULTAS_MAXIMAS} subconsultas"),
            i,
            f,
        ));
    }
    a.entrar()?;
    let sub = consulta_h(a, subconsultas, true);
    a.salir();
    let sub = sub?;
    a.exigir(
        &Token::ParenDer,
        "un parentesis cerrado tras la subconsulta",
    )?;
    // La subconsulta devuelve UNA columna, del tipo de la de fuera.
    let tipo_sub = match &sub.seleccion {
        Seleccion::Filas(Proyeccion::Columnas(c)) if c.len() == 1 => Some(c[0].tipo),
        _ => None,
    };
    match tipo_sub {
        Some(t) if col.tipo.comparable_con(t) => {}
        Some(t) => {
            return Err(ErrorConsulta::nuevo(
                format!(
                    "'{}' es {} y la subconsulta devuelve {}",
                    col.nombre,
                    col.tipo.nombre(),
                    t.nombre()
                ),
                i,
                f,
            ))
        }
        None => {
            return Err(ErrorConsulta::nuevo(
                "una subconsulta tiene que devolver exactamente una columna",
                i,
                f,
            )
            .con_sugerencia(
                "por ejemplo: entity IN (SELECT entity FROM verdicts WHERE ... LIMIT 100)",
            ))
        }
    }
    Ok(Some(ExprH::EnSubconsulta {
        columna: Columna {
            nombre: col.nombre,
            tipo: col.tipo,
        },
        sub: Box::new(sub),
        negado,
    }))
}

// --- Ventanas y duraciones --------------------------------------------------

fn duracion(a: &mut Analizador) -> Result<(u64, usize, usize), ErrorConsulta> {
    let (i, f) = a.tramo_actual();
    let n = match a.actual().map(|s| s.token.clone()) {
        Some(Token::Entero(n)) if n > 0 => {
            a.avanzar();
            n as u64
        }
        _ => {
            return Err(ErrorConsulta::nuevo("aqui falta un numero positivo", i, f)
                .con_sugerencia("por ejemplo: 24 HOURS, 7 DAYS, 30 MINUTES"))
        }
    };
    let (ui, uf) = a.tramo_actual();
    let unidad = match a.actual().map(|s| s.token.clone()) {
        Some(Token::Ident(u)) => u.to_ascii_lowercase(),
        _ => String::new(),
    };
    let factor: u64 = match unidad.as_str() {
        "s" | "second" | "seconds" => 1_000_000_000,
        "m" | "minute" | "minutes" => 60_000_000_000,
        "h" | "hour" | "hours" => 3_600_000_000_000,
        "d" | "day" | "days" => 86_400_000_000_000,
        _ => {
            return Err(
                ErrorConsulta::nuevo("aqui falta una unidad de tiempo", ui, uf)
                    .con_sugerencia("SECONDS, MINUTES, HOURS o DAYS"),
            )
        }
    };
    a.avanzar();
    let ns = n
        .checked_mul(factor)
        .filter(|ns| *ns <= VENTANA_MAXIMA_NS)
        .ok_or_else(|| ErrorConsulta::nuevo("la ventana es mayor que diez anos", i, uf))?;
    Ok((ns, i, uf))
}

fn ventana(a: &mut Analizador) -> Result<Ventana, ErrorConsulta> {
    if acepta_palabra(a, "last") {
        let (ns, ..) = duracion(a)?;
        return Ok(Ventana::Ultimos { ns });
    }
    let (i, _) = a.tramo_actual();
    let desde = instante(a)?;
    exigir_palabra(a, "to", "la palabra TO entre los dos instantes")?;
    let hasta = instante(a)?;
    let (_, f) = a.tramo_actual();
    if hasta <= desde {
        return Err(ErrorConsulta::nuevo(
            "la ventana termina antes de empezar",
            i,
            f,
        ));
    }
    Ok(Ventana::Entre {
        desde_ns: desde,
        hasta_ns: hasta,
    })
}

fn instante(a: &mut Analizador) -> Result<u64, ErrorConsulta> {
    let (i, f) = a.tramo_actual();
    match a.actual().map(|s| s.token.clone()) {
        Some(Token::Cadena(s)) => {
            a.avanzar();
            rfc3339(&s).ok_or_else(|| {
                ErrorConsulta::nuevo(format!("'{s}' no es un instante RFC 3339"), i, f)
                    .con_sugerencia("por ejemplo: '2026-09-26T08:00:00Z'")
            })
        }
        _ => Err(
            ErrorConsulta::nuevo("aqui falta un instante entre comillas", i, f).con_sugerencia(
                "por ejemplo: DURING '2026-09-01T00:00:00Z' TO '2026-09-02T00:00:00Z'",
            ),
        ),
    }
}

/// Dias desde 1970-01-01 de una fecha civil (algoritmo de Howard Hinnant).
fn dias_desde_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `AAAA-MM-DDTHH:MM:SS[.frac](Z|±HH:MM)` a nanosegundos Unix.
fn rfc3339(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let t = s.get(r)?;
        t.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| t.parse().ok())?
    };
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't' | b' ') {
        return None;
    }
    let (ano, mes, dia) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, se) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mes) || !(1..=31).contains(&dia) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    let mut p = 19;
    let mut frac_ns: i64 = 0;
    if b.get(p) == Some(&b'.') {
        p += 1;
        let ini = p;
        while p < b.len() && b[p].is_ascii_digit() {
            p += 1;
        }
        let dig = s.get(ini..p)?;
        if dig.is_empty() {
            return None;
        }
        let nueve: String = dig.chars().chain(std::iter::repeat('0')).take(9).collect();
        frac_ns = nueve.parse().ok()?;
    }
    let desfase_s: i64 = match b.get(p)? {
        b'Z' | b'z' if p + 1 == b.len() => 0,
        signo @ (b'+' | b'-') if p + 6 == b.len() && b[p + 3] == b':' => {
            let (oh, om) = (num(p + 1..p + 3)?, num(p + 4..p + 6)?);
            let d = oh * 3600 + om * 60;
            if *signo == b'+' {
                d
            } else {
                -d
            }
        }
        _ => return None,
    };
    let segundos = dias_desde_civil(ano, mes, dia) * 86_400 + h * 3600 + mi * 60 + se - desfase_s;
    let ns = i128::from(segundos) * 1_000_000_000 + i128::from(frac_ns);
    u64::try_from(ns).ok()
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::sintaxis;

    fn ok(s: &str) -> ConsultaHistorica {
        analizar(s).unwrap_or_else(|e| panic!("{s}: {}", e.dibujar(s)))
    }

    fn err(s: &str) -> ErrorConsulta {
        analizar(s).expect_err(s)
    }

    /// Consultas del endpoint, de las pruebas y de la documentacion.
    const CORPUS_ENDPOINT: &[&str] = &[
        "SELECT pid, path, sha256 FROM processes WHERE network.port = 4444 AND memory.entropy > 7.0 ORDER BY memory.entropy DESC LIMIT 50",
        "SELECT * FROM processes",
        "SELECT COUNT(*) FROM processes WHERE name LIKE '%ssh%'",
        "SELECT pid FROM processes WHERE NOT (uid = 0 OR name IN ('init', 'systemd')) LIMIT 10",
        "SELECT name FROM processes WHERE 4444 < network.port",
        "SELECT pid FROM processes WHERE memory.rwx",
        "select pid from processes where name not like 'k%' order by pid asc",
    ];

    #[test]
    fn toda_consulta_del_endpoint_da_el_mismo_arbol_por_los_dos_caminos() {
        // LA PROMESA DE LA FASE: una consulta se escribe una vez y corre contra
        // el vivo y contra el historico. Aqui se exige que signifique lo mismo.
        for q in CORPUS_ENDPOINT {
            let endpoint = sintaxis::analizar(q).unwrap_or_else(|e| panic!("{q}: {e:?}"));
            assert_eq!(ok(q), desde_endpoint(&endpoint), "{q}");
        }
    }

    #[test]
    fn el_endpoint_sigue_rechazando_todo_lo_del_historico() {
        for q in [
            "SELECT pid FROM processes DURING LAST 24 HOURS",
            "SELECT name, COUNT(*) FROM processes GROUP BY name",
            "SELECT pid FROM processes WHERE entity IN (SELECT entity FROM verdicts LIMIT 5)",
            "SELECT host FROM events",
            "SELECT ts FROM processes",
        ] {
            assert!(sintaxis::analizar(q).is_err(), "el endpoint acepto: {q}");
            let _ = ok(q);
        }
    }

    #[test]
    fn ventana_relativa_y_absoluta() {
        let c = ok("SELECT pid FROM processes DURING LAST 24 HOURS");
        assert_eq!(
            c.ventana,
            Some(Ventana::Ultimos {
                ns: 24 * 3_600_000_000_000
            })
        );
        let c = ok("SELECT pid FROM processes DURING '2026-09-01T00:00:00Z' TO '2026-09-02T00:00:00.5+02:00'");
        assert_eq!(
            c.ventana,
            Some(Ventana::Entre {
                desde_ns: 1_788_220_800_000_000_000,
                hasta_ns: 1_788_220_800_000_000_000 + 22 * 3_600_000_000_000 + 500_000_000
            })
        );
        assert!(err(
            "SELECT pid FROM processes DURING '2026-09-02T00:00:00Z' TO '2026-09-01T00:00:00Z'"
        )
        .mensaje
        .contains("antes de empezar"));
        assert!(err("SELECT pid FROM processes DURING LAST 24 FORTNIGHTS")
            .mensaje
            .contains("unidad"));
        assert!(
            err("SELECT pid FROM processes DURING LAST 99999999999 DAYS")
                .mensaje
                .contains("diez")
        );
    }

    #[test]
    fn agregacion_con_cubos_de_tiempo() {
        let c = ok("SELECT bucket, host, COUNT(*), MAX(observed_ns) FROM events WHERE outcome = 'fallo' DURING LAST 1 DAYS GROUP BY EVERY 1 HOURS, host");
        assert_eq!(c.cada_ns, Some(3_600_000_000_000));
        let Seleccion::Agregada(s) = &c.seleccion else {
            panic!("{c:?}")
        };
        assert_eq!(s.len(), 4);
        assert_eq!(s[0], Salida::Cubo);
        assert!(
            matches!(&s[3], Salida::Agregado(Agregado::Maximo(c)) if c.nombre == "observed_ns")
        );
    }

    #[test]
    fn una_columna_suelta_en_una_agregada_tiene_que_ir_en_group_by() {
        let e = err("SELECT host, COUNT(*) FROM events");
        assert!(e.mensaje.contains("GROUP BY"), "{}", e.mensaje);
        let e = err("SELECT SUM(host) FROM events GROUP BY host");
        assert!(e.mensaje.contains("numericas"), "{}", e.mensaje);
    }

    #[test]
    fn union_por_entidad_como_subconsulta_acotada() {
        let c = ok("SELECT pid, path FROM processes WHERE entity IN (SELECT entity FROM verdicts WHERE result = 'malicioso' LIMIT 500) DURING LAST 7 DAYS");
        let Some(ExprH::EnSubconsulta {
            columna,
            sub,
            negado,
        }) = &c.filtro
        else {
            panic!("{c:?}")
        };
        assert_eq!(columna.nombre, "entity");
        assert!(!negado);
        assert_eq!(sub.tabla, "verdicts");
        assert_eq!(sub.limite, 500);
        assert_eq!(
            sub.ventana,
            Some(Ventana::Ultimos {
                ns: 7 * 86_400_000_000_000
            }),
            "sin ventana propia, hereda la de fuera"
        );
        let c = ok("SELECT pid FROM processes WHERE entity IN (SELECT entity FROM verdicts DURING LAST 1 HOURS LIMIT 5) DURING LAST 7 DAYS");
        let Some(ExprH::EnSubconsulta { sub, .. }) = &c.filtro else {
            panic!("{c:?}")
        };
        assert_eq!(
            sub.ventana,
            Some(Ventana::Ultimos {
                ns: 3_600_000_000_000
            }),
            "la suya manda"
        );
    }

    #[test]
    fn una_subconsulta_sin_techo_o_con_techo_enorme_se_rechaza() {
        let e = err("SELECT pid FROM processes WHERE entity IN (SELECT entity FROM verdicts)");
        assert!(
            e.mensaje.contains("tiene que llevar LIMIT"),
            "{}",
            e.mensaje
        );
        let e = err(
            "SELECT pid FROM processes WHERE entity IN (SELECT entity FROM verdicts LIMIT 5000)",
        );
        assert!(e.mensaje.contains("no puede devolver mas"), "{}", e.mensaje);
        let e = err("SELECT pid FROM processes WHERE entity IN (SELECT entity, result FROM verdicts LIMIT 5)");
        assert!(
            e.mensaje.contains("exactamente una columna"),
            "{}",
            e.mensaje
        );
        let e = err("SELECT pid FROM processes WHERE pid IN (SELECT entity FROM verdicts LIMIT 5)");
        assert!(e.mensaje.contains("devuelve"), "{}", e.mensaje);
    }

    #[test]
    fn las_subconsultas_estan_acotadas_en_numero_y_en_profundidad() {
        let mut q = String::from("SELECT pid FROM processes WHERE ");
        let partes: Vec<String> = (0..SUBCONSULTAS_MAXIMAS + 1)
            .map(|_| "entity IN (SELECT entity FROM verdicts LIMIT 5)".into())
            .collect();
        q.push_str(&partes.join(" OR "));
        assert!(err(&q).mensaje.contains("subconsultas"));
        // Anidadas mas alla del tope de profundidad: error, nunca un desborde de pila.
        let mut q = String::from("SELECT entity FROM verdicts LIMIT 5");
        for _ in 0..200 {
            q = format!("SELECT entity FROM verdicts WHERE entity IN ({q}) LIMIT 5");
        }
        assert!(analizar(&q).is_err());
    }

    #[test]
    fn las_columnas_virtuales_existen_en_toda_tabla_del_historico() {
        let c = ok("SELECT ts, entity FROM connections WHERE ts > 0");
        assert!(
            matches!(c.seleccion, Seleccion::Filas(Proyeccion::Columnas(ref v)) if v.len() == 2)
        );
        let e = err("SELECT tss FROM processes");
        assert_eq!(e.sugerencia.as_deref(), Some("quiza querias decir 'ts'"));
    }

    #[test]
    fn rfc3339_con_y_sin_desfase() {
        assert_eq!(rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(rfc3339("1970-01-01T01:00:00+01:00"), Some(0));
        assert_eq!(
            rfc3339("2000-02-29T12:00:00.123Z"),
            Some(951_825_600_123_000_000)
        );
        assert_eq!(rfc3339("2026-13-01T00:00:00Z"), None);
        assert_eq!(rfc3339("2026-01-01"), None);
        assert_eq!(
            rfc3339("1969-12-31T23:59:59Z"),
            None,
            "antes de la epoca no cabe en u64"
        );
    }

    #[test]
    fn ninguna_entrada_rara_entra_en_panico() {
        for q in [
            "SELECT",
            "SELECT pid FROM processes DURING",
            "SELECT pid FROM processes DURING LAST",
            "SELECT pid FROM processes GROUP BY",
            "SELECT pid FROM processes WHERE entity IN (",
            "SELECT pid FROM processes WHERE entity IN (SELECT",
            "SELECT SUM( FROM events",
            "SELECT pid FROM processes DURING '' TO ''",
            "SELECT pid FROM processes DURING '2026-09-01T00:00:00+99:99' TO 'x'",
        ] {
            let _ = analizar(q);
        }
    }
}
