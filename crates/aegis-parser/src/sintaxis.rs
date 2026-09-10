//! Analizador sintactico y semantico de AegisQL.
//!
//! Es un descendente recursivo con precedencia de Pratt para las expresiones.
//! Se escribe a mano en vez de generarlo por dos razones concretas:
//!
//!   1. Los mensajes de error. Un generador produce "unexpected token" con la
//!      posicion; aqui se puede decir "columna desconocida 'pdi', quiza querias
//!      decir 'pid'", que es la diferencia entre resolver un incidente y
//!      pelearse con la herramienta a las tres de la manana.
//!   2. La validacion contra el esquema ocurre DURANTE el analisis, no en una
//!      pasada posterior. Asi el error apunta al tramo exacto de la consulta y
//!      no a un nodo del arbol sin posicion.
//!
//! # Lo que este modulo garantiza
//!
//! Recibe texto de un operador remoto que se difundira a decenas de miles de
//! endpoints. Por tanto:
//!
//!   - **Nunca entra en panico.** Ni con entrada valida, ni invalida, ni
//!     adversaria. La recursion esta acotada explicitamente.
//!   - **Toda consulta que sale de aqui es ejecutable.** Tabla, columnas, tipos
//!     y limites ya estan comprobados; el ejecutor del endpoint no tiene que
//!     validar nada y no puede fallar por un nombre mal escrito.
//!   - **Toda consulta tiene techo.** Si el operador no escribe `LIMIT`, se le
//!     pone uno.

use crate::ast::{Columna, Comparador, Consulta, Expr, Literal, Orden, Proyeccion};
use crate::error::ErrorConsulta;
use crate::esquema::{self, Tabla, Tipo};
use crate::lexico::{self, Situado, Token};

/// Filas que devuelve una consulta que no escribe `LIMIT`.
///
/// Una consulta sin techo que devuelve los procesos de diez mil maquinas es una
/// denegacion de servicio contra el propio plano de control, provocada sin mala
/// intencion por un analista que se olvido de acotar.
pub const LIMITE_POR_DEFECTO: u32 = 100;

/// Techo absoluto: ni escribiendolo se puede pedir mas.
pub const LIMITE_MAXIMO: u32 = 10_000;

/// Profundidad maxima de anidamiento de expresiones.
///
/// Un descendente recursivo consume pila por cada parentesis. Sin este limite,
/// una consulta de la forma `WHERE ((((((...))))))` con unos miles de
/// parentesis desborda la pila y MATA el proceso: en el servidor seria una
/// denegacion de servicio trivial, y en el endpoint un agente de seguridad que
/// se cae solo. El limite se comprueba al descender, antes de recursar.
pub const PROFUNDIDAD_MAXIMA: usize = 32;

/// Elementos maximos en una lista `IN`.
///
/// Cada elemento es una comparacion mas por fila. Un `IN` con cien mil valores
/// convierte una consulta barata en un bucle anidado.
pub const ELEMENTOS_IN_MAXIMOS: usize = 256;

/// Analiza una consulta y la valida contra el esquema.
pub fn analizar(consulta: &str) -> Result<Consulta, ErrorConsulta> {
    let tokens = lexico::analizar(consulta).map_err(|(i, f)| {
        ErrorConsulta::nuevo("no entiendo este texto", i, f).con_sugerencia(
            "AegisQL admite identificadores, numeros y cadenas entre comillas simples",
        )
    })?;

    if tokens.is_empty() {
        return Err(ErrorConsulta::nuevo("la consulta esta vacia", 0, 0)
            .con_sugerencia("empieza por SELECT"));
    }

    let mut a = Analizador {
        tokens,
        pos: 0,
        fin_entrada: consulta.len(),
        profundidad: 0,
    };
    let c = a.consulta()?;
    a.exigir_final()?;
    Ok(c)
}

/// Estado del analisis.
struct Analizador {
    tokens: Vec<Situado>,
    pos: usize,
    fin_entrada: usize,
    profundidad: usize,
}

impl Analizador {
    // --- Utilidades de recorrido -------------------------------------------

    fn actual(&self) -> Option<&Situado> {
        self.tokens.get(self.pos)
    }

    /// Tramo al que apuntar en un error "aqui esperaba otra cosa".
    ///
    /// Si ya no quedan tokens, apunta al final de la entrada: decirle al
    /// operador "falta algo al final" es util; apuntar a la posicion 0 no.
    fn tramo_actual(&self) -> (usize, usize) {
        match self.actual() {
            Some(s) => (s.inicio, s.fin),
            None => (self.fin_entrada, self.fin_entrada),
        }
    }

    fn avanzar(&mut self) -> Option<Situado> {
        let s = self.tokens.get(self.pos).cloned();
        if s.is_some() {
            self.pos += 1;
        }
        s
    }

    /// Consume el token si es el esperado.
    fn acepta(&mut self, t: &Token) -> bool {
        if self.actual().map(|s| &s.token) == Some(t) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    /// Consume el token esperado o falla con un mensaje concreto.
    fn exigir(&mut self, t: &Token, que: &str) -> Result<Situado, ErrorConsulta> {
        if self.actual().map(|s| &s.token) == Some(t) {
            // El `unwrap` es seguro: la comparacion de arriba ya vio el token.
            Ok(self.avanzar().expect("el token acaba de comprobarse"))
        } else {
            let (i, f) = self.tramo_actual();
            Err(ErrorConsulta::nuevo(format!("aqui falta {que}"), i, f))
        }
    }

    fn exigir_final(&self) -> Result<(), ErrorConsulta> {
        match self.actual() {
            None => Ok(()),
            Some(s) => {
                Err(
                    ErrorConsulta::nuevo("sobra texto al final de la consulta", s.inicio, s.fin)
                        .con_sugerencia(
                            "AegisQL admite una sola consulta; no hay punto y coma ni subconsultas",
                        ),
                )
            }
        }
    }

    // --- Gramatica ----------------------------------------------------------

    fn consulta(&mut self) -> Result<Consulta, ErrorConsulta> {
        self.exigir(&Token::Select, "la palabra SELECT")?;

        // La proyeccion no se puede validar sin saber la tabla, y la tabla
        // viene despues. Se guarda en crudo y se resuelve tras el FROM.
        let proyeccion_cruda = self.proyeccion_cruda()?;

        self.exigir(&Token::From, "la palabra FROM")?;
        let tabla = self.tabla()?;

        let proyeccion = self.resolver_proyeccion(proyeccion_cruda, tabla)?;

        let filtro = if self.acepta(&Token::Where) {
            Some(self.expresion(tabla, 0)?)
        } else {
            None
        };

        let orden = if self.acepta(&Token::Order) {
            self.exigir(&Token::By, "la palabra BY tras ORDER")?;
            Some(self.orden(tabla)?)
        } else {
            None
        };

        let limite = if self.acepta(&Token::Limit) {
            self.limite()?
        } else {
            LIMITE_POR_DEFECTO
        };

        Ok(Consulta {
            proyeccion,
            tabla: tabla.nombre,
            filtro,
            orden,
            limite,
        })
    }

    /// Proyeccion sin resolver: nombres y posiciones, aun sin tabla.
    fn proyeccion_cruda(&mut self) -> Result<ProyeccionCruda, ErrorConsulta> {
        if self.acepta(&Token::Asterisco) {
            return Ok(ProyeccionCruda::Todo);
        }
        if self.acepta(&Token::Count) {
            self.exigir(&Token::ParenIzq, "un parentesis abierto tras COUNT")?;
            self.exigir(&Token::Asterisco, "un asterisco dentro de COUNT")
                .map_err(|e| {
                    e.con_sugerencia("AegisQL solo admite COUNT(*), no COUNT de una columna")
                })?;
            self.exigir(&Token::ParenDer, "un parentesis cerrado tras COUNT(*")?;
            return Ok(ProyeccionCruda::Cuenta);
        }

        let mut nombres = Vec::new();
        loop {
            let (nombre, i, f) = self.identificador("un nombre de columna")?;
            nombres.push((nombre, i, f));
            if !self.acepta(&Token::Coma) {
                break;
            }
        }
        Ok(ProyeccionCruda::Columnas(nombres))
    }

    fn resolver_proyeccion(
        &self,
        cruda: ProyeccionCruda,
        tabla: &'static Tabla,
    ) -> Result<Proyeccion, ErrorConsulta> {
        match cruda {
            ProyeccionCruda::Todo => Ok(Proyeccion::Todo),
            ProyeccionCruda::Cuenta => Ok(Proyeccion::Cuenta),
            ProyeccionCruda::Columnas(ns) => {
                let mut cols = Vec::with_capacity(ns.len());
                for (nombre, i, f) in ns {
                    let c = self.columna(tabla, &nombre, i, f)?;
                    cols.push(Columna {
                        nombre: c.nombre,
                        tipo: c.tipo,
                    });
                }
                Ok(Proyeccion::Columnas(cols))
            }
        }
    }

    fn tabla(&mut self) -> Result<&'static Tabla, ErrorConsulta> {
        let (nombre, i, f) = self.identificador("un nombre de tabla")?;
        match esquema::tabla(&nombre) {
            Some(t) => Ok(t),
            None => {
                let mut e = ErrorConsulta::nuevo(format!("no existe la tabla '{nombre}'"), i, f);
                let parecidas = esquema::tablas_parecidas(&nombre);
                e = if let Some(p) = parecidas.first() {
                    e.con_sugerencia(format!("quiza querias decir '{p}'"))
                } else {
                    let todas: Vec<&str> = esquema::TABLAS.iter().map(|t| t.nombre).collect();
                    e.con_sugerencia(format!("tablas disponibles: {}", todas.join(", ")))
                };
                Err(e)
            }
        }
    }

    fn columna(
        &self,
        tabla: &'static Tabla,
        nombre: &str,
        i: usize,
        f: usize,
    ) -> Result<&'static esquema::Columna, ErrorConsulta> {
        match tabla.columna(nombre) {
            Some(c) => Ok(c),
            None => {
                let mut e = ErrorConsulta::nuevo(
                    format!("la tabla '{}' no tiene la columna '{nombre}'", tabla.nombre),
                    i,
                    f,
                );
                let parecidas = esquema::columnas_parecidas(tabla, nombre);
                e = if let Some(p) = parecidas.first() {
                    e.con_sugerencia(format!("quiza querias decir '{p}'"))
                } else {
                    let todas: Vec<&str> = tabla.columnas.iter().map(|c| c.nombre).collect();
                    e.con_sugerencia(format!(
                        "columnas de '{}': {}",
                        tabla.nombre,
                        todas.join(", ")
                    ))
                };
                Err(e)
            }
        }
    }

    fn identificador(&mut self, que: &str) -> Result<(String, usize, usize), ErrorConsulta> {
        let (i, f) = self.tramo_actual();
        match self.actual().map(|s| s.token.clone()) {
            Some(Token::Ident(n)) => {
                self.pos += 1;
                Ok((n, i, f))
            }
            _ => Err(ErrorConsulta::nuevo(format!("aqui falta {que}"), i, f)),
        }
    }

    fn orden(&mut self, tabla: &'static Tabla) -> Result<Orden, ErrorConsulta> {
        let (nombre, i, f) = self.identificador("un nombre de columna tras ORDER BY")?;
        let c = self.columna(tabla, &nombre, i, f)?;
        let descendente = if self.acepta(&Token::Desc) {
            true
        } else {
            // ASC es el valor por defecto; aceptarlo explicito es cortesia.
            self.acepta(&Token::Asc);
            false
        };
        Ok(Orden {
            columna: c.nombre,
            descendente,
        })
    }

    fn limite(&mut self) -> Result<u32, ErrorConsulta> {
        let (i, f) = self.tramo_actual();
        match self.actual().map(|s| s.token.clone()) {
            Some(Token::Entero(n)) => {
                self.pos += 1;
                if n <= 0 {
                    return Err(ErrorConsulta::nuevo("LIMIT tiene que ser positivo", i, f));
                }
                let n = u32::try_from(n).unwrap_or(LIMITE_MAXIMO);
                if n > LIMITE_MAXIMO {
                    return Err(ErrorConsulta::nuevo(
                        format!("LIMIT no puede pasar de {LIMITE_MAXIMO}"),
                        i,
                        f,
                    )
                    .con_sugerencia(
                        "una consulta que devuelve mas filas que esto por endpoint satura el plano de control; acota el filtro",
                    ));
                }
                Ok(n)
            }
            _ => Err(ErrorConsulta::nuevo(
                "aqui falta un numero tras LIMIT",
                i,
                f,
            )),
        }
    }

    // --- Expresiones (Pratt) ------------------------------------------------
    //
    // Precedencia, de menor a mayor ligadura:
    //   0  OR
    //   1  AND
    //   2  NOT (prefijo)
    //   3  comparaciones, LIKE, IN
    //
    // El parametro `minimo` es la precedencia por debajo de la cual este nivel
    // no absorbe operadores: es lo que hace que `a OR b AND c` se agrupe como
    // `a OR (b AND c)` sin escribir un metodo por nivel.

    fn expresion(&mut self, tabla: &'static Tabla, minimo: u8) -> Result<Expr, ErrorConsulta> {
        self.profundidad += 1;
        if self.profundidad > PROFUNDIDAD_MAXIMA {
            let (i, f) = self.tramo_actual();
            self.profundidad -= 1;
            return Err(ErrorConsulta::nuevo(
                format!("la condicion anida mas de {PROFUNDIDAD_MAXIMA} niveles"),
                i,
                f,
            )
            .con_sugerencia("divide la caceria en varias consultas mas simples"));
        }
        let r = self.expresion_interna(tabla, minimo);
        self.profundidad -= 1;
        r
    }

    fn expresion_interna(
        &mut self,
        tabla: &'static Tabla,
        minimo: u8,
    ) -> Result<Expr, ErrorConsulta> {
        let mut izq = self.prefijo(tabla)?;

        loop {
            let precedencia = match self.actual().map(|s| &s.token) {
                Some(Token::Or) => 0,
                Some(Token::And) => 1,
                _ => break,
            };
            if precedencia < minimo {
                break;
            }
            let op = self
                .avanzar()
                .expect("el operador acaba de comprobarse")
                .token;
            // `precedencia + 1` hace los operadores asociativos por la
            // izquierda: `a AND b AND c` es `(a AND b) AND c`.
            let der = self.expresion(tabla, precedencia + 1)?;
            izq = match op {
                Token::Or => Expr::O(Box::new(izq), Box::new(der)),
                _ => Expr::Y(Box::new(izq), Box::new(der)),
            };
        }
        Ok(izq)
    }

    fn prefijo(&mut self, tabla: &'static Tabla) -> Result<Expr, ErrorConsulta> {
        if self.acepta(&Token::Not) {
            // NOT liga mas que AND pero menos que una comparacion.
            let e = self.expresion(tabla, 2)?;
            return Ok(Expr::No(Box::new(e)));
        }
        if self.acepta(&Token::ParenIzq) {
            let e = self.expresion(tabla, 0)?;
            self.exigir(&Token::ParenDer, "un parentesis cerrado")?;
            return Ok(e);
        }
        self.predicado(tabla)
    }

    /// Una comparacion, un LIKE, un IN o una columna booleana suelta.
    fn predicado(&mut self, tabla: &'static Tabla) -> Result<Expr, ErrorConsulta> {
        // Forma invertida: `4444 = network.port`. Se normaliza para que el
        // ejecutor tenga un solo caso que tratar.
        if let Some(e) = self.predicado_invertido(tabla)? {
            return Ok(e);
        }

        let (nombre, i, f) = self.identificador("una columna en la condicion")?;
        let col = self.columna(tabla, &nombre, i, f)?;

        // NOT LIKE / NOT IN.
        let negado = self.acepta(&Token::Not);

        if self.acepta(&Token::Like) {
            if col.tipo != Tipo::Texto {
                return Err(ErrorConsulta::nuevo(
                    format!(
                        "LIKE solo se aplica a texto, y '{}' es {}",
                        col.nombre,
                        col.tipo.nombre()
                    ),
                    i,
                    f,
                ));
            }
            let (patron, pi, pf) = self.literal_texto()?;
            let _ = (pi, pf);
            return Ok(Expr::Like {
                columna: col.nombre,
                patron,
                negado,
            });
        }

        if self.acepta(&Token::In) {
            return self.lista_in(col, negado);
        }

        if negado {
            let (i2, f2) = self.tramo_actual();
            return Err(ErrorConsulta::nuevo(
                "tras NOT aqui solo puede ir LIKE o IN",
                i2,
                f2,
            ));
        }

        // Columna booleana usada directamente como predicado.
        if col.tipo == Tipo::Booleano && !self.hay_comparador() {
            return Ok(Expr::Bandera {
                columna: col.nombre,
            });
        }

        let op = self.comparador()?;
        let (valor, vi, vf) = self.literal()?;
        self.comprobar_tipos(col, &valor, i, f, vi, vf)?;
        Ok(Expr::Comparacion {
            columna: col.nombre,
            op,
            valor,
        })
    }

    /// Reconoce `<literal> <comparador> <columna>` y devuelve la forma canonica.
    ///
    /// Se mira sin consumir: si lo que hay no es un literal, o tras el literal
    /// no viene un comparador, se deja el analizador donde estaba.
    fn predicado_invertido(
        &mut self,
        tabla: &'static Tabla,
    ) -> Result<Option<Expr>, ErrorConsulta> {
        let guardado = self.pos;
        let Ok((valor, vi, vf)) = self.literal() else {
            self.pos = guardado;
            return Ok(None);
        };
        let Ok(op) = self.comparador() else {
            self.pos = guardado;
            return Ok(None);
        };
        let Ok((nombre, i, f)) = self.identificador("una columna") else {
            self.pos = guardado;
            return Ok(None);
        };
        let col = self.columna(tabla, &nombre, i, f)?;
        self.comprobar_tipos(col, &valor, i, f, vi, vf)?;
        Ok(Some(Expr::Comparacion {
            columna: col.nombre,
            op: op.reflejado(),
            valor,
        }))
    }

    fn lista_in(
        &mut self,
        col: &'static esquema::Columna,
        negado: bool,
    ) -> Result<Expr, ErrorConsulta> {
        self.exigir(&Token::ParenIzq, "un parentesis abierto tras IN")?;
        let mut valores = Vec::new();
        loop {
            let (v, vi, vf) = self.literal()?;
            if !col.tipo.comparable_con(v.tipo()) {
                return Err(ErrorConsulta::nuevo(
                    format!(
                        "'{}' es {} y este valor es {}",
                        col.nombre,
                        col.tipo.nombre(),
                        v.tipo().nombre()
                    ),
                    vi,
                    vf,
                ));
            }
            valores.push(v);
            if valores.len() > ELEMENTOS_IN_MAXIMOS {
                return Err(ErrorConsulta::nuevo(
                    format!("un IN no puede tener mas de {ELEMENTOS_IN_MAXIMOS} valores"),
                    vi,
                    vf,
                )
                .con_sugerencia("cada valor es una comparacion mas por fila y por endpoint"));
            }
            if !self.acepta(&Token::Coma) {
                break;
            }
        }
        self.exigir(
            &Token::ParenDer,
            "un parentesis cerrado tras la lista de IN",
        )?;
        Ok(Expr::En {
            columna: col.nombre,
            valores,
            negado,
        })
    }

    fn hay_comparador(&self) -> bool {
        matches!(
            self.actual().map(|s| &s.token),
            Some(
                Token::Igual
                    | Token::Distinto
                    | Token::Menor
                    | Token::MenorIgual
                    | Token::Mayor
                    | Token::MayorIgual
            )
        )
    }

    fn comparador(&mut self) -> Result<Comparador, ErrorConsulta> {
        let (i, f) = self.tramo_actual();
        let c = match self.actual().map(|s| &s.token) {
            Some(Token::Igual) => Comparador::Igual,
            Some(Token::Distinto) => Comparador::Distinto,
            Some(Token::Menor) => Comparador::Menor,
            Some(Token::MenorIgual) => Comparador::MenorIgual,
            Some(Token::Mayor) => Comparador::Mayor,
            Some(Token::MayorIgual) => Comparador::MayorIgual,
            _ => {
                return Err(ErrorConsulta::nuevo("aqui falta un comparador", i, f)
                    .con_sugerencia("=, !=, <, <=, > o >="))
            }
        };
        self.pos += 1;
        Ok(c)
    }

    fn literal(&mut self) -> Result<(Literal, usize, usize), ErrorConsulta> {
        let (i, f) = self.tramo_actual();
        let l = match self.actual().map(|s| s.token.clone()) {
            Some(Token::Entero(n)) => Literal::Entero(n),
            Some(Token::Real(x)) => Literal::Real(x),
            Some(Token::Cadena(s)) => Literal::Texto(s),
            Some(Token::Verdadero) => Literal::Booleano(true),
            Some(Token::Falso) => Literal::Booleano(false),
            _ => {
                return Err(ErrorConsulta::nuevo("aqui falta un valor", i, f)
                    .con_sugerencia("un numero, un texto entre comillas simples, o true/false"))
            }
        };
        self.pos += 1;
        Ok((l, i, f))
    }

    fn literal_texto(&mut self) -> Result<(String, usize, usize), ErrorConsulta> {
        let (l, i, f) = self.literal()?;
        match l {
            Literal::Texto(s) => Ok((s, i, f)),
            otro => Err(ErrorConsulta::nuevo(
                format!(
                    "el patron de LIKE tiene que ser texto, y esto es {}",
                    otro.tipo().nombre()
                ),
                i,
                f,
            )),
        }
    }

    fn comprobar_tipos(
        &self,
        col: &'static esquema::Columna,
        valor: &Literal,
        ci: usize,
        cf: usize,
        vi: usize,
        vf: usize,
    ) -> Result<(), ErrorConsulta> {
        if col.tipo.comparable_con(valor.tipo()) {
            return Ok(());
        }
        let _ = (ci, cf);
        Err(ErrorConsulta::nuevo(
            format!(
                "'{}' es {} y no se puede comparar con {}",
                col.nombre,
                col.tipo.nombre(),
                valor.tipo().nombre()
            ),
            vi,
            vf,
        ))
    }
}

/// Proyeccion antes de conocer la tabla.
enum ProyeccionCruda {
    Todo,
    Cuenta,
    Columnas(Vec<(String, usize, usize)>),
}

impl Comparador {
    /// Comparador equivalente al intercambiar los dos lados.
    ///
    /// `4444 < network.port` significa lo mismo que `network.port > 4444`.
    /// Normalizarlo aqui evita que el ejecutor tenga que tratar cuatro casos.
    fn reflejado(self) -> Comparador {
        match self {
            Comparador::Igual => Comparador::Igual,
            Comparador::Distinto => Comparador::Distinto,
            Comparador::Menor => Comparador::Mayor,
            Comparador::MenorIgual => Comparador::MayorIgual,
            Comparador::Mayor => Comparador::Menor,
            Comparador::MayorIgual => Comparador::MenorIgual,
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn ok(s: &str) -> Consulta {
        analizar(s).unwrap_or_else(|e| panic!("deberia analizar:\n{}", e.dibujar(s)))
    }

    fn err(s: &str) -> ErrorConsulta {
        analizar(s).expect_err("deberia fallar")
    }

    // --- El ejemplo del encargo, entero -----------------------------------

    #[test]
    fn analiza_la_consulta_de_caza_del_encargo() {
        let c = ok("SELECT pid, path, sha256 FROM processes \
                    WHERE network.port = 4444 AND memory.entropy > 7.0");
        assert_eq!(c.tabla, "processes");
        let Proyeccion::Columnas(cols) = &c.proyeccion else {
            panic!("proyeccion de columnas");
        };
        assert_eq!(
            cols.iter().map(|c| c.nombre).collect::<Vec<_>>(),
            vec!["pid", "path", "sha256"]
        );
        let Some(Expr::Y(a, b)) = &c.filtro else {
            panic!("un AND en la raiz");
        };
        assert_eq!(
            **a,
            Expr::Comparacion {
                columna: "network.port",
                op: Comparador::Igual,
                valor: Literal::Entero(4444),
            }
        );
        assert_eq!(
            **b,
            Expr::Comparacion {
                columna: "memory.entropy",
                op: Comparador::Mayor,
                valor: Literal::Real(7.0),
            }
        );
        // Sin LIMIT explicito se aplica el de por defecto: ninguna consulta
        // sale de aqui sin techo.
        assert_eq!(c.limite, LIMITE_POR_DEFECTO);
    }

    // --- Precedencia -------------------------------------------------------

    #[test]
    fn and_liga_mas_que_or() {
        // a OR (b AND c), no (a OR b) AND c.
        let c = ok("SELECT pid FROM processes WHERE uid = 0 OR uid = 1 AND threads > 4");
        let Some(Expr::O(_, der)) = &c.filtro else {
            panic!("la raiz debe ser OR, no AND");
        };
        assert!(matches!(**der, Expr::Y(_, _)));
    }

    #[test]
    fn el_parentesis_manda_sobre_la_precedencia() {
        let c = ok("SELECT pid FROM processes WHERE (uid = 0 OR uid = 1) AND threads > 4");
        assert!(matches!(c.filtro, Some(Expr::Y(_, _))));
    }

    #[test]
    fn and_es_asociativo_por_la_izquierda() {
        let c = ok("SELECT pid FROM processes WHERE uid = 0 AND gid = 0 AND threads > 1");
        let Some(Expr::Y(izq, der)) = &c.filtro else {
            panic!("AND en la raiz");
        };
        assert!(matches!(**izq, Expr::Y(_, _)), "(a AND b) AND c");
        assert!(matches!(**der, Expr::Comparacion { .. }));
    }

    #[test]
    fn not_liga_mas_que_and() {
        // NOT a AND b  ==  (NOT a) AND b
        let c = ok("SELECT pid FROM processes WHERE NOT uid = 0 AND threads > 1");
        let Some(Expr::Y(izq, _)) = &c.filtro else {
            panic!("la raiz debe ser AND");
        };
        assert!(matches!(**izq, Expr::No(_)));
    }

    // --- Normalizacion -----------------------------------------------------

    #[test]
    fn la_comparacion_invertida_se_normaliza_y_refleja_el_operador() {
        // `4444 < network.port` es `network.port > 4444`.
        let c = ok("SELECT pid FROM processes WHERE 4444 < network.port");
        assert_eq!(
            c.filtro,
            Some(Expr::Comparacion {
                columna: "network.port",
                op: Comparador::Mayor,
                valor: Literal::Entero(4444),
            })
        );
    }

    #[test]
    fn las_dos_formas_de_escribir_lo_mismo_dan_el_mismo_arbol() {
        assert_eq!(
            ok("SELECT pid FROM processes WHERE uid >= 1000").filtro,
            ok("SELECT pid FROM processes WHERE 1000 <= uid").filtro
        );
    }

    // --- Validacion semantica ---------------------------------------------

    #[test]
    fn una_columna_mal_escrita_se_caza_al_analizar_y_se_sugiere_la_buena() {
        let e = err("SELECT pdi FROM processes");
        assert!(e.mensaje.contains("pdi"), "{}", e.mensaje);
        assert_eq!(e.sugerencia.as_deref(), Some("quiza querias decir 'pid'"));
    }

    #[test]
    fn una_tabla_inexistente_se_caza_al_analizar() {
        let e = err("SELECT pid FROM procesos");
        assert!(e.mensaje.contains("procesos"));
        assert!(e.sugerencia.unwrap().contains("processes"));
    }

    #[test]
    fn una_columna_de_otra_tabla_no_vale() {
        // `remote_ip` existe, pero en `connections`, no en `processes`.
        let e = err("SELECT remote_ip FROM processes");
        assert!(e.mensaje.contains("remote_ip"), "{}", e.mensaje);
    }

    #[test]
    fn no_se_puede_comparar_texto_con_numero() {
        let e = err("SELECT pid FROM processes WHERE path = 4444");
        assert!(e.mensaje.contains("texto"), "{}", e.mensaje);
    }

    #[test]
    fn entero_y_real_si_se_comparan_entre_si() {
        // Escribir `> 7` en vez de `> 7.0` es lo que hace cualquiera.
        ok("SELECT pid FROM processes WHERE memory.entropy > 7");
        ok("SELECT pid FROM processes WHERE memory.entropy > 7.5");
    }

    #[test]
    fn like_solo_se_aplica_a_texto() {
        ok("SELECT pid FROM processes WHERE cmdline LIKE '%--decrypt%'");
        let e = err("SELECT pid FROM processes WHERE pid LIKE '4%'");
        assert!(e.mensaje.contains("LIKE"), "{}", e.mensaje);
    }

    #[test]
    fn una_columna_booleana_vale_como_predicado_por_si_sola() {
        let c = ok("SELECT pid FROM processes WHERE memory.rwx");
        assert_eq!(
            c.filtro,
            Some(Expr::Bandera {
                columna: "memory.rwx"
            })
        );
    }

    #[test]
    fn in_exige_valores_del_tipo_de_la_columna() {
        ok("SELECT pid FROM processes WHERE uid IN (0, 1000, 1001)");
        let e = err("SELECT pid FROM processes WHERE uid IN (0, 'root')");
        assert!(e.mensaje.contains("texto"), "{}", e.mensaje);
    }

    #[test]
    fn not_in_y_not_like_se_reconocen() {
        let c = ok("SELECT pid FROM processes WHERE uid NOT IN (0, 1)");
        assert!(matches!(c.filtro, Some(Expr::En { negado: true, .. })));
        let c = ok("SELECT pid FROM processes WHERE path NOT LIKE '/usr/%'");
        assert!(matches!(c.filtro, Some(Expr::Like { negado: true, .. })));
    }

    // --- Limites -----------------------------------------------------------

    #[test]
    fn toda_consulta_sale_con_techo() {
        assert_eq!(ok("SELECT pid FROM processes").limite, LIMITE_POR_DEFECTO);
        assert_eq!(ok("SELECT pid FROM processes LIMIT 5").limite, 5);
    }

    #[test]
    fn no_se_puede_pedir_mas_del_techo_absoluto() {
        let e = err(&format!(
            "SELECT pid FROM processes LIMIT {}",
            LIMITE_MAXIMO + 1
        ));
        assert!(e.mensaje.contains("LIMIT"), "{}", e.mensaje);
    }

    #[test]
    fn un_limite_no_positivo_se_rechaza() {
        assert!(err("SELECT pid FROM processes LIMIT 0")
            .mensaje
            .contains("positivo"));
    }

    #[test]
    fn una_lista_in_desmesurada_se_rechaza() {
        let valores: Vec<String> = (0..ELEMENTOS_IN_MAXIMOS + 5)
            .map(|i| i.to_string())
            .collect();
        let q = format!(
            "SELECT pid FROM processes WHERE uid IN ({})",
            valores.join(", ")
        );
        assert!(err(&q).mensaje.contains("IN"));
    }

    // --- Entrada adversaria -------------------------------------------------
    //
    // Esta gramatica recibe texto de un operador remoto y se difunde a miles de
    // endpoints. Ninguna entrada puede tumbar el proceso.

    #[test]
    fn una_anidacion_desmesurada_se_rechaza_sin_desbordar_la_pila() {
        // Sin el limite de profundidad esto mata el proceso, y en el servidor
        // seria una denegacion de servicio de una linea.
        let n = 5_000;
        let q = format!(
            "SELECT pid FROM processes WHERE {}uid = 0{}",
            "(".repeat(n),
            ")".repeat(n)
        );
        let e = err(&q);
        assert!(e.mensaje.contains("anida"), "{}", e.mensaje);
    }

    #[test]
    fn ninguna_entrada_rara_entra_en_panico() {
        let entradas = [
            "",
            "   ",
            "SELECT",
            "SELECT FROM",
            "SELECT pid FROM",
            "SELECT pid FROM processes WHERE",
            "SELECT pid FROM processes WHERE uid",
            "SELECT pid FROM processes WHERE uid =",
            "SELECT pid FROM processes WHERE = 0",
            "SELECT pid FROM processes WHERE ((((",
            "SELECT pid FROM processes WHERE ))))",
            "SELECT pid FROM processes LIMIT",
            "SELECT pid FROM processes LIMIT -1",
            "SELECT pid FROM processes ORDER BY",
            "SELECT pid FROM processes ORDER",
            "SELECT COUNT FROM processes",
            "SELECT COUNT(pid) FROM processes",
            "SELECT , FROM processes",
            "SELECT pid, FROM processes",
            "SELECT pid FROM processes; DROP TABLE processes",
            "SELECT pid FROM processes WHERE uid IN ()",
            "SELECT pid FROM processes WHERE uid IN (,)",
            "SELECT pid FROM processes WHERE path LIKE",
            "SELECT pid FROM processes WHERE NOT",
            "SELECT pid FROM processes WHERE NOT uid",
            "'",
            "''''''''",
            "\u{0}\u{1}\u{2}",
            "SELECT pid FROM processes WHERE path = 'año'",
        ];
        for e in entradas {
            // Lo unico que se exige es que no entre en panico; el resultado
            // puede ser Ok o Err segun el caso.
            let _ = analizar(e);
        }
    }

    #[test]
    fn no_hay_forma_de_expresar_una_escritura() {
        // No es una lista negra: la gramatica no tiene esos verbos, asi que
        // fallan como identificadores fuera de sitio. Esta prueba deja
        // constancia de que sigue siendo asi.
        for q in [
            "DROP TABLE processes",
            "DELETE FROM processes",
            "UPDATE processes SET uid = 0",
            "INSERT INTO processes VALUES (1)",
            "SELECT pid FROM processes; DELETE FROM processes",
        ] {
            assert!(analizar(q).is_err(), "no deberia analizar: {q}");
        }
    }

    #[test]
    fn no_se_admite_mas_de_una_consulta() {
        let e = err("SELECT pid FROM processes SELECT pid FROM processes");
        assert!(e.mensaje.contains("sobra"), "{}", e.mensaje);
    }

    // --- Orden -------------------------------------------------------------

    #[test]
    fn order_by_valida_la_columna_y_el_sentido() {
        let c = ok("SELECT pid FROM processes ORDER BY memory.entropy DESC LIMIT 20");
        let o = c.orden.unwrap();
        assert_eq!(o.columna, "memory.entropy");
        assert!(o.descendente);
        assert_eq!(c.limite, 20);

        let c = ok("SELECT pid FROM processes ORDER BY pid");
        assert!(!c.orden.unwrap().descendente, "ASC es el defecto");

        assert!(err("SELECT pid FROM processes ORDER BY inventada")
            .mensaje
            .contains("inventada"));
    }

    #[test]
    fn count_solo_admite_asterisco() {
        assert_eq!(
            ok("SELECT COUNT(*) FROM processes").proyeccion,
            Proyeccion::Cuenta
        );
        let e = err("SELECT COUNT(pid) FROM processes");
        assert!(e.sugerencia.unwrap().contains("COUNT(*)"));
    }

    #[test]
    fn el_asterisco_es_una_proyeccion_valida() {
        assert_eq!(ok("SELECT * FROM connections").proyeccion, Proyeccion::Todo);
    }
}
