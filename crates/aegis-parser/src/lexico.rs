//! Analisis lexico de AegisQL.
//!
//! El automata lo genera `logos` a partir de los patrones declarados abajo. Se
//! prefiere a un tokenizador escrito a mano por una razon concreta: lo dificil
//! de un lexer no es la logica, es la EXHAUSTIVIDAD —que ningun byte de la
//! entrada quede sin transicion definida—. `logos` construye el automata
//! completo y convierte en error de compilacion cualquier patron ambiguo.
//!
//! Esta entrada llega de un operador remoto y se difunde a miles de endpoints,
//! asi que el lexer no puede entrar en panico jamas: todo lo que no encaja se
//! convierte en `Token::Invalido` y el parser lo reporta con su posicion.

use logos::Logos;

/// Un componente lexico de AegisQL.
///
/// Las palabras clave NO distinguen mayusculas de minusculas (`SELECT` y
/// `select` son la misma), pero los identificadores SI: `path` y `PATH` son
/// columnas distintas, y confundirlas seria un error silencioso.
#[derive(Logos, Debug, Clone, PartialEq)]
#[logos(skip r"[ \t\r\n\f]+")]
// Comentarios de linea al estilo SQL. Una consulta guardada en un manual de
// respuesta a incidentes se lee mejor con ellos.
#[logos(skip r"--[^\n]*")]
pub enum Token {
    // --- Palabras clave ---------------------------------------------------
    #[regex(r"(?i)select")]
    /// Inicio de una consulta.
    Select,
    #[regex(r"(?i)from")]
    /// Introduce la tabla sobre la que se consulta.
    From,
    #[regex(r"(?i)where")]
    /// Introduce el filtro.
    Where,
    #[regex(r"(?i)order")]
    /// Primera mitad de `ORDER BY`.
    Order,
    #[regex(r"(?i)by")]
    /// Segunda mitad de `ORDER BY`.
    By,
    #[regex(r"(?i)asc")]
    /// Orden ascendente.
    Asc,
    #[regex(r"(?i)desc")]
    /// Orden descendente.
    Desc,
    #[regex(r"(?i)limit")]
    /// Acota el numero de filas devueltas.
    Limit,
    #[regex(r"(?i)and")]
    /// Conjuncion logica.
    And,
    #[regex(r"(?i)or")]
    /// Disyuncion logica.
    Or,
    #[regex(r"(?i)not")]
    /// Negacion logica.
    Not,
    #[regex(r"(?i)like")]
    /// Comparacion de texto con comodines `%` y `_`.
    Like,
    #[regex(r"(?i)in")]
    /// Pertenencia a una lista de literales.
    In,
    #[regex(r"(?i)true")]
    /// Literal booleano cierto.
    Verdadero,
    #[regex(r"(?i)false")]
    /// Literal booleano falso.
    Falso,
    #[regex(r"(?i)count")]
    /// Funcion de agregacion: cuenta filas.
    Count,

    // --- Operadores -------------------------------------------------------
    #[token("=")]
    /// Comparacion de igualdad.
    Igual,
    // Se aceptan las dos formas de desigualdad porque quien escribe consultas
    // viene de SQL o de un lenguaje tipo C, y discutirlo no aporta nada.
    #[token("!=")]
    #[token("<>")]
    /// Comparacion de desigualdad, en sus dos formas.
    Distinto,
    #[token("<")]
    /// Comparacion "menor que".
    Menor,
    #[token("<=")]
    /// Comparacion "menor o igual".
    MenorIgual,
    #[token(">")]
    /// Comparacion "mayor que".
    Mayor,
    #[token(">=")]
    /// Comparacion "mayor o igual".
    MayorIgual,

    // --- Puntuacion -------------------------------------------------------
    #[token("(")]
    /// Abre un grupo o la lista de un `IN`.
    ParenIzq,
    #[token(")")]
    /// Cierra un grupo o la lista de un `IN`.
    ParenDer,
    #[token(",")]
    /// Separa elementos de una lista.
    Coma,
    #[token("*")]
    /// Selecciona todas las columnas, o el argumento de `COUNT(*)`.
    Asterisco,

    // --- Literales e identificadores --------------------------------------
    //
    // El identificador admite un punto interior: `memory.entropy` es UN nombre
    // de columna, no un acceso a un campo de una tabla. AegisQL no tiene JOIN
    // —ver `esquema.rs` para el porque—, asi que el punto no es ambiguo.
    #[regex(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*", |lex| lex.slice().to_string())]
    /// Nombre de columna o de tabla; puede ir cualificado con un punto.
    Ident(String),

    /// Cadena entre comillas simples. Para incluir una comilla se duplica,
    /// igual que en SQL: `'no es un ''problema'''`.
    #[regex(r"'([^']|'')*'", |lex| desescapar(lex.slice()))]
    Cadena(String),

    /// Entero sin signo. El signo, si lo hay, es el operador unario.
    #[regex(r"[0-9]+", |lex| lex.slice().parse::<i64>().ok())]
    Entero(i64),

    /// Real. Se exige digito a ambos lados del punto para que `1.` o `.5` no
    /// se confundan nunca con un identificador cualificado.
    #[regex(r"[0-9]+\.[0-9]+", |lex| lex.slice().parse::<f64>().ok())]
    Real(f64),
}

/// Quita las comillas exteriores y colapsa las dobles interiores.
fn desescapar(bruto: &str) -> String {
    // El patron garantiza que hay al menos dos comillas, pero no se asume:
    // esta funcion se llama con lo que diga el lexer y un cambio futuro del
    // patron no debe convertirse en un panico por indexar fuera de rango.
    let interior = bruto
        .strip_prefix('\'')
        .and_then(|s| s.strip_suffix('\''))
        .unwrap_or(bruto);
    interior.replace("''", "'")
}

/// Un token con el tramo de la entrada del que salio.
///
/// La posicion no es un lujo: un operador que escribe una consulta de caza a
/// las tres de la manana necesita que el error le senale la columna exacta, no
/// que le diga "error de sintaxis".
#[derive(Debug, Clone, PartialEq)]
pub struct Situado {
    /// El componente lexico.
    pub token: Token,
    /// Desplazamiento en bytes del principio, dentro de la consulta original.
    pub inicio: usize,
    /// Desplazamiento en bytes del final (exclusivo).
    pub fin: usize,
}

/// Trocea la consulta.
///
/// Devuelve `Err(posicion)` en el primer byte que no encaja en ningun patron.
/// No hay recuperacion de errores lexicos a proposito: una consulta con basura
/// dentro no se ejecuta a medias en diez mil endpoints.
pub fn analizar(entrada: &str) -> Result<Vec<Situado>, (usize, usize)> {
    let mut lex = Token::lexer(entrada);
    let mut salida = Vec::new();
    while let Some(res) = lex.next() {
        let tramo = lex.span();
        match res {
            Ok(token) => salida.push(Situado {
                token,
                inicio: tramo.start,
                fin: tramo.end,
            }),
            Err(()) => return Err((tramo.start, tramo.end)),
        }
    }
    Ok(salida)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn tokens(s: &str) -> Vec<Token> {
        analizar(s).unwrap().into_iter().map(|t| t.token).collect()
    }

    #[test]
    fn las_palabras_clave_no_distinguen_mayusculas() {
        assert_eq!(tokens("SELECT"), tokens("select"));
        assert_eq!(tokens("Where"), vec![Token::Where]);
    }

    #[test]
    fn los_identificadores_si_distinguen_mayusculas() {
        // Si `PATH` y `path` fueran lo mismo, una consulta escrita con la
        // mayuscula equivocada apuntaria a otra columna sin avisar.
        assert_eq!(tokens("path"), vec![Token::Ident("path".into())]);
        assert_eq!(tokens("PATH"), vec![Token::Ident("PATH".into())]);
        assert_ne!(tokens("path"), tokens("PATH"));
    }

    #[test]
    fn un_nombre_cualificado_es_un_solo_token() {
        assert_eq!(
            tokens("memory.entropy"),
            vec![Token::Ident("memory.entropy".into())]
        );
    }

    #[test]
    fn el_real_exige_digitos_a_ambos_lados_del_punto() {
        assert_eq!(tokens("7.0"), vec![Token::Real(7.0)]);
        // `7.` no es un real: es un entero seguido de algo que no encaja.
        assert!(analizar("7.").is_err());
    }

    #[test]
    fn una_comilla_se_escapa_duplicandola() {
        assert_eq!(
            tokens("'no es un ''problema'''"),
            vec![Token::Cadena("no es un 'problema'".into())]
        );
    }

    #[test]
    fn los_comentarios_se_descartan() {
        assert_eq!(
            tokens("select -- esto es un comentario\n  pid"),
            vec![Token::Select, Token::Ident("pid".into())]
        );
    }

    #[test]
    fn las_dos_formas_de_desigualdad_son_la_misma() {
        assert_eq!(tokens("!="), tokens("<>"));
    }

    #[test]
    fn un_byte_invalido_da_error_con_su_posicion() {
        let e = analizar("select # from processes").unwrap_err();
        assert_eq!(e.0, 7, "el error apunta al caracter ofensivo");
    }

    #[test]
    fn una_cadena_sin_cerrar_no_entra_en_panico() {
        assert!(analizar("'sin cerrar").is_err());
    }

    #[test]
    fn un_entero_desmesurado_no_entra_en_panico() {
        // Mas de lo que cabe en i64: el callback devuelve None y logos lo
        // convierte en error lexico, no en desbordamiento.
        assert!(analizar("999999999999999999999999").is_err());
    }
}
