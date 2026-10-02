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

/// Bytes maximos de una consulta, antes de trocearla.
///
/// El automata de `logos` recorre los patrones con alternativas (el literal
/// entre comillas y el numero, que compite con el real) con una llamada por
/// caracter: sin optimizar, la pila crece con la longitud del token. Medido en
/// un hilo de 2 MiB, como los del servidor: 64 Ki caracteres desbordan y
/// abortan el proceso, 16 Ki caben. 8 KiB deja ocho veces de margen sobre lo
/// que desborda y el doble de lo que admite la API (4 KiB). La prueba
/// `el_peor_token_en_el_tope_cabe_en_un_hilo_de_2_mib` es la puerta.
pub const ENTRADA_MAXIMA_BYTES: usize = 8 * 1024;

/// Si un caracter no puede aparecer en una consulta: los de control (salvo
/// tabulador y saltos de linea), los de direccion de texto y el BOM.
///
/// Una consulta se guarda, se difunde y la lee un analista. El NUL no cabe en
/// un texto de PostgreSQL y hacia fallar la caza al guardarla; los controles de
/// direccion (U+202A-U+202E, U+2066-U+2069) hacen que la consola muestre algo
/// distinto de lo que la consulta dice (Trojan Source, CVE-2021-42574). Ningun
/// dato que se caza los contiene: un nombre de proceso, una ruta o una orden no
/// llevan NUL, y un literal con ellos no casaria con nada legitimo.
pub fn caracter_vetado(c: char) -> bool {
    (c.is_control() && !matches!(c, '\t' | '\n' | '\r'))
        || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}')
}

/// Trocea la consulta.
///
/// Devuelve `Err(posicion)` en el primer byte que no encaja en ningun patron,
/// o el tramo que sobra si la entrada pasa de [`ENTRADA_MAXIMA_BYTES`].
/// No hay recuperacion de errores lexicos a proposito: una consulta con basura
/// dentro no se ejecuta a medias en diez mil endpoints.
pub fn analizar(entrada: &str) -> Result<Vec<Situado>, (usize, usize)> {
    if entrada.len() > ENTRADA_MAXIMA_BYTES {
        return Err((ENTRADA_MAXIMA_BYTES, entrada.len()));
    }
    if let Some((i, c)) = entrada.char_indices().find(|(_, c)| caracter_vetado(*c)) {
        return Err((i, i + c.len_utf8()));
    }
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

    /// La puerta del tope: el peor token de cada clase con la entrada justo en
    /// el limite, en un hilo del tamano de los del servidor. Si alguien sube el
    /// tope o añade un patron que recursa mas, esto aborta y lo dice.
    #[test]
    fn el_peor_token_en_el_tope_cabe_en_un_hilo_de_2_mib() {
        std::thread::Builder::new()
            .stack_size(2 << 20)
            .spawn(|| {
                let n = ENTRADA_MAXIMA_BYTES;
                let cadena = format!("'{}'", "a".repeat(n - 2));
                let numero = "1".repeat(n);
                let real = format!("{}.{}", "1".repeat(n / 2), "1".repeat(n / 2 - 1));
                let ident = "a".repeat(n);
                for q in [&cadena, &numero, &real, &ident] {
                    assert_eq!(q.len(), n);
                    let _ = analizar(q);
                }
                assert!(
                    analizar(&"a".repeat(n + 1)).is_err(),
                    "por encima del tope se rechaza"
                );
            })
            .expect("hilo de prueba")
            .join()
            .expect("sin desborde de pila en el tope");
    }

    #[test]
    fn los_controles_y_la_direccion_de_texto_se_rechazan_con_su_posicion() {
        for (q, pos) in [
            // `...name = '` ocupa 40 bytes: el caracter vetado va justo detras.
            ("SELECT pid FROM processes WHERE name = 'a\u{0}'", 41),
            (
                "SELECT pid FROM processes WHERE name = '\u{202E}gpj.exe'",
                40,
            ),
            ("SELECT pid FROM processes WHERE name = '\u{FEFF}x'", 40),
            ("SELECT pid FROM processes WHERE name = '\u{1B}[31m'", 40),
        ] {
            assert_eq!(analizar(q).unwrap_err().0, pos, "{q:?}");
        }
        // Tabulador y saltos de linea siguen siendo espacio.
        assert!(analizar("SELECT pid\tFROM processes\r\nWHERE uid = 0").is_ok());
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
