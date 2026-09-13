//! Rechazo de expresiones regulares patologicas, ANTES de distribuirlas.
//!
//! # El ataque, que no necesita ser un ataque
//!
//! Una expresion como `(a+)+$` tiene retroceso catastrofico: contra una cadena
//! de treinta caracteres que no casa, un motor con retroceso explora del orden
//! de 2^30 caminos. Son segundos. Con cuarenta, horas.
//!
//! Ahora piensese donde corre eso: **en el endpoint del cliente, por cada
//! paquete**. Una sola regla asi, distribuida a la flota, es una denegacion de
//! servicio contra el propio producto, firmada por nosotros y aplicada por
//! nosotros. No hace falta que nadie la escriba con mala intencion: aparecen
//! solas en reglas escritas con prisa.
//!
//! # Por que se ANALIZA la estructura en vez de medir el tiempo
//!
//! Lo obvio seria compilar la expresion y cronometrarla contra unas cadenas.
//! Eso falla por dos lados:
//!
//! 1. **Depende de la cadena.** El caso malo de una expresion patologica es una
//!    cadena concreta, y encontrarla es el problema que se intenta evitar. Una
//!    medicion con cadenas al azar da verde a expresiones que explotan con la
//!    entrada que traera el atacante.
//! 2. **Depende de la maquina.** Un umbral en milisegundos calibrado en el
//!    servidor de compilacion no dice nada del portatil del cliente.
//!
//! Aqui se mira la ESTRUCTURA, que no depende ni de la cadena ni de la maquina:
//! el retroceso catastrofico viene de un puñado de formas reconocibles.
//!
//! # Las formas que se rechazan, y por que cada una
//!
//! | Forma | Ejemplo | Por que explota |
//! |---|---|---|
//! | Cuantificador sobre cuantificador | `(a+)+`, `(a*)*` | cada reparto de las mismas letras entre las dos vueltas es un camino distinto |
//! | Alternancia solapada bajo cuantificador | `(a\|a)*`, `(a\|ab)*` | las dos ramas casan lo mismo, asi que cada eleccion multiplica los caminos |
//! | Cuantificadores acotados enormes anidados | `(a{1,1000}){1,1000}` | lo mismo, pero contado a mano |
//!
//! # Y una cota de complejidad ademas
//!
//! Una expresion puede no ser patologica y aun asi ser absurda: doscientos
//! grupos, mil alternativas. Cuesta en memoria y en tiempo por paquete, y ese
//! coste lo paga el cliente. Se acota y se DICE, en vez de descubrirlo cuando su
//! CPU esta al cien por cien.
//!
//! # Lo que este analisis NO garantiza
//!
//! No es un demostrador: reconoce las formas conocidas de explosion, no todas
//! las posibles. Se declara asi a proposito, porque un analizador que se vende
//! como completo invita a saltarse las demas defensas. Las demas defensas
//! —presupuesto, canario, modo por defecto sin bloqueo— siguen ahi.

use crate::presupuesto::Presupuesto;

/// Por que una expresion regular no se acepta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Patologia {
    /// Un cuantificador aplicado sobre algo que ya lleva cuantificador.
    CuantificadorAnidado {
        /// Donde empieza la forma, en bytes.
        posicion: usize,
        /// El fragmento implicado, recortado.
        fragmento: String,
    },
    /// Una alternancia cuyas ramas casan lo mismo, bajo un cuantificador.
    AlternanciaSolapada {
        /// Donde empieza.
        posicion: usize,
        /// Las ramas que se solapan.
        fragmento: String,
    },
    /// La expresion es demasiado compleja aunque no sea patologica.
    DemasiadoCompleja {
        /// Complejidad estimada.
        complejidad: u32,
        /// Tope que se ha pasado.
        tope: u32,
    },
    /// La expresion no se puede analizar (parentesis sin cerrar, etc.).
    ///
    /// Se rechaza, y no se da por buena. Una expresion que el analizador no
    /// entiende es una expresion sobre la que no se puede afirmar nada.
    NoAnalizable {
        /// Que paso.
        detalle: String,
    },
}

impl Patologia {
    /// Codigo estable, para contar en el informe.
    #[must_use]
    pub fn codigo(&self) -> &'static str {
        match self {
            Patologia::CuantificadorAnidado { .. } => "regex-cuantificador-anidado",
            Patologia::AlternanciaSolapada { .. } => "regex-alternancia-solapada",
            Patologia::DemasiadoCompleja { .. } => "regex-demasiado-compleja",
            Patologia::NoAnalizable { .. } => "regex-no-analizable",
        }
    }

    /// Explicacion legible.
    #[must_use]
    pub fn explicacion(&self) -> String {
        match self {
            Patologia::CuantificadorAnidado {
                posicion,
                fragmento,
            } => format!(
                "cuantificador sobre cuantificador en la posicion {posicion} («{fragmento}»): \
                 cada reparto de las mismas letras entre las dos vueltas es un camino distinto"
            ),
            Patologia::AlternanciaSolapada {
                posicion,
                fragmento,
            } => format!(
                "alternancia con ramas que casan lo mismo bajo un cuantificador, en la \
                 posicion {posicion} («{fragmento}»): cada eleccion multiplica los caminos"
            ),
            Patologia::DemasiadoCompleja { complejidad, tope } => format!(
                "complejidad {complejidad} por encima del tope {tope}: no explota, pero su \
                 coste por paquete lo paga el endpoint del cliente"
            ),
            Patologia::NoAnalizable { detalle } => format!(
                "no se pudo analizar ({detalle}); una expresion que no se entiende no se \
                 distribuye, porque no se puede afirmar nada sobre ella"
            ),
        }
    }
}

/// Un elemento del recorrido de la expresion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Marco {
    /// Donde abrio el grupo.
    inicio: usize,
    /// Si dentro del grupo hay algun cuantificador en el nivel superior.
    lleva_cuantificador: bool,
    /// Ramas de alternancia vistas en este grupo, por su texto.
    alternancia: bool,
}

/// Analiza una expresion regular y devuelve la patologia si la hay.
///
/// # Errores
/// Devuelve [`Patologia`] cuando la expresion tiene una forma de las que
/// explotan, cuando pasa el tope de complejidad, o cuando no se puede analizar.
pub fn analizar(patron: &str, presupuesto: &Presupuesto) -> Result<u32, Patologia> {
    let bytes = patron.as_bytes();
    let mut complejidad: u32 = 0;
    let mut pila: Vec<Marco> = Vec::new();
    // Texto de cada rama de la alternancia del grupo actual, para detectar
    // solapes. Solo se guarda el nivel actual: anidar mas es raro y el tope de
    // complejidad lo corta igual.
    let mut ramas: Vec<Vec<String>> = vec![Vec::new()];
    let mut rama_actual = String::new();
    // Si el elemento inmediatamente anterior ya llevaba cuantificador.
    let mut anterior_cuantificado = false;
    // Donde empieza el elemento anterior, para poder recortar el fragmento.
    let mut inicio_anterior = 0usize;

    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i];
        match c {
            // Escape: el siguiente byte es literal, pase lo que pase.
            b'\\' => {
                if i + 1 >= bytes.len() {
                    return Err(Patologia::NoAnalizable {
                        detalle: "la expresion acaba en una barra invertida suelta".to_string(),
                    });
                }
                inicio_anterior = i;
                anterior_cuantificado = false;
                rama_actual.push('\\');
                rama_actual.push(bytes[i + 1] as char);
                complejidad = complejidad.saturating_add(1);
                i += 2;
                continue;
            }
            b'(' => {
                // EL PREFIJO DE UN GRUPO NO ES UN CUANTIFICADOR.
                //
                // `(?:`, `(?=`, `(?!`, `(?<=`, `(?<!`, `(?i)`, `(?<nombre>` y
                // `(?P<nombre>` llevan un `?` que forma parte de la sintaxis del
                // grupo. Leerlo como el cuantificador `?` marcaria el grupo como
                // «lleva cuantificador dentro» y haria que `(?:abc)+` —que es
                // absolutamente corriente— se rechazara como patologica.
                //
                // Rechazar lo legitimo tiene el mismo final que no comprobar
                // nada: alguien desactiva el analizador.
                let prefijo = largo_prefijo_de_grupo(&patron[i..]);
                complejidad = complejidad.saturating_add(2);
                inicio_anterior = i;
                anterior_cuantificado = false;

                match prefijo {
                    // Grupo de banderas que SE CIERRA SOLO: `(?i)`, `(?im)`.
                    // No abre nada, asi que empujar un marco dejaria un grupo
                    // abierto para siempre y la expresion entera se rechazaria
                    // como no analizable.
                    Some(Prefijo::Bandera(salto)) => {
                        i += salto;
                    }
                    // Abre grupo, con o sin prefijo especial.
                    Some(Prefijo::Abre(salto)) => {
                        pila.push(Marco {
                            inicio: i,
                            lleva_cuantificador: false,
                            alternancia: false,
                        });
                        ramas.push(Vec::new());
                        rama_actual.clear();
                        i += salto;
                    }
                    None => {
                        pila.push(Marco {
                            inicio: i,
                            lleva_cuantificador: false,
                            alternancia: false,
                        });
                        ramas.push(Vec::new());
                        rama_actual.clear();
                        i += 1;
                    }
                }
                continue;
            }
            b')' => {
                let Some(marco) = pila.pop() else {
                    return Err(Patologia::NoAnalizable {
                        detalle: format!("parentesis de cierre sin abrir en la posicion {i}"),
                    });
                };
                let mut mias = ramas.pop().unwrap_or_default();
                if !rama_actual.is_empty() || marco.alternancia {
                    mias.push(std::mem::take(&mut rama_actual));
                }

                // Lo que sigue al cierre decide si este grupo va cuantificado.
                let siguiente = bytes.get(i + 1).copied();
                let cuantificado = matches!(siguiente, Some(b'*' | b'+' | b'?' | b'{'));

                if cuantificado {
                    // FORMA 1: cuantificador sobre algo que ya llevaba
                    // cuantificador dentro.
                    if marco.lleva_cuantificador {
                        return Err(Patologia::CuantificadorAnidado {
                            posicion: marco.inicio,
                            fragmento: recorte(patron, marco.inicio, i + 2),
                        });
                    }
                    // FORMA 2: alternancia con ramas solapadas, cuantificada.
                    if let Some(par) = ramas_solapadas(&mias) {
                        return Err(Patologia::AlternanciaSolapada {
                            posicion: marco.inicio,
                            fragmento: par,
                        });
                    }
                }

                // El grupo entero pasa a ser «el elemento anterior».
                inicio_anterior = marco.inicio;
                anterior_cuantificado = false;
                if let Some(padre) = pila.last_mut() {
                    // Si este grupo va cuantificado, el padre hereda que dentro
                    // hay un cuantificador.
                    if cuantificado {
                        padre.lleva_cuantificador = true;
                    }
                }
                complejidad = complejidad.saturating_add(1);
                i += 1;
                continue;
            }
            b'|' => {
                if let Some(marco) = pila.last_mut() {
                    marco.alternancia = true;
                }
                if let Some(lista) = ramas.last_mut() {
                    lista.push(std::mem::take(&mut rama_actual));
                }
                anterior_cuantificado = false;
                complejidad = complejidad.saturating_add(2);
                i += 1;
                continue;
            }
            b'*' | b'+' | b'?' => {
                // FORMA 1 sin parentesis: `a++`, `a*?` en el sentido de doble
                // cuantificador. El `?` que sigue a otro cuantificador es el
                // modificador perezoso y NO es patologico, asi que se distingue.
                if anterior_cuantificado && c != b'?' {
                    return Err(Patologia::CuantificadorAnidado {
                        posicion: inicio_anterior,
                        fragmento: recorte(patron, inicio_anterior, i + 1),
                    });
                }
                if c != b'?' || !anterior_cuantificado {
                    anterior_cuantificado = true;
                }
                if let Some(marco) = pila.last_mut() {
                    marco.lleva_cuantificador = true;
                }
                rama_actual.push(c as char);
                complejidad = complejidad.saturating_add(COSTE_CUANTIFICADOR);
                i += 1;
                continue;
            }
            b'{' => {
                // Cuantificador acotado: `{n}`, `{n,}`, `{n,m}`.
                let Some(cierre) = bytes[i..].iter().position(|b| *b == b'}') else {
                    // Una llave suelta es un literal en muchos motores. Se trata
                    // como tal, no como error.
                    rama_actual.push('{');
                    complejidad = complejidad.saturating_add(1);
                    i += 1;
                    continue;
                };
                let cuerpo = &patron[i + 1..i + cierre];
                let Some(repeticiones) = tope_de_repeticiones(cuerpo) else {
                    rama_actual.push('{');
                    complejidad = complejidad.saturating_add(1);
                    i += 1;
                    continue;
                };
                if anterior_cuantificado {
                    return Err(Patologia::CuantificadorAnidado {
                        posicion: inicio_anterior,
                        fragmento: recorte(patron, inicio_anterior, i + cierre + 1),
                    });
                }
                anterior_cuantificado = true;
                if let Some(marco) = pila.last_mut() {
                    marco.lleva_cuantificador = true;
                }
                // Un `{1,1000}` cuesta mil veces lo que lleva dentro: la
                // complejidad tiene que reflejarlo o el tope no acota nada.
                complejidad = complejidad.saturating_add(repeticiones.min(10_000));
                i += cierre + 1;
                continue;
            }
            b'[' => {
                // Clase de caracteres: se salta entera, respetando escapes y el
                // `]` que puede ir el primero de forma literal.
                let mut j = i + 1;
                if bytes.get(j) == Some(&b'^') {
                    j += 1;
                }
                if bytes.get(j) == Some(&b']') {
                    j += 1;
                }
                while j < bytes.len() && bytes[j] != b']' {
                    if bytes[j] == b'\\' {
                        j += 1;
                    }
                    j += 1;
                }
                if j >= bytes.len() {
                    return Err(Patologia::NoAnalizable {
                        detalle: format!("clase de caracteres sin cerrar en la posicion {i}"),
                    });
                }
                inicio_anterior = i;
                anterior_cuantificado = false;
                rama_actual.push_str(&patron[i..=j]);
                complejidad = complejidad.saturating_add(2);
                i = j + 1;
                continue;
            }
            _ => {
                inicio_anterior = i;
                anterior_cuantificado = false;
                rama_actual.push(c as char);
                complejidad = complejidad.saturating_add(1);
                i += 1;
                continue;
            }
        }
    }

    if !pila.is_empty() {
        return Err(Patologia::NoAnalizable {
            detalle: format!("quedan {} parentesis sin cerrar", pila.len()),
        });
    }

    if complejidad > presupuesto.max_complejidad_regex {
        return Err(Patologia::DemasiadoCompleja {
            complejidad,
            tope: presupuesto.max_complejidad_regex,
        });
    }
    Ok(complejidad)
}

/// Si dos ramas de una alternancia casan lo mismo, devuelve el par.
///
/// No hace falta decidir equivalencia de lenguajes —que seria costoso— para
/// atrapar el caso que aparece de verdad: ramas identicas, o una que es prefijo
/// de otra. Las dos multiplican los caminos bajo un cuantificador.
fn ramas_solapadas(ramas: &[String]) -> Option<String> {
    for (i, a) in ramas.iter().enumerate() {
        if a.is_empty() {
            continue;
        }
        for b in ramas.iter().skip(i + 1) {
            if b.is_empty() {
                continue;
            }
            if a == b {
                return Some(format!("{a}|{b}"));
            }
            if b.starts_with(a.as_str()) || a.starts_with(b.as_str()) {
                return Some(format!("{a}|{b}"));
            }
        }
    }
    None
}

/// El tope de repeticiones de un cuerpo `{n}`, `{n,}` o `{n,m}`.
fn tope_de_repeticiones(cuerpo: &str) -> Option<u32> {
    let cuerpo = cuerpo.trim();
    if cuerpo.is_empty() {
        return None;
    }
    let (a, b) = match cuerpo.split_once(',') {
        Some((a, b)) => (a.trim(), b.trim()),
        None => (cuerpo, cuerpo),
    };
    if !a.is_empty() && !a.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if !b.is_empty() && !b.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    // `{n,}` SIN tope superior no es caro por si solo: `a{4,}` es exactamente
    // `aaaa+`, y un `+` sobre un atomo simple es lineal. Su coste es las `n`
    // posiciones fijas mas el del cuantificador abierto.
    //
    // Tratarlo como «el peor caso imaginable» rechazaria expresiones tan
    // corrientes como `\x90{4,}` —un nop sled, que es de las cosas mas utiles
    // que se buscan— y un analizador que rechaza lo legitimo se desactiva el
    // primer dia.
    //
    // Lo que si es caro de verdad es el anidamiento, `(a{1,1000}){1,1000}`, y
    // eso lo atrapa la deteccion de cuantificador anidado, no esta cuenta.
    //
    // Se suman las repeticiones RESTANTES y no todas: el atomo al que se aplica
    // el cuantificador ya se conto una vez al leerlo. Sin este ajuste, `a{4,}` y
    // `aaaa+` —la misma expresion escrita de dos formas— costarian distinto, y
    // la misma regla pasaria o no segun como la hubiera escrito su autor.
    if b.is_empty() {
        let n = a.parse::<u32>().unwrap_or(0);
        return Some(n.saturating_sub(1).saturating_add(COSTE_CUANTIFICADOR));
    }
    b.parse::<u32>().ok().map(|m| m.saturating_sub(1))
}

/// Que clase de prefijo lleva un grupo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Prefijo {
    /// Abre un grupo de verdad; el numero son los bytes del prefijo.
    Abre(usize),
    /// Es un grupo de banderas que se cierra solo, como `(?i)`. No abre nada.
    Bandera(usize),
}

/// Clasifica el prefijo de un grupo con sintaxis especial, si lo hay.
///
/// La distincion entre [`Prefijo::Abre`] y [`Prefijo::Bandera`] no es cosmetica:
/// `(?i)` NO abre grupo, y tratarlo como si lo abriera deja un parentesis
/// pendiente para siempre y hace que la expresion entera se rechace como no
/// analizable. `(?i:...)`, en cambio, si abre.
fn largo_prefijo_de_grupo(resto: &str) -> Option<Prefijo> {
    let b = resto.as_bytes();
    if b.first() != Some(&b'(') || b.get(1) != Some(&b'?') {
        return None;
    }
    match b.get(2) {
        // No capturador, anticipacion positiva y negativa, grupo atomico.
        Some(b':' | b'=' | b'!' | b'>') => Some(Prefijo::Abre(3)),
        // Retrospeccion (`(?<=`, `(?<!`) o grupo con nombre (`(?<n>`).
        Some(b'<') => match b.get(3) {
            Some(b'=' | b'!') => Some(Prefijo::Abre(4)),
            _ => hasta_cierre(b, 3).map(|p| Prefijo::Abre(p + 1)),
        },
        // Grupo con nombre estilo Python: `(?P<nombre>`.
        Some(b'P') => hasta_cierre(b, 3).map(|p| Prefijo::Abre(p + 1)),
        // Banderas: `(?i)` se cierra sola; `(?i:...)` abre grupo.
        Some(c) if c.is_ascii_alphabetic() || *c == b'-' => {
            let mut j = 2;
            while j < b.len() && (b[j].is_ascii_alphabetic() || b[j] == b'-') {
                j += 1;
            }
            match b.get(j) {
                Some(b':') => Some(Prefijo::Abre(j + 1)),
                Some(b')') => Some(Prefijo::Bandera(j + 1)),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Posicion del `>` que cierra el nombre de un grupo con nombre.
fn hasta_cierre(b: &[u8], desde: usize) -> Option<usize> {
    let mut j = desde;
    while j < b.len() && b[j] != b'>' {
        // Un nombre de grupo es alfanumerico; cualquier otra cosa significa que
        // esto no era un grupo con nombre y no se debe consumir a ciegas.
        if !(b[j].is_ascii_alphanumeric() || b[j] == b'_' || b[j] == b'<') {
            return None;
        }
        j += 1;
    }
    if j < b.len() {
        Some(j)
    } else {
        None
    }
}

/// Lo que cuesta un cuantificador abierto (`*`, `+`, `?`).
///
/// Es el mismo numero que se suma al ver el simbolo suelto, para que `a{4,}` y
/// `aaaa+` —que son la misma expresion escrita de dos formas— cuesten lo mismo.
/// Si no coincidieran, la misma regla pasaria o no segun como se escribiera.
const COSTE_CUANTIFICADOR: u32 = 4;

/// Recorta un fragmento para el mensaje, sin partir un caracter multibyte.
fn recorte(patron: &str, desde: usize, hasta: usize) -> String {
    let hasta = hasta.min(patron.len());
    let desde = desde.min(hasta);
    let mut d = desde;
    while d < patron.len() && !patron.is_char_boundary(d) {
        d += 1;
    }
    let mut h = hasta;
    while h < patron.len() && !patron.is_char_boundary(h) {
        h += 1;
    }
    let trozo = &patron[d..h];
    if trozo.len() > 60 {
        // `str::floor_char_boundary` haria esto en una linea, pero es estable
        // desde 1.91 y el MSRV del proyecto es 1.85. El MSRV no es aspiracional:
        // marca las distribuciones de servidor con soporte largo en las que el
        // agente tiene que compilar, asi que se retrocede a mano.
        let mut corte = 60;
        while corte > 0 && !trozo.is_char_boundary(corte) {
            corte -= 1;
        }
        format!("{}…", &trozo[..corte])
    } else {
        trozo.to_string()
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    // --- El recorte del fragmento del mensaje -----------------------------
    //
    // Parece cosmetico y no lo es: el patron viene de un feed, o sea que lo
    // puede escribir un atacante. Cortar por la mitad un caracter multibyte es
    // un panico en tiempo de ejecucion dentro del compilador de reglas, y en un
    // servicio que compila corpus eso es una denegacion de servicio con una sola
    // regla envenenada.

    #[test]
    fn el_recorte_no_parte_un_caracter_multibyte() {
        // 40 caracteres de tres bytes: el corte por byte 60 cae justo en medio
        // de uno de ellos.
        let patron = "\u{4e2d}".repeat(40);
        let r = recorte(&patron, 0, patron.len());
        assert!(r.ends_with('\u{2026}'), "tendria que ir recortado: {r:?}");
        // Que exista como &str ya demuestra que no se partio nada; se comprueba
        // ademas que el contenido es un prefijo real del patron.
        let sin_puntos = r.trim_end_matches('\u{2026}');
        assert!(patron.starts_with(sin_puntos));
        assert!(sin_puntos.len() <= 60);
    }

    #[test]
    fn el_recorte_deja_intacto_lo_que_ya_es_corto() {
        assert_eq!(recorte("abc", 0, 3), "abc");
        assert_eq!(recorte("(a|b)+", 0, 6), "(a|b)+");
    }

    #[test]
    fn el_recorte_aguanta_indices_imposibles() {
        // Los llamantes calculan `hasta` sumando al indice del bucle, asi que
        // puede pasarse del final. Salirse no puede ser un panico.
        assert_eq!(recorte("abc", 0, 999), "abc");
        assert_eq!(recorte("abc", 999, 999), "");
        assert_eq!(recorte("", 0, 0), "");
    }

    #[test]
    fn el_recorte_no_parte_multibyte_ni_en_el_inicio() {
        let patron = "x\u{4e2d}\u{6587}y";
        // Un `desde` que cae dentro del primer caracter de tres bytes.
        let r = recorte(patron, 2, patron.len());
        assert!(patron.ends_with(&r), "{r:?} no es un sufijo de {patron:?}");
    }

    fn p() -> Presupuesto {
        Presupuesto::default()
    }

    /// LOS CASOS QUE EXPLOTAN DE VERDAD. Cada uno de estos, distribuido a la
    /// flota, es una denegacion de servicio contra el propio producto.
    #[test]
    fn las_formas_patologicas_clasicas_se_rechazan() {
        for patron in [
            "(a+)+",
            "(a+)+$",
            "(a*)*",
            "(a+)*",
            "([a-z]+)+",
            "(\\d+)+",
            "(a{1,100}){1,100}",
        ] {
            let r = analizar(patron, &p());
            assert!(
                r.is_err(),
                "«{patron}» tiene retroceso catastrofico y tiene que rechazarse"
            );
        }
    }

    /// La alternancia solapada bajo cuantificador: las dos ramas casan lo mismo,
    /// asi que cada eleccion multiplica los caminos.
    #[test]
    fn la_alternancia_solapada_se_rechaza() {
        for patron in ["(a|a)*", "(a|ab)*", "(foo|foobar)+"] {
            let r = analizar(patron, &p());
            assert!(
                matches!(r, Err(Patologia::AlternanciaSolapada { .. })),
                "«{patron}» -> {r:?}"
            );
        }
    }

    /// Y EL REVERSO, que importa igual: las expresiones NORMALES tienen que
    /// pasar. Un analizador que rechaza lo legitimo se desactiva el primer dia,
    /// y un analizador desactivado no protege de nada.
    #[test]
    fn las_expresiones_normales_pasan() {
        for patron in [
            "^GET /admin",
            "[a-z0-9]{8,16}",
            "(GET|POST|PUT) /api/v[0-9]+/",
            "User-Agent: Mozilla/[45]\\.0",
            "\\x90{4,}",
            "(?:abc)+",
            "a+b+c+",
            "^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$",
            "(alpha|beta|gamma)",
            "[^\\]]+",
        ] {
            let r = analizar(patron, &p());
            assert!(r.is_ok(), "«{patron}» es legitima y tiene que pasar: {r:?}");
        }
    }

    /// EL `?` DE UN PREFIJO DE GRUPO NO ES UN CUANTIFICADOR. Confundirlos
    /// rechazaria `(?:abc)+`, que es de lo mas corriente que hay en una regla
    /// real, y un analizador que rechaza lo legitimo acaba desactivado.
    #[test]
    fn los_prefijos_de_grupo_no_se_leen_como_cuantificadores() {
        for patron in [
            "(?:abc)+",           // no capturador
            "(?i)select.*from",   // banderas
            "(?i:select)",        // banderas con ambito
            "(?-i:Exact)",        // banderas negadas
            "(?=foo)bar",         // anticipacion positiva
            "(?!foo)bar",         // anticipacion negativa
            "(?<=GET )/admin",    // retrospeccion positiva
            "(?<!\\\\w)token",    // retrospeccion negativa
            "(?<nombre>[a-z]+)",  // grupo con nombre
            "(?P<nombre>[a-z]+)", // grupo con nombre, estilo Python
            "(?>atomico)+",       // grupo atomico
            "(?:GET|POST) /api",  // alternancia dentro de no capturador
        ] {
            let r = analizar(patron, &p());
            assert!(r.is_ok(), "«{patron}» es legitima y tiene que pasar: {r:?}");
        }
    }

    /// Pero el analisis de patologias SIGUE funcionando dentro de un grupo con
    /// prefijo: saltarse el prefijo no puede convertirse en saltarse el grupo.
    #[test]
    fn un_grupo_no_capturador_sigue_sometido_al_analisis() {
        let r = analizar("(?:a+)+", &p());
        assert!(
            matches!(r, Err(Patologia::CuantificadorAnidado { .. })),
            "«(?:a+)+» explota igual que «(a+)+»: {r:?}"
        );
    }

    /// Un `?` DETRAS de otro cuantificador es el modificador perezoso, no un
    /// cuantificador anidado. Confundirlos rechazaria media biblioteca de reglas
    /// legitimas.
    #[test]
    fn el_modificador_perezoso_no_es_un_cuantificador_anidado() {
        for patron in ["a+?", "a*?", ".*?foo", "\\d{2,4}?"] {
            let r = analizar(patron, &p());
            assert!(r.is_ok(), "«{patron}» es perezoso, no patologico: {r:?}");
        }
    }

    /// Una expresion que el analizador no entiende NO se da por buena. No se
    /// puede afirmar nada sobre algo que no se ha podido leer.
    #[test]
    fn lo_que_no_se_puede_analizar_se_rechaza() {
        for patron in ["(abc", "abc)", "[a-z", "abc\\"] {
            let r = analizar(patron, &p());
            assert!(
                matches!(r, Err(Patologia::NoAnalizable { .. })),
                "«{patron}» -> {r:?}"
            );
        }
    }

    /// El tope de complejidad atrapa lo que no explota pero cuesta: su precio
    /// por paquete lo paga el endpoint del cliente.
    #[test]
    fn una_expresion_absurda_pero_no_patologica_se_corta_por_complejidad() {
        let patron = "a".repeat(200) + &"(b|c)".repeat(50);
        let estrecho = Presupuesto::estrecho();
        let r = analizar(&patron, &estrecho);
        assert!(
            matches!(r, Err(Patologia::DemasiadoCompleja { .. })),
            "{r:?}"
        );
    }

    /// Un `{n,}` sin tope superior NO es caro por si solo: `a{4,}` es
    /// exactamente `aaaa+`. Tratarlo como el peor caso imaginable rechazaria
    /// expresiones tan corrientes como un nop sled, y un analizador que rechaza
    /// lo legitimo se desactiva el primer dia.
    #[test]
    fn un_cuantificador_sin_tope_superior_no_se_considera_caro() {
        assert!(analizar("\\x90{4,}", &p()).is_ok());
        assert!(analizar("a{2,}", &p()).is_ok());
    }

    /// Y LA MISMA EXPRESION ESCRITA DE DOS FORMAS TIENE QUE COSTAR LO MISMO. Si
    /// no, la misma regla pasaria o no segun como la hubiera escrito su autor,
    /// que es un comportamiento imposible de explicar a nadie.
    #[test]
    fn dos_formas_de_escribir_lo_mismo_cuestan_lo_mismo() {
        let con_llaves = analizar("a{4,}", &p()).expect("legitima");
        let con_mas = analizar("aaaa+", &p()).expect("legitima");
        assert_eq!(
            con_llaves, con_mas,
            "«a{{4,}}» y «aaaa+» son la misma expresion"
        );
    }

    /// Lo que el tope de complejidad SI tiene que atrapar: un cuantificador
    /// acotado enorme, que cuesta sus posiciones de verdad.
    #[test]
    fn un_cuantificador_acotado_enorme_se_corta_por_complejidad() {
        let r = analizar("a{1,50000}", &p());
        assert!(
            matches!(r, Err(Patologia::DemasiadoCompleja { .. })),
            "{r:?}"
        );
    }

    /// Los caracteres escapados no abren grupos ni cuantifican: `\(` es un
    /// parentesis literal, y tratarlo como grupo descolocaria el analisis entero.
    #[test]
    fn los_escapes_no_se_confunden_con_metacaracteres() {
        assert!(analizar("\\(a\\)+", &p()).is_ok());
        assert!(analizar("\\*\\+\\?", &p()).is_ok());
        assert!(analizar("a\\|b", &p()).is_ok());
    }

    /// Una clase de caracteres puede contener `]` y `|` sin que eso signifique
    /// nada: se salta entera.
    #[test]
    fn una_clase_de_caracteres_se_salta_entera() {
        assert!(analizar("[]]+", &p()).is_ok());
        assert!(analizar("[|()*+]+", &p()).is_ok());
        assert!(analizar("[^]]*", &p()).is_ok());
    }

    /// Ninguna entrada arbitraria puede tumbar el analizador: lo que analiza lo
    /// escribe un feed que puede estar comprometido.
    #[test]
    fn ninguna_entrada_arbitraria_provoca_panico() {
        let alfabeto = b"()[]{}|*+?\\^$.abc019 \t";
        let mut semilla = 0x9E37_79B9_7F4A_7C15u64;
        for _ in 0..5_000 {
            semilla = semilla
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let n = (semilla % 40) as usize;
            let patron: String = (0..n)
                .map(|k| {
                    let idx = ((semilla >> (k % 56)) as usize) % alfabeto.len();
                    alfabeto[idx] as char
                })
                .collect();
            let _ = analizar(&patron, &p());
        }
    }

    /// Los codigos son estables porque se cuentan y se comparan entre versiones
    /// del corpus.
    #[test]
    fn cada_patologia_tiene_su_codigo_y_su_explicacion() {
        let casos = [
            ("(a+)+", "regex-cuantificador-anidado"),
            ("(a|ab)*", "regex-alternancia-solapada"),
            ("(abc", "regex-no-analizable"),
        ];
        for (patron, codigo) in casos {
            let Err(e) = analizar(patron, &p()) else {
                panic!("«{patron}» tenia que fallar");
            };
            assert_eq!(e.codigo(), codigo, "«{patron}»");
            assert!(!e.explicacion().is_empty());
        }
    }
}
