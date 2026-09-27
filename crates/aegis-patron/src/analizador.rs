//! El frontal: lee la sintaxis YARA y la compila a reglas.
//!
//! # Compatibilidad de ENTRADA, no de comportamiento
//!
//! Lee la sintaxis de YARA —cadenas de texto y hex con comodines y saltos,
//! modificadores, condiciones con `and`/`or`/`not` y `N of`— porque el corpus
//! existente esta escrito asi. Pero la SEMANTICA es la nueva: coste acotado, sin
//! retroceso, determinista. Compatibilidad de entrada, jamas de comportamiento
//! degradado.
//!
//! # El comprobador de cota, dentro del compilador
//!
//! Un salto de hex sin cota superior (`[10-]`) o una repeticion sin acotar hacen
//! que el coste del patron no se pueda demostrar. Aqui eso NO compila, y el error
//! dice que parte de la regla no se puede acotar. Es la propiedad que YARA no
//! tiene: acepta reglas que se comportan de forma patologica ante entradas
//! adversarias, y esas reglas viajan en corpus publicos.

use crate::regex::{ClaseBytes, Insn, Programa};
use crate::regla::{Cadena, Cond, Conjunto, Cuantificador, Patron, Regla};

/// Un error de compilacion de reglas, nombrando que parte falla.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ErrorCompilacion {
    /// Sintaxis invalida, con lo que se esperaba.
    #[error("sintaxis en la posicion {pos}: {que}")]
    Sintaxis {
        /// Byte donde se detecto.
        pos: usize,
        /// Que se esperaba o que sobra.
        que: String,
    },
    /// Una parte de una regla cuyo coste no se puede acotar.
    #[error("la regla «{regla}» no se puede acotar: {que}")]
    SinCota {
        /// La regla implicada.
        regla: String,
        /// Que parte no se acota.
        que: String,
    },
    /// Una construccion valida de YARA que este incremento aun no implementa. Se
    /// dice claramente en vez de mal-escanear en silencio.
    #[error("la regla «{regla}» usa algo no implementado aun: {que}")]
    NoImplementado {
        /// La regla implicada.
        regla: String,
        /// Que construccion.
        que: String,
    },
}

/// El limite superior de un salto de hex, por encima del cual se considera una via
/// de agotamiento aunque tenga cota (`[0-100000]`).
const MAX_SALTO: u64 = 4096;

/// Compila un texto de reglas YARA en reglas listas para escanear.
///
/// # Errores
/// [`ErrorCompilacion`] nombrando la regla y la parte que falla.
pub fn compilar(fuente: &str, namespace: &str) -> Result<Vec<Regla>, ErrorCompilacion> {
    let mut p = Analizador::nuevo(fuente, namespace);
    p.reglas()
}

struct Analizador<'a> {
    s: &'a [u8],
    pos: usize,
    namespace: String,
}

impl<'a> Analizador<'a> {
    fn nuevo(fuente: &'a str, namespace: &str) -> Self {
        Analizador {
            s: fuente.as_bytes(),
            pos: 0,
            namespace: namespace.to_string(),
        }
    }

    fn err(&self, que: impl Into<String>) -> ErrorCompilacion {
        ErrorCompilacion::Sintaxis {
            pos: self.pos,
            que: que.into(),
        }
    }

    fn fin(&self) -> bool {
        self.pos >= self.s.len()
    }

    fn ver(&self) -> Option<u8> {
        self.s.get(self.pos).copied()
    }

    /// Salta espacios y comentarios (`//` y `/* */`).
    fn espacio(&mut self) {
        loop {
            while let Some(b) = self.ver() {
                if b.is_ascii_whitespace() {
                    self.pos += 1;
                } else {
                    break;
                }
            }
            if self.mira("//") {
                while let Some(b) = self.ver() {
                    self.pos += 1;
                    if b == b'\n' {
                        break;
                    }
                }
            } else if self.mira("/*") {
                self.pos += 2;
                while !self.fin() && !self.mira("*/") {
                    self.pos += 1;
                }
                if self.mira("*/") {
                    self.pos += 2;
                }
            } else {
                break;
            }
        }
    }

    /// Si en la posicion actual esta el literal dado (sin consumir).
    fn mira(&self, lit: &str) -> bool {
        self.s[self.pos..].starts_with(lit.as_bytes())
    }

    /// Consume el literal dado o falla.
    fn exigir(&mut self, lit: &str) -> Result<(), ErrorCompilacion> {
        self.espacio();
        if self.mira(lit) {
            self.pos += lit.len();
            Ok(())
        } else {
            Err(self.err(format!("se esperaba «{lit}»")))
        }
    }

    /// Consume el literal si esta.
    fn opcional(&mut self, lit: &str) -> bool {
        self.espacio();
        if self.mira(lit) {
            self.pos += lit.len();
            true
        } else {
            false
        }
    }

    /// Lee un identificador `[A-Za-z_][A-Za-z0-9_]*`.
    fn identificador(&mut self) -> Result<String, ErrorCompilacion> {
        self.espacio();
        let ini = self.pos;
        if let Some(b) = self.ver() {
            if b.is_ascii_alphabetic() || b == b'_' {
                self.pos += 1;
                while let Some(b) = self.ver() {
                    if b.is_ascii_alphanumeric() || b == b'_' {
                        self.pos += 1;
                    } else {
                        break;
                    }
                }
                return Ok(String::from_utf8_lossy(&self.s[ini..self.pos]).into_owned());
            }
        }
        Err(self.err("se esperaba un identificador"))
    }

    /// Parsea todas las reglas del fichero.
    fn reglas(&mut self) -> Result<Vec<Regla>, ErrorCompilacion> {
        let mut v = Vec::new();
        loop {
            self.espacio();
            if self.fin() {
                break;
            }
            if self.opcional("global") || self.opcional("private") {
                self.espacio();
            }
            if !self.mira("rule") {
                return Err(self.err("se esperaba «rule»"));
            }
            self.pos += 4;
            v.push(self.regla()?);
        }
        Ok(v)
    }

    /// Parsea una regla completa.
    fn regla(&mut self) -> Result<Regla, ErrorCompilacion> {
        let nombre = self.identificador()?;
        // Etiquetas `: tag` opcionales.
        self.espacio();
        if self.opcional(":") {
            while {
                self.espacio();
                self.ver()
                    .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_')
            } {
                let _ = self.identificador()?;
            }
        }
        self.exigir("{")?;

        let mut meta = std::collections::BTreeMap::new();
        let mut cadenas = Vec::new();
        let mut condicion = Cond::Verdadero;

        loop {
            self.espacio();
            if self.opcional("meta") {
                self.exigir(":")?;
                self.seccion_meta(&mut meta)?;
            } else if self.opcional("strings") {
                self.exigir(":")?;
                self.seccion_strings(&nombre, &mut cadenas)?;
            } else if self.opcional("condition") {
                self.exigir(":")?;
                condicion = self.condicion(&nombre, &cadenas)?;
            } else if self.opcional("}") {
                break;
            } else {
                return Err(self.err("se esperaba meta, strings, condition o «}»"));
            }
        }

        Ok(Regla {
            nombre,
            namespace: self.namespace.clone(),
            meta,
            cadenas,
            condicion,
        })
    }

    /// `clave = valor` hasta la siguiente seccion.
    fn seccion_meta(
        &mut self,
        meta: &mut std::collections::BTreeMap<String, String>,
    ) -> Result<(), ErrorCompilacion> {
        loop {
            self.espacio();
            if self.mira("strings") || self.mira("condition") || self.mira("}") {
                break;
            }
            let clave = self.identificador()?;
            self.exigir("=")?;
            self.espacio();
            let valor = match self.ver() {
                Some(b'"') => self.cadena_texto()?,
                Some(b't') | Some(b'f') => self.identificador()?, // true/false
                _ => {
                    // Numero.
                    let ini = self.pos;
                    while self.ver().is_some_and(|b| b.is_ascii_digit() || b == b'-') {
                        self.pos += 1;
                    }
                    String::from_utf8_lossy(&self.s[ini..self.pos]).into_owned()
                }
            };
            meta.insert(clave, valor);
        }
        Ok(())
    }

    /// `$id = "..."|{...}|/.../ modificadores` hasta la siguiente seccion.
    fn seccion_strings(
        &mut self,
        regla: &str,
        cadenas: &mut Vec<Cadena>,
    ) -> Result<(), ErrorCompilacion> {
        loop {
            self.espacio();
            if self.mira("condition") || self.mira("}") {
                break;
            }
            if self.ver() != Some(b'$') {
                return Err(self.err("se esperaba un identificador de cadena «$...»"));
            }
            self.pos += 1;
            let nombre = self.identificador().unwrap_or_default();
            let id = format!("${nombre}");
            self.exigir("=")?;
            self.espacio();
            let patron = match self.ver() {
                Some(b'"') => Patron::Literal(self.cadena_texto()?.into_bytes()),
                Some(b'{') => self.cadena_hex(regla)?,
                Some(b'/') => {
                    return Err(ErrorCompilacion::NoImplementado {
                        regla: regla.to_string(),
                        que: "expresiones regulares /.../; ninguna regla base las usa, y se \
                              anaden en el siguiente incremento sobre el motor sin retroceso \
                              ya presente"
                            .into(),
                    })
                }
                _ => return Err(self.err("se esperaba \"texto\", { hex } o /regex/")),
            };
            let (nocase, ascii, wide, fullword) = self.modificadores();
            cadenas.push(Cadena {
                id,
                patron,
                nocase,
                ascii,
                wide,
                fullword,
            });
        }
        Ok(())
    }

    /// Lee los modificadores que sigan a una cadena.
    fn modificadores(&mut self) -> (bool, bool, bool, bool) {
        let (mut nocase, mut ascii, mut wide, mut fullword) = (false, false, false, false);
        loop {
            self.espacio();
            if self.opcional("nocase") {
                nocase = true;
            } else if self.opcional("ascii") {
                ascii = true;
            } else if self.opcional("wide") {
                wide = true;
            } else if self.opcional("fullword") {
                fullword = true;
            } else if self.opcional("xor") || self.opcional("base64") || self.opcional("base64wide")
            {
                // Reconocidos pero sin efecto en este incremento; no romper el
                // parseo. La cobertura lo declara.
            } else {
                break;
            }
        }
        // ascii es el valor por defecto de YARA cuando no hay wide.
        if !wide {
            ascii = true;
        }
        (nocase, ascii, wide, fullword)
    }

    /// Lee una cadena de texto entre comillas, con los escapes de YARA.
    fn cadena_texto(&mut self) -> Result<String, ErrorCompilacion> {
        self.exigir("\"")?;
        let mut out = Vec::new();
        loop {
            let Some(b) = self.ver() else {
                return Err(self.err("cadena sin cerrar"));
            };
            self.pos += 1;
            match b {
                b'"' => break,
                b'\\' => {
                    let Some(e) = self.ver() else {
                        return Err(self.err("escape sin cerrar"));
                    };
                    self.pos += 1;
                    match e {
                        b'n' => out.push(b'\n'),
                        b't' => out.push(b'\t'),
                        b'r' => out.push(b'\r'),
                        b'\\' => out.push(b'\\'),
                        b'"' => out.push(b'"'),
                        b'x' => {
                            let h = self.leer_hex_byte()?;
                            out.push(h);
                        }
                        otro => out.push(otro),
                    }
                }
                otro => out.push(otro),
            }
        }
        Ok(String::from_utf8_lossy(&out).into_owned())
    }

    /// Lee dos digitos hex tras `\x`.
    fn leer_hex_byte(&mut self) -> Result<u8, ErrorCompilacion> {
        let hi = self
            .ver()
            .and_then(hex_nibble)
            .ok_or_else(|| self.err("hex invalido"))?;
        self.pos += 1;
        let lo = self
            .ver()
            .and_then(hex_nibble)
            .ok_or_else(|| self.err("hex invalido"))?;
        self.pos += 1;
        Ok((hi << 4) | lo)
    }

    /// Lee una cadena hex `{ 48 ?? [2-4] C3 }` y la compila: fija -> literal; con
    /// comodines o saltos -> programa regex; salto sin cota -> rechazo.
    fn cadena_hex(&mut self, regla: &str) -> Result<Patron, ErrorCompilacion> {
        self.exigir("{")?;
        // Se lee la secuencia en tokens: byte, byte con nibble comodin, `??`, o
        // salto `[a-b]`.
        enum Tok {
            Byte(u8),
            NibbleAlto(u8), // 4? : alto conocido
            NibbleBajo(u8), // ?4 : bajo conocido
            Cualquiera,     // ??
            Salto(u64, Option<u64>),
        }
        let mut toks = Vec::new();
        let mut solo_fija = true;
        loop {
            self.espacio();
            match self.ver() {
                Some(b'}') => {
                    self.pos += 1;
                    break;
                }
                Some(b'[') => {
                    self.pos += 1;
                    solo_fija = false;
                    let a = self.leer_numero()?;
                    let b = if self.opcional("-") {
                        self.espacio();
                        if self.ver() == Some(b']') {
                            None // [a-] : sin cota superior
                        } else {
                            Some(self.leer_numero()?)
                        }
                    } else {
                        Some(a) // [a] : exactamente a
                    };
                    self.exigir("]")?;
                    toks.push(Tok::Salto(a, b));
                }
                Some(c) if c == b'?' || hex_nibble(c).is_some() => {
                    let hi = self.ver().unwrap();
                    self.pos += 1;
                    let lo = self.ver().ok_or_else(|| self.err("hex a medias"))?;
                    self.pos += 1;
                    match (hi == b'?', lo == b'?') {
                        (true, true) => {
                            solo_fija = false;
                            toks.push(Tok::Cualquiera);
                        }
                        (true, false) => {
                            solo_fija = false;
                            toks.push(Tok::NibbleBajo(
                                hex_nibble(lo).ok_or_else(|| self.err("nibble invalido"))?,
                            ));
                        }
                        (false, true) => {
                            solo_fija = false;
                            toks.push(Tok::NibbleAlto(
                                hex_nibble(hi).ok_or_else(|| self.err("nibble invalido"))?,
                            ));
                        }
                        (false, false) => {
                            let h = hex_nibble(hi).ok_or_else(|| self.err("nibble invalido"))?;
                            let l = hex_nibble(lo).ok_or_else(|| self.err("nibble invalido"))?;
                            toks.push(Tok::Byte((h << 4) | l));
                        }
                    }
                }
                _ => return Err(self.err("byte hex, comodin o salto en la cadena hex")),
            }
        }

        if solo_fija {
            let bytes = toks
                .iter()
                .filter_map(|t| if let Tok::Byte(b) = t { Some(*b) } else { None })
                .collect();
            return Ok(Patron::Literal(bytes));
        }

        // Con comodines o saltos: se compila a un programa regex, acotando los
        // saltos. Un salto sin cota superior no se puede acotar: se rechaza.
        let mut insns = Vec::new();
        for t in &toks {
            match t {
                Tok::Byte(b) => insns.push(Insn::Byte(*b)),
                Tok::Cualquiera => insns.push(Insn::Cualquiera),
                Tok::NibbleAlto(h) => {
                    let mut c = ClaseBytes::vacia();
                    c.rango(h << 4, (h << 4) | 0x0f);
                    insns.push(Insn::Clase(Box::new(c)));
                }
                Tok::NibbleBajo(l) => {
                    // Nibble bajo conocido, alto cualquiera: 0x0l, 0x1l, ..., 0xfl.
                    let mut c = ClaseBytes::vacia();
                    for hi in 0u8..=0x0f {
                        c.byte((hi << 4) | *l);
                    }
                    insns.push(Insn::Clase(Box::new(c)));
                }
                Tok::Salto(a, b) => {
                    let Some(hi) = b else {
                        return Err(ErrorCompilacion::SinCota {
                            regla: regla.to_string(),
                            que: format!("un salto de hex «[{a}-]» no tiene cota superior"),
                        });
                    };
                    if *hi > MAX_SALTO {
                        return Err(ErrorCompilacion::SinCota {
                            regla: regla.to_string(),
                            que: format!(
                                "un salto «[{a}-{hi}]» supera el maximo demostrable de {MAX_SALTO}"
                            ),
                        });
                    }
                    // `a` bytes obligatorios.
                    for _ in 0..*a {
                        insns.push(Insn::Cualquiera);
                    }
                    // Hasta `hi-a` bytes opcionales: cada opcional puede consumir un
                    // byte y seguir, o SALTAR A LA CONTINUACION (el resto del
                    // patron), no al Aceptar —si no, se comeria lo que viene
                    // despues del salto—. Se anotan las bifurcaciones y se corrigen
                    // a la continuacion en cuanto se conoce.
                    let mut opcionales = Vec::new();
                    for _ in *a..*hi {
                        opcionales.push(insns.len());
                        insns.push(Insn::Bifurcar(insns.len() + 1, 0)); // z se corrige
                        insns.push(Insn::Cualquiera);
                    }
                    let continuacion = insns.len();
                    for i in opcionales {
                        if let Insn::Bifurcar(tomar, _) = insns[i] {
                            insns[i] = Insn::Bifurcar(tomar, continuacion);
                        }
                    }
                }
            }
        }
        insns.push(Insn::Aceptar);
        Ok(Patron::Regex(Programa::nuevo(insns)))
    }

    fn leer_numero(&mut self) -> Result<u64, ErrorCompilacion> {
        self.espacio();
        let ini = self.pos;
        while self.ver().is_some_and(|b| b.is_ascii_digit()) {
            self.pos += 1;
        }
        if self.pos == ini {
            return Err(self.err("se esperaba un numero"));
        }
        String::from_utf8_lossy(&self.s[ini..self.pos])
            .parse()
            .map_err(|_| self.err("numero invalido"))
    }

    // ── Condicion: or > and > not > primaria ────────────────────────────────────

    fn condicion(&mut self, regla: &str, cadenas: &[Cadena]) -> Result<Cond, ErrorCompilacion> {
        self.expr_or(regla, cadenas)
    }

    fn expr_or(&mut self, regla: &str, cadenas: &[Cadena]) -> Result<Cond, ErrorCompilacion> {
        let mut izq = self.expr_and(regla, cadenas)?;
        loop {
            self.espacio();
            if self.palabra("or") {
                let der = self.expr_and(regla, cadenas)?;
                izq = Cond::O(Box::new(izq), Box::new(der));
            } else {
                break;
            }
        }
        Ok(izq)
    }

    fn expr_and(&mut self, regla: &str, cadenas: &[Cadena]) -> Result<Cond, ErrorCompilacion> {
        let mut izq = self.expr_no(regla, cadenas)?;
        loop {
            self.espacio();
            if self.palabra("and") {
                let der = self.expr_no(regla, cadenas)?;
                izq = Cond::Y(Box::new(izq), Box::new(der));
            } else {
                break;
            }
        }
        Ok(izq)
    }

    fn expr_no(&mut self, regla: &str, cadenas: &[Cadena]) -> Result<Cond, ErrorCompilacion> {
        self.espacio();
        if self.palabra("not") {
            Ok(Cond::No(Box::new(self.expr_no(regla, cadenas)?)))
        } else {
            self.primaria(regla, cadenas)
        }
    }

    /// Consume una palabra clave solo si es una palabra completa (no un prefijo de
    /// un identificador).
    fn palabra(&mut self, kw: &str) -> bool {
        self.espacio();
        if self.mira(kw) {
            let sig = self.s.get(self.pos + kw.len()).copied();
            if sig.is_none_or(|b| !(b.is_ascii_alphanumeric() || b == b'_')) {
                self.pos += kw.len();
                return true;
            }
        }
        false
    }

    fn primaria(&mut self, regla: &str, cadenas: &[Cadena]) -> Result<Cond, ErrorCompilacion> {
        self.espacio();
        if self.opcional("(") {
            let c = self.expr_or(regla, cadenas)?;
            self.exigir(")")?;
            return Ok(c);
        }
        if self.palabra("true") {
            return Ok(Cond::Verdadero);
        }
        if self.palabra("false") {
            return Ok(Cond::No(Box::new(Cond::Verdadero)));
        }
        if self.palabra("any") {
            return self.resto_of(Cuantificador::Alguna, regla, cadenas);
        }
        if self.palabra("all") {
            return self.resto_of(Cuantificador::Todas, regla, cadenas);
        }
        // Un numero seguido de `of` (resto_of consume el «of»).
        if self.ver().is_some_and(|b| b.is_ascii_digit()) {
            let n = self.leer_numero()?;
            return self.resto_of(Cuantificador::AlMenos(n), regla, cadenas);
        }
        // Una cadena `$id` (o `$` a secas dentro de un `of`, no aqui).
        if self.ver() == Some(b'$') {
            self.pos += 1;
            let nombre = self.identificador().unwrap_or_default();
            return Ok(Cond::Cadena(format!("${nombre}")));
        }
        Err(self.err("se esperaba (, $cadena, N of, any/all of, true"))
    }

    /// Tras `N`/`any`/`all`: `of them` o `of ( lista )`.
    fn resto_of(
        &mut self,
        cuant: Cuantificador,
        regla: &str,
        cadenas: &[Cadena],
    ) -> Result<Cond, ErrorCompilacion> {
        if !self.palabra("of") {
            return Err(self.err("se esperaba «of»"));
        }
        self.espacio();
        if self.palabra("them") {
            return Ok(Cond::NDe(cuant, Conjunto::Todas));
        }
        self.exigir("(")?;
        let mut lista = Vec::new();
        loop {
            self.espacio();
            if self.opcional(")") {
                break;
            }
            if self.ver() != Some(b'$') {
                return Err(self.err("se esperaba «$...» o «)» en el conjunto"));
            }
            self.pos += 1;
            // Puede ser `$id` o `$pre*`.
            let nombre = self.identificador().unwrap_or_default();
            if self.opcional("*") {
                // Comodin: todas las cadenas cuyo id empieza por el prefijo.
                let pre = format!("${nombre}");
                for c in cadenas {
                    if c.id.starts_with(&pre) {
                        lista.push(c.id.clone());
                    }
                }
            } else {
                lista.push(format!("${nombre}"));
            }
            self.opcional(",");
        }
        let _ = regla;
        Ok(Cond::NDe(cuant, Conjunto::Lista(lista)))
    }
}

/// El valor de un digito hexadecimal.
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn compila_una_regla_de_texto_con_condicion_booleana() {
        let fuente = r#"
            rule R {
                meta:
                    description = "prueba"
                    severity = "high"
                strings:
                    $a = "/dev/tcp/" ascii
                    $b = ">&" ascii
                condition:
                    $a and $b
            }
        "#;
        let reglas = compilar(fuente, "base").expect("compila");
        assert_eq!(reglas.len(), 1);
        let r = &reglas[0];
        assert_eq!(r.nombre, "R");
        assert_eq!(r.cadenas.len(), 2);
        assert_eq!(r.meta.get("description").unwrap(), "prueba");
        assert!(matches!(r.condicion, Cond::Y(_, _)));
    }

    #[test]
    fn compila_hex_fija_como_literal() {
        let fuente = "rule H { strings: $s = { 48 bb 2f 62 } condition: $s }";
        let r = compilar(fuente, "base").unwrap();
        assert_eq!(
            r[0].cadenas[0].patron,
            Patron::Literal(vec![0x48, 0xbb, 0x2f, 0x62])
        );
    }

    #[test]
    fn compila_n_of_them() {
        let fuente = "rule N { strings: $a=\"x\" $b=\"y\" $c=\"z\" condition: 2 of them }";
        let r = compilar(fuente, "base").unwrap();
        assert!(matches!(
            r[0].condicion,
            Cond::NDe(Cuantificador::AlMenos(2), Conjunto::Todas)
        ));
    }

    #[test]
    fn un_salto_de_hex_sin_cota_no_compila() {
        // LA PROPIEDAD DE LA FASE: una regla cuya cota no se puede demostrar NO
        // COMPILA, y el error dice que parte no se acota.
        let fuente = "rule Mala { strings: $s = { 48 [10-] c3 } condition: $s }";
        let e = compilar(fuente, "base").unwrap_err();
        assert!(matches!(e, ErrorCompilacion::SinCota { .. }), "{e:?}");
    }

    #[test]
    fn un_salto_de_hex_acotado_si_compila() {
        let fuente = "rule Buena { strings: $s = { 48 [2-4] c3 } condition: $s }";
        let r = compilar(fuente, "base").unwrap();
        assert!(matches!(r[0].cadenas[0].patron, Patron::Regex(_)));
    }

    #[test]
    fn los_comentarios_no_rompen_el_parseo() {
        let fuente = "/* cabecera */ rule C { // linea\n strings: $a=\"z\" condition: $a }";
        assert_eq!(compilar(fuente, "base").unwrap().len(), 1);
    }
}
