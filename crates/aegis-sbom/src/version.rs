//! Como se ordenan las versiones en cada ecosistema.
//!
//! # Un comparador equivocado es una vulnerabilidad que no aparece
//!
//! «¿Esta `1.2.10` dentro del rango `[1.2.3, 1.2.9)`?» Comparando cadenas, si;
//! comparando versiones, no. Y cada ecosistema tiene su orden: en Debian la
//! tilde va antes que nada (`1.0~rc1 < 1.0`); en Alpine `_p` va DESPUES de la
//! version sin sufijo y `_rc` antes; en Python `1.0.dev1 < 1.0a1 < 1.0 <
//! 1.0.post1`; en SemVer `1.0.0-alpha < 1.0.0`. Un solo comparador para todos
//! acierta en el caso facil y falla en el que importa, y el fallo no se ve: el
//! aviso simplemente no casa.

use std::cmp::Ordering;

use aegis_vuln::Version as VersionDeb;

use crate::componente::Ecosistema;

/// Compara dos versiones con el orden de su ecosistema.
#[must_use]
pub fn comparar(eco: Ecosistema, a: &str, b: &str) -> Ordering {
    match eco {
        // Sin `effective()`: los rangos de un aviso de la distribucion son
        // versiones de la distribucion, y dpkg las ordena tal cual, `+really`
        // incluido. La reinterpretacion de `+really` es para comparar contra
        // versiones del proyecto original, que no es el caso.
        Ecosistema::Deb => VersionDeb::parse(a).cmp(&VersionDeb::parse(b)),
        Ecosistema::Apk => apk(a, b),
        Ecosistema::Cargo | Ecosistema::Npm | Ecosistema::Go => semver(a, b),
        Ecosistema::PyPI => pep440(a, b),
        Ecosistema::Generico => generico(a, b),
    }
}

// --- SemVer 2.0 -----------------------------------------------------------------

/// SemVer: `M.m.p[-pre][+build]`, con la `v` de Go opcional.
///
/// La preversion ordena por identificadores separados por puntos: los numericos
/// por valor y por debajo de los alfanumericos, y una lista mas corta va antes si
/// es prefijo. `+build` no cuenta. Las pseudoversiones de Go
/// (`v0.0.0-20210101000000-abcdef`) son preversiones y se ordenan bien asi.
fn semver(a: &str, b: &str) -> Ordering {
    fn partes(v: &str) -> (Vec<u64>, Option<Vec<&str>>) {
        let v = v.trim().trim_start_matches('v');
        let v = v.split('+').next().unwrap_or(v);
        let (nucleo, pre) = match v.split_once('-') {
            Some((n, p)) => (n, Some(p.split('.').collect())),
            None => (v, None),
        };
        let mut nums: Vec<u64> = nucleo.split('.').map(|x| x.parse().unwrap_or(0)).collect();
        nums.resize(3.max(nums.len()), 0);
        (nums, pre)
    }
    let (na, pa) = partes(a);
    let (nb, pb) = partes(b);
    match na.cmp(&nb) {
        Ordering::Equal => {}
        o => return o,
    }
    match (pa, pb) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(x), Some(y)) => {
            for (i, j) in x.iter().zip(&y) {
                let o = match (i.parse::<u64>(), j.parse::<u64>()) {
                    (Ok(p), Ok(q)) => p.cmp(&q),
                    (Ok(_), Err(_)) => Ordering::Less,
                    (Err(_), Ok(_)) => Ordering::Greater,
                    (Err(_), Err(_)) => i.cmp(j),
                };
                if o != Ordering::Equal {
                    return o;
                }
            }
            x.len().cmp(&y.len())
        }
    }
}

// --- PEP 440 --------------------------------------------------------------------

/// La clave de ordenacion de una version de Python.
///
/// `[N!]N(.N)*[{a|b|rc}N][.postN][.devN][+local]`, con las grafias alternativas
/// que PEP 440 normaliza: `alpha`, `beta`, `c`, `pre`, `preview`, separadores
/// `-` y `_`, y la `v` delante.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ClavePep {
    epoca: u64,
    release: Vec<u64>,
    /// (fase, numero): fase 0 = dev sin pre, 1 = a, 2 = b, 3 = rc, 4 = final.
    pre: (u8, u64),
    /// `None` < `Some`: la version con post va despues.
    post: Option<u64>,
    /// `Some` < `None`: la version con dev va antes. Se guarda invertido.
    dev: (u8, u64),
}

fn pep440_clave(v: &str) -> ClavePep {
    let v = v.trim().to_ascii_lowercase();
    let v = v.trim_start_matches('v');
    let v = v.split('+').next().unwrap_or(v);
    let (epoca, resto) = match v.split_once('!') {
        Some((e, r)) => (e.parse().unwrap_or(0), r),
        None => (0, v),
    };
    let s = resto.replace(['-', '_'], ".");
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut release = Vec::new();
    loop {
        let ini = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i == ini {
            break;
        }
        release.push(s[ini..i].parse().unwrap_or(0));
        if i < bytes.len() && bytes[i] == b'.' && bytes.get(i + 1).is_some_and(u8::is_ascii_digit) {
            i += 1;
        } else {
            break;
        }
    }
    while release.len() > 1 && release.last() == Some(&0) {
        release.pop();
    }
    let mut pre: Option<(u8, u64)> = None;
    let mut post = None;
    let mut dev = None;
    let mut resto = &s[i..];
    let numero = |r: &mut &str| -> u64 {
        let r2 = r.trim_start_matches('.');
        let fin = r2.find(|c: char| !c.is_ascii_digit()).unwrap_or(r2.len());
        let n = r2[..fin].parse().unwrap_or(0);
        *r = &r2[fin..];
        n
    };
    while !resto.is_empty() {
        resto = resto.trim_start_matches('.');
        let etiquetas: &[(&str, u8)] = &[
            ("preview", 3),
            ("alpha", 1),
            ("beta", 2),
            ("post", 10),
            ("rev", 10),
            ("dev", 20),
            ("pre", 3),
            ("rc", 3),
            ("a", 1),
            ("b", 2),
            ("c", 3),
            ("r", 10),
        ];
        let Some((et, fase)) = etiquetas.iter().find(|(e, _)| resto.starts_with(e)) else {
            break;
        };
        resto = &resto[et.len()..];
        let n = numero(&mut resto);
        match fase {
            10 => post = Some(n),
            20 => dev = Some(n),
            f => pre = Some((*f, n)),
        }
    }
    ClavePep {
        epoca,
        release,
        // Una version SOLO con dev (1.0.dev1) va antes que sus preversiones.
        pre: match (pre, post, dev) {
            (Some(p), _, _) => p,
            (None, None, Some(_)) => (0, 0),
            _ => (4, 0),
        },
        post,
        dev: match dev {
            Some(n) => (0, n),
            None => (1, 0),
        },
    }
}

fn pep440(a: &str, b: &str) -> Ordering {
    pep440_clave(a).cmp(&pep440_clave(b))
}

// --- apk ------------------------------------------------------------------------

/// El orden de los sufijos de Alpine: los de antes de la version van por debajo
/// de «sin sufijo», los de despues por encima.
fn sufijo_apk(s: &str) -> Option<i8> {
    Some(match s {
        "alpha" => -4,
        "beta" => -3,
        "pre" => -2,
        "rc" => -1,
        "cvs" => 1,
        "svn" => 2,
        "git" => 3,
        "hg" => 4,
        "p" => 5,
        _ => return None,
    })
}

/// La clave de una version de Alpine: `1.2.3a_rc1_p2-r4`.
fn apk_clave(v: &str) -> (Vec<u64>, u8, Vec<(i8, u64)>, u64) {
    let (cuerpo, rel) = match v.trim().rsplit_once("-r") {
        Some((c, r)) if r.chars().all(|c| c.is_ascii_digit()) && !r.is_empty() => {
            (c, r.parse().unwrap_or(0))
        }
        _ => (v.trim(), 0),
    };
    let mut trozos = cuerpo.split('_');
    let base = trozos.next().unwrap_or("");
    let mut nums = Vec::new();
    let mut letra = 0u8;
    for (i, t) in base.split('.').enumerate() {
        let fin = t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len());
        nums.push(t[..fin].parse().unwrap_or(0));
        if fin < t.len() && i + 1 == base.split('.').count() {
            letra = t.as_bytes()[fin];
        }
    }
    let sufijos = trozos
        .map(|s| {
            let fin = s.find(|c: char| c.is_ascii_digit()).unwrap_or(s.len());
            (
                sufijo_apk(&s[..fin]).unwrap_or(0),
                s[fin..].parse().unwrap_or(0),
            )
        })
        .collect();
    (nums, letra, sufijos, rel)
}

fn apk(a: &str, b: &str) -> Ordering {
    let (na, la, sa, ra) = apk_clave(a);
    let (nb, lb, sb, rb) = apk_clave(b);
    // Los numeros se comparan tramo a tramo; el que se acaba antes es menor.
    for (x, y) in na.iter().zip(&nb) {
        match x.cmp(y) {
            Ordering::Equal => {}
            o => return o,
        }
    }
    match na.len().cmp(&nb.len()).then(la.cmp(&lb)) {
        Ordering::Equal => {}
        o => return o,
    }
    // Sin sufijo equivale a un sufijo de peso 0 en esa posicion.
    let largo = sa.len().max(sb.len());
    for i in 0..largo {
        let x = sa.get(i).copied().unwrap_or((0, 0));
        let y = sb.get(i).copied().unwrap_or((0, 0));
        match x.cmp(&y) {
            Ordering::Equal => {}
            o => return o,
        }
    }
    ra.cmp(&rb)
}

// --- Generico -------------------------------------------------------------------

/// Tramos numericos por valor y alfanumericos por texto: lo razonable cuando no
/// hay ecosistema que diga otra cosa.
fn generico(a: &str, b: &str) -> Ordering {
    let trozos = |s: &str| -> Vec<String> {
        s.split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|t| !t.is_empty())
            .map(str::to_string)
            .collect()
    };
    let (x, y) = (trozos(a), trozos(b));
    for (p, q) in x.iter().zip(&y) {
        let o = match (p.parse::<u64>(), q.parse::<u64>()) {
            (Ok(m), Ok(n)) => m.cmp(&n),
            _ => p.cmp(q),
        };
        if o != Ordering::Equal {
            return o;
        }
    }
    x.len().cmp(&y.len())
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use Ecosistema::*;

    fn ordenados(eco: Ecosistema, v: &[&str]) {
        for w in v.windows(2) {
            assert_eq!(
                comparar(eco, w[0], w[1]),
                Ordering::Less,
                "{:?}: {} < {}",
                eco,
                w[0],
                w[1]
            );
            assert_eq!(comparar(eco, w[1], w[0]), Ordering::Greater);
        }
    }

    #[test]
    fn debian() {
        ordenados(Deb, &["1.0~rc1", "1.0", "1.0-1", "1.0+b1", "1:0.1"]);
        // `+really` se ordena como lo ordena dpkg, no reinterpretado.
        ordenados(Deb, &["1:1.3.dfsg-3", "1:1.3.dfsg+really1.3.1-1"]);
    }

    #[test]
    fn semver_y_go() {
        ordenados(
            Cargo,
            &[
                "1.0.0-alpha",
                "1.0.0-alpha.1",
                "1.0.0-alpha.beta",
                "1.0.0-beta",
                "1.0.0-beta.2",
                "1.0.0-beta.11",
                "1.0.0-rc.1",
                "1.0.0",
                "1.2.9",
                "1.2.10",
            ],
        );
        ordenados(
            Go,
            &[
                "v0.0.0-20210101000000-abcdef123456",
                "v0.1.0",
                "v0.17.0",
                "v1.0.0",
            ],
        );
        assert_eq!(comparar(Npm, "1.0.0+build.1", "1.0.0"), Ordering::Equal);
    }

    #[test]
    fn pep_440() {
        ordenados(
            PyPI,
            &[
                "1.0.dev1",
                "1.0a1",
                "1.0a2.dev1",
                "1.0a2",
                "1.0b1",
                "1.0rc1",
                "1.0",
                "1.0.post1",
                "1.1",
                "1!0.5",
            ],
        );
        assert_eq!(comparar(PyPI, "1.0", "1.0.0"), Ordering::Equal);
        assert_eq!(comparar(PyPI, "1.0-alpha1", "1.0a1"), Ordering::Equal);
        assert_eq!(comparar(PyPI, "2.31.0", "2.4.0"), Ordering::Greater);
    }

    #[test]
    fn alpine() {
        ordenados(
            Apk,
            &[
                "1.2.3_alpha",
                "1.2.3_rc1",
                "1.2.3",
                "1.2.3-r1",
                "1.2.3-r10",
                "1.2.3_p1",
                "1.2.4",
                "1.10",
            ],
        );
        // La letra va despues de la version sin ella y antes del siguiente
        // numero. Su orden frente a un sufijo `_p` no se afirma: no esta
        // cotejado con `apk-tools`, y una prueba no es sitio para suponerlo.
        ordenados(Apk, &["1.2.3", "1.2.3a", "1.2.3b", "1.2.4"]);
    }

    #[test]
    fn generico() {
        ordenados(Generico, &["1.1.1w", "3.0.2", "3.0.10", "3.5.5"]);
    }
}
