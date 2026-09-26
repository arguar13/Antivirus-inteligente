//! El identificador de paquete (`purl`), segun la especificacion Package URL.
//!
//! # Por que importa escribirlo bien
//!
//! El purl es el contrato que une el inventario con el resto del mundo: es la
//! clave con la que OSV, CycloneDX, SPDX y las herramientas del cliente se ponen
//! de acuerdo sobre de que componente se habla. Un purl mal codificado no falla:
//! **no casa**, y un componente que no casa con su aviso es una vulnerabilidad que
//! no aparece en el informe.
//!
//! Las reglas que se aplican son las de la especificacion:
//!
//! - `pkg:tipo/espacio/nombre@version?calificadores`.
//! - Cada segmento se codifica con porcentaje salvo los caracteres no reservados
//!   (`A-Z a-z 0-9 . - _ ~`). El `+` de una version de Debian **se codifica**
//!   (`%2B`): sin codificar se lee como un espacio en cualquier consulta de URL.
//! - Los calificadores van ordenados por clave, y los vacios no se escriben.
//! - El espacio de nombres de Go es la ruta del modulo menos su ultimo tramo, y
//!   cada tramo se codifica por separado: la barra es separador, no contenido.

/// Codifica un segmento con porcentaje.
///
/// `conservar` son caracteres ademas de los no reservados que se dejan tal cual:
/// el `:` de la epoca de una version de Debian no es ambiguo despues de la `@` y
/// las herramientas lo escriben sin codificar.
fn codificar(s: &str, conservar: &[char]) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '~') || conservar.contains(&c)
        {
            o.push(c);
        } else {
            let mut buf = [0u8; 4];
            for b in c.encode_utf8(&mut buf).bytes() {
                o.push_str(&format!("%{b:02X}"));
            }
        }
    }
    o
}

/// Monta un purl.
///
/// `espacio` puede tener varios tramos separados por `/` (Go, Maven); cada uno se
/// codifica aparte.
#[must_use]
pub fn montar(
    tipo: &str,
    espacio: Option<&str>,
    nombre: &str,
    version: Option<&str>,
    calificadores: &[(&str, &str)],
) -> String {
    let mut s = format!("pkg:{}/", tipo.to_ascii_lowercase());
    if let Some(e) = espacio.filter(|e| !e.is_empty()) {
        let tramos: Vec<String> = e
            .split('/')
            .filter(|t| !t.is_empty())
            .map(|t| codificar(t, &[]))
            .collect();
        s.push_str(&tramos.join("/"));
        s.push('/');
    }
    s.push_str(&codificar(nombre, &[]));
    if let Some(v) = version.filter(|v| !v.is_empty()) {
        s.push('@');
        s.push_str(&codificar(v, &[':']));
    }
    let mut q: Vec<(&str, &str)> = calificadores
        .iter()
        .copied()
        .filter(|(_, v)| !v.is_empty())
        .collect();
    q.sort_by(|a, b| a.0.cmp(b.0));
    if !q.is_empty() {
        s.push('?');
        let partes: Vec<String> = q
            .iter()
            .map(|(k, v)| format!("{}={}", k.to_ascii_lowercase(), codificar(v, &[':'])))
            .collect();
        s.push_str(&partes.join("&"));
    }
    s
}

/// Normaliza un nombre de PyPI (PEP 503): minusculas, y cualquier serie de `-`,
/// `_` o `.` pasa a un solo `-`.
///
/// `Django`, `django` y `DJANGO` son el mismo paquete para `pip`; tres claves
/// distintas en el inventario serian tres componentes donde hay uno, y el aviso
/// solo casaria con el que se escribiera como en la base de datos.
#[must_use]
pub fn normalizar_pypi(nombre: &str) -> String {
    let mut o = String::with_capacity(nombre.len());
    let mut separador = false;
    for c in nombre.trim().chars() {
        if matches!(c, '-' | '_' | '.') {
            separador = true;
            continue;
        }
        if separador && !o.is_empty() {
            o.push('-');
        }
        separador = false;
        o.push(c.to_ascii_lowercase());
    }
    o
}

#[cfg(test)]
mod pruebas {
    use super::*;

    // Los ejemplos son los de la propia especificacion de Package URL.

    #[test]
    fn debian_con_calificadores_ordenados() {
        assert_eq!(
            montar(
                "deb",
                Some("debian"),
                "curl",
                Some("7.50.3-1"),
                &[("distro", "jessie"), ("arch", "i386")]
            ),
            "pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie"
        );
    }

    #[test]
    fn el_mas_de_una_version_de_debian_se_codifica_y_la_epoca_no() {
        assert_eq!(
            montar(
                "deb",
                Some("ubuntu"),
                "zlib1g",
                Some("1:1.3.dfsg+really1.3.1-1"),
                &[]
            ),
            "pkg:deb/ubuntu/zlib1g@1:1.3.dfsg%2Breally1.3.1-1"
        );
    }

    #[test]
    fn npm_con_ambito() {
        assert_eq!(
            montar("npm", Some("@angular"), "animation", Some("12.3.1"), &[]),
            "pkg:npm/%40angular/animation@12.3.1"
        );
    }

    #[test]
    fn go_con_ruta_de_modulo() {
        assert_eq!(
            montar(
                "golang",
                Some("github.com/pkg"),
                "errors",
                Some("v0.9.1"),
                &[]
            ),
            "pkg:golang/github.com/pkg/errors@v0.9.1"
        );
    }

    #[test]
    fn cargo_y_pypi() {
        assert_eq!(
            montar("cargo", None, "rand", Some("0.7.2"), &[]),
            "pkg:cargo/rand@0.7.2"
        );
        assert_eq!(
            montar("pypi", None, "django", Some("1.11.1"), &[]),
            "pkg:pypi/django@1.11.1"
        );
    }

    #[test]
    fn un_calificador_vacio_no_se_escribe() {
        assert_eq!(
            montar(
                "deb",
                Some("debian"),
                "a",
                Some("1"),
                &[("arch", ""), ("distro", "")]
            ),
            "pkg:deb/debian/a@1"
        );
    }

    #[test]
    fn pep_503() {
        assert_eq!(normalizar_pypi("Django"), "django");
        assert_eq!(normalizar_pypi("jaraco.functools"), "jaraco-functools");
        assert_eq!(normalizar_pypi("Foo__Bar-._baz"), "foo-bar-baz");
    }
}
