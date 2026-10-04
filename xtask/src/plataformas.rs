//! Plataformas: que es producto y que no (FASE 7 del MP-16, H-36).
//!
//! Windows y macOS no son producto: en Windows falta ser miembro de la
//! Microsoft Virus Initiative, un driver ELAM y la firma por atestacion de
//! Microsoft; en macOS, el entitlement de Endpoint Security de Apple. El README
//! lo decia en una linea, la matriz no lo decia, y documentos de fase como
//! «Paridad de defensa en Windows» se leian como producto.
//!
//! La fuente es `tools/config/plataformas.toml`. De ella salen:
//! - el bloque `{{plataformas}}` del README y la seccion «Plataformas» de la
//!   matriz ([`bloque`]);
//! - la puerta ([`comprobar`], dentro de `cargo xtask arquitectura`):
//!   1. cada documento de una plataforma que no es producto lleva, en sus
//!      primeras lineas, la cabecera exacta que genera la configuracion;
//!   2. todo documento de `docs/` cuyo titulo nombre una plataforma que no es
//!      producto esta en esa lista o en las excepciones, con su motivo;
//!   3. ninguna de las frases prohibidas aparece en el README, su plantilla,
//!      la matriz, `docs/`, `docs/operacion/` ni `deploy/README.md`.

use std::fmt::Write as _;
use std::path::Path;

use serde::Deserialize;

use crate::config;
use crate::repo::Repo;
use crate::Resultado;

/// Fichero de configuracion.
pub const CONFIG: &str = "plataformas.toml";

/// Lineas del principio de un documento donde tiene que estar la cabecera.
const LINEAS_CABECERA: usize = 15;

/// `tools/config/plataformas.toml`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plataformas {
    /// Las plataformas.
    pub plataforma: Vec<Plataforma>,
    /// Documentos que nombran una plataforma sin ser de ella.
    #[serde(default)]
    pub excepcion: Vec<Excepcion>,
    /// Frases que contradicen la tabla.
    pub prohibido: Prohibido,
}

/// Una plataforma.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plataforma {
    /// Como se escribe.
    pub nombre: String,
    /// `producto` o `no-producto`.
    pub estado: String,
    /// Lo que la tabla dice de ella.
    pub detalle: String,
    /// Para `no-producto`: lo que falta, como frase completa.
    #[serde(default)]
    pub requisito: String,
    /// Palabras que, en el titulo de un documento, lo hacen de esta plataforma.
    #[serde(default)]
    pub alias: Vec<String>,
    /// Documentos que tienen que llevar la cabecera.
    #[serde(default)]
    pub documentos: Vec<String>,
}

/// Un documento que nombra una plataforma en su titulo sin ser de ella.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Excepcion {
    /// Ruta del documento.
    pub documento: String,
    /// Por que no lleva la cabecera.
    pub motivo: String,
}

/// Frases prohibidas.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prohibido {
    /// Se buscan sin distinguir mayusculas.
    pub frases: Vec<String>,
}

impl Plataforma {
    fn no_producto(&self) -> bool {
        self.estado == "no-producto"
    }
}

/// La cabecera exacta de un documento de una plataforma que no es producto.
#[must_use]
pub fn cabecera(p: &Plataforma) -> String {
    format!(
        "> **{n} no es producto.** {r} Lo que este documento cuenta de {n} es biblioteca o \
         diseño: no protege ninguna máquina {n}. Ver \
         [Plataformas](matriz-capacidades.md#plataformas).",
        n = p.nombre,
        r = p.requisito.trim()
    )
}

/// Si un documento se declara de una plataforma que no es producto (lo usa el
/// indice del README para marcar su titulo).
#[must_use]
pub fn es_no_producto(texto: &str) -> bool {
    texto
        .lines()
        .take(LINEAS_CABECERA)
        .any(|l| l.starts_with("> **") && l.contains(" no es producto.**"))
}

fn leer(raiz: &Path) -> Resultado<Plataformas> {
    let p: Plataformas = config::leer(raiz, CONFIG)?;
    for x in &p.plataforma {
        match x.estado.as_str() {
            "producto" => {}
            "no-producto" => {
                if x.requisito.trim().is_empty() || !x.requisito.trim().ends_with('.') {
                    return Err(format!(
                        "{CONFIG}: {} no es producto y su `requisito` esta vacio o no es una frase",
                        x.nombre
                    )
                    .into());
                }
            }
            otro => {
                return Err(format!(
                    "{CONFIG}: estado «{otro}» de {} (producto | no-producto)",
                    x.nombre
                )
                .into())
            }
        }
    }
    Ok(p)
}

/// La tabla de plataformas, para el README (`desde_docs = false`) o para la
/// matriz, que vive en `docs/` (`desde_docs = true`).
pub fn bloque(raiz: &Path, desde_docs: bool) -> Resultado<String> {
    let p = leer(raiz)?;
    let (config, matriz) = if desde_docs {
        ("../tools/config/plataformas.toml", "#plataformas")
    } else {
        (
            "tools/config/plataformas.toml",
            "docs/matriz-capacidades.md#plataformas",
        )
    };
    let mut s = String::new();
    if desde_docs {
        s.push_str("## Plataformas\n\n");
    }
    let _ = writeln!(
        s,
        "Qué plataformas son producto, generado desde [`tools/config/plataformas.toml`]({config}). \
         `cargo xtask arquitectura` falla si un documento de una plataforma que no es producto no \
         lo dice en su cabecera, o si un texto del repositorio afirma lo contrario \
         ([detalle]({matriz})).\n"
    );
    s.push_str("| Plataforma | Estado | Qué es hoy | Qué hace falta para que sea producto |\n");
    s.push_str("|---|---|---|---|\n");
    for x in &p.plataforma {
        let _ = writeln!(
            s,
            "| {} | {} | {} | {} |",
            x.nombre,
            if x.no_producto() {
                "**No producto**"
            } else {
                "**Producto**"
            },
            x.detalle.replace('|', "\\|"),
            if x.no_producto() {
                x.requisito.replace('|', "\\|")
            } else {
                "—".to_owned()
            }
        );
    }
    s.push('\n');
    Ok(s)
}

/// El H1 de un documento.
fn titulo(texto: &str) -> Option<&str> {
    texto.lines().find_map(|l| l.strip_prefix("# "))
}

/// Si el titulo nombra alguno de los alias (palabra entera, sin mayusculas).
fn nombra(titulo: &str, alias: &[String]) -> bool {
    let t = titulo.to_lowercase();
    let palabras: Vec<&str> = t
        .split(|c: char| !(c.is_alphanumeric() || c == '-'))
        .filter(|w| !w.is_empty())
        .collect();
    alias
        .iter()
        .any(|a| palabras.iter().any(|w| *w == a.to_lowercase()))
}

/// Frases prohibidas que aparecen en un texto.
fn prohibidas<'a>(texto: &str, frases: &'a [String]) -> Vec<&'a str> {
    let t = texto.to_lowercase();
    frases
        .iter()
        .filter(|f| t.contains(&f.to_lowercase()))
        .map(String::as_str)
        .collect()
}

fn md_de(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut v: Vec<_> = std::fs::read_dir(dir)
        .map(|it| {
            it.flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "md"))
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// La puerta.
pub fn comprobar(repo: &Repo) -> Resultado<String> {
    let raiz = &repo.raiz;
    let p = leer(raiz)?;
    let mut fallos: Vec<String> = Vec::new();
    let rel = |x: &Path| {
        x.strip_prefix(raiz)
            .unwrap_or(x)
            .to_string_lossy()
            .replace('\\', "/")
    };

    // 1. Cabeceras.
    let mut con_cabecera = 0;
    for x in p.plataforma.iter().filter(|x| x.no_producto()) {
        let esperada = cabecera(x);
        for d in &x.documentos {
            match std::fs::read_to_string(raiz.join(d)) {
                Ok(t) => {
                    if t.lines().take(LINEAS_CABECERA).any(|l| l == esperada) {
                        con_cabecera += 1;
                    } else {
                        fallos.push(format!(
                            "{d}: le falta la cabecera de plataforma no producto (o no es la que \
                             genera {CONFIG}). En sus {LINEAS_CABECERA} primeras lineas:\n        {esperada}"
                        ));
                    }
                }
                Err(e) => fallos.push(format!("{d} (citado en {CONFIG}): {e}")),
            }
        }
    }

    // 2. Documentos cuyo titulo nombra una plataforma que no es producto.
    let declarados: Vec<&str> = p
        .plataforma
        .iter()
        .flat_map(|x| x.documentos.iter().map(String::as_str))
        .chain(p.excepcion.iter().map(|e| e.documento.as_str()))
        .collect();
    for e in &p.excepcion {
        if e.motivo.trim().is_empty() {
            fallos.push(format!(
                "{CONFIG}: la excepcion {} no tiene motivo",
                e.documento
            ));
        }
    }
    for f in md_de(&raiz.join("docs")) {
        let t = std::fs::read_to_string(&f).unwrap_or_default();
        let Some(h1) = titulo(&t) else { continue };
        for x in p.plataforma.iter().filter(|x| x.no_producto()) {
            let r = rel(&f);
            if nombra(h1, &x.alias) && !declarados.contains(&r.as_str()) {
                fallos.push(format!(
                    "{r}: su titulo nombra {} y no esta en {CONFIG} (ni en `documentos` ni en \
                     `excepcion`)",
                    x.nombre
                ));
            }
        }
    }

    // 3. Frases que contradicen la tabla.
    let mut textos: Vec<std::path::PathBuf> = vec![
        raiz.join("README.md"),
        raiz.join("docs/plantillas/README.md"),
        raiz.join("deploy/README.md"),
    ];
    textos.extend(md_de(&raiz.join("docs")));
    textos.extend(md_de(&raiz.join("docs/operacion")));
    let mut revisados = 0;
    for f in &textos {
        let Ok(t) = std::fs::read_to_string(f) else {
            continue;
        };
        revisados += 1;
        for frase in prohibidas(&t, &p.prohibido.frases) {
            fallos.push(format!(
                "{}: dice «{frase}», y {CONFIG} dice que no es producto",
                rel(f)
            ));
        }
    }

    if fallos.is_empty() {
        Ok(format!(
            "plataformas: {} declaradas, {con_cabecera} documento(s) con su cabecera de no \
             producto, {revisados} texto(s) sin afirmaciones que lo contradigan",
            p.plataforma.len()
        ))
    } else {
        Err(format!("plataformas:\n    {}", fallos.join("\n    ")).into())
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn windows() -> Plataforma {
        Plataforma {
            nombre: "Windows".into(),
            estado: "no-producto".into(),
            detalle: "driver que compila".into(),
            requisito: "Hace falta MVI.".into(),
            alias: vec!["windows".into(), "elam".into()],
            documentos: vec![],
        }
    }

    #[test]
    fn la_cabecera_se_reconoce_y_marca_el_documento() {
        let c = cabecera(&windows());
        assert!(c.starts_with("> **Windows no es producto.** Hace falta MVI. "));
        assert!(es_no_producto(&format!("# Titulo\n\n{c}\n\ntexto")));
        assert!(!es_no_producto("# Titulo\n\nWindows es producto\n"));
    }

    #[test]
    fn el_titulo_nombra_la_plataforma_por_palabra_entera() {
        let a = windows().alias;
        assert!(nombra(
            "Modulo 42 - Paridad de defensa en Windows: ETW-Ti",
            &a
        ));
        assert!(nombra("Autodefensa legitima: ELAM, PPL y Tamper", &a));
        assert!(!nombra("Ventanas deslizantes (windowsize)", &a));
    }

    #[test]
    fn las_frases_prohibidas_se_buscan_sin_mayusculas() {
        let f = vec!["soporta windows".to_owned(), "multiplataforma".to_owned()];
        assert_eq!(
            prohibidas("El agente SOPORTA Windows.", &f),
            vec!["soporta windows"]
        );
        assert!(prohibidas("Windows no es producto.", &f).is_empty());
    }
}
