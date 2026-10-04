//! El arbol fuente del contenido, tal como vive en el repositorio.
//!
//! ```text
//!   contenido/
//!     canal.txt                      canal = estable
//!     yara/<Regla>/regla.yar         una sola regla, que se llama como el directorio
//!     yara/<Regla>/ficha.txt         modo, activa, presupuestos y medicion
//!     yara/<Regla>/dispara-*         muestras que la disparan
//!     yara/<Regla>/no-dispara-*      muestras que no
//! ```
//!
//! Una muestra `*.hex` se lee como hexadecimal (espacios y lineas `#`
//! ignorados), para poder escribir bytes binarios sin meter binarios en git; el
//! resto se toma tal cual.
//!
//! La ficha es `clave = valor`, una por linea, con estas claves y ninguna mas:
//! `modo`, `activa` (si/no), `pasos_por_byte`, `micros_por_64k`,
//! `muestras_benignas`, `falsos_positivos`. Una clave desconocida es un error:
//! una errata en «modo» no puede dejar la regla con el valor por defecto sin
//! que nadie lo vea.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::paquete::{Coste, Entrada, Medicion, Modo, Tipo};
use crate::publicar::Borrador;

/// Error leyendo el arbol fuente.
#[derive(Debug, thiserror::Error)]
#[error("{}: {que}", .ruta.display())]
pub struct ErrorFuente {
    /// Donde.
    pub ruta: PathBuf,
    /// Que.
    pub que: String,
}

fn error(ruta: &Path, que: impl Into<String>) -> ErrorFuente {
    ErrorFuente {
        ruta: ruta.to_path_buf(),
        que: que.into(),
    }
}

const CLAVES: [&str; 6] = [
    "modo",
    "activa",
    "pasos_por_byte",
    "micros_por_64k",
    "muestras_benignas",
    "falsos_positivos",
];

/// Lee un fichero `clave = valor`.
///
/// # Errores
/// Lineas sin `=` o claves repetidas.
pub fn leer_ficha(texto: &str) -> Result<BTreeMap<String, String>, String> {
    let mut m = BTreeMap::new();
    for (n, linea) in texto.lines().enumerate() {
        let l = linea.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let (k, v) = l
            .split_once('=')
            .ok_or_else(|| format!("linea {}: falta «=»", n + 1))?;
        if m.insert(k.trim().to_string(), v.trim().to_string())
            .is_some()
        {
            return Err(format!("linea {}: clave «{}» repetida", n + 1, k.trim()));
        }
    }
    Ok(m)
}

fn leer_hex(texto: &str) -> Result<Vec<u8>, String> {
    let digitos: Vec<u8> = texto
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .flat_map(str::bytes)
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if digitos.len() % 2 != 0 {
        return Err("numero impar de digitos hexadecimales".into());
    }
    digitos
        .chunks(2)
        .map(|p| {
            let t = std::str::from_utf8(p).map_err(|_| "hex no ASCII".to_string())?;
            u8::from_str_radix(t, 16).map_err(|_| format!("«{t}» no es hex"))
        })
        .collect()
}

fn ficheros(dir: &Path) -> Result<Vec<PathBuf>, ErrorFuente> {
    let mut v = Vec::new();
    for e in std::fs::read_dir(dir).map_err(|e| error(dir, e.to_string()))? {
        let e = e.map_err(|x| error(dir, x.to_string()))?;
        v.push(e.path());
    }
    v.sort();
    Ok(v)
}

fn numero(ficha: &BTreeMap<String, String>, clave: &str, ruta: &Path) -> Result<u64, ErrorFuente> {
    let v = ficha
        .get(clave)
        .ok_or_else(|| error(ruta, format!("falta la clave «{clave}»")))?;
    v.parse()
        .map_err(|_| error(ruta, format!("«{clave}»: «{v}» no es un numero")))
}

fn fichero_fuente(tipo: Tipo) -> &'static str {
    match tipo {
        Tipo::Yara => "regla.yar",
        Tipo::Sigma => "regla.yml",
        Tipo::Modelo => "modelo.onnx",
    }
}

/// Lee una entrada de su directorio.
///
/// # Errores
/// [`ErrorFuente`] con la ruta y el motivo.
pub fn leer_entrada(dir: &Path, tipo: Tipo) -> Result<Entrada, ErrorFuente> {
    let id = dir
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| error(dir, "nombre de directorio no UTF-8"))?
        .to_string();
    let ruta_fuente = dir.join(fichero_fuente(tipo));
    let fuente = std::fs::read(&ruta_fuente).map_err(|e| error(&ruta_fuente, e.to_string()))?;
    let ruta_ficha = dir.join("ficha.txt");
    let texto =
        std::fs::read_to_string(&ruta_ficha).map_err(|e| error(&ruta_ficha, e.to_string()))?;
    let ficha = leer_ficha(&texto).map_err(|m| error(&ruta_ficha, m))?;
    if let Some(k) = ficha.keys().find(|k| !CLAVES.contains(&k.as_str())) {
        return Err(error(&ruta_ficha, format!("clave desconocida «{k}»")));
    }
    let modo_txt = ficha
        .get("modo")
        .ok_or_else(|| error(&ruta_ficha, "falta la clave «modo»"))?;
    let modo = Modo::parsear(modo_txt)
        .ok_or_else(|| error(&ruta_ficha, format!("modo «{modo_txt}» desconocido")))?;
    let activa = match ficha.get("activa").map(String::as_str) {
        Some("si") => true,
        Some("no") => false,
        _ => return Err(error(&ruta_ficha, "«activa» tiene que ser si o no")),
    };
    let micros = numero(&ficha, "micros_por_64k", &ruta_ficha)?;
    let coste = Coste {
        pasos_por_byte: numero(&ficha, "pasos_por_byte", &ruta_ficha)?,
        micros_por_64k: u32::try_from(micros)
            .map_err(|_| error(&ruta_ficha, "«micros_por_64k» fuera de rango"))?,
    };
    let medicion = Medicion {
        muestras_benignas: numero(&ficha, "muestras_benignas", &ruta_ficha)?,
        falsos_positivos: numero(&ficha, "falsos_positivos", &ruta_ficha)?,
    };

    let mut dispara = Vec::new();
    let mut no_dispara = Vec::new();
    for f in ficheros(dir)? {
        let nombre = f
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        let lado = if nombre.starts_with("no-dispara") {
            &mut no_dispara
        } else if nombre.starts_with("dispara") {
            &mut dispara
        } else {
            continue;
        };
        let bytes = std::fs::read(&f).map_err(|e| error(&f, e.to_string()))?;
        let muestra = if nombre.ends_with(".hex") {
            let t = String::from_utf8(bytes).map_err(|_| error(&f, "hex no UTF-8"))?;
            leer_hex(&t).map_err(|m| error(&f, m))?
        } else {
            bytes
        };
        lado.push(muestra);
    }

    Ok(Entrada {
        id,
        tipo,
        modo,
        activa,
        coste,
        medicion,
        fuente,
        dispara,
        no_dispara,
    })
}

/// Lee el arbol entero en un [`Borrador`].
///
/// # Errores
/// [`ErrorFuente`] con la ruta y el motivo del primer problema.
pub fn leer_arbol(raiz: &Path) -> Result<Borrador, ErrorFuente> {
    let ruta_canal = raiz.join("canal.txt");
    let texto =
        std::fs::read_to_string(&ruta_canal).map_err(|e| error(&ruta_canal, e.to_string()))?;
    let ficha = leer_ficha(&texto).map_err(|m| error(&ruta_canal, m))?;
    let canal = ficha
        .get("canal")
        .ok_or_else(|| error(&ruta_canal, "falta la clave «canal»"))?
        .clone();
    let mut entradas = Vec::new();
    for tipo in Tipo::TODOS {
        let dir = raiz.join(tipo.nombre());
        if !dir.is_dir() {
            continue;
        }
        for d in ficheros(&dir)? {
            if d.is_dir() {
                entradas.push(leer_entrada(&d, tipo)?);
            }
        }
    }
    Ok(Borrador { canal, entradas })
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn la_ficha_es_estricta() {
        let f = leer_ficha("# c\nmodo = auditoria\n\nactiva=si\n").unwrap();
        assert_eq!(f["modo"], "auditoria");
        assert_eq!(f["activa"], "si");
        assert!(leer_ficha("sin igual").is_err());
        assert!(leer_ficha("a = 1\na = 2").is_err());
    }

    #[test]
    fn el_hex_ignora_espacios_y_comentarios() {
        assert_eq!(leer_hex("# x\n41 42\n 43").unwrap(), b"ABC");
        assert!(leer_hex("4").is_err());
        assert!(leer_hex("zz").is_err());
    }
}
