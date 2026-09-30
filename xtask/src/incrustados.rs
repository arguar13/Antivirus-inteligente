//! `cargo xtask incrustados`: todo fichero que el codigo incrusta esta en git.
//!
//! `include_bytes!` e `include_str!` leen el fichero al COMPILAR. Si ese fichero
//! existe en el disco del desarrollador pero no en el repositorio —porque el
//! `.gitignore` lo excluye o porque nunca se anadio—, todo compila en su maquina
//! y nada compila en un clon limpio. Paso de verdad: los modelos ONNX de
//! referencia estaban excluidos por `*.onnx` y `aegis-ml` no compilaba en el
//! primer runner independiente (FASE 0 del MP-15).
//!
//! Se comprueban las rutas LITERALES. Las que se construyen con `concat!` y
//! `env!("OUT_DIR")` son salidas de `build.rs` y no tienen que estar en git.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

use crate::repo::{self, Repo};
use crate::Resultado;

/// Las rutas literales de `include_bytes!("...")` / `include_str!("...")`.
fn rutas_incrustadas(texto: &str) -> Vec<String> {
    let mut v = Vec::new();
    for macro_ in ["include_bytes!(", "include_str!("] {
        for (i, _) in texto.match_indices(macro_) {
            let resto = texto[i + macro_.len()..].trim_start();
            if let Some(literal) = resto.strip_prefix('"') {
                if let Some(fin) = literal.find('"') {
                    v.push(literal[..fin].to_string());
                }
            }
        }
    }
    v
}

/// Comprueba que cada fichero incrustado esta versionado.
pub fn comprobar(repo: &Repo) -> Resultado<String> {
    let salida = Command::new("git")
        .args(["ls-files", "--cached"])
        .current_dir(&repo.raiz)
        .output()
        .map_err(|e| format!("git ls-files: {e}"))?;
    let versionados: BTreeSet<String> = String::from_utf8_lossy(&salida.stdout)
        .lines()
        .map(str::to_string)
        .collect();

    let mut total = 0;
    let mut problemas = Vec::new();
    for p in &repo.paquetes {
        for f in repo::fuentes_rust(&repo.raiz.join(&p.dir)) {
            let Ok(texto) = std::fs::read_to_string(&f) else {
                continue;
            };
            for ruta in rutas_incrustadas(&texto) {
                total += 1;
                let base = f.parent().unwrap_or(Path::new("."));
                let destino = base.join(&ruta);
                // Normaliza `..` sin tocar el disco: el fichero puede no existir.
                let mut partes: Vec<String> = Vec::new();
                let rel = repo::relativa(&repo.raiz, &destino);
                for c in rel.split('/') {
                    match c {
                        ".." => {
                            partes.pop();
                        }
                        "." | "" => {}
                        otro => partes.push(otro.to_string()),
                    }
                }
                let normal = partes.join("/");
                if !versionados.contains(&normal) {
                    problemas.push(format!(
                        "{} incrusta «{ruta}» ({normal}), que no esta en git: en un clon limpio no compila",
                        repo::relativa(&repo.raiz, &f)
                    ));
                }
            }
        }
    }

    if problemas.is_empty() {
        Ok(format!(
            "incrustados: {total} ficheros incrustados, todos versionados"
        ))
    } else {
        Err(format!("incrustados:\n    {}", problemas.join("\n    ")).into())
    }
}

#[cfg(test)]
mod tests {
    use super::rutas_incrustadas;

    #[test]
    fn solo_las_rutas_literales() {
        let t = r#"
            const A: &[u8] = include_bytes!("../models/a.onnx");
            const B: &str = include_str!( "../../panel/index.html" );
            const C: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/x.o"));
        "#;
        assert_eq!(
            rutas_incrustadas(t),
            vec![
                "../models/a.onnx".to_string(),
                "../../panel/index.html".to_string()
            ]
        );
    }
}
