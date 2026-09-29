//! `cargo xtask amenazas`: el modelo de amenazas es un documento con estructura.
//!
//! `docs/modelo-de-amenazas.md` es prosa, pero sus tablas son datos y las fases
//! posteriores las citan por identificador. Esta puerta comprueba:
//!
//! - que el documento declara su version;
//! - que cada fila `| AM-x.y | ... |` tiene identificador unico, uno de los
//!   estados validos y seis columnas;
//! - que toda ruta citada como evidencia (entre comillas invertidas) existe;
//! - que un control **existente** lleva al menos una evidencia;
//! - que cada registro de fase posterior a la FASE 0 del MP-15 (`docs/NNN-*.md`
//!   con NNN >= 108) cita el modelo, porque cada fase cambia la superficie.

use std::collections::BTreeSet;

use crate::repo::Repo;
use crate::Resultado;

/// Documento del modelo.
pub const MODELO: &str = "docs/modelo-de-amenazas.md";
/// Primer registro de fase que tiene que citarlo.
const PRIMER_REGISTRO_QUE_CITA: u32 = 108;
const ESTADOS: [&str; 5] = ["existente", "parcial", "ausente", "aceptado", "no-aplica"];

/// Comprueba el modelo y las citas.
pub fn comprobar(repo: &Repo) -> Resultado<String> {
    let texto =
        std::fs::read_to_string(repo.raiz.join(MODELO)).map_err(|e| format!("{MODELO}: {e}"))?;
    let mut problemas = Vec::new();
    if !texto.contains("> **Versión ") {
        problemas.push(format!(
            "{MODELO} no declara su version («> **Versión N**»)"
        ));
    }

    let mut ids = BTreeSet::new();
    let mut cuenta: std::collections::BTreeMap<&str, usize> = Default::default();
    for (n, linea) in texto.lines().enumerate() {
        let Some(resto) = linea.strip_prefix("| AM-") else {
            continue;
        };
        let celdas: Vec<&str> = linea
            .trim_matches('|')
            .split(" | ")
            .map(str::trim)
            .collect();
        let donde = format!("{MODELO}:{}", n + 1);
        if celdas.len() != 6 {
            problemas.push(format!(
                "{donde}: la fila tiene {} columnas y debe tener 6",
                celdas.len()
            ));
            continue;
        }
        let id = celdas[0];
        let valido = resto
            .split_once(' ')
            .map(|(x, _)| x)
            .and_then(|x| x.split_once('.'))
            .is_some_and(|(a, b)| {
                !a.is_empty()
                    && !b.is_empty()
                    && a.chars().all(|c| c.is_ascii_digit())
                    && b.chars().all(|c| c.is_ascii_digit())
            });
        if !valido {
            problemas.push(format!(
                "{donde}: identificador mal formado «{id}» (AM-x.y)"
            ));
        }
        if !ids.insert(id.to_string()) {
            problemas.push(format!("{donde}: {id} repetido"));
        }
        let estado = celdas[3].trim_matches('*');
        match ESTADOS.iter().find(|e| **e == estado) {
            Some(e) => *cuenta.entry(e).or_default() += 1,
            None => problemas.push(format!(
                "{donde}: {id} tiene el estado «{estado}»; validos: {}",
                ESTADOS.join(", ")
            )),
        }
        let evidencias: Vec<&str> = celdas[4]
            .split('`')
            .enumerate()
            .filter(|(i, _)| i % 2 == 1)
            .map(|(_, e)| e)
            .collect();
        for e in &evidencias {
            if !repo.raiz.join(e).exists() {
                problemas.push(format!("{donde}: {id} cita «{e}», que no existe"));
            }
        }
        if estado == "existente" && evidencias.is_empty() {
            problemas.push(format!(
                "{donde}: {id} es «existente» sin evidencia: un control que no se puede señalar no existe"
            ));
        }
    }
    if ids.is_empty() {
        problemas.push(format!("{MODELO} no tiene ninguna fila AM-x.y"));
    }

    // Los registros de fase posteriores tienen que citar el modelo.
    let mut sin_cita = Vec::new();
    if let Ok(entradas) = std::fs::read_dir(repo.raiz.join("docs")) {
        for e in entradas.flatten() {
            let nombre = e.file_name().to_string_lossy().into_owned();
            let Some(num) = nombre.split('-').next().and_then(|n| n.parse::<u32>().ok()) else {
                continue;
            };
            if num < PRIMER_REGISTRO_QUE_CITA {
                continue;
            }
            let t = std::fs::read_to_string(e.path()).unwrap_or_default();
            if !t.contains("modelo-de-amenazas") && !t.contains("AM-") {
                sin_cita.push(nombre);
            }
        }
    }
    for n in sin_cita {
        problemas.push(format!(
            "docs/{n} no cita el modelo de amenazas: cada fase dice que controles cierra, abre o cambia"
        ));
    }

    if problemas.is_empty() {
        Ok(format!(
            "amenazas: {} filas ({})",
            ids.len(),
            cuenta
                .iter()
                .map(|(e, n)| format!("{n} {e}"))
                .collect::<Vec<_>>()
                .join(", ")
        ))
    } else {
        Err(format!("amenazas:\n    {}", problemas.join("\n    ")).into())
    }
}
