//! `cargo xtask nombres`: un solo idioma (espanol) para crates y modulos.
//!
//! El renombrado es planificado (`tools/config/nombres.toml`). Esta puerta no
//! obliga a renombrar hoy: impide que el problema CREZCA. Un crate nuevo nace
//! conforme, un modulo nuevo no usa palabras del lexico ingles, y las listas de
//! pendientes solo pueden menguar.

use std::collections::BTreeSet;

use crate::config::{self, Nombres};
use crate::repo::{self, Repo};
use crate::Resultado;

/// Crates pendientes de traducir al cerrar la FASE 0. Es el TECHO: la lista de
/// `[crates.pendientes]` puede bajar de aqui, nunca subir. Al renombrar un
/// crate se baja tambien este numero, en el mismo commit.
const TECHO_CRATES_PENDIENTES: usize = 56;

/// Modulo de fichero de un crate: `aegis-agent/graph`.
fn modulos(repo: &Repo) -> BTreeSet<String> {
    let mut v = BTreeSet::new();
    for p in &repo.paquetes {
        let src = repo.raiz.join(&p.dir).join("src");
        for f in repo::fuentes_rust(&src) {
            let rel = f.strip_prefix(&src).unwrap_or(&f);
            // Los ejecutables de src/bin/ llevan el nombre del producto y se
            // renombran con su crate; no son modulos.
            if rel.starts_with("bin") {
                continue;
            }
            let mut partes: Vec<String> = rel
                .with_extension("")
                .iter()
                .map(|c| c.to_string_lossy().into_owned())
                .collect();
            if partes.last().is_some_and(|u| u == "mod") {
                partes.pop();
            }
            if partes.is_empty() {
                continue;
            }
            v.insert(format!("{}/{}", p.nombre, partes.join("/")));
        }
    }
    v
}

/// Si el ultimo tramo del modulo contiene una palabra del lexico ingles.
fn es_ingles(modulo: &str, lexico: &BTreeSet<&str>, convencion: &BTreeSet<&str>) -> bool {
    let ultimo = modulo.rsplit('/').next().unwrap_or(modulo);
    if convencion.contains(ultimo) {
        return false;
    }
    ultimo.split('_').any(|t| lexico.contains(t))
}

/// Los modulos en ingles de hoy, para sembrar `[modulos].pendientes`.
pub fn inventario(repo: &Repo) -> Resultado<String> {
    let n: Nombres = config::leer(&repo.raiz, "nombres.toml")?;
    let lexico: BTreeSet<&str> = n.modulos.lexico_ingles.iter().map(String::as_str).collect();
    let conv: BTreeSet<&str> = n.modulos.convencion.iter().map(String::as_str).collect();
    let mut s = String::from("pendientes = [\n");
    for m in modulos(repo)
        .iter()
        .filter(|m| es_ingles(m, &lexico, &conv))
    {
        s.push_str(&format!("    \"{m}\",\n"));
    }
    s.push_str("]\n");
    Ok(s)
}

/// Comprueba el plan de nombres.
pub fn comprobar(repo: &Repo) -> Resultado<String> {
    let n: Nombres = config::leer(&repo.raiz, "nombres.toml")?;
    let mut problemas = Vec::new();

    // ── Crates ──
    let conformes: BTreeSet<&str> = n.crates.conformes.iter().map(String::as_str).collect();
    let existentes: BTreeSet<&str> = repo.paquetes.iter().map(|p| p.nombre.as_str()).collect();
    for p in &existentes {
        match (conformes.contains(p), n.crates.pendientes.contains_key(*p)) {
            (true, true) => problemas.push(format!("{p} esta a la vez en conformes y pendientes")),
            (false, false) => problemas.push(format!(
                "{p} no esta clasificado en nombres.toml; un crate nuevo nace con nombre en \
                 espanol y va a [crates].conformes"
            )),
            _ => {}
        }
    }
    for c in conformes
        .iter()
        .copied()
        .chain(n.crates.pendientes.keys().map(String::as_str))
    {
        if !existentes.contains(c) {
            problemas.push(format!("{c} esta en nombres.toml pero no existe: borralo"));
        }
    }
    for (actual, nuevo) in &n.crates.pendientes {
        if existentes.contains(nuevo.as_str()) {
            problemas.push(format!(
                "el nombre planificado para {actual} ({nuevo}) ya lo usa otro crate"
            ));
        }
    }
    let objetivos: BTreeSet<&str> = n.crates.pendientes.values().map(String::as_str).collect();
    if objetivos.len() != n.crates.pendientes.len() {
        problemas.push("dos crates tienen planificado el mismo nombre".into());
    }
    if n.crates.pendientes.len() > TECHO_CRATES_PENDIENTES {
        problemas.push(format!(
            "hay {} crates pendientes de traducir y el techo es {TECHO_CRATES_PENDIENTES}: \
             los crates nuevos nacen en espanol",
            n.crates.pendientes.len()
        ));
    }

    // ── Modulos ──
    let lexico: BTreeSet<&str> = n.modulos.lexico_ingles.iter().map(String::as_str).collect();
    let conv: BTreeSet<&str> = n.modulos.convencion.iter().map(String::as_str).collect();
    let pendientes: BTreeSet<&str> = n.modulos.pendientes.iter().map(String::as_str).collect();
    let todos = modulos(repo);
    let ingleses: BTreeSet<&str> = todos
        .iter()
        .filter(|m| es_ingles(m, &lexico, &conv))
        .map(String::as_str)
        .collect();
    for m in ingleses.difference(&pendientes) {
        problemas.push(format!(
            "modulo nuevo en ingles: {m} (tradúcelo; el lexico esta en nombres.toml)"
        ));
    }
    for m in pendientes.difference(&ingleses) {
        problemas.push(format!(
            "{m} ya no existe o ya no esta en ingles: borralo de [modulos].pendientes"
        ));
    }

    if problemas.is_empty() {
        Ok(format!(
            "nombres: {} crates ({} conformes, {} pendientes con nombre planificado), \
             {} modulos ({} pendientes de traducir)",
            existentes.len(),
            conformes.len(),
            n.crates.pendientes.len(),
            todos.len(),
            pendientes.len()
        ))
    } else {
        Err(format!("nombres:\n    {}", problemas.join("\n    ")).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detecta_trozos_ingleses_y_respeta_la_convencion() {
        let lex: BTreeSet<&str> = ["graph", "edge", "engine"].into_iter().collect();
        let conv: BTreeSet<&str> = ["lib", "error"].into_iter().collect();
        assert!(es_ingles("aegis-agent/graph", &lex, &conv));
        assert!(es_ingles("aegis-agent/edge_ml", &lex, &conv));
        assert!(!es_ingles("aegis-agent/grafo", &lex, &conv));
        assert!(!es_ingles("aegis-x/error", &lex, &conv));
        assert!(
            !es_ingles("aegis-behavior/motor", &lex, &conv),
            "el crate no cuenta"
        );
    }
}
