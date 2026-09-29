//! `cargo xtask capas`: las dependencias solo bajan de capa.
//!
//! Orden, de abajo arriba: nucleo < plataforma < motores < es. Un crate puede
//! depender de su capa o de una inferior. Las herramientas de prueba quedan
//! fuera. Las violaciones conocidas estan en `tools/config/capas.toml` con su
//! causa y su plan, y esa lista solo puede menguar: una violacion nueva falla, y
//! una excepcion que ya no ocurre tambien (hay que borrarla, o la lista mentiria).

use std::collections::{BTreeMap, BTreeSet};

use crate::config::{self, Capas};
use crate::repo::Repo;
use crate::Resultado;

fn rango(capa: &str) -> Option<u8> {
    match capa {
        "núcleo" => Some(0),
        "plataforma" => Some(1),
        "motores" => Some(2),
        "E/S" => Some(3),
        _ => None, // herramientas: fuera de las capas
    }
}

/// Comprueba las capas. Devuelve el informe o los problemas.
pub fn comprobar(repo: &Repo) -> Resultado<String> {
    let capas: Capas = config::leer(&repo.raiz, "capas.toml")?;
    let capa_de = crate::matriz::capa_de(&capas);
    let mut problemas = Vec::new();

    // Cada crate, exactamente una vez.
    let mut vistos: BTreeMap<&str, usize> = BTreeMap::new();
    for lista in [
        &capas.nucleo,
        &capas.plataforma,
        &capas.motores,
        &capas.es,
        &capas.herramientas,
    ] {
        for c in &lista.crates {
            *vistos.entry(c.as_str()).or_default() += 1;
        }
    }
    for (c, n) in &vistos {
        if *n > 1 {
            problemas.push(format!("{c} aparece en {n} capas"));
        }
        if repo.paquete(c).is_none() {
            problemas.push(format!("{c} esta en capas.toml pero no existe"));
        }
    }
    for p in &repo.paquetes {
        if !vistos.contains_key(p.nombre.as_str()) {
            problemas.push(format!(
                "{} no tiene capa: anadelo a tools/config/capas.toml",
                p.nombre
            ));
        }
    }

    let permitidas: BTreeSet<(&str, &str)> = capas
        .excepcion
        .iter()
        .map(|e| (e.desde.as_str(), e.hacia.as_str()))
        .collect();
    let mut usadas = BTreeSet::new();
    let mut aristas = 0;
    for p in &repo.paquetes {
        let Some(rp) = capa_de.get(&p.nombre).copied().and_then(rango) else {
            continue;
        };
        for d in &p.deps {
            aristas += 1;
            let Some(cd) = capa_de.get(d).copied() else {
                continue;
            };
            let Some(rd) = rango(cd) else {
                problemas.push(format!("{} depende de la herramienta {d}", p.nombre));
                continue;
            };
            if rd > rp {
                if permitidas.contains(&(p.nombre.as_str(), d.as_str())) {
                    usadas.insert((p.nombre.as_str(), d.as_str()));
                } else {
                    problemas.push(format!(
                        "{} ({}) depende de {d} ({cd}): una capa inferior no puede depender de una superior",
                        p.nombre,
                        capa_de[&p.nombre]
                    ));
                }
            }
        }
    }
    for e in &capas.excepcion {
        if !usadas.contains(&(e.desde.as_str(), e.hacia.as_str())) {
            problemas.push(format!(
                "la excepcion {} -> {} ya no ocurre: borrala de capas.toml",
                e.desde, e.hacia
            ));
        }
    }

    if problemas.is_empty() {
        Ok(format!(
            "capas: {} crates, {} dependencias internas, {} excepciones conocidas con plan",
            repo.paquetes.len(),
            aristas,
            capas.excepcion.len()
        ))
    } else {
        Err(format!("capas:\n    {}", problemas.join("\n    ")).into())
    }
}
