//! Inventario de la maquina, sus vulnerabilidades y su alcanzabilidad, en texto.
//!
//! Uso:
//!
//! ```text
//! postura_support [--osv DIR] [--imagen RUTA]... [--hallazgos N] [--componentes FICHERO]
//!                 [--trivy FICHERO.json]
//! ```
//!
//! - `--osv DIR`: un directorio de avisos OSV en JSON (la exportacion de osv.dev
//!   de un ecosistema, descomprimida).
//! - `--componentes FICHERO`: escribe una linea `ecosistema nombre version` por
//!   componente, para cotejar con otra herramienta.
//! - `--trivy FICHERO.json`: la salida JSON de `trivy` sobre la misma maquina;
//!   sus vulnerabilidades se pasan por la alcanzabilidad de aqui, para contar
//!   cuantas de las que Trivy da resultan cargadas, alcanzables y expuestas.
//!
//! Es la herramienta de la puerta de calidad y de la comparativa: NO es un
//! exportador. Escribe texto para una persona y listas para un cotejo, nunca un
//! documento SBOM.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Instant;

use aegis_sbom::componente::Ecosistema;
use aegis_sbom::telemetria::DelSistema;
use aegis_sbom::{evaluar, osv, recoger, Evaluador, Opciones};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut o = Opciones::del_sistema();
    let mut dir_osv: Option<PathBuf> = None;
    let mut cuantos = 15usize;
    let mut lista: Option<PathBuf> = None;
    let mut trivy: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        let v = args.get(i + 1).cloned().unwrap_or_default();
        match args[i].as_str() {
            "--osv" => dir_osv = Some(PathBuf::from(v)),
            "--imagen" => o.imagenes.push(PathBuf::from(v)),
            "--hallazgos" => cuantos = v.parse().unwrap_or(15),
            "--componentes" => lista = Some(PathBuf::from(v)),
            "--trivy" => trivy = Some(PathBuf::from(v)),
            otro => {
                eprintln!("argumento desconocido: {otro}");
                std::process::exit(2);
            }
        }
        i += 2;
    }

    let t = Instant::now();
    let sbom = recoger(&o);
    let t_inv = t.elapsed();
    println!("AegisPosture · inventario de la maquina");
    println!();
    println!("  {} componentes en {:.2?}", sbom.componentes.len(), t_inv);
    for (eco, n) in sbom.por_ecosistema() {
        println!("    {:<8} {n}", eco.nombre());
    }
    println!("  fuentes:");
    for f in &sbom.fuentes {
        println!("    {:<26} {:?}", f.nombre, f.estado);
    }
    for img in &sbom.imagenes {
        println!(
            "  imagen {}: {} capas, {} componentes",
            img.nombre,
            img.capas.len(),
            img.componentes.len()
        );
    }
    if let Some(p) = &lista {
        let mut s = String::new();
        for c in &sbom.componentes {
            s.push_str(&format!(
                "{} {} {}\n",
                c.ecosistema.nombre(),
                c.nombre,
                c.version
            ));
        }
        if let Err(e) = std::fs::write(p, s) {
            eprintln!("no se pudo escribir {}: {e}", p.display());
            std::process::exit(1);
        }
    }

    let t = Instant::now();
    let ev = Evaluador::nuevo(&DelSistema);
    let (leidos, no_leidos) = ev.cobertura();
    println!();
    println!("  telemetria: {leidos} procesos leidos, {no_leidos} no leidos");

    if let Some(d) = &dir_osv {
        // Solo lo que puede casar con este inventario: el resto se descarta al
        // leer, antes de cargar sus listas de versiones.
        let interes = aegis_sbom::correlacion::Interes::de(&sbom.componentes);
        let carga = osv::cargar_directorio_filtrado(d, &|e, n| interes.quiere(e, n));
        println!(
            "  avisos OSV: {} ficheros leidos ({} ilegibles); {} avisos afectan al inventario, {} \
             descartados al leer por no afectar a nada instalado",
            carga.ficheros,
            carga.ilegibles,
            carga.avisos.len(),
            carga.descartados
        );
        let inf = evaluar(&sbom, &carga.avisos, &ev);
        let mut tri: BTreeMap<(&str, &str, &str), usize> = BTreeMap::new();
        for h in &inf.hallazgos {
            *tri.entry((
                h.alcance.cargado.nombre(),
                h.alcance.alcanzable.nombre(),
                h.alcance.expuesto.nombre(),
            ))
            .or_insert(0) += 1;
        }
        let distintos: std::collections::BTreeSet<&str> =
            inf.hallazgos.iter().map(|h| h.fallo.as_str()).collect();
        println!(
            "  hallazgos: {} ({} fallos distintos) en {:.2?}; cargados {}; descartables con \
             evidencia {}; sin evaluar (rangos de commits) {}",
            inf.hallazgos.len(),
            distintos.len(),
            t.elapsed(),
            inf.cargados(),
            inf.descartables(),
            inf.sin_evaluar
        );
        println!("  (cargado, alcanzable, expuesto) -> hallazgos:");
        for ((c, a, e), n) in &tri {
            println!("    ({c:<9} {a:<9} {e:<9}) {n}");
        }
        println!();
        println!("  los {cuantos} primeros por prioridad:");
        for h in inf.hallazgos.iter().take(cuantos) {
            let c = &sbom.componentes[h.componente];
            println!(
                "    {:<18} {:<28} {:<11} cargado={} alcanzable={} expuesto={}",
                h.fallo,
                format!("{} {}", c.nombre, c.version),
                h.gravedad.texto(),
                h.alcance.cargado.nombre(),
                h.alcance.alcanzable.nombre(),
                h.alcance.expuesto.nombre()
            );
            if h.alcance.cargado.es_si() {
                println!("      {}", h.alcance.cargado.porque());
            }
            if h.alcance.expuesto.es_si() {
                println!("      {}", h.alcance.expuesto.porque());
            }
        }
    }

    if let Some(p) = &trivy {
        comparar_con_trivy(p, &sbom, &ev);
    }
}

/// Pasa las vulnerabilidades que da Trivy por la alcanzabilidad de aqui.
fn comparar_con_trivy(p: &PathBuf, sbom: &aegis_sbom::Sbom, ev: &Evaluador<'_>) {
    let Ok(t) = std::fs::read_to_string(p) else {
        eprintln!("no se pudo leer {}", p.display());
        std::process::exit(1);
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&t) else {
        eprintln!("{} no es JSON", p.display());
        std::process::exit(1);
    };
    let mut total = 0usize;
    let mut distintas = std::collections::BTreeSet::new();
    let mut sin_componente = 0usize;
    let mut tri: BTreeMap<(&'static str, &'static str), usize> = BTreeMap::new();
    for r in v
        .get("Results")
        .and_then(|r| r.as_array())
        .into_iter()
        .flatten()
    {
        for vul in r
            .get("Vulnerabilities")
            .and_then(|x| x.as_array())
            .into_iter()
            .flatten()
        {
            total += 1;
            let id = vul
                .get("VulnerabilityID")
                .and_then(|x| x.as_str())
                .unwrap_or("");
            distintas.insert(id.to_string());
            let nombre = vul.get("PkgName").and_then(|x| x.as_str()).unwrap_or("");
            let version = vul
                .get("InstalledVersion")
                .and_then(|x| x.as_str())
                .unwrap_or("");
            let Some(c) = sbom.componentes.iter().find(|c| {
                c.ecosistema == Ecosistema::Deb && c.nombre == nombre && c.version == version
            }) else {
                sin_componente += 1;
                continue;
            };
            let a = ev.evaluar(c, &[]);
            *tri.entry((a.cargado.nombre(), a.expuesto.nombre()))
                .or_insert(0) += 1;
        }
    }
    println!();
    println!(
        "  Trivy: {total} vulnerabilidades ({} distintas); {sin_componente} sobre componentes \
         que no estan en este inventario",
        distintas.len()
    );
    println!("  (cargado, expuesto) segun la telemetria de aqui -> vulnerabilidades de Trivy:");
    for ((c, e), n) in &tri {
        println!("    ({c:<9} {e:<9}) {n}");
    }
}
