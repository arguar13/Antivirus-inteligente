//! El paquete para auditoria externa: `docs/generado/auditoria/`.
//!
//! Tres documentos, generados por `cargo xtask docs` y comprobados por
//! `cargo xtask docs --comprobar` (grupo `documentacion` de make ci):
//!
//! - `README.md`: el indice. Modelo de amenazas, arquitectura (capas), matriz
//!   de capacidades, SBOM y procedencia del build, con lo que dice cada pieza
//!   sacado del codigo.
//! - `alcance-pentest.md`: las superficies de ataque y sus puntos de entrada,
//!   EXTRAIDOS del codigo en cada generacion (variantes de los protocolos,
//!   rutas de la API con su permiso y alcance RBAC y las que se sirven sin
//!   sesion, RPC, limites). Si el codigo
//!   cambia de forma que un extractor no encuentra nada, la generacion falla:
//!   un alcance que describe codigo que ya no existe es peor que ninguno.
//! - `slsa.md`: el nivel SLSA, CALCULADO a partir de requisitos cuya evidencia
//!   se comprueba. Un «cumple» sin evidencia, o un «no» que un fichero del
//!   repositorio desmiente, hacen fallar la generacion.
//!
//! La prosa vive en `tools/config/auditoria.toml` y no puede llevar cifras
//! escritas a mano (regla 3): se busca con [`crate::docs::cifras_a_mano`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::PathBuf;

use crate::config::{self, Auditoria, Capas, Extractor, RequisitoSlsa};
use crate::matriz::Matriz;
use crate::repo::Repo;
use crate::sbom::Sbom;
use crate::Resultado;

/// Directorio del paquete.
pub const DIR: &str = "docs/generado/auditoria";
/// De `DIR` a la raiz del repositorio, para los enlaces.
const A_RAIZ: &str = "../../../";
/// Estados de un requisito SLSA.
const ESTADOS: [&str; 3] = ["cumple", "parcial", "no"];
/// Metodos HTTP que declara una ruta.
const METODOS: [&str; 5] = ["get", "post", "put", "delete", "patch"];
/// Manifiestos de los objetivos de fuzzing: el del agente y el del servidor.
const FUZZ: [&str; 2] = ["fuzz/Cargo.toml", "server/fuzz/Cargo.toml"];

/// Los documentos del paquete: (ruta relativa, contenido).
pub fn generar(repo: &Repo, m: &Matriz, sboms: &[Sbom]) -> Resultado<Vec<(PathBuf, String)>> {
    let aud: Auditoria = config::leer(&repo.raiz, "auditoria.toml")?;
    prosa_sin_cifras(&aud)?;
    let (nivel, pendientes) = nivel_slsa(repo, &aud)?;
    Ok(vec![
        (
            PathBuf::from(DIR).join("README.md"),
            indice(repo, m, sboms, &aud, nivel, &pendientes)?,
        ),
        (
            PathBuf::from(DIR).join("alcance-pentest.md"),
            alcance(repo, m, &aud)?,
        ),
        (
            PathBuf::from(DIR).join("slsa.md"),
            slsa(&aud, nivel, &pendientes),
        ),
    ])
}

fn cabecera(titulo: &str) -> String {
    format!(
        "<!--\n  GENERADO por `cargo xtask docs`. NO SE EDITA AQUI.\n  \
         La prosa vive en tools/config/auditoria.toml y los datos en el codigo.\n-->\n\n\
         # {titulo}\n\n"
    )
}

/// `docs/x.md` -> enlace relativo desde el paquete.
fn enlace(ruta: &str) -> String {
    format!("[`{ruta}`]({A_RAIZ}{ruta})")
}

fn lista(s: &mut String, v: &[String]) {
    for x in v {
        let _ = writeln!(s, "- {x}");
    }
    s.push('\n');
}

fn celda(t: &str) -> String {
    t.replace('|', "\\|").replace('\n', " ")
}

// ── Regla 3 ─────────────────────────────────────────────────────────────────

fn mirar(problemas: &mut Vec<String>, donde: &str, texto: &str) {
    for (_, c) in crate::docs::cifras_a_mano(texto) {
        problemas.push(format!("{donde}: «{c}»"));
    }
}

fn prosa_sin_cifras(aud: &Auditoria) -> Resultado<()> {
    let mut p = Vec::new();
    let t = &aud.textos;
    mirar(&mut p, "textos.introduccion", t.introduccion.as_str());
    mirar(&mut p, "textos.procedencia", t.procedencia.as_str());
    mirar(
        &mut p,
        "textos.alcance_introduccion",
        t.alcance_introduccion.as_str(),
    );
    mirar(
        &mut p,
        "textos.ventanas_y_contacto",
        t.ventanas_y_contacto.as_str(),
    );
    mirar(&mut p, "textos.constructor", t.constructor.as_str());
    for (nombre, v) in [
        ("textos.limitaciones_sbom", &t.limitaciones_sbom),
        ("textos.reglas", &t.reglas),
        ("textos.fuera_de_alcance", &t.fuera_de_alcance),
        ("textos.criterios_de_cierre", &t.criterios_de_cierre),
    ] {
        for x in v {
            mirar(&mut p, nombre, x.as_str());
        }
    }
    for s in &aud.superficie {
        let donde = format!("superficie {}", s.id);
        mirar(&mut p, &donde, s.descripcion.as_str());
        for x in s.ataques.iter().chain(s.fuera.iter()) {
            mirar(&mut p, &donde, x.as_str());
        }
    }
    for r in &aud.slsa {
        mirar(&mut p, "slsa", r.requisito.as_str());
        mirar(&mut p, "slsa", r.detalle.as_str());
    }
    for v in &aud.vendorizado {
        mirar(&mut p, "vendorizado", v.nota.as_str());
    }
    for c in &aud.sistema {
        mirar(&mut p, "sistema", c.descripcion.as_str());
    }
    if p.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "tools/config/auditoria.toml tiene cifras escritas a mano (regla 3):\n    {}",
            p.join("\n    ")
        )
        .into())
    }
}

// ── SLSA ────────────────────────────────────────────────────────────────────

/// Comprueba los requisitos y calcula el nivel alcanzado: el mayor N tal que
/// todo requisito de nivel 1 a N cumple. Devuelve tambien lo que falta para
/// el siguiente.
fn nivel_slsa(repo: &Repo, aud: &Auditoria) -> Resultado<(u8, Vec<String>)> {
    let mut problemas = Vec::new();
    for r in &aud.slsa {
        if !ESTADOS.contains(&r.estado.as_str()) {
            problemas.push(format!(
                "«{}»: estado «{}»; validos: {}",
                r.requisito,
                r.estado,
                ESTADOS.join(", ")
            ));
        }
        if r.nivel > 3 {
            problemas.push(format!("«{}»: nivel {} (0 a 3)", r.requisito, r.nivel));
        }
        if r.estado == "cumple" && r.evidencia.is_empty() {
            problemas.push(format!(
                "«{}» dice que cumple sin evidencia: un control que no se puede senalar no existe",
                r.requisito
            ));
        }
        for e in &r.evidencia {
            if let Err(err) = e.comprobar(&repo.raiz) {
                problemas.push(format!("«{}»: {err}", r.requisito));
            }
        }
        if let Some(d) = &r.desmiente {
            if r.estado != "cumple" && repo.raiz.join(d).exists() {
                problemas.push(format!(
                    "«{}» dice «{}», pero {d} existe: revisa el estado",
                    r.requisito, r.estado
                ));
            }
        }
    }
    if !problemas.is_empty() {
        return Err(format!(
            "tools/config/auditoria.toml [[slsa]]:\n    {}",
            problemas.join("\n    ")
        )
        .into());
    }
    let mut nivel = 0u8;
    for n in 1..=3u8 {
        let del_nivel: Vec<&RequisitoSlsa> = aud.slsa.iter().filter(|r| r.nivel == n).collect();
        if del_nivel.is_empty() || del_nivel.iter().any(|r| r.estado != "cumple") {
            break;
        }
        nivel = n;
    }
    let pendientes = aud
        .slsa
        .iter()
        .filter(|r| r.nivel == nivel + 1 && r.estado != "cumple")
        .map(|r| format!("{} ({})", r.requisito, r.estado))
        .collect();
    Ok((nivel, pendientes))
}

fn frase_nivel(nivel: u8, pendientes: &[String]) -> String {
    let alcanzado = if nivel == 0 {
        "**ninguno completo**".to_string()
    } else {
        format!("**L{nivel}**")
    };
    let mut s = format!("Nivel SLSA alcanzado (v1.0, pista Build): {alcanzado}.");
    if nivel < 3 && !pendientes.is_empty() {
        let _ = write!(s, " Para L{} falta: {}.", nivel + 1, pendientes.join("; "));
    }
    s
}

fn slsa(aud: &Auditoria, nivel: u8, pendientes: &[String]) -> String {
    let mut s = cabecera("Nivel SLSA declarado");
    let _ = writeln!(s, "{}\n", frase_nivel(nivel, pendientes));
    s.push_str(
        "El nivel no se escribe: se calcula con los requisitos de abajo. Un requisito solo \
         cumple si su evidencia existe en el repositorio, y un «no» que un fichero del \
         repositorio desmiente hace fallar la generacion.\n\n",
    );
    let fila = |s: &mut String, r: &RequisitoSlsa| {
        let estado = match r.estado.as_str() {
            "cumple" => "**cumple**".to_string(),
            "no" => "**no**".to_string(),
            otro => otro.to_string(),
        };
        let ev: Vec<String> = r.evidencia.iter().map(|e| enlace(&e.fichero)).collect();
        let _ = writeln!(
            s,
            "| {} | {} | {estado} | {} | {} |",
            if r.nivel == 0 {
                "—".to_string()
            } else {
                format!("L{}", r.nivel)
            },
            celda(&r.requisito),
            if ev.is_empty() {
                "—".to_string()
            } else {
                ev.join(", ")
            },
            celda(&r.detalle)
        );
    };
    s.push_str(
        "## Requisitos de la pista Build\n\n\
         | Nivel | Requisito | Estado | Evidencia | Detalle |\n|---|---|---|---|---|\n",
    );
    for r in aud.slsa.iter().filter(|r| r.nivel > 0) {
        fila(&mut s, r);
    }
    s.push_str(
        "\n## Garantias complementarias\n\n\
         No son niveles SLSA, pero un auditor las pide junto a ellos.\n\n\
         | Nivel | Garantia | Estado | Evidencia | Detalle |\n|---|---|---|---|---|\n",
    );
    for r in aud.slsa.iter().filter(|r| r.nivel == 0) {
        fila(&mut s, r);
    }
    let _ = writeln!(
        s,
        "\n## Donde corre el constructor\n\n{}",
        aud.textos.constructor.trim()
    );
    s
}

// ── Indice ──────────────────────────────────────────────────────────────────

/// Los campos que el build hermetico escribe en `MANIFIESTO.txt`, leidos del
/// propio guion para que el indice no pueda desfasarse de el.
fn campos_del_manifiesto(repo: &Repo) -> Resultado<Vec<String>> {
    const GUION: &str = "tools/ci/hermetico.sh";
    let t = std::fs::read_to_string(repo.raiz.join(GUION)).map_err(|e| format!("{GUION}: {e}"))?;
    let mut campos = Vec::new();
    let mut dentro = false;
    for l in t.lines() {
        if !dentro {
            dentro = l.contains("MANIFIESTO.txt\" <<MAN");
            continue;
        }
        if l.trim() == "MAN" {
            break;
        }
        if let Some((k, _)) = l.split_once(" : ") {
            campos.push(k.trim().to_string());
        }
    }
    for marca in ["> SHA256SUMS", "/HUELLA\""] {
        if !t.contains(marca) {
            return Err(format!(
                "{GUION} ya no escribe «{marca}»: el indice de auditoria describe una procedencia que no existe"
            )
            .into());
        }
    }
    if campos.is_empty() {
        return Err(format!(
            "{GUION}: no se encontro el manifiesto (<<MAN): el indice no sabe que registra el build"
        )
        .into());
    }
    Ok(campos)
}

fn indice(
    repo: &Repo,
    m: &Matriz,
    sboms: &[Sbom],
    aud: &Auditoria,
    nivel: u8,
    pendientes: &[String],
) -> Resultado<String> {
    let mut s = cabecera("Paquete para auditoria externa");
    let _ = writeln!(s, "{}\n", aud.textos.introduccion.trim());

    // Contenido.
    s.push_str(
        "## Contenido\n\n| Pieza | Donde | Como se obtiene | Puerta en `make ci` |\n|---|---|---|---|\n",
    );
    let _ = writeln!(
        s,
        "| Modelo de amenazas | {} | Escrito a mano; su estructura y sus evidencias se comprueban | `cargo xtask amenazas` (grupo `arquitectura`) |",
        enlace(crate::amenazas::MODELO)
    );
    let _ = writeln!(
        s,
        "| Arquitectura | [capas](#arquitectura) y diagrama del [README]({A_RAIZ}README.md) | `cargo metadata` y {} | `cargo xtask capas` (grupo `arquitectura`) |",
        enlace("tools/config/capas.toml")
    );
    let _ = writeln!(
        s,
        "| Matriz de capacidades | {} | Binarios compilados, pruebas e2e de la matriz de kernels y medidas | `cargo xtask docs --comprobar` (grupo `documentacion`) |",
        enlace(crate::docs::MATRIZ)
    );
    s.push_str(
        "| SBOM (CycloneDX 1.5) | [sbom/](sbom/) | `Cargo.lock` y `cargo tree --locked` | `cargo xtask sbom --comprobar` (grupo `auditoria`) y `docs --comprobar` |\n\
         | SBOM con el hash de cada binario y procedencia del build | `dist-hermetico/sbom/` y `dist-hermetico/procedencia.intoto.json` | El build hermetico de la misma tanda | `cargo xtask sbom --dist dist-hermetico` (grupo `auditoria`) |\n\
         | Nivel SLSA | [slsa.md](slsa.md) | Requisitos con evidencia comprobada | `cargo xtask docs --comprobar` |\n\
         | Alcance del pentest | [alcance-pentest.md](alcance-pentest.md) | Puntos de entrada extraidos del codigo | `cargo xtask docs --comprobar` |\n\n",
    );

    // Modelo de amenazas.
    let modelo = std::fs::read_to_string(repo.raiz.join(crate::amenazas::MODELO))
        .map_err(|e| format!("{}: {e}", crate::amenazas::MODELO))?;
    let version = modelo
        .lines()
        .find_map(|l| {
            l.split_once("**Versi\u{f3}n ")
                .map(|(_, r)| r.split("**").next().unwrap_or_default().trim().to_string())
        })
        .unwrap_or_else(|| "sin version declarada".into());
    let filas = crate::amenazas::comprobar(repo)?;
    let _ = writeln!(
        s,
        "## Modelo de amenazas\n\n{} (version {version}): {}.\n",
        enlace(crate::amenazas::MODELO),
        filas.trim_start_matches("amenazas: ")
    );

    // Arquitectura.
    let capas: Capas = config::leer(&repo.raiz, "capas.toml")?;
    s.push_str(
        "## Arquitectura\n\nUna dependencia solo puede bajar de capa; la lista de excepciones \
         solo puede menguar. Detalle y excepciones en la [matriz de capacidades]",
    );
    let _ = writeln!(
        s,
        "({A_RAIZ}{}#excepciones-de-arquitectura).\n\n| Capa | Crates | Cuales |\n|---|---:|---|",
        crate::docs::MATRIZ
    );
    for (nombre, l) in [
        ("nucleo", &capas.nucleo),
        ("plataforma", &capas.plataforma),
        ("motores", &capas.motores),
        ("E/S", &capas.es),
        ("herramientas (no se instalan)", &capas.herramientas),
    ] {
        let mut v: Vec<String> = l.crates.iter().map(|c| format!("`{c}`")).collect();
        v.sort();
        let _ = writeln!(s, "| {nombre} | {} | {} |", v.len(), v.join(", "));
    }
    let _ = writeln!(
        s,
        "\nExcepciones conocidas, con causa y plan: {}.\n",
        capas.excepcion.len()
    );

    // Matriz.
    s.push_str("## Matriz de capacidades\n\n");
    s.push_str(&crate::docs::bloque_estado(m).replace(
        "(docs/matriz-capacidades.md)",
        &format!("({A_RAIZ}{})", crate::docs::MATRIZ),
    ));
    s.push('\n');

    // SBOM.
    s.push_str(
        "## SBOM\n\nUn CycloneDX 1.5 JSON por instalable. «En ejecucion» es lo que llega al \
         binario; «solo al compilar», las dependencias de `build.rs` y las macros \
         procedurales con lo que solo ellas usan (`scope: excluded`).\n\n\
         | Instalable | SBOM | Objetivo | Caracteristicas | En ejecucion | Solo al compilar | Licencias distintas | Incrustados | C incluido | Sistema |\n\
         |---|---|---|---|---:|---:|---:|---:|---:|---:|\n",
    );
    for x in sboms {
        let nombre = format!("{}.cdx.json", x.instalable.binario);
        let _ = writeln!(
            s,
            "| `{}` | [`{nombre}`](sbom/{nombre}) | `{}` | {} | {} | {} | {} | {} | {} | {} |",
            x.instalable.binario,
            x.objetivo,
            if x.caracteristicas.is_empty() {
                "—".to_string()
            } else {
                x.caracteristicas
                    .iter()
                    .map(|c| format!("`{c}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            },
            x.en_ejecucion(),
            x.de_construccion(),
            x.licencias().len(),
            x.incrustados.len(),
            x.vendorizados.len(),
            x.sistema.len()
        );
    }
    let mut por_licencia: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for x in sboms {
        por_licencia
            .entry(x.raiz.licencia.clone())
            .or_default()
            .insert(x.raiz.referencia());
        for (r, c) in &x.componentes {
            por_licencia
                .entry(c.licencia.clone())
                .or_default()
                .insert(r.clone());
        }
    }
    s.push_str(
        "\n**Licencias de los crates** (todos los instalables, cada crate una vez). La politica \
         la aplica `cargo-deny` (grupo `cadena`); el codigo C incluido en un crate no lo ve, y \
         por eso va aparte:\n\n| Licencia (SPDX) | Crates |\n|---|---:|\n",
    );
    for (l, v) in &por_licencia {
        let _ = writeln!(s, "| `{l}` | {} |", v.len());
    }
    let mut vistos = BTreeSet::new();
    let mut incluidos = String::new();
    for x in sboms {
        for v in &x.vendorizados {
            if vistos.insert((v.krate.clone(), v.nombre.clone())) {
                let _ = writeln!(
                    incluidos,
                    "| {} | `{}` | `{}` | {} |",
                    v.nombre,
                    v.krate,
                    v.licencia,
                    celda(&v.nota)
                );
            }
        }
    }
    if !incluidos.is_empty() {
        s.push_str(
            "\n**Codigo C incluido en crates** (licencia declarada por el proyecto de origen, \
             fuera de `cargo-deny`):\n\n| Componente | Dentro de | Licencia | Nota |\n|---|---|---|---|\n",
        );
        s.push_str(&incluidos);
    }
    s.push_str("\n**Limites conocidos del SBOM**\n\n");
    lista(&mut s, &aud.textos.limitaciones_sbom);

    // Procedencia.
    let campos = campos_del_manifiesto(repo)?;
    let _ = writeln!(
        s,
        "## Procedencia del build\n\n{}\n",
        aud.textos.procedencia.trim()
    );
    s.push_str(
        "| Fichero en `dist-hermetico/` | Que es | Lo escribe |\n|---|---|---|\n\
         | `SHA256SUMS` | SHA-256 de cada binario hermetico | `tools/ci/hermetico.sh` |\n\
         | `HUELLA` | Huella del arbol del que salen (commit, cambios y ficheros sin seguir) | `tools/ci/hermetico.sh` con `tools/huella-arbol.sh` |\n",
    );
    let _ = writeln!(
        s,
        "| `MANIFIESTO.txt` | Campos: {} | `tools/ci/hermetico.sh` |",
        campos
            .iter()
            .map(|c| format!("`{c}`"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    s.push_str(
        "| `sbom/<binario>.cdx.json` | El SBOM versionado mas el SHA-256 del binario, el commit y la huella | `cargo xtask sbom --dist` |\n\
         | `procedencia.intoto.json` | Declaracion in-toto v1 con predicado SLSA v1, **sin firmar** | `cargo xtask sbom --dist` |\n\n",
    );

    // SLSA y alcance.
    let _ = writeln!(
        s,
        "## Nivel SLSA\n\n{} Detalle y evidencias: [slsa.md](slsa.md).\n",
        frase_nivel(nivel, pendientes)
    );
    let _ = writeln!(
        s,
        "## Alcance del pentest\n\nSuperficies: {}. Detalle: [alcance-pentest.md](alcance-pentest.md).",
        aud.superficie
            .iter()
            .map(|x| format!("[{}](alcance-pentest.md#{})", x.nombre, x.id))
            .collect::<Vec<_>>()
            .join(", ")
    );
    Ok(s)
}

// ── Alcance del pentest ─────────────────────────────────────────────────────

/// Un punto de entrada sacado del codigo.
#[derive(Debug, PartialEq)]
struct Punto {
    nombre: String,
    detalle: String,
    linea: usize,
    /// Pide atencion: una ruta que se sirve sin sesion o que no tiene fila en
    /// la tabla RBAC, un analizador sin objetivo de fuzzing.
    alerta: bool,
}

/// Nombres de los objetivos de fuzzing (`[[bin]]`) de los dos manifiestos.
fn objetivos_fuzz(repo: &Repo) -> Resultado<Vec<String>> {
    let mut objetivos = Vec::new();
    for manifiesto in FUZZ {
        let t = std::fs::read_to_string(repo.raiz.join(manifiesto))
            .map_err(|e| format!("{manifiesto}: {e}"))?;
        let v: toml::Value = toml::from_str(&t).map_err(|e| format!("{manifiesto}: {e}"))?;
        objetivos.extend(
            v.get("bin")
                .and_then(|b| b.as_array())
                .into_iter()
                .flatten()
                .filter_map(|b| b.get("name").and_then(|n| n.as_str()).map(str::to_string)),
        );
    }
    Ok(objetivos)
}

fn alcance(repo: &Repo, m: &Matriz, aud: &Auditoria) -> Resultado<String> {
    let fuzz = objetivos_fuzz(repo)?;
    let mut s = cabecera("Alcance propuesto del pentest");
    let _ = writeln!(s, "{}\n", aud.textos.alcance_introduccion.trim());

    let mut resumen = String::from(
        "## Resumen\n\n| Superficie | Puntos de entrada | Piden atencion | Crates | Crates que ejecuta un instalable | Objetivos de fuzzing |\n\
         |---|---:|---:|---:|---:|---:|\n",
    );
    let mut detalle = String::new();
    for sup in &aud.superficie {
        // Los crates, con su estado real en la matriz.
        let mut filas = String::new();
        let mut invocados = 0;
        for c in &sup.crates {
            let f = m
                .filas
                .iter()
                .find(|f| f.paquete.nombre == *c)
                .ok_or_else(|| {
                    format!(
                        "auditoria.toml: la superficie {} cita el crate {c}, que no existe",
                        sup.id
                    )
                })?;
            if !f.invocado_por.is_empty() {
                invocados += 1;
            }
            let por: Vec<String> = f.invocado_por.iter().map(|b| format!("`{b}`")).collect();
            let _ = writeln!(
                filas,
                "| `{c}` | {} | {} |",
                f.estado.nombre(),
                if por.is_empty() {
                    "ningun instalable".to_string()
                } else {
                    por.join(", ")
                }
            );
        }

        // Los puntos de entrada.
        let objetivos: Vec<&String> = fuzz
            .iter()
            .filter(|o| sup.fuzz.iter().any(|p| o.starts_with(p.as_str())))
            .collect();
        let mut tablas = String::new();
        let mut total = 0;
        let mut alertas = 0;
        for e in &sup.extractor {
            let puntos = extraer(repo, e, &fuzz)?;
            total += puntos.len();
            alertas += puntos.iter().filter(|p| p.alerta).count();
            let _ = writeln!(
                tablas,
                "#### {} — {}\n\n| Punto de entrada | Detalle | Linea |\n|---|---|---|",
                e.titulo,
                enlace(&e.fichero)
            );
            for p in &puntos {
                let _ = writeln!(
                    tablas,
                    "| `{}` | {}{} | [{}]({A_RAIZ}{}#L{}) |",
                    celda(&p.nombre),
                    if p.alerta { "**atencion** · " } else { "" },
                    celda(&p.detalle),
                    p.linea,
                    e.fichero,
                    p.linea
                );
            }
            tablas.push('\n');
        }

        let _ = writeln!(
            resumen,
            "| [{}](#{}) | {total} | {alertas} | {} | {invocados} | {} |",
            sup.nombre,
            sup.id,
            sup.crates.len(),
            objetivos.len()
        );

        let _ = writeln!(
            detalle,
            "<a id=\"{}\"></a>\n\n## {}\n\n{}\n\n### Crates\n\n| Crate | Estado | Invocado por |\n|---|---|---|\n{filas}",
            sup.id,
            sup.nombre,
            sup.descripcion.trim()
        );
        let _ = writeln!(
            detalle,
            "### Puntos de entrada, extraidos del codigo\n\n{tablas}"
        );
        let _ = writeln!(
            detalle,
            "### Objetivos de fuzzing\n\n{}\n",
            if objetivos.is_empty() {
                "**Ninguno.** Esta superficie no tiene objetivo en `fuzz/` ni en `server/fuzz/`."
                    .to_string()
            } else {
                objetivos
                    .iter()
                    .map(|o| format!("`{o}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        );
        detalle.push_str("### Ataques minimos propuestos\n\n");
        lista(&mut detalle, &sup.ataques);
        if !sup.fuera.is_empty() {
            detalle.push_str("### Fuera de alcance en esta superficie\n\n");
            lista(&mut detalle, &sup.fuera);
        }
    }
    s.push_str(&resumen);
    s.push('\n');
    s.push_str(&detalle);

    let t = &aud.textos;
    s.push_str("## Reglas de enfrentamiento\n\n");
    lista(&mut s, &t.reglas);
    s.push_str("## Fuera de alcance\n\n");
    lista(&mut s, &t.fuera_de_alcance);
    let _ = writeln!(
        s,
        "## Ventanas y contacto\n\n{}\n",
        t.ventanas_y_contacto.trim()
    );
    s.push_str("## Criterios de cierre\n\n");
    lista(&mut s, &t.criterios_de_cierre);
    Ok(s)
}

// ── Extractores ─────────────────────────────────────────────────────────────

fn extraer(repo: &Repo, e: &Extractor, fuzz: &[String]) -> Resultado<Vec<Punto>> {
    let texto = std::fs::read_to_string(repo.raiz.join(&e.fichero))
        .map_err(|err| format!("auditoria.toml: {}: {err}", e.fichero))?;
    let v = match e.tipo.as_str() {
        "variantes" => {
            let nombre = e.nombre.as_deref().ok_or_else(|| {
                format!("auditoria.toml: {}: `variantes` exige `nombre`", e.fichero)
            })?;
            let mut v = variantes(&texto, nombre, e.omitir_atributo.as_deref());
            if let Some(prefijo) = &e.fuzz_prefijo {
                for p in &mut v {
                    let objetivo = format!("{prefijo}{}", p.nombre.to_lowercase());
                    if fuzz.contains(&objetivo) {
                        p.detalle = format!("{} · fuzzing: `{objetivo}`", p.detalle);
                    } else {
                        p.detalle =
                            format!("{} · **sin objetivo de fuzzing** `{objetivo}`", p.detalle);
                        p.alerta = true;
                    }
                }
            }
            v
        }
        "constantes" => constantes(&texto, &e.nombres)
            .map_err(|err| format!("auditoria.toml: {}: {err}", e.fichero))?,
        "rutas" => {
            let publicas = match &e.publicas {
                Some(c) => Some(pares_de_constante(&texto, c).ok_or_else(|| {
                    format!(
                        "auditoria.toml: {}: no se encontro `const {c}` con pares (metodo, ruta)",
                        e.fichero
                    )
                })?),
                None => None,
            };
            let reglas = match &e.reglas {
                Some(f) => {
                    let t = std::fs::read_to_string(repo.raiz.join(f))
                        .map_err(|err| format!("auditoria.toml: {f}: {err}"))?;
                    let r = tabla_rbac(&t);
                    if r.is_empty() {
                        return Err(format!(
                            "auditoria.toml: {f}: no se encontro la tabla RBAC (`const REGLAS`)"
                        )
                        .into());
                    }
                    Some(r)
                }
                None => None,
            };
            rutas(&texto, &e.marcas, publicas.as_deref(), reglas.as_ref())
        }
        "rpc" => rpc(&texto),
        "funciones" => funciones(&texto),
        otro => {
            return Err(format!(
                "auditoria.toml: {}: tipo de extractor desconocido «{otro}»",
                e.fichero
            )
            .into())
        }
    };
    if v.is_empty() {
        return Err(format!(
            "auditoria.toml: el extractor «{}» no encontro nada en {}: el codigo cambio y el \
             alcance del pentest ya no lo describe",
            e.titulo, e.fichero
        )
        .into());
    }
    Ok(v)
}

fn llaves(t: &str) -> i32 {
    t.chars()
        .map(|c| match c {
            '{' => 1,
            '}' => -1,
            _ => 0,
        })
        .sum()
}

/// Variantes de `pub enum <nombre>`, con su comentario de documentacion.
fn variantes(texto: &str, nombre: &str, omitir: Option<&str>) -> Vec<Punto> {
    let lineas: Vec<&str> = texto.lines().collect();
    let cabecera = format!("pub enum {nombre}");
    let Some(ini) = lineas.iter().position(|l| {
        l.trim_start()
            .strip_prefix(cabecera.as_str())
            .is_some_and(|r| r.starts_with(' ') || r.starts_with('{') || r.starts_with('<'))
    }) else {
        return Vec::new();
    };
    let mut v = Vec::new();
    let mut prof = llaves(lineas[ini]);
    let mut doc: Vec<String> = Vec::new();
    let mut atributos: Vec<String> = Vec::new();
    for (i, l) in lineas.iter().enumerate().skip(ini + 1) {
        if prof <= 0 {
            break;
        }
        let t = l.trim();
        if prof == 1 {
            if let Some(d) = t.strip_prefix("///") {
                if !d.trim().is_empty() {
                    doc.push(d.trim().to_string());
                }
                continue;
            }
            if t.starts_with("#[") {
                atributos.push(t.to_string());
                continue;
            }
            if t.chars().next().is_some_and(|c| c.is_ascii_uppercase()) {
                let ident: String = t
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                let fuera = omitir.is_some_and(|o| atributos.iter().any(|a| a.contains(o)));
                if !fuera {
                    v.push(Punto {
                        nombre: ident,
                        detalle: doc.join(" "),
                        linea: i + 1,
                        alerta: false,
                    });
                }
                doc.clear();
                atributos.clear();
            }
        }
        if !t.starts_with("//") {
            prof += llaves(t);
        }
    }
    v
}

/// `const NOMBRE: T = valor;` de cada nombre pedido. Falta uno: error.
fn constantes(texto: &str, nombres: &[String]) -> Resultado<Vec<Punto>> {
    let mut v = Vec::new();
    for n in nombres {
        let encontrada = texto.lines().enumerate().find_map(|(i, l)| {
            let t = l.trim_start();
            let t = t
                .strip_prefix("pub(crate) ")
                .or_else(|| t.strip_prefix("pub "))
                .unwrap_or(t);
            let resto = t.strip_prefix("const ")?.strip_prefix(n.as_str())?;
            let (_, valor) = resto.strip_prefix(':')?.split_once('=')?;
            let valor = valor.trim().trim_end_matches(';').trim();
            Some(Punto {
                nombre: n.clone(),
                detalle: if valor.is_empty() {
                    "(ver el codigo)".to_string()
                } else {
                    format!("`{valor}`")
                },
                linea: i + 1,
                alerta: false,
            })
        });
        match encontrada {
            Some(p) => v.push(p),
            None => return Err(format!("la constante {n} ya no existe").into()),
        }
    }
    Ok(v)
}

/// El cuerpo de una llamada: desde justo despues de su `(` hasta el `)` que la
/// cierra, sin contar los parentesis de dentro de las cadenas.
fn llamada(resto: &str) -> &str {
    let mut prof = 1i32;
    let mut en_cadena = false;
    for (i, c) in resto.char_indices() {
        match c {
            '"' => en_cadena = !en_cadena,
            '(' if !en_cadena => prof += 1,
            ')' if !en_cadena => {
                prof -= 1;
                if prof == 0 {
                    return &resto[..i];
                }
            }
            _ => {}
        }
    }
    resto
}

/// `get(manejador)`, `post(...)`... dentro de la declaracion de una ruta.
fn metodos_de(cuerpo: &str) -> Vec<(String, String)> {
    let mut v: Vec<(usize, String, String)> = Vec::new();
    for m in METODOS {
        let patron = format!("{m}(");
        for (i, _) in cuerpo.match_indices(patron.as_str()) {
            let previo = cuerpo[..i].chars().next_back();
            if previo.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
                continue;
            }
            let manejador: String = cuerpo[i + patron.len()..]
                .trim_start()
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            v.push((i, m.to_uppercase(), manejador));
        }
    }
    v.sort();
    v.into_iter().map(|(_, m, h)| (m, h)).collect()
}

/// Permiso y alcance de cada (metodo, patron) de la tabla RBAC.
type Reglas = BTreeMap<(String, String), (String, String)>;

/// Los literales de cadena de un trozo de codigo, en orden.
fn literales(t: &str) -> Vec<String> {
    let mut v = Vec::new();
    let mut resto = t;
    while let Some(i) = resto.find('"') {
        let tras = &resto[i + 1..];
        let Some(f) = tras.find('"') else {
            break;
        };
        v.push(tras[..f].to_string());
        resto = &tras[f + 1..];
    }
    v
}

/// `const NOMBRE: &[(&str, &str)] = &[("GET", "/salud"), ...];`: sus pares.
/// `None` si la constante no esta o lo que lista no son pares.
fn pares_de_constante(texto: &str, nombre: &str) -> Option<Vec<(String, String)>> {
    let ini = texto.find(&format!("const {nombre}:"))?;
    let cuerpo = &texto[ini..];
    let igual = cuerpo.find('=')?;
    let fin = igual + cuerpo[igual..].find(';')?;
    let l = literales(&cuerpo[igual..fin]);
    if l.is_empty() || l.len() % 2 != 0 {
        return None;
    }
    Some(l.chunks(2).map(|p| (p[0].clone(), p[1].clone())).collect())
}

/// La tabla RBAC: cada `r("METODO", "/patron", Some(P::Permiso), A::Alcance)`
/// (o `None` sin permiso) de `const REGLAS`. Vacia si no la encuentra.
fn tabla_rbac(texto: &str) -> Reglas {
    let mut m = Reglas::new();
    let Some(ini) = texto.find("const REGLAS:") else {
        return m;
    };
    let cuerpo = &texto[ini..];
    let cuerpo = &cuerpo[..cuerpo.find("\n];").unwrap_or(cuerpo.len())];
    for (i, _) in cuerpo.match_indices("r(") {
        let previo = cuerpo[..i].chars().next_back();
        if previo.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        let args: Vec<&str> = llamada(&cuerpo[i + 2..])
            .split(',')
            .map(str::trim)
            .filter(|a| !a.is_empty())
            .collect();
        let [metodo, patron, permiso, alcance] = args[..] else {
            continue;
        };
        let ultimo = |s: &str| s.rsplit("::").next().unwrap_or(s).to_string();
        let permiso = permiso
            .strip_prefix("Some(")
            .and_then(|p| p.strip_suffix(')'))
            .map_or_else(|| "ninguno".to_string(), ultimo);
        m.insert(
            (
                metodo.trim_matches('"').to_string(),
                patron.trim_matches('"').to_string(),
            ),
            (permiso, ultimo(alcance)),
        );
    }
    m
}

/// Rutas HTTP: la marca (`.ruta(`, `.route(`), el patron literal y sus metodos
/// con su manejador. Con `publicas`, las que se sirven sin sesion piden
/// atencion; con `reglas`, cada metodo lleva el permiso y el alcance de su fila
/// RBAC, y el que no tiene fila pide atencion (la API lo deniega: falla
/// cerrada, pero es una ruta que nadie clasifico).
fn rutas(
    texto: &str,
    marcas: &[String],
    publicas: Option<&[(String, String)]>,
    reglas: Option<&Reglas>,
) -> Vec<Punto> {
    let mut v = Vec::new();
    for marca in marcas {
        for (pos, _) in texto.match_indices(marca.as_str()) {
            let ini_linea = texto[..pos].rfind('\n').map_or(0, |i| i + 1);
            if texto[ini_linea..pos].trim_start().starts_with("//") {
                continue;
            }
            let resto = &texto[pos + marca.len()..];
            let Some(literal) = resto.trim_start().strip_prefix('"') else {
                continue;
            };
            let Some(fin) = literal.find('"') else {
                continue;
            };
            let patron = literal[..fin].to_string();
            let mut partes = Vec::new();
            let mut alerta = false;
            for (metodo, manejador) in metodos_de(llamada(resto)) {
                let mut parte = if manejador.is_empty() {
                    format!("`{metodo}` (cierre en linea)")
                } else {
                    format!("`{metodo}` → `{manejador}`")
                };
                let clave = (metodo, patron.clone());
                if publicas.is_some_and(|p| p.contains(&clave)) {
                    alerta = true;
                    parte.push_str(" (**sin sesion**: `RUTAS_PUBLICAS`)");
                } else if let Some(r) = reglas {
                    match r.get(&clave) {
                        Some((permiso, alcance)) => {
                            let _ = write!(parte, " · permiso `{permiso}` · alcance `{alcance}`");
                        }
                        None => {
                            alerta = true;
                            parte.push_str(" (**sin fila en la tabla RBAC**: se deniega)");
                        }
                    }
                }
                partes.push(parte);
            }
            v.push(Punto {
                nombre: patron,
                detalle: partes.join("; "),
                linea: texto[..pos].matches('\n').count() + 1,
                alerta,
            });
        }
    }
    v.sort_by_key(|p| p.linea);
    v
}

/// `rpc Nombre(Peticion) returns (Respuesta);` de un `.proto`.
fn rpc(texto: &str) -> Vec<Punto> {
    texto
        .lines()
        .enumerate()
        .filter_map(|(i, l)| {
            let t = l.trim().strip_prefix("rpc ")?;
            let (nombre, resto) = t.split_once('(')?;
            Some(Punto {
                nombre: nombre.trim().to_string(),
                detalle: format!("({}", resto.trim().trim_end_matches(';').trim()),
                linea: i + 1,
                alerta: false,
            })
        })
        .collect()
}

/// Funciones publicas (fuera de las pruebas), con la primera linea de su doc.
fn funciones(texto: &str) -> Vec<Punto> {
    let mut v = Vec::new();
    let mut doc: Vec<String> = Vec::new();
    for (i, l) in texto.lines().enumerate() {
        let t = l.trim();
        if t.starts_with("#[cfg(test)]") {
            break;
        }
        if let Some(d) = t.strip_prefix("///") {
            doc.push(d.trim().to_string());
            continue;
        }
        if let Some(f) = t
            .strip_prefix("pub async fn ")
            .or_else(|| t.strip_prefix("pub fn "))
        {
            let nombre: String = f
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            v.push(Punto {
                nombre,
                detalle: doc.first().cloned().unwrap_or_default(),
                linea: i + 1,
                alerta: false,
            });
        }
        if !t.starts_with("#[") {
            doc.clear();
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variantes_con_doc_campos_y_cfg_de_prueba() {
        let t = "/// x\npub enum Peticion {\n    /// Estado.\n    Status,\n    /// Escaneo.\n    Scan {\n        /// Ruta.\n        path: String,\n    },\n    #[cfg(feature = \"prueba-fallos\")]\n    Panico,\n    QuarantineList,\n}\n\nimpl Peticion {}\n";
        let v = variantes(t, "Peticion", Some("prueba-fallos"));
        let nombres: Vec<&str> = v.iter().map(|p| p.nombre.as_str()).collect();
        assert_eq!(nombres, vec!["Status", "Scan", "QuarantineList"]);
        assert_eq!(v[0].detalle, "Estado.");
        assert_eq!(v[0].linea, 4);
        assert!(variantes(t, "Otra", None).is_empty());
    }

    #[test]
    fn rutas_con_publicas_y_tabla_rbac() {
        let t = "pub const RUTAS_PUBLICAS: &[(&str, &str)] = &[(\"GET\", \"/salud\")];\n\
                 \n\
                 fn declarar() -> D {\n    \
                 D::nueva()\n    \
                 .ruta(\"/salud\", &[\"GET\"], get(salud))\n    \
                 .ruta(\n        \"/api/x\",\n        &[\"GET\", \"POST\"],\n        get(listar).post(crear),\n    )\n    \
                 // .ruta(\"/comentada\", &[\"GET\"], get(nada))\n    \
                 .ruta(\"/api/y/{id}\", &[\"DELETE\"], axum::routing::delete(borrar))\n\
                 }\n";
        let tabla = "const fn r(m: &str) {}\n\
                     pub const REGLAS: &[Regla] = &[\n    \
                     r(\"GET\", \"/salud\", None, A::Publica),\n    \
                     // Inventario (por inquilino)\n    \
                     r(\"GET\", \"/api/x\", Some(P::Leer), A::Inquilino),\n    \
                     r(\n        \"DELETE\",\n        \"/api/y/{id}\",\n        Some(P::GestionarDeteccion),\n        A::Plataforma,\n    ),\n\
                     ];\n";
        let publicas = pares_de_constante(t, "RUTAS_PUBLICAS").unwrap();
        assert_eq!(publicas, vec![("GET".to_string(), "/salud".to_string())]);
        let reglas = tabla_rbac(tabla);
        assert_eq!(reglas.len(), 3);
        assert_eq!(
            reglas[&("DELETE".to_string(), "/api/y/{id}".to_string())],
            ("GestionarDeteccion".to_string(), "Plataforma".to_string())
        );
        assert_eq!(
            reglas[&("GET".to_string(), "/salud".to_string())],
            ("ninguno".to_string(), "Publica".to_string())
        );

        let v = rutas(
            t,
            &[".ruta(".to_string()],
            Some(publicas.as_slice()),
            Some(&reglas),
        );
        let nombres: Vec<&str> = v.iter().map(|p| p.nombre.as_str()).collect();
        assert_eq!(nombres, vec!["/salud", "/api/x", "/api/y/{id}"]);
        assert!(v[0].alerta, "/salud se sirve sin sesion");
        assert!(v[0].detalle.contains("**sin sesion**"));
        assert!(v[1].alerta, "POST /api/x no tiene fila RBAC");
        assert!(v[1]
            .detalle
            .contains("`GET` → `listar` · permiso `Leer` · alcance `Inquilino`"));
        assert!(v[1]
            .detalle
            .contains("`POST` → `crear` (**sin fila en la tabla RBAC**"));
        assert!(!v[2].alerta);
        assert!(v[2]
            .detalle
            .contains("`DELETE` → `borrar` · permiso `GestionarDeteccion`"));
        assert_eq!(v[1].linea, 6);
        assert!(pares_de_constante(t, "OTRA").is_none());
        assert!(tabla_rbac("nada").is_empty());

        let panel = "Router::new()\n    \
                     .route(\"/\", get(|| async { R::permanent(\"/panel/\") }))\n    \
                     .route(\"/panel/\", get(indice))\n";
        let p = rutas(panel, &[".route(".to_string()], None, None);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].detalle, "`GET` (cierre en linea)");
        assert_eq!(p[1].detalle, "`GET` → `indice`");
        assert!(!p[0].alerta && !p[1].alerta);
    }

    #[test]
    fn constantes_rpc_y_funciones() {
        let t = "pub const VERSION: u16 = 1;\nconst SOCKET: &str = \"/run/x.sock\";\npub const VERSION_X: u8 = 2;\n";
        let v = constantes(t, &["VERSION".to_string(), "SOCKET".to_string()]).unwrap();
        assert_eq!(v[0].detalle, "`1`");
        assert_eq!(v[1].detalle, "`\"/run/x.sock\"`");
        assert!(constantes(t, &["NADA".to_string()]).is_err());

        let p = rpc("service F {\n  rpc Enrolar(A) returns (B);\n}\n");
        assert_eq!(p[0].nombre, "Enrolar");
        assert_eq!(p[0].detalle, "(A) returns (B)");

        let f = funciones("/// Aplica.\n#[must_use]\npub fn apply(x: u8) {}\nfn privada() {}\n#[cfg(test)]\nmod t { pub fn no() {} }\n");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].nombre, "apply");
        assert_eq!(f[0].detalle, "Aplica.");
    }
}
