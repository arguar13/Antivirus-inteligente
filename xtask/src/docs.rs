//! Documentacion generada: `docs/matriz-capacidades.md` y `README.md`.
//!
//! El README se compone de una PLANTILLA (`docs/plantillas/README.md`), que es
//! prosa escrita a mano y se edita como cualquier Markdown, y de BLOQUES que se
//! generan desde el codigo. Un bloque se pide en la plantilla con una linea que
//! solo contiene su marcador:
//!
//! | Marcador                    | Que genera                                        |
//! |-----------------------------|---------------------------------------------------|
//! | `{{estado}}`                | resumen de la matriz de capacidades               |
//! | `{{cifras}}`                | recuentos del repositorio                         |
//! | `{{presupuesto}}`           | tabla de memoria calculada con aegis-presupuesto  |
//! | `{{c4}}`                    | diagrama C4 (Mermaid) con relaciones con evidencia|
//! | `{{instalables}}`           | ejecutables instalables y lo que invocan          |
//! | `{{componentes_agente}}`    | tabla de crates del agente                        |
//! | `{{componentes_servidor}}`  | tabla de crates del plano de control              |
//! | `{{documentacion}}`         | indice de `docs/`                                 |
//!
//! La prosa de la plantilla no puede llevar cifras escritas a mano (regla 3 del
//! proyecto): [`cifras_a_mano`] las busca y la generacion falla si encuentra una.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use aegis_presupuesto::Presupuesto;

use crate::config::{self, Documentacion, Instalables};
use crate::matriz::{Estado, Matriz};
use crate::repo::{self, Repo};
use crate::Resultado;

/// Plantilla del README.
pub const PLANTILLA: &str = "docs/plantillas/README.md";
/// Matriz de capacidades generada.
pub const MATRIZ: &str = "docs/matriz-capacidades.md";

/// Los documentos generados: (ruta relativa, contenido).
pub fn generar(repo: &Repo, m: &Matriz) -> Resultado<Vec<(PathBuf, String)>> {
    let doc: Documentacion = config::leer(&repo.raiz, "documentacion.toml")?;
    let inst: Instalables = config::leer(&repo.raiz, "instalables.toml")?;
    let plantilla = std::fs::read_to_string(repo.raiz.join(PLANTILLA))
        .map_err(|e| format!("{PLANTILLA}: {e}"))?;

    let cifras = cifras_a_mano(&plantilla);
    if !cifras.is_empty() {
        let mut msg = format!(
            "{PLANTILLA} tiene cifras escritas a mano (regla 3): se generan desde el codigo.\n"
        );
        for (linea, c) in cifras {
            let _ = writeln!(msg, "    linea {linea}: «{c}»");
        }
        return Err(msg.into());
    }

    let mut bloques: BTreeMap<&str, String> = BTreeMap::new();
    bloques.insert("estado", bloque_estado(m));
    bloques.insert("cifras", bloque_cifras(repo, m));
    bloques.insert("presupuesto", bloque_presupuesto(&doc));
    bloques.insert("c4", bloque_c4(repo, m, &doc, &inst)?);
    bloques.insert("instalables", bloque_instalables(m));
    bloques.insert("componentes_agente", bloque_componentes(repo, m, "agente"));
    bloques.insert(
        "componentes_servidor",
        bloque_componentes(repo, m, "servidor"),
    );
    bloques.insert("documentacion", bloque_documentacion(repo));

    let mut readme = String::from(
        "<!--\n  GENERADO por `cargo xtask docs`. NO SE EDITA AQUI.\n  \
         La prosa vive en docs/plantillas/README.md y los datos en tools/config/.\n-->\n\n",
    );
    for (n, linea) in plantilla.lines().enumerate() {
        let t = linea.trim();
        if let Some(nombre) = t.strip_prefix("{{").and_then(|x| x.strip_suffix("}}")) {
            let b = bloques
                .get(nombre.trim())
                .ok_or_else(|| format!("{PLANTILLA}:{}: marcador desconocido {t}", n + 1))?;
            readme.push_str(b);
        } else {
            readme.push_str(linea);
            readme.push('\n');
        }
    }

    Ok(vec![
        (PathBuf::from(MATRIZ), render_matriz(repo, m)),
        (PathBuf::from("README.md"), readme),
    ])
}

/// Escribe los documentos, o con `comprobar` solo compara y falla si divergen.
pub fn escribir(raiz: &Path, docs: &[(PathBuf, String)], comprobar: bool) -> Resultado<()> {
    let mut divergen = Vec::new();
    for (ruta, contenido) in docs {
        let abs = raiz.join(ruta);
        let actual = std::fs::read_to_string(&abs).unwrap_or_default();
        // Los finales de linea no son contenido: en Windows git puede entregar CRLF.
        if actual.replace("\r\n", "\n") == *contenido {
            continue;
        }
        if comprobar {
            let primera = actual
                .replace("\r\n", "\n")
                .lines()
                .zip(contenido.lines())
                .position(|(a, b)| a != b)
                .map(|i| i + 1)
                .unwrap_or_else(|| actual.lines().count().min(contenido.lines().count()) + 1);
            divergen.push(format!(
                "{} (primera diferencia en la linea {primera})",
                ruta.display()
            ));
        } else {
            if let Some(dir) = abs.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(&abs, contenido)?;
            eprintln!("xtask: escrito {}", ruta.display());
        }
    }
    if divergen.is_empty() {
        return Ok(());
    }
    Err(format!(
        "la documentacion generada no coincide con el codigo:\n    {}\n\
         Regenerala con `cargo xtask docs` y comitea el resultado. Si cambiaste la\n\
         prosa, edita docs/plantillas/README.md; si cambiaste datos, tools/config/.",
        divergen.join("\n    ")
    )
    .into())
}

// ── Cifras escritas a mano ──────────────────────────────────────────────────

/// Unidades que convierten un numero en una cifra del producto.
const UNIDADES: [&str; 26] = [
    "%",
    "mib",
    "gib",
    "kib",
    "mb",
    "gb",
    "kb",
    "ms",
    "µs",
    "us",
    "segundos",
    "minutos",
    "pruebas",
    "crates",
    "dependencias",
    "líneas",
    "lineas",
    "tablas",
    "verificadores",
    "invariantes",
    "agentes",
    "programas",
    "eventos",
    "categorías",
    "sondas",
    "fases",
];

/// Busca en la prosa (fuera de bloques de codigo, codigo en linea y enlaces)
/// numeros seguidos de una unidad: «45 MB», «22 MiB», «39 dependencias». Esas
/// cifras envejecen solas; las que importan se generan.
pub fn cifras_a_mano(texto: &str) -> Vec<(usize, String)> {
    let mut hallazgos = Vec::new();
    let mut en_bloque = false;
    for (n, linea) in texto.lines().enumerate() {
        if linea.trim_start().starts_with("```") {
            en_bloque = !en_bloque;
            continue;
        }
        if en_bloque || linea.trim_start().starts_with("<!--") {
            continue;
        }
        let limpia = quitar_codigo_y_enlaces(linea);
        let chars: Vec<char> = limpia.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            let empieza = chars[i].is_ascii_digit()
                && (i == 0 || !(chars[i - 1].is_alphanumeric() || chars[i - 1] == '-'));
            if !empieza {
                i += 1;
                continue;
            }
            let ini = i;
            while i < chars.len()
                && (chars[i].is_ascii_digit() || chars[i] == '.' || chars[i] == ',')
            {
                i += 1;
            }
            // Un numero pegado a letras es un identificador (Ed25519, x86-64).
            if i < chars.len() && (chars[i].is_alphanumeric() && chars[i] != 'µ' || chars[i] == '-')
            {
                continue;
            }
            let mut j = i;
            while j < chars.len() && chars[j] == ' ' {
                j += 1;
            }
            let palabra: String = chars[j..]
                .iter()
                .take_while(|c| c.is_alphanumeric() || **c == '%' || **c == 'µ')
                .collect::<String>()
                .to_lowercase();
            if !palabra.is_empty() && UNIDADES.contains(&palabra.as_str()) {
                let cifra: String = chars[ini..j + palabra.chars().count()].iter().collect();
                hallazgos.push((n + 1, cifra));
            }
        }
    }
    hallazgos
}

/// Borra el codigo en linea (`...`), los marcadores `{{...}}` y el destino de
/// los enlaces `](...)`, que no son prosa.
fn quitar_codigo_y_enlaces(linea: &str) -> String {
    let mut s = String::new();
    let mut en_codigo = false;
    let mut chars = linea.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '`' {
            en_codigo = !en_codigo;
            continue;
        }
        if en_codigo {
            continue;
        }
        if c == ']' && chars.peek() == Some(&'(') {
            for d in chars.by_ref() {
                if d == ')' {
                    break;
                }
            }
            continue;
        }
        s.push(c);
    }
    s
}

// ── Bloques ─────────────────────────────────────────────────────────────────

fn contar(m: &Matriz, ws: &str, e: Estado) -> usize {
    m.filas
        .iter()
        .filter(|f| f.paquete.workspace == ws && f.estado == e)
        .count()
}

fn bloque_estado(m: &Matriz) -> String {
    let mut s = String::new();
    s.push_str("| Espacio de trabajo | Producto | Condicional | Biblioteca | Herramienta |\n");
    s.push_str("|---|---:|---:|---:|---:|\n");
    for (ws, nombre) in [
        ("agente", "Agente (`crates/`)"),
        ("servidor", "Plano de control (`server/crates/`)"),
        ("enjambre", "Enjambre (`swarm-net/`)"),
    ] {
        let _ = writeln!(
            s,
            "| {nombre} | {} | {} | {} | {} |",
            contar(m, ws, Estado::Producto),
            contar(m, ws, Estado::Condicional),
            contar(m, ws, Estado::Biblioteca),
            contar(m, ws, Estado::Herramienta),
        );
    }
    s.push_str(
        "\n**Producto** = lo invoca un ejecutable instalable, lo ejerce una prueba de extremo \
         a extremo en la matriz de kernels y tiene una medida. **Condicional** = lo mismo, pero \
         depende de hardware o de un certificado y lo declara. **Biblioteca** = código probado \
         que hoy no protege ninguna máquina. Detalle crate a crate, con lo que le falta a cada \
         uno: [matriz de capacidades](docs/matriz-capacidades.md).\n",
    );
    s
}

fn bloque_cifras(repo: &Repo, m: &Matriz) -> String {
    let mut s = String::new();
    let ws_crates = |ws: &str| repo.paquetes.iter().filter(|p| p.workspace == ws).count();
    let pruebas = |ws: &str| -> usize {
        repo.paquetes
            .iter()
            .filter(|p| p.workspace == ws)
            .map(|p| repo::contar_pruebas(&repo.raiz.join(&p.dir)))
            .sum()
    };
    let lineas = |ws: &str| -> usize {
        repo.paquetes
            .iter()
            .filter(|p| p.workspace == ws)
            .map(|p| repo::contar_lineas(&repo.raiz.join(&p.dir)))
            .sum()
    };
    let mut c_propio = Vec::new();
    for d in [
        "drivers/linux/aegis-bpf/src",
        "drivers/linux/aegis-bpf/include",
        "kernel/windows",
    ] {
        repo::recorrer(&repo.raiz.join(d), &mut c_propio, &|f: &Path| {
            f.extension().is_some_and(|e| e == "c" || e == "h")
        });
    }
    let lineas_c: usize = c_propio
        .iter()
        .filter_map(|f| std::fs::read_to_string(f).ok())
        .map(|t| t.lines().count())
        .sum();
    let mut verificadores = Vec::new();
    repo::recorrer(&repo.raiz.join("tools"), &mut verificadores, &|f: &Path| {
        f.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("verificar-") && n.ends_with(".sh"))
    });
    let deps_agente = std::fs::read_to_string(repo.raiz.join("tools/lineabase-agente.txt"))
        .unwrap_or_default()
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#')
        })
        .count();

    s.push_str("| Magnitud | Agente | Plano de control | Enjambre |\n|---|---:|---:|---:|\n");
    let _ = writeln!(
        s,
        "| Crates | {} | {} | {} |",
        ws_crates("agente"),
        ws_crates("servidor"),
        ws_crates("enjambre")
    );
    let _ = writeln!(
        s,
        "| Funciones de prueba | {} | {} | {} |",
        miles(pruebas("agente")),
        miles(pruebas("servidor")),
        miles(pruebas("enjambre"))
    );
    let _ = writeln!(
        s,
        "| Líneas de Rust | {} | {} | {} |",
        miles(lineas("agente")),
        miles(lineas("servidor")),
        miles(lineas("enjambre"))
    );
    s.push('\n');
    let _ = writeln!(
        s,
        "Además: **{}** líneas de C propio (sondas eBPF y driver de Windows, sin contar el \
         `vmlinux.h` generado), **{}** verificadores `tools/verificar-*.sh`, **{}** \
         dependencias directas del agente con su justificación en \
         [`tools/lineabase-agente.txt`](tools/lineabase-agente.txt), y **{}** ejecutables \
         instalables.",
        miles(lineas_c),
        verificadores.len(),
        deps_agente,
        m.instalables.len()
    );
    s
}

fn bloque_presupuesto(doc: &Documentacion) -> String {
    const GIB: u64 = 1024 * 1024 * 1024;
    let mib = |b: u64| -> String {
        if b >= GIB {
            format!("{:.1} GiB", b as f64 / GIB as f64).replace('.', ",")
        } else {
            format!("{} MiB", b / (1024 * 1024))
        }
    };
    let mut s = String::from(
        "| Clase de host | RAM | Reposo | Pico | Techo duro | % del host (techo) |\n\
         |---|---:|---:|---:|---:|---:|\n",
    );
    for h in &doc.presupuesto.host {
        let p = Presupuesto::para(h.ram_gib * GIB);
        let peso = p.peso_del_techo();
        let _ = writeln!(
            s,
            "| {} | {} GiB | {} | {} | {} | {},{:02} % |",
            h.nombre,
            h.ram_gib,
            mib(p.reposo),
            mib(p.pico),
            mib(p.techo),
            peso / 100,
            peso % 100
        );
    }
    s.push_str(
        "\n<sub>Calculada por `cargo xtask docs` con `aegis_presupuesto::Presupuesto::para`, \
         el mismo código que aplica el agente.</sub>\n",
    );
    s
}

fn id_mermaid(s: &str) -> String {
    s.replace('-', "_")
}

fn bloque_c4(
    repo: &Repo,
    m: &Matriz,
    doc: &Documentacion,
    inst: &Instalables,
) -> Resultado<String> {
    let binarios: Vec<&str> = inst.instalable.iter().map(|i| i.binario.as_str()).collect();
    let externos: Vec<&str> = doc.c4.externo.iter().map(|e| e.id.as_str()).collect();
    for r in &doc.c4.relacion {
        for extremo in [&r.desde, &r.hacia] {
            if !binarios.contains(&extremo.as_str()) && !externos.contains(&extremo.as_str()) {
                return Err(format!(
                    "documentacion.toml: la relacion usa «{extremo}», que no es un instalable ni un externo"
                )
                .into());
            }
        }
        r.evidencia.comprobar(&repo.raiz)?;
    }

    let mut s = String::from("```mermaid\nflowchart LR\n");
    for (lado, titulo) in [
        ("endpoint", "Endpoint Linux"),
        ("plano-de-control", "Plano de control"),
    ] {
        let _ = writeln!(s, "    subgraph {}[\"{titulo}\"]", id_mermaid(lado));
        for i in m.instalables.iter().filter(|i| i.instalable.lado == lado) {
            let _ = writeln!(
                s,
                "        {}[\"<b>{}</b><br/>{}<br/><i>invoca {} crate{}</i>\"]",
                id_mermaid(&i.instalable.binario),
                i.instalable.binario,
                i.instalable.descripcion.replace('"', "'"),
                i.invoca.len(),
                if i.invoca.len() == 1 { "" } else { "s" }
            );
        }
        s.push_str("    end\n");
    }
    for e in &doc.c4.externo {
        let _ = writeln!(
            s,
            "    {}([\"<b>{}</b><br/>{}\"]):::externo",
            id_mermaid(&e.id),
            e.nombre,
            e.detalle.replace('"', "'")
        );
    }
    for r in &doc.c4.relacion {
        let _ = writeln!(
            s,
            "    {} -->|\"{}\"| {}",
            id_mermaid(&r.desde),
            r.etiqueta.replace('"', "'"),
            id_mermaid(&r.hacia)
        );
    }
    s.push_str("    classDef externo fill:#eef2f7,stroke:#7b8794,color:#1f2933\n```\n");
    s.push_str(
        "\n<sub>Generado desde `tools/config/instalables.toml` y \
         `tools/config/documentacion.toml`. Cada flecha exige una evidencia en el código; \
         una relación que no existe no se puede dibujar.</sub>\n",
    );
    Ok(s)
}

fn bloque_instalables(m: &Matriz) -> String {
    let mut s = String::from(
        "| Ejecutable | Lado | Qué es | Crates que enlaza | Crates que invoca |\n\
         |---|---|---|---:|---:|\n",
    );
    for i in &m.instalables {
        let _ = writeln!(
            s,
            "| `{}` | {} | {} | {} | {} |",
            i.instalable.binario,
            i.instalable.lado,
            i.instalable.descripcion,
            i.enlaza.len(),
            i.invoca.len()
        );
    }
    s
}

fn bloque_componentes(repo: &Repo, m: &Matriz, ws: &str) -> String {
    let mut s = String::from(
        "| Crate | Qué hace | Capa | Estado | Pruebas | `forbid(unsafe)` |\n\
         |---|---|---|---|---:|:---:|\n",
    );
    for f in m.filas.iter().filter(|f| f.paquete.workspace == ws) {
        let dir = repo.raiz.join(&f.paquete.dir);
        let _ = writeln!(
            s,
            "| [`{}`]({}) | {} | {} | {} | {} | {} |",
            f.paquete.nombre,
            repo::relativa(&repo.raiz, &dir),
            f.paquete.descripcion.replace('|', "\\|"),
            f.capa,
            f.estado.nombre(),
            repo::contar_pruebas(&dir),
            if prohibe_unsafe(repo, &f.paquete.dir) {
                "sí"
            } else {
                "—"
            }
        );
    }
    s
}

/// Si el crate prohibe `unsafe`: en su raiz (`#![forbid(unsafe_code)]`) o por
/// las lints del workspace a las que se acoge.
fn prohibe_unsafe(repo: &Repo, dir: &Path) -> bool {
    let d = repo.raiz.join(dir);
    let en_raiz = ["src/lib.rs", "src/main.rs"].iter().any(|f| {
        std::fs::read_to_string(d.join(f)).is_ok_and(|t| t.contains("#![forbid(unsafe_code)]"))
    });
    if en_raiz {
        return true;
    }
    let manifiesto = std::fs::read_to_string(d.join("Cargo.toml")).unwrap_or_default();
    if !manifiesto.contains("workspace = true") || !manifiesto.contains("[lints]") {
        return false;
    }
    // Workspace del que hereda: el primer Cargo.toml con [workspace] hacia arriba.
    let mut dir = d.parent();
    while let Some(p) = dir {
        if let Ok(t) = std::fs::read_to_string(p.join("Cargo.toml")) {
            if t.contains("[workspace]") {
                return t.contains("unsafe_code = \"forbid\"");
            }
        }
        dir = p.parent();
    }
    false
}

fn bloque_documentacion(repo: &Repo) -> String {
    let mut docs: Vec<(Option<u32>, String, String)> = Vec::new();
    if let Ok(entradas) = std::fs::read_dir(repo.raiz.join("docs")) {
        for e in entradas.flatten() {
            let nombre = e.file_name().to_string_lossy().into_owned();
            if !nombre.ends_with(".md") {
                continue;
            }
            let texto = std::fs::read_to_string(e.path()).unwrap_or_default();
            let titulo = texto
                .lines()
                .find_map(|l| l.strip_prefix("# "))
                .unwrap_or(&nombre)
                .to_string();
            // «Módulo 12 — Actualización segura» -> «Actualización segura».
            let titulo = titulo
                .split_once(" — ")
                .filter(|(a, _)| a.starts_with("Módulo"))
                .map(|(_, b)| b.to_string())
                .unwrap_or(titulo);
            let num = nombre.split('-').next().and_then(|n| n.parse::<u32>().ok());
            docs.push((num, nombre, titulo));
        }
    }
    docs.sort();
    let mut s = String::from("**Documentos vivos** (se mantienen al día en cada fase):\n\n");
    for (_, nombre, titulo) in docs.iter().filter(|d| d.0.is_none()) {
        let _ = writeln!(s, "- [{titulo}](docs/{nombre})");
    }
    s.push_str(
        "\n**Registro de fases** (cada documento cuenta lo que se hizo en su fase y cómo se \
         verificó; es histórico y no se reescribe):\n\n| Módulo | Documento |\n|---:|---|\n",
    );
    for (num, nombre, titulo) in docs.iter().filter(|d| d.0.is_some()) {
        let _ = writeln!(
            s,
            "| {} | [{}](docs/{nombre}) |",
            num.unwrap_or_default(),
            titulo.replace('|', "\\|")
        );
    }
    s
}

/// 12345 -> «12.345».
fn miles(n: usize) -> String {
    let d = n.to_string();
    let mut s = String::new();
    for (i, c) in d.chars().enumerate() {
        if i > 0 && (d.len() - i) % 3 == 0 {
            s.push('.');
        }
        s.push(c);
    }
    s
}

// ── La matriz de capacidades ────────────────────────────────────────────────

fn render_matriz(repo: &Repo, m: &Matriz) -> String {
    let mut s = String::from(
        "<!--\n  GENERADO por `cargo xtask docs`. NO SE EDITA AQUI.\n  \
         Los datos viven en tools/config/ y en el codigo.\n-->\n\n\
         # Matriz de capacidades\n\n\
         El estado **real** de cada crate de AegisCore: qué llega a una máquina, qué se \
         ejecuta de verdad, qué se ha probado sobre un kernel real y qué se ha medido. \
         Se calcula compilando los ejecutables instalables y leyendo sus símbolos; no se \
         declara a mano.\n\n\
         ## Criterios\n\n\
         | Estado | Criterio |\n|---|---|\n\
         | **Producto** | (a) lo **invoca** un ejecutable instalable —sobreviven símbolos suyos en el binario release, tras el LTO—; (b) lo ejerce una **prueba de extremo a extremo** de la matriz de kernels; (c) tiene al menos una **medida** publicada (`AEGIS-MEDIDA`). |\n\
         | **Condicional** | lo invoca un instalable, pero depende de hardware o de un certificado; lo detecta en tiempo de ejecución y declara la degradación ([`tools/config/condiciones.toml`](../tools/config/condiciones.toml)). |\n\
         | **Biblioteca** | todo lo demás: código probado que hoy no protege ninguna máquina. |\n\
         | **Herramienta** | crates de prueba; no se instalan. |\n\n\
         **Enlazar no es invocar.** Un crate puede estar en el árbol de dependencias de un \
         binario y no ejecutarse nunca: el enlazador lo descarta entero. La columna *invocado \
         por* solo cuenta los crates de los que queda código en el binario.\n\n",
    );

    s.push_str("## Resumen\n\n");
    s.push_str(&bloque_estado(m).replace("docs/matriz-capacidades.md", "#por-crate"));

    s.push_str("\n## Por ejecutable instalable\n\n");
    for i in &m.instalables {
        let _ = writeln!(
            s,
            "### `{}` ({})\n\n{}\n",
            i.instalable.binario, i.instalable.lado, i.instalable.descripcion
        );
        let invoca: Vec<String> = i.invoca.iter().map(|c| format!("`{c}`")).collect();
        let muertos: Vec<String> = i
            .enlaza
            .difference(&i.invoca)
            .map(|c| format!("`{c}`"))
            .collect();
        let _ = writeln!(
            s,
            "- **Invoca** ({}): {}",
            invoca.len(),
            if invoca.is_empty() {
                "—".into()
            } else {
                invoca.join(", ")
            }
        );
        let _ = writeln!(
            s,
            "- **Enlaza sin invocar** ({}): {}\n",
            muertos.len(),
            if muertos.is_empty() {
                "—".into()
            } else {
                muertos.join(", ")
            }
        );
    }

    s.push_str("## Matriz de kernels\n\n");
    s.push_str(
        "Cada prueba de extremo a extremo se ejecuta dentro de una microVM con el kernel y el \
         espacio de usuario reales de cada distribución (`cargo xtask kernels`). Configuración: \
         [`tools/config/kernels.toml`](../tools/config/kernels.toml).\n\n\
         | Imagen | Distribución | Arquitectura | Kernel | Nota |\n|---|---|---|---|---|\n",
    );
    for im in &m.kernels.imagen {
        let _ = writeln!(
            s,
            "| `{}` | {} | {} | {} | {} |",
            im.id,
            im.distro,
            im.arquitectura,
            im.kernel,
            if im.nota.is_empty() { "—" } else { &im.nota }
        );
    }
    s.push_str("\n| Objeto eBPF (pasa el verificador en cada kernel) | Exige kfunc |\n|---|---|\n");
    for b in &m.kernels.bpf {
        let _ = writeln!(
            s,
            "| `{}.bpf.o` | {} |",
            b.objeto,
            if b.requiere_kfunc.is_empty() {
                "—".to_string()
            } else {
                b.requiere_kfunc.join(", ") + " (sin ellas: *no aplica*, no fallo)"
            }
        );
    }
    s.push_str("\n| Prueba e2e | Qué demuestra | Crates que ejerce |\n|---|---|---:|\n");
    for (p, ej) in &m.pruebas {
        let _ = writeln!(s, "| `{}` | {} | {} |", p.id, p.descripcion, ej.len());
    }

    s.push_str("\n## Excepciones de arquitectura\n\n");
    if m.excepciones.is_empty() {
        s.push_str("Ninguna: todas las dependencias bajan de capa.\n");
    } else {
        s.push_str(
            "Dependencias que hoy suben de capa \
             ([`tools/config/capas.toml`](../tools/config/capas.toml)). La lista solo puede \
             menguar: una nueva hace fallar `make ci`.\n\n\
             | Desde | Hacia | Causa | Plan |\n|---|---|---|---|\n",
        );
        for e in &m.excepciones {
            let _ = writeln!(
                s,
                "| `{}` | `{}` | {} | {} |",
                e.desde, e.hacia, e.causa, e.plan
            );
        }
    }

    s.push_str("\n## Por crate\n\n");
    s.push_str(
        "| Crate | Capa | Estado | Invocado por | Gancho | Prueba e2e | Medidas | Qué le falta |\n\
         |---|---|---|---|---|---|---|---|\n",
    );
    for f in &m.filas {
        let lista = |v: &mut dyn Iterator<Item = String>| -> String {
            let v: Vec<String> = v.collect();
            if v.is_empty() {
                "—".into()
            } else {
                v.join(", ")
            }
        };
        let gancho = f
            .gancho
            .as_ref()
            .map(|(fi, l)| format!("[{fi}:{l}](../{fi}#L{l})"))
            .unwrap_or_else(|| "—".into());
        let mut falta = f.falta.join("; ");
        if let Some((req, deg)) = &f.condicion {
            let c = format!("requiere {req} (sin ello: {deg})");
            falta = if falta.is_empty() {
                c
            } else {
                format!("{falta}; {c}")
            };
        }
        let _ = writeln!(
            s,
            "| `{}` | {} | **{}** | {} | {} | {} | {} | {} |",
            f.paquete.nombre,
            f.capa,
            f.estado.nombre(),
            lista(&mut f.invocado_por.iter().map(|b| format!("`{b}`"))),
            gancho,
            lista(&mut f.e2e.iter().map(|b| format!("`{b}`"))),
            lista(&mut f.medidas.iter().cloned()),
            if falta.is_empty() {
                "—".into()
            } else {
                falta
            }
        );
    }
    let _ = repo;
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detecta_cifras_de_producto_y_respeta_identificadores() {
        let t = "El agente ocupa 45 MB y 39 dependencias.\n\
                 Usa Ed25519, ML-KEM-768, TLS 1.3, Ring 0 y cgroup v2.\n\
                 `22 MiB` en codigo no cuenta, ni un [enlace](docs/12-x.md).\n\
                 ```\n100 %\n```\n\
                 {{cifras}}\n\
                 Un 15 % del host.";
        let h = cifras_a_mano(t);
        let cifras: Vec<&str> = h.iter().map(|(_, c)| c.as_str()).collect();
        assert_eq!(cifras, vec!["45 MB", "39 dependencias", "15 %"]);
        assert_eq!(h[2].0, 8);
    }

    #[test]
    fn separador_de_miles() {
        assert_eq!(miles(7), "7");
        assert_eq!(miles(1234), "1.234");
        assert_eq!(miles(228511), "228.511");
    }
}
