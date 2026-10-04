//! `cargo xtask marcador`: el scorecard publico, `docs/generado/scorecard.md`
//! (FASE 4 del MP-16, «Hecho cuando»).
//!
//! # La regla
//!
//! **Cada numero sale de una linea medida; lo que no se midio dice «sin
//! medir».** Ninguna cifra se escribe a mano ni se rellena con un objetivo. Las
//! fuentes son:
//!
//! - la matriz de kernels (`cargo xtask kernels ejecutar`): las lineas
//!   `AEGIS-MEDIDA` y `AEGIS-LOG` de `resultado.txt` de cada imagen:
//!   - `rango-en-vivo` -> cobertura ATT&CK y tiempo hasta la deteccion;
//!   - `corpus-en-vivo` -> deteccion y falsos positivos por motor y latencia
//!     de veredicto (contrato de lineas mas abajo);
//!   - `trabajador-en-vivo` -> p99 del analisis en el trabajador confinado;
//! - `docs/generado/motores.txt` (generado por el agente) -> filas de motores;
//! - la tarjeta GENERADA del modelo estatico y `tools/config/modelo.toml`.
//!
//! Contrato de `corpus-en-vivo` (lo que este generador lee):
//!
//! ```text
//!   AEGIS-MEDIDA|aegis-corpus|detectados_<motor>|<k>|de_<n>   maliciosos acusados
//!   AEGIS-MEDIDA|aegis-corpus|fp_<motor>|<k>|de_<n>           benignos acusados
//!   AEGIS-MEDIDA|aegis-corpus|latencia_veredicto_p50|<ms>|ms
//!   AEGIS-MEDIDA|aegis-corpus|latencia_veredicto_p99|<ms>|ms
//! ```
//!
//! con `<motor>` = `global` para «cualquier motor».

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use crate::config::{self, Kernels};
use crate::kernels;
use crate::repo::Repo;
use crate::Resultado;

/// Texto de una celda sin dato.
pub const SIN_MEDIR: &str = "sin medir";

/// Donde se escribe.
pub const RUTA: &str = "docs/generado/scorecard.md";

/// Una linea `AEGIS-MEDIDA|crate|nombre|valor|unidad`.
#[derive(Debug, Clone)]
struct Medida {
    componente: String,
    nombre: String,
    valor: String,
    unidad: String,
}

fn medidas(lineas: &[String]) -> Vec<Medida> {
    lineas
        .iter()
        .filter_map(|l| l.strip_prefix("AEGIS-MEDIDA|"))
        .filter_map(|m| {
            let c: Vec<&str> = m.split('|').collect();
            (c.len() >= 4).then(|| Medida {
                componente: c[0].to_string(),
                nombre: c[1].to_string(),
                valor: c[2].trim().to_string(),
                unidad: c[3].trim().to_string(),
            })
        })
        .collect()
}

/// Un valor medido como numero, o nada si la linea traia `?` o texto.
fn numero(v: &str) -> Option<f64> {
    v.parse::<f64>().ok().filter(|x| x.is_finite())
}

/// `de_<n>` -> n.
fn denominador(unidad: &str) -> Option<u64> {
    unidad.strip_prefix("de_").and_then(|n| n.parse().ok())
}

/// El id de una imagen de la matriz y las lineas de su resultado.
type LineasDeImagen = (String, Vec<String>);

/// Las lineas de cada imagen de `tools/config/kernels.toml`, en su orden, y
/// las imagenes cuyo resultado es ANTERIOR a los binarios medidos.
///
/// `target/matriz-kernels/<id>/resultado.txt` sobrevive entre tandas: una imagen
/// que esta vez no arranco conserva el de una tanda anterior, medido sobre OTROS
/// binarios. Un resultado mas viejo que la `HUELLA` de los binarios de su
/// arquitectura (`dist-hermetico/` o `dist-hermetico-<arq>/`, la misma que
/// `kernels` exige antes de arrancar) no se mezcla con los de ahora: esa imagen
/// sale «sin medir» y se nombra como descartada.
fn resultados(repo: &Repo) -> Resultado<(Vec<LineasDeImagen>, Vec<String>)> {
    let k: Kernels = config::leer(&repo.raiz, "kernels.toml")?;
    let dir = kernels::trabajo(repo);
    let mut v = Vec::new();
    let mut descartadas = Vec::new();
    for im in &k.imagen {
        let ruta = dir.join(&im.id).join("resultado.txt");
        let dist = if im.arquitectura == "x86_64" {
            "dist-hermetico".to_string()
        } else {
            format!("dist-hermetico-{}", im.arquitectura)
        };
        let binarios = modificado(&repo.raiz.join(dist).join("HUELLA"));
        // Sin HUELLA no hay binarios a los que atribuir el resultado (`kernels`
        // no arranca sin ella): tambien se descarta.
        let viejo = match (modificado(&ruta), binarios) {
            (Some(r), Some(b)) => r < b,
            (Some(_), None) => true,
            (None, _) => false,
        };
        let lineas = if viejo {
            descartadas.push(im.id.clone());
            Vec::new()
        } else {
            std::fs::read_to_string(ruta)
                .map(|t| t.lines().map(str::to_string).collect())
                .unwrap_or_default()
        };
        v.push((im.id.clone(), lineas));
    }
    Ok((v, descartadas))
}

fn modificado(ruta: &Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(ruta).and_then(|m| m.modified()).ok()
}

/// `clave = valor` (el mismo subconjunto plano que lee el agente).
fn plano(ruta: &Path) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    let Ok(t) = std::fs::read_to_string(ruta) else {
        return m;
    };
    for l in t.lines().map(str::trim) {
        if l.is_empty() || l.starts_with('#') || l.starts_with('[') {
            continue;
        }
        if let Some((k, v)) = l.split_once('=') {
            let v = v
                .split_once(" #")
                .map_or(v, |(a, _)| a)
                .trim()
                .trim_matches('"');
            m.insert(k.trim().to_string(), v.to_string());
        }
    }
    m
}

fn por_mil(k: u64, n: u64) -> String {
    if n == 0 {
        return SIN_MEDIR.to_string();
    }
    format!("{:.2} ‰ ({k}/{n})", k as f64 * 1000.0 / n as f64)
}

/// Genera el texto del scorecard. Funcion pura sobre sus entradas: la prueban
/// los casos de abajo sin matriz ni disco.
fn generar(
    imagenes: &[(String, Vec<String>)],
    descartadas: &[String],
    motores_txt: Option<&str>,
    tarjeta: &BTreeMap<String, String>,
    modelo_conf: &BTreeMap<String, String>,
    huella: Option<&str>,
) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "# Scorecard de AegisCore\n");
    let _ = writeln!(
        s,
        "> GENERADO por `cargo xtask marcador` en `make ci`, despues de la matriz de \
         kernels. No editar a mano. Cada cifra sale de una linea medida; una celda sin \
         dato dice «{SIN_MEDIR}».\n"
    );
    let _ = writeln!(
        s,
        "Arbol de los binarios medidos: {}\n",
        huella.map_or(SIN_MEDIR.to_string(), |h| format!("`{h}`"))
    );
    let con_datos: Vec<&str> = imagenes
        .iter()
        .filter(|(_, l)| !l.is_empty())
        .map(|(id, _)| id.as_str())
        .collect();
    let _ = writeln!(
        s,
        "Imagenes con resultado: {}\n",
        if con_datos.is_empty() {
            SIN_MEDIR.to_string()
        } else {
            con_datos.join(", ")
        }
    );
    if !descartadas.is_empty() {
        let _ = writeln!(
            s,
            "Descartadas por ser anteriores a esos binarios (cuentan como «{SIN_MEDIR}»): {}
",
            descartadas.join(", ")
        );
    }

    // ── 1. Cobertura ATT&CK ────────────────────────────────────────────────
    let _ = writeln!(s, "## Cobertura ATT&CK (rango en vivo)\n");
    let _ = writeln!(
        s,
        "Emulaciones reales contra el agente publicado en cada microVM \
         (`rango-en-vivo`). Celda: segundos hasta la señal del agente, «hueco» si no \
         la hubo en su ventana.\n"
    );
    let mut tecnicas: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut detector: BTreeMap<String, String> = BTreeMap::new();
    let mut cobertura: Vec<(String, String)> = Vec::new();
    for (id, lineas) in imagenes {
        for m in medidas(lineas) {
            if m.componente != "aegis-rango" {
                continue;
            }
            if let Some(t) = m.nombre.strip_prefix("deteccion_") {
                let celda = match numero(&m.valor) {
                    Some(x) if x < 0.0 => "hueco".to_string(),
                    Some(x) => format!("{x} s"),
                    None => SIN_MEDIR.to_string(),
                };
                tecnicas
                    .entry(t.to_string())
                    .or_default()
                    .insert(id.clone(), celda);
            } else if m.nombre == "tecnicas_detectadas" {
                if let (Some(k), Some(n)) = (numero(&m.valor), denominador(&m.unidad)) {
                    cobertura.push((id.clone(), format!("{k}/{n}")));
                }
            }
        }
        for l in lineas {
            let Some(resto) = l.strip_prefix("AEGIS-LOG|rango ") else {
                continue;
            };
            let mut p = resto.split_whitespace();
            let (Some(t), Some(estado)) = (p.next(), p.next()) else {
                continue;
            };
            if estado == "DETECTADA" {
                // «<t> DETECTADA por <motor>: ...»
                if let Some(motor) = p.nth(1) {
                    let motor = motor.trim_end_matches(':').to_string();
                    let e = detector.entry(t.to_string()).or_default();
                    if !e.split(", ").any(|x| x == motor) {
                        if !e.is_empty() {
                            e.push_str(", ");
                        }
                        e.push_str(&motor);
                    }
                }
            }
        }
    }
    if tecnicas.is_empty() {
        let _ = writeln!(
            s,
            "{SIN_MEDIR}: ninguna imagen trae lineas de `rango-en-vivo`.\n"
        );
    } else {
        let _ = write!(s, "| Tecnica | Motor que la detecto |");
        for id in &con_datos {
            let _ = write!(s, " {id} |");
        }
        let _ = write!(s, "\n|---|---|");
        for _ in &con_datos {
            let _ = write!(s, "---|");
        }
        let _ = writeln!(s);
        for (t, celdas) in &tecnicas {
            let _ = write!(
                s,
                "| {t} | {} |",
                detector.get(t).map_or("ninguno", String::as_str)
            );
            for id in &con_datos {
                let _ = write!(
                    s,
                    " {} |",
                    celdas.get(*id).map_or(SIN_MEDIR, String::as_str)
                );
            }
            let _ = writeln!(s);
        }
        let _ = writeln!(s);
        let _ = writeln!(s, "| Imagen | Tecnicas detectadas |\n|---|---|");
        for id in &con_datos {
            let c = cobertura
                .iter()
                .find(|(i, _)| i.as_str() == *id)
                .map_or(SIN_MEDIR, |(_, c)| c.as_str());
            let _ = writeln!(s, "| {id} | {c} |");
        }
        let _ = writeln!(s);
    }

    // ── 2. Deteccion y falsos positivos por motor ──────────────────────────
    let _ = writeln!(
        s,
        "## Deteccion y falsos positivos por motor (corpus en VM)\n"
    );
    let _ = writeln!(
        s,
        "Corpus de laboratorio analizado dentro de una microVM sin red \
         (`corpus-en-vivo`). Por mil binarios, con el recuento al lado; se suman las \
         imagenes que lo ejecutaron.\n"
    );
    let mut det: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut fp: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut latencias: Vec<(String, String, String)> = Vec::new();
    for (id, lineas) in imagenes {
        for m in medidas(lineas) {
            match m.componente.as_str() {
                "aegis-corpus" => {
                    let k = numero(&m.valor).map(|x| x as u64);
                    let n = denominador(&m.unidad);
                    if let (Some(motor), Some(k), Some(n)) =
                        (m.nombre.strip_prefix("detectados_"), k, n)
                    {
                        let e = det.entry(motor.to_string()).or_default();
                        e.0 += k;
                        e.1 += n;
                    } else if let (Some(motor), Some(k), Some(n)) =
                        (m.nombre.strip_prefix("fp_"), k, n)
                    {
                        let e = fp.entry(motor.to_string()).or_default();
                        e.0 += k;
                        e.1 += n;
                    } else if let Some(q) = m.nombre.strip_prefix("latencia_veredicto_") {
                        if numero(&m.valor).is_some() {
                            latencias.push((
                                format!("veredicto {q} (corpus)"),
                                id.clone(),
                                format!("{} {}", m.valor, m.unidad),
                            ));
                        }
                    }
                }
                "aegis-trabajador" if m.nombre == "p99_analisis" => {
                    if let Some(ns) = numero(&m.valor) {
                        latencias.push((
                            "analisis p99 en el trabajador confinado".into(),
                            id.clone(),
                            format!("{:.2} ms", ns / 1e6),
                        ));
                    }
                }
                _ => {}
            }
        }
    }
    let mut motores: BTreeSet<String> = BTreeSet::new();
    if let Some(t) = motores_txt {
        for l in t
            .lines()
            .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        {
            if let Some(n) = l.split('\t').next() {
                motores.insert(n.trim().to_string());
            }
        }
    }
    motores.extend(det.keys().cloned());
    motores.extend(fp.keys().cloned());
    motores.remove("global");
    let _ = writeln!(
        s,
        "| Motor | Deteccion (maliciosos) | Falsos positivos (benignos) |\n|---|---|---|"
    );
    let celda = |m: &BTreeMap<String, (u64, u64)>, k: &str| {
        m.get(k)
            .map_or(SIN_MEDIR.to_string(), |(a, n)| por_mil(*a, *n))
    };
    for m in motores.iter().map(String::as_str).chain(["global"]) {
        let nombre = if m == "global" {
            "**cualquier motor**"
        } else {
            m
        };
        let _ = writeln!(s, "| {nombre} | {} | {} |", celda(&det, m), celda(&fp, m));
    }
    let _ = writeln!(s);

    // ── 3. Latencia ────────────────────────────────────────────────────────
    let _ = writeln!(s, "## Latencia de veredicto\n");
    let tiempos: Vec<f64> = tecnicas
        .values()
        .flat_map(|c| c.values())
        .filter_map(|c| c.strip_suffix(" s").and_then(|x| x.parse::<f64>().ok()))
        .collect();
    if !tiempos.is_empty() {
        let mut t = tiempos;
        t.sort_by(f64::total_cmp);
        latencias.push((
            "desde la emulacion hasta la señal (mediana, rango)".into(),
            "todas".into(),
            format!("{} s", t[t.len() / 2]),
        ));
    }
    if latencias.is_empty() {
        let _ = writeln!(s, "{SIN_MEDIR}.\n");
    } else {
        let _ = writeln!(s, "| Medida | Imagen | Valor |\n|---|---|---|");
        for (que, id, v) in &latencias {
            let _ = writeln!(s, "| {que} | {id} | {v} |");
        }
        let _ = writeln!(s);
    }
    let _ = writeln!(
        s,
        "Latencia de veredicto sobre el corpus: {}.\n",
        if latencias.iter().any(|(q, _, _)| q.contains("(corpus)")) {
            "en la tabla"
        } else {
            SIN_MEDIR
        }
    );

    // ── 4. Modelo estatico ─────────────────────────────────────────────────
    let _ = writeln!(s, "## Modelo estatico\n");
    let v = |k: &str| {
        tarjeta
            .get(k)
            .filter(|x| !x.is_empty())
            .map_or(SIN_MEDIR.to_string(), String::clone)
    };
    let _ = writeln!(s, "| Campo | Valor |\n|---|---|");
    let _ = writeln!(s, "| Clase segun su tarjeta | {} |", v("clase"));
    let _ = writeln!(s, "| Version | {} |", v("version_modelo"));
    let _ = writeln!(
        s,
        "| AUC (evaluacion posterior al corte) | {} |",
        v("auc_eval")
    );
    let _ = writeln!(s, "| Recall en bloqueo | {} |", v("recall_eval_bloqueo"));
    let _ = writeln!(
        s,
        "| Cota 95 % del FPR en bloqueo | {} |",
        v("fpr_cota95_bloqueo")
    );
    let _ = writeln!(
        s,
        "| FPR objetivo (tools/config/modelo.toml) | {} |",
        modelo_conf
            .get("fpr_objetivo")
            .map_or(SIN_MEDIR, String::as_str)
    );
    let _ = writeln!(
        s,
        "\nEl agente usa el modelo solo si su tarjeta corresponde por hash al modelo \
         empotrado y cumple ese objetivo (`crates/aegis-ml/src/puerta.rs`); si no, su \
         puntuacion sale NoConcluyente. Detalle: `docs/generado/tarjeta-modelo-estatico.md`.\n"
    );

    // ── 5. Lo que gobiernan estos numeros ──────────────────────────────────
    let sin_fp: Vec<&str> = motores
        .iter()
        .filter(|m| !fp.contains_key(*m))
        .map(String::as_str)
        .collect();
    let _ = writeln!(s, "## Solo-auditoria frente a imponer\n");
    let _ = writeln!(
        s,
        "Un motor sin falsos positivos medidos no puede pasar de solo-auditoria a \
         imponer. Sin medir hoy: {}.",
        if sin_fp.is_empty() {
            "ninguno".to_string()
        } else {
            sin_fp.join(", ")
        }
    );
    s
}

/// Genera el scorecard desde los resultados presentes.
///
/// Sin `publicar` lo deja en `target/marcador/scorecard.md`: escribir en el
/// arbol a mitad de `make ci` cambiaria su huella (`tools/huella-arbol.sh`
/// cuenta los ficheros sin seguimiento), y con ella la procedencia de la matriz
/// y el apunte de `--reanudar`. Con `publicar` lo copia a
/// `docs/generado/scorecard.md`, que es lo que se comitea tras una tanda verde.
pub fn escribir(repo: &Repo, publicar: bool) -> Resultado<String> {
    let (imagenes, descartadas) = resultados(repo)?;
    let motores = std::fs::read_to_string(repo.raiz.join("docs/generado/motores.txt")).ok();
    let tarjeta = plano(
        &repo
            .raiz
            .join("crates/aegis-ml/models/aegis-static-v1.tarjeta"),
    );
    let conf = plano(&repo.raiz.join("tools/config/modelo.toml"));
    let huella = std::fs::read_to_string(repo.raiz.join("dist-hermetico/HUELLA"))
        .ok()
        .map(|h| h.trim().to_string())
        .filter(|h| h.len() == 64);
    let texto = generar(
        &imagenes,
        &descartadas,
        motores.as_deref(),
        &tarjeta,
        &conf,
        huella.as_deref(),
    );
    let ruta = if publicar {
        repo.raiz.join(RUTA)
    } else {
        kernels::trabajo(repo)
            .with_file_name("marcador")
            .join("scorecard.md")
    };
    if let Some(d) = ruta.parent() {
        std::fs::create_dir_all(d)?;
    }
    std::fs::write(&ruta, texto)?;
    let con = imagenes.iter().filter(|(_, l)| !l.is_empty()).count();
    Ok(format!(
        "marcador: {} generado ({con} de {} imagenes con resultado)",
        ruta.display(),
        imagenes.len()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn l(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn sin_resultados_todo_dice_sin_medir_y_no_hay_numeros_inventados() {
        let im = vec![("debian-12".to_string(), Vec::new())];
        let s = generar(&im, &[], None, &BTreeMap::new(), &BTreeMap::new(), None);
        assert!(s.contains("sin medir: ninguna imagen trae lineas de `rango-en-vivo`"));
        assert!(s.contains("| **cualquier motor** | sin medir | sin medir |"));
        assert!(!s.contains('‰'), "{s}");
    }

    #[test]
    fn las_cifras_salen_de_las_lineas() {
        let im = vec![(
            "ubuntu-24.04".to_string(),
            l(&[
                "AEGIS-MEDIDA|aegis-rango|deteccion_T1486|4|s",
                "AEGIS-MEDIDA|aegis-rango|deteccion_T1620|-1|s",
                "AEGIS-MEDIDA|aegis-rango|tecnicas_detectadas|1|de_2",
                "AEGIS-LOG|rango T1486 DETECTADA por secuestro: [SEÑAL] x",
                "AEGIS-LOG|rango T1620 HUECO (motor esperado memoria)",
                "AEGIS-MEDIDA|aegis-corpus|fp_modelo|3|de_30000",
                "AEGIS-MEDIDA|aegis-corpus|detectados_global|900|de_1000",
                "AEGIS-MEDIDA|aegis-corpus|latencia_veredicto_p99|120|ms",
            ]),
        )];
        let motores = "# c\nmodelo\taprendizaje\tfrio\tx\nconducta\tconductual\tcaliente\tx\n";
        let s = generar(
            &im,
            &[],
            Some(motores),
            &BTreeMap::new(),
            &BTreeMap::new(),
            None,
        );
        assert!(s.contains("| T1486 | secuestro | 4 s |"), "{s}");
        assert!(s.contains("| T1620 | ninguno | hueco |"), "{s}");
        assert!(s.contains("| ubuntu-24.04 | 1/2 |"), "{s}");
        assert!(
            s.contains("| modelo | sin medir | 0.10 ‰ (3/30000) |"),
            "{s}"
        );
        assert!(s.contains("| conducta | sin medir | sin medir |"), "{s}");
        assert!(
            s.contains("| **cualquier motor** | 900.00 ‰ (900/1000) | sin medir |"),
            "{s}"
        );
        assert!(s.contains("120 ms"), "{s}");
        assert!(s.contains("Sin medir hoy: conducta."), "{s}");
    }

    #[test]
    fn un_valor_no_numerico_no_se_convierte_en_cifra() {
        let im = vec![(
            "x".to_string(),
            l(&["AEGIS-MEDIDA|aegis-rango|deteccion_T1053.003|?|s"]),
        )];
        let s = generar(&im, &[], None, &BTreeMap::new(), &BTreeMap::new(), None);
        assert!(s.contains("| T1053.003 | ninguno | sin medir |"), "{s}");
    }

    #[test]
    fn un_resultado_anterior_a_los_binarios_no_cuenta() {
        // resultados() lo vacia; aqui se comprueba que se dice, no que se calla.
        let im = vec![("debian-12".to_string(), Vec::new())];
        let s = generar(
            &im,
            &["debian-12".to_string()],
            None,
            &BTreeMap::new(),
            &BTreeMap::new(),
            None,
        );
        assert!(
            s.contains("Descartadas por ser anteriores a esos binarios"),
            "{s}"
        );
        assert!(s.contains("Imagenes con resultado: sin medir"), "{s}");
    }
}
