//! Importa el subconjunto Linux de un checkout de SigmaHQ al contenido del
//! agente. Lo invoca `tools/sigma/importar.sh`, que fija y comprueba el commit.
//!
//! ```text
//! importar <checkout-sigmahq> <texto-drl-1.1> <commit> <etiqueta> <commit-drl> <salida>
//! ```
//!
//! `<salida>` es un directorio con la forma de `crates/aegis-sigma`
//! (`reglas/linux/` y `src/`); el script lo sustituye en el repositorio solo si
//! esto termina bien.
//!
//! Filtra con EL MISMO codigo que carga el agente ([`Juego::cargar`]) y con la
//! misma puerta de eventos generados: lo que entra es exactamente lo que el
//! agente puede evaluar. Lo que no entra queda en `INFORME-IMPORTACION` con su
//! motivo. Las reglas se copian TAL CUAL (con su `id`, su autor y su
//! referencia), y la licencia DRL 1.1 y la atribucion van al lado.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use aegis_sigma::compacta::{Categoria, Juego};
use aegis_sigma::regla::{Nivel, Topes};
use aegis_sigma::{contenido, generador, yaml};

/// Las categorias que produce la telemetria del agente.
const CATEGORIAS: [&str; 3] = ["process_creation", "file_event", "network_connection"];

/// Presupuesto de falsos positivos para una regla nueva, por su nivel. Es un
/// PUNTO DE PARTIDA que revisa una persona: cuanto mas alto el nivel, menos
/// ruido se tolera.
fn fp_por_defecto(n: Nivel) -> u32 {
    match n {
        Nivel::Critical => 1,
        Nivel::High => 5,
        Nivel::Medium => 20,
        Nivel::Low => 50,
        Nivel::Informational => 100,
    }
}

struct Aceptada {
    fichero: String,
    id: String,
    titulo: String,
    autor: String,
    ruta: String,
    nivel: Nivel,
}

/// De donde sale lo importado.
struct Origen<'a> {
    checkout: &'a Path,
    licencia: &'a Path,
    commit: &'a str,
    etiqueta: &'a str,
    commit_drl: &'a str,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [checkout, licencia, commit, etiqueta, commit_drl, salida] = args.as_slice() else {
        eprintln!(
            "uso: importar <checkout-sigmahq> <texto-drl-1.1> <commit> <etiqueta> <commit-drl> \
             <salida>"
        );
        return ExitCode::from(2);
    };
    let origen = Origen {
        checkout: Path::new(checkout),
        licencia: Path::new(licencia),
        commit,
        etiqueta,
        commit_drl,
    };
    match importar(&origen, Path::new(salida)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("importar: {e}");
            ExitCode::FAILURE
        }
    }
}

fn yml_de(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut v = Vec::new();
    let entradas = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for e in entradas {
        let p = e.map_err(|e| format!("{}: {e}", dir.display()))?.path();
        if p.extension().is_some_and(|x| x == "yml") {
            v.push(p);
        }
    }
    v.sort();
    Ok(v)
}

fn texto_de(fuente: &str, clave: &str) -> String {
    yaml::leer(fuente, Topes::default().max_anidamiento)
        .ok()
        .and_then(|d| {
            d.mapa()
                .and_then(|m| m.get(clave))
                .and_then(|v| v.texto().map(str::to_string))
        })
        .unwrap_or_else(|| "(sin dato)".to_string())
}

fn escribir(ruta: &Path, texto: &str) -> Result<(), String> {
    std::fs::write(ruta, texto).map_err(|e| format!("{}: {e}", ruta.display()))
}

#[allow(clippy::too_many_lines)]
fn importar(o: &Origen<'_>, salida: &Path) -> Result<(), String> {
    let destino = salida.join("reglas").join("linux");
    std::fs::create_dir_all(&destino).map_err(|e| format!("{}: {e}", destino.display()))?;

    // Sin la licencia no se distribuye nada.
    std::fs::copy(o.licencia, destino.join("LICENCIA-DRL-1.1.md"))
        .map_err(|e| format!("{}: {e}; sin licencia no se importa", o.licencia.display()))?;

    // Los presupuestos que ya fijo una persona se conservan.
    let previos = match std::fs::read_to_string(destino.join("PRESUPUESTOS")) {
        Ok(t) => contenido::leer_presupuestos(&t).map_err(|e| e.detalle)?,
        Err(_) => BTreeMap::new(),
    };

    let mut aceptadas: Vec<Aceptada> = Vec::new();
    let mut rechazos: Vec<(String, String, String)> = Vec::new();
    let mut vistas = 0usize;
    for cat in CATEGORIAS {
        let d = o.checkout.join("rules").join("linux").join(cat);
        for f in yml_de(&d)? {
            vistas += 1;
            let ruta = f
                .strip_prefix(o.checkout)
                .unwrap_or(&f)
                .display()
                .to_string()
                .replace('\\', "/");
            let fichero = f
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_string();
            let mut rechazar = |codigo: &str, detalle: String| {
                rechazos.push((ruta.clone(), codigo.to_string(), detalle));
            };
            let fuente = match std::fs::read_to_string(&f) {
                Ok(t) => t,
                Err(e) => {
                    rechazar("lectura", e.to_string());
                    continue;
                }
            };
            // La regla se copia SIN CAMBIOS (la licencia pide marcar cualquier
            // modificacion), y el arbol no admite CRLF: una regla con CRLF no
            // entra, con su motivo, en vez de convertirse.
            if fuente.contains('\r') {
                rechazar("finales-crlf", "la regla trae CRLF".into());
                continue;
            }
            let juego = Juego::cargar(&[(fichero.as_str(), fuente.as_str())], &Topes::default());
            if let Some(r) = juego.rechazos().first() {
                rechazar(r.codigo, r.detalle.clone());
                continue;
            }
            let Some(regla) = Categoria::TODAS
                .iter()
                .flat_map(|c| juego.reglas(*c))
                .next()
            else {
                rechazar("sin-regla", "el juego quedo vacio sin rechazo".into());
                continue;
            };
            let Some(si) = generador::dispara(regla) else {
                rechazar(
                    "prueba-sin-evento-que-dispara",
                    "ningun evento la dispara".into(),
                );
                continue;
            };
            if generador::no_dispara(regla, &si).is_none() {
                rechazar(
                    "prueba-sin-evento-que-no-dispara",
                    "dispara aunque se altere o quite cualquier campo".into(),
                );
                continue;
            }
            if aceptadas
                .iter()
                .any(|a| a.fichero == fichero || a.id == regla.id())
            {
                rechazar(
                    "duplicada",
                    format!("fichero o id repetido: {}", regla.id()),
                );
                continue;
            }
            escribir(&destino.join(&fichero), &fuente)?;
            aceptadas.push(Aceptada {
                fichero,
                id: regla.id().to_string(),
                titulo: regla.titulo().to_string(),
                autor: texto_de(&fuente, "author"),
                ruta,
                nivel: regla.nivel(),
            });
        }
    }
    if aceptadas.is_empty() {
        return Err(format!("{vistas} reglas vistas y ninguna aceptada"));
    }

    // PRESUPUESTOS
    let mut p = String::from(
        "# Presupuesto de falsos positivos por regla: disparos por millon de eventos\n\
         # benignos de su categoria. Las lineas nuevas salen del nivel de la regla y\n\
         # las REVISA una persona; las revisadas se conservan al reimportar.\n",
    );
    for a in &aceptadas {
        let n = previos
            .get(&a.id)
            .copied()
            .unwrap_or_else(|| fp_por_defecto(a.nivel));
        let _ = writeln!(p, "{}    {n}", a.id);
    }
    escribir(&destino.join("PRESUPUESTOS"), &p)?;

    // ATRIBUCION. La segunda linea la comprueba tools/verificar-sigma.sh contra
    // tools/sigma/COMMIT: lo que viaja tiene que venir del commit fijado.
    let mut t = format!(
        "Reglas de deteccion de SigmaHQ (https://github.com/SigmaHQ/sigma).\n\
         commit {commit} (release {etiqueta})\n\
         Distribuidas bajo la Detection Rule License 1.1 (DRL 1.1): texto en\n\
         LICENCIA-DRL-1.1.md, de https://github.com/SigmaHQ/Detection-Rule-License\n\
         (commit {drl}). Cada fichero se copia sin cambios y conserva su autor, su id\n\
         y sus referencias; su origen es\n\
         https://github.com/SigmaHQ/sigma/blob/{commit}/<ruta en SigmaHQ>.\n\n\
         fichero | id | titulo | autor | ruta en SigmaHQ\n",
        commit = o.commit,
        etiqueta = o.etiqueta,
        drl = o.commit_drl,
    );
    for a in &aceptadas {
        let _ = writeln!(
            t,
            "{} | {} | {} | {} | {}",
            a.fichero, a.id, a.titulo, a.autor, a.ruta
        );
    }
    escribir(&destino.join("ATRIBUCION"), &t)?;

    // INFORME-IMPORTACION
    let mut por_motivo: BTreeMap<&str, usize> = BTreeMap::new();
    for (_, codigo, _) in &rechazos {
        *por_motivo.entry(codigo.as_str()).or_default() += 1;
    }
    let mut inf = format!(
        "SigmaHQ {} ({}): {vistas} reglas de Linux vistas en {}, {} aceptadas, {} \
         rechazadas.\n\nRechazos por motivo:\n",
        o.commit,
        o.etiqueta,
        CATEGORIAS.join(", "),
        aceptadas.len(),
        rechazos.len()
    );
    for (m, n) in &por_motivo {
        let _ = writeln!(inf, "  {n:5}  {m}");
    }
    inf.push_str("\nRechazos, uno por uno:\n");
    for (ruta, codigo, detalle) in &rechazos {
        let _ = writeln!(inf, "{ruta} | {codigo} | {detalle}");
    }
    escribir(&destino.join("INFORME-IMPORTACION"), &inf)?;

    // src/incluidas.rs (rustfmt lo formatea despues)
    let mut r = String::from(
        "//! Las reglas que viajan dentro del binario del agente.\n//!\n\
         //! FICHERO GENERADO por `tools/sigma/importar.sh` (ejemplo `importar` de este\n\
         //! crate) desde el commit fijado en `tools/sigma/COMMIT`: no se edita a mano.\n\
         //! La prueba `reglas_incluidas` falla si `reglas/linux/` y esta lista no\n\
         //! coinciden.\n\n\
         /// `(fichero, fuente)` de cada regla incluida.\n\
         pub const LINUX: &[(&str, &str)] = &[\n",
    );
    for a in &aceptadas {
        let _ = writeln!(
            r,
            "    (\"{0}\", include_str!(\"../reglas/linux/{0}\")),",
            a.fichero
        );
    }
    r.push_str(
        "];\n\n/// El fichero de presupuestos de falsos positivos de las reglas incluidas.\n\
         pub const PRESUPUESTOS: &str = include_str!(\"../reglas/linux/PRESUPUESTOS\");\n",
    );
    escribir(&salida.join("src").join("incluidas.rs"), &r)?;

    println!(
        "importar: {} de {vistas} reglas aceptadas; {} rechazadas (ver INFORME-IMPORTACION)",
        aceptadas.len(),
        rechazos.len()
    );
    Ok(())
}
