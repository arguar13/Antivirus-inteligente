//! La matriz de capacidades: el estado REAL de cada crate.
//!
//! | Estado        | Criterio                                                        |
//! |---------------|-----------------------------------------------------------------|
//! | Producto      | lo invoca un instalable, lo ejerce una prueba e2e de la matriz  |
//! |               | de kernels y tiene al menos una medida publicada                |
//! | Condicional   | lo invoca un instalable y depende de hardware o certificado,    |
//! |               | con deteccion en tiempo de ejecucion declarada                  |
//! | Biblioteca    | todo lo demas                                                   |
//! | Herramienta   | crates de prueba que no se instalan                             |
//!
//! Nada de esto se declara a mano: el enlace y la invocacion salen de los
//! binarios compilados (ver [`crate::enlace`]), las pruebas e2e de
//! `tools/config/kernels.toml` y las medidas de las lineas `AEGIS-MEDIDA` que el
//! codigo emite.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::config::{
    self, Capas, Condiciones, Excepcion, Instalable, Instalables, Kernels, PruebaE2e,
};
use crate::enlace;
use crate::repo::{self, Paquete, Repo};
use crate::Resultado;

/// Estado de un crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Estado {
    /// Instalado, ejercido en la matriz de kernels y medido.
    Producto,
    /// Instalado, dependiente de hardware o certificado, con degradacion declarada.
    Condicional,
    /// Codigo probado que hoy no protege ninguna maquina.
    Biblioteca,
    /// Herramienta de prueba.
    Herramienta,
}

impl Estado {
    /// Nombre para la documentacion.
    pub fn nombre(self) -> &'static str {
        match self {
            Estado::Producto => "Producto",
            Estado::Condicional => "Condicional",
            Estado::Biblioteca => "Biblioteca",
            Estado::Herramienta => "Herramienta",
        }
    }
}

/// Lo que se sabe de un instalable.
#[derive(Debug)]
pub struct InfoInstalable {
    /// Su entrada de configuracion.
    pub instalable: Instalable,
    /// Crates del repositorio que enlaza.
    pub enlaza: BTreeSet<String>,
    /// Crates de los que conserva simbolos.
    pub invoca: BTreeSet<String>,
}

/// Lo que se sabe de un crate.
#[derive(Debug)]
pub struct Fila {
    /// El crate.
    pub paquete: Paquete,
    /// Su capa.
    pub capa: String,
    /// Instalables que lo invocan.
    pub invocado_por: BTreeSet<String>,
    /// Donde lo llama su dependiente dentro del instalable (fichero, linea).
    pub gancho: Option<(String, usize)>,
    /// Pruebas e2e de la matriz de kernels que lo ejercen.
    pub e2e: Vec<String>,
    /// Medidas que emite (nombre y unidad).
    pub medidas: BTreeSet<String>,
    /// Requisito de hardware o certificado y lo que se degrada sin el, si es
    /// condicional.
    pub condicion: Option<(String, String)>,
    /// Estado resultante.
    pub estado: Estado,
    /// Que le falta para ser Producto.
    pub falta: Vec<&'static str>,
}

/// La matriz entera.
#[derive(Debug)]
pub struct Matriz {
    /// Una entrada por instalable.
    pub instalables: Vec<InfoInstalable>,
    /// Una fila por crate, ordenadas por nombre.
    pub filas: Vec<Fila>,
    /// Pruebas e2e y los crates que ejercen.
    pub pruebas: Vec<(PruebaE2e, BTreeSet<String>)>,
    /// La configuracion de la matriz de kernels.
    pub kernels: Kernels,
    /// Dependencias que hoy suben de capa, con su causa y su plan.
    pub excepciones: Vec<Excepcion>,
}

/// Capa de cada crate segun `tools/config/capas.toml`.
pub fn capa_de(capas: &Capas) -> BTreeMap<String, &'static str> {
    let mut m = BTreeMap::new();
    for (nombre, lista) in [
        ("núcleo", &capas.nucleo),
        ("plataforma", &capas.plataforma),
        ("motores", &capas.motores),
        ("E/S", &capas.es),
        ("herramienta", &capas.herramientas),
    ] {
        for c in &lista.crates {
            m.insert(c.clone(), nombre);
        }
    }
    m
}

/// Calcula la matriz. Compila los instalables y las pruebas e2e.
pub fn calcular(repo: &Repo) -> Resultado<Matriz> {
    let instalables: Instalables = config::leer(&repo.raiz, "instalables.toml")?;
    let capas: Capas = config::leer(&repo.raiz, "capas.toml")?;
    let condiciones: Condiciones = config::leer(&repo.raiz, "condiciones.toml")?;
    let kernels: Kernels = config::leer(&repo.raiz, "kernels.toml")?;
    let capas_de = capa_de(&capas);

    // 1. Enlace e invocacion de cada instalable.
    let mut infos = Vec::new();
    for inst in &instalables.instalable {
        if repo.paquete(&inst.paquete).is_none() {
            return Err(format!(
                "instalables.toml: el paquete {} no existe en ningun workspace",
                inst.paquete
            )
            .into());
        }
        eprintln!("xtask: analizando el instalable {}", inst.binario);
        let enlaza = enlace::cierre(repo, &inst.workspace, &inst.paquete, &inst.caracteristicas)?;
        let exe = enlace::compilar_binario(
            repo,
            &inst.workspace,
            &inst.paquete,
            &inst.binario,
            &inst.caracteristicas,
        )?;
        let invoca = enlace::invocados(repo, &exe)?;
        infos.push(InfoInstalable {
            instalable: inst.clone(),
            enlaza,
            invoca,
        });
    }

    // 2. Crates que ejerce cada prueba e2e de la matriz de kernels.
    let mut pruebas = Vec::new();
    for p in &kernels.prueba {
        let ejercidos = match p.tipo.as_str() {
            "instalable" => {
                let bin = p.binario.as_deref().unwrap_or_default();
                infos
                    .iter()
                    .find(|i| i.instalable.binario == bin)
                    .map(|i| i.invoca.clone())
                    .ok_or_else(|| format!("kernels.toml: {} no es un instalable", bin))?
            }
            "cargo-test" => {
                let paquete = p.paquete.as_deref().unwrap_or_default();
                let prueba = p.prueba.as_deref().unwrap_or_default();
                let ws = repo
                    .paquete(paquete)
                    .map(|x| x.workspace)
                    .ok_or_else(|| format!("kernels.toml: paquete {paquete} desconocido"))?;
                eprintln!("xtask: analizando la prueba e2e {paquete}/{prueba}");
                let exe = enlace::compilar_prueba(repo, ws, paquete, prueba, &p.caracteristicas)?;
                enlace::invocados(repo, &exe)?
            }
            otro => return Err(format!("kernels.toml: tipo de prueba desconocido: {otro}").into()),
        };
        pruebas.push((p.clone(), ejercidos));
    }

    // 3. Medidas declaradas en el codigo.
    let medidas = medidas_emitidas(repo);

    // 4. Condicionales, con su evidencia comprobada.
    let mut condicion_de = BTreeMap::new();
    for c in &condiciones.condicional {
        c.deteccion.comprobar(&repo.raiz)?;
        condicion_de.insert(
            c.krate.clone(),
            (c.requisito.clone(), c.degradacion.clone()),
        );
    }

    // 5. Una fila por crate.
    let mut filas = Vec::new();
    for p in &repo.paquetes {
        let capa = capas_de
            .get(&p.nombre)
            .map(|c| c.to_string())
            .ok_or_else(|| {
                format!(
                    "el crate {} no esta en tools/config/capas.toml: clasificalo",
                    p.nombre
                )
            })?;
        let enlazado_por: BTreeSet<String> = infos
            .iter()
            .filter(|i| i.enlaza.contains(&p.nombre))
            .map(|i| i.instalable.binario.clone())
            .collect();
        let invocado_por: BTreeSet<String> = infos
            .iter()
            .filter(|i| i.invoca.contains(&p.nombre))
            .map(|i| i.instalable.binario.clone())
            .collect();
        let gancho = infos
            .iter()
            .find(|i| i.invoca.contains(&p.nombre))
            .and_then(|i| gancho(repo, i, p));
        let e2e: Vec<String> = pruebas
            .iter()
            .filter(|(_, ej)| ej.contains(&p.nombre))
            .map(|(pr, _)| pr.id.clone())
            .collect();
        let med = medidas.get(&p.nombre).cloned().unwrap_or_default();
        let condicion = condicion_de.get(&p.nombre).cloned();

        let invocado = !invocado_por.is_empty();
        let mut falta = Vec::new();
        if !invocado {
            falta.push(if enlazado_por.is_empty() {
                "ningún instalable lo enlaza"
            } else {
                "enlazado, pero ningún símbolo sobrevive en el binario"
            });
        }
        if e2e.is_empty() {
            falta.push("sin prueba e2e en la matriz de kernels");
        }
        if med.is_empty() {
            falta.push("sin medida");
        }
        let estado = if capa == "herramienta" {
            falta.clear();
            Estado::Herramienta
        } else if falta.is_empty() {
            Estado::Producto
        } else if invocado && condicion.is_some() {
            Estado::Condicional
        } else {
            Estado::Biblioteca
        };
        filas.push(Fila {
            paquete: p.clone(),
            capa,
            invocado_por,
            gancho,
            e2e,
            medidas: med,
            condicion,
            estado,
            falta,
        });
    }

    Ok(Matriz {
        instalables: infos,
        filas,
        pruebas,
        kernels,
        excepciones: capas.excepcion,
    })
}

/// Donde se invoca `p` dentro de un instalable: la primera referencia a
/// `ident::` en el codigo (no de pruebas) de un crate del instalable que depende
/// de el. Para el propio paquete del instalable, su punto de entrada.
fn gancho(repo: &Repo, info: &InfoInstalable, p: &Paquete) -> Option<(String, usize)> {
    if p.nombre == info.instalable.paquete {
        let dir = repo.raiz.join(&p.dir);
        for cand in [
            format!("src/bin/{}.rs", info.instalable.binario),
            "src/main.rs".to_string(),
        ] {
            if dir.join(&cand).is_file() {
                return Some((repo::relativa(&repo.raiz, &dir.join(cand)), 1));
            }
        }
        return None;
    }
    let patron = format!("{}::", p.ident());
    let usos = [format!("use {}", p.ident()), patron.clone()];
    for padre in repo
        .paquetes
        .iter()
        .filter(|q| q.deps.contains(&p.nombre) && info.invoca.contains(&q.nombre))
    {
        for f in repo::fuentes_rust(&repo.raiz.join(&padre.dir).join("src")) {
            let Ok(texto) = std::fs::read_to_string(&f) else {
                continue;
            };
            for (n, linea) in texto.lines().enumerate() {
                // Lo que viene detras de `#[cfg(test)]` es codigo de pruebas:
                // un gancho ahi no es un gancho del producto.
                if linea.trim_start().starts_with("#[cfg(test)]") {
                    break;
                }
                let codigo = linea.split("//").next().unwrap_or_default();
                if usos.iter().any(|u| codigo.contains(u.as_str())) {
                    return Some((repo::relativa(&repo.raiz, &f), n + 1));
                }
            }
        }
    }
    None
}

/// Medidas declaradas con lineas `AEGIS-MEDIDA|<crate>|<nombre>|<valor>|<unidad>`
/// en las fuentes de los crates y en `tools/`. Devuelve, por crate, `nombre (unidad)`.
pub fn medidas_emitidas(repo: &Repo) -> BTreeMap<String, BTreeSet<String>> {
    const MARCA: &str = "AEGIS-MEDIDA|";
    let propios: BTreeSet<&str> = repo.paquetes.iter().map(|p| p.nombre.as_str()).collect();
    let mut ficheros = Vec::new();
    for p in &repo.paquetes {
        ficheros.extend(repo::fuentes_rust(&repo.raiz.join(&p.dir)));
    }
    repo::recorrer(&repo.raiz.join("tools"), &mut ficheros, &|f: &Path| {
        f.extension().is_some_and(|e| e == "sh" || e == "rs")
    });
    let mut m: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for f in ficheros {
        let Ok(texto) = std::fs::read_to_string(&f) else {
            continue;
        };
        for (i, _) in texto.match_indices(MARCA) {
            let resto = &texto[i + MARCA.len()..];
            let partes: Vec<&str> = resto.splitn(5, '|').collect();
            if partes.len() < 4 {
                continue;
            }
            let (krate, nombre) = (partes[0], partes[1]);
            let unidad: String = partes[3]
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '/' || *c == '%')
                .collect();
            if propios.contains(krate) && !nombre.is_empty() && !unidad.is_empty() {
                m.entry(krate.to_string())
                    .or_default()
                    .insert(format!("{nombre} ({unidad})"));
            }
        }
    }
    m
}
