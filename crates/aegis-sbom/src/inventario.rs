//! El inventario completo de una maquina: todas las fuentes, y lo que se pudo
//! leer de cada una.
//!
//! # Un SBOM que no dice lo que no vio miente por omision
//!
//! «312 componentes» no dice nada sin «de estas fuentes, leidas asi». Si la base
//! de datos de rpm existia y no hay lector, si el recorrido se corto en su tope,
//! si tres binarios traian metadatos que no se pudieron leer, eso va en el SBOM
//! como parte del resultado ([`Fuente`]), no en un registro que nadie mira.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::aplicacion;
use crate::binario::{self, Metadatos};
use crate::componente::{Componente, Ecosistema};
use crate::contenedor;
use crate::sistema;

/// Como fue la lectura de una fuente.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Estado {
    /// Leida entera.
    Leida {
        /// Cuantos componentes dio.
        componentes: usize,
    },
    /// Leida en parte.
    Parcial {
        /// Cuantos componentes dio.
        leidos: usize,
        /// Que falto.
        motivo: String,
    },
    /// No existe en esta maquina.
    Ausente,
    /// Existe y no hay lector: sus componentes NO estan en el inventario.
    NoSoportada {
        /// Por que.
        motivo: String,
    },
    /// Existe y no se pudo leer.
    Ilegible {
        /// Por que.
        motivo: String,
    },
}

/// Una fuente del inventario y como se leyo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fuente {
    /// Nombre.
    pub nombre: String,
    /// Estado.
    pub estado: Estado,
}

/// El inventario de una maquina.
#[derive(Debug, Clone, Default)]
pub struct Sbom {
    /// Los componentes, sin repetir.
    pub componentes: Vec<Componente>,
    /// Las fuentes y como se leyeron.
    pub fuentes: Vec<Fuente>,
    /// Las imagenes de contenedor inventariadas.
    pub imagenes: Vec<contenedor::Imagen>,
}

impl Sbom {
    /// Componentes por ecosistema.
    #[must_use]
    pub fn por_ecosistema(&self) -> BTreeMap<Ecosistema, usize> {
        let mut m = BTreeMap::new();
        for c in &self.componentes {
            *m.entry(c.ecosistema).or_insert(0) += 1;
        }
        m
    }

    /// Si alguna fuente no se leyo entera.
    #[must_use]
    pub fn incompleto(&self) -> bool {
        self.fuentes.iter().any(|f| {
            matches!(
                f.estado,
                Estado::Parcial { .. } | Estado::NoSoportada { .. } | Estado::Ilegible { .. }
            )
        })
    }
}

/// Que se inventaria.
#[derive(Debug, Clone)]
pub struct Opciones {
    /// La raiz del sistema.
    pub raiz: PathBuf,
    /// Directorios de ejecutables en los que mirar metadatos y firmas.
    pub dirs_binarios: Vec<PathBuf>,
    /// Donde buscar manifiestos y paquetes de aplicacion.
    pub raices_aplicacion: Vec<PathBuf>,
    /// Lo que el recorrido no pisa.
    pub excluidos: Vec<PathBuf>,
    /// Imagenes de contenedor en fichero (`docker save`) o layout OCI.
    pub imagenes: Vec<PathBuf>,
    /// Si se lee el almacen `overlay2` de Docker bajo la raiz.
    pub docker: bool,
}

impl Opciones {
    /// Las opciones para inventariar la maquina en la que corre.
    ///
    /// El recorrido de aplicacion empieza en `/` y excluye los sistemas de
    /// ficheros virtuales (`/proc`, `/sys`, `/dev`, `/run`), `/mnt` y `/media`
    /// —montajes ajenos: en WSL, `/mnt/c` es el disco de Windows entero— y el
    /// almacen de Docker, que se lee aparte, capa a capa.
    #[must_use]
    pub fn del_sistema() -> Opciones {
        let r = PathBuf::from("/");
        Opciones {
            dirs_binarios: [
                "/usr/bin",
                "/usr/sbin",
                "/usr/local/bin",
                "/usr/local/sbin",
                "/usr/libexec",
                "/usr/lib/cargo/bin",
                "/opt",
            ]
            .iter()
            .map(PathBuf::from)
            .collect(),
            raices_aplicacion: vec![r.clone()],
            excluidos: [
                "/proc",
                "/sys",
                "/dev",
                "/run",
                "/mnt",
                "/media",
                "/var/lib/docker",
                "/var/lib/containerd",
                "/snap",
            ]
            .iter()
            .map(PathBuf::from)
            .collect(),
            imagenes: Vec::new(),
            docker: true,
            raiz: r,
        }
    }
}

/// Tope de ficheros que se miran en un directorio de ejecutables.
pub const MAX_BINARIOS: usize = 200_000;

/// Los ficheros regulares bajo un directorio, sin seguir enlaces.
fn ficheros_bajo(dir: &Path, tope: usize) -> (Vec<PathBuf>, bool) {
    let mut out = Vec::new();
    let mut pila = vec![(dir.to_path_buf(), 0usize)];
    while let Some((d, prof)) = pila.pop() {
        let Ok(it) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in it.flatten() {
            let Ok(ft) = e.file_type() else {
                continue;
            };
            if ft.is_dir() && prof < aplicacion::MAX_PROFUNDIDAD {
                pila.push((e.path(), prof + 1));
            } else if ft.is_file() {
                if out.len() >= tope {
                    return (out, true);
                }
                out.push(e.path());
            }
        }
    }
    out.sort();
    (out, false)
}

/// Inventaria.
#[must_use]
pub fn recoger(o: &Opciones) -> Sbom {
    let mut sbom = Sbom::default();

    // 1. Paquetes del sistema.
    let (sistema, fuentes) = sistema::paquetes(&o.raiz);
    // Lo que reclama el gestor de paquetes, en ruta canonica: un binario suyo no
    // se busca por firma (ya esta inventariado por su paquete).
    let reclamados: std::collections::BTreeSet<PathBuf> = sistema
        .iter()
        .flat_map(|c| &c.ficheros)
        .filter_map(|f| std::fs::canonicalize(o.raiz.join(f.strip_prefix("/").unwrap_or(f))).ok())
        .collect();
    sbom.componentes.extend(sistema);
    sbom.fuentes.extend(fuentes);

    // 2. Binarios: metadatos de compilacion y firmas.
    let mut con_metadatos = 0usize;
    let mut ilegibles: Vec<String> = Vec::new();
    let mut por_firma = 0usize;
    let mut cortado = false;
    // Los binarios que se miran: los de los directorios de ejecutables (donde
    // esta lo que no instalo ningun paquete) Y los ejecutables que declaran los
    // paquetes, esten donde esten. Solo con los directorios, los modulos de Go
    // de `/usr/lib/snapd/snapd` no entraban en el inventario. Cada binario una
    // vez, por su ruta canonica.
    let mut candidatos: Vec<PathBuf> = Vec::new();
    for d in &o.dirs_binarios {
        let (fs, c) = ficheros_bajo(d, MAX_BINARIOS);
        cortado |= c;
        candidatos.extend(fs);
    }
    candidatos.extend(
        reclamados
            .iter()
            .filter(|p| {
                let n = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                !(n.ends_with(".so") || n.contains(".so."))
            })
            .cloned(),
    );
    let mut vistos_bin: std::collections::BTreeSet<PathBuf> = std::collections::BTreeSet::new();
    {
        for f in candidatos {
            let canon = std::fs::canonicalize(&f).unwrap_or_else(|_| f.clone());
            if !vistos_bin.insert(canon) {
                continue;
            }
            match binario::metadatos(&f) {
                Metadatos::Leidos(v) => {
                    con_metadatos += 1;
                    for mut c in v {
                        c.ficheros = vec![f.clone()];
                        sbom.componentes.push(c);
                    }
                }
                Metadatos::Ilegibles { formato, motivo } => {
                    ilegibles.push(format!("{} ({formato}): {motivo}", f.display()));
                }
                Metadatos::Ninguno => {}
            }
            let canon = std::fs::canonicalize(&f).unwrap_or_else(|_| f.clone());
            if !reclamados.contains(&canon) && binario::secciones(&f).is_some() {
                // Solo lo que ningun paquete reclama se busca por firma: lo
                // reclamado ya esta inventariado por su paquete.
                let v = binario::por_firma(&f);
                por_firma += v.len();
                sbom.componentes.extend(v);
            }
        }
    }
    sbom.fuentes.push(Fuente {
        nombre: "metadatos-de-compilacion".into(),
        estado: if ilegibles.is_empty() && !cortado {
            Estado::Leida {
                componentes: con_metadatos,
            }
        } else {
            Estado::Parcial {
                leidos: con_metadatos,
                motivo: if cortado {
                    "el recorrido de ejecutables llego a su tope".into()
                } else {
                    format!(
                        "{} binario(s) con metadatos ilegibles: {}",
                        ilegibles.len(),
                        ilegibles
                            .iter()
                            .take(3)
                            .cloned()
                            .collect::<Vec<_>>()
                            .join("; ")
                    )
                },
            }
        },
    });
    sbom.fuentes.push(Fuente {
        nombre: "firmas".into(),
        estado: Estado::Leida {
            componentes: por_firma,
        },
    });

    // 3. Dependencias de aplicacion.
    let excluidos: Vec<&Path> = o.excluidos.iter().map(PathBuf::as_path).collect();
    let mut n_app = 0usize;
    let mut app_cortado = false;
    for r in &o.raices_aplicacion {
        let rec = aplicacion::recorrer(r, &excluidos);
        app_cortado |= rec.cortado;
        for (f, t) in rec.ficheros {
            let v = aplicacion::componentes_de(&f, t);
            n_app += v.len();
            sbom.componentes.extend(v);
        }
    }
    sbom.fuentes.push(Fuente {
        nombre: "aplicacion".into(),
        estado: if app_cortado {
            Estado::Parcial {
                leidos: n_app,
                motivo: "el recorrido llego a su tope de entradas o de profundidad".into(),
            }
        } else {
            Estado::Leida { componentes: n_app }
        },
    });

    // 4. Contenedores.
    let mut imagenes = Vec::new();
    for i in &o.imagenes {
        let r = if i.is_dir() {
            contenedor::desde_oci(i)
        } else {
            contenedor::desde_tar(i)
        };
        match r {
            Ok(v) => imagenes.extend(v),
            Err(e) => sbom.fuentes.push(Fuente {
                nombre: format!("imagen {}", i.display()),
                estado: Estado::Ilegible {
                    motivo: e.to_string(),
                },
            }),
        }
    }
    if o.docker {
        let almacen = o.raiz.join("var/lib/docker/image/overlay2");
        if almacen.exists() {
            match contenedor::desde_overlay2(&o.raiz) {
                Ok(v) => imagenes.extend(v),
                Err(e) => sbom.fuentes.push(Fuente {
                    nombre: "docker-overlay2".into(),
                    estado: Estado::Ilegible {
                        motivo: e.to_string(),
                    },
                }),
            }
        } else {
            sbom.fuentes.push(Fuente {
                nombre: "docker-overlay2".into(),
                estado: Estado::Ausente,
            });
        }
    }
    for img in &imagenes {
        sbom.componentes.extend(img.componentes.iter().cloned());
    }
    sbom.imagenes = imagenes;

    sbom.componentes = desduplicar(std::mem::take(&mut sbom.componentes));
    sbom
}

/// Quita repetidos por [`Componente::clave`], uniendo sus ficheros.
///
/// Se queda la primera procedencia vista, que por el orden de [`recoger`] es la
/// mas fuerte: el gestor de paquetes antes que los metadatos del binario, y
/// estos antes que un manifiesto.
#[must_use]
pub fn desduplicar(v: Vec<Componente>) -> Vec<Componente> {
    let mut vistos: BTreeMap<String, usize> = BTreeMap::new();
    let mut out: Vec<Componente> = Vec::with_capacity(v.len());
    for c in v {
        let k = format!("{:?}", c.clave());
        match vistos.get(&k) {
            Some(i) => {
                for f in c.ficheros {
                    if !out[*i].ficheros.contains(&f) {
                        out[*i].ficheros.push(f);
                    }
                }
            }
            None => {
                vistos.insert(k, out.len());
                out.push(c);
            }
        }
    }
    out
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::componente::Procedencia;

    #[test]
    fn el_mismo_componente_de_dos_fuentes_es_uno_con_los_ficheros_de_ambas() {
        let mut a = Componente::nuevo(
            Ecosistema::Cargo,
            "libc",
            "0.2.153",
            Procedencia::MetadatosDeCompilacion {
                binario: "/usr/bin/sudo".into(),
                formato: "cargo-auditable",
            },
        );
        a.ficheros = vec!["/usr/bin/sudo".into()];
        let mut b = a.clone();
        b.procedencia = Procedencia::Manifiesto {
            fichero: "/usr/share/doc/sudo-rs/Cargo.lock".into(),
        };
        b.ficheros = vec!["/usr/bin/su".into()];
        let v = desduplicar(vec![a, b]);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].procedencia.nombre(), "metadatos-de-compilacion");
        assert_eq!(v[0].ficheros.len(), 2);
    }
}
