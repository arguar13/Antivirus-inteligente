//! Que es un componente, de donde salio y como se llama fuera de aqui.
//!
//! # La procedencia no es un adorno
//!
//! Dos inventarios con el mismo numero de componentes pueden decir cosas muy
//! distintas. «La base de datos de dpkg dice que esta instalado» es un hecho
//! sobre lo que el gestor de paquetes cree; «el binario lleva incrustada la lista
//! de crates con que se compilo» es un hecho sobre el binario; «aparece la cadena
//! `OpenSSL 3.0.2` en un ejecutable que ningun paquete reclama» es una inferencia
//! por firma. Un informe que las mezcla sin distinguirlas pide al lector que se
//! fie de las tres por igual. Cada componente lleva la suya.

use std::path::PathBuf;

use crate::purl;

/// A que ecosistema pertenece un componente.
///
/// Decide tres cosas a la vez: como se escribe su purl, con que algoritmo se
/// comparan sus versiones y en que ecosistema de OSV se buscan sus avisos. Por
/// eso es un enumerado cerrado y no una cadena.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Ecosistema {
    /// Paquete de Debian o Ubuntu.
    Deb,
    /// Paquete de Alpine.
    Apk,
    /// Crate de Rust.
    Cargo,
    /// Paquete de npm.
    Npm,
    /// Paquete de Python.
    PyPI,
    /// Modulo de Go.
    Go,
    /// Biblioteca identificada por firma o por nombre de fichero, sin
    /// ecosistema de paquetes detras.
    Generico,
}

impl Ecosistema {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Ecosistema::Deb => "deb",
            Ecosistema::Apk => "apk",
            Ecosistema::Cargo => "cargo",
            Ecosistema::Npm => "npm",
            Ecosistema::PyPI => "pypi",
            Ecosistema::Go => "golang",
            Ecosistema::Generico => "generic",
        }
    }

    /// Todos, en orden estable.
    #[must_use]
    pub fn todos() -> &'static [Ecosistema] {
        &[
            Ecosistema::Deb,
            Ecosistema::Apk,
            Ecosistema::Cargo,
            Ecosistema::Npm,
            Ecosistema::PyPI,
            Ecosistema::Go,
            Ecosistema::Generico,
        ]
    }
}

/// La distribucion a la que pertenece un paquete del sistema.
///
/// Hace falta para casar con OSV: el mismo `openssl 3.0.2-0ubuntu1.10` puede ser
/// vulnerable en Ubuntu 22.04 y no existir en Debian 12, y los avisos de cada
/// distribucion estan en su ecosistema (`Ubuntu:22.04:LTS`, `Debian:12`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Distro {
    /// El `ID` de `/etc/os-release`: `ubuntu`, `debian`, `alpine`.
    pub id: String,
    /// El `VERSION_ID`: `24.04`, `12`, `3.19.1`.
    pub version: String,
}

/// De donde salio un componente.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Procedencia {
    /// La base de datos del gestor de paquetes.
    GestorDePaquetes {
        /// El fichero de la base de datos.
        base: PathBuf,
    },
    /// Metadatos de compilacion incrustados en un binario: la lista de crates de
    /// `cargo-auditable`, la informacion de modulos de Go.
    MetadatosDeCompilacion {
        /// El binario.
        binario: PathBuf,
        /// Que formato se leyo.
        formato: &'static str,
    },
    /// Una firma conocida dentro de un fichero que ningun paquete reclama.
    ///
    /// Es la unica procedencia que es una inferencia y no un hecho declarado:
    /// ver [`crate::binario::FIRMAS`].
    Firma {
        /// El fichero.
        fichero: PathBuf,
        /// Que firma se reconocio.
        firma: &'static str,
    },
    /// Un manifiesto de dependencias: `Cargo.lock`, `package-lock.json`,
    /// `requirements.txt`.
    Manifiesto {
        /// El fichero.
        fichero: PathBuf,
    },
    /// Los metadatos de un paquete instalado (`*.dist-info/METADATA`).
    Instalado {
        /// El fichero de metadatos.
        fichero: PathBuf,
    },
}

impl Procedencia {
    /// Nombre estable, para agrupar.
    #[must_use]
    pub fn nombre(&self) -> &'static str {
        match self {
            Procedencia::GestorDePaquetes { .. } => "gestor-de-paquetes",
            Procedencia::MetadatosDeCompilacion { .. } => "metadatos-de-compilacion",
            Procedencia::Firma { .. } => "firma",
            Procedencia::Manifiesto { .. } => "manifiesto",
            Procedencia::Instalado { .. } => "instalado",
        }
    }

    /// Si es un hecho declarado por una fuente o una inferencia.
    #[must_use]
    pub fn es_inferencia(&self) -> bool {
        matches!(self, Procedencia::Firma { .. })
    }
}

/// La capa de una imagen de contenedor en la que aparecio un componente.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Capa {
    /// La imagen.
    pub imagen: String,
    /// El resumen de la capa (`sha256:...`).
    pub resumen: String,
    /// Su posicion, desde la base (0).
    pub indice: usize,
}

/// La identidad de un componente para desduplicar: ecosistema, nombre, version,
/// arquitectura y (imagen, capa).
pub type Clave<'a> = (
    Ecosistema,
    &'a str,
    &'a str,
    Option<&'a str>,
    Option<(&'a str, usize)>,
);

/// Un componente de software.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Componente {
    /// Ecosistema.
    pub ecosistema: Ecosistema,
    /// Nombre, tal como lo escribe su ecosistema.
    pub nombre: String,
    /// Version, tal como la escribe su ecosistema.
    pub version: String,
    /// El paquete fuente, cuando no se llama igual (Debian, Alpine).
    pub fuente: Option<String>,
    /// La version fuente, cuando difiere.
    pub version_fuente: Option<String>,
    /// Arquitectura, si se conoce.
    pub arquitectura: Option<String>,
    /// Distribucion, para los paquetes del sistema.
    pub distro: Option<Distro>,
    /// De donde salio.
    pub procedencia: Procedencia,
    /// En que capa de que imagen, si viene de un contenedor.
    pub capa: Option<Capa>,
    /// Los ficheros por los que un proceso lo puede tener cargado.
    ///
    /// Solo los que se proyectan en memoria —bibliotecas y ejecutables—, no los
    /// miles de ficheros de documentacion de un paquete: la pregunta que
    /// responden es «¿lo tiene cargado algun proceso?», y a esa solo contestan
    /// los ficheros que aparecen en un mapa de memoria.
    pub ficheros: Vec<PathBuf>,
    /// Si el componente trae codigo INTERPRETADO (Python, Perl, shell...).
    ///
    /// Un interprete lee ese codigo, no lo proyecta: no aparece en ningun mapa
    /// de memoria aunque se este ejecutando. Con codigo interpretado, «ningun
    /// mapa lo muestra» NO es «no esta cargado». `None` es que no se sabe;
    /// `Some(false)` es que se leyo la lista de ficheros y no hay.
    pub interpretado: Option<bool>,
}

impl Componente {
    /// Un componente minimo.
    #[must_use]
    pub fn nuevo(
        ecosistema: Ecosistema,
        nombre: impl Into<String>,
        version: impl Into<String>,
        procedencia: Procedencia,
    ) -> Componente {
        Componente {
            ecosistema,
            nombre: nombre.into(),
            version: version.into(),
            fuente: None,
            version_fuente: None,
            arquitectura: None,
            distro: None,
            procedencia,
            capa: None,
            ficheros: Vec::new(),
            interpretado: None,
        }
    }

    /// El nombre del paquete fuente: el declarado o el propio.
    #[must_use]
    pub fn nombre_fuente(&self) -> &str {
        self.fuente.as_deref().unwrap_or(&self.nombre)
    }

    /// La version fuente: la declarada o la propia.
    #[must_use]
    pub fn version_de_fuente(&self) -> &str {
        self.version_fuente.as_deref().unwrap_or(&self.version)
    }

    /// El purl del componente.
    #[must_use]
    pub fn purl(&self) -> String {
        let arq = self.arquitectura.as_deref().unwrap_or("");
        match self.ecosistema {
            Ecosistema::Deb | Ecosistema::Apk => {
                let (espacio, distro) = match &self.distro {
                    Some(d) => (d.id.as_str(), format!("{}-{}", d.id, d.version)),
                    None => ("", String::new()),
                };
                // `upstream` es el calificador con que las herramientas escriben el
                // paquete fuente, y es lo que casa con los avisos de la distro.
                let upstream = self.fuente.as_deref().unwrap_or("");
                purl::montar(
                    self.ecosistema.nombre(),
                    Some(espacio),
                    &self.nombre,
                    Some(&self.version),
                    &[("arch", arq), ("distro", &distro), ("upstream", upstream)],
                )
            }
            Ecosistema::Npm => match self.nombre.split_once('/') {
                Some((ambito, n)) if ambito.starts_with('@') => {
                    purl::montar("npm", Some(ambito), n, Some(&self.version), &[])
                }
                _ => purl::montar("npm", None, &self.nombre, Some(&self.version), &[]),
            },
            Ecosistema::PyPI => purl::montar(
                "pypi",
                None,
                &purl::normalizar_pypi(&self.nombre),
                Some(&self.version),
                &[],
            ),
            Ecosistema::Go => match self.nombre.rsplit_once('/') {
                Some((espacio, n)) => {
                    purl::montar("golang", Some(espacio), n, Some(&self.version), &[])
                }
                None => purl::montar("golang", None, &self.nombre, Some(&self.version), &[]),
            },
            Ecosistema::Cargo | Ecosistema::Generico => purl::montar(
                self.ecosistema.nombre(),
                None,
                &self.nombre,
                Some(&self.version),
                &[],
            ),
        }
    }

    /// La clave con la que se desduplica: ecosistema, nombre, version,
    /// arquitectura y capa.
    ///
    /// La procedencia NO entra: el mismo `serde 1.0.200` visto en el `Cargo.lock`
    /// y en los metadatos del binario compilado con el es un componente, no dos.
    /// La capa SI entra: el mismo paquete en dos imagenes son dos instalaciones.
    #[must_use]
    pub fn clave(&self) -> Clave<'_> {
        (
            self.ecosistema,
            &self.nombre,
            &self.version,
            self.arquitectura.as_deref(),
            self.capa.as_ref().map(|c| (c.imagen.as_str(), c.indice)),
        )
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn deb() -> Componente {
        let mut c = Componente::nuevo(
            Ecosistema::Deb,
            "libssl3t64",
            "3.0.13-0ubuntu3.4",
            Procedencia::GestorDePaquetes {
                base: "/var/lib/dpkg/status".into(),
            },
        );
        c.fuente = Some("openssl".into());
        c.arquitectura = Some("amd64".into());
        c.distro = Some(Distro {
            id: "ubuntu".into(),
            version: "24.04".into(),
        });
        c
    }

    #[test]
    fn el_purl_de_un_paquete_de_ubuntu_lleva_distro_y_fuente() {
        assert_eq!(
            deb().purl(),
            "pkg:deb/ubuntu/libssl3t64@3.0.13-0ubuntu3.4?arch=amd64&distro=ubuntu-24.04&upstream=openssl"
        );
    }

    #[test]
    fn el_purl_de_npm_con_ambito_y_de_go() {
        let n = Componente::nuevo(
            Ecosistema::Npm,
            "@babel/core",
            "7.24.0",
            Procedencia::Manifiesto {
                fichero: "package-lock.json".into(),
            },
        );
        assert_eq!(n.purl(), "pkg:npm/%40babel/core@7.24.0");
        let g = Componente::nuevo(
            Ecosistema::Go,
            "golang.org/x/net",
            "v0.17.0",
            Procedencia::MetadatosDeCompilacion {
                binario: "/usr/bin/x".into(),
                formato: "go-buildinfo",
            },
        );
        assert_eq!(g.purl(), "pkg:golang/golang.org/x/net@v0.17.0");
    }

    #[test]
    fn la_fuente_por_defecto_es_el_propio_paquete() {
        let mut c = deb();
        assert_eq!(c.nombre_fuente(), "openssl");
        c.fuente = None;
        assert_eq!(c.nombre_fuente(), "libssl3t64");
        assert_eq!(c.version_de_fuente(), "3.0.13-0ubuntu3.4");
    }

    #[test]
    fn la_procedencia_no_distingue_componentes_y_la_capa_si() {
        let a = deb();
        let mut b = deb();
        b.procedencia = Procedencia::Manifiesto {
            fichero: "x".into(),
        };
        assert_eq!(a.clave(), b.clave());
        b.capa = Some(Capa {
            imagen: "img".into(),
            resumen: "sha256:1".into(),
            indice: 0,
        });
        assert_ne!(a.clave(), b.clave());
    }
}
