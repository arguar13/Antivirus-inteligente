//! Inventario de software del host.
//!
//! Sin inventario no hay escaneo de vulnerabilidades: la pregunta "estoy
//! expuesto a CVE-X" es exactamente "tengo instalado el paquete Y en una
//! version dentro del rango afectado".
//!
//! Se lee la base de datos del gestor de paquetes DIRECTAMENTE en vez de
//! invocar `dpkg-query` o `rpm -qa`. Tres razones: funciona en contenedores
//! donde el binario del gestor no esta instalado pero su base de datos si;
//! no lanza procesos, que en un producto que vigila ejecuciones significaria
//! generar su propia telemetria; y no depende de que el formato de salida del
//! comando no cambie entre versiones.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::version::Version;

/// Un paquete instalado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    /// Nombre del paquete.
    pub name: String,
    /// Version instalada.
    pub version: Version,
    /// Arquitectura, si el gestor la declara.
    pub arch: String,
    /// Origen del dato.
    pub source: PackageSource,
}

/// Gestor de paquetes del que proviene la informacion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageSource {
    /// Base de datos de dpkg (Debian, Ubuntu).
    Dpkg,
    /// Base de datos de apk (Alpine).
    Apk,
    /// Salida de rpm (Fedora, RHEL, SUSE).
    Rpm,
}

/// Informacion del sistema operativo y del kernel.
#[derive(Debug, Clone, Default)]
pub struct SystemInfo {
    /// Version del kernel, tal y como la publica `/proc/sys/kernel/osrelease`.
    pub kernel_release: String,
    /// Version del kernel ya analizada, para comparar con rangos de CVE.
    pub kernel_version: Option<Version>,
    /// Identificador de la distribucion (`ID` de `/etc/os-release`).
    pub os_id: String,
    /// Version de la distribucion (`VERSION_ID`).
    pub os_version: String,
    /// Nombre legible de la distribucion.
    pub os_pretty: String,
}

/// Inventario completo del host.
#[derive(Debug, Clone, Default)]
pub struct Inventory {
    /// Informacion del sistema.
    pub system: SystemInfo,
    /// Paquetes instalados, indexados por nombre.
    ///
    /// Se usa `BTreeMap` y no `HashMap` para que el informe salga en orden
    /// estable: un informe de seguridad que cambia de orden entre ejecuciones
    /// es imposible de comparar con el anterior.
    pub packages: BTreeMap<String, Package>,
}

impl Inventory {
    /// Recoge el inventario del host, tomando `root` como raiz.
    ///
    /// El parametro `root` existe para poder probar el escaner contra arboles
    /// de ficheros sinteticos: un escaner de postura que solo se puede probar
    /// modificando la maquina real no se prueba.
    pub fn collect(root: &Path) -> Inventory {
        Inventory {
            system: collect_system(root),
            packages: collect_packages(root),
        }
    }

    /// Numero de paquetes inventariados.
    pub fn len(&self) -> usize {
        self.packages.len()
    }

    /// Indica si no se pudo inventariar ningun paquete.
    pub fn is_empty(&self) -> bool {
        self.packages.is_empty()
    }
}

fn leer(root: &Path, rel: &str) -> Option<String> {
    std::fs::read_to_string(root.join(rel.trim_start_matches('/'))).ok()
}

fn collect_system(root: &Path) -> SystemInfo {
    let kernel_release = leer(root, "/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    let mut info = SystemInfo {
        kernel_version: if kernel_release.is_empty() {
            None
        } else {
            Some(Version::parse(&kernel_release))
        },
        kernel_release,
        ..Default::default()
    };

    if let Some(os) = leer(root, "/etc/os-release") {
        for linea in os.lines() {
            let Some((clave, valor)) = linea.split_once('=') else {
                continue;
            };
            let valor = valor.trim().trim_matches('"').to_string();
            match clave.trim() {
                "ID" => info.os_id = valor,
                "VERSION_ID" => info.os_version = valor,
                "PRETTY_NAME" => info.os_pretty = valor,
                _ => {}
            }
        }
    }
    info
}

fn collect_packages(root: &Path) -> BTreeMap<String, Package> {
    let mut paquetes = BTreeMap::new();

    if let Some(texto) = leer(root, "/var/lib/dpkg/status") {
        parse_dpkg_status(&texto, &mut paquetes);
    }
    if let Some(texto) = leer(root, "/lib/apk/db/installed") {
        parse_apk_installed(&texto, &mut paquetes);
    }

    paquetes
}

/// Analiza `/var/lib/dpkg/status`.
///
/// El formato son parrafos separados por linea en blanco, con campos
/// `Clave: valor`. Solo cuentan los paquetes cuyo campo `Status` indica
/// `installed`: la base de datos conserva entradas de paquetes desinstalados
/// pero con configuracion residual, y contarlos como instalados inventaria
/// software que no esta en el disco y genera CVE fantasma.
pub fn parse_dpkg_status(texto: &str, salida: &mut BTreeMap<String, Package>) {
    let mut nombre = String::new();
    let mut version = String::new();
    let mut arch = String::new();
    let mut instalado = false;

    let cerrar = |nombre: &mut String,
                  version: &mut String,
                  arch: &mut String,
                  instalado: &mut bool,
                  salida: &mut BTreeMap<String, Package>| {
        if *instalado && !nombre.is_empty() && !version.is_empty() {
            salida.insert(
                nombre.clone(),
                Package {
                    name: std::mem::take(nombre),
                    version: Version::parse(version),
                    arch: std::mem::take(arch),
                    source: PackageSource::Dpkg,
                },
            );
        }
        nombre.clear();
        version.clear();
        arch.clear();
        *instalado = false;
    };

    for linea in texto.lines() {
        if linea.is_empty() {
            cerrar(&mut nombre, &mut version, &mut arch, &mut instalado, salida);
            continue;
        }
        // Las lineas de continuacion empiezan por espacio y no son campos.
        if linea.starts_with(' ') || linea.starts_with('\t') {
            continue;
        }
        let Some((clave, valor)) = linea.split_once(':') else {
            continue;
        };
        let valor = valor.trim();
        match clave {
            "Package" => nombre = valor.to_string(),
            "Version" => version = valor.to_string(),
            "Architecture" => arch = valor.to_string(),
            // "install ok installed" es el unico estado que significa que el
            // software esta realmente en el disco.
            "Status" => instalado = valor.split_whitespace().nth(2) == Some("installed"),
            _ => {}
        }
    }
    cerrar(&mut nombre, &mut version, &mut arch, &mut instalado, salida);
}

/// Analiza `/lib/apk/db/installed` (Alpine).
///
/// Formato de campos de una sola letra: `P:` nombre, `V:` version, `A:` arquitectura.
pub fn parse_apk_installed(texto: &str, salida: &mut BTreeMap<String, Package>) {
    let mut nombre = String::new();
    let mut version = String::new();
    let mut arch = String::new();

    for linea in texto.lines() {
        if linea.is_empty() {
            if !nombre.is_empty() && !version.is_empty() {
                salida.insert(
                    nombre.clone(),
                    Package {
                        name: std::mem::take(&mut nombre),
                        version: Version::parse(&version),
                        arch: std::mem::take(&mut arch),
                        source: PackageSource::Apk,
                    },
                );
            }
            nombre.clear();
            version.clear();
            arch.clear();
            continue;
        }
        match linea.split_at(2) {
            ("P:", v) => nombre = v.to_string(),
            ("V:", v) => version = v.to_string(),
            ("A:", v) => arch = v.to_string(),
            _ => {}
        }
    }
    if !nombre.is_empty() && !version.is_empty() {
        salida.insert(
            nombre.clone(),
            Package {
                name: nombre,
                version: Version::parse(&version),
                arch,
                source: PackageSource::Apk,
            },
        );
    }
}

/// Rutas de las bases de datos que el inventario sabe leer.
pub fn known_package_databases() -> [PathBuf; 2] {
    [
        PathBuf::from("/var/lib/dpkg/status"),
        PathBuf::from("/lib/apk/db/installed"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpkg_ignora_los_paquetes_solo_con_configuracion_residual() {
        let texto = "\
Package: openssl
Status: install ok installed
Architecture: amd64
Version: 3.0.2-0ubuntu1.10

Package: fantasma
Status: deinstall ok config-files
Architecture: amd64
Version: 1.0-1

Package: sudo
Status: install ok installed
Architecture: amd64
Version: 1.9.15p5-3ubuntu5
";
        let mut m = BTreeMap::new();
        parse_dpkg_status(texto, &mut m);

        assert_eq!(m.len(), 2);
        assert!(m.contains_key("openssl"));
        assert!(m.contains_key("sudo"));
        // Contar los residuales inventaria software que no esta en el disco y
        // genera CVE fantasma.
        assert!(!m.contains_key("fantasma"));
        assert_eq!(m["openssl"].version.to_string(), "3.0.2-0ubuntu1.10");
    }

    #[test]
    fn dpkg_ignora_lineas_de_continuacion() {
        let texto = "\
Package: bash
Status: install ok installed
Version: 5.2.21-2ubuntu4
Description: GNU Bourne Again SHell
 Bash is an sh-compatible command language interpreter.
 Version: esto no es un campo
";
        let mut m = BTreeMap::new();
        parse_dpkg_status(texto, &mut m);
        assert_eq!(m["bash"].version.to_string(), "5.2.21-2ubuntu4");
    }

    #[test]
    fn apk_se_analiza() {
        let texto = "P:musl\nV:1.2.4-r2\nA:x86_64\n\nP:busybox\nV:1.36.1-r15\nA:x86_64\n";
        let mut m = BTreeMap::new();
        parse_apk_installed(texto, &mut m);
        assert_eq!(m.len(), 2);
        assert_eq!(m["musl"].version.to_string(), "1.2.4-r2");
        assert_eq!(m["busybox"].source, PackageSource::Apk);
    }

    #[test]
    fn el_inventario_del_host_real_encuentra_algo() {
        let inv = Inventory::collect(Path::new("/"));
        assert!(
            !inv.system.kernel_release.is_empty(),
            "debe leerse el kernel"
        );
        // En una imagen Debian o Ubuntu tiene que haber paquetes; en otra base
        // el inventario puede estar vacio y eso no es un fallo de la prueba.
        if Path::new("/var/lib/dpkg/status").exists() {
            assert!(inv.len() > 10, "solo {} paquetes inventariados", inv.len());
        }
    }
}
