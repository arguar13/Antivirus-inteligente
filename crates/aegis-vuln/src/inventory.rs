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
    /// El paquete FUENTE del que se construyo, cuando no se llama igual.
    ///
    /// Es lo que decide si una vulnerabilidad aplica: Debian y Ubuntu publican
    /// sus avisos —y OSV los indexa— por paquete fuente. El fallo de OpenSSL
    /// esta en `openssl`, y lo que hay instalado se llama `libssl3`. Correlacionar
    /// por el nombre binario no encuentra nada para casi ninguna biblioteca, y
    /// no lo dice.
    ///
    /// `None` significa que el gestor no declaro fuente, y entonces la fuente es
    /// el propio paquete: ver [`Package::source_name`].
    pub source_package: Option<String>,
    /// La version del paquete fuente, cuando difiere de la del binario.
    ///
    /// Pasa con los binNMU y con los paquetes que llevan version propia: dpkg lo
    /// escribe como `Source: zlib (1:1.3.dfsg-3)`. Los rangos de un aviso son de
    /// la version FUENTE.
    pub source_version: Option<Version>,
}

impl Package {
    /// El nombre del paquete fuente: el declarado o, si no hay, el propio.
    #[must_use]
    pub fn source_name(&self) -> &str {
        self.source_package.as_deref().unwrap_or(&self.name)
    }

    /// La version del paquete fuente: la declarada o, si no hay, la propia.
    #[must_use]
    pub fn source_version(&self) -> &Version {
        self.source_version.as_ref().unwrap_or(&self.version)
    }
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
///
/// # Multiarquitectura
///
/// Un mismo paquete puede estar instalado para dos arquitecturas a la vez
/// —`libc6:amd64` y `libc6:i386`—, y son dos instalaciones con sus ficheros y sus
/// vulnerabilidades. Indexar solo por nombre hacia que la segunda **pisara** a la
/// primera y el inventario perdia un paquete sin decirlo. Cuando un nombre
/// aparece con dos arquitecturas, las dos entradas pasan a `nombre:arq`, que es
/// como las nombra el propio dpkg, y el resultado no depende del orden en que
/// esten en el fichero.
pub fn parse_dpkg_status(texto: &str, salida: &mut BTreeMap<String, Package>) {
    let mut nombre = String::new();
    let mut version = String::new();
    let mut arch = String::new();
    let mut fuente = String::new();
    let mut instalado = false;

    let cerrar = |nombre: &mut String,
                  version: &mut String,
                  arch: &mut String,
                  fuente: &mut String,
                  instalado: &mut bool,
                  salida: &mut BTreeMap<String, Package>| {
        if *instalado && !nombre.is_empty() && !version.is_empty() {
            let (source_package, source_version) = analizar_source(fuente, nombre);
            insertar_multiarq(
                salida,
                Package {
                    name: std::mem::take(nombre),
                    version: Version::parse(version),
                    arch: std::mem::take(arch),
                    source: PackageSource::Dpkg,
                    source_package,
                    source_version,
                },
            );
        }
        nombre.clear();
        version.clear();
        arch.clear();
        fuente.clear();
        *instalado = false;
    };

    for linea in texto.lines() {
        if linea.is_empty() {
            cerrar(
                &mut nombre,
                &mut version,
                &mut arch,
                &mut fuente,
                &mut instalado,
                salida,
            );
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
            "Source" => fuente = valor.to_string(),
            // "install ok installed" es el unico estado que significa que el
            // software esta realmente en el disco.
            "Status" => instalado = valor.split_whitespace().nth(2) == Some("installed"),
            _ => {}
        }
    }
    cerrar(
        &mut nombre,
        &mut version,
        &mut arch,
        &mut fuente,
        &mut instalado,
        salida,
    );
}

/// Separa el campo `Source` de dpkg: `zlib` o `zlib (1:1.3.dfsg-3)`.
///
/// Devuelve `None` en el nombre cuando la fuente es el propio paquete, para que
/// «no declaro fuente» y «declaro la misma» se lean igual: en los dos casos la
/// fuente es el paquete.
fn analizar_source(campo: &str, paquete: &str) -> (Option<String>, Option<Version>) {
    let campo = campo.trim();
    if campo.is_empty() {
        return (None, None);
    }
    let (nombre, version) = match campo.split_once('(') {
        Some((n, resto)) => (n.trim(), resto.split(')').next().map(str::trim)),
        None => (campo, None),
    };
    let nombre = (!nombre.is_empty() && nombre != paquete).then(|| nombre.to_string());
    let version = version.filter(|v| !v.is_empty()).map(Version::parse);
    (nombre, version)
}

/// Inserta un paquete distinguiendo arquitecturas cuando el nombre se repite.
fn insertar_multiarq(salida: &mut BTreeMap<String, Package>, p: Package) {
    let calificada = |p: &Package| format!("{}:{}", p.name, p.arch);
    // Si ya hay una entrada calificada con este nombre, esta tambien lo va.
    let hay_calificadas = salida
        .range(format!("{}:", p.name)..)
        .next()
        .is_some_and(|(k, v)| v.name == p.name && k.starts_with(&format!("{}:", p.name)));
    if hay_calificadas {
        salida.insert(calificada(&p), p);
        return;
    }
    match salida.get(&p.name) {
        Some(previo) if previo.arch != p.arch => {
            // Segunda arquitectura: las dos pasan a nombre calificado.
            if let Some(previo) = salida.remove(&p.name) {
                salida.insert(calificada(&previo), previo);
            }
            salida.insert(calificada(&p), p);
        }
        _ => {
            salida.insert(p.name.clone(), p);
        }
    }
}

/// Analiza `/lib/apk/db/installed` (Alpine).
///
/// Formato de campos de una sola letra: `P:` nombre, `V:` version, `A:`
/// arquitectura y `o:` origen, que es el paquete fuente —el que usan los avisos
/// de Alpine, igual que en Debian—.
pub fn parse_apk_installed(texto: &str, salida: &mut BTreeMap<String, Package>) {
    let mut nombre = String::new();
    let mut version = String::new();
    let mut arch = String::new();
    let mut origen = String::new();

    let cerrar = |nombre: &mut String,
                  version: &mut String,
                  arch: &mut String,
                  origen: &mut String,
                  salida: &mut BTreeMap<String, Package>| {
        if !nombre.is_empty() && !version.is_empty() {
            let source_package =
                (!origen.is_empty() && origen != nombre).then(|| std::mem::take(origen));
            salida.insert(
                nombre.clone(),
                Package {
                    name: std::mem::take(nombre),
                    version: Version::parse(version),
                    arch: std::mem::take(arch),
                    source: PackageSource::Apk,
                    source_package,
                    // apk construye todos los subpaquetes de un origen con su
                    // misma version: no hay version fuente distinta que leer.
                    source_version: None,
                },
            );
        }
        nombre.clear();
        version.clear();
        arch.clear();
        origen.clear();
    };

    for linea in texto.lines() {
        if linea.is_empty() {
            cerrar(&mut nombre, &mut version, &mut arch, &mut origen, salida);
            continue;
        }
        // `split_at(2)` sobre una linea de menos de dos bytes, o que parte un
        // caracter multibyte, entraria en panico: una base de datos corrupta no
        // puede tumbar el inventario.
        let Some((clave, v)) = linea.get(..2).zip(linea.get(2..)) else {
            continue;
        };
        match clave {
            "P:" => nombre = v.to_string(),
            "V:" => version = v.to_string(),
            "A:" => arch = v.to_string(),
            "o:" => origen = v.to_string(),
            _ => {}
        }
    }
    cerrar(&mut nombre, &mut version, &mut arch, &mut origen, salida);
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
    fn dpkg_guarda_el_paquete_fuente_y_su_version() {
        // Los dos formatos reales del campo, copiados de un status de Ubuntu.
        let texto = "\
Package: libssl3t64
Status: install ok installed
Architecture: amd64
Source: openssl
Version: 3.0.13-0ubuntu3.4

Package: zlib1g
Status: install ok installed
Architecture: amd64
Source: zlib (1:1.3.dfsg-3.1ubuntu2)
Version: 1:1.3.dfsg-3.1ubuntu2.1

Package: bash
Status: install ok installed
Architecture: amd64
Version: 5.2.21-2ubuntu4
";
        let mut m = BTreeMap::new();
        parse_dpkg_status(texto, &mut m);
        assert_eq!(m["libssl3t64"].source_name(), "openssl");
        assert_eq!(
            m["libssl3t64"].source_version().to_string(),
            "3.0.13-0ubuntu3.4",
            "sin version fuente declarada, es la del binario"
        );
        assert_eq!(m["zlib1g"].source_name(), "zlib");
        assert_eq!(
            m["zlib1g"].source_version().to_string(),
            "1:1.3.dfsg-3.1ubuntu2",
            "la version fuente declarada manda sobre la del binario"
        );
        assert_eq!(m["bash"].source_name(), "bash");
        assert_eq!(m["bash"].source_package, None);
    }

    #[test]
    fn dpkg_no_pierde_la_segunda_arquitectura_de_un_paquete() {
        // Antes la segunda pisaba a la primera. El orden del fichero no puede
        // cambiar el resultado, asi que se prueba en los dos.
        let amd = "Package: libc6\nStatus: install ok installed\nArchitecture: amd64\n\
                   Source: glibc\nVersion: 2.39-0ubuntu8\n";
        let i386 = "Package: libc6\nStatus: install ok installed\nArchitecture: i386\n\
                    Source: glibc\nVersion: 2.39-0ubuntu8\n";
        let unico = "Package: bash\nStatus: install ok installed\nArchitecture: amd64\n\
                     Version: 5.2\n";
        for orden in [
            format!("{amd}\n{i386}\n{unico}"),
            format!("{i386}\n{unico}\n{amd}"),
        ] {
            let mut m = BTreeMap::new();
            parse_dpkg_status(&orden, &mut m);
            let claves: Vec<&str> = m.keys().map(String::as_str).collect();
            assert_eq!(claves, ["bash", "libc6:amd64", "libc6:i386"], "{orden}");
            assert_eq!(m["libc6:i386"].arch, "i386");
            assert_eq!(m["libc6:amd64"].name, "libc6");
        }
    }

    #[test]
    fn apk_guarda_el_origen_y_no_se_cae_con_una_linea_corta() {
        // `o:` es el paquete fuente en Alpine; la linea de un solo byte y la
        // que parte un caracter multibyte antes hacian entrar en panico.
        let texto = "P:libcrypto3\nV:3.1.4-r5\nA:x86_64\no:openssl\nx\n\u{e9}\n\nP:musl\nV:1.2.4-r2\no:musl\n";
        let mut m = BTreeMap::new();
        parse_apk_installed(texto, &mut m);
        assert_eq!(m["libcrypto3"].source_name(), "openssl");
        assert_eq!(
            m["musl"].source_package, None,
            "el origen es el propio paquete"
        );
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
