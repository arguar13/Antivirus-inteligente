//! Los paquetes del sistema, y que ficheros de cada uno puede tener cargados un
//! proceso.
//!
//! # El inventario lo lee `aegis-vuln`; aqui se le anaden los ficheros
//!
//! La lista de paquetes instalados sale de [`aegis_vuln::Inventory`], el mismo
//! lector que usa el escaner de vulnerabilidades: dos lectores de la base de
//! datos de dpkg acabarian discrepando sobre que hay instalado en la misma
//! maquina. Lo que se anade es lo que la pregunta de alcanzabilidad necesita:
//! **que ficheros materializan cada paquete**, porque «¿lo tiene cargado algun
//! proceso?» se contesta cruzando esos ficheros con los mapas de memoria.
//!
//! De la lista de ficheros de un paquete solo se guardan los que se pueden
//! proyectar en memoria —bibliotecas y ejecutables—. Un paquete de documentacion
//! tiene miles de ficheros que ningun mapa de memoria va a mostrar nunca, y
//! guardarlos todos multiplicaria la memoria del inventario por diez sin cambiar
//! una sola respuesta.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use aegis_vuln::inventory::{Package, PackageSource};
use aegis_vuln::Inventory;

use crate::componente::{Componente, Distro, Ecosistema, Procedencia};
use crate::inventario::{Estado, Fuente};

/// Tope de bytes de una lista de ficheros de un paquete.
///
/// La de `linux-modules` pasa del megabyte; ocho es holgado y sigue siendo un
/// tope frente a un fichero manipulado.
pub const MAX_LISTA: u64 = 8 * 1024 * 1024;

/// Tope de ficheros proyectables que se guardan por paquete.
pub const MAX_FICHEROS_POR_PAQUETE: usize = 4096;

/// Si una ruta es de las que pueden aparecer en un mapa de memoria como codigo.
///
/// Bibliotecas compartidas (`.so`, `.so.N`) y lo que esta en un directorio de
/// ejecutables. Es un criterio por nombre y no por contenido a proposito: se
/// aplica a decenas de miles de rutas, y abrir cada fichero para mirar su
/// cabecera costaria mas que el resto del inventario junto.
#[must_use]
pub fn es_proyectable(ruta: &str) -> bool {
    let nombre = ruta.rsplit('/').next().unwrap_or(ruta);
    if nombre.ends_with(".so") || nombre.contains(".so.") {
        return true;
    }
    let dir = ruta.rsplit_once('/').map_or("", |(d, _)| d);
    dir.ends_with("/bin") || dir.ends_with("/sbin") || dir.contains("/libexec")
}

/// La distribucion de la raiz, de `/etc/os-release`.
#[must_use]
pub fn distro_de(inv: &Inventory) -> Option<Distro> {
    let s = &inv.system;
    (!s.os_id.is_empty()).then(|| Distro {
        id: s.os_id.to_ascii_lowercase(),
        version: s.os_version.clone(),
    })
}

/// Extensiones de codigo que ejecuta un interprete.
const INTERPRETADO: &[&str] = &[
    ".py", ".pyc", ".pl", ".pm", ".rb", ".js", ".mjs", ".cjs", ".sh", ".bash", ".lua", ".php",
    ".tcl", ".jar", ".class",
];

/// Los ficheros de un paquete, clasificados para la pregunta «¿esta cargado?».
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Clasificados {
    /// Bibliotecas y ejecutables ELF: aparecen en un mapa de memoria.
    pub proyectables: Vec<PathBuf>,
    /// Si trae codigo interpretado, que no aparece en ninguno.
    pub interpretado: bool,
}

/// Si un fichero regular CON permiso de ejecucion empieza por la cabecera ELF.
///
/// `None` si no es un fichero regular ejecutable. Solo se abre lo que tiene el
/// bit de ejecucion: de los cien mil ficheros de una distribucion, unos pocos
/// miles, y la cabecera son cuatro bytes.
fn ejecutable(ruta: &Path) -> Option<bool> {
    use std::io::Read;
    let md = std::fs::symlink_metadata(ruta).ok()?;
    if !md.is_file() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if md.permissions().mode() & 0o111 == 0 {
            return None;
        }
    }
    let mut m = [0u8; 4];
    let n = std::fs::File::open(ruta).ok()?.read(&mut m).ok()?;
    Some(n == 4 && m == *b"\x7fELF")
}

/// Clasifica las rutas de un paquete.
///
/// Una biblioteca (`.so`) se da por proyectable por su nombre. Lo que esta en un
/// directorio de ejecutables NO: un script de Python en `/usr/bin` se ejecuta
/// con el interprete, y en el mapa de memoria aparece el interprete, no el
/// script. Contarlo como proyectable hacia salir «no cargado» un paquete en
/// uso. Por eso ahi se mira la cabecera: ELF es proyectable; lo demas,
/// interpretado.
#[must_use]
pub fn clasificar<'a>(raiz: &Path, rutas: impl Iterator<Item = &'a str>) -> Clasificados {
    let mut c = Clasificados::default();
    for r in rutas {
        let nombre = r.rsplit('/').next().unwrap_or(r);
        if INTERPRETADO.iter().any(|e| nombre.ends_with(e)) {
            c.interpretado = true;
            continue;
        }
        let es_biblioteca = nombre.ends_with(".so") || nombre.contains(".so.");
        // Un ejecutable NO se reconoce por el directorio. La primera version
        // solo miraba `bin`, `sbin` y `libexec`, y se le escapaban los que viven
        // en un directorio de bibliotecas: `/usr/lib/systemd/systemd` —el proceso
        // 1— o `/usr/lib/snapd/snapd`. El paquete de systemd salia «no cargado»
        // con systemd corriendo, y los modulos de Go de snapd no aparecian en el
        // inventario (la comparativa con Syft lo destapo). Lo que decide es el
        // fichero: regular, con permiso de ejecucion y cabecera ELF.
        let proyectable = es_biblioteca
            || match ejecutable(&raiz.join(r.trim_start_matches('/'))) {
                Some(true) => true,
                // Ejecutable sin cabecera ELF: un script, que corre en un
                // interprete y no aparece en los mapas.
                Some(false) => {
                    c.interpretado = true;
                    false
                }
                // No es un fichero regular ejecutable: no es codigo.
                None => false,
            };
        if proyectable && c.proyectables.len() < MAX_FICHEROS_POR_PAQUETE {
            c.proyectables.push(PathBuf::from(r));
        }
    }
    c
}

/// Lee y clasifica los ficheros de un paquete de dpkg.
///
/// dpkg nombra la lista `nombre.list` o, en los paquetes `Multi-Arch: same`,
/// `nombre:arq.list` aunque solo haya una arquitectura instalada. Se prueban las
/// dos.
fn ficheros_dpkg(raiz: &Path, p: &Package) -> Option<Clasificados> {
    let info = raiz.join("var/lib/dpkg/info");
    let candidatos = [
        info.join(format!("{}:{}.list", p.name, p.arch)),
        info.join(format!("{}.list", p.name)),
    ];
    for c in candidatos {
        let Ok(md) = std::fs::metadata(&c) else {
            continue;
        };
        if md.len() > MAX_LISTA {
            return None;
        }
        let texto = std::fs::read_to_string(&c).ok()?;
        return Some(clasificar(raiz, texto.lines()));
    }
    None
}

/// Los ficheros de cada paquete de Alpine, clasificados.
///
/// La base de datos de apk los trae dentro: `F:` abre un directorio y cada `R:`
/// es un fichero de ese directorio, del paquete de la ultima `P:`.
fn ficheros_apk(raiz: &Path, texto: &str) -> BTreeMap<String, Clasificados> {
    let mut rutas: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut paquete = String::new();
    let mut dir = String::new();
    for linea in texto.lines() {
        let Some((clave, v)) = linea.get(..2).zip(linea.get(2..)) else {
            continue;
        };
        match clave {
            "P:" => {
                paquete = v.to_string();
                dir.clear();
                rutas.entry(paquete.clone()).or_default();
            }
            "F:" => dir = v.to_string(),
            "R:" => {
                let e = rutas.entry(paquete.clone()).or_default();
                if e.len() < 4 * MAX_FICHEROS_POR_PAQUETE {
                    e.push(format!("/{dir}/{v}").replace("//", "/"));
                }
            }
            _ => {}
        }
    }
    rutas
        .into_iter()
        .map(|(p, r)| (p, clasificar(raiz, r.iter().map(String::as_str))))
        .collect()
}

/// Los paquetes del sistema bajo `raiz`, como componentes, y lo que se pudo leer.
#[must_use]
pub fn paquetes(raiz: &Path) -> (Vec<Componente>, Vec<Fuente>) {
    let inv = Inventory::collect(raiz);
    let distro = distro_de(&inv);
    let apk = std::fs::read_to_string(raiz.join("lib/apk/db/installed"))
        .map(|t| ficheros_apk(raiz, &t))
        .unwrap_or_default();

    let mut v = Vec::with_capacity(inv.packages.len());
    let mut sin_lista = 0usize;
    for p in inv.packages.values() {
        let (ecosistema, base, ficheros) = match p.source {
            PackageSource::Dpkg => (
                Ecosistema::Deb,
                "/var/lib/dpkg/status",
                ficheros_dpkg(raiz, p),
            ),
            PackageSource::Apk => (
                Ecosistema::Apk,
                "/lib/apk/db/installed",
                apk.get(&p.name).cloned(),
            ),
            // No hay lector de rpm: `aegis-vuln` declara la variante y no la
            // produce. Si algun dia la produce, aqui se vera como paquete sin
            // ecosistema en vez de mezclarse con Debian.
            PackageSource::Rpm => continue,
        };
        if ficheros.is_none() {
            sin_lista += 1;
        }
        let mut c = Componente::nuevo(
            ecosistema,
            p.name.clone(),
            p.version.to_string(),
            Procedencia::GestorDePaquetes {
                base: PathBuf::from(base),
            },
        );
        c.fuente = p.source_package.clone();
        c.version_fuente = p.source_version.as_ref().map(ToString::to_string);
        c.arquitectura = (!p.arch.is_empty()).then(|| p.arch.clone());
        c.distro = distro.clone();
        if let Some(f) = ficheros {
            c.ficheros = f.proyectables;
            c.interpretado = Some(f.interpretado);
        }
        v.push(c);
    }

    let mut fuentes = Vec::new();
    for (nombre, rel, eco) in [
        ("dpkg", "var/lib/dpkg/status", Ecosistema::Deb),
        ("apk", "lib/apk/db/installed", Ecosistema::Apk),
    ] {
        let n = v.iter().filter(|c| c.ecosistema == eco).count();
        let estado = if !raiz.join(rel).exists() {
            Estado::Ausente
        } else if eco == Ecosistema::Deb && sin_lista > 0 {
            // Un paquete sin lista de ficheros no puede decir si esta cargado:
            // se cuenta, porque es la diferencia entre «no lo carga nadie» y «no
            // se sabe que ficheros son suyos».
            Estado::Parcial {
                leidos: n,
                motivo: format!("{sin_lista} paquete(s) sin lista de ficheros legible"),
            }
        } else {
            Estado::Leida { componentes: n }
        };
        fuentes.push(Fuente {
            nombre: nombre.into(),
            estado,
        });
    }
    // El lector de rpm no existe: se dice, no se calla.
    if raiz.join("var/lib/rpm").exists() {
        fuentes.push(Fuente {
            nombre: "rpm".into(),
            estado: Estado::NoSoportada {
                motivo: "hay base de datos de rpm y no hay lector: sus paquetes no estan en el \
                         inventario"
                    .into(),
            },
        });
    }
    (v, fuentes)
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn solo_se_guardan_los_ficheros_que_pueden_estar_en_memoria() {
        assert!(es_proyectable("/usr/lib/x86_64-linux-gnu/libz.so.1.3.1"));
        assert!(es_proyectable("/lib/x86_64-linux-gnu/libz.so.1"));
        assert!(es_proyectable("/usr/lib/x86_64-linux-gnu/libfoo.so"));
        assert!(es_proyectable("/usr/bin/curl"));
        assert!(es_proyectable("/usr/sbin/sshd"));
        assert!(es_proyectable("/usr/libexec/openssh/sftp-server"));
        assert!(!es_proyectable("/usr/share/doc/zlib1g/copyright"));
        assert!(!es_proyectable(
            "/usr/lib/x86_64-linux-gnu/pkgconfig/zlib.pc"
        ));
        assert!(!es_proyectable("/usr/share/man/man3/zlib.3.gz"));
    }

    /// Una raiz con un ELF y un script en `/bin`.
    fn raiz_con_bin(n: &str) -> PathBuf {
        let r = std::env::temp_dir().join(format!("aegis-sbom-sis-{n}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&r);
        std::fs::create_dir_all(r.join("bin")).unwrap();
        std::fs::write(r.join("bin/busybox"), b"\x7fELF\x02\x01\x01").unwrap();
        std::fs::write(r.join("bin/herramienta"), b"#!/usr/bin/python3\nprint(1)\n").unwrap();
        // Un ejecutable en un directorio de bibliotecas, como systemd.
        std::fs::create_dir_all(r.join("usr/lib/systemd")).unwrap();
        std::fs::write(r.join("usr/lib/systemd/systemd"), b"\x7fELF\x02\x01\x01").unwrap();
        // Un fichero de datos sin permiso de ejecucion, aunque empiece por ELF.
        std::fs::write(r.join("usr/lib/systemd/datos"), b"\x7fELF").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for f in ["bin/busybox", "bin/herramienta", "usr/lib/systemd/systemd"] {
                std::fs::set_permissions(r.join(f), std::fs::Permissions::from_mode(0o755))
                    .unwrap();
            }
        }
        r
    }

    #[test]
    fn los_ficheros_de_apk_se_atribuyen_a_su_paquete() {
        let r = raiz_con_bin("apk");
        let db = "P:libcrypto3\nV:3.1.4-r5\nF:usr/lib\nR:libcrypto.so.3\nR:engines-3.txt\n\n\
                  P:busybox\nV:1.36\nF:bin\nR:busybox\nF:etc\nR:securetty\n\n\
                  P:tzdata\nV:2024a\nF:usr/share/zoneinfo\nR:UTC\n";
        let m = ficheros_apk(&r, db);
        assert_eq!(
            m["libcrypto3"].proyectables,
            [PathBuf::from("/usr/lib/libcrypto.so.3")]
        );
        assert_eq!(m["busybox"].proyectables, [PathBuf::from("/bin/busybox")]);
        assert!(!m["tzdata"].interpretado && m["tzdata"].proyectables.is_empty());
        let _ = std::fs::remove_dir_all(&r);
    }

    #[test]
    fn un_script_en_bin_es_codigo_interpretado_y_no_proyectable() {
        // Un script de Python en /usr/bin se ejecuta con el interprete: en el
        // mapa aparece python, no el script. Contarlo como proyectable hacia
        // salir «no cargado» un paquete en uso.
        let r = raiz_con_bin("script");
        let c = clasificar(&r, ["/bin/busybox", "/bin/herramienta"].into_iter());
        assert_eq!(c.proyectables, [PathBuf::from("/bin/busybox")]);
        assert!(c.interpretado);
        // Un ejecutable ELF fuera de `bin` es proyectable; un fichero sin permiso
        // de ejecucion no es codigo aunque empiece por ELF.
        let c = clasificar(
            &r,
            ["/usr/lib/systemd/systemd", "/usr/lib/systemd/datos"].into_iter(),
        );
        assert_eq!(c.proyectables, [PathBuf::from("/usr/lib/systemd/systemd")]);
        assert!(!c.interpretado);
        let c = clasificar(&r, ["/usr/lib/python3/dist-packages/a/b.py"].into_iter());
        assert!(c.interpretado && c.proyectables.is_empty());
        let _ = std::fs::remove_dir_all(&r);
    }
}
