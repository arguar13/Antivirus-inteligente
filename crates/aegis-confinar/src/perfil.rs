//! El perfil aprendido, como TIPO.
//!
//! # Lo que se guarda y lo que se generaliza
//!
//! De la observacion salen hechos exactos: «abrio `/usr/lib/x86_64-linux-gnu/libc.so.6`
//! para leer». Un perfil que los copiara tal cual seria fragil hasta lo inutil: la
//! siguiente actualizacion de la biblioteca cambia el nombre del fichero y el
//! programa deja de arrancar. Y uno que generalizara sin criterio seria inutil
//! en el otro sentido: «puede leer `/`» no confina nada.
//!
//! Las reglas de generalizacion, escritas y probadas:
//!
//! 1. **Prefijos del sistema** (`/usr`, `/lib`, `/lib64`, `/bin`, `/sbin` y la
//!    cache del enlazador): cualquier lectura o ejecucion debajo da el prefijo
//!    entero en lectura. Es donde viven las bibliotecas, y cambian con cada
//!    actualizacion.
//! 2. **Directorios sensibles** (`/etc`, `/root`, `/home`, `/var/lib`, `/boot`,
//!    `/dev`, `/run`): se concede el FICHERO concreto, nunca el directorio. Que un
//!    programa lea `/etc/hostname` no le da `/etc/shadow`.
//! 3. **`/proc` y `/sys`**: el directorio entero en lectura. Un proceso lee su
//!    propio `/proc/self`, y el nombre cambia con cada PID.
//! 4. **Lo demas**: el directorio que lo contiene.
//! 5. **Escrituras**: crear o borrar necesita el directorio (es una entrada del
//!    directorio); escribir un fichero existente, el fichero si esta en un
//!    directorio sensible y el directorio si no.
//!
//! Y un tope: si las reglas pasan de [`MAX_REGLAS`], se suben de nivel las mas
//! profundas hasta que quepan, sin llegar nunca a `/`. Si ni asi caben, se dice
//! en [`Perfil::avisos`] en vez de conceder de mas en silencio.
//!
//! # Capacidades
//!
//! Las deducibles salen de la observacion (ver [`crate::observacion`]). Las
//! implicitas —`CAP_DAC_OVERRIDE` y compania— se conservan si el proceso corria
//! como root, porque ninguna llamada dice si las usa. Todo lo demas se quita.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use aegis_sandbox::policy::FsPolicy;
use aegis_sandbox::syscalls;

use crate::observacion::{cap, Acceso, Observacion};

/// Tope de reglas de Landlock de un perfil.
pub const MAX_REGLAS: usize = 128;

/// Prefijos del sistema: lectura del prefijo entero.
const PREFIJOS_SISTEMA: &[&str] = &["/usr", "/lib", "/lib64", "/lib32", "/bin", "/sbin"];
/// Directorios donde se concede el fichero y no el directorio.
const SENSIBLES: &[&str] = &[
    "/etc", "/root", "/home", "/var/lib", "/boot", "/dev", "/run",
];
/// Pseudo-sistemas de ficheros que se conceden enteros en lectura.
const PSEUDO: &[&str] = &["/proc", "/sys"];

/// El perfil de un programa.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Perfil {
    /// El ejecutable (ruta real).
    pub ejecutable: PathBuf,
    /// Llamadas usadas.
    pub llamadas: BTreeSet<u32>,
    /// Familias de socket usadas.
    pub dominios: BTreeSet<u32>,
    /// Ficheros leidos o ejecutados, tal cual.
    pub lecturas: BTreeSet<PathBuf>,
    /// Ficheros escritos, tal cual.
    pub escrituras: BTreeSet<PathBuf>,
    /// Entradas creadas o borradas, tal cual.
    pub entradas: BTreeSet<PathBuf>,
    /// Puertos a los que se conecto (familia, puerto).
    pub conexiones: BTreeSet<(u16, u16)>,
    /// Puertos en los que escucho.
    pub escuchas: BTreeSet<(u16, u16)>,
    /// Capacidades deducidas.
    pub capacidades: u64,
    /// Si corria como root (y por tanto conserva las implicitas).
    pub root: bool,
    /// Cuantas observaciones lo sostienen.
    pub observaciones: u64,
    /// Cuantas ejecuciones de aprendizaje se fusionaron en el.
    pub ejecuciones: u32,
}

/// Si `ruta` esta debajo de `base`.
fn debajo(ruta: &Path, base: &Path) -> bool {
    ruta.starts_with(base)
}

fn prefijo_sistema(r: &Path) -> Option<&'static str> {
    PREFIJOS_SISTEMA
        .iter()
        .find(|p| debajo(r, Path::new(p)))
        .copied()
}

fn es_sensible(r: &Path) -> bool {
    SENSIBLES.iter().any(|s| debajo(r, Path::new(s)))
}

fn pseudo(r: &Path) -> Option<&'static str> {
    PSEUDO.iter().find(|p| debajo(r, Path::new(p))).copied()
}

fn padre(r: &Path) -> PathBuf {
    r.parent()
        .filter(|p| *p != Path::new("/"))
        .map_or_else(|| r.to_path_buf(), Path::to_path_buf)
}

impl Perfil {
    /// Un perfil vacio para un ejecutable.
    #[must_use]
    pub fn nuevo(ejecutable: &Path) -> Perfil {
        Perfil {
            ejecutable: ejecutable.to_path_buf(),
            ..Default::default()
        }
    }

    /// Anota un hecho.
    pub fn anotar(&mut self, o: &Observacion) {
        self.observaciones += 1;
        match o {
            Observacion::Llamada(nr) => {
                self.llamadas.insert(*nr);
            }
            Observacion::Fichero { ruta, acceso } => match acceso {
                Acceso::Lectura | Acceso::Ejecucion => {
                    self.lecturas.insert(ruta.clone());
                }
                Acceso::Escritura => {
                    self.escrituras.insert(ruta.clone());
                }
                Acceso::Creacion | Acceso::Borrado => {
                    self.entradas.insert(ruta.clone());
                }
            },
            Observacion::Socket { dominio, .. } => {
                self.dominios.insert(*dominio);
            }
            Observacion::Conexion { familia, puerto } => {
                self.conexiones.insert((*familia, *puerto));
            }
            Observacion::Escucha { familia, puerto } => {
                self.escuchas.insert((*familia, *puerto));
            }
            Observacion::Capacidad(c) => {
                if *c < 64 {
                    self.capacidades |= 1 << c;
                }
            }
        }
    }

    /// Fusiona otra ejecucion de aprendizaje: un programa no hace lo mismo en
    /// cada arranque, y el perfil tiene que cubrir la union.
    pub fn fusionar(&mut self, otro: &Perfil) {
        self.llamadas.extend(&otro.llamadas);
        self.dominios.extend(&otro.dominios);
        self.lecturas.extend(otro.lecturas.iter().cloned());
        self.escrituras.extend(otro.escrituras.iter().cloned());
        self.entradas.extend(otro.entradas.iter().cloned());
        self.conexiones.extend(&otro.conexiones);
        self.escuchas.extend(&otro.escuchas);
        self.capacidades |= otro.capacidades;
        self.root |= otro.root;
        self.observaciones += otro.observaciones;
        self.ejecuciones += otro.ejecuciones;
    }

    /// Las capacidades que el proceso conserva al imponerse el perfil.
    #[must_use]
    pub fn capacidades_retenidas(&self) -> u64 {
        if self.root {
            self.capacidades | cap::IMPLICITAS
        } else {
            self.capacidades
        }
    }

    /// Las reglas de Landlock, generalizadas.
    #[must_use]
    pub fn reglas(&self) -> (FsPolicy, Vec<String>) {
        let mut avisos = Vec::new();
        let mut lectura: BTreeSet<PathBuf> = BTreeSet::new();
        let mut escritura: BTreeSet<PathBuf> = BTreeSet::new();

        for r in &self.lecturas {
            let regla = if let Some(p) = prefijo_sistema(r) {
                PathBuf::from(p)
            } else if let Some(p) = pseudo(r) {
                PathBuf::from(p)
            } else if es_sensible(r) {
                r.clone()
            } else {
                padre(r)
            };
            lectura.insert(regla);
        }
        // La cache del enlazador vive en /etc y la necesita todo binario dinamico.
        if self
            .lecturas
            .iter()
            .any(|r| r == Path::new("/etc/ld.so.cache"))
        {
            lectura.insert(PathBuf::from("/etc/ld.so.cache"));
        }
        for r in &self.escrituras {
            escritura.insert(if es_sensible(r) { r.clone() } else { padre(r) });
        }
        for r in &self.entradas {
            let p = padre(r);
            if es_sensible(&p) && p.components().count() <= 2 {
                avisos.push(format!(
                    "el programa crea o borra entradas en {}: se concede ese directorio en escritura",
                    p.display()
                ));
            }
            escritura.insert(p);
        }
        // Lo que ya esta en escritura no hace falta repetirlo en lectura.
        lectura.retain(|l| !escritura.iter().any(|e| debajo(l, e)));

        // El tope: se suben de nivel las reglas mas profundas.
        let total = |l: &BTreeSet<PathBuf>, e: &BTreeSet<PathBuf>| l.len() + e.len();
        let mut rondas = 0;
        while total(&lectura, &escritura) > MAX_REGLAS && rondas < 16 {
            rondas += 1;
            let subir = |s: &BTreeSet<PathBuf>| -> BTreeSet<PathBuf> {
                let profundidad = s.iter().map(|p| p.components().count()).max().unwrap_or(0);
                s.iter()
                    .map(|p| {
                        if p.components().count() == profundidad && profundidad > 2 {
                            padre(p)
                        } else {
                            p.clone()
                        }
                    })
                    .collect()
            };
            lectura = subir(&lectura);
            escritura = subir(&escritura);
        }
        if total(&lectura, &escritura) > MAX_REGLAS {
            avisos.push(format!(
                "{} reglas, por encima del tope de {MAX_REGLAS}: el perfil concede mas de lo \
                 que Landlock puede expresar con precision",
                total(&lectura, &escritura)
            ));
        }
        (
            FsPolicy {
                read_only: lectura.into_iter().collect(),
                read_write: escritura.into_iter().collect(),
            },
            avisos,
        )
    }

    /// Los avisos del perfil.
    #[must_use]
    pub fn avisos(&self) -> Vec<String> {
        self.reglas().1
    }

    /// Si el perfil permite tocar esta ruta de esta manera. Es lo que usa el
    /// modo permisivo para anotar lo que habria bloqueado.
    #[must_use]
    pub fn permite_ruta(&self, ruta: &Path, acceso: Acceso) -> bool {
        let (fs, _) = self.reglas();
        let en = |v: &[PathBuf]| v.iter().any(|b| debajo(ruta, b));
        match acceso {
            Acceso::Lectura | Acceso::Ejecucion => en(&fs.read_only) || en(&fs.read_write),
            Acceso::Escritura => en(&fs.read_write),
            Acceso::Creacion | Acceso::Borrado => {
                let p = padre(ruta);
                fs.read_write
                    .iter()
                    .any(|b| debajo(&p, b) || debajo(ruta, b))
            }
        }
    }

    /// El perfil en texto, determinista: el mismo aprendizaje da el mismo texto,
    /// y dos perfiles se comparan con un `diff`.
    #[must_use]
    pub fn texto(&self) -> String {
        let mut s = format!("perfil {}\n", self.ejecutable.display());
        s.push_str(&format!(
            "# {} observaciones en {} ejecucion(es); root: {}\n",
            self.observaciones,
            self.ejecuciones,
            if self.root { "si" } else { "no" }
        ));
        for nr in &self.llamadas {
            match syscalls::nombre(*nr) {
                Some(n) => s.push_str(&format!("llamada {n}\n")),
                None => s.push_str(&format!("llamada #{nr}\n")),
            }
        }
        for d in &self.dominios {
            s.push_str(&format!("socket {d}\n"));
        }
        let (fs, avisos) = self.reglas();
        for r in &fs.read_only {
            s.push_str(&format!("lee {}\n", r.display()));
        }
        for r in &fs.read_write {
            s.push_str(&format!("escribe {}\n", r.display()));
        }
        for (f, p) in &self.conexiones {
            s.push_str(&format!("conecta {f}:{p}\n"));
        }
        for (f, p) in &self.escuchas {
            s.push_str(&format!("escucha {f}:{p}\n"));
        }
        s.push_str(&format!(
            "capacidades {:#x}\n",
            self.capacidades_retenidas()
        ));
        for a in avisos {
            s.push_str(&format!("# AVISO: {a}\n"));
        }
        s
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn leer(p: &mut Perfil, r: &str) {
        p.anotar(&Observacion::Fichero {
            ruta: PathBuf::from(r),
            acceso: Acceso::Lectura,
        });
    }

    #[test]
    fn las_bibliotecas_dan_el_prefijo_y_etc_da_el_fichero_nunca_el_directorio() {
        let mut p = Perfil::nuevo(Path::new("/usr/bin/x"));
        leer(&mut p, "/usr/lib/x86_64-linux-gnu/libc.so.6");
        leer(&mut p, "/etc/hostname");
        leer(&mut p, "/etc/ld.so.cache");
        leer(&mut p, "/proc/1234/status");
        leer(&mut p, "/srv/app/datos/a.json");
        let (fs, _) = p.reglas();
        assert!(fs.read_only.contains(&PathBuf::from("/usr")));
        assert!(fs.read_only.contains(&PathBuf::from("/etc/hostname")));
        assert!(
            !fs.read_only.contains(&PathBuf::from("/etc")),
            "leer un fichero de /etc no da /etc"
        );
        assert!(fs.read_only.contains(&PathBuf::from("/proc")));
        assert!(fs.read_only.contains(&PathBuf::from("/srv/app/datos")));
        assert!(p.permite_ruta(Path::new("/etc/hostname"), Acceso::Lectura));
        assert!(!p.permite_ruta(Path::new("/etc/shadow"), Acceso::Lectura));
        assert!(!p.permite_ruta(Path::new("/etc/hostname"), Acceso::Escritura));
    }

    #[test]
    fn crear_un_fichero_concede_su_directorio_en_escritura() {
        let mut p = Perfil::nuevo(Path::new("/usr/bin/x"));
        p.anotar(&Observacion::Fichero {
            ruta: PathBuf::from("/var/tmp/app/cola/0001.tmp"),
            acceso: Acceso::Creacion,
        });
        let (fs, _) = p.reglas();
        assert_eq!(fs.read_write, vec![PathBuf::from("/var/tmp/app/cola")]);
        assert!(p.permite_ruta(Path::new("/var/tmp/app/cola/0002.tmp"), Acceso::Creacion));
        assert!(!p.permite_ruta(Path::new("/var/tmp/otro/x"), Acceso::Creacion));
    }

    #[test]
    fn crear_en_un_directorio_sensible_se_avisa() {
        let mut p = Perfil::nuevo(Path::new("/usr/bin/x"));
        p.anotar(&Observacion::Fichero {
            ruta: PathBuf::from("/etc/nuevo.conf"),
            acceso: Acceso::Creacion,
        });
        assert!(
            p.avisos().iter().any(|a| a.contains("/etc")),
            "{:?}",
            p.avisos()
        );
    }

    #[test]
    fn el_tope_sube_de_nivel_sin_llegar_nunca_a_la_raiz() {
        let mut p = Perfil::nuevo(Path::new("/usr/bin/x"));
        for i in 0..300 {
            leer(&mut p, &format!("/datos/cliente{}/sub/f", i % 150));
        }
        let (fs, _) = p.reglas();
        assert!(
            fs.read_only.len() + fs.read_write.len() <= MAX_REGLAS,
            "{}",
            fs.read_only.len()
        );
        assert!(!fs.read_only.contains(&PathBuf::from("/")));
    }

    #[test]
    fn las_capacidades_implicitas_solo_se_conservan_en_root() {
        let mut p = Perfil::nuevo(Path::new("/usr/bin/x"));
        p.anotar(&Observacion::Capacidad(cap::NET_BIND_SERVICE));
        assert_eq!(p.capacidades_retenidas(), 1 << cap::NET_BIND_SERVICE);
        p.root = true;
        assert_eq!(
            p.capacidades_retenidas(),
            (1 << cap::NET_BIND_SERVICE) | cap::IMPLICITAS
        );
        assert_eq!(
            p.capacidades_retenidas() & (1 << cap::SYS_ADMIN),
            0,
            "nunca se regala SYS_ADMIN"
        );
    }

    #[test]
    fn el_texto_es_determinista_y_legible() {
        let mut a = Perfil::nuevo(Path::new("/usr/bin/x"));
        let mut b = Perfil::nuevo(Path::new("/usr/bin/x"));
        for nr in [1u32, 0, 257, 60] {
            a.anotar(&Observacion::Llamada(nr));
        }
        for nr in [60u32, 257, 0, 1] {
            b.anotar(&Observacion::Llamada(nr));
        }
        assert_eq!(a.texto(), b.texto());
        if cfg!(target_arch = "x86_64") {
            assert!(a.texto().contains("llamada openat"), "{}", a.texto());
        }
    }

    #[test]
    fn fusionar_da_la_union() {
        let mut a = Perfil::nuevo(Path::new("/x"));
        a.anotar(&Observacion::Llamada(0));
        a.ejecuciones = 1;
        let mut b = Perfil::nuevo(Path::new("/x"));
        b.anotar(&Observacion::Llamada(1));
        b.root = true;
        b.ejecuciones = 1;
        a.fusionar(&b);
        assert_eq!(a.llamadas.len(), 2);
        assert!(a.root);
        assert_eq!(a.ejecuciones, 2);
    }
}
