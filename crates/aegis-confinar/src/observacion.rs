//! De una llamada suspendida a hechos: que fichero, que familia de red, que
//! puerto, que capacidad.
//!
//! # Que se puede deducir de una llamada, y que no
//!
//! El numero de llamada lo dice el kernel y es exacto. Los argumentos enteros
//! (la familia de `socket`, las banderas de `open`) tambien. Los argumentos que
//! son PUNTEROS —una ruta, una direccion de red— hay que leerlos de la memoria
//! del proceso, y eso tiene carrera: otro hilo puede cambiarlos entre la lectura
//! y el uso. Aqui da igual, porque esto solo APRENDE: lo que se impone lo impone
//! el kernel sobre el objeto ya resuelto (Landlock), no esta lectura.
//!
//! Las capacidades son la parte delicada. Algunas se deducen de la llamada sin
//! ambiguedad (`mount` necesita `CAP_SYS_ADMIN`, un `bind` a un puerto por debajo
//! de 1024 necesita `CAP_NET_BIND_SERVICE`). Otras **no se pueden deducir**: un
//! proceso de root que abre un fichero ajeno usa `CAP_DAC_OVERRIDE` sin que
//! ninguna llamada lo diga. Esas se marcan como implicitas y se conservan en los
//! procesos de root: quitarlas romperia servicios que si las usan, y el
//! aprendizaje no tiene forma de saber que las usan.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

use aegis_sandbox::supervisor::Notificacion;
use aegis_sandbox::syscalls;

/// Como se toca un fichero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Acceso {
    /// Leer (o abrir sin escribir).
    Lectura,
    /// Escribir un fichero que ya existe.
    Escritura,
    /// Ejecutarlo.
    Ejecucion,
    /// Crear una entrada nueva en su directorio.
    Creacion,
    /// Borrar o renombrar la entrada.
    Borrado,
}

/// Un hecho aprendido.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Observacion {
    /// Se uso esta llamada.
    Llamada(u32),
    /// Se toco este fichero de esta manera.
    Fichero {
        /// Ruta absoluta, normalizada sin resolver enlaces.
        ruta: PathBuf,
        /// Como.
        acceso: Acceso,
    },
    /// Se creo un socket de esta familia.
    Socket {
        /// `AF_*`.
        dominio: u32,
        /// `SOCK_*` (sin las banderas).
        tipo: u32,
    },
    /// Se conecto a este puerto.
    Conexion {
        /// Familia.
        familia: u16,
        /// Puerto.
        puerto: u16,
    },
    /// Se escucho en este puerto.
    Escucha {
        /// Familia.
        familia: u16,
        /// Puerto.
        puerto: u16,
    },
    /// Se uso una operacion que exige esta capacidad.
    Capacidad(u32),
}

/// Quien sabe leer la memoria y el estado de un proceso supervisado.
///
/// Es una FRONTERA (el proceso vivo): el decodificador de abajo es el mismo en
/// produccion y en las pruebas.
pub trait LectorProceso {
    /// Una cadena terminada en cero.
    fn cadena(&self, hilo: u32, direccion: u64) -> Option<Vec<u8>>;
    /// `n` bytes.
    fn bytes(&self, hilo: u32, direccion: u64, n: usize) -> Option<Vec<u8>>;
    /// El directorio de trabajo del proceso.
    fn directorio_actual(&self, hilo: u32) -> Option<PathBuf>;
    /// La ruta de un descriptor del proceso.
    fn ruta_de_descriptor(&self, hilo: u32, fd: i32) -> Option<PathBuf>;
}

/// Capacidades de Linux por numero, las que se nombran aqui.
pub mod cap {
    /// `CAP_CHOWN`.
    pub const CHOWN: u32 = 0;
    /// `CAP_DAC_OVERRIDE`.
    pub const DAC_OVERRIDE: u32 = 1;
    /// `CAP_DAC_READ_SEARCH`.
    pub const DAC_READ_SEARCH: u32 = 2;
    /// `CAP_FOWNER`.
    pub const FOWNER: u32 = 3;
    /// `CAP_FSETID`.
    pub const FSETID: u32 = 4;
    /// `CAP_KILL`.
    pub const KILL: u32 = 5;
    /// `CAP_SETGID`.
    pub const SETGID: u32 = 6;
    /// `CAP_SETUID`.
    pub const SETUID: u32 = 7;
    /// `CAP_SETPCAP`.
    pub const SETPCAP: u32 = 8;
    /// `CAP_NET_BIND_SERVICE`.
    pub const NET_BIND_SERVICE: u32 = 10;
    /// `CAP_NET_RAW`.
    pub const NET_RAW: u32 = 13;
    /// `CAP_IPC_LOCK`.
    pub const IPC_LOCK: u32 = 14;
    /// `CAP_SYS_MODULE`.
    pub const SYS_MODULE: u32 = 16;
    /// `CAP_SYS_RAWIO`.
    pub const SYS_RAWIO: u32 = 17;
    /// `CAP_SYS_CHROOT`.
    pub const SYS_CHROOT: u32 = 18;
    /// `CAP_SYS_PTRACE`.
    pub const SYS_PTRACE: u32 = 19;
    /// `CAP_SYS_ADMIN`.
    pub const SYS_ADMIN: u32 = 21;
    /// `CAP_SYS_BOOT`.
    pub const SYS_BOOT: u32 = 22;
    /// `CAP_SYS_NICE`.
    pub const SYS_NICE: u32 = 23;
    /// `CAP_SYS_RESOURCE`.
    pub const SYS_RESOURCE: u32 = 24;
    /// `CAP_SYS_TIME`.
    pub const SYS_TIME: u32 = 25;
    /// `CAP_MKNOD`.
    pub const MKNOD: u32 = 27;
    /// `CAP_SYSLOG`.
    pub const SYSLOG: u32 = 34;
    /// `CAP_PERFMON`.
    pub const PERFMON: u32 = 38;
    /// `CAP_BPF`.
    pub const BPF: u32 = 39;

    /// Las que un proceso de root usa sin que ninguna llamada lo diga: se
    /// conservan siempre en los procesos de root. Ver la cabecera del modulo.
    pub const IMPLICITAS: u64 =
        (1 << DAC_OVERRIDE) | (1 << DAC_READ_SEARCH) | (1 << FOWNER) | (1 << FSETID) | (1 << KILL);
}

/// Que es cada llamada para el aprendizaje.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Clase {
    /// `open`: ruta en arg0, banderas en arg1.
    Open,
    /// `openat`: dirfd arg0, ruta arg1, banderas arg2.
    OpenAt,
    /// `openat2`: dirfd arg0, ruta arg1, `struct open_how` en arg2.
    OpenAt2,
    /// Una ruta en `arg` (con dirfd en `dirfd` si lo hay) accedida asi.
    Ruta {
        dirfd: Option<usize>,
        ruta: usize,
        acceso: Acceso,
    },
    /// `rename`/`link`: dos rutas.
    Dos {
        dirfd_a: Option<usize>,
        a: usize,
        acceso_a: Acceso,
        dirfd_b: Option<usize>,
        b: usize,
    },
    /// Exige esta capacidad SOLO si el argumento `arg` no es nulo: `prlimit64`
    /// con el limite nuevo a nulo solo LEE, y glibc lo llama asi al arrancar
    /// cualquier programa. Deducir `CAP_SYS_RESOURCE` de eso se la dejaria a todos.
    CapacidadSiArg {
        /// La capacidad.
        cap: u32,
        /// El argumento que tiene que ser no nulo.
        arg: usize,
    },
    /// `socket`.
    Socket,
    /// `connect`.
    Connect,
    /// `bind`.
    Bind,
    /// Exige esta capacidad.
    Capacidad(u32),
}

fn tabla() -> &'static BTreeMap<u32, Clase> {
    static T: OnceLock<BTreeMap<u32, Clase>> = OnceLock::new();
    T.get_or_init(|| {
        use Acceso::*;
        use Clase::*;
        let r = |dirfd, ruta, acceso| Ruta {
            dirfd,
            ruta,
            acceso,
        };
        let filas: Vec<(&str, Clase)> = vec![
            ("open", Open),
            ("openat", OpenAt),
            ("openat2", OpenAt2),
            ("creat", r(None, 0, Creacion)),
            ("execve", r(None, 0, Ejecucion)),
            ("execveat", r(Some(0), 1, Ejecucion)),
            ("mkdir", r(None, 0, Creacion)),
            ("mkdirat", r(Some(0), 1, Creacion)),
            ("mknod", r(None, 0, Creacion)),
            ("mknodat", r(Some(0), 1, Creacion)),
            ("unlink", r(None, 0, Borrado)),
            ("unlinkat", r(Some(0), 1, Borrado)),
            ("rmdir", r(None, 0, Borrado)),
            ("truncate", r(None, 0, Escritura)),
            ("symlink", r(None, 1, Creacion)),
            ("symlinkat", r(Some(1), 2, Creacion)),
            (
                "rename",
                Dos {
                    dirfd_a: None,
                    a: 0,
                    acceso_a: Borrado,
                    dirfd_b: None,
                    b: 1,
                },
            ),
            (
                "renameat",
                Dos {
                    dirfd_a: Some(0),
                    a: 1,
                    acceso_a: Borrado,
                    dirfd_b: Some(2),
                    b: 3,
                },
            ),
            (
                "renameat2",
                Dos {
                    dirfd_a: Some(0),
                    a: 1,
                    acceso_a: Borrado,
                    dirfd_b: Some(2),
                    b: 3,
                },
            ),
            (
                "link",
                Dos {
                    dirfd_a: None,
                    a: 0,
                    acceso_a: Lectura,
                    dirfd_b: None,
                    b: 1,
                },
            ),
            (
                "linkat",
                Dos {
                    dirfd_a: Some(0),
                    a: 1,
                    acceso_a: Lectura,
                    dirfd_b: Some(2),
                    b: 3,
                },
            ),
            ("socket", Socket),
            ("connect", Connect),
            ("bind", Bind),
            ("chown", Capacidad(cap::CHOWN)),
            ("fchown", Capacidad(cap::CHOWN)),
            ("lchown", Capacidad(cap::CHOWN)),
            ("fchownat", Capacidad(cap::CHOWN)),
            ("setuid", Capacidad(cap::SETUID)),
            ("setreuid", Capacidad(cap::SETUID)),
            ("setresuid", Capacidad(cap::SETUID)),
            ("setfsuid", Capacidad(cap::SETUID)),
            ("setgid", Capacidad(cap::SETGID)),
            ("setregid", Capacidad(cap::SETGID)),
            ("setresgid", Capacidad(cap::SETGID)),
            ("setfsgid", Capacidad(cap::SETGID)),
            ("setgroups", Capacidad(cap::SETGID)),
            ("capset", Capacidad(cap::SETPCAP)),
            ("mlock", Capacidad(cap::IPC_LOCK)),
            ("mlock2", Capacidad(cap::IPC_LOCK)),
            ("mlockall", Capacidad(cap::IPC_LOCK)),
            ("init_module", Capacidad(cap::SYS_MODULE)),
            ("finit_module", Capacidad(cap::SYS_MODULE)),
            ("delete_module", Capacidad(cap::SYS_MODULE)),
            ("iopl", Capacidad(cap::SYS_RAWIO)),
            ("ioperm", Capacidad(cap::SYS_RAWIO)),
            ("chroot", Capacidad(cap::SYS_CHROOT)),
            ("ptrace", Capacidad(cap::SYS_PTRACE)),
            ("process_vm_readv", Capacidad(cap::SYS_PTRACE)),
            ("process_vm_writev", Capacidad(cap::SYS_PTRACE)),
            ("mount", Capacidad(cap::SYS_ADMIN)),
            ("umount2", Capacidad(cap::SYS_ADMIN)),
            ("pivot_root", Capacidad(cap::SYS_ADMIN)),
            ("swapon", Capacidad(cap::SYS_ADMIN)),
            ("swapoff", Capacidad(cap::SYS_ADMIN)),
            ("sethostname", Capacidad(cap::SYS_ADMIN)),
            ("setdomainname", Capacidad(cap::SYS_ADMIN)),
            ("setns", Capacidad(cap::SYS_ADMIN)),
            ("unshare", Capacidad(cap::SYS_ADMIN)),
            ("reboot", Capacidad(cap::SYS_BOOT)),
            ("kexec_load", Capacidad(cap::SYS_BOOT)),
            ("kexec_file_load", Capacidad(cap::SYS_BOOT)),
            ("setpriority", Capacidad(cap::SYS_NICE)),
            ("sched_setscheduler", Capacidad(cap::SYS_NICE)),
            ("sched_setparam", Capacidad(cap::SYS_NICE)),
            ("setrlimit", Capacidad(cap::SYS_RESOURCE)),
            (
                "prlimit64",
                CapacidadSiArg {
                    cap: cap::SYS_RESOURCE,
                    arg: 2,
                },
            ),
            ("settimeofday", Capacidad(cap::SYS_TIME)),
            ("clock_settime", Capacidad(cap::SYS_TIME)),
            ("adjtimex", Capacidad(cap::SYS_TIME)),
            ("clock_adjtime", Capacidad(cap::SYS_TIME)),
            ("syslog", Capacidad(cap::SYSLOG)),
            ("perf_event_open", Capacidad(cap::PERFMON)),
            ("bpf", Capacidad(cap::BPF)),
            ("open_by_handle_at", Capacidad(cap::DAC_READ_SEARCH)),
        ];
        filas
            .into_iter()
            .filter_map(|(n, c)| syscalls::numero(n).map(|nr| (nr, c)))
            .collect()
    })
}

/// Si esta llamada toma rutas o direcciones que el modo permisivo tiene que
/// mirar aunque este en el perfil.
#[must_use]
pub fn mira_argumentos(nr: u32) -> bool {
    matches!(
        tabla().get(&nr),
        Some(
            Clase::Open
                | Clase::OpenAt
                | Clase::OpenAt2
                | Clase::Ruta { .. }
                | Clase::Dos { .. }
                | Clase::Socket
                | Clase::Connect
                | Clase::Bind
        )
    )
}

/// `AT_FDCWD`.
const AT_FDCWD: i32 = -100;
/// `O_ACCMODE`.
const O_ACCMODE: u64 = 0o3;
/// `O_CREAT`.
const O_CREAT: u64 = 0o100;
/// `O_TRUNC`.
const O_TRUNC: u64 = 0o1000;

/// Normaliza una ruta sin resolver enlaces: quita `.` y aplica `..`.
#[must_use]
pub fn normalizar(p: &Path) -> PathBuf {
    let mut v: Vec<std::ffi::OsString> = Vec::new();
    for c in p.components() {
        match c {
            Component::RootDir | Component::Prefix(_) | Component::CurDir => {}
            Component::ParentDir => {
                v.pop();
            }
            Component::Normal(s) => v.push(s.to_os_string()),
        }
    }
    let mut r = PathBuf::from("/");
    for s in v {
        r.push(s);
    }
    r
}

/// Resuelve una ruta tal y como la ve el proceso.
fn resolver(
    l: &dyn LectorProceso,
    n: &Notificacion,
    dirfd: Option<usize>,
    arg: usize,
) -> Option<PathBuf> {
    let bruto = l.cadena(n.pid, n.args[arg])?;
    let p = PathBuf::from(String::from_utf8_lossy(&bruto).into_owned());
    if p.is_absolute() {
        return Some(normalizar(&p));
    }
    let base = match dirfd {
        None => l.directorio_actual(n.pid)?,
        Some(i) => {
            let fd = n.args[i] as i32;
            if fd == AT_FDCWD {
                l.directorio_actual(n.pid)?
            } else {
                l.ruta_de_descriptor(n.pid, fd)?
            }
        }
    };
    Some(normalizar(&base.join(p)))
}

fn acceso_de_banderas(f: u64) -> Acceso {
    if f & O_CREAT != 0 {
        Acceso::Creacion
    } else if f & O_ACCMODE != 0 || f & O_TRUNC != 0 {
        Acceso::Escritura
    } else {
        Acceso::Lectura
    }
}

/// Familia y puerto de una `sockaddr` en memoria del proceso.
fn direccion(l: &dyn LectorProceso, n: &Notificacion) -> Option<(u16, u16)> {
    let largo = (n.args[2] as usize).min(128);
    if largo < 2 {
        return None;
    }
    let b = l.bytes(n.pid, n.args[1], largo.min(4))?;
    let familia = u16::from_le_bytes([b[0], *b.get(1)?]);
    let puerto =
        if (familia == libc::AF_INET as u16 || familia == libc::AF_INET6 as u16) && b.len() >= 4 {
            u16::from_be_bytes([b[2], b[3]])
        } else {
            0
        };
    Some((familia, puerto))
}

/// Los hechos de una llamada.
#[must_use]
pub fn decodificar(n: &Notificacion, l: &dyn LectorProceso) -> Vec<Observacion> {
    let mut v = vec![Observacion::Llamada(n.nr)];
    let Some(clase) = tabla().get(&n.nr).copied() else {
        return v;
    };
    let fichero =
        |ruta: Option<PathBuf>, acceso| ruta.map(|ruta| Observacion::Fichero { ruta, acceso });
    match clase {
        Clase::Open => v.extend(fichero(
            resolver(l, n, None, 0),
            acceso_de_banderas(n.args[1]),
        )),
        Clase::OpenAt => v.extend(fichero(
            resolver(l, n, Some(0), 1),
            acceso_de_banderas(n.args[2]),
        )),
        Clase::OpenAt2 => {
            let banderas = l
                .bytes(n.pid, n.args[2], 8)
                .and_then(|b| b.try_into().ok())
                .map(u64::from_le_bytes)
                .unwrap_or(0);
            v.extend(fichero(
                resolver(l, n, Some(0), 1),
                acceso_de_banderas(banderas),
            ));
        }
        Clase::Ruta {
            dirfd,
            ruta,
            acceso,
        } => v.extend(fichero(resolver(l, n, dirfd, ruta), acceso)),
        Clase::Dos {
            dirfd_a,
            a,
            acceso_a,
            dirfd_b,
            b,
        } => {
            v.extend(fichero(resolver(l, n, dirfd_a, a), acceso_a));
            v.extend(fichero(resolver(l, n, dirfd_b, b), Acceso::Creacion));
        }
        Clase::Socket => {
            let dominio = n.args[0] as u32;
            // SOCK_NONBLOCK y SOCK_CLOEXEC viajan en los mismos bits: fuera.
            let tipo = (n.args[1] as u32) & 0xf;
            v.push(Observacion::Socket { dominio, tipo });
            if tipo == libc::SOCK_RAW as u32 || dominio == libc::AF_PACKET as u32 {
                v.push(Observacion::Capacidad(cap::NET_RAW));
            }
        }
        Clase::Connect => {
            if let Some((familia, puerto)) = direccion(l, n) {
                v.push(Observacion::Conexion { familia, puerto });
            }
        }
        Clase::Bind => {
            if let Some((familia, puerto)) = direccion(l, n) {
                v.push(Observacion::Escucha { familia, puerto });
                if puerto != 0 && puerto < 1024 {
                    v.push(Observacion::Capacidad(cap::NET_BIND_SERVICE));
                }
            }
        }
        Clase::Capacidad(c) => v.push(Observacion::Capacidad(c)),
        Clase::CapacidadSiArg { cap: c, arg } => {
            if n.args[arg] != 0 {
                v.push(Observacion::Capacidad(c));
            }
        }
    }
    v
}

#[cfg(test)]
pub(crate) mod pruebas {
    use super::*;
    use std::collections::HashMap;

    /// Doble de FRONTERA: la memoria de un proceso con lo que la prueba ponga.
    #[derive(Default)]
    pub(crate) struct ProcesoDeMentira {
        pub(crate) memoria: HashMap<u64, Vec<u8>>,
        pub(crate) cwd: PathBuf,
        pub(crate) fds: HashMap<i32, PathBuf>,
    }

    impl LectorProceso for ProcesoDeMentira {
        fn cadena(&self, _h: u32, d: u64) -> Option<Vec<u8>> {
            self.memoria.get(&d).cloned()
        }
        fn bytes(&self, _h: u32, d: u64, n: usize) -> Option<Vec<u8>> {
            self.memoria.get(&d).map(|b| b[..n.min(b.len())].to_vec())
        }
        fn directorio_actual(&self, _h: u32) -> Option<PathBuf> {
            Some(self.cwd.clone())
        }
        fn ruta_de_descriptor(&self, _h: u32, fd: i32) -> Option<PathBuf> {
            self.fds.get(&fd).cloned()
        }
    }

    fn n(nombre: &str, args: [u64; 6]) -> Notificacion {
        Notificacion {
            id: 1,
            pid: 7,
            nr: syscalls::numero(nombre).expect(nombre),
            arch: aegis_sandbox::seccomp::AUDIT_ARCH,
            args,
        }
    }

    #[test]
    fn openat_relativo_se_resuelve_contra_el_directorio_actual_o_el_descriptor() {
        let mut p = ProcesoDeMentira {
            cwd: PathBuf::from("/srv/app"),
            ..Default::default()
        };
        p.memoria.insert(0x1000, b"datos/../conf.ini".to_vec());
        p.fds.insert(5, PathBuf::from("/var/lib/app"));
        let a = decodificar(
            &n("openat", [AT_FDCWD as u32 as u64, 0x1000, 0, 0, 0, 0]),
            &p,
        );
        assert!(
            a.contains(&Observacion::Fichero {
                ruta: PathBuf::from("/srv/app/conf.ini"),
                acceso: Acceso::Lectura
            }),
            "{a:?}"
        );
        let b = decodificar(&n("openat", [5, 0x1000, O_CREAT, 0, 0, 0]), &p);
        assert!(
            b.contains(&Observacion::Fichero {
                ruta: PathBuf::from("/var/lib/app/conf.ini"),
                acceso: Acceso::Creacion
            }),
            "{b:?}"
        );
    }

    #[test]
    fn las_banderas_de_open_dicen_el_acceso() {
        assert_eq!(acceso_de_banderas(0), Acceso::Lectura);
        assert_eq!(acceso_de_banderas(1), Acceso::Escritura);
        assert_eq!(acceso_de_banderas(2), Acceso::Escritura);
        assert_eq!(acceso_de_banderas(O_TRUNC), Acceso::Escritura);
        assert_eq!(acceso_de_banderas(O_CREAT | 1), Acceso::Creacion);
    }

    #[test]
    fn socket_bind_y_connect_dan_familia_puerto_y_capacidad() {
        let mut p = ProcesoDeMentira::default();
        // sockaddr_in: familia 2, puerto 80 en orden de red.
        p.memoria.insert(0x2000, vec![2, 0, 0, 80, 127, 0, 0, 1]);
        p.memoria.insert(0x3000, vec![2, 0, 0x1F, 0x90, 0, 0, 0, 0]);
        let s = decodificar(&n("socket", [2, 1 | 0x80000, 0, 0, 0, 0]), &p);
        assert!(
            s.contains(&Observacion::Socket {
                dominio: 2,
                tipo: 1
            }),
            "{s:?}"
        );
        let crudo = decodificar(&n("socket", [2, 3, 0, 0, 0, 0]), &p);
        assert!(crudo.contains(&Observacion::Capacidad(cap::NET_RAW)));
        let b = decodificar(&n("bind", [3, 0x2000, 16, 0, 0, 0]), &p);
        assert!(b.contains(&Observacion::Escucha {
            familia: 2,
            puerto: 80
        }));
        assert!(b.contains(&Observacion::Capacidad(cap::NET_BIND_SERVICE)));
        let c = decodificar(&n("connect", [3, 0x3000, 16, 0, 0, 0]), &p);
        assert!(c.contains(&Observacion::Conexion {
            familia: 2,
            puerto: 8080
        }));
        assert!(!c.iter().any(|o| matches!(o, Observacion::Capacidad(_))));
    }

    #[test]
    fn las_capacidades_deducibles_se_deducen_y_una_llamada_cualquiera_no_da_ninguna() {
        let p = ProcesoDeMentira::default();
        assert!(
            decodificar(&n("mount", [0; 6]), &p).contains(&Observacion::Capacidad(cap::SYS_ADMIN))
        );
        assert!(decodificar(&n("ptrace", [0; 6]), &p)
            .contains(&Observacion::Capacidad(cap::SYS_PTRACE)));
        let r = decodificar(&n("read", [0; 6]), &p);
        assert_eq!(r, vec![Observacion::Llamada(0)]);
        // prlimit64 que solo lee (limite nuevo nulo): ninguna capacidad. Es lo que
        // hace glibc al arrancar cualquier programa.
        let lee = decodificar(&n("prlimit64", [0, 3, 0, 0x7000, 0, 0]), &p);
        assert!(
            !lee.iter().any(|o| matches!(o, Observacion::Capacidad(_))),
            "{lee:?}"
        );
        let fija = decodificar(&n("prlimit64", [0, 3, 0x6000, 0, 0, 0]), &p);
        assert!(fija.contains(&Observacion::Capacidad(cap::SYS_RESOURCE)));
    }

    #[test]
    fn un_puntero_ilegible_no_inventa_una_ruta() {
        let p = ProcesoDeMentira::default();
        let a = decodificar(&n("open", [0xdead, 0, 0, 0, 0, 0]), &p);
        assert_eq!(a.len(), 1, "solo la llamada: {a:?}");
    }

    #[test]
    fn la_normalizacion_no_escapa_de_la_raiz() {
        assert_eq!(
            normalizar(Path::new("/a/b/../../../../etc")),
            PathBuf::from("/etc")
        );
        assert_eq!(normalizar(Path::new("/a/./b/")), PathBuf::from("/a/b"));
    }

    #[test]
    fn la_tabla_nombra_llamadas_que_existen() {
        assert!(tabla().len() > 70, "{}", tabla().len());
        assert!(mira_argumentos(syscalls::numero("openat").expect("x")));
        assert!(!mira_argumentos(syscalls::numero("read").expect("x")));
    }
}
