//! Deteccion de las capacidades del kernel en tiempo de ejecucion, y el plan de
//! degradacion que se deriva de ellas.
//!
//! # Por que existe
//!
//! Hasta aqui el agente trataba el kernel como una sola pregunta de si o no: el
//! `preflight` exigia TODOS los tracepoints y, si faltaba uno, el agente no
//! arrancaba. Eso tenia dos fallos de raiz:
//!
//! 1. **Todo o nada.** En aarch64 no existe la llamada `rename` —solo
//!    `renameat2`—, asi que el tracepoint `sys_enter_rename` no esta, y el agente
//!    se negaba a arrancar en ARM entero por una sonda que alli sobra. Un kernel
//!    sin la sonda de red dejaba sin telemetria de procesos a una maquina que si
//!    la podia tener.
//! 2. **Validado en un solo kernel.** Lo que se sabia del entorno salia de la
//!    maquina de integracion. En la flota hay BTF que no esta, BPF LSM apagado,
//!    cgroup v1, SELinux en modo estricto o `lockdown`, y ninguno de esos casos
//!    se veia hasta que fallaba en un cliente.
//!
//! Ahora el agente PREGUNTA al kernel que tiene, deriva de la respuesta que
//! familias de telemetria puede sostener y cuales no, y lo DECLARA: al arrancar
//! lo imprime, y con `--capacidades` lo emite en un formato que la matriz de
//! kernels (`tools/matriz-kernels/`) recoge de cada distribucion.
//!
//! # Doctrina
//!
//! - **Nunca silenciosa.** Toda familia que no se puede sostener sale con su
//!   motivo y su remedio. Una familia sin datos es `SinDatos`, no «limpio».
//! - **Solo auditoria.** Detectar no actua: este modulo no monta sistemas de
//!   ficheros, no cambia politicas y no toca `sysctl`. Dice que falta y como se
//!   arregla; arreglarlo es cosa del operador.
//! - **Lo que no se sabe, se dice.** Si `securityfs` no esta montado no se puede
//!   saber si BPF LSM esta activo, y la respuesta es `Desconocido` con el motivo,
//!   no un «no» inventado.

use std::fmt;
use std::path::{Path, PathBuf};

/// Respuesta de tres valores a una pregunta sobre el kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tri {
    /// La capacidad esta presente.
    Si,
    /// La capacidad falta.
    No,
    /// No se pudo averiguar, con el motivo.
    Desconocido(String),
}

impl Tri {
    fn de_bool(b: bool) -> Self {
        if b {
            Tri::Si
        } else {
            Tri::No
        }
    }

    /// Forma corta para la salida de maquina.
    pub fn corto(&self) -> &str {
        match self {
            Tri::Si => "si",
            Tri::No => "no",
            Tri::Desconocido(_) => "desconocido",
        }
    }
}

impl fmt::Display for Tri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Tri::Desconocido(m) => write!(f, "desconocido ({m})"),
            otro => f.write_str(otro.corto()),
        }
    }
}

/// Jerarquia de cgroups montada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cgroup {
    /// Jerarquia unificada: `MemoryHigh`/`MemoryMax` los impone el kernel.
    V2,
    /// Solo la jerarquia clasica.
    V1,
    /// Las dos a la vez (systemd en modo hibrido): la de memoria es la v1.
    Hibrido,
    /// No hay cgroups montados donde se esperan.
    Desconocido,
}

impl Cgroup {
    fn corto(&self) -> &'static str {
        match self {
            Cgroup::V2 => "v2",
            Cgroup::V1 => "v1",
            Cgroup::Hibrido => "hibrido",
            Cgroup::Desconocido => "desconocido",
        }
    }
}

/// Familias de telemetria de kernel. Cada sonda pertenece a exactamente una, y
/// la degradacion se declara por familia: es la unidad en la que un analista
/// entiende que ha perdido («no veo red»), no el nombre de un tracepoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Familia {
    /// Ejecucion de procesos (`execve`). Es la columna vertebral del linaje.
    Ejecucion,
    /// Fin de procesos: sin ella el grafo no libera nodos por salida.
    SalidaProceso,
    /// Apertura de ficheros.
    Ficheros,
    /// Escrituras: base de la deteccion de ransomware.
    Escrituras,
    /// Renombrados: la otra mitad del ransomware.
    Renombrados,
    /// `ptrace`: inyeccion y robo de credenciales de memoria.
    Ptrace,
    /// Cambios de estado de sockets TCP.
    Red,
}

impl Familia {
    /// Todas, en orden de valor para la deteccion (de mas a menos).
    pub const TODAS: [Familia; 7] = [
        Familia::Ejecucion,
        Familia::SalidaProceso,
        Familia::Ficheros,
        Familia::Escrituras,
        Familia::Renombrados,
        Familia::Ptrace,
        Familia::Red,
    ];

    /// Nombre estable para la salida de maquina.
    pub fn nombre(&self) -> &'static str {
        match self {
            Familia::Ejecucion => "ejecucion",
            Familia::SalidaProceso => "salida-proceso",
            Familia::Ficheros => "ficheros",
            Familia::Escrituras => "escrituras",
            Familia::Renombrados => "renombrados",
            Familia::Ptrace => "ptrace",
            Familia::Red => "red",
        }
    }
}

/// Familia a la que pertenece cada programa del objeto de sondas, por el nombre
/// de su funcion en `aegis_probes.bpf.c`.
///
/// La lista de TRACEPOINTS ya no se escribe a mano: sale de la seccion ELF de
/// cada programa del objeto empotrado (ver `bpf::planificar`). Lo unico que se
/// declara aqui es a que familia pertenece cada programa, y una prueba recorre
/// el objeto real y falla si aparece un programa sin familia: una sonda nueva
/// que nadie clasifica no puede degradarse en silencio.
pub fn familia_de_programa(nombre: &str) -> Option<Familia> {
    Some(match nombre {
        "aegis_tp_execve" => Familia::Ejecucion,
        "aegis_tp_process_exit" => Familia::SalidaProceso,
        "aegis_tp_openat" | "aegis_tp_openat_exit" => Familia::Ficheros,
        "aegis_tp_write" => Familia::Escrituras,
        "aegis_tp_rename" | "aegis_tp_renameat2" => Familia::Renombrados,
        "aegis_tp_ptrace" => Familia::Ptrace,
        "aegis_tp_sock_state" => Familia::Red,
        _ => return None,
    })
}

/// Una sonda que no se engancha en este kernel, y por que.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SondaOmitida {
    /// Nombre del programa en el objeto.
    pub programa: String,
    /// Tracepoint que falta, en la forma `categoria/evento`.
    pub tracepoint: String,
    /// Familia a la que pertenece.
    pub familia: Option<Familia>,
}

/// Que sondas se enganchan y que familias quedan sin datos en este kernel.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlanSondas {
    /// Programas que se cargan y enganchan.
    pub activos: Vec<String>,
    /// Programas que se omiten porque su tracepoint no existe aqui.
    pub omitidos: Vec<SondaOmitida>,
    /// Familias que no conservan NINGUNA sonda: su telemetria es `SinDatos`.
    /// Una familia con alguna sonda viva no esta aqui (en aarch64 falta
    /// `sys_enter_rename`, pero `renameat2` sigue viendo los renombrados).
    pub familias_sin_datos: Vec<Familia>,
}

/// Decide que programas se enganchan, a partir de las secciones ELF del objeto
/// (no de una lista escrita a mano) y de los tracepoints que existen en tracefs.
///
/// `existe` responde si un tracepoint `categoria/evento` esta en este kernel; en
/// produccion mira tracefs, en las pruebas es un conjunto fijo.
pub fn planificar<'a>(
    programas: impl IntoIterator<Item = (&'a str, &'a str)>,
    existe: impl Fn(&str) -> bool,
) -> PlanSondas {
    let mut plan = PlanSondas::default();
    let mut vivas: Vec<Familia> = Vec::new();
    for (nombre, seccion) in programas {
        let familia = familia_de_programa(nombre);
        match seccion.strip_prefix("tracepoint/") {
            Some(tp) if !existe(tp) => plan.omitidos.push(SondaOmitida {
                programa: nombre.to_string(),
                tracepoint: tp.to_string(),
                familia,
            }),
            _ => {
                plan.activos.push(nombre.to_string());
                vivas.extend(familia);
            }
        }
    }
    plan.familias_sin_datos = Familia::TODAS
        .into_iter()
        .filter(|f| !vivas.contains(f))
        .collect();
    plan
}

/// Lo que el propio kernel responde cuando se le pregunta con `bpf()`. Solo se
/// rellena con la caracteristica `bpf` y privilegios; sin ellos cada campo es
/// `Desconocido` con el motivo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SondeoBpf {
    /// Mapas `BPF_MAP_TYPE_RINGBUF` (5.8+, o retroportados).
    pub ringbuf: Tri,
    /// Programas de tracepoint.
    pub tracepoint: Tri,
    /// Programas XDP.
    pub xdp: Tri,
    /// Programas `BPF_PROG_TYPE_LSM` (que el tipo exista no significa que BPF
    /// LSM este activo: eso lo dice `lsm_activos`).
    pub lsm: Tri,
}

impl SondeoBpf {
    /// Sondeo no realizado, con el motivo en cada campo.
    pub fn no_realizado(motivo: &str) -> Self {
        let d = || Tri::Desconocido(motivo.to_string());
        SondeoBpf {
            ringbuf: d(),
            tracepoint: d(),
            xdp: d(),
            lsm: d(),
        }
    }
}

/// Todo lo que el agente sabe del kernel en el que corre.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capacidades {
    /// `uname -r`.
    pub kernel: String,
    /// Arquitectura para la que se compilo el agente.
    pub arquitectura: &'static str,
    /// BTF del kernel en `/sys/kernel/btf/vmlinux`: sin el, CO-RE no reubica.
    pub btf: bool,
    /// Donde esta montado tracefs, si lo esta.
    pub tracefs: Option<PathBuf>,
    /// LSM activos segun `securityfs`, o el motivo por el que no se sabe.
    pub lsm_activos: Result<Vec<String>, String>,
    /// Jerarquia de cgroups.
    pub cgroup: Cgroup,
    /// Modo de SELinux (`enforcing`/`permissive`) si esta cargado.
    pub selinux: Option<String>,
    /// AppArmor habilitado.
    pub apparmor: bool,
    /// Modo de `lockdown` activo (`none`, `integrity`, `confidentiality`).
    pub lockdown: Option<String>,
    /// `kernel.unprivileged_bpf_disabled`.
    pub bpf_sin_privilegio: Option<String>,
    /// Respuesta directa del kernel a `bpf()`.
    pub sondeo: SondeoBpf,
}

impl Capacidades {
    /// BPF LSM activo, en tres valores.
    pub fn bpf_lsm(&self) -> Tri {
        match &self.lsm_activos {
            Ok(lista) => Tri::de_bool(lista.iter().any(|l| l == "bpf")),
            Err(m) => Tri::Desconocido(m.clone()),
        }
    }
}

/// Lee un fichero de texto de una sola linea, recortado.
fn leer(ruta: &Path) -> Option<String> {
    std::fs::read_to_string(ruta)
        .ok()
        .map(|s| s.trim().to_string())
}

/// Detecta las capacidades leyendo el `/proc` y el `/sys` bajo `raiz`.
///
/// `raiz` es `/` en produccion; las pruebas le pasan un arbol falso. El sondeo
/// directo por `bpf()` NO se hace aqui (es el `sondeo` que se pasa): esto es la
/// parte que se puede leer sin privilegios y probar sin kernel.
pub fn detectar_en(raiz: &Path, sondeo: SondeoBpf) -> Capacidades {
    let r = |p: &str| raiz.join(p.trim_start_matches('/'));

    let tracefs = ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"]
        .iter()
        .map(|p| r(p))
        .find(|p| p.join("events").is_dir())
        // Se devuelve la ruta REAL (sin la raiz de pruebas) para el operador.
        .map(|p| PathBuf::from("/").join(p.strip_prefix(raiz).unwrap_or(&p)));

    // Un directorio vacio en /sys/kernel/security no es securityfs: es su punto de
    // montaje sin montar (WSL2 sin systemd). Se pregunta a la tabla de montajes;
    // si no se puede leer, se cae a mirar si el directorio existe.
    let securityfs_montado = leer(&r("/proc/self/mounts"))
        .map(|m| {
            m.lines()
                .any(|l| l.split_whitespace().nth(2) == Some("securityfs"))
        })
        .unwrap_or_else(|| r("/sys/kernel/security").is_dir());
    let lsm_activos = match leer(&r("/sys/kernel/security/lsm")) {
        Some(s) => Ok(s
            .split(',')
            .filter(|x| !x.is_empty())
            .map(str::to_string)
            .collect()),
        None if !securityfs_montado => {
            Err("securityfs no esta montado en /sys/kernel/security".to_string())
        }
        None => Err("/sys/kernel/security/lsm no es legible".to_string()),
    };

    let cgroup = if r("/sys/fs/cgroup/cgroup.controllers").is_file() {
        Cgroup::V2
    } else if r("/sys/fs/cgroup/unified/cgroup.controllers").is_file() {
        Cgroup::Hibrido
    } else if r("/sys/fs/cgroup/memory").is_dir() {
        Cgroup::V1
    } else {
        Cgroup::Desconocido
    };

    let selinux = leer(&r("/sys/fs/selinux/enforce")).map(|v| {
        if v == "1" {
            "enforcing".to_string()
        } else {
            "permissive".to_string()
        }
    });

    // El fichero de lockdown lista los modos y marca el activo entre corchetes:
    // `none [integrity] confidentiality`.
    let lockdown = leer(&r("/sys/kernel/security/lockdown")).and_then(|s| {
        let ini = s.find('[')?;
        let fin = s[ini..].find(']')? + ini;
        Some(s[ini + 1..fin].to_string())
    });

    Capacidades {
        kernel: leer(&r("/proc/sys/kernel/osrelease")).unwrap_or_else(|| "?".into()),
        arquitectura: std::env::consts::ARCH,
        btf: r("/sys/kernel/btf/vmlinux").is_file(),
        tracefs,
        lsm_activos,
        cgroup,
        selinux,
        apparmor: leer(&r("/sys/module/apparmor/parameters/enabled")).as_deref() == Some("Y"),
        lockdown,
        bpf_sin_privilegio: leer(&r("/proc/sys/kernel/unprivileged_bpf_disabled")),
        sondeo,
    }
}

/// Una consecuencia declarada de una capacidad ausente.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Degradacion {
    /// Que capacidad falta (clave estable).
    pub capacidad: &'static str,
    /// Que deja de funcionar, dicho para un operador.
    pub efecto: String,
    /// Como se arregla, si se puede.
    pub remedio: &'static str,
    /// Familias de telemetria que quedan `SinDatos` por esta causa. Vacio si la
    /// consecuencia no es una familia (presupuesto, confinamiento...).
    pub familias: Vec<Familia>,
    /// Si impide cargar las sondas de kernel del todo.
    pub bloquea_telemetria: bool,
}

/// Deriva el plan de degradacion de las capacidades. Es una funcion pura: el
/// mismo kernel da el mismo plan, y cada rama tiene su prueba.
pub fn plan_degradacion(c: &Capacidades) -> Vec<Degradacion> {
    let mut plan = Vec::new();

    if !c.btf {
        plan.push(Degradacion {
            capacidad: "btf",
            efecto: "sin BTF del kernel, CO-RE no puede reubicar las sondas: no hay \
                     telemetria de kernel (todas las familias SinDatos)"
                .into(),
            remedio: "kernel con CONFIG_DEBUG_INFO_BTF=y (lo traen todas las \
                      distribuciones de la matriz)",
            familias: Familia::TODAS.to_vec(),
            bloquea_telemetria: true,
        });
    }
    if c.sondeo.ringbuf == Tri::No {
        plan.push(Degradacion {
            capacidad: "ringbuf",
            efecto: "el kernel no tiene BPF_MAP_TYPE_RINGBUF y el agente no implementa \
                     el camino por perf buffer: no hay telemetria de kernel"
                .into(),
            remedio: "kernel 5.8 o posterior (o con ringbuf retroportado)",
            familias: Familia::TODAS.to_vec(),
            bloquea_telemetria: true,
        });
    }
    if c.tracefs.is_none() {
        plan.push(Degradacion {
            capacidad: "tracefs",
            efecto: "tracefs no esta montado: no se pueden resolver los tracepoints \
                     y no hay telemetria de kernel"
                .into(),
            remedio: "mount -t tracefs nodev /sys/kernel/tracing",
            familias: Familia::TODAS.to_vec(),
            bloquea_telemetria: true,
        });
    }
    match c.bpf_lsm() {
        Tri::Si => {}
        otro => plan.push(Degradacion {
            capacidad: "bpf-lsm",
            efecto: format!(
                "BPF LSM {}: hoy el producto no carga programas LSM, asi que no se \
                 pierde telemetria; lo que dependa de un gancho LSM (atribucion de \
                 autor en integridad, bloqueo en el kernel) no esta disponible",
                match otro {
                    Tri::No => "no esta en la lista lsm= activa".to_string(),
                    t => t.to_string(),
                }
            ),
            remedio: "arrancar con lsm=...,bpf en la linea de comandos del kernel",
            familias: vec![],
            bloquea_telemetria: false,
        }),
    }
    match c.cgroup {
        Cgroup::V2 => {}
        ref otro => plan.push(Degradacion {
            capacidad: "cgroup-v2",
            efecto: format!(
                "cgroups {}: el techo de memoria del agente no lo impone el kernel \
                 (MemoryMax); queda solo la contencion interna y el watchdog",
                otro.corto()
            ),
            remedio: "systemd.unified_cgroup_hierarchy=1",
            familias: vec![],
            bloquea_telemetria: false,
        }),
    }
    if c.lockdown.as_deref() == Some("confidentiality") {
        plan.push(Degradacion {
            capacidad: "lockdown",
            efecto: "lockdown=confidentiality prohibe leer memoria del kernel desde BPF: \
                     las sondas pueden no cargar"
                .into(),
            remedio: "lockdown=integrity o none (decision de la organizacion)",
            familias: vec![],
            bloquea_telemetria: false,
        });
    }
    if c.selinux.as_deref() == Some("enforcing") {
        plan.push(Degradacion {
            capacidad: "selinux",
            efecto: "SELinux en enforcing: el dominio del agente necesita permiso \
                     para bpf, perfmon y tracefs o la carga se deniega"
                .into(),
            remedio: "ejecutar el agente como unconfined_service_t o con su modulo de politica",
            familias: vec![],
            bloquea_telemetria: false,
        });
    }
    plan
}

/// Informe de arranque, para un humano.
pub fn informe(c: &Capacidades, plan: &[Degradacion]) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "kernel {} ({}), BTF {}, tracefs {}, BPF LSM {}, cgroup {}\n",
        c.kernel,
        c.arquitectura,
        Tri::de_bool(c.btf),
        c.tracefs
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "no montado".into()),
        c.bpf_lsm(),
        c.cgroup.corto(),
    ));
    if plan.is_empty() {
        s.push_str("sin degradaciones: todas las capacidades presentes\n");
    }
    for d in plan {
        s.push_str(&format!("DEGRADADO [{}] {}\n", d.capacidad, d.efecto));
        s.push_str(&format!("    remedio: {}\n", d.remedio));
    }
    s
}

/// Salida de maquina: una linea `AEGIS-CAP|clave|valor` por hecho y una
/// `AEGIS-DEG|capacidad|familias|bloquea` por degradacion. Es lo que la matriz de
/// kernels recoge de la consola serie de cada microVM, asi que el formato es
/// estable y no lleva espacios en las claves.
pub fn salida_maquina(c: &Capacidades, plan: &[Degradacion]) -> String {
    let mut s = String::new();
    let mut hecho = |k: &str, v: &str| s.push_str(&format!("AEGIS-CAP|{k}|{v}\n"));
    hecho("kernel", &c.kernel);
    hecho("arquitectura", c.arquitectura);
    hecho("btf", Tri::de_bool(c.btf).corto());
    hecho(
        "tracefs",
        &c.tracefs
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "no".into()),
    );
    hecho("bpf-lsm", c.bpf_lsm().corto());
    hecho(
        "lsm",
        &c.lsm_activos
            .as_ref()
            .map(|l| l.join(","))
            .unwrap_or_else(|m| format!("desconocido:{m}")),
    );
    hecho("cgroup", c.cgroup.corto());
    hecho("selinux", c.selinux.as_deref().unwrap_or("no"));
    hecho("apparmor", if c.apparmor { "si" } else { "no" });
    hecho("lockdown", c.lockdown.as_deref().unwrap_or("no"));
    hecho("ringbuf", c.sondeo.ringbuf.corto());
    hecho("prog-tracepoint", c.sondeo.tracepoint.corto());
    hecho("prog-xdp", c.sondeo.xdp.corto());
    hecho("prog-lsm", c.sondeo.lsm.corto());
    for d in plan {
        s.push_str(&format!(
            "AEGIS-DEG|{}|{}|{}\n",
            d.capacidad,
            d.familias
                .iter()
                .map(Familia::nombre)
                .collect::<Vec<_>>()
                .join(","),
            if d.bloquea_telemetria {
                "bloquea"
            } else {
                "no-bloquea"
            }
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Un `/sys` y un `/proc` falsos en un directorio temporal propio.
    struct Arbol(PathBuf);

    impl Arbol {
        fn nuevo(nombre: &str) -> Self {
            let d = std::env::temp_dir()
                .join(format!("aegis-capacidades-{nombre}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&d);
            fs::create_dir_all(&d).unwrap();
            Arbol(d)
        }
        fn fichero(&self, ruta: &str, contenido: &str) -> &Self {
            let p = self.0.join(ruta.trim_start_matches('/'));
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, contenido).unwrap();
            self
        }
        fn dir(&self, ruta: &str) -> &Self {
            fs::create_dir_all(self.0.join(ruta.trim_start_matches('/'))).unwrap();
            self
        }
    }

    impl Drop for Arbol {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn sondeo_completo() -> SondeoBpf {
        SondeoBpf {
            ringbuf: Tri::Si,
            tracepoint: Tri::Si,
            xdp: Tri::Si,
            lsm: Tri::Si,
        }
    }

    /// Un kernel moderno completo: Ubuntu 24.04 con BPF LSM activado.
    fn completo(nombre: &str) -> Arbol {
        let a = Arbol::nuevo(nombre);
        a.fichero("/proc/sys/kernel/osrelease", "6.8.0-45-generic\n")
            .fichero("/sys/kernel/btf/vmlinux", "BTF")
            .dir("/sys/kernel/tracing/events")
            .fichero(
                "/sys/kernel/security/lsm",
                "lockdown,capability,bpf,apparmor\n",
            )
            .fichero("/sys/fs/cgroup/cgroup.controllers", "memory pids\n")
            .fichero("/sys/module/apparmor/parameters/enabled", "Y\n")
            .fichero(
                "/sys/kernel/security/lockdown",
                "[none] integrity confidentiality\n",
            );
        a
    }

    #[test]
    fn un_kernel_completo_no_declara_degradaciones() {
        let a = completo("completo");
        let c = detectar_en(&a.0, sondeo_completo());
        assert_eq!(c.kernel, "6.8.0-45-generic");
        assert!(c.btf);
        assert_eq!(c.tracefs, Some(PathBuf::from("/sys/kernel/tracing")));
        assert_eq!(c.bpf_lsm(), Tri::Si);
        assert_eq!(c.cgroup, Cgroup::V2);
        assert!(c.apparmor);
        assert_eq!(c.lockdown.as_deref(), Some("none"));
        assert!(
            plan_degradacion(&c).is_empty(),
            "{:?}",
            plan_degradacion(&c)
        );
    }

    #[test]
    fn sin_btf_todas_las_familias_quedan_sin_datos_y_se_dice() {
        let a = completo("sin-btf");
        fs::remove_file(a.0.join("sys/kernel/btf/vmlinux")).unwrap();
        let c = detectar_en(&a.0, sondeo_completo());
        let plan = plan_degradacion(&c);
        let d = plan.iter().find(|d| d.capacidad == "btf").unwrap();
        assert!(d.bloquea_telemetria);
        assert_eq!(d.familias, Familia::TODAS.to_vec());
    }

    #[test]
    fn tracefs_en_debugfs_de_los_kernels_viejos_vale() {
        let a = completo("debugfs");
        fs::remove_dir_all(a.0.join("sys/kernel/tracing")).unwrap();
        a.dir("/sys/kernel/debug/tracing/events");
        let c = detectar_en(&a.0, sondeo_completo());
        assert_eq!(c.tracefs, Some(PathBuf::from("/sys/kernel/debug/tracing")));
        assert!(plan_degradacion(&c)
            .iter()
            .all(|d| d.capacidad != "tracefs"));
    }

    #[test]
    fn sin_securityfs_bpf_lsm_es_desconocido_y_no_un_no_inventado() {
        let a = completo("sin-securityfs");
        fs::remove_dir_all(a.0.join("sys/kernel/security")).unwrap();
        let c = detectar_en(&a.0, sondeo_completo());
        assert!(matches!(c.bpf_lsm(), Tri::Desconocido(ref m) if m.contains("securityfs")));
        let d = plan_degradacion(&c)
            .into_iter()
            .find(|d| d.capacidad == "bpf-lsm")
            .unwrap();
        assert!(
            !d.bloquea_telemetria,
            "BPF LSM no bloquea: hoy no hay programas LSM"
        );
        assert!(d.efecto.contains("desconocido"));
    }

    #[test]
    fn un_punto_de_montaje_vacio_no_es_securityfs() {
        // WSL2 sin systemd: el directorio existe, securityfs no esta montado.
        let a = completo("punto-vacio");
        fs::remove_file(a.0.join("sys/kernel/security/lsm")).unwrap();
        a.fichero("/proc/self/mounts", "sysfs /sys sysfs rw 0 0\n");
        let c = detectar_en(&a.0, sondeo_completo());
        assert!(
            matches!(c.bpf_lsm(), Tri::Desconocido(ref m) if m.contains("no esta montado")),
            "{:?}",
            c.bpf_lsm()
        );
    }

    #[test]
    fn bpf_lsm_compilado_pero_fuera_de_la_lista_activa_se_declara() {
        let a = completo("lsm-apagado");
        a.fichero("/sys/kernel/security/lsm", "lockdown,capability,selinux\n");
        let c = detectar_en(&a.0, sondeo_completo());
        assert_eq!(c.bpf_lsm(), Tri::No);
        assert!(plan_degradacion(&c)
            .iter()
            .any(|d| d.capacidad == "bpf-lsm"));
    }

    #[test]
    fn cgroup_v1_e_hibrido_pierden_la_obligacion_del_kernel() {
        let a = completo("cgroup-v1");
        fs::remove_file(a.0.join("sys/fs/cgroup/cgroup.controllers")).unwrap();
        a.dir("/sys/fs/cgroup/memory");
        let c = detectar_en(&a.0, sondeo_completo());
        assert_eq!(c.cgroup, Cgroup::V1);
        assert!(plan_degradacion(&c)
            .iter()
            .any(|d| d.capacidad == "cgroup-v2"));

        a.fichero("/sys/fs/cgroup/unified/cgroup.controllers", "");
        assert_eq!(detectar_en(&a.0, sondeo_completo()).cgroup, Cgroup::Hibrido);
    }

    #[test]
    fn selinux_enforcing_y_lockdown_confidencial_se_declaran() {
        let a = completo("selinux");
        a.fichero("/sys/fs/selinux/enforce", "1").fichero(
            "/sys/kernel/security/lockdown",
            "none integrity [confidentiality]\n",
        );
        let c = detectar_en(&a.0, sondeo_completo());
        assert_eq!(c.selinux.as_deref(), Some("enforcing"));
        let plan = plan_degradacion(&c);
        assert!(plan.iter().any(|d| d.capacidad == "selinux"));
        assert!(plan.iter().any(|d| d.capacidad == "lockdown"));
    }

    #[test]
    fn sin_ringbuf_se_bloquea_la_telemetria_y_se_dice_por_que() {
        let a = completo("sin-ringbuf");
        let mut s = sondeo_completo();
        s.ringbuf = Tri::No;
        let c = detectar_en(&a.0, s);
        let d = plan_degradacion(&c)
            .into_iter()
            .find(|d| d.capacidad == "ringbuf")
            .unwrap();
        assert!(d.bloquea_telemetria);
        assert!(d.efecto.contains("perf buffer"), "{}", d.efecto);
    }

    #[test]
    fn la_salida_de_maquina_es_estable_y_parseable() {
        let a = completo("maquina");
        fs::remove_file(a.0.join("sys/kernel/btf/vmlinux")).unwrap();
        let c = detectar_en(&a.0, sondeo_completo());
        let s = salida_maquina(&c, &plan_degradacion(&c));
        assert!(s.contains("AEGIS-CAP|btf|no\n"));
        assert!(s.contains("AEGIS-CAP|cgroup|v2\n"));
        assert!(s.contains(
            "AEGIS-DEG|btf|ejecucion,salida-proceso,ficheros,escrituras,renombrados,ptrace,red|bloquea\n"
        ));
        for linea in s.lines() {
            assert!(
                linea.starts_with("AEGIS-CAP|") || linea.starts_with("AEGIS-DEG|"),
                "{linea}"
            );
            assert!(!linea.contains(' ') || linea.starts_with("AEGIS-CAP|lsm|desconocido"));
        }
    }

    #[test]
    fn falta_rename_en_aarch64_y_la_familia_sigue_viva_por_renameat2() {
        let programas = [
            ("aegis_tp_execve", "tracepoint/syscalls/sys_enter_execve"),
            ("aegis_tp_rename", "tracepoint/syscalls/sys_enter_rename"),
            (
                "aegis_tp_renameat2",
                "tracepoint/syscalls/sys_enter_renameat2",
            ),
        ];
        let plan = planificar(programas, |tp| tp != "syscalls/sys_enter_rename");
        assert_eq!(plan.activos, vec!["aegis_tp_execve", "aegis_tp_renameat2"]);
        assert_eq!(plan.omitidos.len(), 1);
        assert_eq!(plan.omitidos[0].tracepoint, "syscalls/sys_enter_rename");
        assert_eq!(plan.omitidos[0].familia, Some(Familia::Renombrados));
        assert!(!plan.familias_sin_datos.contains(&Familia::Renombrados));
        assert!(!plan.familias_sin_datos.contains(&Familia::Ejecucion));
    }

    #[test]
    fn sin_la_sonda_de_red_solo_la_red_queda_sin_datos() {
        let programas = [
            ("aegis_tp_execve", "tracepoint/syscalls/sys_enter_execve"),
            ("aegis_tp_sock_state", "tracepoint/sock/inet_sock_set_state"),
        ];
        let plan = planificar(programas, |tp| !tp.starts_with("sock/"));
        assert_eq!(plan.activos, vec!["aegis_tp_execve"]);
        assert!(plan.familias_sin_datos.contains(&Familia::Red));
        assert!(!plan.familias_sin_datos.contains(&Familia::Ejecucion));
    }

    #[test]
    fn un_programa_que_no_es_tracepoint_no_se_filtra_por_tracefs() {
        let plan = planificar([("aegis_xdp", "xdp")], |_| false);
        assert_eq!(plan.activos, vec!["aegis_xdp"]);
        assert!(plan.omitidos.is_empty());
    }

    #[test]
    fn toda_familia_tiene_al_menos_un_programa() {
        let programas = [
            "aegis_tp_execve",
            "aegis_tp_process_exit",
            "aegis_tp_openat",
            "aegis_tp_openat_exit",
            "aegis_tp_write",
            "aegis_tp_rename",
            "aegis_tp_renameat2",
            "aegis_tp_ptrace",
            "aegis_tp_sock_state",
        ];
        for f in Familia::TODAS {
            assert!(
                programas.iter().any(|p| familia_de_programa(p) == Some(f)),
                "{f:?} sin programa"
            );
        }
        assert_eq!(familia_de_programa("desconocido"), None);
    }
}
