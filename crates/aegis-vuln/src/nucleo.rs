//! Postura del KERNEL: el endurecimiento que el host tiene de verdad, leido de
//! `/proc/sys`, de securityfs y de selinuxfs (FASE 5.2 del MP-16).
//!
//! [`crate::posture`] mira media docena de sysctl en un escaneo puntual y los da
//! como hallazgos. Esto es lo que necesita un motor que vigila: cada ajuste
//! tiene una escala de proteccion (el `rango` de [`Lectura::Valor`], 0 = ninguna), una
//! linea base declarada en `tools/config/postura-kernel.toml`, una
//! recomendacion y su porque; y como el agente lo relee en caliente, se puede
//! ver a alguien BAJAR una proteccion ([`bajada`]).
//!
//! # Por que un rango y no el valor
//!
//! Porque el valor no ordena. En `unprivileged_bpf_disabled` el 1 protege mas
//! que el 2 (el 1 no se puede deshacer sin reiniciar); en `perf_event_paranoid`
//! el -1 y el 0 son lo mismo para un atacante; el modo de lockdown es una
//! palabra. Comparar valores en bruto haria de «subir» y «bajar» una loteria.
//!
//! # Ausente no es ilegible
//!
//! Que un fichero no exista dice algo del kernel: sin `kexec_load_disabled` no
//! hay kexec que deshabilitar (protegido); sin `yama/ptrace_scope` no hay Yama
//! (sin proteccion). Cada ajuste lo interpreta. Un fichero que existe y no se
//! puede leer, o que dice algo ininteligible, es «no pude mirar»
//! ([`Lectura::Ilegible`]) y nunca se confunde con un valor.
//!
//! # Disponible no es aplicado
//!
//! Para el MAC se distingue, como en `aegis-enforce`, lo que el kernel OFRECE de
//! lo que IMPONE: SELinux en permisivo o AppArmor sin un solo perfil en enforce
//! estan disponibles y no protegen nada.
//!
//! Todo toma una raiz para probarse sobre un `/proc/sys` simulado.

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::Path;

/// Un ajuste de endurecimiento del kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Ajuste {
    /// Modo de Kernel Lockdown.
    Lockdown,
    /// `kernel.kptr_restrict`.
    KptrRestrict,
    /// `kernel.dmesg_restrict`.
    DmesgRestrict,
    /// `kernel.unprivileged_bpf_disabled`.
    BpfSinPrivilegios,
    /// Espacios de nombres de usuario sin privilegios.
    UsernsSinPrivilegios,
    /// `kernel.yama.ptrace_scope`.
    PtraceYama,
    /// `kernel.perf_event_paranoid`.
    PerfParanoid,
    /// `kernel.kexec_load_disabled`.
    KexecDeshabilitado,
    /// `kernel.modules_disabled`.
    ModulosDeshabilitados,
    /// Control de acceso obligatorio: SELinux o AppArmor.
    Mac,
    /// `kernel.randomize_va_space` (ASLR).
    Aslr,
    /// `vm.mmap_min_addr`.
    MmapMinimo,
    /// `fs.suid_dumpable`.
    VolcadoSuid,
    /// `fs.protected_symlinks` y `fs.protected_hardlinks`.
    EnlacesProtegidos,
    /// `kernel.io_uring_disabled`.
    IoUringDeshabilitado,
}

const TODOS: [Ajuste; 15] = [
    Ajuste::Lockdown,
    Ajuste::KptrRestrict,
    Ajuste::DmesgRestrict,
    Ajuste::BpfSinPrivilegios,
    Ajuste::UsernsSinPrivilegios,
    Ajuste::PtraceYama,
    Ajuste::PerfParanoid,
    Ajuste::KexecDeshabilitado,
    Ajuste::ModulosDeshabilitados,
    Ajuste::Mac,
    Ajuste::Aslr,
    Ajuste::MmapMinimo,
    Ajuste::VolcadoSuid,
    Ajuste::EnlacesProtegidos,
    Ajuste::IoUringDeshabilitado,
];

const USERNS_MAX: &str = "/proc/sys/user/max_user_namespaces";
const USERNS_CLONE: &str = "/proc/sys/kernel/unprivileged_userns_clone";
const USERNS_APPARMOR: &str = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns";
const SELINUX_ENFORCE: &str = "/sys/fs/selinux/enforce";
const APPARMOR_ACTIVO: &str = "/sys/module/apparmor/parameters/enabled";
const APPARMOR_PERFILES: &str = "/sys/kernel/security/apparmor/profiles";
const ENLACES_SIMBOLICOS: &str = "/proc/sys/fs/protected_symlinks";
const ENLACES_DUROS: &str = "/proc/sys/fs/protected_hardlinks";

impl Ajuste {
    /// Todos los ajustes, en orden estable.
    #[must_use]
    pub fn todos() -> &'static [Ajuste] {
        &TODOS
    }

    /// Nombre estable: el de la linea base y el de los informes.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Ajuste::Lockdown => "lockdown",
            Ajuste::KptrRestrict => "kernel.kptr_restrict",
            Ajuste::DmesgRestrict => "kernel.dmesg_restrict",
            Ajuste::BpfSinPrivilegios => "kernel.unprivileged_bpf_disabled",
            Ajuste::UsernsSinPrivilegios => "userns",
            Ajuste::PtraceYama => "kernel.yama.ptrace_scope",
            Ajuste::PerfParanoid => "kernel.perf_event_paranoid",
            Ajuste::KexecDeshabilitado => "kernel.kexec_load_disabled",
            Ajuste::ModulosDeshabilitados => "kernel.modules_disabled",
            Ajuste::Mac => "mac",
            Ajuste::Aslr => "kernel.randomize_va_space",
            Ajuste::MmapMinimo => "vm.mmap_min_addr",
            Ajuste::VolcadoSuid => "fs.suid_dumpable",
            Ajuste::EnlacesProtegidos => "fs.protected_links",
            Ajuste::IoUringDeshabilitado => "kernel.io_uring_disabled",
        }
    }

    /// El ajuste de un nombre estable.
    #[must_use]
    pub fn de_nombre(nombre: &str) -> Option<Ajuste> {
        TODOS.iter().copied().find(|a| a.nombre() == nombre)
    }

    /// La ruta absoluta que lo representa. Nombra la entidad del ajuste.
    #[must_use]
    pub fn ruta(self) -> &'static str {
        match self {
            Ajuste::Lockdown => "/sys/kernel/security/lockdown",
            Ajuste::KptrRestrict => "/proc/sys/kernel/kptr_restrict",
            Ajuste::DmesgRestrict => "/proc/sys/kernel/dmesg_restrict",
            Ajuste::BpfSinPrivilegios => "/proc/sys/kernel/unprivileged_bpf_disabled",
            Ajuste::UsernsSinPrivilegios => USERNS_MAX,
            Ajuste::PtraceYama => "/proc/sys/kernel/yama/ptrace_scope",
            Ajuste::PerfParanoid => "/proc/sys/kernel/perf_event_paranoid",
            Ajuste::KexecDeshabilitado => "/proc/sys/kernel/kexec_load_disabled",
            Ajuste::ModulosDeshabilitados => "/proc/sys/kernel/modules_disabled",
            Ajuste::Mac => "/sys/kernel/security/lsm",
            Ajuste::Aslr => "/proc/sys/kernel/randomize_va_space",
            Ajuste::MmapMinimo => "/proc/sys/vm/mmap_min_addr",
            Ajuste::VolcadoSuid => "/proc/sys/fs/suid_dumpable",
            Ajuste::EnlacesProtegidos => ENLACES_SIMBOLICOS,
            Ajuste::IoUringDeshabilitado => "/proc/sys/kernel/io_uring_disabled",
        }
    }

    /// Las rutas cuya escritura cambia el ajuste. Sirven para atribuir una
    /// bajada al proceso que escribio.
    #[must_use]
    pub fn rutas_de_escritura(self) -> &'static [&'static str] {
        match self {
            Ajuste::Lockdown => &["/sys/kernel/security/lockdown"],
            Ajuste::KptrRestrict => &["/proc/sys/kernel/kptr_restrict"],
            Ajuste::DmesgRestrict => &["/proc/sys/kernel/dmesg_restrict"],
            Ajuste::BpfSinPrivilegios => &["/proc/sys/kernel/unprivileged_bpf_disabled"],
            Ajuste::UsernsSinPrivilegios => &[USERNS_MAX, USERNS_CLONE, USERNS_APPARMOR],
            Ajuste::PtraceYama => &["/proc/sys/kernel/yama/ptrace_scope"],
            Ajuste::PerfParanoid => &["/proc/sys/kernel/perf_event_paranoid"],
            Ajuste::KexecDeshabilitado => &["/proc/sys/kernel/kexec_load_disabled"],
            Ajuste::ModulosDeshabilitados => &["/proc/sys/kernel/modules_disabled"],
            Ajuste::Mac => &[
                SELINUX_ENFORCE,
                "/sys/kernel/security/apparmor/.remove",
                "/sys/kernel/security/apparmor/.replace",
                "/sys/kernel/security/apparmor/.load",
            ],
            Ajuste::Aslr => &["/proc/sys/kernel/randomize_va_space"],
            Ajuste::MmapMinimo => &["/proc/sys/vm/mmap_min_addr"],
            Ajuste::VolcadoSuid => &["/proc/sys/fs/suid_dumpable"],
            Ajuste::EnlacesProtegidos => &[ENLACES_SIMBOLICOS, ENLACES_DUROS],
            Ajuste::IoUringDeshabilitado => &["/proc/sys/kernel/io_uring_disabled"],
        }
    }

    /// El rango mas alto que puede tener.
    #[must_use]
    pub fn rango_maximo(self) -> u8 {
        match self {
            Ajuste::DmesgRestrict
            | Ajuste::KexecDeshabilitado
            | Ajuste::ModulosDeshabilitados
            | Ajuste::MmapMinimo
            | Ajuste::EnlacesProtegidos => 1,
            Ajuste::Lockdown
            | Ajuste::KptrRestrict
            | Ajuste::BpfSinPrivilegios
            | Ajuste::UsernsSinPrivilegios
            | Ajuste::Mac
            | Ajuste::Aslr
            | Ajuste::VolcadoSuid
            | Ajuste::IoUringDeshabilitado => 2,
            Ajuste::PtraceYama | Ajuste::PerfParanoid => 3,
        }
    }

    /// Si en este rango el kernel ya no deja bajarlo sin reiniciar.
    ///
    /// Verlo bajar en caliente desde ahi no es un administrador cambiando de
    /// opinion: es que alguien escribio en la memoria del kernel.
    #[must_use]
    pub fn irreversible(self, rango: u8) -> bool {
        match self {
            // El modo de lockdown solo sube en marcha.
            Ajuste::Lockdown => rango > 0,
            Ajuste::BpfSinPrivilegios => rango == 2,
            Ajuste::PtraceYama => rango == 3,
            Ajuste::KexecDeshabilitado | Ajuste::ModulosDeshabilitados => rango == 1,
            Ajuste::KptrRestrict
            | Ajuste::DmesgRestrict
            | Ajuste::UsernsSinPrivilegios
            | Ajuste::PerfParanoid
            | Ajuste::Mac
            | Ajuste::Aslr
            | Ajuste::MmapMinimo
            | Ajuste::VolcadoSuid
            | Ajuste::EnlacesProtegidos
            | Ajuste::IoUringDeshabilitado => false,
        }
    }

    /// Por que importa, en una frase.
    #[must_use]
    pub fn justificacion(self) -> &'static str {
        match self {
            Ajuste::Lockdown => {
                "impide que root modifique el kernel en marcha (/dev/mem, kexec y modulos sin \
                 firmar, MSR, hibernacion sin firmar): separa «ser root» de «ser dueño del kernel»"
            }
            Ajuste::KptrRestrict => {
                "oculta las direcciones del kernel en /proc/kallsyms y similares; un exploit \
                 local las usa para saltarse KASLR"
            }
            Ajuste::DmesgRestrict => {
                "el registro del kernel filtra direcciones y estado interno a cualquier usuario"
            }
            Ajuste::BpfSinPrivilegios => {
                "eBPF sin privilegios expone el verificador, con historial de escaladas \
                 (CVE-2021-3490, CVE-2022-23222), y canales laterales especulativos"
            }
            Ajuste::UsernsSinPrivilegios => {
                "un espacio de usuario sin privilegios da CAP_SYS_ADMIN dentro de el a cualquiera, \
                 y con ello la superficie de netfilter, overlayfs y montajes: la via de muchas \
                 escaladas locales (CVE-2022-0185, CVE-2023-0386, CVE-2024-1086)"
            }
            Ajuste::PtraceYama => {
                "sin restriccion, un proceso puede adjuntarse a cualquier otro del mismo usuario \
                 y leerle credenciales, tokens y claves del agente SSH"
            }
            Ajuste::PerfParanoid => {
                "perf_event sin privilegios es superficie del kernel con exploits y canales \
                 laterales conocidos; un usuario normal no lo necesita"
            }
            Ajuste::KexecDeshabilitado => {
                "kexec arranca otro kernel sin pasar por el firmware: con root, un kernel del \
                 atacante sin reiniciar el hardware"
            }
            Ajuste::ModulosDeshabilitados => {
                "un modulo cargado es codigo en ring 0: la via clasica del rootkit de kernel"
            }
            Ajuste::Mac => {
                "sin un MAC que IMPONGA, un servicio comprometido tiene todo lo que tiene su \
                 usuario; cargado en permisivo esta disponible, no aplicado"
            }
            Ajuste::Aslr => {
                "sin aleatorizacion de direcciones, la pila, el monton y las bibliotecas estan \
                 siempre en el mismo sitio y un fallo de memoria es mucho mas facil de aprovechar"
            }
            Ajuste::MmapMinimo => {
                "con 0, un proceso puede mapear la pagina cero y un puntero nulo en el kernel \
                 deja de ser un cuelgue para convertirse en una escalada"
            }
            Ajuste::VolcadoSuid => {
                "con 1, un programa setuid vuelca su memoria en un core legible por el usuario \
                 que lo lanzo: secretos de root en un fichero ajeno"
            }
            Ajuste::EnlacesProtegidos => {
                "sin ellos, un enlace plantado en /tmp o un enlace duro a un fichero ajeno \
                 desvia lo que escribe un proceso privilegiado (carreras TOCTOU clasicas)"
            }
            Ajuste::IoUringDeshabilitado => {
                "io_uring abierto a todos es una superficie grande del kernel con un historial \
                 largo de fallos, y sus operaciones no pasan por las llamadas al sistema que \
                 ve la telemetria clasica"
            }
        }
    }

    /// Que hacer para llegar al rango `minimo`.
    #[must_use]
    pub fn recomendacion(self, minimo: u8) -> String {
        match self {
            Ajuste::Lockdown => {
                "arrancar con lockdown=integrity (o con Secure Boot, que en muchas \
                 distribuciones lo activa); NO confidentiality: cierra bpf_probe_read_kernel y \
                 tracefs y deja ciega la telemetria del agente"
                    .to_string()
            }
            Ajuste::KptrRestrict | Ajuste::DmesgRestrict | Ajuste::PerfParanoid => format!(
                "sysctl -w {}={minimo} y persistirlo en /etc/sysctl.d/",
                self.nombre()
            ),
            Ajuste::BpfSinPrivilegios => "sysctl -w kernel.unprivileged_bpf_disabled=2 y \
                 persistirlo en /etc/sysctl.d/ (o =1, que ya no se puede deshacer sin reiniciar)"
                .to_string(),
            Ajuste::UsernsSinPrivilegios => "si no hay contenedores sin root ni navegadores que \
                 los usen para su sandbox: sysctl -w kernel.unprivileged_userns_clone=0 \
                 (Debian/Ubuntu) o kernel.apparmor_restrict_unprivileged_userns=1 (Ubuntu); \
                 user.max_user_namespaces=0 los quita a todos, root incluido"
                .to_string(),
            Ajuste::PtraceYama => format!(
                "sysctl -w kernel.yama.ptrace_scope={} y persistirlo; no 3: impide tambien a \
                 root leer memoria ajena y deja sin forense en vivo al motor de memoria del agente",
                minimo.clamp(1, 2)
            ),
            Ajuste::KexecDeshabilitado => "sysctl -w kernel.kexec_load_disabled=1 DESPUES de que \
                 kdump cargue su kernel de captura (no se deshace sin reiniciar)"
                .to_string(),
            Ajuste::ModulosDeshabilitados => "sysctl -w kernel.modules_disabled=1 al final del \
                 arranque, solo en hosts cuyo hardware no cambia: no se deshace y no se carga \
                 ningun modulo mas, tampoco legitimo"
                .to_string(),
            Ajuste::Mac => "SELinux en enforcing (setenforce 1 y SELINUX=enforcing en \
                 /etc/selinux/config) o perfiles AppArmor en enforce (aa-enforce) para los \
                 servicios expuestos"
                .to_string(),
            Ajuste::Aslr => "sysctl -w kernel.randomize_va_space=2 y persistirlo en \
                 /etc/sysctl.d/"
                .to_string(),
            Ajuste::MmapMinimo => "sysctl -w vm.mmap_min_addr=65536 y persistirlo en \
                 /etc/sysctl.d/"
                .to_string(),
            Ajuste::VolcadoSuid => "sysctl -w fs.suid_dumpable=0 (o 2, que solo deja volcar \
                 a root) y persistirlo en /etc/sysctl.d/"
                .to_string(),
            Ajuste::EnlacesProtegidos => "sysctl -w fs.protected_symlinks=1 \
                 fs.protected_hardlinks=1 y persistirlo en /etc/sysctl.d/"
                .to_string(),
            Ajuste::IoUringDeshabilitado => format!(
                "sysctl -w kernel.io_uring_disabled={} y persistirlo, si ningun servicio lo usa \
                 (algunas bases de datos y servidores de E/S lo usan; con 1 solo lo conserva el \
                 grupo kernel.io_uring_group)",
                minimo.clamp(1, 2)
            ),
        }
    }
}

/// Lo que se leyo de un ajuste.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lectura {
    /// Se pudo leer y entender.
    Valor {
        /// Lo leido, en una frase corta (`kernel.kptr_restrict=0`).
        texto: String,
        /// Nivel de proteccion: 0 es ninguna; ver [`Ajuste::rango_maximo`].
        rango: u8,
    },
    /// Existe y no se pudo leer o no se entiende: no se pudo mirar.
    Ilegible(String),
}

impl Lectura {
    /// El rango, si se pudo leer.
    #[must_use]
    pub fn rango(&self) -> Option<u8> {
        match self {
            Lectura::Valor { rango, .. } => Some(*rango),
            Lectura::Ilegible(_) => None,
        }
    }

    /// Lo leido, o el motivo de no poder leerlo.
    #[must_use]
    pub fn texto(&self) -> &str {
        match self {
            Lectura::Valor { texto, .. } => texto,
            Lectura::Ilegible(m) => m,
        }
    }
}

/// Contenido recortado del fichero, `None` si no existe.
fn crudo(raiz: &Path, ruta: &str) -> Result<Option<String>, String> {
    match std::fs::read_to_string(raiz.join(ruta.trim_start_matches('/'))) {
        Ok(s) => Ok(Some(s.trim().to_string())),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{ruta}: {e}")),
    }
}

fn entero(raiz: &Path, ruta: &str) -> Result<Option<i64>, String> {
    match crudo(raiz, ruta)? {
        None => Ok(None),
        Some(s) => s
            .parse::<i64>()
            .map(Some)
            .map_err(|_| format!("{ruta}: valor ininteligible {s:?}")),
    }
}

fn sujetar(v: i64, tope: u8) -> u8 {
    u8::try_from(v.clamp(0, i64::from(tope))).unwrap_or(0)
}

fn opcional(v: Option<i64>) -> String {
    v.map_or_else(|| "ausente".to_string(), |x| x.to_string())
}

/// Lee un ajuste bajo `raiz` (`/` en el host).
#[must_use]
pub fn leer(raiz: &Path, a: Ajuste) -> Lectura {
    match leer_valor(raiz, a) {
        Ok((texto, rango)) => Lectura::Valor { texto, rango },
        Err(m) => Lectura::Ilegible(m),
    }
}

/// Lee todos los ajustes.
#[must_use]
pub fn leer_todos(raiz: &Path) -> Vec<(Ajuste, Lectura)> {
    TODOS.iter().map(|&a| (a, leer(raiz, a))).collect()
}

fn leer_valor(raiz: &Path, a: Ajuste) -> Result<(String, u8), String> {
    let nombre = a.nombre();
    match a {
        Ajuste::Lockdown => {
            let Some(s) = crudo(raiz, a.ruta())? else {
                return Ok(("sin el LSM lockdown".to_string(), 0));
            };
            let modo = s
                .split_whitespace()
                .find(|p| p.starts_with('['))
                .map(|p| p.trim_matches(['[', ']']))
                .ok_or_else(|| format!("{}: sin modo entre corchetes: {s:?}", a.ruta()))?;
            let rango = match modo {
                "none" => 0,
                "integrity" => 1,
                "confidentiality" => 2,
                otro => return Err(format!("{}: modo desconocido {otro:?}", a.ruta())),
            };
            Ok((format!("lockdown={modo}"), rango))
        }
        Ajuste::KptrRestrict
        | Ajuste::DmesgRestrict
        | Ajuste::PtraceYama
        | Ajuste::KexecDeshabilitado
        | Ajuste::ModulosDeshabilitados => match entero(raiz, a.ruta())? {
            Some(v) => Ok((format!("{nombre}={v}"), sujetar(v, a.rango_maximo()))),
            None => match a {
                Ajuste::PtraceYama => Ok(("sin Yama en este kernel".to_string(), 0)),
                // Sin el sysctl no hay nada que deshabilitar: el kernel no lo trae.
                Ajuste::KexecDeshabilitado => Ok(("kernel sin kexec".to_string(), 1)),
                Ajuste::ModulosDeshabilitados => {
                    Ok(("kernel sin modulos cargables".to_string(), 1))
                }
                _ => Err(format!("{}: no existe", a.ruta())),
            },
        },
        Ajuste::BpfSinPrivilegios => match entero(raiz, a.ruta())? {
            None => Ok(("kernel sin la llamada bpf()".to_string(), 2)),
            Some(v) => {
                let rango = match v {
                    0 => 0,
                    2 => 1,
                    1 => 2,
                    otro => return Err(format!("{}: valor desconocido {otro}", a.ruta())),
                };
                Ok((format!("{nombre}={v}"), rango))
            }
        },
        Ajuste::PerfParanoid => match entero(raiz, a.ruta())? {
            None => Ok(("kernel sin perf_event".to_string(), 3)),
            Some(v) => Ok((format!("{nombre}={v}"), sujetar(v, 3))),
        },
        Ajuste::UsernsSinPrivilegios => {
            let max = entero(raiz, USERNS_MAX)?;
            let clone = entero(raiz, USERNS_CLONE)?;
            let apparmor = entero(raiz, USERNS_APPARMOR)?;
            let rango = if max.is_none() || max == Some(0) {
                2
            } else if clone == Some(0) || apparmor == Some(1) {
                1
            } else {
                0
            };
            Ok((
                format!(
                    "max_user_namespaces={} unprivileged_userns_clone={} \
                     apparmor_restrict_unprivileged_userns={}",
                    opcional(max),
                    opcional(clone),
                    opcional(apparmor)
                ),
                rango,
            ))
        }
        Ajuste::Mac => {
            if let Some(s) = crudo(raiz, SELINUX_ENFORCE)? {
                return match s.as_str() {
                    "1" => Ok(("selinux impone (enforcing)".to_string(), 2)),
                    "0" => Ok((
                        "selinux en permisivo: disponible, no aplicado".to_string(),
                        1,
                    )),
                    otro => Err(format!("{SELINUX_ENFORCE}: valor desconocido {otro:?}")),
                };
            }
            if crudo(raiz, APPARMOR_ACTIVO)?.as_deref() == Some("Y") {
                let perfiles = crudo(raiz, APPARMOR_PERFILES)?.ok_or_else(|| {
                    format!("apparmor activo sin {APPARMOR_PERFILES} (securityfs sin montar)")
                })?;
                let impuestos = perfiles
                    .lines()
                    .filter(|l| l.trim_end().ends_with("(enforce)"))
                    .count();
                let queja = perfiles
                    .lines()
                    .filter(|l| l.trim_end().ends_with("(complain)"))
                    .count();
                return Ok(if impuestos > 0 {
                    (
                        format!("apparmor impone {impuestos} perfil(es), {queja} en queja"),
                        2,
                    )
                } else {
                    (
                        format!(
                            "apparmor activo sin perfiles en enforce ({queja} en queja): \
                             disponible, no aplicado"
                        ),
                        1,
                    )
                });
            }
            Ok(("sin MAC: ni SELinux ni AppArmor activos".to_string(), 0))
        }
        Ajuste::Aslr => match entero(raiz, a.ruta())? {
            Some(v) => Ok((format!("{nombre}={v}"), sujetar(v, 2))),
            None => Err(format!("{}: no existe", a.ruta())),
        },
        Ajuste::MmapMinimo => match entero(raiz, a.ruta())? {
            // Por debajo de una pagina no protege la pagina cero.
            Some(v) => Ok((format!("{nombre}={v}"), u8::from(v >= 4096))),
            None => Err(format!("{}: no existe", a.ruta())),
        },
        Ajuste::VolcadoSuid => match entero(raiz, a.ruta())? {
            Some(v) => {
                let rango = match v {
                    1 => 0,
                    2 => 1,
                    0 => 2,
                    otro => return Err(format!("{}: valor desconocido {otro}", a.ruta())),
                };
                Ok((format!("{nombre}={v}"), rango))
            }
            None => Err(format!("{}: no existe", a.ruta())),
        },
        Ajuste::EnlacesProtegidos => {
            let simbolicos = entero(raiz, ENLACES_SIMBOLICOS)?;
            let duros = entero(raiz, ENLACES_DUROS)?;
            let rango = u8::from(simbolicos == Some(1) && duros == Some(1));
            Ok((
                format!(
                    "protected_symlinks={} protected_hardlinks={}",
                    opcional(simbolicos),
                    opcional(duros)
                ),
                rango,
            ))
        }
        Ajuste::IoUringDeshabilitado => match entero(raiz, a.ruta())? {
            Some(v) => Ok((format!("{nombre}={v}"), sujetar(v, 2))),
            // El interruptor llego en 6.6: sin el, io_uring (si el kernel lo
            // trae) queda abierto a todos y no se puede cerrar en marcha.
            None => Ok((
                "sin el interruptor io_uring_disabled (kernel anterior a 6.6)".to_string(),
                0,
            )),
        },
    }
}

/// Lo que exige la linea base de un ajuste.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nivel {
    /// Por debajo es una brecha.
    Base,
    /// Por debajo es un consejo: rompe algo legitimo en una parte de los hosts.
    Recomendado,
}

impl Nivel {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Nivel::Base => "base",
            Nivel::Recomendado => "recomendado",
        }
    }
}

/// La exigencia de la linea base para un ajuste.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exigencia {
    /// Rango minimo.
    pub minimo: u8,
    /// Si es base o recomendado.
    pub nivel: Nivel,
}

/// La linea base declarada.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LineaBase {
    exigencias: BTreeMap<Ajuste, Exigencia>,
}

impl LineaBase {
    /// Analiza el subconjunto de TOML de `tools/config/postura-kernel.toml`:
    /// una tabla `[linea_base]` con `"<ajuste>" = { minimo = N, nivel = "..." }`.
    ///
    /// Estricto a proposito: un ajuste mal escrito no puede convertirse en un
    /// ajuste sin vigilar.
    ///
    /// # Errores
    ///
    /// La primera linea que no entiende, con su numero.
    pub fn analizar(texto: &str) -> Result<LineaBase, String> {
        let mut exigencias = BTreeMap::new();
        let mut seccion = String::new();
        for (i, linea) in texto.lines().enumerate() {
            let n = i + 1;
            let l = linea.split('#').next().unwrap_or("").trim();
            if l.is_empty() {
                continue;
            }
            if l.starts_with('[') {
                seccion = l.trim_matches(['[', ']']).trim().to_string();
                continue;
            }
            if seccion != "linea_base" {
                continue;
            }
            let (clave, valor) = l
                .split_once('=')
                .ok_or_else(|| format!("linea {n}: falta '='"))?;
            let clave = clave.trim().trim_matches('"');
            let a = Ajuste::de_nombre(clave)
                .ok_or_else(|| format!("linea {n}: ajuste desconocido {clave:?}"))?;
            let cuerpo = valor
                .trim()
                .strip_prefix('{')
                .and_then(|v| v.strip_suffix('}'))
                .ok_or_else(|| {
                    format!("linea {n}: se esperaba {{ minimo = N, nivel = \"base|recomendado\" }}")
                })?;
            let mut minimo = None;
            let mut nivel = None;
            for campo in cuerpo.split(',') {
                let campo = campo.trim();
                if campo.is_empty() {
                    continue;
                }
                let (k, v) = campo
                    .split_once('=')
                    .ok_or_else(|| format!("linea {n}: campo sin '=': {campo:?}"))?;
                let v = v.trim();
                match k.trim() {
                    "minimo" => {
                        minimo = Some(v.parse::<u8>().map_err(|_| {
                            format!("linea {n}: minimo {v:?} no es un entero de 0 a 255")
                        })?);
                    }
                    "nivel" => {
                        nivel = Some(match v.trim_matches('"') {
                            "base" => Nivel::Base,
                            "recomendado" => Nivel::Recomendado,
                            otro => {
                                return Err(format!(
                                    "linea {n}: nivel {otro:?} desconocido (base o recomendado)"
                                ))
                            }
                        });
                    }
                    otro => return Err(format!("linea {n}: campo desconocido {otro:?}")),
                }
            }
            let (Some(minimo), Some(nivel)) = (minimo, nivel) else {
                return Err(format!("linea {n}: faltan minimo o nivel"));
            };
            if minimo > a.rango_maximo() {
                return Err(format!(
                    "linea {n}: {clave} no llega nunca a {minimo} (su rango maximo es {})",
                    a.rango_maximo()
                ));
            }
            if exigencias.insert(a, Exigencia { minimo, nivel }).is_some() {
                return Err(format!("linea {n}: {clave} repetido"));
            }
        }
        Ok(LineaBase { exigencias })
    }

    /// Lo que se exige a un ajuste, si se exige algo.
    #[must_use]
    pub fn exigencia(&self, a: Ajuste) -> Option<Exigencia> {
        self.exigencias.get(&a).copied()
    }

    /// Los ajustes que la linea base no declara.
    #[must_use]
    pub fn faltan(&self) -> Vec<Ajuste> {
        TODOS
            .iter()
            .copied()
            .filter(|a| !self.exigencias.contains_key(a))
            .collect()
    }
}

/// Un ajuste por debajo de la linea base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Brecha {
    /// El ajuste.
    pub ajuste: Ajuste,
    /// Lo leido.
    pub actual: String,
    /// Su rango.
    pub rango: u8,
    /// Lo exigido.
    pub exigencia: Exigencia,
    /// Que hacer.
    pub recomendacion: String,
}

/// La brecha de un ajuste frente a la linea base, si la hay. Lo ilegible no es
/// brecha: es no haber mirado, y se dice aparte.
#[must_use]
pub fn brecha(a: Ajuste, lectura: &Lectura, base: &LineaBase) -> Option<Brecha> {
    let Lectura::Valor { texto, rango } = lectura else {
        return None;
    };
    let exigencia = base.exigencia(a)?;
    (*rango < exigencia.minimo).then(|| Brecha {
        ajuste: a,
        actual: texto.clone(),
        rango: *rango,
        exigencia,
        recomendacion: a.recomendacion(exigencia.minimo),
    })
}

/// Una proteccion que bajo entre dos lecturas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bajada {
    /// El ajuste.
    pub ajuste: Ajuste,
    /// Lo leido antes.
    pub antes: String,
    /// Lo leido ahora.
    pub ahora: String,
    /// Rango antes.
    pub desde: u8,
    /// Rango ahora.
    pub hasta: u8,
    /// Si desde ese rango el kernel no deja bajar sin reiniciar.
    pub irreversible: bool,
}

/// Si el ajuste perdio proteccion entre `antes` y `ahora`. Subir no es noticia.
#[must_use]
pub fn bajada(a: Ajuste, antes: &Lectura, ahora: &Lectura) -> Option<Bajada> {
    let (Some(desde), Some(hasta)) = (antes.rango(), ahora.rango()) else {
        return None;
    };
    (hasta < desde).then(|| Bajada {
        ajuste: a,
        antes: antes.texto().to_string(),
        ahora: ahora.texto().to_string(),
        desde,
        hasta,
        irreversible: a.irreversible(desde),
    })
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use std::path::PathBuf;

    /// La linea base de verdad, la que embebe el agente.
    const DECLARADA: &str = include_str!("../../../tools/config/postura-kernel.toml");

    fn raiz(nombre: &str) -> PathBuf {
        let r = std::env::temp_dir().join(format!("aegis-nucleo-{}-{nombre}", std::process::id()));
        let _ = std::fs::remove_dir_all(&r);
        std::fs::create_dir_all(&r).unwrap();
        r
    }

    fn poner(raiz: &Path, ruta: &str, contenido: &str) {
        let p = raiz.join(ruta.trim_start_matches('/'));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, contenido).unwrap();
    }

    fn rango(raiz: &Path, a: Ajuste) -> u8 {
        leer(raiz, a)
            .rango()
            .unwrap_or_else(|| panic!("{a:?}: {:?}", leer(raiz, a)))
    }

    #[test]
    fn la_linea_base_declarada_cubre_todos_los_ajustes() {
        let b = LineaBase::analizar(DECLARADA).unwrap();
        assert!(b.faltan().is_empty(), "faltan {:?}", b.faltan());
        // Las dos elecciones que no son obvias quedan fijadas aqui.
        assert_eq!(b.exigencia(Ajuste::Lockdown).unwrap().minimo, 1);
        assert_eq!(b.exigencia(Ajuste::PtraceYama).unwrap().minimo, 1);
    }

    #[test]
    fn la_linea_base_es_estricta() {
        assert!(LineaBase::analizar(
            "[linea_base]\n\"kernel.kptr\" = { minimo = 1, nivel = \"base\" }"
        )
        .unwrap_err()
        .contains("desconocido"));
        assert!(LineaBase::analizar(
            "[linea_base]\n\"kernel.dmesg_restrict\" = { minimo = 2, nivel = \"base\" }"
        )
        .unwrap_err()
        .contains("rango maximo"));
        assert!(
            LineaBase::analizar("[linea_base]\n\"mac\" = { minimo = 2, nivel = \"alto\" }")
                .unwrap_err()
                .contains("nivel")
        );
        let doble = "[linea_base]\n\"mac\" = { minimo = 2, nivel = \"base\" }\n\"mac\" = { minimo = 1, nivel = \"base\" }";
        assert!(LineaBase::analizar(doble).unwrap_err().contains("repetido"));
        // Fuera de [linea_base] no se mira.
        assert_eq!(
            LineaBase::analizar("[otra]\nx = 1\n")
                .unwrap()
                .faltan()
                .len(),
            TODOS.len()
        );
    }

    #[test]
    fn el_rango_ordena_lo_que_el_valor_no() {
        let r = raiz("rango");
        poner(&r, "/proc/sys/kernel/unprivileged_bpf_disabled", "2\n");
        assert_eq!(rango(&r, Ajuste::BpfSinPrivilegios), 1);
        poner(&r, "/proc/sys/kernel/unprivileged_bpf_disabled", "1\n");
        assert_eq!(rango(&r, Ajuste::BpfSinPrivilegios), 2);
        assert!(Ajuste::BpfSinPrivilegios.irreversible(2));
        poner(&r, "/proc/sys/kernel/perf_event_paranoid", "-1\n");
        assert_eq!(rango(&r, Ajuste::PerfParanoid), 0);
        poner(&r, "/proc/sys/kernel/perf_event_paranoid", "4\n");
        assert_eq!(rango(&r, Ajuste::PerfParanoid), 3);
        poner(
            &r,
            "/sys/kernel/security/lockdown",
            "none [integrity] confidentiality\n",
        );
        assert_eq!(rango(&r, Ajuste::Lockdown), 1);
        // suid_dumpable: el 0 protege mas que el 2, y el 1 es lo peor.
        poner(&r, "/proc/sys/fs/suid_dumpable", "1\n");
        assert_eq!(rango(&r, Ajuste::VolcadoSuid), 0);
        poner(&r, "/proc/sys/fs/suid_dumpable", "2\n");
        assert_eq!(rango(&r, Ajuste::VolcadoSuid), 1);
        poner(&r, "/proc/sys/fs/suid_dumpable", "0\n");
        assert_eq!(rango(&r, Ajuste::VolcadoSuid), 2);
        poner(&r, "/proc/sys/fs/suid_dumpable", "3\n");
        assert!(matches!(
            leer(&r, Ajuste::VolcadoSuid),
            Lectura::Ilegible(_)
        ));
        // mmap_min_addr: por debajo de una pagina no protege la pagina cero.
        poner(&r, "/proc/sys/vm/mmap_min_addr", "0\n");
        assert_eq!(rango(&r, Ajuste::MmapMinimo), 0);
        poner(&r, "/proc/sys/vm/mmap_min_addr", "65536\n");
        assert_eq!(rango(&r, Ajuste::MmapMinimo), 1);
        // Los dos enlaces protegidos, o ninguno cuenta.
        poner(&r, "/proc/sys/fs/protected_symlinks", "1\n");
        poner(&r, "/proc/sys/fs/protected_hardlinks", "0\n");
        assert_eq!(rango(&r, Ajuste::EnlacesProtegidos), 0);
        poner(&r, "/proc/sys/fs/protected_hardlinks", "1\n");
        assert_eq!(rango(&r, Ajuste::EnlacesProtegidos), 1);
        poner(&r, "/proc/sys/kernel/io_uring_disabled", "2\n");
        assert_eq!(rango(&r, Ajuste::IoUringDeshabilitado), 2);
        poner(&r, "/proc/sys/kernel/randomize_va_space", "1\n");
        assert_eq!(rango(&r, Ajuste::Aslr), 1);
        let _ = std::fs::remove_dir_all(&r);
    }

    #[test]
    fn ausente_dice_algo_del_kernel_y_cada_ajuste_lo_interpreta() {
        let r = raiz("ausente");
        assert_eq!(rango(&r, Ajuste::Lockdown), 0);
        assert_eq!(rango(&r, Ajuste::PtraceYama), 0);
        assert_eq!(rango(&r, Ajuste::KexecDeshabilitado), 1);
        assert_eq!(rango(&r, Ajuste::ModulosDeshabilitados), 1);
        assert_eq!(rango(&r, Ajuste::UsernsSinPrivilegios), 2);
        assert_eq!(rango(&r, Ajuste::Mac), 0);
        // Sin el interruptor (kernel < 6.6) io_uring queda abierto.
        assert_eq!(rango(&r, Ajuste::IoUringDeshabilitado), 0);
        assert_eq!(rango(&r, Ajuste::EnlacesProtegidos), 0);
        // ASLR y mmap_min_addr existen en todo kernel: que falten no es un valor.
        assert!(matches!(leer(&r, Ajuste::Aslr), Lectura::Ilegible(_)));
        assert!(matches!(leer(&r, Ajuste::MmapMinimo), Lectura::Ilegible(_)));
        // kptr_restrict existe en todo kernel moderno: que falte no es un valor.
        assert!(matches!(
            leer(&r, Ajuste::KptrRestrict),
            Lectura::Ilegible(_)
        ));
        let _ = std::fs::remove_dir_all(&r);
    }

    #[test]
    fn ilegible_no_es_un_valor() {
        let r = raiz("ilegible");
        // Un directorio donde se espera un fichero: existe y no se puede leer.
        std::fs::create_dir_all(r.join("proc/sys/kernel/kptr_restrict")).unwrap();
        poner(&r, "/proc/sys/kernel/dmesg_restrict", "quizas\n");
        assert!(matches!(
            leer(&r, Ajuste::KptrRestrict),
            Lectura::Ilegible(_)
        ));
        let Lectura::Ilegible(m) = leer(&r, Ajuste::DmesgRestrict) else {
            panic!()
        };
        assert!(m.contains("ininteligible"), "{m}");
        let base = LineaBase::analizar(DECLARADA).unwrap();
        assert!(brecha(Ajuste::KptrRestrict, &leer(&r, Ajuste::KptrRestrict), &base).is_none());
        let _ = std::fs::remove_dir_all(&r);
    }

    #[test]
    fn userns_y_mac_distinguen_disponible_de_aplicado() {
        let r = raiz("mac");
        poner(&r, USERNS_MAX, "63000\n");
        poner(&r, USERNS_CLONE, "1\n");
        assert_eq!(rango(&r, Ajuste::UsernsSinPrivilegios), 0);
        poner(&r, USERNS_APPARMOR, "1\n");
        assert_eq!(rango(&r, Ajuste::UsernsSinPrivilegios), 1);

        poner(&r, APPARMOR_ACTIVO, "Y\n");
        poner(&r, APPARMOR_PERFILES, "/usr/sbin/cupsd (complain)\n");
        assert_eq!(
            rango(&r, Ajuste::Mac),
            1,
            "AppArmor sin enforce no aplica nada"
        );
        poner(
            &r,
            APPARMOR_PERFILES,
            "/usr/sbin/cupsd (complain)\n/usr/sbin/nginx (enforce)\n",
        );
        assert_eq!(rango(&r, Ajuste::Mac), 2);
        // SELinux manda si esta montado.
        poner(&r, SELINUX_ENFORCE, "0");
        let l = leer(&r, Ajuste::Mac);
        assert_eq!(l.rango(), Some(1));
        assert!(l.texto().contains("permisivo"), "{l:?}");
        let _ = std::fs::remove_dir_all(&r);
    }

    #[test]
    fn brecha_y_bajada() {
        let base = LineaBase::analizar(DECLARADA).unwrap();
        let cero = Lectura::Valor {
            texto: "kernel.kptr_restrict=0".into(),
            rango: 0,
        };
        let uno = Lectura::Valor {
            texto: "kernel.kptr_restrict=1".into(),
            rango: 1,
        };
        let b = brecha(Ajuste::KptrRestrict, &cero, &base).unwrap();
        assert_eq!(b.exigencia.nivel, Nivel::Base);
        assert!(b.recomendacion.contains("sysctl -w kernel.kptr_restrict=1"));
        assert!(brecha(Ajuste::KptrRestrict, &uno, &base).is_none());

        let baja = bajada(Ajuste::KptrRestrict, &uno, &cero).unwrap();
        assert!(!baja.irreversible);
        assert!(
            bajada(Ajuste::KptrRestrict, &cero, &uno).is_none(),
            "subir no es noticia"
        );
        let modulos_si = Lectura::Valor {
            texto: "kernel.modules_disabled=1".into(),
            rango: 1,
        };
        let modulos_no = Lectura::Valor {
            texto: "kernel.modules_disabled=0".into(),
            rango: 0,
        };
        assert!(
            bajada(Ajuste::ModulosDeshabilitados, &modulos_si, &modulos_no)
                .unwrap()
                .irreversible
        );
        assert!(bajada(Ajuste::KptrRestrict, &Lectura::Ilegible("x".into()), &cero).is_none());
    }
}
