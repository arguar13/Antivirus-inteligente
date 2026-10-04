//! Los motores del agente, detras del contrato unico de [`aegis_motor`].
//!
//! Este modulo es la UNICA puerta entre el agente y sus motores: cada motor se
//! adapta aqui al trait [`aegis_motor::Motor`], se registra en el arbitro y solo
//! el arbitro lo invoca. La puerta `motores` de make ci comprueba que ningun otro
//! sitio del agente llame a un motor ni combine veredictos por su cuenta.

pub mod baliza;
pub mod conducta;
#[cfg(target_os = "linux")]
pub mod estatico;
pub mod integridad;
#[cfg(target_os = "linux")]
pub mod memoria;
#[cfg(all(target_os = "linux", feature = "bpf"))]
pub mod nucleo;
#[cfg(target_os = "linux")]
pub mod postura;
pub mod rol;
pub mod secuestro;
pub mod sigma;
pub mod triaje;
// La fuente de verdad de los motores registrables (Hallazgo 0 de la
// FASE 4): de aqui salen tanto lo que el arbitro registra como lo que
// `--motores` imprime.
#[cfg(target_os = "linux")]
pub mod registro;

use std::path::Path;

use aegis_entidad::entidad::{maquina, proceso_por_clave};
use aegis_entidad::Eid;
use aegis_motor::{Evento, Host, Requisito};

use crate::capacidades::{Capacidades, Tri};
use crate::triage::TelemetryEvent;

/// Quien es esta maquina y en que arranque esta, para nombrar los procesos.
#[derive(Debug, Clone)]
pub struct Identidad {
    /// La maquina.
    pub maquina: Eid,
    /// El arranque actual: las claves de proceso del kernel solo son unicas
    /// dentro de un arranque.
    pub boot: u64,
}

impl Identidad {
    /// La del host en el que corre el agente.
    ///
    /// `/etc/machine-id` identifica la instalacion; `boot_id`, el arranque. Si
    /// falta alguno se usa un valor fijo y se dice: los procesos seguiran siendo
    /// distinguibles entre si, solo que no entre maquinas o arranques.
    pub fn del_host() -> Identidad {
        let id = leer_primera_linea(Path::new("/etc/machine-id")).unwrap_or_else(|| {
            eprintln!("aegis-agent: sin /etc/machine-id; la maquina se nombra como «desconocida»");
            "desconocida".to_string()
        });
        let boot = leer_primera_linea(Path::new("/proc/sys/kernel/random/boot_id"))
            .map(|b| boot_de(&b))
            .unwrap_or(0);
        Identidad {
            maquina: maquina(&id),
            boot,
        }
    }

    /// Una identidad fija, para pruebas.
    pub fn fija(nombre: &str) -> Identidad {
        Identidad {
            maquina: maquina(nombre),
            boot: 1,
        }
    }
}

fn leer_primera_linea(ruta: &Path) -> Option<String> {
    let s = std::fs::read_to_string(ruta).ok()?;
    let l = s.lines().next()?.trim().to_string();
    (!l.is_empty()).then_some(l)
}

/// Los primeros 64 bits del UUID de arranque.
fn boot_de(uuid: &str) -> u64 {
    let hex: String = uuid
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(16)
        .collect();
    u64::from_str_radix(&hex, 16).unwrap_or(0)
}

/// Un evento de telemetria con la entidad a la que se refiere.
#[derive(Debug, Clone)]
pub struct EventoAgente {
    /// El evento del kernel, ya decodificado.
    pub evento: TelemetryEvent,
    /// El proceso que lo protagoniza.
    pub entidad: Eid,
}

impl EventoAgente {
    /// Nombra el proceso protagonista del evento.
    pub fn nuevo(evento: TelemetryEvent, identidad: &Identidad) -> EventoAgente {
        let entidad = proceso_por_clave(&identidad.maquina, identidad.boot, evento.actor().0);
        EventoAgente { evento, entidad }
    }
}

impl Evento for EventoAgente {
    fn entidad(&self) -> Eid {
        self.entidad.clone()
    }
    fn cuando_ns(&self) -> u64 {
        self.evento.ts_ns()
    }
}

/// Lo que este host ofrece a los motores, segun la deteccion de capacidades.
pub struct HostAgente<'a> {
    caps: &'a Capacidades,
    trabajador: Result<(), String>,
}

impl<'a> HostAgente<'a> {
    /// Sobre las capacidades detectadas al arrancar.
    ///
    /// `trabajador` dice si el trabajador confinado esta arrancado, o por que no.
    pub fn nuevo(caps: &'a Capacidades, trabajador: Result<(), String>) -> HostAgente<'a> {
        HostAgente { caps, trabajador }
    }
}

fn tri(t: &Tri, que: &str) -> Result<(), String> {
    match t {
        Tri::Si => Ok(()),
        Tri::No => Err(format!("{que}: no")),
        Tri::Desconocido(m) => Err(format!("{que}: desconocido ({m})")),
    }
}

impl Host for HostAgente<'_> {
    fn ofrece(&self, requisito: Requisito) -> Result<(), String> {
        match requisito {
            Requisito::TelemetriaKernel => {
                if self.caps.tracefs.is_none() {
                    return Err("tracefs no esta montado".into());
                }
                tri(&self.caps.sondeo.ringbuf, "ring buffer BPF")
            }
            Requisito::BpfLsm => tri(&self.caps.bpf_lsm(), "bpf en la lista lsm= activa"),
            Requisito::TrabajadorConfinado => self.trabajador.clone(),
            Requisito::Kvm => {
                if Path::new("/dev/kvm").exists() {
                    Ok(())
                } else {
                    Err("no hay /dev/kvm".into())
                }
            }
            Requisito::MemoriaAjena => memoria_ajena(
                std::fs::read_to_string("/proc/self/status").ok().as_deref(),
                leer_primera_linea(Path::new("/proc/sys/kernel/yama/ptrace_scope")).as_deref(),
            ),
            Requisito::KfuncsTareas => match std::fs::read("/sys/kernel/btf/vmlinux") {
                Ok(btf) => kfuncs_tareas(
                    &btf,
                    std::fs::read_to_string("/proc/self/status").ok().as_deref(),
                ),
                Err(e) => Err(format!("sin /sys/kernel/btf/vmlinux: {e}")),
            },
        }
    }
}

/// Los kfuncs que llaman los programas de la verificacion cruzada de tareas.
///
/// Son TODOS los que `aegis_kintegrity.bpf.c` declara `__ksym`, no una
/// muestra: una prueba de abajo coteja esta lista con ese fichero.
const KFUNCS_TAREAS: [&str; 7] = [
    "bpf_iter_task_new",
    "bpf_iter_task_next",
    "bpf_iter_task_destroy",
    "bpf_task_from_pid",
    "bpf_task_release",
    "bpf_rcu_read_lock",
    "bpf_rcu_read_unlock",
];

/// CAP_SYS_ADMIN; desde Linux 5.8 abarca a CAP_BPF y a CAP_PERFMON.
const CAP_SYS_ADMIN: u32 = 21;
/// CAP_PERFMON.
const CAP_PERFMON: u32 = 38;
/// CAP_BPF.
const CAP_BPF: u32 = 39;

/// Si este kernel y este proceso pueden sostener la verificacion cruzada de
/// tareas.
///
/// # Lo que se promete, y por que ahora se puede
///
/// Que el BTF DECLARE un kfunc no dice que un programa pueda LLAMARLO: el
/// kernel lo registra por tipo de programa (`kfunc_init`, en
/// kernel/bpf/helpers.c). Medido en el codigo del kernel:
///
/// | kfunc | TRACING | SYSCALL |
/// |---|---|---|
/// | `bpf_task_from_pid`, `bpf_task_release` | desde 6.2, cuando aparecen | desde 6.10 |
/// | `bpf_iter_task_*` (6.7), `bpf_rcu_read_*` (6.2) | todos los tipos | todos los tipos |
///
/// Con los programas `SEC("syscall")` esta sonda prometia de mas en 6.7-6.9:
/// Ubuntu 24.04 (6.8) declara `bpf_task_from_pid` y lo rechaza en ese tipo.
/// Los programas son ahora iteradores `iter.s/task` (tipo TRACING), y para
/// TRACING declarado equivale a permitido en todo kernel de la rama principal:
/// la sonda puede decidir por el BTF. Una prueba de abajo ata esta promesa a
/// la seccion de los programas del objeto; si alguien vuelve a `syscall`, cae.
///
/// Lo que el tipo TRACING exige y el BTF no dice son privilegios: CAP_BPF y
/// CAP_PERFMON, o CAP_SYS_ADMIN, donde `syscall` se conformaba con CAP_BPF.
///
/// Los nombres se buscan ENTRE NUL en la tabla de cadenas del BTF: la version
/// del kernel no sirve, porque RHEL los trae por backport y otros los quitan
/// de la configuracion. La ultima palabra la tiene la carga: un kernel con
/// parches propios que declare y no permita deja el motor sin datos con el
/// motivo del verificador, y la matriz de kernels lo cuenta como fallo de esta
/// sonda.
fn kfuncs_tareas(btf: &[u8], status: Option<&str>) -> Result<(), String> {
    let faltan: Vec<&str> = KFUNCS_TAREAS
        .iter()
        .copied()
        .filter(|k| {
            let mut aguja = vec![0u8];
            aguja.extend_from_slice(k.as_bytes());
            aguja.push(0);
            !btf.windows(aguja.len()).any(|w| w == aguja.as_slice())
        })
        .collect();
    if faltan.is_empty() {
        privilegios_tracing(status)
    } else {
        Err(format!(
            "el kernel no declara {} (Linux 6.7+)",
            faltan.join(", ")
        ))
    }
}

/// El conjunto efectivo de capacidades de un `/proc/<pid>/status`.
fn cap_eff(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|h| u64::from_str_radix(h.trim(), 16).ok())
}

/// Si este proceso puede cargar y enlazar un programa TRACING.
fn privilegios_tracing(status: Option<&str>) -> Result<(), String> {
    let status = status.ok_or("sin /proc/self/status")?;
    let caps = cap_eff(status).ok_or("CapEff ilegible en /proc/self/status")?;
    let tiene = |c: u32| caps & (1u64 << c) != 0;
    if tiene(CAP_SYS_ADMIN) || (tiene(CAP_BPF) && tiene(CAP_PERFMON)) {
        Ok(())
    } else {
        Err("un programa tracing exige CAP_BPF y CAP_PERFMON, o CAP_SYS_ADMIN".into())
    }
}

/// CAP_SYS_PTRACE en el conjunto efectivo.
const CAP_SYS_PTRACE: u32 = 19;

/// Si este proceso puede leer la memoria de otros, segun su `status` y Yama.
///
/// Se decide sobre el texto para poder probar cada rama sin privilegios.
fn memoria_ajena(status: Option<&str>, yama: Option<&str>) -> Result<(), String> {
    if yama == Some("3") {
        return Err("Yama ptrace_scope=3: nadie puede leer memoria ajena, root incluido".into());
    }
    let status = status.ok_or("sin /proc/self/status")?;
    let cap_eff = status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|h| u64::from_str_radix(h.trim(), 16).ok())
        .ok_or("CapEff ilegible en /proc/self/status")?;
    if cap_eff & (1u64 << CAP_SYS_PTRACE) == 0 {
        return Err("sin CAP_SYS_PTRACE en el conjunto efectivo".into());
    }
    Ok(())
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Una tabla de cadenas de BTF con esos nombres, cada uno entre NUL.
    fn btf_con(nombres: &[&str]) -> Vec<u8> {
        let mut b = vec![0u8];
        for n in nombres {
            b.extend_from_slice(n.as_bytes());
            b.push(0);
        }
        b
    }

    /// Un `status` cuyo `CapEff` tiene exactamente esas capacidades.
    fn status_con(caps: &[u32]) -> String {
        let mascara = caps.iter().fold(0u64, |m, c| m | (1u64 << c));
        format!("CapEff: {mascara:016x}")
    }

    /// El objeto eBPF de la verificacion cruzada, tal y como se compila.
    const OBJETO_TAREAS: &str =
        include_str!("../../../../drivers/linux/aegis-bpf/src/aegis_kintegrity.bpf.c");

    /// La seccion de los programas de tareas: iteradores de tareas durmientes,
    /// que el kernel carga como programas de tipo TRACING.
    const SECCION_TAREAS: &str = "iter.s/task";

    #[test]
    fn los_kfuncs_se_buscan_como_nombres_completos() {
        let root = status_con(&[CAP_SYS_ADMIN]);
        assert!(kfuncs_tareas(&btf_con(&KFUNCS_TAREAS), Some(&root)).is_ok());
        // Ni un prefijo ni un sufijo valen: bpf_iter_task_new_x y
        // xbpf_iter_task_new no declaran bpf_iter_task_new.
        for impostor in ["bpf_iter_task_new_x", "xbpf_iter_task_new"] {
            let mut nombres = KFUNCS_TAREAS.to_vec();
            nombres[0] = impostor;
            let e = kfuncs_tareas(&btf_con(&nombres), Some(&root)).unwrap_err();
            assert!(e.contains("bpf_iter_task_new"), "{e}");
        }
        // Un 6.2-6.6: tiene bpf_task_from_pid y el RCU, no el iterador abierto.
        let viejo = btf_con(&[
            "bpf_task_from_pid",
            "bpf_task_release",
            "bpf_rcu_read_lock",
            "bpf_rcu_read_unlock",
        ]);
        let e = kfuncs_tareas(&viejo, Some(&root)).unwrap_err();
        assert!(
            e.contains("bpf_iter_task_new")
                && e.contains("bpf_iter_task_destroy")
                && !e.contains("bpf_task_from_pid"),
            "{e}"
        );
    }

    #[test]
    fn el_tipo_tracing_exige_cap_bpf_y_cap_perfmon() {
        let btf = btf_con(&KFUNCS_TAREAS);
        let con = |caps: &[u32]| kfuncs_tareas(&btf, Some(&status_con(caps)));
        assert!(con(&[CAP_BPF, CAP_PERFMON]).is_ok());
        assert!(con(&[CAP_SYS_ADMIN]).is_ok());
        // CAP_BPF basta para un programa syscall; para uno tracing, no.
        let e = con(&[CAP_BPF]).unwrap_err();
        assert!(e.contains("CAP_PERFMON"), "{e}");
        assert!(con(&[CAP_PERFMON]).is_err());
        assert!(con(&[]).is_err());
        assert!(kfuncs_tareas(&btf, Some("sin campo")).is_err());
        assert!(kfuncs_tareas(&btf, None).is_err());
    }

    #[test]
    fn la_sonda_comprueba_exactamente_los_kfuncs_que_llama_el_objeto() {
        let mut declarados: Vec<&str> = OBJETO_TAREAS
            .lines()
            .map(str::trim_start)
            .filter(|l| l.starts_with("extern "))
            .filter_map(|l| l.split_once('(').map(|(antes, _)| antes))
            .filter_map(|antes| antes.rsplit_once([' ', '*']))
            .map(|(_, nombre)| nombre)
            .collect();
        declarados.sort_unstable();
        let mut sonda = KFUNCS_TAREAS.to_vec();
        sonda.sort_unstable();
        assert_eq!(declarados, sonda);
    }

    #[test]
    fn la_promesa_de_la_sonda_esta_atada_al_tipo_de_programa() {
        // La tabla de `kfuncs_tareas` vale para TRACING: con `SEC("syscall")`
        // la sonda volveria a prometer en 6.7-6.9 lo que ese tipo no permite.
        let esperada = format!("SEC({SECCION_TAREAS:?})");
        let secciones: Vec<&str> = OBJETO_TAREAS
            .lines()
            .map(str::trim_start)
            .filter(|l| l.starts_with("SEC("))
            .collect();
        assert_eq!(secciones.len(), 2, "{secciones:?}");
        assert!(secciones.iter().all(|s| *s == esperada), "{secciones:?}");
    }

    #[test]
    fn memoria_ajena_exige_la_capacidad_y_que_yama_no_la_cierre() {
        let root = "Name:\taegis\nCapEff:\t000001ffffffffff\n";
        let sin = "Name:\taegis\nCapEff:\t0000000000000000\n";
        assert!(memoria_ajena(Some(root), Some("1")).is_ok());
        assert!(memoria_ajena(Some(root), None).is_ok());
        assert!(memoria_ajena(Some(root), Some("3"))
            .unwrap_err()
            .contains("Yama"));
        assert!(memoria_ajena(Some(sin), Some("0"))
            .unwrap_err()
            .contains("CAP_SYS_PTRACE"));
        assert!(memoria_ajena(Some("sin campo"), None).is_err());
        assert!(memoria_ajena(None, None).is_err());
    }

    #[test]
    fn el_boot_id_da_un_entero_estable() {
        let a = boot_de("6f1c2a3b-4d5e-6f70-8192-a3b4c5d6e7f8");
        assert_eq!(a, 0x6f1c_2a3b_4d5e_6f70);
        assert_eq!(boot_de(""), 0);
    }
}
