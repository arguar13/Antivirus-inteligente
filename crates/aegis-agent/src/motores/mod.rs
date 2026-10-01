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
pub mod secuestro;
pub mod triaje;

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
                Ok(btf) => kfuncs_tareas(&btf),
                Err(e) => Err(format!("sin /sys/kernel/btf/vmlinux: {e}")),
            },
        }
    }
}

/// Los kfuncs que necesita la verificacion cruzada de tareas.
const KFUNCS_TAREAS: [&str; 3] = [
    "bpf_iter_task_new",
    "bpf_iter_task_next",
    "bpf_task_from_pid",
];

/// Si el BTF del kernel declara los kfuncs de tareas.
///
/// Se busca el nombre ENTRE NUL en la tabla de cadenas del BTF: la
/// version del kernel no sirve, porque RHEL los trae por backport y otros los
/// quitan de la configuracion.
fn kfuncs_tareas(btf: &[u8]) -> Result<(), String> {
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
        Ok(())
    } else {
        Err(format!(
            "el kernel no declara {} (Linux 6.7+)",
            faltan.join(", ")
        ))
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

    #[test]
    fn los_kfuncs_se_buscan_como_nombres_completos() {
        let todo = b"\0bpf_iter_task_new\0bpf_iter_task_next\0bpf_task_from_pid\0";
        assert!(kfuncs_tareas(todo).is_ok());
        // Ni un prefijo ni un sufijo valen: bpf_iter_task_new_x y
        // xbpf_iter_task_new no declaran bpf_iter_task_new.
        let prefijo = b"\0bpf_iter_task_new_x\0bpf_iter_task_next\0bpf_task_from_pid\0";
        assert!(kfuncs_tareas(prefijo)
            .unwrap_err()
            .contains("bpf_iter_task_new"));
        let sufijo = b"\0xbpf_iter_task_new\0bpf_iter_task_next\0bpf_task_from_pid\0";
        assert!(kfuncs_tareas(sufijo).is_err());
        let viejo = b"\0bpf_task_from_pid\0";
        let e = kfuncs_tareas(viejo).unwrap_err();
        assert!(
            e.contains("bpf_iter_task_new") && e.contains("bpf_iter_task_next"),
            "{e}"
        );
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
