//! Los motores del agente, detras del contrato unico de [`aegis_motor`].
//!
//! Este modulo es la UNICA puerta entre el agente y sus motores: cada motor se
//! adapta aqui al trait [`aegis_motor::Motor`], se registra en el arbitro y solo
//! el arbitro lo invoca. La puerta `motores` de make ci comprueba que ningun otro
//! sitio del agente llame a un motor ni combine veredictos por su cuenta.

pub mod conducta;
#[cfg(target_os = "linux")]
pub mod estatico;
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
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn el_boot_id_da_un_entero_estable() {
        let a = boot_de("6f1c2a3b-4d5e-6f70-8192-a3b4c5d6e7f8");
        assert_eq!(a, 0x6f1c_2a3b_4d5e_6f70);
        assert_eq!(boot_de(""), 0);
    }
}
