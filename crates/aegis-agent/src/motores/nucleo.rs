//! Integridad del kernel: procesos que el sistema esconde (FASE 2 del MP-16,
//! ola A).
//!
//! `aegis-kintegrity` compara tres censos de tareas —`/proc`, la lista de
//! tareas del kernel y el espacio de PID— tomados por caminos distintos, y
//! confirma cada discrepancia antes de acusar. Este motor lo barre cada
//! [`CADA_NS`] en el camino frio y entrega lo confirmado.
//!
//! # A quien se señala
//!
//! A la MAQUINA. Un proceso escondido por DKOM no es el culpable de nada que se
//! pueda atribuir a su entidad —el agente nunca vio su clave—: lo comprometido
//! es el kernel que miente, y eso es de la maquina.
//!
//! # Lo que no se pudo mirar no es limpio
//!
//! Un barrido en el que los censos no numeran igual (el agente en otro espacio
//! de nombres de PID) o en el que algo no cupo en los mapas no concluye nada, y
//! se entrega como `SinDatos` con el motivo, una vez por motivo.
//!
//! # Nace en solo-auditoria
//!
//! Solo señala; `exige_mitigacion` del crate no se consulta todavia.

use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::time::Duration;

use aegis_entidad::{Confianza, Eid, Juicio, Motor as Firma, Senal, Severidad};
use aegis_kintegrity::{Anomaly, BpfViews, KernelIntegrity, KiConfig, ScanReport};
use aegis_motor::{Camino, Causa, Dictamen, Ficha, Motor, Plazo, Presupuesto, Requisito};

use crate::motores::{EventoAgente, Identidad};

/// Cada cuanto se barre.
const CADA: Duration = Duration::from_secs(30);

/// Lo que el hilo del barrido entrega.
type Barrido = Result<ScanReport, String>;

/// El hilo que posee el verificador eBPF.
///
/// Vive aparte por dos razones, y las dos bastarian solas: un barrido recorre
/// todo el rango de PID y no puede parar el bucle de eventos del agente; y el
/// objeto de libbpf no se puede mover entre hilos, asi que quien lo carga tiene
/// que ser quien lo usa. El hilo termina cuando el motor se suelta: se cierra
/// `parar` y su espera entre barridos vuelve con desconexion.
struct Hilo {
    informes: Receiver<Barrido>,
    _parar: Sender<()>,
}

fn arrancar() -> Hilo {
    let (tx, informes) = mpsc::channel();
    let (parar, paro) = mpsc::channel::<()>();
    let lanzado = std::thread::Builder::new()
        .name("aegis-nucleo".into())
        .spawn(move || {
            let mut ki = match BpfViews::cargar() {
                Ok(v) => KernelIntegrity::new(v, KiConfig::default()),
                Err(e) => {
                    let _ = tx.send(Err(format!("no se cargo el verificador: {e}")));
                    return;
                }
            };
            loop {
                let r = ki.scan().map_err(|e| format!("barrido fallido: {e}"));
                if tx.send(r).is_err() {
                    return;
                }
                match paro.recv_timeout(CADA) {
                    Err(RecvTimeoutError::Timeout) => {}
                    _ => return,
                }
            }
        });
    let informes = match lanzado {
        Ok(_) => informes,
        Err(e) => {
            // Sin hilo no hay barridos: el motivo llega por el mismo canal.
            let (tx, rx) = mpsc::channel();
            let _ = tx.send(Err(format!("no se pudo lanzar el hilo del barrido: {e}")));
            rx
        }
    };
    Hilo {
        informes,
        _parar: parar,
    }
}

/// Los procesos que el kernel esconde.
pub struct MotorNucleo {
    /// Se lanza en el primer mantenimiento: solo lo recibe un motor
    /// registrado, y un motor degradado no carga nada en el kernel.
    hilo: Option<Hilo>,
    maquina: Eid,
    /// El ultimo motivo de «no se pudo mirar» entregado: no se repite en cada
    /// barrido, se dice cuando cambia.
    motivo: Option<String>,
    /// Anomalias ya entregadas, por (tid, clase).
    notificadas: Vec<(u32, &'static str)>,
}

impl MotorNucleo {
    /// Sin cargar: el verificador eBPF se carga en su hilo, en el primer
    /// mantenimiento, y no retrasa el arranque del agente.
    pub fn nuevo(identidad: &Identidad) -> MotorNucleo {
        MotorNucleo {
            hilo: None,
            maquina: identidad.maquina.clone(),
            motivo: None,
            notificadas: Vec::new(),
        }
    }

    fn sin_datos(&mut self, motivo: String) -> Vec<(Eid, Dictamen)> {
        if self.motivo.as_deref() == Some(motivo.as_str()) {
            return Vec::new();
        }
        self.motivo = Some(motivo.clone());
        vec![(
            self.maquina.clone(),
            Dictamen::SinDatos(Causa::Otra(motivo)),
        )]
    }

    fn entregar(&mut self, informe: &ScanReport, ahora_ns: u64) -> Vec<(Eid, Dictamen)> {
        if !informe.espacios_de_pid_comparables {
            return self.sin_datos(
                "los censos no numeran igual: el agente corre en otro espacio de nombres de PID"
                    .into(),
            );
        }
        if informe.desbordes > 0 {
            return self.sin_datos(format!(
                "{} tareas no cupieron en los mapas del kernel",
                informe.desbordes
            ));
        }
        self.motivo = None;
        let nuevas: Vec<Senal> = informe
            .anomalies
            .iter()
            .filter(|a| {
                let clave = (a.tid, a.kind.as_str());
                if self.notificadas.contains(&clave) {
                    false
                } else {
                    self.notificadas.push(clave);
                    true
                }
            })
            .map(|a| senal(&self.maquina, a, ahora_ns))
            .collect();
        if nuevas.is_empty() {
            Vec::new()
        } else {
            vec![(self.maquina.clone(), Dictamen::Senales(nuevas))]
        }
    }
}

fn senal(maquina: &Eid, a: &Anomaly, cuando_ns: u64) -> Senal {
    // Esconder un proceso no tiene lectura benigna; las asimetrias que pueden
    // ser un desmontaje en curso se quedan en sospecha.
    let (juicio, sev, conf) = if a.exige_mitigacion() {
        (Juicio::Malicioso, Severidad::Critica, 90)
    } else {
        (Juicio::Sospechoso, Severidad::Media, 40)
    };
    Senal::nueva(
        Firma::Nucleo,
        maquina.clone(),
        juicio,
        sev,
        Confianza::nueva(conf),
        format!(
            "{} tid {}{}{} ({} confirmaciones): {}",
            a.kind.as_str(),
            a.tid,
            a.tgid.map(|g| format!(" tgid {g}")).unwrap_or_default(),
            a.comm
                .as_deref()
                .map(|c| format!(" «{c}»"))
                .unwrap_or_default(),
            a.confirmaciones,
            a.detalle
        ),
        cuando_ns,
    )
}

impl Motor<EventoAgente> for MotorNucleo {
    fn ficha(&self) -> Ficha {
        Ficha {
            nombre: "nucleo",
            firma: Firma::Nucleo,
            camino: Camino::Frio,
            // No mira eventos: todo su trabajo es el barrido.
            presupuesto: Presupuesto::caliente(1, 256 * 1024),
            requisitos: &[Requisito::KfuncsTareas],
        }
    }

    fn evaluar(&mut self, _ev: &EventoAgente, _plazo: &Plazo) -> Dictamen {
        Dictamen::NoAplica
    }

    fn mantener(&mut self, ahora_ns: u64) -> Vec<(Eid, Dictamen)> {
        let hilo = self.hilo.get_or_insert_with(arrancar);
        let barridos: Vec<Barrido> = hilo.informes.try_iter().collect();
        let mut salida = Vec::new();
        for b in barridos {
            salida.extend(match b {
                Ok(informe) => self.entregar(&informe, ahora_ns),
                Err(motivo) => self.sin_datos(motivo),
            });
        }
        salida
    }

    fn memoria(&self) -> usize {
        self.notificadas.len() * 24
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_kintegrity::AnomalyKind;

    fn anomalia(kind: AnomalyKind) -> Anomaly {
        Anomaly {
            tid: 4321,
            tgid: Some(4321),
            comm: Some("kworker-falso".into()),
            kind,
            severity: kind.severity(),
            confirmaciones: 3,
            detalle: "en el espacio de PID y no en la lista de tareas".into(),
        }
    }

    fn informe(anomalies: Vec<Anomaly>) -> ScanReport {
        ScanReport {
            anomalies,
            espacios_de_pid_comparables: true,
            ..ScanReport::default()
        }
    }

    #[test]
    fn un_proceso_escondido_se_señala_a_la_maquina_una_sola_vez() {
        let mut m = MotorNucleo::nuevo(&Identidad::fija("m"));
        let inf = informe(vec![anomalia(AnomalyKind::DkomUnlinked)]);
        let d = m.entregar(&inf, 7);
        assert_eq!(d.len(), 1);
        let (e, Dictamen::Senales(s)) = &d[0] else {
            panic!("{d:?}")
        };
        assert_eq!(e, &m.maquina);
        assert_eq!(s[0].juicio, Juicio::Malicioso);
        assert!(s[0].porque.contains("dkom-desenlazado") && s[0].porque.contains("4321"));
        assert!(
            m.entregar(&inf, 8).is_empty(),
            "la misma anomalia no se repite"
        );
    }

    #[test]
    fn lo_que_no_se_pudo_mirar_no_es_limpio_y_se_dice_una_vez() {
        let mut m = MotorNucleo::nuevo(&Identidad::fija("m"));
        let mut inf = informe(Vec::new());
        inf.espacios_de_pid_comparables = false;
        let d = m.entregar(&inf, 1);
        assert!(
            matches!(d.as_slice(), [(_, Dictamen::SinDatos(_))]),
            "{d:?}"
        );
        assert!(m.entregar(&inf, 2).is_empty());
        inf.espacios_de_pid_comparables = true;
        assert!(m.entregar(&inf, 3).is_empty());
        inf.espacios_de_pid_comparables = false;
        assert_eq!(
            m.entregar(&inf, 4).len(),
            1,
            "el motivo vuelve tras un barrido valido"
        );
    }

    #[test]
    fn una_asimetria_que_puede_ser_un_desmontaje_se_queda_en_sospecha() {
        let mut m = MotorNucleo::nuevo(&Identidad::fija("m"));
        let d = m.entregar(&informe(vec![anomalia(AnomalyKind::PidSpaceDetached)]), 1);
        let (_, Dictamen::Senales(s)) = &d[0] else {
            panic!("{d:?}")
        };
        assert_eq!(s[0].juicio, Juicio::Sospechoso);
    }
}
