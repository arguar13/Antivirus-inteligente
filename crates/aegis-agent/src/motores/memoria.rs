//! Forense de memoria en vivo: codigo sin fichero, carga reflexiva y *module
//! stomping* (FASE 2 del MP-16, ola A).
//!
//! `aegis-memhunter` sabe leer el mapa de un proceso (`smaps`), su tabla de
//! paginas (`pagemap`) y los primeros bytes de una region sin parar al proceso,
//! y decir que hay alli que no deberia. Este motor decide A QUIEN mirar y CUANDO:
//!
//! - **Tras un `exec`**, un instante despues: el cargador ya termino y lo que
//!   haya ejecutable y anonimo lo puso el propio programa.
//! - **Tras un `ptrace` que escribe memoria** sobre otro proceso: se mira el
//!   OBJETIVO, que es donde queda la inyeccion.
//! - **En ronda**, de pocos en pocos, sobre los procesos que el agente ya ha
//!   visto: la carga reflexiva no necesita ningun evento del kernel que la
//!   anuncie, y un proceso largo se infecta cuando quiere.
//!
//! # Por que solo procesos ya vistos
//!
//! La entidad de un proceso sale de la clave que calculan las sondas a partir
//! de `(tgid, arranque en ns)`, y el espacio de usuario solo tiene el arranque
//! en ticks: no se puede reconstruir. Un proceso anterior al agente entra en la
//! ronda en cuanto produce cualquier evento con su pid. Lo que nunca produce
//! ninguno queda fuera, y se dice en la matriz de capacidades.
//!
//! # Coste
//!
//! Todo va en el camino FRIO (`mantener`), con un tope de procesos por pasada:
//! el camino caliente solo anota un pid.
//!
//! # Nace en solo-auditoria
//!
//! Solo señala. Ni suspende ni vuelca el proceso.

use std::collections::{BTreeMap, VecDeque};

use aegis_entidad::{Confianza, Eid, Juicio, Motor as Firma, Senal, Severidad};
use aegis_memhunter::{hunter::cazar, AegisMemHunter, Anomalia, MemHunterError};
use aegis_motor::{Camino, Causa, Dictamen, Ficha, Motor, Plazo, Presupuesto, Requisito};

use crate::motores::EventoAgente;
use crate::triage::TelemetryEvent;

/// Cuanto se espera tras el evento antes de mirar.
const RETRASO_NS: u64 = 2_000_000_000;
/// Procesos que se analizan, como mucho, en cada pasada de mantenimiento.
const POR_PASADA: usize = 4;
/// Cada cuanto se revisita un proceso vivo en la ronda.
const RONDA_NS: u64 = 60_000_000_000;
/// Procesos que se recuerdan: el techo de la memoria del motor.
const MAX_VIVOS: usize = 8192;
/// Analisis pendientes, como mucho.
const MAX_PENDIENTES: usize = 1024;

struct Vivo {
    entidad: Eid,
    /// Ultima vez que se analizo; 0 = nunca.
    visto_ns: u64,
    /// Anomalias ya notificadas, por clave estable: la misma region no se vuelve
    /// a entregar en cada ronda.
    notificadas: Vec<(u64, &'static str)>,
}

struct Pendiente {
    pid: u32,
    desde_ns: u64,
}

/// Forense de memoria de los procesos vistos.
pub struct MotorMemoria {
    cazador: AegisMemHunter,
    vivos: BTreeMap<u32, Vivo>,
    pendientes: VecDeque<Pendiente>,
    /// Pid por el que va la ronda.
    cursor: u32,
    propio: u32,
}

impl MotorMemoria {
    /// Con la politica por defecto del cazador.
    pub fn nuevo() -> MotorMemoria {
        MotorMemoria {
            cazador: AegisMemHunter::nuevo(),
            vivos: BTreeMap::new(),
            pendientes: VecDeque::new(),
            cursor: 0,
            propio: std::process::id(),
        }
    }

    fn conocer(&mut self, pid: u32, entidad: &Eid) {
        if pid == 0 || pid == self.propio {
            return;
        }
        if self.vivos.len() >= MAX_VIVOS && !self.vivos.contains_key(&pid) {
            return;
        }
        let v = self.vivos.entry(pid).or_insert_with(|| Vivo {
            entidad: entidad.clone(),
            visto_ns: 0,
            notificadas: Vec::new(),
        });
        // Un pid reutilizado es otro proceso: su entidad manda.
        if &v.entidad != entidad {
            v.entidad = entidad.clone();
            v.visto_ns = 0;
            v.notificadas.clear();
        }
    }

    fn pedir(&mut self, pid: u32, desde_ns: u64) {
        if self.pendientes.len() < MAX_PENDIENTES && !self.pendientes.iter().any(|p| p.pid == pid) {
            self.pendientes.push_back(Pendiente { pid, desde_ns });
        }
    }

    /// Los pids a analizar en esta pasada: primero los pedidos por un evento que
    /// ya maduraron, luego la ronda.
    fn turno(&mut self, ahora_ns: u64) -> Vec<u32> {
        let mut turno = Vec::new();
        while turno.len() < POR_PASADA {
            match self.pendientes.front() {
                Some(p) if ahora_ns.saturating_sub(p.desde_ns) >= RETRASO_NS => {
                    let p = self.pendientes.pop_front().map(|p| p.pid);
                    turno.extend(p);
                }
                _ => break,
            }
        }
        let desde = self.cursor;
        let ronda = self
            .vivos
            .range(desde.saturating_add(1)..)
            .chain(self.vivos.range(..=desde))
            .filter(|(_, v)| v.visto_ns == 0 || ahora_ns.saturating_sub(v.visto_ns) >= RONDA_NS)
            .map(|(pid, _)| *pid)
            .filter(|pid| !turno.contains(pid))
            .take(POR_PASADA.saturating_sub(turno.len()))
            .collect::<Vec<_>>();
        if let Some(ultimo) = ronda.last() {
            self.cursor = *ultimo;
        }
        turno.extend(ronda);
        turno
    }
}

impl Default for MotorMemoria {
    fn default() -> Self {
        MotorMemoria::nuevo()
    }
}

fn severidad(s: aegis_memhunter::Severidad) -> Severidad {
    use aegis_memhunter::Severidad as M;
    match s {
        M::Informativa => Severidad::Info,
        M::Baja => Severidad::Baja,
        M::Media => Severidad::Media,
        M::Alta => Severidad::Alta,
        M::Critica => Severidad::Critica,
    }
}

fn senal(entidad: &Eid, a: &Anomalia, cuando_ns: u64) -> Senal {
    let sev = severidad(a.severidad);
    // Las clases objetivas (cabecera de imagen en memoria anonima, codigo de
    // modulo sustituido) son hechos, no parecidos: con ellas se afirma.
    let juicio = if sev >= Severidad::Critica {
        Juicio::Malicioso
    } else {
        Juicio::Sospechoso
    };
    let confianza = match sev {
        Severidad::Critica => 90,
        Severidad::Alta => 70,
        Severidad::Media => 45,
        Severidad::Baja => 25,
        Severidad::Info => 10,
    };
    Senal::nueva(
        Firma::MemHunter,
        entidad.clone(),
        juicio,
        sev,
        Confianza::nueva(confianza),
        format!(
            "{} [{}] en {:#x}-{:#x}{}: {}",
            a.clase.clave(),
            a.clase.tecnica_mitre(),
            a.inicio,
            a.fin,
            a.ruta
                .as_deref()
                .map(|r| format!(" ({r})"))
                .unwrap_or_default(),
            a.evidencia
        ),
        cuando_ns,
    )
}

impl Motor<EventoAgente> for MotorMemoria {
    fn ficha(&self) -> Ficha {
        Ficha {
            nombre: "memoria",
            firma: Firma::MemHunter,
            camino: Camino::Frio,
            // En el bucle solo se anota un pid.
            presupuesto: Presupuesto::caliente(50, MAX_VIVOS * 128 + MAX_PENDIENTES * 16),
            requisitos: &[Requisito::TelemetriaKernel, Requisito::MemoriaAjena],
        }
    }

    fn evaluar(&mut self, ev: &EventoAgente, _plazo: &Plazo) -> Dictamen {
        match &ev.evento {
            TelemetryEvent::Exec { pid, ts_ns, .. } => {
                self.conocer(*pid, &ev.entidad);
                if self.vivos.contains_key(pid) {
                    self.pedir(*pid, *ts_ns);
                }
            }
            TelemetryEvent::Ptrace {
                target_pid,
                writes_memory: true,
                ts_ns,
                ..
            } => {
                // El objetivo se analiza aunque no se le conozca entidad: la
                // señal va entonces al que escribio, que es quien la merece.
                if !self.vivos.contains_key(target_pid) {
                    self.conocer(*target_pid, &ev.entidad);
                }
                self.pedir(*target_pid, *ts_ns);
            }
            TelemetryEvent::Exit { .. } => {
                // El pid no viaja en la salida; la ronda lo olvida al no
                // encontrarlo (ProcesoMuerto).
            }
            TelemetryEvent::FileWrite { pid, .. }
            | TelemetryEvent::FileWriteSample { pid, .. }
            | TelemetryEvent::FdBind { pid, .. }
            | TelemetryEvent::FileRename { pid, .. }
            | TelemetryEvent::NetConnect { pid, .. } => self.conocer(*pid, &ev.entidad),
            TelemetryEvent::Ptrace { .. } => {}
        }
        Dictamen::NoAplica
    }

    fn mantener(&mut self, ahora_ns: u64) -> Vec<(Eid, Dictamen)> {
        let mut salida = Vec::new();
        for pid in self.turno(ahora_ns) {
            let Ok(p) = i32::try_from(pid) else { continue };
            let informe = match cazar(p, &self.cazador) {
                Ok(i) => i,
                Err(MemHunterError::ProcesoMuerto { .. }) => {
                    self.vivos.remove(&pid);
                    continue;
                }
                Err(MemHunterError::Lectura { causa, .. })
                    if causa.kind() == std::io::ErrorKind::NotFound =>
                {
                    self.vivos.remove(&pid);
                    continue;
                }
                Err(e) => {
                    if let Some(v) = self.vivos.get(&pid) {
                        salida.push((
                            v.entidad.clone(),
                            Dictamen::SinDatos(Causa::Otra(e.to_string())),
                        ));
                    }
                    continue;
                }
            };
            let Some(v) = self.vivos.get_mut(&pid) else {
                continue;
            };
            v.visto_ns = ahora_ns;
            let nuevas: Vec<Senal> = informe
                .anomalias
                .iter()
                .filter(|a| a.severidad >= aegis_memhunter::Severidad::Media)
                .filter(|a| {
                    let clave = (a.inicio, a.clase.clave());
                    if v.notificadas.contains(&clave) {
                        false
                    } else {
                        v.notificadas.push(clave);
                        true
                    }
                })
                .map(|a| senal(&v.entidad, a, ahora_ns))
                .collect();
            if !nuevas.is_empty() {
                salida.push((v.entidad.clone(), Dictamen::Senales(nuevas)));
            }
        }
        salida
    }

    fn memoria(&self) -> usize {
        self.vivos.len() * 128 + self.pendientes.len() * 16
    }

    fn aligerar(&mut self) {
        // Bajo presion se olvida la ronda de los procesos nunca analizados; los
        // pedidos por un evento se conservan.
        self.vivos
            .retain(|_, v| v.visto_ns != 0 || !v.notificadas.is_empty());
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::graph::ProcKey;
    use crate::motores::Identidad;
    use aegis_entidad::entidad::{maquina, proceso_por_clave};
    use std::sync::Arc;

    fn exec(pid: u32, clave: u64, ts: u64) -> EventoAgente {
        EventoAgente::nuevo(
            TelemetryEvent::Exec {
                actor: ProcKey(clave),
                pid,
                parent: ProcKey(0),
                image: Arc::from("/usr/bin/prueba"),
                cmdline: Arc::from("prueba"),
                started_ns: ts,
                ts_ns: ts,
            },
            &Identidad::fija("m"),
        )
    }

    #[test]
    fn un_exec_se_analiza_despues_del_retraso_y_no_antes() {
        let mut m = MotorMemoria::nuevo();
        let _ = m.evaluar(
            &exec(4242, 7, 1_000),
            &Plazo::desde_ahora(std::time::Duration::from_secs(1)),
        );
        // La ronda tambien lo propondria (nunca analizado); lo que se comprueba
        // es que el pedido no madura antes de tiempo.
        assert_eq!(m.pendientes.len(), 1);
        let _ = m.turno(1_000 + RETRASO_NS - 1);
        assert_eq!(
            m.pendientes.len(),
            1,
            "el pedido no puede madurar antes del retraso"
        );
        let t = m.turno(1_000 + RETRASO_NS);
        assert!(t.contains(&4242));
        assert!(m.pendientes.is_empty());
    }

    #[test]
    fn la_ronda_no_pasa_de_su_tope_por_pasada_y_da_la_vuelta() {
        let mut m = MotorMemoria::nuevo();
        for pid in 100..110 {
            m.conocer(pid, &proceso_por_clave(&maquina("m"), 1, u64::from(pid)));
        }
        let a = m.turno(0);
        assert_eq!(a.len(), POR_PASADA);
        for pid in &a {
            m.vivos.get_mut(pid).unwrap().visto_ns = 1;
        }
        let b = m.turno(1);
        assert!(
            b.iter().all(|p| !a.contains(p)),
            "la ronda avanza: {a:?} {b:?}"
        );
    }

    #[test]
    fn el_propio_agente_no_se_analiza() {
        let mut m = MotorMemoria::nuevo();
        let _ = m.evaluar(
            &exec(std::process::id(), 9, 1),
            &Plazo::desde_ahora(std::time::Duration::from_secs(1)),
        );
        assert!(m.vivos.is_empty());
    }

    /// La deteccion en vivo la prueban el crate (en su propio proceso) y la
    /// matriz (`memoria-en-vivo`, contra el agente publicado); aqui, que la
    /// traduccion a señal diga que, donde y con que tecnica, y que solo las
    /// clases objetivas afirmen.
    #[test]
    fn la_señal_lleva_clase_tecnica_y_region_y_solo_lo_objetivo_afirma() {
        let e = proceso_por_clave(&maquina("m"), 1, 7);
        let mut a = Anomalia {
            clase: aegis_memhunter::ClaseAnomalia::ImagenReflexiva,
            severidad: aegis_memhunter::Severidad::Critica,
            inicio: 0x7f00_0000,
            fin: 0x7f02_0000,
            ruta: None,
            bytes_desligados: 0,
            mayor_bloque_desligado: 0,
            evidencia: "cabecera ELF en memoria anonima".into(),
        };
        let s = senal(&e, &a, 5);
        assert_eq!(s.juicio, Juicio::Malicioso);
        assert!(
            s.porque.contains("imagen_reflexiva") && s.porque.contains("0x7f000000"),
            "{}",
            s.porque
        );
        assert!(s.porque.contains(a.clase.tecnica_mitre()));
        a.clase = aegis_memhunter::ClaseAnomalia::EjecutableAnonimo;
        a.severidad = aegis_memhunter::Severidad::Alta;
        assert_eq!(senal(&e, &a, 5).juicio, Juicio::Sospechoso);
    }
}
