//! Integridad por significado: una puerta trasera en un fichero de configuracion
//! (FASE 2 del MP-16, ola A).
//!
//! `aegis-integridad` sabe decir QUE significa un cambio —«PermitRootLogin paso
//! de no a si», «se concedio NOPASSWD», «se anadio una clave autorizada»— frente
//! a una linea base conocida-buena. Este motor le da los ojos: la telemetria de
//! ficheros del kernel dice cuando alguien abre para escribir uno de los ficheros
//! vigilados, y un momento despues (camino FRIO) se relee, se compara y, si
//! cambio el significado, se entrega la señal con su autor.
//!
//! # Por que se relee despues y no en el evento
//!
//! El evento es la APERTURA para escribir: el contenido nuevo todavia no esta. El
//! gancho LSM que capturaria el contenido en el momento es trabajo de la fase de
//! prevencion; hasta entonces se relee un instante despues, y la ventana se dice.
//!
//! # Nace en solo-auditoria
//!
//! Solo señala. La restauracion desde la linea base (`proponer_restauracion`)
//! existe en el crate y NO se ejecuta: pasar a imponer exige los numeros de la
//! FASE 4.

use std::collections::{BTreeMap, VecDeque};

use aegis_entidad::{Eid, Motor as Firma};
use aegis_integridad::{senal_de_cambio, Autor, CambioConAutor, Credenciales, Formato, LineaBase};
use aegis_motor::{Camino, Causa, Dictamen, Ficha, Motor, Plazo, Presupuesto, Requisito};

use crate::motores::{EventoAgente, Identidad};
use crate::triage::TelemetryEvent;

/// Tamaño maximo que se relee de un fichero vigilado: un `sshd_config` de un
/// megabyte ya es en si mismo una anomalia, y el techo protege al agente.
const MAX_LECTURA: u64 = 1024 * 1024;
/// Cuanto se espera tras la apertura antes de releer.
const RETRASO_NS: u64 = 1_000_000_000;
/// Aperturas pendientes de releer, como mucho.
const MAX_PENDIENTES: usize = 256;

/// Los ficheros que se vigilan, y como se leen.
fn vigilados() -> Vec<(String, Formato)> {
    let mut v = vec![
        ("/etc/ssh/sshd_config".to_string(), Formato::SshdConfig),
        ("/etc/sudoers".to_string(), Formato::Sudoers),
        (
            "/root/.ssh/authorized_keys".to_string(),
            Formato::AuthorizedKeys,
        ),
    ];
    for (dir, formato, sufijo) in [
        ("/etc/sudoers.d", Formato::Sudoers, ""),
        ("/home", Formato::AuthorizedKeys, ".ssh/authorized_keys"),
    ] {
        if let Ok(entradas) = std::fs::read_dir(dir) {
            for e in entradas.flatten() {
                let ruta = if sufijo.is_empty() {
                    e.path()
                } else {
                    e.path().join(sufijo)
                };
                v.push((ruta.to_string_lossy().into_owned(), formato));
            }
        }
    }
    v
}

fn leer(ruta: &str) -> Option<Vec<u8>> {
    let m = std::fs::metadata(ruta).ok()?;
    if m.len() > MAX_LECTURA {
        return None;
    }
    std::fs::read(ruta).ok()
}

/// Uid real y efectivo de un proceso, si sigue vivo.
fn credenciales(pid: u32) -> Option<Credenciales> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let campo = |nombre: &str| -> Option<Vec<u32>> {
        let l = s.lines().find(|l| l.starts_with(nombre))?;
        Some(
            l.split_whitespace()
                .skip(1)
                .filter_map(|x| x.parse().ok())
                .collect(),
        )
    };
    let uid = campo("Uid:")?;
    let gid = campo("Gid:")?;
    Some(Credenciales {
        uid: *uid.first()?,
        gid: *gid.first()?,
        euid: *uid.get(1)?,
    })
}

struct Pendiente {
    ruta: String,
    actor: Eid,
    pid: u32,
    cuando_ns: u64,
}

/// La integridad de los ficheros de configuracion sensibles.
pub struct MotorIntegridad {
    base: LineaBase,
    formatos: BTreeMap<String, Formato>,
    pendientes: VecDeque<Pendiente>,
    /// Resumen del ultimo contenido ya notificado por ruta: el mismo cambio no
    /// se vuelve a entregar en cada escritura.
    notificado: BTreeMap<String, blake3::Hash>,
    identidad: Identidad,
}

impl MotorIntegridad {
    /// Toma la linea base con el contenido ACTUAL de los ficheros vigilados.
    ///
    /// Al instalar, lo actual es lo conocido-bueno; la linea base sellada y
    /// firmada por el plano de control (`LineaBaseSellada`) la sustituye cuando
    /// el agente se enrola.
    pub fn nuevo(identidad: Identidad) -> MotorIntegridad {
        MotorIntegridad::sobre(identidad, vigilados())
    }

    /// Sobre una lista concreta de ficheros; los que no se puedan leer ahora no
    /// se vigilan (no hay linea base con la que compararlos).
    fn sobre(identidad: Identidad, lista: Vec<(String, Formato)>) -> MotorIntegridad {
        let mut base = LineaBase::nueva();
        let mut formatos = BTreeMap::new();
        for (ruta, formato) in lista {
            if let Some(b) = leer(&ruta) {
                base = base.con_config(&ruta, formato, &String::from_utf8_lossy(&b));
                formatos.insert(ruta, formato);
            }
        }
        MotorIntegridad {
            base,
            formatos,
            pendientes: VecDeque::new(),
            notificado: BTreeMap::new(),
            identidad,
        }
    }

    fn vigilada(&self, ruta: &str) -> bool {
        self.formatos.contains_key(ruta)
    }

    /// Los ficheros que vigila de verdad: los que existian y se pudieron leer
    /// al tomar la linea base. Se publica al arrancar, para que «no vio el
    /// cambio» se pueda separar de «no lo estaba mirando».
    pub fn vigilados(&self) -> Vec<&str> {
        self.formatos.keys().map(String::as_str).collect()
    }
}

impl Motor<EventoAgente> for MotorIntegridad {
    fn ficha(&self) -> Ficha {
        Ficha {
            nombre: "integridad",
            firma: Firma::Conductual,
            camino: Camino::Frio,
            // En el bucle solo se anota una ruta: microsegundos.
            presupuesto: Presupuesto::caliente(100, MAX_PENDIENTES * 256 + 64 * 1024),
            requisitos: &[Requisito::TelemetriaKernel],
        }
    }

    fn evaluar(&mut self, ev: &EventoAgente, _plazo: &Plazo) -> Dictamen {
        let (ruta, pid) = match &ev.evento {
            TelemetryEvent::FileWrite { path, pid, .. } => (path, *pid),
            TelemetryEvent::FileRename { to, pid, .. } => (to, *pid),
            _ => return Dictamen::NoAplica,
        };
        if self.vigilada(ruta) && self.pendientes.len() < MAX_PENDIENTES {
            self.pendientes.push_back(Pendiente {
                ruta: ruta.to_string(),
                actor: ev.entidad.clone(),
                pid,
                cuando_ns: ev.evento.ts_ns(),
            });
        }
        Dictamen::NoAplica
    }

    fn mantener(&mut self, ahora_ns: u64) -> Vec<(Eid, Dictamen)> {
        let mut salida = Vec::new();
        while let Some(p) = self.pendientes.front() {
            if ahora_ns.saturating_sub(p.cuando_ns) < RETRASO_NS {
                break;
            }
            let Some(p) = self.pendientes.pop_front() else {
                break;
            };
            let Some(contenido) = leer(&p.ruta) else {
                // Borrado, sustituido por algo enorme o ilegible: no se pudo
                // mirar, y eso se dice sobre el fichero en vez de callarlo.
                let objetivo = aegis_entidad::entidad::ubicacion(&self.identidad.maquina, &p.ruta);
                salida.push((
                    objetivo,
                    Dictamen::SinDatos(Causa::Otra(format!(
                        "integridad: no se pudo releer {} tras la escritura",
                        p.ruta
                    ))),
                ));
                continue;
            };
            let resumen = blake3::hash(&contenido);
            if self.notificado.get(&p.ruta) == Some(&resumen) {
                continue;
            }
            let cambios = self.base.cambios(&p.ruta, &contenido);
            if cambios.is_empty() {
                continue;
            }
            self.notificado.insert(p.ruta.clone(), resumen);
            let objetivo = aegis_entidad::entidad::ubicacion(&self.identidad.maquina, &p.ruta);
            let autor = match credenciales(p.pid) {
                Some(c) => Autor::nuevo(p.actor.clone(), c, Vec::new()),
                None => Autor::sin_credenciales(p.actor.clone(), Vec::new()),
            };
            let cambio =
                CambioConAutor::nuevo(objetivo.clone(), Some(p.ruta.clone()), autor, p.cuando_ns);
            let senales = cambios
                .iter()
                .map(|c| senal_de_cambio(&cambio, c))
                .collect();
            salida.push((objetivo, Dictamen::Senales(senales)));
        }
        salida
    }

    fn memoria(&self) -> usize {
        self.pendientes.len() * 256 + self.notificado.len() * 96
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::graph::ProcKey;
    use std::sync::Arc;

    const S: u64 = 1_000_000_000;

    fn escritura(ruta: &str, ts: u64) -> EventoAgente {
        EventoAgente::nuevo(
            TelemetryEvent::FileWrite {
                actor: ProcKey(99),
                pid: std::process::id(),
                path: Arc::from(ruta),
                flags: 0o2001,
                ts_ns: ts,
            },
            &Identidad::fija("m"),
        )
    }

    fn plazo() -> Plazo {
        Plazo::desde_ahora(std::time::Duration::from_secs(1))
    }

    /// El camino entero con un fichero de verdad: la apertura se anota, el
    /// contenido se relee DESPUES del retraso y el cambio se entrega una vez,
    /// diciendo que cambio.
    #[test]
    fn una_puerta_trasera_en_sshd_config_se_entrega_con_su_significado() {
        let dir = std::env::temp_dir().join(format!("aegis-integridad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("sshd_config");
        std::fs::write(&cfg, "#PermitRootLogin prohibit-password\nUsePAM yes\n").unwrap();
        let ruta = cfg.to_string_lossy().into_owned();
        let mut m = MotorIntegridad::sobre(
            Identidad::fija("m"),
            vec![(ruta.clone(), Formato::SshdConfig)],
        );
        assert!(m.vigilada(&ruta));

        let mut f = std::fs::OpenOptions::new().append(true).open(&cfg).unwrap();
        std::io::Write::write_all(&mut f, b"\nPermitRootLogin yes\n").unwrap();
        drop(f);
        let _ = m.evaluar(&escritura(&ruta, 10 * S), &plazo());

        assert!(
            m.mantener(10 * S + RETRASO_NS - 1).is_empty(),
            "antes del retraso no se relee"
        );
        let d = m.mantener(10 * S + RETRASO_NS);
        assert_eq!(d.len(), 1, "{d:?}");
        let Dictamen::Senales(s) = &d[0].1 else {
            panic!("{d:?}")
        };
        assert!(
            s.iter().any(|x| x.porque.contains("PermitRootLogin")),
            "{s:?}"
        );

        let _ = m.evaluar(&escritura(&ruta, 20 * S), &plazo());
        assert!(
            m.mantener(30 * S).is_empty(),
            "el mismo cambio no se entrega dos veces"
        );

        // Si el fichero desaparece tras una escritura, no se pudo mirar: se
        // dice sobre el fichero en vez de callarlo.
        std::fs::remove_file(&cfg).unwrap();
        let _ = m.evaluar(&escritura(&ruta, 40 * S), &plazo());
        let d = m.mantener(50 * S);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            matches!(d.as_slice(), [(_, Dictamen::SinDatos(Causa::Otra(m)))] if m.contains("no se pudo releer")),
            "{d:?}"
        );
    }

    #[test]
    fn una_ruta_no_vigilada_no_se_anota() {
        let mut m = MotorIntegridad::sobre(Identidad::fija("m"), Vec::new());
        let _ = m.evaluar(&escritura("/tmp/cualquiera", S), &plazo());
        assert!(m.pendientes.is_empty());
    }
}
