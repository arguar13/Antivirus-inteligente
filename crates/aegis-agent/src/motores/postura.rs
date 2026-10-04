//! La postura del kernel, vigilada (FASE 5.2 del MP-16).
//!
//! Lee el endurecimiento REAL del host —lockdown, kptr_restrict,
//! dmesg_restrict, bpf y espacios de usuario sin privilegios, Yama,
//! perf_event_paranoid, kexec, carga de modulos y el modo del MAC— con
//! `aegis_vuln::nucleo`, lo compara con la linea base declarada en
//! `tools/config/postura-kernel.toml` y lo publica: una linea por ajuste en el
//! informe periodico (y en `aegisctl status`), con la recomendacion y su porque.
//!
//! # Lo que señala
//!
//! - **Por debajo de la linea base**, una vez, al leerlo por primera vez:
//!   severidad Baja si el ajuste es de nivel `base`, Info si es `recomendado`.
//!   La entidad es la ubicacion del ajuste (`/proc/sys/kernel/kptr_restrict`), no
//!   la maquina: el arbitro guarda una señal por motor y juicio en cada
//!   expediente, y diez brechas sobre la misma maquina se pisarian entre si.
//! - **Una proteccion que BAJA en caliente** (`sysctl -w`, `setenforce 0`,
//!   descargar perfiles de AppArmor): severidad Media, sobre el ajuste y, si la
//!   telemetria vio quien escribio el fichero, tambien sobre ese proceso. Si el
//!   ajuste estaba en un valor que el kernel no deja bajar sin reiniciar
//!   (`modules_disabled=1`, lockdown, Yama 3), severidad Alta: verlo bajar
//!   significa que alguien escribio en la memoria del kernel.
//! - **Lo que no se pudo leer** es `SinDatos` con el motivo, una vez por ajuste
//!   hasta que se vuelva a poder leer. Nunca pasa por un valor.
//!
//! # Coste
//!
//! Caliente: mirar si una escritura cae en una de unas quince rutas. Frio: diez
//! lecturas pequeñas de procfs/sysfs cada treinta segundos.
//!
//! # Nace en solo-auditoria
//!
//! Solo señala y recomienda. Subir un ajuste lo decide el operador: varios
//! (modules_disabled, kexec_load_disabled) no se deshacen sin reiniciar.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use aegis_entidad::entidad::ubicacion;
use aegis_entidad::{Confianza, Eid, Juicio, Motor as Firma, Senal, Severidad};
use aegis_motor::{Camino, Causa, Dictamen, Ficha, Motor, Plazo, Presupuesto};
use aegis_vuln::nucleo::{bajada, brecha, leer, Ajuste, Bajada, Lectura, LineaBase, Nivel};

use crate::motores::{EventoAgente, Identidad};
use crate::triage::TelemetryEvent;

/// La linea base declarada, embebida al compilar: el agente instalado no lee
/// `tools/`, y una linea base que se pudiera editar en el host sin firmar seria
/// lo primero que un intruso bajaria.
const LINEA_BASE: &str = include_str!("../../../../tools/config/postura-kernel.toml");
/// Cada cuanto se relee la postura.
const CADA_NS: u64 = 30_000_000_000;
/// Margen hacia atras para atribuir una escritura a la bajada que se ve despues.
const MARGEN_NS: u64 = 2_000_000_000;
/// Confianza de lo leido: el valor se lee directamente del kernel.
const CONFIANZA: u8 = 80;

struct Escritura {
    actor: Eid,
    pid: u32,
    ruta: String,
    cuando_ns: u64,
}

/// La postura del kernel.
pub struct MotorPostura {
    raiz: PathBuf,
    base: LineaBase,
    error_base: Option<String>,
    maquina: Eid,
    /// La ultima lectura LEGIBLE de cada ajuste.
    ultima: BTreeMap<Ajuste, Lectura>,
    /// Ajustes que no se pudieron leer, con el motivo (ya notificados).
    ilegibles: BTreeMap<Ajuste, String>,
    leido_ns: Option<u64>,
    /// La ultima escritura vista sobre las rutas de cada ajuste.
    escrituras: BTreeMap<Ajuste, Escritura>,
    bajadas: u64,
    informe: Arc<Mutex<Vec<String>>>,
}

impl MotorPostura {
    /// Sobre el host, con la linea base embebida. Publica en `informe`.
    pub fn nuevo(identidad: Identidad, informe: Arc<Mutex<Vec<String>>>) -> MotorPostura {
        MotorPostura::sobre(identidad, PathBuf::from("/"), LINEA_BASE, informe)
    }

    fn sobre(
        identidad: Identidad,
        raiz: PathBuf,
        linea_base: &str,
        informe: Arc<Mutex<Vec<String>>>,
    ) -> MotorPostura {
        // Una linea base ilegible no apaga el motor: las bajadas en caliente se
        // siguen viendo, y el error se publica en cada informe.
        let (base, error_base) = match LineaBase::analizar(linea_base) {
            Ok(b) => (b, None),
            Err(e) => (LineaBase::default(), Some(e)),
        };
        MotorPostura {
            raiz,
            base,
            error_base,
            maquina: identidad.maquina,
            ultima: BTreeMap::new(),
            ilegibles: BTreeMap::new(),
            leido_ns: None,
            escrituras: BTreeMap::new(),
            bajadas: 0,
            informe,
        }
    }

    fn objetivo(&self, a: Ajuste) -> Eid {
        ubicacion(&self.maquina, a.ruta())
    }

    fn senal(&self, entidad: Eid, sev: Severidad, conf: u8, porque: String, cuando: u64) -> Senal {
        Senal::nueva(
            Firma::FirmwareAudit,
            entidad,
            Juicio::Sospechoso,
            sev,
            Confianza::nueva(conf),
            porque,
            cuando,
        )
    }

    fn por_brecha(&self, a: Ajuste, lectura: &Lectura, ahora_ns: u64) -> Option<Senal> {
        let b = brecha(a, lectura, &self.base)?;
        let sev = match b.exigencia.nivel {
            Nivel::Base => Severidad::Baja,
            Nivel::Recomendado => Severidad::Info,
        };
        Some(self.senal(
            self.objetivo(a),
            sev,
            CONFIANZA,
            format!(
                "postura: {} por debajo de la linea base ({}, rango {} de minimo {}). \
                 Recomendacion: {}. Por que: {}",
                b.actual,
                b.exigencia.nivel.nombre(),
                b.rango,
                b.exigencia.minimo,
                b.recomendacion,
                a.justificacion()
            ),
            ahora_ns,
        ))
    }

    fn por_bajada(
        &self,
        b: &Bajada,
        autor: Option<&Escritura>,
        ahora_ns: u64,
    ) -> Vec<(Eid, Dictamen)> {
        let a = b.ajuste;
        let (sev, conf) = if b.irreversible {
            (Severidad::Alta, 85)
        } else {
            (Severidad::Media, CONFIANZA)
        };
        let mut porque = format!(
            "postura: {} bajo en caliente de «{}» a «{}»",
            a.nombre(),
            b.antes,
            b.ahora
        );
        if let Some(e) = self.base.exigencia(a) {
            if b.hasta < e.minimo {
                porque.push_str(&format!(
                    "; queda por debajo de la linea base ({}, minimo {})",
                    e.nivel.nombre(),
                    e.minimo
                ));
            }
        }
        if b.irreversible {
            porque.push_str(
                "; desde ese valor el kernel no deja bajarlo sin reiniciar: verlo bajar \
                 significa que alguien escribio en la memoria del kernel",
            );
        }
        match autor {
            Some(w) => porque.push_str(&format!(
                "; escribio {} el pid {} ({})",
                w.ruta, w.pid, w.actor
            )),
            None => porque.push_str("; la telemetria no vio quien escribio"),
        }
        let mut salida = vec![(
            self.objetivo(a),
            Dictamen::Senales(vec![self.senal(
                self.objetivo(a),
                sev,
                conf,
                porque.clone(),
                ahora_ns,
            )]),
        )];
        if let Some(w) = autor {
            salida.push((
                w.actor.clone(),
                Dictamen::Senales(vec![self.senal(
                    w.actor.clone(),
                    sev,
                    conf,
                    porque,
                    ahora_ns,
                )]),
            ));
        }
        salida
    }

    fn publicar(&self) {
        let mut lineas = Vec::with_capacity(Ajuste::todos().len() + 1);
        let bajo = Ajuste::todos()
            .iter()
            .filter(|&&a| {
                self.ultima
                    .get(&a)
                    .is_some_and(|l| brecha(a, l, &self.base).is_some())
            })
            .count();
        lineas.push(format!(
            "postura: {} ajuste(s), {} por debajo de la linea base, {} ilegible(s), {} bajada(s) en caliente{}",
            Ajuste::todos().len(),
            bajo,
            self.ilegibles.len(),
            self.bajadas,
            self.error_base
                .as_deref()
                .map(|e| format!(" | LINEA BASE ILEGIBLE: {e}"))
                .unwrap_or_default()
        ));
        for &a in Ajuste::todos() {
            let exigido = self
                .base
                .exigencia(a)
                .map(|e| format!("minimo {} ({})", e.minimo, e.nivel.nombre()))
                .unwrap_or_else(|| "sin exigencia".to_string());
            let linea = if let Some(m) = self.ilegibles.get(&a) {
                format!("postura {}: ILEGIBLE ({m}); {exigido}", a.nombre())
            } else if let Some(l) = self.ultima.get(&a) {
                match brecha(a, l, &self.base) {
                    Some(b) => format!(
                        "postura {}: {} rango {}; {exigido}; BAJO -> {}",
                        a.nombre(),
                        l.texto(),
                        b.rango,
                        b.recomendacion
                    ),
                    None => format!(
                        "postura {}: {} rango {}; {exigido}; OK",
                        a.nombre(),
                        l.texto(),
                        l.rango().unwrap_or(0)
                    ),
                }
            } else {
                format!("postura {}: sin leer todavia; {exigido}", a.nombre())
            };
            lineas.push(linea);
        }
        if let Ok(mut g) = self.informe.lock() {
            *g = lineas;
        }
    }
}

impl Motor<EventoAgente> for MotorPostura {
    fn ficha(&self) -> Ficha {
        Ficha {
            nombre: "postura",
            // Plano de plataforma: lo que dice del kernel no corrobora a los
            // motores que miran procesos, y comparte plano con `nucleo` sin
            // compartir firma (el expediente guarda una señal por firma y juicio).
            firma: Firma::FirmwareAudit,
            camino: Camino::Frio,
            presupuesto: Presupuesto::caliente(20, 64 * 1024),
            // Leer la postura no necesita la telemetria; atribuir una bajada si,
            // y sin ella solo se pierde el autor.
            requisitos: &[],
        }
    }

    fn evaluar(&mut self, ev: &EventoAgente, _plazo: &Plazo) -> Dictamen {
        let TelemetryEvent::FileWrite {
            path, pid, ts_ns, ..
        } = &ev.evento
        else {
            return Dictamen::NoAplica;
        };
        if !path.starts_with("/proc/sys/") && !path.starts_with("/sys/") {
            return Dictamen::NoAplica;
        }
        let ruta: &str = path;
        if let Some(a) = Ajuste::todos()
            .iter()
            .copied()
            .find(|a| a.rutas_de_escritura().contains(&ruta))
        {
            self.escrituras.insert(
                a,
                Escritura {
                    actor: ev.entidad.clone(),
                    pid: *pid,
                    ruta: ruta.to_string(),
                    cuando_ns: *ts_ns,
                },
            );
        }
        Dictamen::NoAplica
    }

    fn mantener(&mut self, ahora_ns: u64) -> Vec<(Eid, Dictamen)> {
        if self
            .leido_ns
            .is_some_and(|t| ahora_ns.saturating_sub(t) < CADA_NS)
        {
            return Vec::new();
        }
        let desde = self.leido_ns.map_or(0, |t| t.saturating_sub(MARGEN_NS));
        self.leido_ns = Some(ahora_ns);
        let mut salida = Vec::new();
        for &a in Ajuste::todos() {
            let lectura = leer(&self.raiz, a);
            if let Lectura::Ilegible(m) = &lectura {
                // Se dice una vez por ajuste, hasta que se vuelva a poder leer; el
                // motivo que se publica es siempre el de la ultima lectura.
                if self.ilegibles.insert(a, m.clone()).is_none() {
                    salida.push((
                        self.objetivo(a),
                        Dictamen::SinDatos(Causa::Otra(format!(
                            "postura: no se pudo leer {}: {m}",
                            a.nombre()
                        ))),
                    ));
                }
                continue;
            }
            self.ilegibles.remove(&a);
            match self.ultima.get(&a).cloned() {
                None => {
                    if let Some(s) = self.por_brecha(a, &lectura, ahora_ns) {
                        salida.push((s.entidad.clone(), Dictamen::Senales(vec![s])));
                    }
                }
                Some(antes) => {
                    if let Some(b) = bajada(a, &antes, &lectura) {
                        self.bajadas += 1;
                        let autor = self.escrituras.get(&a).filter(|w| w.cuando_ns >= desde);
                        salida.extend(self.por_bajada(&b, autor, ahora_ns));
                    }
                }
            }
            self.ultima.insert(a, lectura);
        }
        self.escrituras.clear();
        self.publicar();
        salida
    }

    fn memoria(&self) -> usize {
        (self.ultima.len() + self.ilegibles.len()) * 192 + self.escrituras.len() * 160
    }

    fn aligerar(&mut self) {
        // Lo unico prescindible: perder el autor no deja de ver la bajada.
        self.escrituras.clear();
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::graph::ProcKey;
    use std::path::Path;

    const S: u64 = 1_000_000_000;

    fn raiz(nombre: &str) -> PathBuf {
        let r = std::env::temp_dir().join(format!("aegis-postura-{}-{nombre}", std::process::id()));
        let _ = std::fs::remove_dir_all(&r);
        std::fs::create_dir_all(&r).unwrap();
        r
    }

    fn poner(raiz: &Path, ruta: &str, contenido: &str) {
        let p = raiz.join(ruta.trim_start_matches('/'));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, contenido).unwrap();
    }

    /// Un host tipico sin endurecer: kptr_restrict a 0, SELinux en permisivo,
    /// sin lockdown y con espacios de usuario abiertos.
    fn host_debil(r: &Path) {
        poner(
            r,
            "/sys/kernel/security/lockdown",
            "[none] integrity confidentiality\n",
        );
        poner(r, "/proc/sys/kernel/kptr_restrict", "0\n");
        poner(r, "/proc/sys/kernel/dmesg_restrict", "1\n");
        poner(r, "/proc/sys/kernel/unprivileged_bpf_disabled", "2\n");
        poner(r, "/proc/sys/user/max_user_namespaces", "63000\n");
        poner(r, "/proc/sys/kernel/unprivileged_userns_clone", "1\n");
        poner(r, "/proc/sys/kernel/yama/ptrace_scope", "1\n");
        poner(r, "/proc/sys/kernel/perf_event_paranoid", "2\n");
        poner(r, "/proc/sys/kernel/kexec_load_disabled", "0\n");
        poner(r, "/proc/sys/kernel/modules_disabled", "0\n");
        poner(r, "/sys/fs/selinux/enforce", "0\n");
        // Lo que los kernels de distribucion ya traen bien de serie.
        poner(r, "/proc/sys/kernel/randomize_va_space", "2\n");
        poner(r, "/proc/sys/vm/mmap_min_addr", "65536\n");
        poner(r, "/proc/sys/fs/suid_dumpable", "0\n");
        poner(r, "/proc/sys/fs/protected_symlinks", "1\n");
        poner(r, "/proc/sys/fs/protected_hardlinks", "1\n");
        poner(r, "/proc/sys/kernel/io_uring_disabled", "1\n");
    }

    fn motor(r: &Path) -> (MotorPostura, Arc<Mutex<Vec<String>>>) {
        let informe: Arc<Mutex<Vec<String>>> = Arc::default();
        let m = MotorPostura::sobre(
            Identidad::fija("m"),
            r.to_path_buf(),
            LINEA_BASE,
            Arc::clone(&informe),
        );
        (m, informe)
    }

    fn senales(d: &[(Eid, Dictamen)]) -> Vec<Senal> {
        d.iter()
            .flat_map(|(_, x)| match x {
                Dictamen::Senales(s) => s.clone(),
                _ => Vec::new(),
            })
            .collect()
    }

    fn escritura(ruta: &str, pid: u32, ts: u64) -> EventoAgente {
        EventoAgente::nuevo(
            TelemetryEvent::FileWrite {
                actor: ProcKey(u64::from(pid)),
                pid,
                path: Arc::from(ruta),
                flags: 0o1001,
                ts_ns: ts,
            },
            &Identidad::fija("m"),
        )
    }

    fn plazo() -> Plazo {
        Plazo::desde_ahora(std::time::Duration::from_secs(1))
    }

    #[test]
    fn la_linea_base_embebida_se_entiende_y_cubre_todo() {
        let b = LineaBase::analizar(LINEA_BASE).unwrap();
        assert!(b.faltan().is_empty(), "{:?}", b.faltan());
    }

    #[test]
    fn la_primera_lectura_señala_cada_brecha_con_su_recomendacion_y_publica_todo() {
        let r = raiz("brechas");
        host_debil(&r);
        let (mut m, informe) = motor(&r);
        let d = m.mantener(S);
        let s = senales(&d);
        // lockdown, userns, kexec y modulos (recomendado: Info); kptr y mac
        // (base: Baja). dmesg, bpf, yama, perf, aslr, mmap_min_addr,
        // suid_dumpable, los enlaces e io_uring estan en la linea base.
        assert_eq!(s.len(), 6, "{s:#?}");
        let id = Identidad::fija("m");
        let kptr = s
            .iter()
            .find(|x| x.entidad == ubicacion(&id.maquina, "/proc/sys/kernel/kptr_restrict"))
            .expect("kptr_restrict");
        assert_eq!(kptr.severidad, Severidad::Baja);
        assert_eq!(kptr.juicio, Juicio::Sospechoso);
        assert!(
            kptr.porque.contains("sysctl -w kernel.kptr_restrict=1"),
            "{}",
            kptr.porque
        );
        assert!(kptr.porque.contains("KASLR"), "{}", kptr.porque);
        let lockdown = s
            .iter()
            .find(|x| x.porque.contains("lockdown=none"))
            .expect("lockdown");
        assert_eq!(lockdown.severidad, Severidad::Info);
        assert!(lockdown.porque.contains("NO confidentiality"));
        assert!(s.iter().all(|x| !x.porque.contains("ptrace_scope")));

        let g = informe.lock().unwrap().clone();
        assert_eq!(g.len(), Ajuste::todos().len() + 1, "{g:#?}");
        assert!(g[0].contains("6 por debajo"), "{}", g[0]);
        assert!(g
            .iter()
            .any(|l| l.starts_with("postura kernel.yama.ptrace_scope") && l.ends_with("OK")));
        assert!(g
            .iter()
            .any(|l| l.starts_with("postura mac") && l.contains("BAJO")));

        // La misma brecha no se repite en cada lectura.
        assert!(m.mantener(S + CADA_NS).is_empty());
        let _ = std::fs::remove_dir_all(&r);
    }

    #[test]
    fn bajar_una_proteccion_en_caliente_es_media_y_se_atribuye_a_quien_escribio() {
        let r = raiz("bajada");
        host_debil(&r);
        let (mut m, _) = motor(&r);
        let _ = m.mantener(10 * S);
        assert!(
            m.mantener(10 * S + CADA_NS - 1).is_empty(),
            "antes de su turno no relee"
        );

        poner(&r, "/proc/sys/kernel/yama/ptrace_scope", "0\n");
        let ev = escritura("/proc/sys/kernel/yama/ptrace_scope", 4242, 20 * S);
        let actor = ev.entidad.clone();
        assert_eq!(m.evaluar(&ev, &plazo()), Dictamen::NoAplica);

        let d = m.mantener(10 * S + CADA_NS);
        assert_eq!(d.len(), 2, "sobre el ajuste y sobre quien lo bajo: {d:#?}");
        assert!(d.iter().any(|(e, _)| *e == actor));
        let s = senales(&d);
        assert!(s.iter().all(|x| x.severidad == Severidad::Media));
        let p = &s[0].porque;
        assert!(
            p.contains("«kernel.yama.ptrace_scope=1» a «kernel.yama.ptrace_scope=0»"),
            "{p}"
        );
        assert!(p.contains("por debajo de la linea base"), "{p}");
        assert!(p.contains("pid 4242"), "{p}");

        // Subir no es noticia.
        poner(&r, "/proc/sys/kernel/yama/ptrace_scope", "2\n");
        assert!(m.mantener(10 * S + 2 * CADA_NS).is_empty());
        let _ = std::fs::remove_dir_all(&r);
    }

    #[test]
    fn bajar_lo_que_el_kernel_no_deja_bajar_es_alta_aunque_no_se_vea_al_autor() {
        let r = raiz("irreversible");
        host_debil(&r);
        poner(&r, "/proc/sys/kernel/modules_disabled", "1\n");
        let (mut m, _) = motor(&r);
        let _ = m.mantener(S);
        poner(&r, "/proc/sys/kernel/modules_disabled", "0\n");
        let d = m.mantener(S + CADA_NS);
        let s = senales(&d);
        assert_eq!(s.len(), 1, "{s:#?}");
        assert_eq!(s[0].severidad, Severidad::Alta);
        assert!(s[0].porque.contains("sin reiniciar"), "{}", s[0].porque);
        assert!(
            s[0].porque.contains("no vio quien escribio"),
            "{}",
            s[0].porque
        );
        let _ = std::fs::remove_dir_all(&r);
    }

    #[test]
    fn lo_ilegible_es_sin_datos_una_vez_y_se_publica() {
        let r = raiz("ilegible");
        host_debil(&r);
        std::fs::remove_file(r.join("proc/sys/kernel/kptr_restrict")).unwrap();
        std::fs::create_dir_all(r.join("proc/sys/kernel/kptr_restrict")).unwrap();
        let (mut m, informe) = motor(&r);
        let d = m.mantener(S);
        let sin: Vec<_> = d
            .iter()
            .filter(|(_, x)| matches!(x, Dictamen::SinDatos(_)))
            .collect();
        assert_eq!(sin.len(), 1, "{d:#?}");
        assert!(
            matches!(&sin[0].1, Dictamen::SinDatos(Causa::Otra(t)) if t.contains("kernel.kptr_restrict")),
            "{sin:?}"
        );
        assert!(informe
            .lock()
            .unwrap()
            .iter()
            .any(|l| l.starts_with("postura kernel.kptr_restrict: ILEGIBLE")));
        let d = m.mantener(S + CADA_NS);
        assert!(
            d.iter().all(|(_, x)| !matches!(x, Dictamen::SinDatos(_))),
            "no se repite: {d:#?}"
        );
        let _ = std::fs::remove_dir_all(&r);
    }

    #[test]
    fn una_escritura_ajena_a_la_postura_no_se_anota() {
        let r = raiz("ajena");
        let (mut m, _) = motor(&r);
        let _ = m.evaluar(&escritura("/etc/passwd", 1, S), &plazo());
        let _ = m.evaluar(&escritura("/proc/sys/vm/swappiness", 1, S), &plazo());
        assert!(m.escrituras.is_empty());
        let _ = std::fs::remove_dir_all(&r);
    }
}
