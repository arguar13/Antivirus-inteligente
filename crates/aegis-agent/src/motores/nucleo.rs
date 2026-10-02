//! Integridad del kernel: procesos que el sistema esconde (FASE 2 del MP-16,
//! ola A).
//!
//! `aegis-kintegrity` compara tres censos de tareas —`/proc`, la lista de
//! tareas del kernel y el espacio de PID— tomados por caminos distintos, y
//! confirma cada discrepancia antes de acusar. Este motor lo barre cada `CADA`
//! en el camino frio y entrega lo confirmado.
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
//! # Cobertura: un barrido parcial no es un barrido completo
//!
//! La vista C (el espacio de PID) se sondea por tramos y con presupuesto
//! ([`aegis_kintegrity::tramos`]): si `pid_max` no cabe en el presupuesto, cada
//! barrido sondea una parte, y la rotacion garantiza que en
//! [`ScanReport::barridos_por_vuelta`] barridos CONSECUTIVOS se sondea el rango
//! entero. Eso cambia lo que significa cada informe, y el motor lo dice:
//!
//! * **Un barrido parcial no es `SinDatos`.** En Ubuntu y Fedora, con `pid_max`
//!   en su limite y el presupuesto por defecto, lo es CADA barrido, y no por un
//!   fallo: el motor mira todo lo que planifico y el resto tiene una cota.
//!   `SinDatos` dice «le tocaba mirar y no pudo», que aqui seria falso. Y seria
//!   dañino: el arbitro guarda un solo motivo por motor
//!   ([`aegis_motor::EstadoMotor::ultimo_sin_datos`]), y un «barrido parcial»
//!   permanente taparia el motivo de un fallo real —la carga rechazada, los
//!   desbordes, otro espacio de nombres—, que es lo que leen el operador y la
//!   matriz de kernels.
//! * **Un barrido parcial tampoco dice «limpio».** «Limpio» solo se afirma de
//!   una VUELTA: tantos barridos validos consecutivos como la cota de la
//!   rotacion, sin anomalias y sin nada que [`ScanReport::concluye_limpio`]
//!   rechace en lo sondeado. Un barrido que no concluye (o que no llega) rompe
//!   la vuelta, porque la cota habla de barridos consecutivos, y la siguiente
//!   empieza de cero. Se cuentan las vueltas limpias, las que tuvieron
//!   pendientes, las que tuvieron anomalias y las interrumpidas.
//!
//! Todo eso va en la linea del motor del informe periodico y de
//! `aegisctl status` ([`Motor::detalle`]), con las cifras de cada informe y no
//! con cifras escritas aqui: `cobertura: barridos=… ultimo_barrido=…
//! pid_sondeados=… pid_sin_sondear=… barridos_por_vuelta=… vuelta_en_curso=…/…
//! vueltas_limpias=… vueltas_con_pendientes=… vueltas_con_anomalias=…
//! vueltas_interrumpidas=… ultima_vuelta=…`.
//!
//! # Nace en solo-auditoria
//!
//! Solo señala; `exige_mitigacion` del crate no se consulta todavia.

use std::fmt::Write as _;
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

/// Motivo de un barrido cuyos censos no numeran igual.
const OTRO_ESPACIO: &str =
    "los censos no numeran igual: el agente corre en otro espacio de nombres de PID";

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

/// Por que un informe no concluye nada, si no concluye.
///
/// Es la misma condicion para las dos cosas que dependen de ella: el
/// `SinDatos` que se entrega y la vuelta que se interrumpe.
fn motivo_sin_datos(informe: &ScanReport) -> Option<String> {
    if !informe.espacios_de_pid_comparables {
        Some(OTRO_ESPACIO.into())
    } else if informe.desbordes > 0 {
        Some(format!(
            "{} tareas no cupieron en los mapas del kernel",
            informe.desbordes
        ))
    } else {
        None
    }
}

/// Lo peor que vio un barrido en lo que sondeo, de menos a mas grave.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
enum Hallazgo {
    /// Nada: [`ScanReport::concluye_limpio`] en lo sondeado.
    #[default]
    Ninguno,
    /// Ninguna anomalia, pero algo que impide concluir limpio: sospechas por
    /// confirmar (`pendientes`).
    Pendientes,
    /// Al menos una anomalia confirmada.
    Anomalias,
}

impl Hallazgo {
    /// Lo que vio un barrido valido.
    ///
    /// «Limpio» es [`ScanReport::concluye_limpio`] —la regla del crate, sin
    /// copiarla— aplicado a lo sondeado: se le quita la clausula de cobertura
    /// (`pid_sin_sondear`), porque aqui la cobertura la da la vuelta entera y
    /// no cada barrido.
    fn de(informe: &ScanReport) -> Hallazgo {
        let limpio_en_lo_sondeado = ScanReport {
            pid_sin_sondear: 0,
            ..informe.clone()
        }
        .concluye_limpio();
        if !informe.anomalies.is_empty() {
            Hallazgo::Anomalias
        } else if limpio_en_lo_sondeado {
            Hallazgo::Ninguno
        } else {
            Hallazgo::Pendientes
        }
    }

    /// Como se publica una vuelta que acabo asi.
    fn vuelta(self) -> &'static str {
        match self {
            Hallazgo::Ninguno => "limpia",
            Hallazgo::Pendientes => "con_pendientes",
            Hallazgo::Anomalias => "con_anomalias",
        }
    }
}

/// Como fue el ultimo barrido, en cuanto a lo que miro.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum UltimoBarrido {
    /// Todavia no ha llegado ninguno.
    #[default]
    Ninguno,
    /// Sondeo el rango configurado entero.
    Completo,
    /// Sondeo una parte; el resto llega por rotacion.
    Parcial,
    /// El informe no dice cuanto sondeo (`barridos_por_vuelta` = 0).
    SinCifras,
    /// Llego, pero no concluye nada (ver [`motivo_sin_datos`]).
    NoConcluye,
    /// No llego informe: fallo la carga del verificador o el barrido.
    Fallido,
}

impl UltimoBarrido {
    /// Como se publica.
    fn nombre(self) -> &'static str {
        match self {
            UltimoBarrido::Ninguno => "ninguno",
            UltimoBarrido::Completo => "completo",
            UltimoBarrido::Parcial => "parcial",
            UltimoBarrido::SinCifras => "sin_cifras",
            UltimoBarrido::NoConcluye => "no_concluye",
            UltimoBarrido::Fallido => "fallido",
        }
    }
}

/// Lo que dijo de su cobertura el ultimo informe que llego.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cifras {
    /// [`ScanReport::pid_sondeados`].
    sondeados: u64,
    /// [`ScanReport::pid_sin_sondear`].
    sin_sondear: u64,
    /// [`ScanReport::barridos_por_vuelta`].
    por_vuelta: u32,
}

/// Una vuelta en curso: barridos validos consecutivos con la misma cota.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Vuelta {
    /// La cota de la rotacion con la que empezo.
    por_vuelta: u32,
    /// Barridos validos que lleva.
    barridos: u32,
    /// Lo peor que vio hasta ahora.
    peor: Hallazgo,
}

/// Cuanto del espacio de PID se ha mirado, barrido a barrido y por vueltas.
///
/// Es puro: no toca el kernel ni el reloj, y se prueba con informes hechos a
/// mano o con los planes del planificador real.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Cobertura {
    /// Barridos intentados, con informe o sin el.
    barridos: u64,
    /// Como fue el ultimo.
    ultimo: UltimoBarrido,
    /// Las cifras del ultimo informe que llego; ninguna tras un fallo.
    cifras: Option<Cifras>,
    /// La vuelta que se esta completando, si hay una.
    en_curso: Option<Vuelta>,
    /// Vueltas completas sin hallazgos.
    limpias: u64,
    /// Vueltas completas con pendientes y sin anomalias.
    con_pendientes: u64,
    /// Vueltas completas con alguna anomalia.
    con_anomalias: u64,
    /// Vueltas que un barrido sin conclusion dejo a medias.
    interrumpidas: u64,
    /// Como acabo la ultima vuelta completa; `None` si no hubo ninguna.
    ultima: Option<Hallazgo>,
}

impl Cobertura {
    /// Anota un barrido que llego con informe.
    fn anotar(&mut self, informe: &ScanReport) {
        self.barridos = self.barridos.saturating_add(1);
        let por_vuelta = informe.barridos_por_vuelta;
        self.cifras = Some(Cifras {
            sondeados: informe.pid_sondeados,
            sin_sondear: informe.pid_sin_sondear,
            por_vuelta,
        });
        self.ultimo = if motivo_sin_datos(informe).is_some() {
            UltimoBarrido::NoConcluye
        } else if por_vuelta == 0 {
            UltimoBarrido::SinCifras
        } else if informe.pid_sin_sondear == 0 {
            UltimoBarrido::Completo
        } else {
            UltimoBarrido::Parcial
        };
        if matches!(
            self.ultimo,
            UltimoBarrido::NoConcluye | UltimoBarrido::SinCifras
        ) {
            // La cota de la rotacion habla de barridos CONSECUTIVOS: uno que
            // no se puede contar rompe la vuelta.
            self.interrumpir();
            return;
        }
        if self.en_curso.is_some_and(|v| v.por_vuelta != por_vuelta) {
            // La cota cambio a mitad: lo anotado no completa la nueva.
            self.interrumpir();
        }
        let v = self.en_curso.get_or_insert(Vuelta {
            por_vuelta,
            barridos: 0,
            peor: Hallazgo::Ninguno,
        });
        v.barridos = v.barridos.saturating_add(1);
        v.peor = v.peor.max(Hallazgo::de(informe));
        if v.barridos < v.por_vuelta {
            return;
        }
        let peor = v.peor;
        self.en_curso = None;
        let cuenta = match peor {
            Hallazgo::Ninguno => &mut self.limpias,
            Hallazgo::Pendientes => &mut self.con_pendientes,
            Hallazgo::Anomalias => &mut self.con_anomalias,
        };
        *cuenta = cuenta.saturating_add(1);
        self.ultima = Some(peor);
    }

    /// Anota un barrido que no trajo informe.
    fn fallo(&mut self) {
        self.barridos = self.barridos.saturating_add(1);
        self.ultimo = UltimoBarrido::Fallido;
        self.cifras = None;
        self.interrumpir();
    }

    /// Deja a medias la vuelta en curso, si la hay.
    fn interrumpir(&mut self) {
        if self.en_curso.take().is_some() {
            self.interrumpidas = self.interrumpidas.saturating_add(1);
        }
    }

    /// La linea que se publica: pares `clave=valor` separados por espacios.
    fn linea(&self) -> String {
        let mut s = format!(
            "cobertura: barridos={} ultimo_barrido={}",
            self.barridos,
            self.ultimo.nombre()
        );
        if let Some(c) = self.cifras {
            let _ = write!(
                s,
                " pid_sondeados={} pid_sin_sondear={} barridos_por_vuelta={}",
                c.sondeados, c.sin_sondear, c.por_vuelta
            );
        }
        let (hechos, cota) = match self.en_curso {
            Some(v) => (v.barridos, Some(v.por_vuelta)),
            None => (0, self.cifras.map(|c| c.por_vuelta).filter(|k| *k > 0)),
        };
        let _ = match cota {
            Some(k) => write!(s, " vuelta_en_curso={hechos}/{k}"),
            None => write!(s, " vuelta_en_curso={hechos}"),
        };
        let _ = write!(
            s,
            " vueltas_limpias={} vueltas_con_pendientes={} vueltas_con_anomalias={} \
             vueltas_interrumpidas={} ultima_vuelta={}",
            self.limpias,
            self.con_pendientes,
            self.con_anomalias,
            self.interrumpidas,
            self.ultima.map_or("ninguna", Hallazgo::vuelta)
        );
        s
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
    /// Cuanto se ha mirado: lo que publica [`Motor::detalle`].
    cobertura: Cobertura,
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
            cobertura: Cobertura::default(),
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

    /// Lo que entrega por cada cosa que llega del hilo del barrido.
    fn recibir(&mut self, barrido: Barrido, ahora_ns: u64) -> Vec<(Eid, Dictamen)> {
        match barrido {
            Ok(informe) => self.entregar(&informe, ahora_ns),
            Err(motivo) => {
                self.cobertura.fallo();
                self.sin_datos(motivo)
            }
        }
    }

    fn entregar(&mut self, informe: &ScanReport, ahora_ns: u64) -> Vec<(Eid, Dictamen)> {
        // Primero la cobertura: un barrido que no concluye tambien cuenta, para
        // romper la vuelta.
        self.cobertura.anotar(informe);
        if let Some(motivo) = motivo_sin_datos(informe) {
            return self.sin_datos(motivo);
        }
        // Un barrido parcial NO es SinDatos: ver la documentacion del modulo.
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
            salida.extend(self.recibir(b, ahora_ns));
        }
        salida
    }

    fn memoria(&self) -> usize {
        self.notificadas.len() * 24
    }

    /// La cobertura: cuanto sondeo el ultimo barrido y cuantas vueltas
    /// completas lleva, y como acabaron. Ver la documentacion del modulo.
    fn detalle(&self) -> Option<String> {
        Some(self.cobertura.linea())
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_kintegrity::tramos::{Plan, Rotacion, PID_MAX_LIMIT, PRESUPUESTO_TRAMOS};
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

    /// Un informe valido con la cobertura de ese plan.
    fn informe_de(plan: &Plan) -> ScanReport {
        ScanReport {
            espacios_de_pid_comparables: true,
            pid_sondeados: plan.sondeados,
            pid_sin_sondear: plan.sin_sondear,
            barridos_por_vuelta: plan.barridos_por_vuelta,
            ..ScanReport::default()
        }
    }

    /// Informes como los de Ubuntu y Fedora (`pid_max` en su limite) con el
    /// presupuesto por defecto: las cifras salen del planificador real.
    fn ubuntu() -> impl FnMut() -> ScanReport {
        let mut r = Rotacion::default();
        move || informe_de(&r.planificar(1, PID_MAX_LIMIT - 1, PRESUPUESTO_TRAMOS, &[]))
    }

    /// El valor de `clave` en una linea de pares `clave=valor`.
    fn valor<'a>(linea: &'a str, clave: &str) -> Option<&'a str> {
        linea
            .split_whitespace()
            .find_map(|par| par.strip_prefix(clave)?.strip_prefix('='))
    }

    fn detalle(m: &MotorNucleo) -> String {
        m.detalle().expect("el nucleo siempre publica su cobertura")
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

    #[test]
    fn antes_del_primer_barrido_publica_que_no_ha_mirado_nada() {
        let m = MotorNucleo::nuevo(&Identidad::fija("m"));
        let d = detalle(&m);
        assert_eq!(valor(&d, "barridos"), Some("0"), "{d}");
        assert_eq!(valor(&d, "ultimo_barrido"), Some("ninguno"), "{d}");
        assert_eq!(valor(&d, "ultima_vuelta"), Some("ninguna"), "{d}");
        assert_eq!(
            valor(&d, "pid_sondeados"),
            None,
            "sin informe no hay cifras: {d}"
        );
        assert!(m.hilo.is_none(), "publicar no carga nada en el kernel");
    }

    #[test]
    fn un_barrido_parcial_no_es_sin_datos_ni_limpio_y_se_distingue() {
        let mut m = MotorNucleo::nuevo(&Identidad::fija("m"));
        let mut siguiente = ubuntu();
        let inf = siguiente();
        assert!(inf.pid_sin_sondear > 0, "{inf:?}");
        assert!(
            !inf.concluye_limpio(),
            "el crate tampoco concluye de un barrido parcial"
        );
        // Nada que entregar: ni señales ni SinDatos.
        assert!(m.entregar(&inf, 1).is_empty());
        let d = detalle(&m);
        assert_eq!(valor(&d, "ultimo_barrido"), Some("parcial"), "{d}");
        let sondeados = inf.pid_sondeados.to_string();
        let sin_sondear = inf.pid_sin_sondear.to_string();
        let por_vuelta = inf.barridos_por_vuelta.to_string();
        assert_eq!(valor(&d, "pid_sondeados"), Some(sondeados.as_str()), "{d}");
        assert_eq!(
            valor(&d, "pid_sin_sondear"),
            Some(sin_sondear.as_str()),
            "{d}"
        );
        assert_eq!(
            valor(&d, "barridos_por_vuelta"),
            Some(por_vuelta.as_str()),
            "{d}"
        );
        assert_eq!(valor(&d, "vueltas_limpias"), Some("0"), "{d}");
        assert_eq!(valor(&d, "ultima_vuelta"), Some("ninguna"), "{d}");
    }

    #[test]
    fn limpio_solo_se_afirma_con_una_vuelta_completa() {
        let mut m = MotorNucleo::nuevo(&Identidad::fija("m"));
        let mut siguiente = ubuntu();
        let mut inf = siguiente();
        let k = inf.barridos_por_vuelta;
        assert!(
            k > 1,
            "con pid_max en su limite un barrido no cubre el rango"
        );
        for i in 1..k {
            assert!(m.entregar(&inf, u64::from(i)).is_empty());
            let d = detalle(&m);
            assert_eq!(valor(&d, "vueltas_limpias"), Some("0"), "{d}");
            assert_eq!(valor(&d, "ultima_vuelta"), Some("ninguna"), "{d}");
            let en_curso = format!("{i}/{k}");
            assert_eq!(valor(&d, "vuelta_en_curso"), Some(en_curso.as_str()), "{d}");
            inf = siguiente();
        }
        assert!(m.entregar(&inf, u64::from(k)).is_empty());
        let d = detalle(&m);
        assert_eq!(valor(&d, "vueltas_limpias"), Some("1"), "{d}");
        assert_eq!(valor(&d, "ultima_vuelta"), Some("limpia"), "{d}");
        let nueva = format!("0/{k}");
        assert_eq!(valor(&d, "vuelta_en_curso"), Some(nueva.as_str()), "{d}");
    }

    #[test]
    fn una_anomalia_o_un_pendiente_en_la_vuelta_no_la_deja_limpia() {
        let mut siguiente = ubuntu();
        for (que, peor) in [
            ("pendiente", "con_pendientes"),
            ("anomalia", "con_anomalias"),
        ] {
            let mut m = MotorNucleo::nuevo(&Identidad::fija("m"));
            let mut inf = siguiente();
            let k = inf.barridos_por_vuelta;
            for i in 1..=k {
                if i == 1 {
                    let a = anomalia(AnomalyKind::DkomUnlinked);
                    if que == "pendiente" {
                        inf.pendientes.push(a);
                    } else {
                        inf.anomalies.push(a);
                    }
                }
                m.entregar(&inf, u64::from(i));
                inf = siguiente();
            }
            let d = detalle(&m);
            assert_eq!(valor(&d, "ultima_vuelta"), Some(peor), "{que}: {d}");
            assert_eq!(valor(&d, "vueltas_limpias"), Some("0"), "{que}: {d}");
            assert_eq!(
                valor(&d, &format!("vueltas_{peor}")),
                Some("1"),
                "{que}: {d}"
            );
        }
    }

    #[test]
    fn un_barrido_que_no_concluye_o_no_llega_interrumpe_la_vuelta() {
        let mut m = MotorNucleo::nuevo(&Identidad::fija("m"));
        let mut siguiente = ubuntu();
        let k = siguiente().barridos_por_vuelta;
        // Todos menos uno de una vuelta, y un barrido en otro espacio de
        // nombres: SinDatos, y la vuelta se pierde.
        for i in 1..k {
            m.entregar(&siguiente(), u64::from(i));
        }
        let mut ciego = siguiente();
        ciego.espacios_de_pid_comparables = false;
        let d = m.entregar(&ciego, u64::from(k));
        assert!(
            matches!(d.as_slice(), [(_, Dictamen::SinDatos(_))]),
            "{d:?}"
        );
        let l = detalle(&m);
        assert_eq!(valor(&l, "ultimo_barrido"), Some("no_concluye"), "{l}");
        assert_eq!(valor(&l, "vueltas_interrumpidas"), Some("1"), "{l}");
        assert_eq!(valor(&l, "vueltas_limpias"), Some("0"), "{l}");
        // Un barrido que no llega tambien la rompe.
        m.entregar(&siguiente(), 0);
        let d = m.recibir(Err("barrido fallido: prueba".into()), 0);
        assert!(
            matches!(d.as_slice(), [(_, Dictamen::SinDatos(_))]),
            "{d:?}"
        );
        let l = detalle(&m);
        assert_eq!(valor(&l, "ultimo_barrido"), Some("fallido"), "{l}");
        assert_eq!(
            valor(&l, "pid_sondeados"),
            None,
            "un fallo no trae cifras: {l}"
        );
        assert_eq!(valor(&l, "vueltas_interrumpidas"), Some("2"), "{l}");
        // Despues, una vuelta entera de barridos validos si concluye limpia.
        for i in 1..=k {
            m.entregar(&siguiente(), u64::from(i));
        }
        let l = detalle(&m);
        assert_eq!(valor(&l, "vueltas_limpias"), Some("1"), "{l}");
        assert_eq!(valor(&l, "ultima_vuelta"), Some("limpia"), "{l}");
        // Barridos intentados, con informe o sin el: k-1 validos, el ciego, el
        // valido que abre la vuelta rota, el fallido y la vuelta entera (k).
        let total = (2 * u64::from(k) + 2).to_string();
        assert_eq!(valor(&l, "barridos"), Some(total.as_str()), "{l}");
    }

    #[test]
    fn un_barrido_completo_es_una_vuelta_por_si_solo() {
        // Un pid_max que cabe en el presupuesto (el de WSL, por ejemplo): cada
        // barrido sondea el rango entero.
        let mut r = Rotacion::default();
        let tope = i32::try_from(PRESUPUESTO_TRAMOS).unwrap_or(i32::MAX)
            * i32::try_from(aegis_kintegrity::abi::MAX_BARRIDO).unwrap_or(i32::MAX);
        let plan = r.planificar(1, tope.saturating_sub(1), PRESUPUESTO_TRAMOS, &[]);
        assert_eq!((plan.sin_sondear, plan.barridos_por_vuelta), (0, 1));
        let inf = informe_de(&plan);
        assert!(inf.concluye_limpio());
        let mut m = MotorNucleo::nuevo(&Identidad::fija("m"));
        assert!(m.entregar(&inf, 1).is_empty());
        let d = detalle(&m);
        assert_eq!(valor(&d, "ultimo_barrido"), Some("completo"), "{d}");
        assert_eq!(valor(&d, "pid_sin_sondear"), Some("0"), "{d}");
        assert_eq!(valor(&d, "vueltas_limpias"), Some("1"), "{d}");
        assert_eq!(valor(&d, "vuelta_en_curso"), Some("0/1"), "{d}");
    }

    #[test]
    fn un_informe_sin_cifras_no_cuenta_para_ninguna_vuelta() {
        // `barridos_por_vuelta` = 0: el informe no dice cuanto miro.
        let mut m = MotorNucleo::nuevo(&Identidad::fija("m"));
        assert!(m.entregar(&informe(Vec::new()), 1).is_empty());
        let d = detalle(&m);
        assert_eq!(valor(&d, "ultimo_barrido"), Some("sin_cifras"), "{d}");
        assert_eq!(valor(&d, "vuelta_en_curso"), Some("0"), "{d}");
        assert_eq!(valor(&d, "ultima_vuelta"), Some("ninguna"), "{d}");
    }

    #[test]
    fn la_linea_de_cobertura_cabe_entera_en_el_informe() {
        let c = Cobertura {
            barridos: u64::MAX,
            ultimo: UltimoBarrido::NoConcluye,
            cifras: Some(Cifras {
                sondeados: u64::MAX,
                sin_sondear: u64::MAX,
                por_vuelta: u32::MAX,
            }),
            en_curso: Some(Vuelta {
                por_vuelta: u32::MAX,
                barridos: u32::MAX,
                peor: Hallazgo::Anomalias,
            }),
            limpias: u64::MAX,
            con_pendientes: u64::MAX,
            con_anomalias: u64::MAX,
            interrumpidas: u64::MAX,
            ultima: Some(Hallazgo::Pendientes),
        };
        let l = c.linea();
        assert!(
            l.len() <= aegis_motor::arbitro::MAX_DETALLE,
            "{} > {}: el arbitro la cortaria",
            l.len(),
            aegis_motor::arbitro::MAX_DETALLE
        );
    }
}
