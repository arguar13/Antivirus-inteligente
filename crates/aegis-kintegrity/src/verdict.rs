//! Comparacion de las vistas y emision del veredicto.
//!
//! Todo este modulo es PURO: recibe vistas ya tomadas y devuelve conclusiones.
//! No toca el kernel, no lee `/proc` y no depende de tener privilegios, asi que
//! la logica que decide si un proceso es un rootkit se prueba entera en
//! cualquier maquina. Esa logica es la que puede acusar en falso, y por tanto
//! la que mas cobertura necesita.
//!
//! # Por que un candidato no es una anomalia
//!
//! Entre tomar una vista y tomar la siguiente, los procesos nacen y mueren. Un
//! `ls` que termina justo en medio aparece en una vista y no en la otra, y un
//! detector ingenuo lo denunciaria como rootkit. En un servidor con carga eso
//! son decenas de falsos positivos criticos por minuto: el producto se apaga la
//! primera semana.
//!
//! Por eso la comparacion produce CANDIDATOS, y solo una confirmacion —volver a
//! mirar ese TID concreto por los dos caminos, con microsegundos de diferencia—
//! los convierte en anomalias. Un proceso que murio desaparece de las dos
//! vistas; uno oculto conserva la asimetria.

use std::collections::BTreeSet;

use crate::views::{TaskRecord, ViewSet};

/// Que clase de manipulacion describe la discrepancia.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AnomalyKind {
    /// Esta en el espacio de PID pero NO en la lista de tareas.
    ///
    /// Es la firma de DKOM: el rootkit desenlaza el `task_struct` de la lista
    /// global para que `/proc` y `ps` no lo vean, pero tiene que dejarlo en el
    /// arbol de PID o el proceso deja de ser planificable y de poder recibir
    /// senales, que es tanto como matarlo.
    DkomUnlinked,
    /// El kernel lo ve por los dos caminos, pero `/proc` no lo lista.
    ///
    /// La manipulacion esta en espacio de usuario: un hook de `getdents`, un
    /// `LD_PRELOAD` sobre `readdir`, o un montaje encima de `/proc`.
    UserlandHidden,
    /// Esta en la lista de tareas pero no en el espacio de PID.
    ///
    /// Es la asimetria inversa y mucho mas rara. Un proceso asi no puede recibir
    /// senales, de modo que casi siempre es una tarea en pleno desmontaje; la
    /// confirmacion lo separa de una manipulacion del `idr`.
    PidSpaceDetached,
    /// `/proc` lo lista pero el kernel no lo conoce por ningun camino.
    ///
    /// Una entrada de `/proc` sin tarea detras es un `/proc` falsificado: la
    /// direccion contraria a esconder, usada para desviar la atencion o para
    /// que un analista persiga un PID que no existe.
    PhantomProcEntry,
    /// El mismo TID con instantes de arranque distintos en las dos vistas de
    /// kernel.
    ///
    /// Las dos vistas se toman en la misma invocacion, con microsegundos de
    /// diferencia, asi que un reciclado de PID en esa ventana es improbable
    /// pero no imposible; lo que no es normal es que una de las dos publique un
    /// arranque que la otra no reconoce.
    IdentityMismatch,
}

impl AnomalyKind {
    /// Etiqueta estable para registros y para el canal de control.
    pub fn as_str(self) -> &'static str {
        match self {
            AnomalyKind::DkomUnlinked => "dkom-desenlazado",
            AnomalyKind::UserlandHidden => "oculto-en-userland",
            AnomalyKind::PidSpaceDetached => "fuera-del-espacio-de-pid",
            AnomalyKind::PhantomProcEntry => "entrada-fantasma-en-proc",
            AnomalyKind::IdentityMismatch => "identidad-incoherente",
        }
    }

    /// Gravedad sobre 100.
    ///
    /// Las dos formas de OCULTAR un proceso son las maximas porque no tienen
    /// lectura benigna: ningun sistema operativo esconde procesos por su
    /// cuenta. Las otras dos pueden darse de forma transitoria durante el
    /// desmontaje de una tarea, y por eso pesan menos aunque tambien confirmen.
    pub fn severity(self) -> u8 {
        match self {
            AnomalyKind::DkomUnlinked => 100,
            AnomalyKind::UserlandHidden => 95,
            AnomalyKind::PidSpaceDetached => 70,
            AnomalyKind::PhantomProcEntry => 65,
            AnomalyKind::IdentityMismatch => 50,
        }
    }

    /// Indica si la clase justifica una mitigacion automatica.
    pub fn exige_mitigacion(self) -> bool {
        matches!(
            self,
            AnomalyKind::DkomUnlinked | AnomalyKind::UserlandHidden
        )
    }
}

/// Una discrepancia sin confirmar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// TID sobre el que hay discrepancia.
    pub tid: u32,
    /// Clase que sugiere la discrepancia.
    pub kind: AnomalyKind,
    /// Lo que se sabe de la tarea por la vista que si la vio.
    pub record: Option<TaskRecord>,
}

/// Lo que devuelve la confirmacion de un TID concreto.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Confirmation {
    /// Sigue en la lista de tareas.
    pub en_lista: bool,
    /// Sigue en el espacio de PID.
    pub en_pidmap: bool,
    /// Sigue en `/proc`.
    pub en_procfs: bool,
    /// El kernel lo resuelve en el espacio de nombres de PID de este proceso.
    ///
    /// Es el tercer camino, y el unico que numera igual que `/proc`. Ver
    /// [`crate::views::resuelve_el_kernel`]: separa «los dos lados numeran
    /// distinto» de «la entrada de `/proc` esta falsificada», que hasta que se
    /// midio contra un kernel de verdad se escribian igual.
    pub en_vpid: bool,
    /// Instante de arranque leido en la confirmacion, si se pudo.
    pub start_boottime: Option<u64>,
}

/// Una anomalia confirmada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anomaly {
    /// TID afectado.
    pub tid: u32,
    /// Grupo de hilos, si se conoce.
    pub tgid: Option<u32>,
    /// Nombre corto, si se conoce.
    pub comm: Option<String>,
    /// Clase confirmada.
    pub kind: AnomalyKind,
    /// Gravedad sobre 100.
    pub severity: u8,
    /// Confirmaciones consecutivas acumuladas.
    pub confirmaciones: u32,
    /// Explicacion para el analista.
    pub detalle: String,
}

impl Anomaly {
    /// Indica si procede una mitigacion automatica.
    pub fn exige_mitigacion(&self) -> bool {
        self.kind.exige_mitigacion()
    }
}

/// Configuracion de la comparacion.
#[derive(Debug, Clone)]
pub struct VerdictConfig {
    /// TID que nunca se consideran, con su motivo.
    ///
    /// El unico habitante legitimo es el TID 0: las tareas ociosas por CPU
    /// tienen PID 0, no aparecen en `/proc` y `bpf_task_from_pid(0)` no las
    /// resuelve. Sin esta exclusion, cada arranque reportaria una anomalia por
    /// CPU.
    pub exentos: BTreeSet<u32>,
    /// Confirmaciones consecutivas necesarias para dar por buena una anomalia.
    pub confirmaciones_requeridas: u32,
    /// Candidatos maximos que se examinan en un barrido.
    ///
    /// Acota el trabajo ante una maquina que de verdad tenga miles de
    /// discrepancias: confirmar cada una cuesta un recorrido de la lista de
    /// tareas, y un detector que se bloquea investigando no detecta nada mas.
    pub max_candidatos: usize,
}

impl Default for VerdictConfig {
    fn default() -> Self {
        let mut exentos = BTreeSet::new();
        exentos.insert(0);
        Self {
            exentos,
            confirmaciones_requeridas: 2,
            max_candidatos: 256,
        }
    }
}

/// Compara las tres vistas y devuelve las discrepancias a confirmar.
///
/// Cuando el barrido del kernel se desbordo, las ausencias de las vistas de
/// kernel dejan de ser concluyentes —podrian venir del truncamiento— y solo se
/// emiten las discrepancias que NO dependen de esa ausencia.
pub fn candidatos(v: &ViewSet, cfg: &VerdictConfig) -> Vec<Candidate> {
    let mut salida = Vec::new();
    let incompleto = v.desbordes > 0;

    let mut todos: BTreeSet<u32> = BTreeSet::new();
    todos.extend(v.procfs.keys().copied());
    todos.extend(v.task_list.keys().copied());
    todos.extend(v.pid_space.keys().copied());

    for tid in todos {
        if cfg.exentos.contains(&tid) {
            continue;
        }
        if salida.len() >= cfg.max_candidatos {
            break;
        }
        let en_proc = v.procfs.get(&tid);
        let en_lista = v.task_list.get(&tid);
        let en_pid = v.pid_space.get(&tid);

        let kind = match (en_proc.is_some(), en_lista.is_some(), en_pid.is_some()) {
            // Las tres coinciden: hay que mirar la identidad, no la presencia.
            (_, true, true) => {
                let (a, b) = (en_lista.unwrap(), en_pid.unwrap());
                if a.start_boottime.is_some()
                    && b.start_boottime.is_some()
                    && a.start_boottime != b.start_boottime
                {
                    Some(AnomalyKind::IdentityMismatch)
                } else if en_proc.is_none() {
                    Some(AnomalyKind::UserlandHidden)
                } else {
                    None
                }
            }
            // Solo el espacio de PID lo ve: la firma de DKOM.
            (_, false, true) if !incompleto => Some(AnomalyKind::DkomUnlinked),
            // Solo la lista lo ve.
            (_, true, false) if !incompleto => Some(AnomalyKind::PidSpaceDetached),
            // Solo `/proc` lo ve: entrada sin tarea detras.
            (true, false, false) if !incompleto => Some(AnomalyKind::PhantomProcEntry),
            _ => None,
        };

        if let Some(kind) = kind {
            salida.push(Candidate {
                tid,
                kind,
                record: en_lista.or(en_pid).or(en_proc).cloned(),
            });
        }
    }
    salida
}

/// Juzga un candidato a la luz de su confirmacion.
///
/// Devuelve `None` por dos motivos distintos, y quien llama los separa:
///
/// - La discrepancia **se desvanecio**, que es el caso normal: el proceso habia
///   muerto entre las vistas y el barrido lo capto a medias.
/// - La discrepancia **no es comparable**: la tarea aparece solo en `/proc` y el
///   kernel la resuelve por el camino que numera como `/proc`, de modo que
///   existe y lo que falla es la comparacion. Ver [`Confirmation::en_vpid`].
pub fn juzgar(c: &Candidate, conf: &Confirmation) -> Option<AnomalyKind> {
    // Una tarea que ya no esta en ninguna parte era una carrera, no un rootkit.
    if !conf.en_lista && !conf.en_pidmap && !conf.en_procfs {
        return None;
    }
    let kind = match (conf.en_procfs, conf.en_lista, conf.en_pidmap) {
        (_, false, true) => AnomalyKind::DkomUnlinked,
        (false, true, true) => AnomalyKind::UserlandHidden,
        (_, true, false) => AnomalyKind::PidSpaceDetached,
        // Solo `/proc` lo ve. Antes de acusar hay que descartar la explicacion
        // aburrida: que las vistas de eBPF numeren en otro espacio de nombres de
        // PID que el que `/proc` usa. Si el kernel resuelve el TID por el camino
        // que numera COMO `/proc`, la tarea existe y lo que falla es la
        // comparacion, no la maquina. Acusar ahi seria acusar de rootkit a cada
        // proceso de un contenedor.
        (true, false, false) => {
            if conf.en_vpid {
                return None;
            }
            AnomalyKind::PhantomProcEntry
        }
        // Coherente por los tres caminos: la unica sospecha que puede quedar es
        // la de identidad, y solo si es la que se venia siguiendo.
        (true, true, true) => {
            if c.kind == AnomalyKind::IdentityMismatch {
                AnomalyKind::IdentityMismatch
            } else {
                return None;
            }
        }
        (false, false, false) => return None,
    };
    Some(kind)
}

/// Construye la anomalia final.
pub fn anomalia(c: &Candidate, kind: AnomalyKind, confirmaciones: u32) -> Anomaly {
    let detalle = match kind {
        AnomalyKind::DkomUnlinked => format!(
            "el TID {} responde en el espacio de PID del kernel pero NO aparece \
             al recorrer la lista de tareas: su task_struct esta desenlazado \
             (DKOM). El proceso se sigue ejecutando y es invisible para /proc, \
             ps y cualquier herramienta que pregunte al sistema.",
            c.tid
        ),
        AnomalyKind::UserlandHidden => format!(
            "el kernel ve el TID {} por sus dos estructuras internas, pero /proc \
             no lo lista: la ocultacion esta en espacio de usuario (hook de \
             getdents, LD_PRELOAD o un montaje encima de /proc).",
            c.tid
        ),
        AnomalyKind::PidSpaceDetached => format!(
            "el TID {} aparece en la lista de tareas pero no se resuelve por el \
             espacio de PID: no podria recibir senales. O esta en pleno \
             desmontaje o alguien manipulo el idr del espacio de nombres.",
            c.tid
        ),
        AnomalyKind::PhantomProcEntry => format!(
            "/proc publica el TID {} y el kernel no lo conoce por NINGUNO de los \
             tres caminos: ni recorriendo la lista de tareas, ni resolviendolo \
             en el espacio de PID, ni por el planificador —que numera en el \
             mismo espacio de nombres que /proc—. La entrada de /proc esta \
             falsificada.",
            c.tid
        ),
        AnomalyKind::IdentityMismatch => format!(
            "el TID {} publica instantes de arranque distintos en las dos vistas \
             de kernel, tomadas con microsegundos de diferencia.",
            c.tid
        ),
    };
    Anomaly {
        tid: c.tid,
        tgid: c.record.as_ref().map(|r| r.tgid),
        comm: c.record.as_ref().and_then(|r| r.comm.clone()),
        kind,
        severity: kind.severity(),
        confirmaciones,
        detalle,
    }
}
