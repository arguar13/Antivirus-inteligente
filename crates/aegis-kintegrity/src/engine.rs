//! El motor: orquesta barrido, confirmacion y persistencia.

use std::collections::HashMap;

use crate::error::KiError;
use crate::tramos::{self, Plan, Rotacion, Tramo};
use crate::verdict::{self, Anomaly, AnomalyKind, Confirmation, VerdictConfig};
use crate::views::{self, ViewSet, Vista};

/// Origen de las dos vistas de kernel.
///
/// Es un rasgo y no una implementacion concreta para que el motor —donde vive
/// la decision de acusar a un proceso de ser un rootkit— se pueda ejercitar
/// entero sin kernel, con vistas construidas a mano que reproducen exactamente
/// las manipulaciones que se quieren detectar. Montar un rootkit DKOM de verdad
/// en la maquina de integracion no es una opcion.
pub trait KernelViews {
    /// Toma las dos vistas de kernel sobre `[primero, ultimo]` entero.
    ///
    /// Devuelve `(lista de tareas, espacio de PID, desbordes)`. Un origen real
    /// lo parte en tramos ([`crate::tramos::partir`]) y toma las dos vistas de
    /// cada tramo en una sola invocacion.
    fn barrer(&mut self, primero: i32, ultimo: i32) -> Result<(Vista, Vista, u32), KiError>;

    /// Toma las dos vistas de kernel de esos tramos, y solo de esos.
    ///
    /// Cada tramo es UNA invocacion del programa, que toma B y C juntas sobre
    /// el tramo. El motor descarta lo que llegue de fuera de los tramos, asi
    /// que un origen que no sepa filtrar —el de las pruebas— puede devolver de
    /// mas sin falsear nada.
    ///
    /// Por defecto, un [`KernelViews::barrer`] por tramo, unidos.
    fn barrer_tramos(&mut self, tramos: &[Tramo]) -> Result<(Vista, Vista, u32), KiError> {
        let mut lista = Vista::new();
        let mut pidmap = Vista::new();
        let mut desbordes = 0u32;
        for t in tramos {
            let (l, p, d) = self.barrer(t.primero, t.ultimo)?;
            lista.extend(l);
            pidmap.extend(p);
            desbordes = desbordes.saturating_add(d);
        }
        Ok((lista, pidmap, desbordes))
    }

    /// Vuelve a mirar UN solo TID por los dos caminos.
    ///
    /// Devuelve `(en la lista, en el espacio de PID, instante de arranque)`.
    fn confirmar(&mut self, tid: u32) -> Result<(bool, bool, Option<u64>), KiError>;
}

/// Configuracion del motor.
#[derive(Debug, Clone)]
pub struct KiConfig {
    /// Primer PID del barrido.
    pub primero: i32,
    /// Ultimo PID del barrido, inclusive.
    ///
    /// Por defecto `pid_max - 1`, con `pid_max` leido de
    /// `/proc/sys/kernel/pid_max`, que es el limite superior EXCLUSIVO del
    /// asignador: barrer por encima gasta iteraciones en un rango que el kernel
    /// no puede asignar, y barrer por debajo deja un hueco donde esconderse.
    pub ultimo: i32,
    /// Tramos de [`crate::abi::MAX_BARRIDO`] PID que sondea, como mucho, un
    /// barrido; ver [`crate::tramos`].
    ///
    /// Con `pid_max` = 4194304 el rango son 64 tramos: el presupuesto por
    /// defecto ([`tramos::PRESUPUESTO_TRAMOS`]) sondea 16 por barrido y da la
    /// vuelta entera cada 6. Lo que un barrido no sondea se cuenta en
    /// [`ScanReport::pid_sin_sondear`].
    pub presupuesto_tramos: usize,
    /// Reglas de comparacion.
    pub verdict: VerdictConfig,
}

impl Default for KiConfig {
    fn default() -> Self {
        Self {
            primero: 1,
            ultimo: pid_max() - 1,
            presupuesto_tramos: tramos::PRESUPUESTO_TRAMOS,
            verdict: VerdictConfig::default(),
        }
    }
}

/// Lee `pid_max` del sistema.
///
/// Ante cualquier problema devuelve 32768, el valor por defecto de Linux: es
/// preferible barrer el rango clasico a no barrer nada.
pub fn pid_max() -> i32 {
    std::fs::read_to_string("/proc/sys/kernel/pid_max")
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(32_768)
}

/// Resultado de un barrido.
#[derive(Debug, Clone, Default)]
pub struct ScanReport {
    /// Anomalias que superaron el umbral de confirmaciones.
    pub anomalies: Vec<Anomaly>,
    /// Anomalias confirmadas que aun no llegan al umbral.
    pub pendientes: Vec<Anomaly>,
    /// Tareas vistas en la lista de tareas.
    pub en_lista: usize,
    /// Tareas vistas en el espacio de PID.
    pub en_pidmap: usize,
    /// Tareas vistas en `/proc`.
    pub en_procfs: usize,
    /// Candidatos examinados.
    pub candidatos: usize,
    /// Candidatos que se desvanecieron al confirmarlos: carreras, no rootkits.
    pub descartados_por_carrera: usize,
    /// Entradas de `/proc` que el kernel SI conoce, pero con otro numero.
    ///
    /// Las vistas de eBPF numeran en el espacio de nombres de PID inicial y
    /// `/proc` numera en el del proceso que lee. Cuando no son el mismo, una
    /// entrada aparece solo en `/proc` sin que nadie la haya falsificado: el
    /// planificador la resuelve sin problema. No es una anomalia y tampoco es
    /// una carrera, asi que se cuenta aparte en vez de mezclarla con ninguna de
    /// las dos. Un numero alto y sostenido aqui significa que este agente corre
    /// en un espacio de nombres distinto del que ve el kernel, y que la
    /// verificacion cruzada NO esta cubriendo esas tareas. Quien quiera esa
    /// conclusion no tiene que deducirla de este contador:
    /// [`ScanReport::espacios_de_pid_comparables`] la da medida.
    pub numeracion_distinta: usize,
    /// Si las tres vistas numeran en el mismo espacio de nombres de PID.
    ///
    /// Es la **precondicion** de todo este crate: comparar tres censos solo
    /// dice algo si los tres nombran a las mismas tareas con los mismos
    /// numeros. Las vistas de kernel numeran en el espacio inicial y `/proc` en
    /// el del proceso que lee, asi que la precondicion no se cumple sola.
    ///
    /// Se mide de la forma mas directa que hay, y no deduciendola de los
    /// contadores: **el agente se busca a si mismo** en las vistas del kernel.
    /// Si no se encuentra —existiendo, y estando su TID dentro del rango
    /// barrido—, es que los dos lados no numeran igual.
    ///
    /// En `false` el barrido **no verifico nada** de lo que no cuadra: las
    /// ausencias que vea son de numeracion, no de ocultacion. Un informe con
    /// `anomalies` vacio y esto en `false` no significa «la maquina esta
    /// limpia», significa «aqui no se pudo mirar». Son cosas distintas y se
    /// dicen distinto.
    pub espacios_de_pid_comparables: bool,
    /// Entradas que no cupieron en los mapas del kernel.
    pub desbordes: u32,
    /// PID que este barrido sondeo en la vista C.
    pub pid_sondeados: u64,
    /// PID del rango configurado que este barrido NO sondeo.
    ///
    /// La vista C se toma por tramos y con presupuesto ([`crate::tramos`]):
    /// con `pid_max` = 4194304 un barrido no los sondea todos, y lo que queda
    /// fuera se cuenta aqui en vez de pasar por mirado. Fuera de lo sondeado
    /// no se compara ninguna de las tres vistas; se mira en los barridos
    /// siguientes, como mucho dentro de [`ScanReport::barridos_por_vuelta`].
    pub pid_sin_sondear: u64,
    /// Barridos que tarda, como mucho, en sondearse el rango entero: 1 si cada
    /// barrido lo cubre todo, 0 si el informe no dice nada de eso.
    pub barridos_por_vuelta: u32,
}

impl ScanReport {
    /// Indica si el barrido encontro algo que exige mitigacion.
    pub fn exige_mitigacion(&self) -> bool {
        self.anomalies.iter().any(|a| a.exige_mitigacion())
    }

    /// Gravedad maxima observada.
    pub fn severidad_maxima(&self) -> u8 {
        self.anomalies.iter().map(|a| a.severity).max().unwrap_or(0)
    }

    /// Indica si de este barrido se puede concluir «no hay nada oculto».
    ///
    /// Un barrido sin anomalias NO autoriza esa frase por si solo. Solo la
    /// autoriza si ademas la comparacion era posible —los tres censos numeran
    /// igual— y estaba completa —nada se quedo fuera de los mapas del kernel—.
    /// Lo que no se pudo mirar se cuenta como no mirado, nunca como limpio.
    ///
    /// Tampoco la autoriza un barrido que dejo PID sin sondear: con un
    /// `pid_max` mayor que el presupuesto, ningun barrido suelto lo hace, y
    /// la cobertura del rango entero llega por rotacion en
    /// [`ScanReport::barridos_por_vuelta`] barridos.
    pub fn concluye_limpio(&self) -> bool {
        self.anomalies.is_empty()
            && self.pendientes.is_empty()
            && self.espacios_de_pid_comparables
            && self.desbordes == 0
            && self.pid_sin_sondear == 0
    }
}

/// Motor de verificacion cruzada.
pub struct KernelIntegrity<K: KernelViews> {
    kernel: K,
    config: KiConfig,
    /// Como se relee `/proc` en la confirmacion. Inyectable para las pruebas.
    procfs_confirm: Box<dyn Fn() -> Vista + Send>,
    /// Confirmaciones consecutivas por (TID, clase).
    ///
    /// La clase forma parte de la clave a proposito: un TID que pasa de
    /// `PidSpaceDetached` a `DkomUnlinked` no esta confirmando lo mismo, y
    /// arrastrar el contador entre clases distintas convertiria dos sospechas
    /// debiles en una fuerte.
    rachas: HashMap<(u32, AnomalyKind), u32>,
    /// Que tramos del espacio de PID se sondearon, y cuando.
    rotacion: Rotacion,
    /// `ns_last_pid` en el barrido anterior: de ahi al de ahora van los PID
    /// nacidos entre barridos.
    cursor: Option<i32>,
}

impl<K: KernelViews + std::fmt::Debug> std::fmt::Debug for KernelIntegrity<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KernelIntegrity")
            .field("kernel", &self.kernel)
            .field("config", &self.config)
            .field("rachas", &self.rachas.len())
            .finish()
    }
}

impl<K: KernelViews> KernelIntegrity<K> {
    /// Crea el motor.
    pub fn new(kernel: K, config: KiConfig) -> KernelIntegrity<K> {
        KernelIntegrity {
            kernel,
            config,
            procfs_confirm: Box::new(views::leer_procfs),
            rachas: HashMap::new(),
            rotacion: Rotacion::default(),
            cursor: None,
        }
    }

    /// Crea el motor con una relectura de `/proc` a medida, para las pruebas.
    pub fn con_relectura(
        kernel: K,
        config: KiConfig,
        procfs_confirm: impl Fn() -> Vista + Send + 'static,
    ) -> KernelIntegrity<K> {
        KernelIntegrity {
            kernel,
            config,
            procfs_confirm: Box::new(procfs_confirm),
            rachas: HashMap::new(),
            rotacion: Rotacion::default(),
            cursor: None,
        }
    }

    /// Configuracion en uso.
    pub fn config(&self) -> &KiConfig {
        &self.config
    }

    /// Acceso mutable al origen de vistas de kernel.
    ///
    /// Existe para que una prueba de integracion pueda tomar las vistas reales
    /// del kernel por separado y manipular DESPUES solo la vista de usuario,
    /// que es exactamente lo que hace un rootkit de `getdents`: todo lo de
    /// kernel autentico, solo `/proc` mentido.
    pub fn kernel_mut(&mut self) -> &mut K {
        &mut self.kernel
    }

    /// Racha de confirmaciones de una sospecha concreta.
    pub fn racha(&self, tid: u32, kind: AnomalyKind) -> u32 {
        self.rachas.get(&(tid, kind)).copied().unwrap_or(0)
    }

    /// Toma las tres vistas y emite el veredicto.
    pub fn scan(&mut self) -> Result<ScanReport, KiError> {
        self.scan_con(views::leer_procfs)
    }

    /// [`KernelIntegrity::scan`] con la lectura de `/proc` a medida.
    ///
    /// Existe para las pruebas: con un kernel de mentira la vista A tiene que
    /// ser de mentira tambien, o cada tarea real de la maquina seria una
    /// entrada «solo en /proc». Se recibe como funcion, y no como vista ya
    /// tomada, para que se lea donde se lee la de verdad: justo despues de las
    /// vistas de kernel.
    pub fn scan_con(&mut self, leer: impl FnOnce() -> Vista) -> Result<ScanReport, KiError> {
        let plan = self.planificar();
        // El orden importa: primero las dos vistas de kernel, que van juntas
        // en una invocacion por tramo, y `/proc` inmediatamente despues. Al
        // reves, la vista de usuario seria la mas vieja de las tres y toda
        // tarea nacida en el intervalo pareceria oculta en userland.
        let (task_list, pid_space, desbordes) = self.kernel.barrer_tramos(&plan.tramos)?;
        let procfs = leer();

        // Solo se compara lo sondeado. Una tarea de `/proc` cuyo tramo no se
        // sondeo no esta en C porque nadie la busco, no porque falte; y lo que
        // un origen devuelva de mas, fuera de los tramos, tampoco entra.
        let vistas = ViewSet {
            procfs: recortar(procfs, &plan),
            task_list: recortar(task_list, &plan),
            pid_space: recortar(pid_space, &plan),
            desbordes,
        };
        self.evaluar_plan(&vistas, &plan)
    }

    /// Los tramos de este barrido: primero los relevantes, luego la rotacion.
    fn planificar(&mut self) -> Plan {
        let mut relevantes: Vec<u32> = Vec::new();
        // La sonda primero: sin su tramo no se puede comprobar la precondicion.
        if let Ok(yo) = u32::try_from(tid_propio()) {
            relevantes.push(yo);
        }
        // Las sospechas abiertas: confirmarlas exige barridos CONSECUTIVOS.
        let mut abiertas: Vec<u32> = self.rachas.keys().map(|(tid, _)| *tid).collect();
        abiertas.sort_unstable();
        relevantes.extend(abiertas);
        // Lo nacido desde el barrido anterior: un proceso recien escondido.
        let cursor = ultimo_pid_asignado();
        if let Some(ahora) = cursor {
            relevantes.extend(tramos::nacidos(
                self.cursor,
                ahora,
                self.config.primero,
                self.config.ultimo,
            ));
            self.cursor = cursor;
        }
        self.rotacion.planificar(
            self.config.primero,
            self.config.ultimo,
            self.config.presupuesto_tramos,
            &relevantes,
        )
    }

    /// Relee `/proc` por el canal de listado, para la confirmacion.
    ///
    /// Es un metodo y no una funcion suelta para que una prueba pueda cambiar
    /// el conjunto que ve la confirmacion —esconderle un TID— y comprobar que
    /// la deteccion sobrevive a la confirmacion, sin necesitar un rootkit real.
    fn releer_procfs(&self) -> Vista {
        (self.procfs_confirm)()
    }

    /// Comprueba la precondicion de la verificacion cruzada: que las vistas del
    /// kernel numeren en el mismo espacio de nombres de PID que `/proc`.
    ///
    /// La sonda es el propio agente. Su TID existe con certeza —lo esta
    /// ejecutando—, `/proc` lo publica con ese numero, y si las vistas del
    /// kernel numeraran igual tendrian que traerlo. Que no lo traigan solo
    /// admite dos lecturas, y las dos invalidan el barrido:
    ///
    /// - Las vistas numeran en otro espacio de nombres. Entonces ninguna
    ///   ausencia significa ocultacion, porque no se estan comparando censos
    ///   del mismo conjunto de numeros.
    /// - Algo esconde al agente de las vistas del kernel. Entonces el
    ///   observador ya esta comprometido y sus censos no valen nada.
    ///
    /// No se puede concluir nada en ninguno de los dos casos, que es justo lo
    /// que el informe pasa a decir.
    fn vistas_comparables(&self, vistas: &ViewSet, plan: &Plan) -> bool {
        let yo = tid_propio();
        // Fuera del rango barrido su ausencia no prueba nada: no se le pidio al
        // kernel que lo trajera. Sin sonda no hay comprobacion, y sin
        // comprobacion la precondicion no se da por buena.
        if yo < self.config.primero || yo > self.config.ultimo {
            return false;
        }
        let yo = yo as u32;
        // Lo mismo si su tramo no se sondeo. La planificacion lo pone siempre
        // primero, asi que aqui solo se llega con vistas tomadas a mano.
        if !plan.cubre(yo) {
            return false;
        }
        let Some(suyo) = vistas
            .task_list
            .get(&yo)
            .or_else(|| vistas.pid_space.get(&yo))
        else {
            return false;
        };
        // Que el numero ESTE no basta, y creerlo dejaria la comprobacion sin
        // valor justo donde hace falta. En un espacio de nombres de PID anidado
        // los numeros bajos colisionan con tareas reales del espacio inicial
        // —el 2 es `kthreadd`—, asi que encontrar "mi" numero en las vistas del
        // kernel puede ser haber encontrado a OTRO. Se comprueba entonces que
        // la tarea publicada bajo ese numero sea esta misma.
        let mio = views::leer_comm(std::process::id(), yo);
        match (&suyo.comm, &mio) {
            (Some(kernel), Some(propio)) => kernel == propio,
            // Sin nombre por alguno de los dos lados la identidad no se puede
            // afirmar, y una precondicion que no se puede afirmar no se da por
            // buena: el error se inclina hacia «aqui no se pudo comprobar».
            _ => false,
        }
    }

    /// Evalua un conjunto de vistas ya tomado.
    ///
    /// Publico para poder ejercitar el motor con vistas construidas a mano que
    /// reproducen manipulaciones concretas.
    ///
    /// Las vistas se toman por completas: el rango configurado entero,
    /// sondeado.
    pub fn evaluar(&mut self, vistas: &ViewSet) -> Result<ScanReport, KiError> {
        let plan = Plan::completo(self.config.primero, self.config.ultimo);
        self.evaluar_plan(vistas, &plan)
    }

    /// Evalua unas vistas tomadas segun `plan`.
    fn evaluar_plan(&mut self, vistas: &ViewSet, plan: &Plan) -> Result<ScanReport, KiError> {
        let mut informe = ScanReport {
            en_lista: vistas.task_list.len(),
            en_pidmap: vistas.pid_space.len(),
            en_procfs: vistas.procfs.len(),
            desbordes: vistas.desbordes,
            espacios_de_pid_comparables: self.vistas_comparables(vistas, plan),
            pid_sondeados: plan.sondeados,
            pid_sin_sondear: plan.sin_sondear,
            barridos_por_vuelta: plan.barridos_por_vuelta,
            ..Default::default()
        };

        let candidatos = verdict::candidatos(vistas, &self.config.verdict);
        informe.candidatos = candidatos.len();

        let mut vivas: Vec<(u32, AnomalyKind)> = Vec::new();

        // La confirmacion de la vista A vuelve a recorrer /proc por el MISMO
        // canal que la vista original —la lista del directorio, es decir
        // getdents— y no por acceso directo a /proc/<tid>. La diferencia
        // importa: un rootkit de userland engancha getdents, y confirmar por
        // acceso directo consultaria un oraculo que ese rootkit no toca,
        // descartando una deteccion legitima. Se toma una sola instantanea
        // fresca y se comparte entre todas las confirmaciones, para no recorrer
        // /proc entero una vez por candidato.
        let procfs_fresco = if candidatos.is_empty() {
            None
        } else {
            Some(self.releer_procfs())
        };

        for c in &candidatos {
            let (en_lista, en_pidmap, start) = self.kernel.confirmar(c.tid)?;
            let conf = Confirmation {
                en_lista,
                en_pidmap,
                en_procfs: procfs_fresco
                    .as_ref()
                    .map(|v| v.contains_key(&c.tid))
                    .unwrap_or(false),
                // El tercer camino, y el unico que numera igual que `/proc`. Se
                // pregunta solo cuando hace falta —cuando las dos vistas de
                // kernel dicen que no esta—, que es el unico caso en el que su
                // respuesta cambia el veredicto.
                en_vpid: !en_lista && !en_pidmap && views::resuelve_el_kernel(c.tid),
                start_boottime: start,
            };
            let Some(kind) = verdict::juzgar(c, &conf) else {
                if conf.en_procfs && conf.en_vpid {
                    informe.numeracion_distinta += 1;
                } else {
                    informe.descartados_por_carrera += 1;
                }
                continue;
            };

            let clave = (c.tid, kind);
            let racha = self.rachas.entry(clave).or_insert(0);
            *racha += 1;
            let n = *racha;
            vivas.push(clave);

            let a = verdict::anomalia(c, kind, n);
            if n >= self.config.verdict.confirmaciones_requeridas {
                informe.anomalies.push(a);
            } else {
                informe.pendientes.push(a);
            }
        }

        // Las rachas de lo que ya no aparece se olvidan: exigir N
        // confirmaciones CONSECUTIVAS es lo que impide que una carrera
        // repetida a lo largo de horas acabe sumando el umbral.
        // Pero solo se olvida lo que se MIRO: una sospecha cuyo tramo este
        // barrido no sondeo no ha desaparecido, no se ha mirado.
        self.rachas
            .retain(|k, _| vivas.contains(k) || !plan.cubre(k.0));

        informe
            .anomalies
            .sort_by(|a, b| b.severity.cmp(&a.severity).then(a.tid.cmp(&b.tid)));
        Ok(informe)
    }
}

/// Lo de una vista que cae en los tramos de un plan.
fn recortar(v: Vista, plan: &Plan) -> Vista {
    v.into_iter().filter(|(tid, _)| plan.cubre(*tid)).collect()
}

/// El TID del hilo que llama: la sonda de la precondicion.
fn tid_propio() -> i32 {
    // SAFETY: `gettid` no recibe argumentos ni toca memoria del proceso.
    unsafe { libc::gettid() }
}

/// El ultimo PID que asigno el kernel en este espacio de nombres
/// (`/proc/sys/kernel/ns_last_pid`), si se puede leer.
///
/// Solo ordena que tramos se sondean antes ([`crate::tramos::nacidos`]): la
/// cota de la rotacion no depende de el, asi que un valor falso retrasa una
/// deteccion pero no la evita.
fn ultimo_pid_asignado() -> Option<i32> {
    std::fs::read_to_string("/proc/sys/kernel/ns_last_pid")
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
        .filter(|v| *v >= 0)
}

/// Indica si `/proc/<tid>` es accesible por ACCESO DIRECTO.
///
/// NO se usa en la confirmacion —para eso esta la relectura por listado, ver
/// [`KernelIntegrity::evaluar`]—, sino como senal independiente y adicional: un
/// rootkit que engancha `getdents` para desaparecer del listado pero deja
/// `/proc/<tid>/stat` accesible se delata comparando las dos, y esta funcion es
/// el lado del acceso directo de esa comparacion.
pub fn procfs_acceso_directo(tid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{tid}/stat")).exists()
}
