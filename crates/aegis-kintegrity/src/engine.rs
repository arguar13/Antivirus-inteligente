//! El motor: orquesta barrido, confirmacion y persistencia.

use std::collections::HashMap;

use crate::error::KiError;
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
    /// Toma las dos vistas de kernel en una sola invocacion.
    ///
    /// Devuelve `(lista de tareas, espacio de PID, desbordes)`.
    fn barrer(&mut self, primero: i32, ultimo: i32) -> Result<(Vista, Vista, u32), KiError>;

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
    /// Por defecto se lee de `/proc/sys/kernel/pid_max`: barrer por encima
    /// gasta iteraciones en un rango que el kernel no puede asignar, y barrer
    /// por debajo deja un hueco donde esconderse.
    pub ultimo: i32,
    /// Reglas de comparacion.
    pub verdict: VerdictConfig,
}

impl Default for KiConfig {
    fn default() -> Self {
        Self {
            primero: 1,
            ultimo: pid_max(),
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
    pub fn concluye_limpio(&self) -> bool {
        self.anomalies.is_empty()
            && self.pendientes.is_empty()
            && self.espacios_de_pid_comparables
            && self.desbordes == 0
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
        // El orden importa: primero las dos vistas de kernel, que van juntas en
        // una invocacion, y `/proc` inmediatamente despues. Al reves, la vista
        // de usuario seria la mas vieja de las tres y toda tarea nacida en el
        // intervalo pareceria oculta en userland.
        let (task_list, pid_space, desbordes) = self
            .kernel
            .barrer(self.config.primero, self.config.ultimo)?;
        let procfs = views::leer_procfs();

        let vistas = ViewSet {
            procfs,
            task_list,
            pid_space,
            desbordes,
        };
        self.evaluar(&vistas)
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
    fn vistas_comparables(&self, vistas: &ViewSet) -> bool {
        // SAFETY: `gettid` no recibe argumentos ni toca memoria del proceso.
        let yo = unsafe { libc::gettid() };
        // Fuera del rango barrido su ausencia no prueba nada: no se le pidio al
        // kernel que lo trajera. Sin sonda no hay comprobacion, y sin
        // comprobacion la precondicion no se da por buena.
        if yo < self.config.primero || yo > self.config.ultimo {
            return false;
        }
        let yo = yo as u32;
        vistas.task_list.contains_key(&yo) || vistas.pid_space.contains_key(&yo)
    }

    /// Evalua un conjunto de vistas ya tomado.
    ///
    /// Publico para poder ejercitar el motor con vistas construidas a mano que
    /// reproducen manipulaciones concretas.
    pub fn evaluar(&mut self, vistas: &ViewSet) -> Result<ScanReport, KiError> {
        let mut informe = ScanReport {
            en_lista: vistas.task_list.len(),
            en_pidmap: vistas.pid_space.len(),
            en_procfs: vistas.procfs.len(),
            desbordes: vistas.desbordes,
            espacios_de_pid_comparables: self.vistas_comparables(vistas),
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
        self.rachas.retain(|k, _| vivas.contains(k));

        informe
            .anomalies
            .sort_by(|a, b| b.severity.cmp(&a.severity).then(a.tid.cmp(&b.tid)));
        Ok(informe)
    }
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
