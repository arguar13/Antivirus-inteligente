//! El contexto de una lectura: presupuesto, reloj, raiz del sistema y maquina.
//!
//! # Por que las tablas no leen rutas absolutas a pelo
//!
//! Todas las tablas de este crate leen del sistema de ficheros: `/proc`, `/sys`,
//! `/etc`. Si cada una escribiera `"/etc/passwd"` en el codigo, probar la tabla
//! de usuarios exigiria tener usuarios de prueba en la maquina de integracion,
//! y probar la de PCRs exigiria un TPM. Lo que se hace en su lugar —y lo que ya
//! hacia `aegis-vuln::inventory::collect(root)` desde la FASE 20— es
//! parametrizar la RAIZ.
//!
//! Conviene ser preciso sobre que autoriza eso y que no, porque la regla de la
//! casa prohibe los dobles: parametrizar la raiz sustituye el DISCO, que es una
//! frontera. No sustituye ninguna decision, ningun analizador y ningun
//! veredicto. Las pruebas principales de cada tabla corren contra la raiz REAL
//! de la maquina que ejecuta el CI; la raiz alternativa sirve para ejercer los
//! casos que esa maquina no tiene —un `/etc/sudoers` con una regla peligrosa,
//! un cgroup v1, un fichero que no se puede abrir— sin los cuales la mitad del
//! codigo de honestidad no se probaria nunca.
//!
//! # Por que el tiempo entra como argumento
//!
//! `ahora_ns` se pasa y no se lee del reloj. Es la regla del producto desde la
//! FASE 79 y aqui tiene una consecuencia concreta: los identificadores de
//! entidad que derivan las tablas —el `Eid` de un proceso lleva su instante de
//! arranque— tienen que ser los MISMOS que derivo el sensor cuando vio nacer a
//! ese proceso. Dos relojes leidos en dos momentos dan dos identidades para la
//! misma cosa, y entonces el linaje se parte en dos sin que nadie lo note.
//!
//! El presupuesto es lo unico que mide tiempo transcurrido, y mide DURACION, no
//! instante: `Instant` no es una marca de tiempo, es un cronometro.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use aegis_entidad::Eid;
use aegis_scal::linux::process::ProcFsProcesses;
use aegis_scal::process::{ProcessInfo, ProcessLifecycleProvider};

use crate::tabla::MotivoNoLeible;

/// Presupuesto de tiempo de TODO lo que se lea con un mismo contexto.
///
/// El cronometro arranca al construir el [`Contexto`] y no se reinicia entre
/// tablas, lo cual es deliberado y conviene decirlo claro porque lo natural es
/// suponer lo contrario: una consulta que toca cinco tablas tiene DOS segundos
/// en total, no dos por tabla. El endpoint de un cliente no distingue si el
/// minuto que lleva ocupado se lo come una tabla o veinte.
///
/// Quien necesite un presupuesto por tabla —la puerta de calidad, una
/// recoleccion programada— construye un contexto por tabla, que es barato salvo
/// por el censo de `/proc` que hace el proveedor de procesos.
pub const PRESUPUESTO_POR_DEFECTO: Duration = Duration::from_secs(2);

/// Tope de filas que una tabla devuelve por lectura.
///
/// No es el `LIMIT` de la consulta —ese lo aplica el ejecutor despues de
/// filtrar—, sino la cota de la TABLA: lo que impide que `files` sobre una raiz
/// con diez millones de inodos llene la memoria del agente antes de que el
/// `LIMIT 10` llegue a aplicarse. Una lectura que llega aqui se marca
/// `truncada`, jamas se recorta en silencio.
pub const TOPE_DE_FILAS: usize = 100_000;

/// Todo lo que una tabla necesita saber para leerse.
#[derive(Debug)]
pub struct Contexto {
    raiz: PathBuf,
    maquina: Eid,
    boot: u64,
    ahora_ns: u64,
    presupuesto: Duration,
    reloj: Instant,
    procesos: ProcFsProcesses,
}

impl Contexto {
    /// Contexto contra la maquina real.
    ///
    /// Construye UNA vez el proveedor de procesos, que toma un censo completo
    /// de `/proc` en su constructor. Construir uno por tabla —lo evidente si no
    /// se ha leido `aegis-scal`— costaria un barrido de `/proc` por cada tabla
    /// de la consulta.
    pub fn del_sistema(maquina: Eid, boot: u64, ahora_ns: u64) -> Contexto {
        Contexto {
            raiz: PathBuf::from("/"),
            maquina,
            boot,
            ahora_ns,
            presupuesto: PRESUPUESTO_POR_DEFECTO,
            reloj: Instant::now(),
            procesos: ProcFsProcesses::new(),
        }
    }

    /// Contexto contra otra raiz, para ejercer lo que esta maquina no tiene.
    ///
    /// Ver la cabecera del modulo sobre que sustituye esto y que no.
    pub fn con_raiz(mut self, raiz: impl Into<PathBuf>) -> Contexto {
        self.raiz = raiz.into();
        self
    }

    /// Cambia el presupuesto de tiempo.
    pub fn con_presupuesto(mut self, d: Duration) -> Contexto {
        self.presupuesto = d;
        self
    }

    /// La raiz sobre la que se lee.
    pub fn raiz(&self) -> &Path {
        &self.raiz
    }

    /// Indica si se esta leyendo la maquina real y no un arbol de prueba.
    ///
    /// Lo miran las tablas que dependen de `aegis-scal` —procesos, memoria,
    /// sockets—, porque esas leen `/proc` de verdad y no saben de raices. Sobre
    /// una raiz alternativa declaran el motivo en vez de mentir mezclando los
    /// procesos de la maquina con un arbol de ficheros que no es el suyo.
    pub fn es_el_sistema_real(&self) -> bool {
        self.raiz == Path::new("/")
    }

    /// Ruta absoluta de algo relativo a la raiz.
    ///
    /// Se escribe `ctx.ruta("etc/passwd")`, sin barra inicial: con ella,
    /// `Path::join` descarta la raiz y devuelve `/etc/passwd`, que es
    /// exactamente el fallo que este metodo existe para evitar. La prueba
    /// `la_ruta_absoluta_no_se_escapa_de_la_raiz` lo fija.
    pub fn ruta(&self, relativa: &str) -> PathBuf {
        self.raiz.join(relativa.trim_start_matches('/'))
    }

    /// La maquina, para derivar identidades de entidad.
    pub fn maquina(&self) -> &Eid {
        &self.maquina
    }

    /// El arranque del sistema, que forma parte de la identidad de un proceso.
    pub fn boot(&self) -> u64 {
        self.boot
    }

    /// El instante de la consulta, en nanosegundos.
    pub fn ahora_ns(&self) -> u64 {
        self.ahora_ns
    }

    /// Indica si ya se agoto el presupuesto de esta lectura.
    pub fn agotado(&self) -> bool {
        self.reloj.elapsed() > self.presupuesto
    }

    /// Los procesos vivos, del proveedor construido una sola vez.
    pub fn procesos(&self) -> Result<Vec<ProcessInfo>, MotivoNoLeible> {
        self.procesos.list().map_err(desde_scal)
    }

    /// Un proceso concreto. Es lo que usa el empuje de predicados por `pid`.
    pub fn proceso(&self, pid: u32) -> Result<ProcessInfo, MotivoNoLeible> {
        self.procesos.info(pid).map_err(desde_scal)
    }

    // -----------------------------------------------------------------------
    // Lectura con motivo
    // -----------------------------------------------------------------------

    /// Lee un fichero de texto, traduciendo el error del sistema a un motivo.
    ///
    /// Es el metodo mas usado del crate y por eso merece decir lo que hace: un
    /// `io::Error` no vale como respuesta a un analista —«Os { code: 13 }» no le
    /// dice nada—, asi que aqui se traduce UNA vez, con el contexto de lo que se
    /// estaba haciendo, y ese motivo es el que viaja hasta el panel.
    pub fn leer_texto(&self, relativa: &str) -> Result<String, MotivoNoLeible> {
        let ruta = self.ruta(relativa);
        std::fs::read_to_string(&ruta).map_err(|e| desde_io(e, &ruta, "leer"))
    }

    /// Lee un fichero de texto que puede no existir, sin que su ausencia sea un
    /// fallo de la tabla.
    ///
    /// `/etc/sudoers.d/algo` que no esta no es un problema: es una maquina que
    /// no lo usa. Se distingue de un fichero que esta y no se puede abrir, que
    /// si es un hueco que hay que declarar.
    pub fn leer_texto_opcional(&self, relativa: &str) -> Result<Option<String>, MotivoNoLeible> {
        match self.leer_texto(relativa) {
            Ok(t) => Ok(Some(t)),
            Err(MotivoNoLeible::FuenteAusente { .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Enumera un directorio, traduciendo el error a un motivo.
    ///
    /// Devuelve los nombres ordenados: el orden de `read_dir` lo decide el
    /// sistema de ficheros y no es estable entre lecturas, lo que haria que la
    /// misma consulta sobre el mismo estado diera resultados en distinto orden.
    /// La invariante 6 del megaprompt —determinismo— empieza aqui.
    pub fn listar(&self, relativa: &str) -> Result<Vec<PathBuf>, MotivoNoLeible> {
        let ruta = self.ruta(relativa);
        let entradas = std::fs::read_dir(&ruta).map_err(|e| desde_io(e, &ruta, "enumerar"))?;
        let mut salida: Vec<PathBuf> = entradas.flatten().map(|e| e.path()).collect();
        salida.sort();
        Ok(salida)
    }

    /// Indica si algo existe bajo la raiz.
    pub fn existe(&self, relativa: &str) -> bool {
        self.ruta(relativa).exists()
    }
}

/// Traduce un error de `aegis-scal` a un motivo del analista.
pub(crate) fn desde_scal(e: aegis_scal::ScalError) -> MotivoNoLeible {
    use aegis_scal::ScalError as E;
    match e {
        E::Unsupported { detail, .. } => {
            MotivoNoLeible::NoAplicaEnEstaPlataforma { interfaz: detail }
        }
        E::NoSuchProcess(pid) => MotivoNoLeible::CambioDuranteLaLectura {
            ruta: format!("/proc/{pid}"),
        },
        E::PermissionDenied { op, needs } => MotivoNoLeible::SinPrivilegios {
            operacion: op,
            necesita: needs,
        },
        E::Os { op, source } => MotivoNoLeible::ErrorDelSistema {
            operacion: op,
            detalle: source.to_string(),
        },
        E::BadPath { path, detail } => MotivoNoLeible::ErrorDelSistema {
            operacion: "resolver una ruta",
            detalle: format!("{}: {detail}", path.display()),
        },
        E::MissingTool { tool, purpose } => MotivoNoLeible::ErrorDelSistema {
            operacion: purpose,
            detalle: format!("falta la herramienta {tool}"),
        },
        E::Backend { backend, detail } => MotivoNoLeible::ErrorDelSistema {
            operacion: "hablar con el backend del sistema",
            detalle: format!("{backend}: {detail}"),
        },
        E::ToolFailed { tool, code, stderr } => MotivoNoLeible::ErrorDelSistema {
            operacion: "ejecutar una herramienta del sistema",
            detalle: format!("{tool} salio con {code}: {stderr}"),
        },
    }
}

/// Traduce un error de entrada/salida a un motivo del analista.
pub(crate) fn desde_io(e: std::io::Error, ruta: &Path, operacion: &'static str) -> MotivoNoLeible {
    use std::io::ErrorKind as K;
    match e.kind() {
        K::NotFound => MotivoNoLeible::FuenteAusente {
            ruta: ruta.display().to_string(),
        },
        K::PermissionDenied => MotivoNoLeible::SinPrivilegios {
            operacion,
            // Se dice lo que de verdad hace falta y no un "ser root" generico:
            // muchas de estas lecturas las permite una capacidad concreta, y un
            // agente bien desplegado no corre como root.
            necesita: "CAP_DAC_READ_SEARCH o ser el dueno",
        },
        // ESRCH llega como Uncategorized en muchos nucleos: un proceso que
        // murio entre enumerarlo y leerlo. No es un fallo, es una maquina viva.
        _ if e.raw_os_error() == Some(3) => MotivoNoLeible::CambioDuranteLaLectura {
            ruta: ruta.display().to_string(),
        },
        _ => MotivoNoLeible::ErrorDelSistema {
            operacion,
            detalle: e.to_string(),
        },
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn ctx() -> Contexto {
        Contexto::del_sistema(aegis_entidad::entidad::maquina("prueba"), 0, 0)
    }

    #[test]
    fn la_ruta_absoluta_no_se_escapa_de_la_raiz() {
        // `Path::join("/etc/passwd")` DESCARTA la raiz y devuelve "/etc/passwd".
        // Si `ruta()` no quitara la barra inicial, una tabla probada contra un
        // arbol de prueba leeria la maquina real sin que nadie lo notase: la
        // prueba pasaria leyendo otra cosa.
        let c = ctx().con_raiz("/tmp/raiz-de-prueba");
        assert_eq!(
            c.ruta("/etc/passwd"),
            PathBuf::from("/tmp/raiz-de-prueba/etc/passwd")
        );
        assert_eq!(
            c.ruta("etc/passwd"),
            PathBuf::from("/tmp/raiz-de-prueba/etc/passwd")
        );
    }

    #[test]
    fn se_distingue_la_maquina_real_de_un_arbol_de_prueba() {
        assert!(ctx().es_el_sistema_real());
        assert!(!ctx().con_raiz("/tmp/x").es_el_sistema_real());
    }

    #[test]
    fn un_fichero_que_no_esta_da_fuente_ausente_y_no_un_error_del_sistema() {
        // La distincion importa: "no existe" es informacion sobre la maquina,
        // "fallo al leer" es informacion sobre el agente.
        let c = ctx().con_raiz("/tmp/no-existe-esta-raiz-jamas");
        match c.leer_texto("etc/passwd") {
            Err(MotivoNoLeible::FuenteAusente { .. }) => {}
            otro => panic!("se esperaba FuenteAusente, salio {otro:?}"),
        }
    }

    #[test]
    fn lo_opcional_que_no_esta_no_es_un_fallo() {
        let c = ctx().con_raiz("/tmp/no-existe-esta-raiz-jamas");
        assert_eq!(c.leer_texto_opcional("etc/sudoers").unwrap(), None);
    }

    #[test]
    fn en_esta_maquina_se_lee_proc_y_hay_procesos() {
        // Contra el sistema REAL, que es como se prueba este crate.
        let c = ctx();
        let texto = c.leer_texto("proc/self/status").expect("/proc/self/status");
        assert!(texto.contains("Pid:"), "no parece /proc/self/status");
        let ps = c.procesos().expect("enumerar procesos");
        assert!(ps.len() > 1, "una maquina viva tiene mas de un proceso");
    }

    #[test]
    fn el_listado_de_un_directorio_es_estable() {
        // Dos lecturas seguidas del mismo directorio dan el mismo orden. Sin
        // esto, la misma consulta sobre el mismo estado daria dos respuestas
        // distintas, que es lo que la invariante de determinismo prohibe.
        let c = ctx();
        let a = c.listar("proc/self").expect("listar /proc/self");
        let b = c.listar("proc/self").expect("listar /proc/self");
        assert_eq!(a, b);
        assert!(a.windows(2).all(|p| p[0] <= p[1]), "no esta ordenado");
    }

    #[test]
    fn el_presupuesto_se_puede_agotar() {
        let c = ctx().con_presupuesto(Duration::from_nanos(1));
        std::thread::sleep(Duration::from_millis(2));
        assert!(c.agotado());
    }

    #[test]
    fn un_presupuesto_normal_no_esta_agotado_al_empezar() {
        assert!(!ctx().agotado());
    }

    #[test]
    fn el_proceso_propio_se_encuentra_por_su_pid() {
        // El empuje de predicados depende de esto: `WHERE pid = N` tiene que
        // poder pedir UN proceso sin enumerar /proc entero.
        let c = ctx();
        let yo = std::process::id();
        let info = c.proceso(yo).expect("mi propio proceso existe");
        assert_eq!(info.key.pid, yo);
    }

    #[test]
    fn un_pid_que_no_existe_da_un_motivo_y_no_un_panico() {
        let c = ctx();
        // 0 no es un pid valido de proceso de usuario en Linux.
        match c.proceso(0) {
            Err(m) => assert!(!m.frase().is_empty()),
            Ok(_) => panic!("el pid 0 no deberia resolverse a un proceso"),
        }
    }
}
