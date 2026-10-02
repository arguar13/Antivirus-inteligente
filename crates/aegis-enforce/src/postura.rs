//! La postura de aplicacion de esta maquina, medida contra el sistema real.
//!
//! # Disponible no es aplicado
//!
//! Que el kernel ADMITA un mecanismo no dice que el producto lo este usando. Un
//! kernel con seccomp y Landlock y un agente que no confina nada con ellos es
//! una maquina que solo observa, y describirla como «aplicando» es el informe
//! tranquilizador que este crate existe para impedir. La primera version de este
//! modulo cometia justo ese error (hallazgo H-28): daba la capa por impuesta en
//! cuanto el kernel la ofrecia.
//!
//! Por eso hay dos estados distintos, y el segundo no se deduce del primero:
//!
//! - [`Estado::Disponible`]: el kernel lo ofrece. Se sabe preguntando al kernel.
//! - [`Estado::Aplica`]: hay una [`Evidencia`] medida en tiempo de ejecucion
//!   sobre un proceso concreto del producto (un [`Testigo`]): un filtro seccomp
//!   propio que se ve en `/proc/<pid>/status`, un dominio Landlock que el proceso
//!   declara tras `landlock_restrict_self` y que se corrobora desde fuera, o un
//!   enlace BPF LSM que el proceso sostiene y se ve en `/proc/<pid>/fdinfo`.
//!
//! Una [`Evidencia`] solo la construye este modulo, al medir: fuera de el no hay
//! forma de fabricarla, y por tanto tampoco de escribir un `Estado::Aplica` a
//! mano en ningun otro crate.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use aegis_scal::platform::Platform;

/// Un mecanismo por el que el producto puede imponer algo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capacidad {
    /// Filtros de llamadas al sistema (Linux).
    Seccomp,
    /// Restriccion de acceso a ficheros por ruta (Linux).
    Landlock,
    /// Ganchos LSM programables, que pueden **negar** una operacion (Linux).
    BpfLsm,
    /// Filtrado de paquetes en el camino de recepcion (Linux).
    Xdp,
    /// Minifiltro del sistema de ficheros (Windows).
    Minifiltro,
    /// Callbacks de objeto para la auto-defensa (Windows).
    ObCallbacks,
    /// Endpoint Security (macOS).
    EndpointSecurity,
}

impl Capacidad {
    /// Nombre legible.
    pub fn nombre(&self) -> &'static str {
        match self {
            Capacidad::Seccomp => "seccomp",
            Capacidad::Landlock => "Landlock",
            Capacidad::BpfLsm => "BPF LSM",
            Capacidad::Xdp => "XDP",
            Capacidad::Minifiltro => "minifiltro",
            Capacidad::ObCallbacks => "ObCallbacks",
            Capacidad::EndpointSecurity => "Endpoint Security",
        }
    }

    /// En que plataforma tiene sentido.
    pub fn plataforma(&self) -> Platform {
        match self {
            Capacidad::Seccomp | Capacidad::Landlock | Capacidad::BpfLsm | Capacidad::Xdp => {
                Platform::Linux
            }
            Capacidad::Minifiltro | Capacidad::ObCallbacks => Platform::Windows,
            Capacidad::EndpointSecurity => Platform::MacOs,
        }
    }
}

/// Lo que se midio para poder decir que una capacidad se esta aplicando.
///
/// No tiene constructor publico: solo la crea [`Postura::medida_con`] al leer el
/// sistema. Es lo que impide que `Estado::Aplica` se escriba a mano.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidencia {
    fuente: Fuente,
}

/// De donde sale una evidencia. Privado a proposito: ver [`Evidencia`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum Fuente {
    /// `Seccomp: 2` en el status del testigo, con filtros que no heredo.
    FiltroSeccomp {
        pid: u32,
        /// Filtros propios (los del testigo menos los de su padre), si el
        /// kernel publica `Seccomp_filters`; `None` si el padre no tiene ninguno
        /// y el kernel no dice cuantos hay.
        propios: Option<u32>,
    },
    /// Dominio Landlock declarado por el proceso y corroborado desde fuera.
    DominioLandlock { pid: u32, abi: u32 },
    /// Enlace BPF LSM visible en el fdinfo de un descriptor del proceso.
    EnlaceBpfLsm {
        pid: u32,
        fd: u32,
        prog_id: Option<u32>,
    },
}

impl Evidencia {
    /// El proceso (o hilo) sobre el que se midio.
    pub fn pid(&self) -> u32 {
        match self.fuente {
            Fuente::FiltroSeccomp { pid, .. }
            | Fuente::DominioLandlock { pid, .. }
            | Fuente::EnlaceBpfLsm { pid, .. } => pid,
        }
    }
}

impl fmt::Display for Evidencia {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.fuente {
            Fuente::FiltroSeccomp {
                pid,
                propios: Some(n),
            } => write!(
                f,
                "filtro seccomp en /proc/{pid}/status: modo 2, {n} filtro(s) propios \
                 (descontados los heredados del padre)"
            ),
            Fuente::FiltroSeccomp { pid, propios: None } => write!(
                f,
                "filtro seccomp en /proc/{pid}/status: modo 2, y su padre no tiene ninguno"
            ),
            Fuente::DominioLandlock { pid, abi } => write!(
                f,
                "dominio Landlock (ABI {abi}) que el proceso {pid} declara tras \
                 landlock_restrict_self, corroborado desde fuera (vivo, NoNewPrivs 1); el \
                 kernel no publica el dominio fuera del proceso"
            ),
            Fuente::EnlaceBpfLsm { pid, fd, prog_id } => {
                write!(
                    f,
                    "enlace BPF LSM sostenido por el proceso {pid} en su descriptor {fd}"
                )?;
                if let Some(id) = prog_id {
                    write!(f, " (prog_id {id})")?;
                }
                write!(f, ", leido de /proc/{pid}/fdinfo/{fd}")
            }
        }
    }
}

/// Un proceso del producto en el que buscar evidencia de aplicacion.
///
/// Nombrar un testigo NO es evidencia: es decir donde mirar. Lo que cuenta es lo
/// que el kernel dice de ese proceso en el momento de medir.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Testigo {
    /// El pid del proceso, o el tid de un hilo concreto: `/proc/<tid>/status`
    /// describe ese hilo, y seccomp y Landlock se ponen por hilo.
    pub pid: u32,
    /// La ABI de Landlock que el propio proceso declara haber puesto con
    /// `landlock_restrict_self` (el trabajador confinado la cuenta en su saludo:
    /// `landlock=si (N)`). El kernel no publica el dominio fuera del proceso, asi
    /// que es lo unico que hay; se corrobora con lo que si se ve desde fuera.
    pub landlock_declarado: Option<u32>,
}

impl Testigo {
    /// Un proceso sin nada declarado.
    pub fn proceso(pid: u32) -> Testigo {
        Testigo {
            pid,
            landlock_declarado: None,
        }
    }

    /// El mismo testigo, declarando el dominio Landlock que se puso.
    #[must_use]
    pub fn con_landlock(mut self, abi: u32) -> Testigo {
        self.landlock_declarado = Some(abi);
        self
    }
}

impl FromStr for Testigo {
    type Err = String;

    /// `PID` o `PID:landlock=ABI`.
    fn from_str(s: &str) -> Result<Testigo, String> {
        let (pid, resto) = match s.split_once(':') {
            Some((p, r)) => (p, Some(r)),
            None => (s, None),
        };
        let pid: u32 = pid
            .trim()
            .parse()
            .map_err(|_| format!("pid invalido: «{pid}»"))?;
        let mut t = Testigo::proceso(pid);
        if let Some(r) = resto {
            let abi = r
                .strip_prefix("landlock=")
                .and_then(|a| a.trim().parse::<u32>().ok())
                .ok_or_else(|| format!("se esperaba landlock=ABI: «{r}»"))?;
            t = t.con_landlock(abi);
        }
        Ok(t)
    }
}

/// En que situacion esta una capacidad en esta maquina.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Estado {
    /// Se esta aplicando, y hay con que demostrarlo.
    ///
    /// Solo sale de una [`Evidencia`] medida sobre un [`Testigo`]. Que el kernel
    /// lo ofrezca no basta: eso es [`Estado::Disponible`].
    Aplica {
        /// Lo que se midio.
        evidencia: Evidencia,
    },
    /// El kernel lo ofrece, y nada medido demuestra que el producto lo use.
    ///
    /// Existe como estado propio por el mismo motivo que `SoloObserva`: contarlo
    /// como aplicacion describe como protegida una maquina que no lo esta.
    Disponible {
        /// Que ofrece el kernel y por que no cuenta como aplicado.
        motivo: String,
    },
    /// Ve la operacion y **no** puede negarla.
    ///
    /// Es telemetria. Existe como estado propio porque contarla como aplicacion
    /// es lo que produce el informe tranquilizador de una maquina desprotegida.
    SoloObserva {
        /// Por que no puede negar.
        motivo: String,
    },
    /// No esta disponible aqui.
    Ausente {
        /// Por que.
        motivo: String,
    },
    /// No aplica en esta plataforma.
    ///
    /// Distinto de ausente: que en Linux no haya minifiltro no es una carencia
    /// de la maquina, y mezclarlos llenaria de falsas alarmas el informe de cada
    /// endpoint de la flota.
    OtraPlataforma,
}

impl Estado {
    /// Si de verdad se esta negando algo con ella, con evidencia.
    pub fn aplica(&self) -> bool {
        matches!(self, Estado::Aplica { .. })
    }

    /// Si el kernel la ofrece (se este usando o no).
    pub fn disponible(&self) -> bool {
        matches!(self, Estado::Aplica { .. } | Estado::Disponible { .. })
    }

    /// Etiqueta estable, para informes y scripts.
    pub fn etiqueta(&self) -> &'static str {
        match self {
            Estado::Aplica { .. } => "APLICA",
            Estado::Disponible { .. } => "DISPONIBLE",
            Estado::SoloObserva { .. } => "SOLO-OBSERVA",
            Estado::Ausente { .. } => "AUSENTE",
            Estado::OtraPlataforma => "OTRA-PLATAFORMA",
        }
    }

    /// La evidencia o el motivo, en una linea.
    pub fn detalle(&self) -> String {
        match self {
            Estado::Aplica { evidencia } => evidencia.to_string(),
            Estado::Disponible { motivo }
            | Estado::SoloObserva { motivo }
            | Estado::Ausente { motivo } => motivo.clone(),
            Estado::OtraPlataforma => "no es de esta plataforma".into(),
        }
    }
}

/// Lo que una politica exige del endpoint donde se despliega.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exigencia {
    /// Basta con ver y alertar.
    Observar,
    /// Hace falta poder impedirlo.
    Aplicar,
}

/// Lo que esta maquina impone, medido.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Postura {
    /// Plataforma sobre la que se midio.
    pub plataforma: Platform,
    /// El estado de cada capacidad.
    pub capacidades: BTreeMap<Capacidad, Estado>,
}

impl Postura {
    /// Sondea esta maquina sin ningun testigo.
    ///
    /// Sin testigos no hay evidencia, asi que ninguna capacidad puede salir
    /// aplicando: lo mejor que se puede decir es que esta disponible. Es la
    /// respuesta correcta para una maquina donde el producto no ha confinado
    /// nada que se pueda medir.
    pub fn medida() -> Postura {
        Postura::medida_con(&[])
    }

    /// Sondea esta maquina y busca evidencia de aplicacion en los testigos.
    ///
    /// No lee configuracion: pregunta al sistema. Lo que diga un fichero sobre
    /// lo que el producto «tiene activado» no dice nada de lo que este kernel
    /// acepta, ni de lo que de verdad se ha puesto sobre un proceso.
    pub fn medida_con(testigos: &[Testigo]) -> Postura {
        let mut capacidades = BTreeMap::new();
        let plataforma = plataforma_actual();
        let lecturas: Vec<Lectura> = testigos.iter().map(|t| Lectura::de(*t)).collect();

        for c in [
            Capacidad::Seccomp,
            Capacidad::Landlock,
            Capacidad::BpfLsm,
            Capacidad::Xdp,
            Capacidad::Minifiltro,
            Capacidad::ObCallbacks,
            Capacidad::EndpointSecurity,
        ] {
            let estado = if c.plataforma() != plataforma {
                Estado::OtraPlataforma
            } else {
                sondear(c, &lecturas)
            };
            capacidades.insert(c, estado);
        }

        Postura {
            plataforma,
            capacidades,
        }
    }

    /// Si esta maquina esta impidiendo algo, por algun camino, con evidencia.
    pub fn puede_aplicar_algo(&self) -> bool {
        self.capacidades.values().any(|e| e.aplica())
    }

    /// Si una politica con esta exigencia se puede cumplir aqui.
    ///
    /// Con [`Exigencia::Aplicar`] hace falta al menos un mecanismo que niegue de
    /// verdad, medido. **Falla cerrado**: una politica que dice «esto no se
    /// ejecuta» y se despliega sobre una maquina que no lo esta impidiendo tiene
    /// que rechazarse en el despliegue, no descubrirse en el incidente. Que el
    /// kernel ofrezca el mecanismo no basta.
    pub fn puede_cumplir(&self, exigencia: Exigencia) -> bool {
        match exigencia {
            Exigencia::Observar => true,
            Exigencia::Aplicar => self.puede_aplicar_algo(),
        }
    }

    /// Las capacidades que aplican de verdad, con evidencia.
    pub fn aplicando(&self) -> Vec<Capacidad> {
        self.capacidades
            .iter()
            .filter(|(_, e)| e.aplica())
            .map(|(c, _)| *c)
            .collect()
    }

    /// Las que el kernel ofrece y nada medido demuestra que se usen.
    pub fn disponibles(&self) -> Vec<Capacidad> {
        self.capacidades
            .iter()
            .filter(|(_, e)| matches!(e, Estado::Disponible { .. }))
            .map(|(c, _)| *c)
            .collect()
    }

    /// Lo que no se esta imponiendo, con su motivo, para el informe.
    ///
    /// Incluye lo disponible sin usar: que el kernel lo ofrezca y nadie lo
    /// ponga es, para quien lee el informe, algo que no protege. No lista lo de
    /// otras plataformas: que en Linux no haya minifiltro no es una carencia, y
    /// meterlo aqui llenaria de ruido el informe de cada endpoint hasta que
    /// nadie lo leyera.
    pub fn lo_que_no_se_puede_imponer(&self) -> Vec<String> {
        self.capacidades
            .iter()
            .filter_map(|(c, e)| match e {
                Estado::Aplica { .. } | Estado::OtraPlataforma => None,
                Estado::Disponible { motivo } => Some(format!(
                    "{}: el kernel lo ofrece y nada medido lo esta usando ({motivo})",
                    c.nombre()
                )),
                Estado::SoloObserva { motivo } => Some(format!(
                    "{}: ve la operacion pero no puede negarla ({motivo})",
                    c.nombre()
                )),
                Estado::Ausente { motivo } => {
                    Some(format!("{}: no esta disponible ({motivo})", c.nombre()))
                }
            })
            .collect()
    }

    /// La frase con la que el agente debe describirse.
    ///
    /// Es la unica salida que se permite al panel, y por eso esta aqui y no en
    /// la interfaz: «protegido» es una palabra que hay que ganarse, y quien la
    /// escribe no puede ser quien la muestra.
    pub fn como_describirse(&self) -> &'static str {
        if self.puede_aplicar_algo() {
            "aplicando: hay evidencia medida de que este agente impide operaciones en \
             esta maquina"
        } else {
            "SOLO OBSERVANDO: este agente ve y alerta, y nada medido demuestra que \
             impida algo en esta maquina"
        }
    }
}

/// La plataforma sobre la que corre esto.
fn plataforma_actual() -> Platform {
    if cfg!(target_os = "linux") {
        Platform::Linux
    } else if cfg!(target_os = "windows") {
        Platform::Windows
    } else if cfg!(target_os = "macos") {
        Platform::MacOs
    } else {
        Platform::Linux
    }
}

// ── Lo que se lee de /proc ──────────────────────────────────────────────────

/// Los campos de `/proc/<pid>/status` que importan aqui.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Status {
    /// `Seccomp:`: 0 sin filtro, 1 estricto, 2 con filtro.
    seccomp: Option<u32>,
    /// `Seccomp_filters:` (Linux 5.9 en adelante): filtros apilados.
    filtros: Option<u32>,
    /// `PPid:`.
    ppid: Option<u32>,
    /// `NoNewPrivs:`.
    no_new_privs: Option<bool>,
}

/// El valor de un campo `nombre:<espacios>valor` de un fichero de /proc.
///
/// Exige los dos puntos justo detras del nombre: asi `Seccomp` no se confunde
/// con `Seccomp_filters`, ni `prog_id` con `prog_tag`.
fn campo<'a>(texto: &'a str, nombre: &str) -> Option<&'a str> {
    texto
        .lines()
        .find_map(|l| l.strip_prefix(nombre)?.strip_prefix(':'))
        .map(str::trim)
}

/// Puro: lee los campos del texto de `/proc/<pid>/status`.
fn parsear_status(texto: &str) -> Status {
    let num = |n: &str| campo(texto, n).and_then(|v| v.parse::<u32>().ok());
    Status {
        seccomp: num("Seccomp"),
        filtros: num("Seccomp_filters"),
        ppid: num("PPid"),
        no_new_privs: num("NoNewPrivs").map(|v| v == 1),
    }
}

/// Puro: el `State:` de `/proc/<pid>/status` si dice que el proceso ya no vive.
///
/// Un proceso muerto que su padre aun no ha recogido (zombi, `Z`) conserva su
/// `/proc/<pid>/status`, y en el siguen `Seccomp: 2` y `NoNewPrivs: 1`: sin esta
/// comprobacion, un trabajador confinado que acaba de morir seguiria contando
/// como evidencia de algo que ya no impone nada. `X` (muerto) casi nunca llega
/// a verse, pero tampoco vive. Sin campo `State` no se presume nada.
fn sin_vida(texto: &str) -> Option<&str> {
    campo(texto, "State").filter(|s| s.starts_with('Z') || s.starts_with('X'))
}

fn leer_status(pid: u32) -> Result<Status, String> {
    let ruta = format!("/proc/{pid}/status");
    let texto = std::fs::read_to_string(&ruta).map_err(|e| format!("{ruta}: {e}"))?;
    if let Some(estado) = sin_vida(&texto) {
        return Err(format!(
            "el proceso {pid} ya no vive ({estado}): lo que queda de el en {ruta} no \
             impone nada"
        ));
    }
    Ok(parsear_status(&texto))
}

/// Lo leido de un testigo, una sola vez por medida.
struct Lectura {
    testigo: Testigo,
    propio: Result<Status, String>,
    /// El status del padre, para descontar lo heredado.
    padre: Option<Status>,
}

impl Lectura {
    fn de(testigo: Testigo) -> Lectura {
        let propio = leer_status(testigo.pid);
        let padre = propio
            .as_ref()
            .ok()
            .and_then(|s| s.ppid)
            .and_then(|pp| leer_status(pp).ok());
        Lectura {
            testigo,
            propio,
            padre,
        }
    }
}

// ── Decidir ─────────────────────────────────────────────────────────────────

/// Puro: el estado de una capacidad a partir de si el kernel la ofrece y de lo
/// medido en cada testigo.
///
/// Es el unico sitio de donde sale `Estado::Aplica`, y solo sale de un
/// `Ok(Evidencia)`. Sin testigos, o si ninguno la tiene puesta, la capacidad
/// queda disponible y el motivo dice por que.
fn decidir(
    ausente: Option<String>,
    ofrece: &str,
    intentos: Vec<Result<Evidencia, String>>,
) -> Estado {
    if let Some(motivo) = ausente {
        return Estado::Ausente { motivo };
    }
    let mut fallos = Vec::new();
    for i in intentos {
        match i {
            Ok(evidencia) => return Estado::Aplica { evidencia },
            Err(m) => fallos.push(m),
        }
    }
    let motivo = if fallos.is_empty() {
        format!("{ofrece}; ningun proceso del producto se ha medido con ella puesta")
    } else {
        format!(
            "{ofrece}; en los procesos medidos no esta puesta: {}",
            fallos.join("; ")
        )
    };
    Estado::Disponible { motivo }
}

/// Sondea una capacidad contra el sistema de verdad.
fn sondear(c: Capacidad, lecturas: &[Lectura]) -> Estado {
    match c {
        Capacidad::Seccomp | Capacidad::Landlock => sondear_aislamiento(c, lecturas),
        Capacidad::BpfLsm => sondear_bpf_lsm(lecturas),
        Capacidad::Xdp => Estado::Ausente {
            motivo: "el enganche XDP se mide por interfaz al programarlo, no aqui".into(),
        },
        // En Linux nunca se llega: `Postura::medida_con` ya devolvio OtraPlataforma.
        Capacidad::Minifiltro | Capacidad::ObCallbacks => Estado::Ausente {
            motivo: "hace falta el driver cargado y firmado".into(),
        },
        Capacidad::EndpointSecurity => Estado::Ausente {
            motivo: "hace falta el permiso concedido por el usuario y el entitlement de Apple"
                .into(),
        },
    }
}

/// seccomp y Landlock: la disponibilidad la dice `aegis-sandbox`; la
/// aplicacion, los testigos.
fn sondear_aislamiento(c: Capacidad, lecturas: &[Lectura]) -> Estado {
    let s = aegis_sandbox::Support::detect();
    match c {
        Capacidad::Seccomp => {
            let ausente = if s.seccomp {
                None
            } else {
                Some("el kernel no admite filtros de seccomp".to_string())
            };
            let intentos = lecturas
                .iter()
                .map(|l| -> Result<Evidencia, String> {
                    let propio = l.propio.as_ref().map_err(Clone::clone)?;
                    evidencia_seccomp(l.testigo.pid, propio, l.padre.as_ref())
                })
                .collect();
            decidir(ausente, "el kernel admite filtros de seccomp", intentos)
        }
        Capacidad::Landlock => {
            let abi = s.landlock_abi.filter(|a| *a >= 1);
            let ausente = match abi {
                Some(_) => None,
                None => Some("el kernel no trae Landlock o no esta habilitado".to_string()),
            };
            let intentos = lecturas
                .iter()
                .map(|l| -> Result<Evidencia, String> {
                    let propio = l.propio.as_ref().map_err(Clone::clone)?;
                    evidencia_landlock(l.testigo.pid, propio, l.testigo.landlock_declarado, abi)
                })
                .collect();
            decidir(
                ausente,
                &format!("el kernel ofrece Landlock (ABI {})", abi.unwrap_or(0)),
                intentos,
            )
        }
        _ => unreachable!("solo se llama con seccomp o Landlock"),
    }
}

/// Puro: si el status de un testigo prueba un filtro seccomp PUESTO POR EL
/// PRODUCTO.
///
/// Un filtro heredado no cuenta: si el agente corre dentro de un contenedor con
/// el perfil seccomp de Docker, o bajo un servicio de systemd con
/// `SystemCallFilter=`, todos sus hijos tienen `Seccomp: 2` sin que el producto
/// haya puesto nada. Por eso se descuentan los filtros del padre.
fn evidencia_seccomp(
    pid: u32,
    propio: &Status,
    padre: Option<&Status>,
) -> Result<Evidencia, String> {
    match propio.seccomp {
        Some(2) => {}
        Some(m) => {
            return Err(format!(
                "el proceso {pid} no tiene filtro seccomp (modo {m})"
            ))
        }
        None => return Err(format!("/proc/{pid}/status no publica el campo Seccomp")),
    }
    let Some(padre) = padre else {
        return Err(format!(
            "no se puede leer el padre de {pid}: sin el no se sabe si el filtro es propio \
             o heredado"
        ));
    };
    let propios = match (padre.seccomp, propio.filtros, padre.filtros) {
        (Some(0), n, _) => n,
        (Some(_), Some(t), Some(p)) if t > p => Some(t - p),
        (Some(_), Some(_), Some(_)) => {
            return Err(format!(
                "todos los filtros de {pid} los heredo de su padre: no los puso el producto"
            ))
        }
        _ => {
            return Err(format!(
                "el padre de {pid} tambien tiene filtro y el kernel no publica \
                 Seccomp_filters: no se puede separar lo propio de lo heredado"
            ))
        }
    };
    Ok(Evidencia {
        fuente: Fuente::FiltroSeccomp { pid, propios },
    })
}

/// Puro: si lo que declara un testigo sobre Landlock cuadra con lo que se ve.
///
/// El kernel no publica fuera del proceso si tiene un dominio Landlock, asi que
/// la declaracion del propio proceso es lo unico que hay. Se corrobora con lo
/// que SI se ve: que el proceso vive, que tiene `NoNewPrivs` (sin el,
/// `landlock_restrict_self` falla para un proceso sin privilegios, y el
/// producto siempre lo pone antes) y que la ABI declarada existe en este kernel.
fn evidencia_landlock(
    pid: u32,
    propio: &Status,
    declarado: Option<u32>,
    abi_kernel: Option<u32>,
) -> Result<Evidencia, String> {
    let Some(abi) = declarado else {
        return Err(format!(
            "el proceso {pid} no declara ningun dominio Landlock"
        ));
    };
    let Some(k) = abi_kernel else {
        return Err("el kernel no ofrece Landlock".into());
    };
    if abi == 0 || abi > k {
        return Err(format!(
            "el proceso {pid} declara la ABI {abi} y el kernel ofrece hasta la {k}: no cuadra"
        ));
    }
    if propio.no_new_privs != Some(true) {
        return Err(format!(
            "el proceso {pid} no tiene NoNewPrivs: el dominio que declara no lo puso el \
             producto como lo pone"
        ));
    }
    Ok(Evidencia {
        fuente: Fuente::DominioLandlock { pid, abi },
    })
}

/// BPF LSM: el unico que puede NEGAR desde un programa eBPF.
///
/// Los ganchos de traza —kprobes, tracepoints— ven pasar la operacion y no
/// pueden pararla. Confundirlos es exactamente el error que este crate existe
/// para impedir: un producto que dice bloquear con kprobes esta alertando.
fn sondear_bpf_lsm(lecturas: &[Lectura]) -> Estado {
    // La LECTURA vive aqui; la DECISION vive en `clasificar_lsm`, que es pura y
    // comprobable sin depender de que securityfs este montado.
    let lista = std::fs::read_to_string("/sys/kernel/security/lsm").ok();
    let intentos = lecturas
        .iter()
        .map(|l| buscar_enlace_bpf_lsm(l.testigo.pid))
        .collect();
    clasificar_lsm(lista.as_deref(), intentos)
}

/// Clasifica BPF LSM a partir de la lista de LSM activos del kernel y de lo
/// medido en los testigos.
///
/// Puro, sin E/S: por eso se puede probar de forma determinista con la entrada
/// inyectada. `None` es «no se pudo leer»: securityfs sin montar, o el kernel
/// sin el framework LSM. Que `bpf` este en la lista dice que el kernel ADMITE
/// programas BPF LSM, no que haya uno enganchado: eso solo lo dice un enlace
/// medido.
fn clasificar_lsm(lista: Option<&str>, intentos: Vec<Result<Evidencia, String>>) -> Estado {
    let Some(lista) = lista else {
        return Estado::Ausente {
            motivo: "no se puede leer /sys/kernel/security/lsm (securityfs sin montar o el \
                     kernel sin el framework LSM): no se puede afirmar que niegue"
                .into(),
        };
    };
    if !lista.split(',').any(|l| l.trim() == "bpf") {
        return Estado::SoloObserva {
            motivo: format!(
                "el kernel trae LSM ({}) pero «bpf» no esta en la lista: se puede \
                 observar con kprobes y no se puede negar",
                lista.trim()
            ),
        };
    }
    decidir(
        None,
        "«bpf» esta en la lista de LSM activos: el kernel admite programas BPF LSM",
        intentos,
    )
}

/// Tope de descriptores que se miran por testigo: un proceso con decenas de
/// miles de descriptores no puede convertir la medida en un barrido sin fin.
const MAX_DESCRIPTORES: usize = 4096;

/// Busca en los descriptores de un testigo un enlace BPF LSM vivo.
fn buscar_enlace_bpf_lsm(pid: u32) -> Result<Evidencia, String> {
    let dir = format!("/proc/{pid}/fdinfo");
    let entradas = std::fs::read_dir(&dir).map_err(|e| format!("{dir}: {e}"))?;
    for e in entradas.flatten().take(MAX_DESCRIPTORES) {
        let Some(fd) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(texto) = std::fs::read_to_string(e.path()) else {
            continue;
        };
        if es_enlace_bpf_lsm(&texto) {
            let prog_id = campo(&texto, "prog_id").and_then(|v| v.parse().ok());
            return Ok(Evidencia {
                fuente: Fuente::EnlaceBpfLsm { pid, fd, prog_id },
            });
        }
    }
    Err(format!(
        "el proceso {pid} no sostiene ningun enlace BPF LSM"
    ))
}

/// Puro: si el fdinfo de un descriptor es el de un enlace BPF LSM.
///
/// Un programa LSM se engancha con un enlace de tipo `tracing` y
/// `attach_type` `BPF_LSM_MAC` (27), o de tipo `cgroup` con `BPF_LSM_CGROUP`
/// (43). Un programa CARGADO sin enlace no niega nada, y por eso no basta con
/// ver un `prog_type` 29: hace falta el enlace. Se aceptan tambien los nombres,
/// por si el kernel los imprime en vez del numero.
fn es_enlace_bpf_lsm(fdinfo: &str) -> bool {
    match (campo(fdinfo, "link_type"), campo(fdinfo, "attach_type")) {
        (Some("tracing"), Some(a)) => a == "27" || a == "lsm_mac",
        (Some("cgroup"), Some(a)) => a == "43" || a == "lsm_cgroup",
        _ => false,
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn evidencia_de_prueba(pid: u32) -> Evidencia {
        Evidencia {
            fuente: Fuente::FiltroSeccomp {
                pid,
                propios: Some(1),
            },
        }
    }

    #[test]
    fn la_postura_de_esta_maquina_se_mide_de_verdad() {
        let p = Postura::medida();
        assert_eq!(p.plataforma, Platform::Linux, "el CI es Linux");
        assert_eq!(p.capacidades.len(), 7, "las siete capacidades, contadas");
        // Las de otras plataformas se marcan como tales y no como carencias.
        assert_eq!(
            p.capacidades[&Capacidad::Minifiltro],
            Estado::OtraPlataforma
        );
        assert_eq!(
            p.capacidades[&Capacidad::EndpointSecurity],
            Estado::OtraPlataforma
        );
    }

    #[test]
    fn disponible_no_es_aplicado_en_esta_maquina() {
        // El kernel del CI admite seccomp y Landlock (la puerta del sandbox los
        // ejercita en cada `make ci`). Sin un testigo medido, eso los hace
        // DISPONIBLES y no aplicados: que el kernel los ofrezca no dice que el
        // producto los este usando. Es la prueba del hallazgo H-28, al reves de
        // la que habia.
        let p = Postura::medida();
        for c in [Capacidad::Seccomp, Capacidad::Landlock] {
            let e = &p.capacidades[&c];
            assert!(
                matches!(e, Estado::Disponible { .. }),
                "{}: el kernel lo ofrece y nada medido lo usa: {e:?}",
                c.nombre()
            );
            assert!(!e.aplica(), "{}: disponible no es aplicado", c.nombre());
            assert!(e.disponible());
        }
    }

    #[test]
    fn aplica_solo_sale_de_evidencia() {
        let sin = decidir(None, "el kernel lo ofrece", vec![]);
        assert!(matches!(sin, Estado::Disponible { .. }), "{sin:?}");
        assert!(!sin.aplica());

        let fallida = decidir(
            None,
            "el kernel lo ofrece",
            vec![Err("el proceso 7 no tiene filtro seccomp (modo 0)".into())],
        );
        match &fallida {
            Estado::Disponible { motivo } => assert!(motivo.contains("el proceso 7"), "{motivo}"),
            otro => panic!("sin evidencia no puede aplicar: {otro:?}"),
        }

        let con = decidir(
            None,
            "el kernel lo ofrece",
            vec![Err("x".into()), Ok(evidencia_de_prueba(7))],
        );
        assert!(con.aplica(), "{con:?}");
        assert_eq!(con.etiqueta(), "APLICA");

        // Si el kernel no lo ofrece, ninguna evidencia lo hace aplicar: algo no
        // cuadra y se dice que falta.
        let ausente = decidir(
            Some("sin kernel".into()),
            "el kernel lo ofrece",
            vec![Ok(evidencia_de_prueba(7))],
        );
        assert!(matches!(ausente, Estado::Ausente { .. }), "{ausente:?}");
    }

    #[test]
    fn la_clasificacion_de_bpf_lsm_es_determinista_y_no_depende_del_entorno() {
        // «bpf» en la lista => el kernel ADMITE programas LSM. Sin un enlace
        // medido es solo disponible: que el framework exista no niega nada.
        let admite = clasificar_lsm(
            Some("capability,landlock,yama,safesetid,selinux,bpf"),
            vec![],
        );
        assert!(matches!(admite, Estado::Disponible { .. }), "{admite:?}");
        assert!(!admite.aplica(), "admitir no es negar");
        // Con un enlace medido, si.
        let enganchado = clasificar_lsm(
            Some("capability,bpf"),
            vec![Ok(Evidencia {
                fuente: Fuente::EnlaceBpfLsm {
                    pid: 42,
                    fd: 9,
                    prog_id: Some(77),
                },
            })],
        );
        assert!(enganchado.aplica(), "{enganchado:?}");
        // Lista SIN «bpf» => ve con kprobes y no niega: SoloObserva, y NO aplica.
        let solo = clasificar_lsm(Some("capability,landlock,yama"), vec![]);
        assert!(matches!(solo, Estado::SoloObserva { .. }), "{solo:?}");
        assert!(!solo.aplica(), "observar no es negar");
        // Sin fichero (securityfs sin montar, o kernel sin el framework) =>
        // Ausente, y se DICE con su motivo, en vez de afirmar que niega.
        let aus = clasificar_lsm(None, vec![]);
        assert!(matches!(aus, Estado::Ausente { .. }), "{aus:?}");
        assert!(!aus.aplica());
    }

    #[test]
    fn solo_un_enlace_lsm_es_evidencia_de_bpf_lsm() {
        let enlace = "link_type:\ttracing\nlink_id:\t3\nprog_tag:\tabcd\nprog_id:\t10\n\
                      attach_type:\t27\ntarget_obj_id:\t1\ntarget_btf_id:\t5000\n";
        assert!(es_enlace_bpf_lsm(enlace));
        assert_eq!(campo(enlace, "prog_id"), Some("10"));
        let cgroup = "link_type:\tcgroup\nlink_id:\t4\nprog_id:\t11\n\
                      cgroup_id:\t1\nattach_type:\t43\n";
        assert!(es_enlace_bpf_lsm(cgroup));
        // Un fentry tambien es un enlace «tracing», y ve sin negar.
        let fentry = "link_type:\ttracing\nlink_id:\t5\nprog_id:\t12\nattach_type:\t24\n";
        assert!(!es_enlace_bpf_lsm(fentry));
        // Un programa LSM CARGADO sin enlace no niega nada.
        let programa = "pos:\t0\nflags:\t02000002\nprog_type:\t29\nprog_jited:\t1\nprog_id:\t13\n";
        assert!(!es_enlace_bpf_lsm(programa));
        // Un kprobe es telemetria.
        let kprobe = "link_type:\tperf\nlink_id:\t6\nprog_id:\t14\n";
        assert!(!es_enlace_bpf_lsm(kprobe));
    }

    #[test]
    fn el_status_de_proc_se_lee_bien() {
        let t = "Name:\taegis-trabajador\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t4242\n\
                 Pid:\t4242\nPPid:\t4000\nTracerPid:\t0\nNoNewPrivs:\t1\nSeccomp:\t2\n\
                 Seccomp_filters:\t3\nSpeculation_Store_Bypass:\tthread vulnerable\n";
        assert_eq!(
            parsear_status(t),
            Status {
                seccomp: Some(2),
                filtros: Some(3),
                ppid: Some(4000),
                no_new_privs: Some(true),
            }
        );
        // Un kernel anterior a 5.9 no publica Seccomp_filters: se sabe que falta.
        let viejo = parsear_status("PPid:\t1\nNoNewPrivs:\t0\nSeccomp:\t0\n");
        assert_eq!(viejo.filtros, None);
        assert_eq!(viejo.no_new_privs, Some(false));
    }

    #[test]
    fn un_filtro_heredado_no_es_evidencia() {
        let limpio = Status {
            seccomp: Some(0),
            filtros: Some(0),
            ppid: Some(1),
            no_new_privs: Some(false),
        };
        let con = |n: u32| Status {
            seccomp: Some(2),
            filtros: Some(n),
            ppid: Some(10),
            no_new_privs: Some(true),
        };
        // Sin filtro.
        assert!(evidencia_seccomp(7, &limpio, Some(&limpio)).is_err());
        // Un filtro propio sobre un padre limpio: evidencia.
        let e = evidencia_seccomp(7, &con(1), Some(&limpio)).unwrap();
        assert_eq!(e.pid(), 7);
        // El agente dentro de un contenedor con 2 filtros, y el hijo con 3: uno es
        // propio.
        let e = evidencia_seccomp(7, &con(3), Some(&con(2))).unwrap();
        assert_eq!(
            e.fuente,
            Fuente::FiltroSeccomp {
                pid: 7,
                propios: Some(1),
            }
        );
        // Todos heredados: el producto no puso nada.
        let r = evidencia_seccomp(7, &con(2), Some(&con(2)));
        assert!(r.as_ref().is_err_and(|m| m.contains("heredo")), "{r:?}");
        // Padre con filtro y sin recuento: no se puede separar.
        let sin_recuento = Status {
            filtros: None,
            ..con(0)
        };
        assert!(evidencia_seccomp(7, &sin_recuento, Some(&sin_recuento)).is_err());
        // Sin padre legible: no se atribuye.
        assert!(evidencia_seccomp(7, &con(1), None).is_err());
    }

    #[test]
    fn landlock_declarado_se_corrobora() {
        let bien = Status {
            seccomp: Some(2),
            filtros: Some(1),
            ppid: Some(10),
            no_new_privs: Some(true),
        };
        assert!(evidencia_landlock(7, &bien, Some(3), Some(5)).is_ok());
        // No declara nada: no hay evidencia.
        assert!(evidencia_landlock(7, &bien, None, Some(5)).is_err());
        // Declara una ABI que este kernel no tiene: no cuadra.
        assert!(evidencia_landlock(7, &bien, Some(6), Some(5)).is_err());
        assert!(evidencia_landlock(7, &bien, Some(0), Some(5)).is_err());
        // Sin NoNewPrivs no pudo ponerlo como lo pone el producto.
        let sin_nnp = Status {
            no_new_privs: Some(false),
            ..bien
        };
        assert!(evidencia_landlock(7, &sin_nnp, Some(3), Some(5)).is_err());
    }

    #[test]
    fn un_testigo_se_lee_de_texto() {
        assert_eq!("4242".parse::<Testigo>(), Ok(Testigo::proceso(4242)));
        assert_eq!(
            "4242:landlock=5".parse::<Testigo>(),
            Ok(Testigo::proceso(4242).con_landlock(5))
        );
        assert!("x".parse::<Testigo>().is_err());
        assert!("4242:abi=5".parse::<Testigo>().is_err());
    }

    #[test]
    fn observar_no_cuenta_como_aplicar() {
        let e = Estado::SoloObserva {
            motivo: "kprobes ven la operacion y no la paran".into(),
        };
        assert!(!e.aplica(), "ver pasar algo no es poder pararlo");
    }

    #[test]
    fn una_politica_que_exige_aplicar_se_rechaza_donde_no_se_puede_aplicar() {
        // La regla de fallar cerrado. Una maquina sin ningun mecanismo de
        // aplicacion no puede recibir una politica de bloqueo, y eso se decide
        // en el despliegue y no en el incidente.
        let vacia = Postura {
            plataforma: Platform::Linux,
            capacidades: [(
                Capacidad::Seccomp,
                Estado::Ausente {
                    motivo: "kernel sin seccomp".into(),
                },
            )]
            .into(),
        };
        assert!(!vacia.puede_aplicar_algo());
        assert!(
            !vacia.puede_cumplir(Exigencia::Aplicar),
            "una politica de bloqueo no se puede cumplir aqui"
        );
        assert!(
            vacia.puede_cumplir(Exigencia::Observar),
            "y una de observacion si"
        );
    }

    #[test]
    fn lo_disponible_no_cumple_una_politica_de_bloqueo() {
        // Todo lo que el kernel ofrece, y nada puesto: una politica que dice
        // «esto no se ejecuta» no se cumpliria.
        let ofrecida = Postura {
            plataforma: Platform::Linux,
            capacidades: [
                (
                    Capacidad::Seccomp,
                    Estado::Disponible {
                        motivo: "el kernel lo admite".into(),
                    },
                ),
                (
                    Capacidad::Landlock,
                    Estado::Disponible {
                        motivo: "el kernel lo admite".into(),
                    },
                ),
            ]
            .into(),
        };
        assert!(!ofrecida.puede_cumplir(Exigencia::Aplicar));
        assert!(ofrecida.como_describirse().starts_with("SOLO OBSERVANDO"));
        assert_eq!(
            ofrecida.disponibles(),
            vec![Capacidad::Seccomp, Capacidad::Landlock]
        );
    }

    #[test]
    fn un_agente_que_no_puede_bloquear_no_se_describe_como_protegiendo() {
        let vacia = Postura {
            plataforma: Platform::Linux,
            capacidades: BTreeMap::new(),
        };
        let frase = vacia.como_describirse();
        assert!(
            frase.contains("SOLO OBSERVANDO"),
            "no puede llamarse protegido: {frase}"
        );
        assert!(!frase.contains("aplicando"), "{frase}");
    }

    #[test]
    fn sin_evidencia_esta_maquina_se_describe_como_solo_observando() {
        // La antigua prueba exigia lo contrario —que esta maquina se describiera
        // como aplicando— solo porque el kernel ofrece seccomp y Landlock. Sin un
        // proceso medido, lo honrado es esto.
        let p = Postura::medida();
        assert!(
            !p.puede_aplicar_algo(),
            "sin testigos no hay evidencia: {:?}",
            p.capacidades
        );
        assert!(p.como_describirse().starts_with("SOLO OBSERVANDO"));
        assert!(p.aplicando().is_empty());
        assert!(p.disponibles().contains(&Capacidad::Seccomp));
        let falta = p.lo_que_no_se_puede_imponer();
        assert!(
            falta
                .iter()
                .any(|f| f.starts_with("seccomp:") && f.contains("nada medido")),
            "{falta:?}"
        );
    }

    #[test]
    fn lo_de_otras_plataformas_no_sale_como_carencia() {
        // Si saliera, cada endpoint de Linux reportaria tres carencias por no
        // ser Windows ni un Mac, y el informe dejaria de leerse.
        let p = Postura::medida();
        let falta = p.lo_que_no_se_puede_imponer();
        assert!(
            !falta.iter().any(|f| f.contains("minifiltro")),
            "no es una carencia de una maquina Linux: {falta:?}"
        );
        assert!(!falta.iter().any(|f| f.contains("Endpoint Security")));
    }

    #[test]
    fn un_testigo_muerto_no_es_evidencia() {
        // Un zombi conserva su status, con el filtro y NoNewPrivs puestos...
        let zombi = "Name:\taegis-agent\nState:\tZ (zombie)\nTgid:\t4242\nPid:\t4242\n\
                     PPid:\t4000\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t1\n";
        // ...que, leido sin mas, pasaria por evidencia: por eso se mira antes.
        let s = parsear_status(zombi);
        assert!(evidencia_landlock(4242, &s, Some(1), Some(5)).is_ok());
        assert_eq!(sin_vida(zombi), Some("Z (zombie)"));
        assert_eq!(sin_vida("State:\tX (dead)\n"), Some("X (dead)"));
        for vivo in [
            "State:\tR (running)\n",
            "State:\tS (sleeping)\n",
            "State:\tD (disk sleep)\n",
            "State:\tT (stopped)\n",
        ] {
            assert_eq!(sin_vida(vivo), None, "{vivo}");
        }
        assert_eq!(sin_vida("Seccomp:\t2\n"), None);
    }

    #[test]
    fn cada_capacidad_declara_su_plataforma() {
        assert_eq!(Capacidad::Seccomp.plataforma(), Platform::Linux);
        assert_eq!(Capacidad::Minifiltro.plataforma(), Platform::Windows);
        assert_eq!(Capacidad::EndpointSecurity.plataforma(), Platform::MacOs);
    }
}
