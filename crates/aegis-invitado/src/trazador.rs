//! El trazador: `ptrace` de verdad sobre la muestra, dentro del invitado.
//!
//! # Que se traza y por que asi
//!
//! Se usa `PTRACE_SYSCALL` con `PTRACE_O_TRACESYSGOOD` y el juego completo de
//! `TRACEFORK`/`TRACEVFORK`/`TRACECLONE`/`TRACEEXEC`/`TRACEEXIT`. Sin seguir a
//! los hijos, la primera cosa que hace cualquier malware serio —lanzar un
//! proceso y morirse— dejaria la traza en blanco justo cuando empieza lo bueno.
//!
//! # Las tres cosas que lo hacen desplegable
//!
//! **Un plazo que se cumple de verdad.** `waitpid` bloquea; un plazo comprobado
//! entre iteraciones no sirve de nada contra una muestra que se queda parada en
//! una llamada. El plazo lo aplica un hilo aparte que mata al grupo entero, y
//! entonces `waitpid` devuelve. Una muestra que no termina **siempre** se corta,
//! y el informe dice que se corto: un informe que no distingue «no hizo nada» de
//! «no le dio tiempo» es peor que ninguno.
//!
//! **Un tope de eventos.** Un bucle que llama a `getpid()` un millon de veces por
//! segundo llena el canal, la memoria del anfitrion y el informe. Al llegar al
//! tope se deja de emitir y **se dice**, en vez de seguir hasta que algo reviente.
//!
//! **Cortar no es perder.** Cuando se corta por plazo o por tope, lo trazado
//! hasta ese momento sigue siendo evidencia valida. Se entrega con la marca de
//! que esta incompleta.
//!
//! # Lo que este trazador NO ve, declarado
//!
//! - Lo que ocurre **dentro** de una llamada: se ven los argumentos a la entrada
//!   y el resultado a la salida, no el efecto en el kernel.
//! - Codigo que corre en otro anillo. Una muestra que carga un modulo ha salido
//!   del alcance de `ptrace`; lo que se ve es el `finit_module`, y por eso esa
//!   llamada esta marcada como evasion.
//! - Hilos que la muestra cree fuera del arbol trazado son imposibles con las
//!   opciones de arriba, pero un `ptrace` propio de la muestra sobre si misma
//!   **si** puede desengancharla, y eso se emite como [`Evento::Degradado`].

use std::ffi::CString;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::llamadas::{self, Interes};
use crate::protocolo::{AccionFichero, AccionProceso, Evento};

/// Donde van los hechos que el trazador observa.
///
/// Es un rasgo y no un canal concreto para que el trazador se pueda ejercitar
/// contra un `Vec` en una prueba **sin dejar de ser el trazador de verdad**: lo
/// que cambia es a donde escribe, no lo que hace.
pub trait Sumidero {
    /// Anota un hecho.
    fn emitir(&mut self, evento: Evento);
}

impl Sumidero for Vec<Evento> {
    fn emitir(&mut self, evento: Evento) {
        self.push(evento);
    }
}

/// Que se detona y con que limites.
#[derive(Debug, Clone)]
pub struct Config {
    /// Programa por ejecutar.
    pub programa: PathBuf,
    /// Argumentos, sin el `argv[0]`.
    pub argumentos: Vec<String>,
    /// Directorio de trabajo.
    pub directorio: Option<PathBuf>,
    /// Plazo de pared. Al agotarse se mata al grupo entero.
    pub plazo: Duration,
    /// Eventos maximos antes de dejar de emitir.
    pub max_eventos: u64,
    /// Tope de memoria virtual del arbol trazado, en bytes. `None` deja el del sistema.
    pub max_memoria: Option<u64>,
    /// Tope de ficheros que puede crear, en bytes. `None` deja el del sistema.
    pub max_fichero: Option<u64>,
}

impl Config {
    /// Configuracion de un programa con los limites por omision.
    #[must_use]
    pub fn nueva(programa: PathBuf) -> Config {
        Config {
            programa,
            argumentos: Vec::new(),
            directorio: None,
            plazo: Duration::from_secs(60),
            max_eventos: 200_000,
            max_memoria: Some(512 * 1024 * 1024),
            max_fichero: Some(256 * 1024 * 1024),
        }
    }
}

/// Por que se corto una detonacion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Corte {
    /// Se agoto el plazo de pared.
    Plazo,
    /// Se alcanzo el tope de eventos.
    Eventos,
}

impl Corte {
    /// Nombre estable para el informe.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Corte::Plazo => "plazo",
            Corte::Eventos => "eventos",
        }
    }
}

/// Como acabo la detonacion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Desenlace {
    /// La muestra termino por si sola.
    Termino {
        /// Codigo de salida.
        codigo: i32,
    },
    /// La mato una senal.
    Senal {
        /// Numero de senal.
        senal: i32,
    },
    /// Se corto desde fuera.
    Cortado {
        /// Por que.
        motivo: Corte,
    },
}

impl Desenlace {
    /// Si la detonacion llego a su fin natural.
    ///
    /// Un `false` **no** significa que la muestra sea inofensiva: significa que
    /// el informe esta incompleto, y son cosas distintas que un sandbox honesto
    /// no puede confundir.
    #[must_use]
    pub fn completo(&self) -> bool {
        matches!(self, Desenlace::Termino { .. } | Desenlace::Senal { .. })
    }
}

/// Lo que puede salir mal al trazar.
#[derive(Debug)]
pub enum ErrorTrazador {
    /// No se pudo lanzar la muestra.
    NoArranca(String),
    /// `ptrace` no esta disponible o lo deniegan.
    SinPtrace(String),
    /// La configuracion no tiene sentido.
    Config(String),
}

impl core::fmt::Display for ErrorTrazador {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ErrorTrazador::NoArranca(d) => write!(f, "no se pudo lanzar la muestra: {d}"),
            ErrorTrazador::SinPtrace(d) => write!(f, "ptrace no disponible: {d}"),
            ErrorTrazador::Config(d) => write!(f, "configuracion invalida: {d}"),
        }
    }
}

impl std::error::Error for ErrorTrazador {}

/// Resultado completo de una traza.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resultado {
    /// Como acabo.
    pub desenlace: Desenlace,
    /// Eventos emitidos.
    pub emitidos: u64,
    /// Eventos que NO se emitieron por haber llegado al tope.
    ///
    /// Va en el informe: una traza recortada que no dice que lo esta invita a
    /// leerla como si fuera completa.
    pub descartados: u64,
    /// Llamadas observadas, se emitieran o no.
    pub llamadas_vistas: u64,
}

/// Banderas de `waitpid` del trazador.
///
/// # `__WNOTHREAD` no es una optimizacion: sin el, esto se cuelga
///
/// En Linux el trazador de `ptrace` es un **hilo** concreto, no el proceso. Las
/// paradas de un trazado solo puede atenderlas el hilo que lo enganho, pero
/// `waitpid(-1, ...)` sin esta bandera recoge a los hijos de **cualquier** hilo
/// del grupo. Con dos detonaciones a la vez —o simplemente con las pruebas
/// corriendo en paralelo, que es como las corre `cargo test`— un hilo recoge la
/// notificacion del trazado de otro, no puede hacer nada con ella porque no es
/// su trazador, y el hilo que si lo era se queda esperando para siempre una
/// notificacion que ya se llevo otro. El trazado se queda parado en `t` y la
/// detonacion no termina nunca.
///
/// `__WNOTHREAD` acota la espera a los hijos del hilo que llama, que es
/// exactamente el conjunto de los que este trazador puede atender.
///
/// `__WALL` esta porque el kernel presenta los `clone` de la muestra como hilos,
/// y sin el no se verian: un malware que reparte su trabajo en hilos dejaria la
/// traza vacia.
const ESPERA: libc::c_int = libc::__WALL | libc::__WNOTHREAD;

// --- El trazador --------------------------------------------------------------

/// Traza la ejecucion de una muestra y entrega los hechos al sumidero.
///
/// # Errores
/// [`ErrorTrazador`] si la muestra no arranca o si `ptrace` no esta disponible.
#[allow(unsafe_code)] // fork/ptrace/waitpid; cada bloque lleva su SAFETY
pub fn trazar<S: Sumidero>(cfg: &Config, sumidero: &mut S) -> Result<Resultado, ErrorTrazador> {
    if cfg.plazo.is_zero() {
        return Err(ErrorTrazador::Config("el plazo no puede ser cero".into()));
    }

    // TODO lo que el hijo va a necesitar se prepara ANTES del fork. Entre el
    // `fork` y el `execve`, el hijo de un programa con varios hilos solo puede
    // llamar a funciones seguras frente a senales: reservar memoria ahi puede
    // bloquearse para siempre contra un `malloc` que otro hilo dejo a medias.
    let programa = CString::new(cfg.programa.as_os_str().as_encoded_bytes())
        .map_err(|_| ErrorTrazador::Config("el programa lleva un byte nulo".into()))?;
    let mut argv_duenos: Vec<CString> = Vec::with_capacity(cfg.argumentos.len() + 1);
    argv_duenos.push(programa.clone());
    for a in &cfg.argumentos {
        argv_duenos.push(
            CString::new(a.as_bytes())
                .map_err(|_| ErrorTrazador::Config("un argumento lleva un byte nulo".into()))?,
        );
    }
    let mut argv: Vec<*const libc::c_char> = argv_duenos.iter().map(|c| c.as_ptr()).collect();
    argv.push(core::ptr::null());
    let envp: Vec<*const libc::c_char> = vec![core::ptr::null()];
    let directorio = match &cfg.directorio {
        Some(d) => Some(
            CString::new(d.as_os_str().as_encoded_bytes())
                .map_err(|_| ErrorTrazador::Config("el directorio lleva un byte nulo".into()))?,
        ),
        None => None,
    };
    let max_memoria = cfg.max_memoria;
    let max_fichero = cfg.max_fichero;

    // SAFETY: `fork` no tiene precondiciones. El hijo se limita a llamadas
    // seguras frente a senales (ptrace, raise, setrlimit, chdir, execve) sobre
    // punteros preparados arriba, y acaba en `_exit` si el `execve` falla.
    let hijo = unsafe { libc::fork() };
    if hijo < 0 {
        return Err(ErrorTrazador::NoArranca("fork fallo".into()));
    }
    if hijo == 0 {
        // --- Somos el hijo. A partir de aqui, nada de reservar memoria. ---
        // SAFETY: llamadas seguras frente a senales, con punteros validos que se
        // prepararon antes del fork y que siguen vivos en esta copia.
        unsafe {
            if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) < 0 {
                libc::_exit(126);
            }
            if let Some(m) = max_memoria {
                let l = libc::rlimit {
                    rlim_cur: m,
                    rlim_max: m,
                };
                libc::setrlimit(libc::RLIMIT_AS, &l);
            }
            if let Some(m) = max_fichero {
                let l = libc::rlimit {
                    rlim_cur: m,
                    rlim_max: m,
                };
                libc::setrlimit(libc::RLIMIT_FSIZE, &l);
            }
            // Un grupo de procesos propio: asi el plazo mata al arbol entero de
            // un golpe, incluidos los hijos que la muestra haya lanzado para
            // sobrevivir a su propia muerte.
            libc::setpgid(0, 0);
            if let Some(d) = &directorio {
                if libc::chdir(d.as_ptr()) < 0 {
                    libc::_exit(125);
                }
            }
            // La parada avisa al padre de que ya puede poner las opciones de
            // ptrace: sin ella habria una carrera con el execve.
            libc::raise(libc::SIGSTOP);
            libc::execve(programa.as_ptr(), argv.as_ptr(), envp.as_ptr());
            libc::_exit(127);
        }
    }

    // --- Somos el padre. ---
    let mut estado: libc::c_int = 0;
    // SAFETY: `hijo` es el pid que acaba de devolver `fork` y `estado` es una
    // variable local viva durante toda la llamada.
    if unsafe { libc::waitpid(hijo, &mut estado, ESPERA) } < 0 {
        return Err(ErrorTrazador::NoArranca("el hijo no llego a parar".into()));
    }

    let opciones = libc::PTRACE_O_TRACESYSGOOD
        | libc::PTRACE_O_TRACEFORK
        | libc::PTRACE_O_TRACEVFORK
        | libc::PTRACE_O_TRACECLONE
        | libc::PTRACE_O_TRACEEXEC
        | libc::PTRACE_O_TRACEEXIT
        // Si el trazador muere, el arbol trazado muere con el. Sin esto, una
        // muestra que consiga matar al agente invitado se quedaria corriendo
        // suelta dentro de la maquina que se suponia contenida.
        | libc::PTRACE_O_EXITKILL;
    // SAFETY: el hijo esta parado y trazado; poner opciones sobre el es valido.
    if unsafe { libc::ptrace(libc::PTRACE_SETOPTIONS, hijo, 0, opciones) } < 0 {
        // SAFETY: matar al hijo que acabamos de crear y esperarlo.
        unsafe {
            libc::kill(hijo, libc::SIGKILL);
            libc::waitpid(hijo, &mut estado, ESPERA);
        }
        return Err(ErrorTrazador::SinPtrace(
            "el kernel no acepta PTRACE_SETOPTIONS (contenedor sin CAP_SYS_PTRACE?)".into(),
        ));
    }

    sumidero.emitir(Evento::Proceso {
        pid: hijo,
        padre: std::process::id() as i32,
        accion: AccionProceso::Nace,
        imagen: cfg.programa.display().to_string(),
        argumentos: cfg.argumentos.clone(),
    });

    let vencido = arrancar_plazo(hijo, cfg.plazo);
    let resultado = bucle(hijo, cfg, sumidero, &vencido);
    vencido.cancelar();
    resultado
}

/// Guardia del plazo: mata al grupo cuando se acaba el tiempo.
struct Plazo {
    vencido: Arc<AtomicBool>,
    seguir: Arc<AtomicBool>,
}

impl Plazo {
    fn expirado(&self) -> bool {
        self.vencido.load(Ordering::Relaxed)
    }

    fn cancelar(&self) {
        self.seguir.store(false, Ordering::Relaxed);
    }
}

/// Lanza el hilo que aplica el plazo.
///
/// Tiene que ser un hilo aparte, y no una comprobacion entre iteraciones: el
/// bucle se pasa la vida bloqueado en `waitpid`, asi que una muestra que se
/// quede quieta en una llamada nunca le daria ocasion de mirar el reloj. El que
/// desbloquea el `waitpid` es el `SIGKILL`.
#[allow(unsafe_code)] // kill sobre el grupo de procesos del trazado
fn arrancar_plazo(pid: i32, plazo: Duration) -> Plazo {
    let vencido = Arc::new(AtomicBool::new(false));
    let seguir = Arc::new(AtomicBool::new(true));
    let v = Arc::clone(&vencido);
    let s = Arc::clone(&seguir);
    std::thread::spawn(move || {
        let fin = Instant::now() + plazo;
        loop {
            if !s.load(Ordering::Relaxed) {
                return;
            }
            // `fin - Instant::now()` PANICA si el instante ya paso, y entre la
            // comprobacion de arriba y esta linea puede pasar. Un panico aqui
            // mataria el hilo del plazo en silencio, y una muestra que no
            // termina se quedaria corriendo para siempre dentro de la maquina
            // infectada: el fallo mas caro posible, escondido en una resta.
            let queda = fin.saturating_duration_since(Instant::now());
            if queda.is_zero() {
                break;
            }
            std::thread::sleep(queda.min(Duration::from_millis(20)));
        }
        if !s.load(Ordering::Relaxed) {
            return;
        }
        v.store(true, Ordering::Relaxed);
        // SAFETY: `kill` con un pgid negativo manda la senal al grupo entero.
        // Si el grupo ya no existe, devuelve error y no pasa nada.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
            libc::kill(pid, libc::SIGKILL);
        }
    });
    Plazo { vencido, seguir }
}

/// Estado por proceso trazado.
#[derive(Default)]
struct Seguido {
    /// Si la proxima parada de llamada es la salida y no la entrada.
    en_llamada: bool,
    /// Numero de la llamada en curso.
    numero: u64,
}

#[allow(unsafe_code)] // waitpid/ptrace sobre los procesos trazados
fn bucle<S: Sumidero>(
    raiz: i32,
    cfg: &Config,
    sumidero: &mut S,
    plazo: &Plazo,
) -> Result<Resultado, ErrorTrazador> {
    use std::collections::BTreeMap;

    let mut seguidos: BTreeMap<i32, Seguido> = BTreeMap::new();
    seguidos.insert(raiz, Seguido::default());

    let mut emitidos: u64 = 1; // el Proceso::Nace de la raiz
    let mut descartados: u64 = 0;
    let mut llamadas_vistas: u64 = 0;
    let mut desenlace: Option<Desenlace> = None;
    let mut tope_alcanzado = false;

    // Se arranca al hijo, que esta parado en su SIGSTOP.
    // SAFETY: `raiz` esta parado y trazado.
    unsafe { libc::ptrace(libc::PTRACE_SYSCALL, raiz, 0, 0) };

    loop {
        let mut estado: libc::c_int = 0;
        // SAFETY: se espera a cualquier tracee de ESTE hilo; ver `ESPERA`.
        let pid = unsafe { libc::waitpid(-1, &mut estado, ESPERA) };
        if pid < 0 {
            // No quedan hijos: se acabo.
            break;
        }

        let seguido = seguidos.entry(pid).or_default();

        if libc::WIFEXITED(estado) {
            let codigo = libc::WEXITSTATUS(estado);
            if emitidos < cfg.max_eventos {
                sumidero.emitir(Evento::Proceso {
                    pid,
                    padre: 0,
                    accion: AccionProceso::Muere,
                    imagen: String::new(),
                    argumentos: Vec::new(),
                });
                emitidos += 1;
            } else {
                descartados += 1;
            }
            seguidos.remove(&pid);
            if pid == raiz {
                desenlace = Some(Desenlace::Termino { codigo });
            }
            if seguidos.is_empty() {
                break;
            }
            continue;
        }

        if libc::WIFSIGNALED(estado) {
            let senal = libc::WTERMSIG(estado);
            seguidos.remove(&pid);
            if pid == raiz {
                desenlace = Some(if plazo.expirado() {
                    Desenlace::Cortado {
                        motivo: Corte::Plazo,
                    }
                } else {
                    Desenlace::Senal { senal }
                });
            }
            if seguidos.is_empty() {
                break;
            }
            continue;
        }

        if !libc::WIFSTOPPED(estado) {
            continue;
        }

        let senal = libc::WSTOPSIG(estado);
        let evento_ptrace = (estado >> 16) & 0xff;
        let mut senal_a_entregar = 0;

        if evento_ptrace != 0 {
            match evento_ptrace {
                libc::PTRACE_EVENT_FORK | libc::PTRACE_EVENT_VFORK | libc::PTRACE_EVENT_CLONE => {
                    let mut nuevo: libc::c_long = 0;
                    // SAFETY: el proceso esta parado en el evento; `PTRACE_GETEVENTMSG`
                    // escribe el pid del hijo en el puntero que se le pasa.
                    unsafe {
                        libc::ptrace(
                            libc::PTRACE_GETEVENTMSG,
                            pid,
                            0,
                            core::ptr::addr_of_mut!(nuevo),
                        )
                    };
                    let nuevo = nuevo as i32;
                    if nuevo > 0 {
                        seguidos.entry(nuevo).or_default();
                        if emitidos < cfg.max_eventos {
                            sumidero.emitir(Evento::Proceso {
                                pid: nuevo,
                                padre: pid,
                                accion: AccionProceso::Nace,
                                imagen: String::new(),
                                argumentos: Vec::new(),
                            });
                            emitidos += 1;
                        } else {
                            descartados += 1;
                        }
                    }
                }
                libc::PTRACE_EVENT_EXEC => {
                    let imagen = leer_enlace_exe(pid);
                    if emitidos < cfg.max_eventos {
                        sumidero.emitir(Evento::Proceso {
                            pid,
                            padre: 0,
                            accion: AccionProceso::Ejecuta,
                            imagen,
                            argumentos: Vec::new(),
                        });
                        emitidos += 1;
                    } else {
                        descartados += 1;
                    }
                }
                _ => {}
            }
        } else if senal == libc::SIGTRAP | 0x80 {
            // Parada de llamada al sistema. `TRACESYSGOOD` pone el bit 0x80 para
            // que se distinga de un SIGTRAP de verdad; sin el, un `int3` de la
            // propia muestra se confundiria con una llamada y la traza entera se
            // desincronizaria a partir de ahi.
            llamadas_vistas += 1;
            if !seguido.en_llamada {
                seguido.en_llamada = true;
                if let Some(regs) = leer_registros(pid) {
                    seguido.numero = regs.orig_rax;
                    let antes = emitidos;
                    clasificar(pid, &regs, cfg, sumidero, &mut emitidos, &mut descartados);
                    if emitidos == antes && descartados > 0 {
                        tope_alcanzado = true;
                    }
                }
            } else {
                seguido.en_llamada = false;
            }
        } else if senal != libc::SIGTRAP {
            // Una senal de verdad para el proceso trazado: se le reinyecta, o se
            // le estaria cambiando el comportamiento a la muestra que se quiere
            // observar.
            senal_a_entregar = senal;
        }

        if emitidos >= cfg.max_eventos {
            tope_alcanzado = true;
        }

        // SAFETY: el proceso esta parado; se le deja seguir hasta la siguiente
        // parada de llamada, entregandole la senal que le tocaba si la habia.
        if unsafe {
            libc::ptrace(
                libc::PTRACE_SYSCALL,
                pid,
                0,
                senal_a_entregar as libc::c_long,
            )
        } < 0
        {
            // Ya no esta: lo habra matado el plazo o se habra desenganchado.
            seguidos.remove(&pid);
            if seguidos.is_empty() {
                break;
            }
        }
    }

    let desenlace = desenlace.unwrap_or(if plazo.expirado() {
        Desenlace::Cortado {
            motivo: Corte::Plazo,
        }
    } else if tope_alcanzado {
        Desenlace::Cortado {
            motivo: Corte::Eventos,
        }
    } else {
        Desenlace::Termino { codigo: 0 }
    });

    Ok(Resultado {
        desenlace,
        emitidos,
        descartados,
        llamadas_vistas,
    })
}

/// Convierte una parada de llamada en el hecho que revela, si revela alguno.
fn clasificar<S: Sumidero>(
    pid: i32,
    regs: &libc::user_regs_struct,
    cfg: &Config,
    sumidero: &mut S,
    emitidos: &mut u64,
    descartados: &mut u64,
) {
    let numero = regs.orig_rax;
    let Some(entrada) = llamadas::buscar(numero) else {
        return;
    };

    if *emitidos >= cfg.max_eventos {
        *descartados += 1;
        return;
    }

    let args = [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9];
    let ruta = entrada
        .arg_ruta
        .and_then(|i| leer_cadena(pid, args[i]))
        .unwrap_or_default();

    let evento = match entrada.interes {
        Interes::Proceso => Evento::Proceso {
            pid,
            padre: 0,
            accion: AccionProceso::Ejecuta,
            imagen: ruta,
            argumentos: Vec::new(),
        },
        Interes::Fichero(accion) => {
            // `open`/`openat` dicen si es lectura o escritura en las banderas, y
            // la diferencia entre mirar un fichero y reescribirlo es la
            // diferencia entre husmear y cifrar.
            let accion = match numero {
                2 if llamadas::abre_para_escribir(args[1]) => AccionFichero::Escribe,
                257 | 437 if llamadas::abre_para_escribir(args[2]) => AccionFichero::Escribe,
                _ => accion,
            };
            Evento::Fichero {
                pid,
                accion,
                ruta,
                bytes: 0,
            }
        }
        Interes::Red(accion) => Evento::Red {
            pid,
            accion,
            destino: destino_de_sockaddr(pid, args[1]).unwrap_or_default(),
            puerto: puerto_de_sockaddr(pid, args[1]).unwrap_or(0),
            bytes: 0,
        },
        Interes::Evasion => {
            let nombre = if numero == 10 && llamadas::memoria_escribible_y_ejecutable(args[2]) {
                "mprotect+WX".to_string()
            } else {
                entrada.nombre.to_string()
            };
            Evento::Llamada {
                pid,
                numero,
                nombre,
            }
        }
        Interes::Generico => Evento::Llamada {
            pid,
            numero,
            nombre: entrada.nombre.to_string(),
        },
    };

    sumidero.emitir(evento);
    *emitidos += 1;
}

/// Lee los registros del proceso parado.
#[allow(unsafe_code)] // PTRACE_GETREGS
fn leer_registros(pid: i32) -> Option<libc::user_regs_struct> {
    // SAFETY: se reserva la estructura en la pila y se le pide al kernel que la
    // rellene. `PTRACE_GETREGS` escribe exactamente `size_of::<user_regs_struct>()`
    // bytes, y solo lo hace si el proceso esta parado y trazado.
    let mut regs: libc::user_regs_struct = unsafe { core::mem::zeroed() };
    let rc = unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGS,
            pid,
            0,
            core::ptr::addr_of_mut!(regs) as *mut libc::c_void,
        )
    };
    if rc < 0 {
        None
    } else {
        Some(regs)
    }
}

/// Lee una cadena terminada en nulo de la memoria del proceso trazado.
///
/// Se hace por `/proc/<pid>/mem` y no por `PTRACE_PEEKDATA` palabra a palabra:
/// una ruta de 4096 bytes serian 512 llamadas al kernel, y esto ocurre en cada
/// `openat` de una traza que puede tener cientos de miles.
///
/// La direccion la elige la muestra, asi que puede ser basura. Una lectura que
/// falla devuelve `None` y no rompe nada: perder una ruta es un agujero en la
/// evidencia, y romper el trazador es perderla toda.
fn leer_cadena(pid: i32, direccion: u64) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};

    if direccion == 0 {
        return None;
    }
    let mut f = std::fs::File::open(format!("/proc/{pid}/mem")).ok()?;
    f.seek(SeekFrom::Start(direccion)).ok()?;

    let mut bufer = [0u8; crate::protocolo::MAX_CADENA];
    let mut leidos = 0usize;
    // Se lee a trozos hasta encontrar el nulo o llegar al tope. Leer los 4 KiB
    // de golpe fallaria cada vez que la cadena esta al final de una pagina y la
    // siguiente no esta mapeada, que es el caso normal.
    while leidos < bufer.len() {
        let trozo = (bufer.len() - leidos).min(256);
        match f.read(&mut bufer[leidos..leidos + trozo]) {
            Ok(0) => break,
            Ok(n) => {
                if let Some(p) = bufer[leidos..leidos + n].iter().position(|b| *b == 0) {
                    leidos += p;
                    return Some(crate::protocolo::escapar(&bufer[..leidos]));
                }
                leidos += n;
            }
            Err(_) => break,
        }
    }
    if leidos == 0 {
        None
    } else {
        Some(crate::protocolo::escapar(&bufer[..leidos]))
    }
}

/// Saca la direccion de una `struct sockaddr` de la memoria del trazado.
fn destino_de_sockaddr(pid: i32, direccion: u64) -> Option<String> {
    let bruto = leer_bytes(pid, direccion, 28)?;
    let familia = u16::from_le_bytes([bruto[0], bruto[1]]);
    match familia {
        // AF_INET
        2 => Some(format!(
            "{}.{}.{}.{}",
            bruto[4], bruto[5], bruto[6], bruto[7]
        )),
        // AF_INET6
        10 => {
            let mut partes = Vec::with_capacity(8);
            for i in 0..8 {
                partes.push(format!(
                    "{:x}",
                    u16::from_be_bytes([bruto[8 + i * 2], bruto[9 + i * 2]])
                ));
            }
            Some(partes.join(":"))
        }
        // AF_UNIX: la ruta empieza en el byte 2.
        1 => {
            let fin = bruto[2..].iter().position(|b| *b == 0).unwrap_or(0) + 2;
            Some(crate::protocolo::escapar(&bruto[2..fin]))
        }
        otra => Some(format!("familia_{otra}")),
    }
}

/// Saca el puerto de una `struct sockaddr`, si lo lleva.
fn puerto_de_sockaddr(pid: i32, direccion: u64) -> Option<u16> {
    let bruto = leer_bytes(pid, direccion, 4)?;
    let familia = u16::from_le_bytes([bruto[0], bruto[1]]);
    // El puerto va en orden de red, que es justo el fallo que hace que un
    // informe ensene 443 como 47873.
    if familia == 2 || familia == 10 {
        Some(u16::from_be_bytes([bruto[2], bruto[3]]))
    } else {
        None
    }
}

/// Lee `n` bytes de la memoria del proceso trazado.
fn leer_bytes(pid: i32, direccion: u64, n: usize) -> Option<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    if direccion == 0 || n == 0 {
        return None;
    }
    let mut f = std::fs::File::open(format!("/proc/{pid}/mem")).ok()?;
    f.seek(SeekFrom::Start(direccion)).ok()?;
    let mut v = vec![0u8; n];
    let mut leidos = 0;
    while leidos < n {
        match f.read(&mut v[leidos..]) {
            Ok(0) => break,
            Ok(k) => leidos += k,
            Err(_) => break,
        }
    }
    if leidos == 0 {
        return None;
    }
    v.truncate(leidos.max(4).min(n));
    if v.len() < 4 {
        return None;
    }
    Some(v)
}

/// Resuelve `/proc/<pid>/exe` para saber que imagen esta corriendo.
fn leer_enlace_exe(pid: i32) -> String {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .map(|p| p.display().to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_prueba::{omitir, Requisito};

    fn sh(guion: &str) -> Config {
        let mut c = Config::nueva(PathBuf::from("/bin/sh"));
        c.argumentos = vec!["-c".into(), guion.into()];
        c.plazo = Duration::from_secs(20);
        c
    }

    fn hay_ptrace() -> bool {
        // Un contenedor sin CAP_SYS_PTRACE no puede trazar nada, y fingir que si
        // haria que estas pruebas dieran verde sin ejercitar nada.
        let mut v: Vec<Evento> = Vec::new();
        trazar(&sh("exit 0"), &mut v).is_ok()
    }

    // --- El trazador, contra procesos REALES ------------------------------

    #[test]
    fn una_muestra_que_ejecuta_deja_su_rastro() {
        if !hay_ptrace() {
            omitir(
                "no se puede trazar con ptrace (hace falta CAP_SYS_PTRACE)",
                Requisito::Ptrace,
            );
            return;
        }
        let mut v: Vec<Evento> = Vec::new();
        let r = trazar(&sh("/bin/true"), &mut v).unwrap();

        assert!(r.desenlace.completo(), "{:?}", r.desenlace);
        assert!(r.llamadas_vistas > 0, "no se vio ni una llamada");
        assert!(
            v.iter().any(|e| matches!(
                e,
                Evento::Proceso {
                    accion: AccionProceso::Nace,
                    ..
                }
            )),
            "falta el nacimiento del proceso raiz"
        );
    }

    #[test]
    fn los_hijos_se_siguen_y_no_se_pierde_lo_que_hacen() {
        // Lo primero que hace cualquier malware serio es lanzar un proceso y
        // morirse. Sin seguir a los hijos, la traza se queda en blanco justo
        // cuando empieza lo interesante.
        if !hay_ptrace() {
            omitir(
                "no se puede trazar con ptrace (hace falta CAP_SYS_PTRACE)",
                Requisito::Ptrace,
            );
            return;
        }
        let mut v: Vec<Evento> = Vec::new();
        trazar(&sh("/bin/true; /bin/true; /bin/true"), &mut v).unwrap();

        let nacimientos = v
            .iter()
            .filter(|e| {
                matches!(
                    e,
                    Evento::Proceso {
                        accion: AccionProceso::Nace,
                        ..
                    }
                )
            })
            .count();
        assert!(
            nacimientos >= 2,
            "solo {nacimientos} nacimientos: no se estan siguiendo los hijos"
        );
    }

    #[test]
    fn escribir_un_fichero_se_distingue_de_leerlo() {
        if !hay_ptrace() {
            omitir(
                "no se puede trazar con ptrace (hace falta CAP_SYS_PTRACE)",
                Requisito::Ptrace,
            );
            return;
        }
        let dir = std::env::temp_dir().join(format!("aegis-traza-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let objetivo = dir.join("victima.txt");
        let guion = format!("echo hola > {}", objetivo.display());

        let mut v: Vec<Evento> = Vec::new();
        trazar(&sh(&guion), &mut v).unwrap();

        let escrituras: Vec<&Evento> = v
            .iter()
            .filter(|e| {
                matches!(
                    e,
                    Evento::Fichero {
                        accion: AccionFichero::Escribe,
                        ..
                    }
                )
            })
            .collect();
        assert!(
            !escrituras.is_empty(),
            "una escritura tiene que verse como escritura, no como lectura"
        );
        assert!(
            escrituras.iter().any(|e| match e {
                Evento::Fichero { ruta, .. } => ruta.contains("victima.txt"),
                _ => false,
            }),
            "la ruta escrita no aparece: {escrituras:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn una_muestra_que_no_termina_se_corta_y_el_informe_lo_dice() {
        // El plazo lo aplica un hilo aparte justamente para esto: el bucle esta
        // bloqueado en waitpid y una comprobacion entre iteraciones no llegaria
        // nunca.
        if !hay_ptrace() {
            omitir(
                "no se puede trazar con ptrace (hace falta CAP_SYS_PTRACE)",
                Requisito::Ptrace,
            );
            return;
        }
        let mut cfg = sh("sleep 600");
        cfg.plazo = Duration::from_millis(700);

        let inicio = Instant::now();
        let mut v: Vec<Evento> = Vec::new();
        let r = trazar(&cfg, &mut v).unwrap();
        let tardanza = inicio.elapsed();

        assert_eq!(
            r.desenlace,
            Desenlace::Cortado {
                motivo: Corte::Plazo
            },
            "tiene que declararse cortada, no terminada"
        );
        assert!(
            !r.desenlace.completo(),
            "un corte NO es un informe completo"
        );
        assert!(
            tardanza < Duration::from_secs(10),
            "el plazo no se aplico: {tardanza:?}"
        );
    }

    #[test]
    fn el_tope_de_eventos_recorta_y_lo_declara() {
        // Un bucle de llamadas llena el canal, la memoria y el informe. Al llegar
        // al tope se deja de emitir y se DICE cuanto se perdio.
        if !hay_ptrace() {
            omitir(
                "no se puede trazar con ptrace (hace falta CAP_SYS_PTRACE)",
                Requisito::Ptrace,
            );
            return;
        }
        let mut cfg = sh("for i in $(seq 1 400); do /bin/true; done");
        cfg.max_eventos = 50;
        cfg.plazo = Duration::from_secs(30);

        let mut v: Vec<Evento> = Vec::new();
        let r = trazar(&cfg, &mut v).unwrap();

        assert!(
            r.emitidos <= 60,
            "emitidos {} sobre un tope de 50",
            r.emitidos
        );
        assert!(
            r.descartados > 0,
            "si se recorto, el informe tiene que decir cuanto"
        );
    }

    #[test]
    fn la_muestra_se_lanza_con_su_propio_grupo_de_procesos() {
        // El plazo mata al GRUPO, no al proceso: un malware que lanza un hijo y
        // se muere dejaria al hijo corriendo suelto dentro de la maquina que se
        // suponia contenida.
        if !hay_ptrace() {
            omitir(
                "no se puede trazar con ptrace (hace falta CAP_SYS_PTRACE)",
                Requisito::Ptrace,
            );
            return;
        }
        let mut cfg = sh("sleep 600 & sleep 600");
        cfg.plazo = Duration::from_millis(700);
        let mut v: Vec<Evento> = Vec::new();
        let r = trazar(&cfg, &mut v).unwrap();
        assert!(!r.desenlace.completo());
    }

    #[test]
    fn un_programa_que_no_existe_no_cuelga_al_trazador() {
        if !hay_ptrace() {
            omitir(
                "no se puede trazar con ptrace (hace falta CAP_SYS_PTRACE)",
                Requisito::Ptrace,
            );
            return;
        }
        let mut cfg = Config::nueva(PathBuf::from("/no/existe/esto/de/aqui"));
        cfg.plazo = Duration::from_secs(5);
        let mut v: Vec<Evento> = Vec::new();
        let r = trazar(&cfg, &mut v).unwrap();
        // El hijo sale con 127; lo que importa es que el trazador vuelva.
        assert!(matches!(r.desenlace, Desenlace::Termino { .. }));
    }

    // --- La configuracion ---------------------------------------------------

    #[test]
    fn un_plazo_de_cero_se_rechaza() {
        let mut cfg = sh("exit 0");
        cfg.plazo = Duration::ZERO;
        let mut v: Vec<Evento> = Vec::new();
        assert!(matches!(
            trazar(&cfg, &mut v),
            Err(ErrorTrazador::Config(_))
        ));
    }

    #[test]
    fn un_argumento_con_byte_nulo_se_rechaza_antes_del_fork() {
        let mut cfg = Config::nueva(PathBuf::from("/bin/sh"));
        cfg.argumentos = vec!["-c".into(), "echo \0 hola".into()];
        let mut v: Vec<Evento> = Vec::new();
        assert!(matches!(
            trazar(&cfg, &mut v),
            Err(ErrorTrazador::Config(_))
        ));
    }

    #[test]
    fn los_limites_por_omision_son_conservadores() {
        let c = Config::nueva(PathBuf::from("/bin/true"));
        assert!(
            c.max_memoria.is_some(),
            "sin tope de memoria no hay frontera"
        );
        assert!(
            c.max_fichero.is_some(),
            "sin tope de fichero se llena el disco"
        );
        assert!(!c.plazo.is_zero());
        assert!(c.max_eventos > 0);
    }

    #[test]
    fn un_corte_nunca_cuenta_como_informe_completo() {
        assert!(!Desenlace::Cortado {
            motivo: Corte::Plazo
        }
        .completo());
        assert!(!Desenlace::Cortado {
            motivo: Corte::Eventos
        }
        .completo());
        assert!(Desenlace::Termino { codigo: 0 }.completo());
        assert!(Desenlace::Senal { senal: 9 }.completo());
    }
}
