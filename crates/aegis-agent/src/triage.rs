//! Triaje de eventos: camino rapido y escalado.
//!
//! El colector recibe del orden de 10^3 a 10^5 eventos por segundo. Pasarlos
//! todos por el motor de heuristica costaria mas CPU que todo el resto del
//! producto junto, asi que la mayoria tiene que morir aqui, en decenas de
//! nanosegundos y sin reservar memoria.
//!
//! El triaje decide entre tres destinos:
//!
//! - [`Verdict::Discard`]: ruido conocido. Ni siquiera entra al grafo.
//! - [`Verdict::Record`]: actualiza el grafo y el estado conductual, y ahi
//!   acaba. Es el destino de la inmensa mayoria de lo que no es ruido.
//! - [`Verdict::Escalate`]: va a la cola del motor de heuristica.
//!
//! La regla que ordena el modulo: **el camino rapido nunca reserva memoria ni
//! recorre el grafo**. Consulta las marcas del actor, que es una busqueda en un
//! mapa concurrente, y compara prefijos de ruta. Reconstruir el linaje es cosa
//! del camino lento, sobre los pocos eventos que llegan a el.

use std::sync::Arc;

use dashmap::DashMap;

use crate::graph::{is_temp_path, ImageClass, ProcKey, ProcessGraph, TaintSet};

/// Evento de telemetria ya decodificado desde el ABI.
///
/// El triaje trabaja sobre este tipo y no sobre los bytes crudos para poder
/// probarse entero sin kernel: la logica de decision es la parte del agente que
/// mas necesita cobertura y la que menos deberia depender de poder cargar
/// programas eBPF.
#[derive(Debug, Clone)]
pub enum TelemetryEvent {
    /// Intento de ejecucion de una imagen.
    Exec {
        /// Identidad del proceso que ejecuta.
        actor: ProcKey,
        /// PID.
        pid: u32,
        /// Padre.
        parent: ProcKey,
        /// Ruta de la imagen.
        image: Arc<str>,
        /// Linea de comandos.
        cmdline: Arc<str>,
        /// Instante de arranque del proceso.
        started_ns: u64,
        /// Instante del evento.
        ts_ns: u64,
    },
    /// Apertura con intencion de escritura.
    FileWrite {
        /// Actor.
        actor: ProcKey,
        /// PID.
        pid: u32,
        /// Ruta afectada.
        path: Arc<str>,
        /// Banderas de `openat`.
        flags: u32,
        /// Instante del evento.
        ts_ns: u64,
    },
    /// Llamada a `ptrace` sobre otro proceso.
    Ptrace {
        /// Actor.
        actor: ProcKey,
        /// PID origen.
        source_pid: u32,
        /// PID objetivo.
        target_pid: u32,
        /// Peticion de ptrace.
        request: u32,
        /// Indica si la peticion escribe en la memoria del objetivo.
        writes_memory: bool,
        /// Instante del evento.
        ts_ns: u64,
    },
    /// Fin de proceso.
    Exit {
        /// Actor.
        actor: ProcKey,
        /// Instante del evento.
        ts_ns: u64,
    },
    /// Escritura con muestra del buffer, del sondeo de `sys_enter_write`.
    ///
    /// Llega con descriptor y sin ruta: el kernel no puede resolver un `fd` a
    /// una ruta en el camino caliente sin recorrer estructuras que el
    /// verificador no permite recorrer. La ruta la aporta el evento
    /// [`TelemetryEvent::FdBind`] emitido al salir de `openat`.
    FileWriteSample {
        /// Actor.
        actor: ProcKey,
        /// PID.
        pid: u32,
        /// Descriptor sobre el que se escribio.
        fd: i32,
        /// Bytes que el proceso pidio escribir.
        bytes: u64,
        /// Muestra del principio del buffer, vacia si el kernel no muestreo.
        sample: Arc<[u8]>,
        /// Valores de byte distintos en la muestra, contados en el kernel.
        distinct_bytes: u16,
        /// Instante del evento.
        ts_ns: u64,
    },
    /// Asociacion descriptor -> ruta, del sondeo de salida de `openat`.
    FdBind {
        /// Actor.
        actor: ProcKey,
        /// PID.
        pid: u32,
        /// Descriptor devuelto.
        fd: i32,
        /// Ruta abierta.
        path: Arc<str>,
        /// Banderas de apertura.
        open_flags: u32,
        /// Instante del evento.
        ts_ns: u64,
    },
    /// Renombrado de un fichero.
    FileRename {
        /// Actor.
        actor: ProcKey,
        /// PID.
        pid: u32,
        /// Ruta de origen.
        from: Arc<str>,
        /// Ruta de destino.
        to: Arc<str>,
        /// Instante del evento.
        ts_ns: u64,
    },
    /// Establecimiento de conexion TCP.
    NetConnect {
        /// Actor.
        actor: ProcKey,
        /// PID.
        pid: u32,
        /// Direccion destino, siempre en 16 bytes.
        daddr: [u8; 16],
        /// Puerto destino.
        dport: u16,
        /// Familia de direcciones.
        family: u16,
        /// Indica si el destino es la propia maquina.
        loopback: bool,
        /// Indica si el destino esta en rango privado.
        private_dst: bool,
        /// Instante del evento.
        ts_ns: u64,
    },
}

impl TelemetryEvent {
    /// Actor del evento.
    pub fn actor(&self) -> ProcKey {
        match self {
            TelemetryEvent::Exec { actor, .. }
            | TelemetryEvent::FileWrite { actor, .. }
            | TelemetryEvent::FileWriteSample { actor, .. }
            | TelemetryEvent::FdBind { actor, .. }
            | TelemetryEvent::FileRename { actor, .. }
            | TelemetryEvent::Ptrace { actor, .. }
            | TelemetryEvent::Exit { actor, .. }
            | TelemetryEvent::NetConnect { actor, .. } => *actor,
        }
    }

    /// Instante del evento.
    pub fn ts_ns(&self) -> u64 {
        match self {
            TelemetryEvent::Exec { ts_ns, .. }
            | TelemetryEvent::FileWrite { ts_ns, .. }
            | TelemetryEvent::FileWriteSample { ts_ns, .. }
            | TelemetryEvent::FdBind { ts_ns, .. }
            | TelemetryEvent::FileRename { ts_ns, .. }
            | TelemetryEvent::Ptrace { ts_ns, .. }
            | TelemetryEvent::Exit { ts_ns, .. }
            | TelemetryEvent::NetConnect { ts_ns, .. } => *ts_ns,
        }
    }
}

/// Motivo por el que un evento se descarta en el camino rapido.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DiscardReason {
    /// Sistema de ficheros virtual: `/proc`, `/sys`, `/dev`.
    VirtualFilesystem,
    /// Estado efimero de servicios: `/run`.
    RuntimeState,
    /// Ruido de compilacion: el actor pertenece a un arbol de build y escribe
    /// en un directorio de artefactos.
    BuildArtifact,
    /// Trafico contra la propia maquina.
    Loopback,
}

/// Motivo por el que un evento escala al motor de heuristica.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EscalationReason {
    /// Un proceso manipula la memoria de otro.
    CrossProcessMemory,
    /// Escritura sobre credenciales del sistema.
    CredentialStore,
    /// Escritura sobre un mecanismo de arranque o persistencia.
    PersistenceMechanism,
    /// Escritura sobre un binario del sistema.
    SystemBinary,
    /// Escritura sobre el cargador dinamico: precarga de bibliotecas.
    DynamicLoader,
    /// Ejecucion desde un directorio temporal con linaje sospechoso.
    SuspiciousExecOrigin,
    /// Cadena de ejecucion caracteristica de abuso de aplicacion ofimatica o
    /// navegador.
    LivingOffTheLand,
    /// Conexion saliente a un destino publico desde un proceso contaminado.
    TaintedEgress,
    /// La puntuacion conductual acumulada supero el umbral.
    BehaviorThreshold,
}

/// Escalado al motor de heuristica.
#[derive(Debug, Clone)]
pub struct Escalation {
    /// Motivo principal.
    pub reason: EscalationReason,
    /// Puntuacion conductual del actor tras aplicar este evento.
    pub score: u32,
    /// Evento que lo origina.
    pub event: TelemetryEvent,
}

/// Destino de un evento tras el triaje.
#[derive(Debug, Clone)]
pub enum Verdict {
    /// Ruido: se descarta sin tocar el grafo.
    Discard(DiscardReason),
    /// Se contabiliza en el grafo y ahi acaba.
    Record,
    /// Va a la cola del motor de heuristica.
    Escalate(Box<Escalation>),
}

/// Sensibilidad de una ruta del sistema de ficheros.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PathSensitivity {
    /// Ruido conocido, sin valor forense.
    Noise,
    /// Sin significado especial.
    Normal,
    /// Almacen de credenciales.
    Credentials,
    /// Mecanismo de arranque o persistencia.
    Persistence,
    /// Binario o biblioteca del sistema.
    SystemBinary,
    /// Configuracion del cargador dinamico.
    DynamicLoader,
}

/// Clasifica una ruta por su significado para la seguridad del sistema.
///
/// El orden de las comprobaciones importa: `/etc/ld.so.preload` tiene que
/// resolverse antes que el prefijo generico `/etc/`, porque su significado es
/// mucho mas especifico.
pub fn classify_path(path: &str) -> PathSensitivity {
    // 1. Ruido: se comprueba primero porque es el caso mas frecuente con
    //    diferencia, y el camino rapido se optimiza para el caso frecuente.
    const NOISE: [&str; 6] = [
        "/proc/",
        "/sys/",
        "/dev/",
        "/run/",
        "/var/log/journal/",
        "/tmp/.X11",
    ];
    if NOISE.iter().any(|p| path.starts_with(p)) {
        return PathSensitivity::Noise;
    }

    // 2. Cargador dinamico. ld.so.preload es la persistencia mas silenciosa que
    //    existe en Linux: una linea ahi inyecta una biblioteca en CADA proceso
    //    que arranque despues.
    if path == "/etc/ld.so.preload"
        || path.starts_with("/etc/ld.so.conf")
        || path == "/etc/ld.so.cache"
    {
        return PathSensitivity::DynamicLoader;
    }

    // 3. Credenciales.
    const CREDENTIALS: [&str; 7] = [
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/passwd",
        "/etc/sudoers",
        "/etc/security/",
        "/etc/pam.d/",
        "/etc/krb5.keytab",
    ];
    if CREDENTIALS.iter().any(|p| path.starts_with(p)) {
        return PathSensitivity::Credentials;
    }
    if path.contains("/.ssh/") {
        return PathSensitivity::Credentials;
    }

    // 4. Persistencia.
    const PERSISTENCE: [&str; 9] = [
        "/etc/cron",
        "/var/spool/cron/",
        "/etc/systemd/system/",
        "/usr/lib/systemd/system/",
        "/lib/systemd/system/",
        "/etc/init.d/",
        "/etc/rc.local",
        "/etc/profile",
        "/etc/xdg/autostart/",
    ];
    if PERSISTENCE.iter().any(|p| path.starts_with(p)) {
        return PathSensitivity::Persistence;
    }
    // Persistencia por perfil de usuario.
    if path.ends_with("/.bashrc")
        || path.ends_with("/.bash_profile")
        || path.ends_with("/.profile")
        || path.ends_with("/.zshrc")
        || path.contains("/.config/systemd/user/")
        || path.contains("/.config/autostart/")
    {
        return PathSensitivity::Persistence;
    }

    // 5. Binarios del sistema.
    const SYSTEM_BIN: [&str; 7] = [
        "/bin/",
        "/sbin/",
        "/usr/bin/",
        "/usr/sbin/",
        "/usr/lib/",
        "/lib/",
        "/boot/",
    ];
    if SYSTEM_BIN.iter().any(|p| path.starts_with(p)) {
        return PathSensitivity::SystemBinary;
    }

    PathSensitivity::Normal
}

/// Directorios de artefactos de compilacion.
fn is_build_artifact(path: &str) -> bool {
    const FRAGMENTS: [&str; 7] = [
        "/target/",
        "/node_modules/",
        "/.git/",
        "/__pycache__/",
        "/.cargo/registry/",
        "/CMakeFiles/",
        "/.gradle/",
    ];
    FRAGMENTS.iter().any(|f| path.contains(f)) || path.ends_with(".o") || path.ends_with(".d")
}

/// Umbrales del triaje.
#[derive(Debug, Clone, Copy)]
pub struct TriageConfig {
    /// Puntuacion a partir de la cual un actor escala aunque el evento
    /// concreto no lo justifique por si solo.
    pub score_threshold: u32,
    /// Puertos cuyo destino publico no se considera relevante por si mismo.
    pub quiet_ports: [u16; 4],
    /// Ventana durante la cual dos procesos siguen considerandose la misma
    /// sesion de trazado.
    pub ptrace_session_ns: u64,
    /// Numero maximo de sesiones de trazado en seguimiento simultaneo.
    pub max_ptrace_sessions: usize,
}

impl Default for TriageConfig {
    fn default() -> Self {
        Self {
            score_threshold: 60,
            // HTTP, HTTPS, DNS y NTP salientes son el fondo de ruido de
            // cualquier maquina. Solo escalan si el actor esta contaminado.
            quiet_ports: [80, 443, 53, 123],
            // Una sesion de depuracion dura minutos; 5 es holgado sin permitir
            // que un atacante se reenganche indefinidamente sin volver a alertar.
            ptrace_session_ns: 300 * 1_000_000_000,
            max_ptrace_sessions: 4096,
        }
    }
}

/// Estado de una relacion de trazado entre dos procesos.
#[derive(Debug, Clone, Copy)]
struct PtraceSession {
    /// Instante del primer enganche.
    first_ns: u64,
    /// Si ya se escalo por escritura en la memoria del objetivo.
    escalated_write: bool,
}

/// Motor de triaje.
#[derive(Debug)]
pub struct Triage {
    config: TriageConfig,
    /// Relaciones de trazado ya vistas, por (trazador, PID objetivo).
    ///
    /// Existe porque un depurador genera CIENTOS de llamadas a `ptrace` por
    /// sesion: un solo `strace` produjo 140 escalados en una prueba real contra
    /// el kernel. La senal util es "A se engancho a B", no "A hizo su
    /// PTRACE_PEEKDATA numero 87". Sin esta deduplicacion, el motor de
    /// heuristica recibe el mismo hecho repetido y la alerta util se ahoga.
    ptrace_sessions: DashMap<(ProcKey, u32), PtraceSession>,
}

impl Triage {
    /// Crea un motor de triaje.
    pub fn new(config: TriageConfig) -> Self {
        Self {
            config,
            ptrace_sessions: DashMap::new(),
        }
    }

    /// Olvida las sesiones de trazado mas antiguas que la ventana configurada.
    ///
    /// Se llama desde el mantenimiento periodico, no por evento: sin esto, el
    /// mapa crece con cada par (trazador, objetivo) que haya existido en la
    /// vida del agente.
    pub fn prune_sessions(&self, now_ns: u64) -> usize {
        let ventana = self.config.ptrace_session_ns;
        let antes = self.ptrace_sessions.len();
        self.ptrace_sessions
            .retain(|_, v| now_ns.saturating_sub(v.first_ns) < ventana);
        antes - self.ptrace_sessions.len()
    }

    /// Numero de sesiones de trazado en seguimiento.
    pub fn tracked_ptrace_sessions(&self) -> usize {
        self.ptrace_sessions.len()
    }

    /// Clasifica un evento.
    ///
    /// `graph` se consulta solo para leer marcas y puntuacion del actor, que
    /// son busquedas O(1); no se recorre el linaje.
    pub fn classify(&self, graph: &ProcessGraph, ev: &TelemetryEvent) -> Verdict {
        match ev {
            TelemetryEvent::Exit { .. } => Verdict::Record,
            TelemetryEvent::Ptrace { .. } => self.classify_ptrace(graph, ev),
            TelemetryEvent::FileWrite { .. } => self.classify_file(graph, ev),
            TelemetryEvent::Exec { .. } => self.classify_exec(graph, ev),
            TelemetryEvent::NetConnect { .. } => self.classify_net(graph, ev),
            // El renombrado se clasifica por la ruta de destino: mover un
            // binario a `/usr/bin` importa tanto como escribirlo ahi.
            TelemetryEvent::FileRename { .. } => self.classify_file(graph, ev),
            // Estos dos no pasan por el triaje conductual: van al motor
            // anti-ransomware, que tiene sus propias senales y su propio
            // presupuesto. Contarlos aqui ademas inflaria la puntuacion de
            // cualquier proceso que escriba mucho, que es casi cualquier
            // proceso.
            TelemetryEvent::FileWriteSample { .. } | TelemetryEvent::FdBind { .. } => {
                Verdict::Record
            }
        }
    }

    fn escalate(
        &self,
        graph: &ProcessGraph,
        ev: &TelemetryEvent,
        reason: EscalationReason,
        points: u32,
    ) -> Verdict {
        let score = graph
            .with_behavior(ev.actor(), |b| b.add_score(points, ev.ts_ns()))
            .unwrap_or(points);
        Verdict::Escalate(Box::new(Escalation {
            reason,
            score,
            event: ev.clone(),
        }))
    }

    /// Suma puntos sin escalar, y escala solo si el acumulado cruza el umbral.
    ///
    /// Es lo que permite detectar al proceso que hace muchas cosas levemente
    /// raras sin que ninguna de ellas, por separado, merezca una alerta.
    fn accrue(
        &self,
        graph: &ProcessGraph,
        ev: &TelemetryEvent,
        reason: EscalationReason,
        points: u32,
    ) -> Verdict {
        let score = graph
            .with_behavior(ev.actor(), |b| b.add_score(points, ev.ts_ns()))
            .unwrap_or(points);
        if score >= self.config.score_threshold {
            return Verdict::Escalate(Box::new(Escalation {
                reason: EscalationReason::BehaviorThreshold,
                score,
                event: ev.clone(),
            }));
        }
        let _ = reason;
        Verdict::Record
    }

    fn classify_ptrace(&self, graph: &ProcessGraph, ev: &TelemetryEvent) -> Verdict {
        let TelemetryEvent::Ptrace {
            actor,
            source_pid,
            target_pid,
            writes_memory,
            ts_ns,
            ..
        } = ev
        else {
            unreachable!("classify_ptrace solo recibe eventos Ptrace")
        };

        graph.with_behavior(*actor, |b| {
            b.ptrace_calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        });

        // Un proceso trazandose a si mismo no cruza ninguna frontera. El kernel
        // ya filtra PTRACE_TRACEME, pero un proceso puede pasar su propio PID.
        if source_pid == target_pid {
            return Verdict::Record;
        }

        let clave = (*actor, *target_pid);

        // Se decide el destino con la guarda del fragmento ya liberada: hacer
        // el escalado con la entrada bloqueada mantendria un lock de DashMap
        // vivo mientras se consulta el grafo (ver invariante de graph.rs).
        enum Accion {
            PrimerEnganche,
            AsciendeAEscritura,
            YaConocida,
        }

        let accion = match self.ptrace_sessions.get_mut(&clave) {
            Some(mut sesion) => {
                if *writes_memory && !sesion.escalated_write {
                    sesion.escalated_write = true;
                    Accion::AsciendeAEscritura
                } else {
                    Accion::YaConocida
                }
            }
            None => {
                // Cota dura del mapa: si se llena, se deja de deduplicar en vez
                // de crecer sin limite. Escalar de mas es preferible a que el
                // agente se coma la memoria de la maquina que protege.
                if self.ptrace_sessions.len() < self.config.max_ptrace_sessions {
                    self.ptrace_sessions.insert(
                        clave,
                        PtraceSession {
                            first_ns: *ts_ns,
                            escalated_write: *writes_memory,
                        },
                    );
                }
                Accion::PrimerEnganche
            }
        };

        match accion {
            // El primer enganche de A sobre B es el hecho que hay que alertar.
            Accion::PrimerEnganche => {
                let puntos = if *writes_memory { 50 } else { 25 };
                self.escalate(graph, ev, EscalationReason::CrossProcessMemory, puntos)
            }
            // Pasar de leer a ESCRIBIR en la memoria del objetivo es un cambio
            // real de severidad: observar es depurar, escribir es inyectar.
            Accion::AsciendeAEscritura => {
                self.escalate(graph, ev, EscalationReason::CrossProcessMemory, 50)
            }
            // El resto de la sesion no aporta informacion nueva y NO suma
            // puntuacion. Acumular aunque fuera de uno en uno haria que 200
            // llamadas de un `strace` normal cruzaran el umbral por si solas,
            // que es exactamente el ruido que la deduplicacion elimina. Si el
            // trazador ademas hace otras cosas raras, esas si acumulan y
            // cruzaran el umbral por su cuenta.
            Accion::YaConocida => Verdict::Record,
        }
    }

    fn classify_file(&self, graph: &ProcessGraph, ev: &TelemetryEvent) -> Verdict {
        // El renombrado se juzga por su DESTINO: mover un binario a
        // `/usr/bin/` tiene el mismo efecto que escribirlo ahi, y un atacante
        // que prepara el fichero en `/tmp` y lo mueve despues esquivaria un
        // triaje que solo mirase el origen.
        let (actor, path) = match ev {
            TelemetryEvent::FileWrite { actor, path, .. } => (actor, path),
            TelemetryEvent::FileRename { actor, to, .. } => (actor, to),
            _ => unreachable!("classify_file solo recibe eventos de fichero"),
        };

        let taints = graph.taints(*actor);

        match classify_path(path) {
            PathSensitivity::Noise => {
                let reason = if path.starts_with("/run/") {
                    DiscardReason::RuntimeState
                } else {
                    DiscardReason::VirtualFilesystem
                };
                return Verdict::Discard(reason);
            }
            PathSensitivity::DynamicLoader => {
                return self.escalate(graph, ev, EscalationReason::DynamicLoader, 80);
            }
            PathSensitivity::Credentials => {
                return self.escalate(graph, ev, EscalationReason::CredentialStore, 70);
            }
            PathSensitivity::Persistence => {
                return self.escalate(graph, ev, EscalationReason::PersistenceMechanism, 60);
            }
            PathSensitivity::SystemBinary => {
                // Un gestor de paquetes reescribiendo /usr/bin es su trabajo.
                // Sin esta excepcion, cada `apt upgrade` seria un incidente.
                if taints.contains(TaintSet::BUILD_SYSTEM) {
                    return Verdict::Record;
                }
                return self.escalate(graph, ev, EscalationReason::SystemBinary, 65);
            }
            PathSensitivity::Normal => {}
        }

        // Ruido de compilacion: un arbol de build escribe cientos de miles de
        // ficheros de artefactos. Se descarta antes de tocar el grafo.
        if taints.contains(TaintSet::BUILD_SYSTEM) && is_build_artifact(path) {
            return Verdict::Discard(DiscardReason::BuildArtifact);
        }

        graph.with_behavior(*actor, |b| {
            b.writes.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        });
        Verdict::Record
    }

    fn classify_exec(&self, graph: &ProcessGraph, ev: &TelemetryEvent) -> Verdict {
        let TelemetryEvent::Exec { actor, image, .. } = ev else {
            unreachable!("classify_exec solo recibe eventos Exec")
        };

        let taints = graph.taints(*actor);
        let clase = crate::graph::classify_image(image);

        // Cadena de "living off the land": un descendiente de aplicacion
        // ofimatica o de navegador lanzando un interprete. La regla no mira el
        // nombre del proceso que ejecuta, que el atacante cambia trivialmente,
        // sino el ORIGEN de la cadena, que no puede falsificar sin comprometer
        // antes el proceso de origen.
        let origen_documental = taints.intersects(TaintSet::OFFICE_CHILD | TaintSet::BROWSER_CHILD);
        if origen_documental && matches!(clase, ImageClass::Shell | ImageClass::Interpreter) {
            return self.escalate(graph, ev, EscalationReason::LivingOffTheLand, 75);
        }

        // Ejecutar desde un directorio temporal es normal en compilaciones e
        // instaladores; deja de serlo cuando ademas el linaje viene de un
        // documento, de la red o de una sesion remota.
        if is_temp_path(image) {
            let linaje_sospechoso = taints.intersects(
                TaintSet::OFFICE_CHILD
                    | TaintSet::BROWSER_CHILD
                    | TaintSet::FROM_INTERNET
                    | TaintSet::REMOTE_ORIGIN,
            );
            if linaje_sospechoso && !taints.contains(TaintSet::BUILD_SYSTEM) {
                return self.escalate(graph, ev, EscalationReason::SuspiciousExecOrigin, 55);
            }
            return self.accrue(graph, ev, EscalationReason::SuspiciousExecOrigin, 10);
        }

        Verdict::Record
    }

    fn classify_net(&self, graph: &ProcessGraph, ev: &TelemetryEvent) -> Verdict {
        let TelemetryEvent::NetConnect {
            actor,
            dport,
            loopback,
            private_dst,
            ..
        } = ev
        else {
            unreachable!("classify_net solo recibe eventos NetConnect")
        };

        if *loopback {
            return Verdict::Discard(DiscardReason::Loopback);
        }
        if *private_dst {
            return Verdict::Record;
        }

        graph.with_behavior(*actor, |b| {
            b.public_connections
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        });

        let taints = graph.taints(*actor);
        let contaminado = taints.intersects(
            TaintSet::OFFICE_CHILD
                | TaintSet::BROWSER_CHILD
                | TaintSet::FROM_INTERNET
                | TaintSet::FROM_TEMP,
        );

        // Un navegador hablando por 443 es su trabajo; un descendiente de un
        // documento haciendo lo mismo es exfiltracion o C2 hasta que se
        // demuestre lo contrario.
        if contaminado {
            return self.escalate(graph, ev, EscalationReason::TaintedEgress, 45);
        }

        // Puerto fuera del ruido de fondo: acumula sin alertar todavia.
        if !self.config.quiet_ports.contains(dport) {
            return self.accrue(graph, ev, EscalationReason::TaintedEgress, 15);
        }

        Verdict::Record
    }
}

impl Default for Triage {
    fn default() -> Self {
        Self::new(TriageConfig::default())
    }
}
