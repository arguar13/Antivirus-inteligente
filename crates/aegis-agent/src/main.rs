//! Binario del agente de AegisCore.
//!
//! Engancha las sondas de kernel, consume la telemetria y la entrega al arbitro,
//! que la reparte a los motores registrados y combina lo que dicen. Publica un
//! veredicto cuando el de una entidad cambia a algo que hay que atender.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(all(target_os = "linux", feature = "bpf"))]
use aegis_agent::motores::baliza::MotorBaliza;
#[cfg(all(target_os = "linux", feature = "bpf"))]
use aegis_agent::motores::conducta::MotorConducta;
#[cfg(all(target_os = "linux", feature = "bpf"))]
use aegis_agent::motores::estatico::{EstadoAnalista, MotorEstatico, MotorModelo, Resultado};
#[cfg(all(target_os = "linux", feature = "bpf"))]
use aegis_agent::motores::integridad::MotorIntegridad;
#[cfg(all(target_os = "linux", feature = "bpf"))]
use aegis_agent::motores::memoria::MotorMemoria;
#[cfg(all(target_os = "linux", feature = "bpf"))]
use aegis_agent::motores::nucleo::MotorNucleo;
#[cfg(all(target_os = "linux", feature = "bpf"))]
use aegis_agent::motores::postura::MotorPostura;
#[cfg(all(target_os = "linux", feature = "bpf"))]
use aegis_agent::motores::rol::{ConfigRol, MotorRol};
#[cfg(all(target_os = "linux", feature = "bpf"))]
use aegis_agent::motores::secuestro::MotorSecuestro;
#[cfg(all(target_os = "linux", feature = "bpf"))]
use aegis_agent::motores::triaje::MotorTriaje;
#[cfg(all(target_os = "linux", feature = "bpf"))]
use aegis_agent::motores::{EventoAgente, HostAgente, Identidad};
#[cfg(all(target_os = "linux", feature = "bpf"))]
use aegis_agent::plano::PlanoControl;
use aegis_agent::{GraphConfig, Pipeline, TriageConfig};
#[cfg(all(target_os = "linux", feature = "bpf"))]
use aegis_motor::{Arbitro, ConfigArbitro};

/// Bandera de parada. La toca el manejador de senales, que solo puede usar
/// operaciones seguras en ese contexto: un store atomico lo es, imprimir o
/// reservar memoria no.
static PARAR: AtomicBool = AtomicBool::new(false);

#[cfg(all(target_os = "linux", feature = "bpf"))]
extern "C" fn manejar_senal(_sig: libc::c_int) {
    PARAR.store(true, Ordering::Relaxed);
}

#[cfg(all(target_os = "linux", feature = "bpf"))]
fn instalar_manejadores() {
    // SAFETY: se instala un manejador que solo hace un store atomico
    // `Relaxed`, que es seguro en contexto de senal. No reserva memoria, no
    // toma locks y no llama a funciones no reentrantes.
    unsafe {
        // El doble cast pasando por *const () es obligatorio: convertir un
        // item de funcion directamente a entero es un lint denegado, porque el
        // tamano del item de funcion no es el de un puntero en toda plataforma.
        let manejador = manejar_senal as *const () as libc::sighandler_t;
        libc::signal(libc::SIGINT, manejador);
        libc::signal(libc::SIGTERM, manejador);
    }
}

/// Lo que se le pidio al agente por linea de ordenes.
struct Opciones {
    intervalo: Duration,
    harden: bool,
    control_socket: Option<String>,
    latido: std::path::PathBuf,
    plano_control: Option<std::path::PathBuf>,
}

/// Ruta del latido que lee el watchdog (`aegis-watchdog --heartbeat`).
const LATIDO_POR_DEFECTO: &str = "/run/aegiscore/agent.heartbeat";

/// Cada cuanto, como mucho, se mantiene el arbitro y se recoge lo que el camino
/// frio de los motores termino. Cada motor se dosifica despues por su cuenta:
/// esto solo acota la frecuencia del recorrido.
#[cfg(all(target_os = "linux", feature = "bpf"))]
const MANTENER_CADA: Duration = Duration::from_secs(1);

const AYUDA: &str = "aegis-agent - agente de deteccion de AegisCore
     
     USO: aegis-agent [--stats-interval SEGUNDOS] [--harden]
          [--control-socket RUTA] [--latido RUTA] [--plano-control RUTA]
          aegis-agent --capacidades [--maquina]
     
     --capacidades  informa de lo que ofrece este kernel (BTF, tracefs,
                    ringbuf, BPF LSM, cgroup, SELinux/AppArmor, lockdown)
                    y de lo que se degrada; sale con 3 si no habria
                    telemetria de kernel. Con --maquina, lineas AEGIS-CAP/DEG.
     --latido RUTA  donde escribe el latido que vigila aegis-watchdog
                    (por defecto /run/aegiscore/agent.heartbeat).
     --plano-control RUTA  enlace con el plano de control, en solo
                    auditoria (por defecto /etc/aegiscore/plano-control.toml;
                    sin ese fichero el agente protege en local y no reporta).
     
     Requiere CAP_BPF y CAP_PERFMON (o root) para cargar las sondas,
     y un kernel con CONFIG_DEBUG_INFO_BTF=y. Para confinar a su
     trabajador de analisis necesita ademas ser root.";

/// Interpreta los argumentos, y RECHAZA los que no conoce.
///
/// Antes se buscaban las opciones conocidas y se ignoraba el resto: la unidad de
/// systemd del despliegue le pasaba `--config agente.toml` y el agente arrancaba
/// sin configuracion y sin decirlo (FASE 1 del MP-16). Una opcion que no se
/// entiende es un error de quien lanza el agente, y tiene que verse al arrancar.
fn opciones(args: &[String]) -> Result<Opciones, String> {
    let mut o = Opciones {
        intervalo: Duration::from_secs(10),
        harden: false,
        control_socket: None,
        latido: LATIDO_POR_DEFECTO.into(),
        plano_control: None,
    };
    let mut i = 1;
    while i < args.len() {
        let valor = |i: usize| {
            args.get(i + 1)
                .cloned()
                .ok_or_else(|| format!("{} necesita un valor", args[i]))
        };
        match args[i].as_str() {
            "--stats-interval" => {
                let v = valor(i)?;
                o.intervalo =
                    Duration::from_secs(v.parse().map_err(|_| {
                        format!("--stats-interval: «{v}» no es un numero de segundos")
                    })?);
                i += 2;
            }
            "--control-socket" => {
                o.control_socket = Some(valor(i)?);
                i += 2;
            }
            "--latido" => {
                o.latido = valor(i)?.into();
                i += 2;
            }
            "--plano-control" => {
                o.plano_control = Some(valor(i)?.into());
                i += 2;
            }
            "--harden" => {
                o.harden = true;
                i += 1;
            }
            otra => return Err(format!("opcion desconocida: {otra}")),
        }
    }
    Ok(o)
}

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().collect();

    // El trabajador confinado es este mismo binario. Se decide lo PRIMERO: antes
    // de blindar, de sondear el kernel o de tocar nada que el trabajador no
    // necesite, porque todo eso son llamadas que su confinamiento no permite.
    #[cfg(target_os = "linux")]
    aegis_agent::motores::estatico::servir_si_es_trabajador(&args);

    if args.iter().any(|a| a == "-h" || a == "--help") {
        eprintln!("{AYUDA}");
        return std::process::ExitCode::SUCCESS;
    }

    if args.get(1).map(String::as_str) == Some("--capacidades") {
        return match args.get(2).map(String::as_str) {
            None => informar_capacidades(false),
            Some("--maquina") if args.len() == 3 => informar_capacidades(true),
            Some(otra) => {
                eprintln!("aegis-agent: opcion desconocida tras --capacidades: {otra}");
                std::process::ExitCode::from(2)
            }
        };
    }

    let o = match opciones(&args) {
        Ok(o) => o,
        Err(m) => {
            eprintln!(
                "aegis-agent: {m}

{AYUDA}"
            );
            return std::process::ExitCode::from(2);
        }
    };

    blindar(o.harden);
    ejecutar(o)
}

/// Capacidades del kernel, con el sondeo directo por `bpf()` si se compilo con
/// la caracteristica `bpf`.
fn capacidades() -> aegis_agent::capacidades::Capacidades {
    #[cfg(all(target_os = "linux", feature = "bpf"))]
    {
        aegis_agent::bpf::capacidades()
    }
    #[cfg(not(all(target_os = "linux", feature = "bpf")))]
    {
        use aegis_agent::capacidades::{detectar_en, SondeoBpf};
        detectar_en(
            std::path::Path::new("/"),
            SondeoBpf::no_realizado("agente compilado sin la caracteristica bpf"),
        )
    }
}

/// `--capacidades`: el informe, y un codigo de salida que un script puede usar
/// sin leerlo (3 = no habria telemetria de kernel).
fn informar_capacidades(maquina: bool) -> std::process::ExitCode {
    use aegis_agent::capacidades::{informe, plan_degradacion, salida_maquina};
    let caps = capacidades();
    let plan = plan_degradacion(&caps);
    if maquina {
        print!("{}", salida_maquina(&caps, &plan));
    } else {
        print!("{}", informe(&caps, &plan));
    }
    if plan.iter().any(|d| d.bloquea_telemetria) {
        std::process::ExitCode::from(3)
    } else {
        std::process::ExitCode::SUCCESS
    }
}

/// Fuente de estado para el canal de control, respaldada por el pipeline.
///
/// Solo lee contadores atomicos, asi que compartir el pipeline con el hilo de
/// control no introduce contencion ni bloqueos con el bucle de eventos.
#[cfg(all(target_os = "linux", feature = "bpf"))]
struct EstadoPipeline {
    pipeline: Arc<Pipeline>,
    /// Las lineas del ultimo informe: las mismas que van al registro.
    informe: Arc<std::sync::Mutex<Vec<String>>>,
}

#[cfg(all(target_os = "linux", feature = "bpf"))]
impl aegis_ctl::StatusSource for EstadoPipeline {
    fn events_received(&self) -> u64 {
        self.pipeline
            .stats
            .received
            .load(std::sync::atomic::Ordering::Relaxed)
    }
    fn events_escalated(&self) -> u64 {
        self.pipeline
            .stats
            .escalated
            .load(std::sync::atomic::Ordering::Relaxed)
    }
    fn state(&self) -> String {
        "running".to_string()
    }
    fn detalle(&self) -> Vec<String> {
        self.informe.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

/// Blindaje del agente (FASE 13).
///
/// Descifra en memoria la tabla de cadenas criticas y comprueba si hay un
/// depurador adjunto. La respuesta AGRESIVA (`PTRACE_TRACEME` + cierre ante un
/// depurador) es opcional y se activa con `--harden`, no por defecto, por una
/// razon operativa concreta: un proceso que reclama el trazador convierte la
/// senal de parada del propio sistema (SIGTERM) en una parada de trazado en vez
/// de una terminacion, con lo que un supervisor que lo detenga con `kill` se
/// quedaria esperando. En produccion, donde el agente lo lanza el watchdog y no
/// un supervisor generico, se pasa `--harden`.
fn blindar(agresivo: bool) {
    match aegis_harden::unseal_builtin() {
        Ok(vault) => {
            // Se informa del NUMERO, nunca del contenido: un secreto que aparece
            // en un log deja de serlo.
            eprintln!(
                "aegis-agent: blindaje activo, {} cadenas criticas descifradas en memoria",
                vault.len()
            );
        }
        Err(e) => {
            // Que el binario no pueda descifrar sus propias cadenas indica una
            // tabla corrupta o manipulada: es un fallo de integridad, no un
            // aviso. Se sigue arrancando porque la deteccion no depende de esas
            // cadenas, pero se deja constancia ruidosa.
            eprintln!("aegis-agent: AVISO de integridad - no se descifro el blindaje: {e}");
        }
    }

    // Comprobacion pasiva SIEMPRE: no reclama el trazador ni cierra el proceso,
    // asi que es segura bajo cualquier supervisor.
    let chequeo = aegis_harden::detect();
    if chequeo.detected {
        eprintln!(
            "aegis-agent: AVISO - depurador detectado ({:?}). La integridad de la              deteccion no se puede garantizar bajo depuracion.",
            chequeo.proc_check
        );
    }

    if agresivo {
        // Respuesta de produccion: reclama el trazador (bloquea adjuntar un
        // depurador despues) y cierra si ya habia uno.
        aegis_harden::enforce(aegis_harden::Policy::Terminate);
    }
}

/// El estado del bucle de eventos, compartido entre el callback de los eventos
/// y el pulso. Nunca se toma a la vez desde los dos: el sondeo llama a uno y
/// luego al otro, en el mismo hilo.
#[cfg(all(target_os = "linux", feature = "bpf"))]
struct Bucle {
    arbitro: Arbitro<EventoAgente>,
    ultimo_informe: Instant,
    ultimo_mantenimiento: Instant,
    ultimo_latido: Option<Instant>,
    latido_roto: bool,
}

#[cfg(all(target_os = "linux", feature = "bpf"))]
fn veredicto(v: &aegis_entidad::Veredicto, plano: Option<&PlanoControl>) {
    println!("[VEREDICTO] {} {}", v.entidad, v.resumen());
    // Al plano de control, si lo hay: un clon a una cola acotada. Ni red ni
    // serializacion en este hilo; eso lo paga el hilo del enlace.
    if let Some(p) = plano {
        p.ofrecer(v);
    }
    for s in &v.senales {
        println!(
            "[SEÑAL] {} {} {} {}: {}",
            v.entidad,
            s.motor.nombre(),
            s.severidad.nombre(),
            s.confianza,
            s.porque
        );
    }
}

/// Entrega al arbitro lo que el camino frio termino de analizar.
#[cfg(all(target_os = "linux", feature = "bpf"))]
fn drenar(
    rx: Option<&std::sync::mpsc::Receiver<Resultado>>,
    b: &mut Bucle,
    plano: Option<&PlanoControl>,
) {
    let Some(rx) = rx else { return };
    while let Ok(r) = rx.try_recv() {
        if let Some(v) = b
            .arbitro
            .aportar(r.motor, &r.entidad, r.dictamen, r.cuando_ns)
        {
            veredicto(&v, plano);
        }
    }
}

/// Un latido por segundo, como mucho. El watchdog da por colgado al agente si
/// el latido envejece mas de su `--max-age-ms` (15 s por defecto).
#[cfg(all(target_os = "linux", feature = "bpf"))]
fn latir(latido: &aegis_watchdog::Heartbeat, b: &mut Bucle) {
    if b.ultimo_latido
        .is_some_and(|t| t.elapsed() < Duration::from_secs(1))
    {
        return;
    }
    b.ultimo_latido = Some(Instant::now());
    if let Err(e) = latido.beat(aegis_watchdog::now_ns()) {
        if !b.latido_roto {
            eprintln!(
                "aegis-agent: DEGRADADO latido: no se pudo escribir {}: {e}; un watchdog que \
                 lo vigile reiniciara al agente",
                latido.path().display()
            );
            b.latido_roto = true;
        }
    } else {
        b.latido_roto = false;
    }
}

#[cfg(all(target_os = "linux", feature = "bpf"))]
fn ejecutar(o: Opciones) -> std::process::ExitCode {
    use std::cell::RefCell;

    use aegis_agent::bpf;

    instalar_manejadores();

    // Lo que este kernel ofrece y lo que se degrada, SIEMPRE al arrancar: una
    // degradacion que solo se ve pidiendola es una degradacion silenciosa.
    let caps = capacidades();
    {
        let plan = aegis_agent::capacidades::plan_degradacion(&caps);
        for linea in aegis_agent::capacidades::informe(&caps, &plan).lines() {
            eprintln!("aegis-agent: {linea}");
        }
    }

    let pipeline = Arc::new(Pipeline::new(
        GraphConfig::default(),
        TriageConfig::default(),
    ));

    // Canal de control opcional: si se pidio un socket, se levanta el servidor
    // en un hilo aparte. Lo caro del control (YARA) se carga en diferido, asi
    // que el hilo en reposo no anade memoria al presupuesto.
    let control_stop = Arc::new(AtomicBool::new(false));
    let ultimo_informe: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
    let control_hilo = o.control_socket.as_ref().and_then(|ruta| {
        match aegis_ctl::ControlServer::bind(ruta) {
            Ok(server) => {
                eprintln!("aegis-agent: canal de control en {ruta}");
                let handler = aegis_ctl::AgentControl::lazy(
                    std::path::PathBuf::from("/var/lib/aegiscore/quarantine"),
                    /*isolate_dry_run=*/ false,
                    Arc::new(EstadoPipeline {
                        pipeline: Arc::clone(&pipeline),
                        informe: Arc::clone(&ultimo_informe),
                    }),
                );
                let parar = Arc::clone(&control_stop);
                Some(std::thread::spawn(move || {
                    server.serve(&handler, &parar);
                }))
            }
            Err(e) => {
                eprintln!("aegis-agent: no se pudo abrir el canal de control: {e}");
                None
            }
        }
    });

    let config = bpf::SourceConfig::default();

    // El trabajador confinado donde corren los parsers de bytes no confiables.
    // Si no arranca o no puede confinarse lo bastante, los motores que lo
    // necesitan quedan declarados como no disponibles; el resto del agente
    // protege igual.
    let (host_trabajador, estatico, resultados, analista, hilo_analista) =
        match MotorEstatico::arrancar_con_trabajador() {
            Ok((a, declarado)) => {
                eprintln!("aegis-agent: trabajador confinado: {declarado}");
                (
                    Ok(()),
                    a.motor,
                    Some(a.resultados),
                    Some(a.estado),
                    Some(a.hilo),
                )
            }
            Err(m) => (Err(m), MotorEstatico::inerte(), None, None, None),
        };

    // La postura de aplicacion (H-28), SIEMPRE al arrancar, como las
    // capacidades: con el trabajador confinado como testigo si arranco; sin el,
    // nada puede salir aplicado. Solo se lee y se publica (solo-auditoria).
    for l in informar_aplicacion(analista.as_deref()) {
        eprintln!("aegis-agent: {l}");
    }

    // El arbitro: el UNICO que invoca motores y el unico que combina lo que
    // dicen. Cada motor se registra segun lo que este host le ofrece, y el que
    // no puede correr aqui queda declarado, nunca omitido en silencio.
    let identidad = Identidad::del_host();
    // Lo que publican por su cuenta la postura del kernel y la linea base por
    // rol (FASE 5 del MP-16): se suma al informe periodico y a `aegisctl status`.
    let informe_postura: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
    let informe_rol: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
    let mut arbitro: Arbitro<EventoAgente> = Arbitro::nuevo(ConfigArbitro::default());
    {
        let host = HostAgente::nuevo(&caps, host_trabajador);
        let rol = MotorRol::nuevo(ConfigRol::del_host(), Arc::clone(&informe_rol));
        eprintln!("aegis-agent: rol: {}", rol.resumen());
        let integridad = MotorIntegridad::nuevo(identidad.clone());
        eprintln!(
            "aegis-agent: integridad: vigila {} fichero(s): {}",
            integridad.vigilados().len(),
            integridad.vigilados().join(" ")
        );
        let motores: Vec<Box<dyn aegis_motor::Motor<EventoAgente>>> = vec![
            Box::new(MotorTriaje::nuevo(
                Arc::clone(&pipeline),
                GraphConfig::default().max_nodes,
            )),
            Box::new(MotorConducta::nuevo(identidad.clone())),
            Box::new(MotorSecuestro::nuevo(identidad.clone())),
            Box::new(estatico),
            Box::new(MotorModelo),
            Box::new(integridad),
            Box::new(MotorMemoria::nuevo()),
            Box::new(MotorNucleo::nuevo(&identidad)),
            Box::new(MotorBaliza::nuevo()),
            Box::new(MotorPostura::nuevo(
                identidad.clone(),
                Arc::clone(&informe_postura),
            )),
            Box::new(rol),
        ];
        for m in motores {
            let nombre = m.ficha().nombre;
            match arbitro.registrar(m, &host) {
                Ok(()) => eprintln!("aegis-agent: motor {nombre} registrado"),
                Err(o) => eprintln!(
                    "aegis-agent: DEGRADADO motor={} requisito={}: {}",
                    o.motor,
                    o.requisito.nombre(),
                    o.motivo
                ),
            }
        }
    }

    // El enlace con el plano de control (H-23): su propio hilo y su cola
    // acotada, en solo-auditoria. Sin configuracion no hay conexion; el agente
    // lo dice y sigue protegiendo en local.
    let plano = arrancar_plano(o.plano_control.as_deref());

    eprintln!(
        "aegis-agent: enganchando sondas (pid propio {}, excluido de la telemetria)",
        config.agent_pid
    );

    let p = Arc::clone(&pipeline);
    let latido = aegis_watchdog::Heartbeat::new(&o.latido);
    let bucle = RefCell::new(Bucle {
        arbitro,
        ultimo_informe: Instant::now(),
        ultimo_mantenimiento: Instant::now(),
        ultimo_latido: None,
        latido_roto: false,
    });

    let resultado = bpf::run_con_pulso(
        &config,
        &PARAR,
        |registro| {
            if let Some(evento) = p.decodificar(registro) {
                let evento = EventoAgente::nuevo(evento, &identidad);
                if let Some(v) = bucle.borrow_mut().arbitro.procesar(&evento) {
                    veredicto(&v, plano.as_ref());
                }
            }
        },
        |contadores| {
            let mut b = bucle.borrow_mut();
            drenar(resultados.as_ref(), &mut b, plano.as_ref());
            latir(&latido, &mut b);
            // Mantenimiento y estadisticas en el pulso, nunca por evento. El
            // camino frio de los motores entrega aqui lo que termino.
            if b.ultimo_mantenimiento.elapsed() >= MANTENER_CADA {
                b.ultimo_mantenimiento = Instant::now();
                for v in b.arbitro.mantener(bpf::ahora_boot_ns()) {
                    veredicto(&v, plano.as_ref());
                }
            }
            if b.ultimo_informe.elapsed() >= o.intervalo {
                b.ultimo_informe = Instant::now();
                let mut lineas = informar(&p, &b.arbitro, analista.as_deref());
                lineas.push(informar_kernel(contadores));
                for propio in [&informe_postura, &informe_rol] {
                    if let Ok(g) = propio.lock() {
                        lineas.extend(g.iter().cloned());
                    }
                }
                // El estado de los motores viaja con el siguiente latido al plano
                // de control; aqui solo se deja, sin red.
                if let Some(pc) = plano.as_ref() {
                    pc.publicar_estado(aegis_agent::plano::estado_motores_json(
                        &b.arbitro.estado(),
                        b.arbitro.omitidos(),
                        b.arbitro.veredictos(),
                        b.arbitro.expedientes(),
                        b.arbitro.expulsados(),
                    ));
                    lineas.push(pc.informe());
                }
                for l in &lineas {
                    eprintln!("aegis-agent: {l}");
                }
                if let Ok(mut g) = ultimo_informe.lock() {
                    *g = lineas;
                }
            }
        },
    );

    // El hilo de control se detiene cuando el bucle de eventos termina.
    control_stop.store(true, Ordering::Relaxed);
    if let Some(h) = control_hilo {
        let _ = h.join();
    }

    // El enlace se para despues del bucle. Lo que quede en su cola no se pierde
    // en silencio: se cuenta y se dice.
    if let Some(pc) = plano {
        let fin = pc.parar();
        eprintln!("aegis-agent: {}", aegis_agent::plano::resumen(&fin));
        if fin.en_cola > 0 {
            eprintln!(
                "aegis-agent: AVISO - {} veredicto(s) quedaron sin entregar al plano de \
                 control al parar",
                fin.en_cola
            );
        }
    }

    let b = bucle.into_inner();
    match resultado {
        Ok(stats) => {
            eprintln!(
                "aegis-agent: parada limpia. kernel: emitidos={} perdidos={} filtrados={} truncados={} cedidos={} perdidas_por_familia={}",
                stats.emitted,
                stats.dropped_full,
                stats.filtered,
                stats.truncated,
                stats.cedidos,
                por_familia(&stats.perdidas_por_familia)
            );
            if stats.dropped_full > 0 {
                eprintln!(
                    "aegis-agent: AVISO - {} eventos se perdieron por ring lleno. \
                     Eso es un punto ciego de deteccion, no una metrica de rendimiento.",
                    stats.dropped_full
                );
            }
            informar(&pipeline, &b.arbitro, analista.as_deref());
            cerrar_analista(b, hilo_analista);
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("aegis-agent: error fatal: {e}");
            cerrar_analista(b, hilo_analista);
            std::process::ExitCode::FAILURE
        }
    }
}

/// Arranca el enlace con el plano de control, o dice por que no.
///
/// Nunca impide arrancar al agente: sin plano de control protege igual en
/// local. Lo que no puede es callarse que no reporta.
#[cfg(all(target_os = "linux", feature = "bpf"))]
fn arrancar_plano(explicita: Option<&std::path::Path>) -> Option<PlanoControl> {
    use aegis_agent::plano;
    let ruta = explicita.unwrap_or(std::path::Path::new(plano::CONFIG_POR_DEFECTO));
    let cfg = match plano::cargar(ruta, explicita.is_some()) {
        Ok(Some(cfg)) => cfg,
        Ok(None) => {
            eprintln!(
                "aegis-agent: sin plano de control: no existe {}; el agente protege en local \
                 y no reporta",
                ruta.display()
            );
            return None;
        }
        Err(m) => {
            eprintln!(
                "aegis-agent: DEGRADADO plano de control: {m}; el agente protege en local y no \
                 reporta"
            );
            return None;
        }
    };
    match PlanoControl::arrancar(&cfg, env!("CARGO_PKG_VERSION")) {
        Ok((pc, avisos)) => {
            for a in avisos {
                eprintln!("aegis-agent: AVISO plano de control: {a}");
            }
            eprintln!(
                "aegis-agent: plano de control {} como {} (solo auditoria; cola de {} en memoria)",
                cfg.servidor,
                pc.cn(),
                aegis_presupuesto::humano(pc.capacidad_bytes() as u64)
            );
            Some(pc)
        }
        Err(m) => {
            eprintln!(
                "aegis-agent: DEGRADADO plano de control: {m}; el agente protege en local y no \
                 reporta"
            );
            None
        }
    }
}

/// Suelta el arbitro —y con el el motor estatico y su canal— y espera al hilo
/// analista, que al quedarse sin encargos mata al trabajador y borra su cgroup.
/// Sin esperar, el proceso salia antes y el cgroup quedaba huerfano.
#[cfg(all(target_os = "linux", feature = "bpf"))]
fn cerrar_analista(b: Bucle, hilo: Option<std::thread::JoinHandle<()>>) {
    drop(b);
    if let Some(h) = hilo {
        let _ = h.join();
    }
}

/// `familia=n` de las familias con perdidas, o `ninguna`.
#[cfg(all(target_os = "linux", feature = "bpf"))]
fn por_familia(p: &[(aegis_agent::capacidades::Familia, u64)]) -> String {
    let v: Vec<String> = p
        .iter()
        .filter(|(_, n)| *n > 0)
        .map(|(f, n)| format!("{}={n}", f.nombre()))
        .collect();
    if v.is_empty() {
        "ninguna".into()
    } else {
        v.join(",")
    }
}

/// Lo que el kernel lleva emitido y perdido, por familia: la perdida se ve en
/// cada informe, no solo al parar.
#[cfg(all(target_os = "linux", feature = "bpf"))]
fn informar_kernel(c: &aegis_agent::bpf::Contadores<'_>) -> String {
    format!(
        "kernel: emitidos={} perdidos={} cedidos={} perdidas_por_familia={}",
        c.emitidos(),
        c.perdidos(),
        c.cedidos(),
        por_familia(&c.perdidas_por_familia())
    )
}

/// Contadores del pipeline, del arbitro, de cada motor y del trabajador, en una
/// linea cada uno, sin el prefijo del registro.
#[cfg(all(target_os = "linux", feature = "bpf"))]
fn informar(
    p: &Pipeline,
    arbitro: &Arbitro<EventoAgente>,
    analista: Option<&std::sync::Mutex<EstadoAnalista>>,
) -> Vec<String> {
    let mut lineas = Vec::new();
    let s = p.stats.snapshot();
    lineas.push(format!(
        "pipeline: {} | nodos={} ptrace_sesiones={}",
        s.iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" "),
        p.graph.len(),
        p.triage.tracked_ptrace_sessions()
    ));
    let h = arbitro.por_evento();
    lineas.push(format!(
        "arbitro: eventos={} p50_ns={} p99_ns={} max_ns={} veredictos={} expedientes={} expulsados={}",
        h.cuenta(),
        h.percentil(50.0),
        h.percentil(99.0),
        h.maximo(),
        arbitro.veredictos(),
        arbitro.expedientes(),
        arbitro.expulsados()
    ));
    for m in arbitro.estado() {
        lineas.push(format!(
            "motor {}: camino={} evaluaciones={} senales={} p99_ns={} excesos={} suspensiones={} sin_datos={:?} memoria={}{}{}",
            m.nombre,
            m.camino.nombre(),
            m.evaluaciones,
            m.senales,
            m.latencia.percentil(99.0),
            m.excesos,
            m.suspensiones,
            m.sin_datos,
            m.memoria,
            // Lo que el motor dice de si mismo (`Motor::detalle`): el del
            // nucleo, cuanto del espacio de PID lleva mirado. Va antes del
            // motivo de «sin datos», que es texto libre y cierra la linea.
            m.detalle
                .as_deref()
                .map(|d| format!(" {d}"))
                .unwrap_or_default(),
            m.ultimo_sin_datos
                .as_deref()
                .map(|u| format!(" ultimo_sin_datos=«{u}»"))
                .unwrap_or_default()
        ));
    }
    if let Some(e) = analista.and_then(|a| a.lock().ok().map(|g| g.clone())) {
        let t = &e.trabajador;
        lineas.push(format!(
            "trabajador: arranques={} muertes={} por_memoria={} plazos={} analisis={} no_pudo={} enfriamientos={} p99_ns={} | analista: encargos={} aciertos={} ilegibles={} enormes={} perdidos={} ultimo_ilegible={}",
            t.arranques,
            t.muertes,
            t.muertes_por_memoria,
            t.plazos,
            t.analisis,
            t.no_pudo,
            t.enfriamientos,
            t.latencia.percentil(99.0),
            e.encargos,
            e.aciertos,
            e.ilegibles,
            e.enormes,
            e.perdidos,
            e.ultimo_ilegible.as_deref().unwrap_or("-")
        ));
    }
    lineas.extend(informar_aplicacion(analista));
    lineas
}

/// La postura de aplicacion, en lineas (H-28).
///
/// Con trabajador, la ultima que midio el hilo analista: es el dueño del
/// trabajador, el unico que puede medirlo sin que su pid cambie de proceso a
/// mitad. Sin trabajador se mide aqui y sin testigo, y entonces lo mas que
/// sale es DISPONIBLE. Solo lee `/proc`: no decide ni impide nada.
#[cfg(all(target_os = "linux", feature = "bpf"))]
fn informar_aplicacion(analista: Option<&std::sync::Mutex<EstadoAnalista>>) -> Vec<String> {
    use aegis_agent::aplicacion;
    let medida = match analista {
        Some(a) => a.lock().ok().and_then(|g| g.aplicacion.clone()),
        None => Some(aplicacion::medir(None)),
    };
    match medida {
        Some(m) => aplicacion::lineas(&m),
        None => vec![
            "aplicacion: sin medida que publicar (el hilo analista no ha dejado ninguna)"
                .to_string(),
        ],
    }
}

#[cfg(not(all(target_os = "linux", feature = "bpf")))]
fn ejecutar(o: Opciones) -> std::process::ExitCode {
    let _ = (&PARAR, Arc::new(0u8), Instant::now());
    let _ = (o.intervalo, o.control_socket, o.latido, o.plano_control);
    let _ = Pipeline::new(GraphConfig::default(), TriageConfig::default());
    eprintln!(
        "aegis-agent se compilo sin la caracteristica 'bpf' o para un sistema que no es Linux.\n\
         La logica de correlacion esta disponible como biblioteca, pero no hay origen de\n\
         telemetria: recompila en Linux con --features bpf."
    );
    std::process::ExitCode::FAILURE
}
