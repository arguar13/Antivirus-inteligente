//! # fleet_simulator — generador de carga del plano de control
//!
//! Simula una flota de miles de endpoints contra un `aegis-server` real, para
//! responder a preguntas que no se contestan razonando:
//!
//! - ¿Aguanta el plano de control la flota que dice aguantar?
//! - ¿Se mantiene la latencia por debajo del objetivo con la flota entera?
//! - ¿Se atasca PostgreSQL por concurrencia, o el cuello esta en otro sitio?
//!
//! # Fidelidad del protocolo
//!
//! Los agentes virtuales usan el CODEC AUTENTICO (`aegis_fleet::proto`) y
//! certificados emitidos por la CA REAL del servidor: los bytes que llegan al
//! plano de control son indistinguibles de los de un endpoint de produccion.
//! Lo unico que cambia es que el transporte es asincrono, porque un hilo por
//! agente choca con el limite de hilos mucho antes que con el del protocolo.
//!
//! # Dos cargas muy distintas
//!
//! **Latidos**: conexiones cortas y frecuentes. Diez mil agentes con latido cada
//! treinta segundos son 333 latidos por segundo, cada uno de milisegundos: la
//! concurrencia instantanea es minima. Mide RENDIMIENTO.
//!
//! **Suscripciones**: conexiones LARGAS. Diez mil agentes suscritos a la
//! politica son diez mil conexiones abiertas a la vez. Mide ESCALA, y es donde
//! aparecen los limites de verdad.
//!
//! # Uso
//!
//! ```text
//! fleet_simulator --agentes 10000 --duracion 60 --modo mixto \
//!     --servidor 127.0.0.1:8443 --ca-dir /var/lib/aegis/ca
//! ```

#![forbid(unsafe_code)]

mod histograma;
mod marco;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aegis_fleet::pki::{AutoridadCertificadora, Identidad};
use aegis_fleet::proto::{Latido, ReporteEvento, SolicitudEnrolamiento, SuscripcionPolitica};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::ClientConfig;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use histograma::Histograma;

/// Nombre con el que el plano de control emite su certificado de servidor.
const NOMBRE_SERVIDOR: &str = "localhost";

/// Codigos de metodo del servicio, los mismos que usa el agente.
mod metodo {
    /// Enrolar.
    pub const ENROLAR: u8 = 1;
    /// Latir.
    pub const LATIR: u8 = 2;
    /// Reportar evento.
    pub const EVENTO: u8 = 3;
    /// Suscribirse a la politica.
    pub const SUSCRIBIR: u8 = 6;
}

/// Que carga se genera.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Modo {
    /// Solo latidos: mide rendimiento.
    Latidos,
    /// Solo canales de politica abiertos: mide escala.
    Suscripciones,
    /// Las dos a la vez, que es lo que hace una flota real.
    Mixto,
}

/// Configuracion de la simulacion.
struct Config {
    servidor: SocketAddr,
    ca_dir: PathBuf,
    agentes: usize,
    duracion: Duration,
    intervalo_latido: Duration,
    modo: Modo,
    /// Cuantos agentes se enrolan a la vez al arrancar.
    ///
    /// Sin este freno, diez mil conexiones simultaneas en el primer segundo
    /// mediran la avalancha de arranque y no el regimen estacionario, que es lo
    /// que de verdad vive un plano de control.
    rampa: usize,
    /// Objetivo de latencia que se comprueba al final.
    objetivo_ms: f64,
    /// Segundos iniciales que NO cuentan para el veredicto.
    ///
    /// En produccion los agentes ya estan corriendo: no arrancan diez mil a la
    /// vez. Mezclar la avalancha de arranque con el regimen estacionario mide
    /// una cosa distinta de la que se quiere afirmar. La avalancha se mide
    /// aparte, porque tambien importa —es lo que pasa cuando el plano de
    /// control se reinicia y toda la flota reconecta— pero no se confunde con
    /// el regimen normal.
    calentamiento: Duration,
}

/// Contadores compartidos por todos los agentes virtuales.
#[derive(Default)]
struct Metricas {
    enrolados: AtomicU64,
    latidos: AtomicU64,
    eventos: AtomicU64,
    suscritos: AtomicU64,
    empujes: AtomicU64,
    fallos_conexion: AtomicU64,
    fallos_operacion: AtomicU64,
}

fn ayuda() -> ! {
    eprintln!(
        "fleet_simulator - generador de carga del plano de control de AegisCore

USO:
    fleet_simulator [OPCIONES]

OPCIONES:
    --servidor <IP:PUERTO>   canal de flota            [por defecto 127.0.0.1:8443]
    --ca-dir <RUTA>          CA del plano de control   [por defecto /var/lib/aegis/ca]
    --agentes <N>            agentes virtuales         [por defecto 1000]
    --duracion <SEG>         duracion del regimen      [por defecto 60]
    --intervalo <SEG>        intervalo de latido       [por defecto 30]
    --modo <MODO>            latidos|suscripciones|mixto [por defecto mixto]
    --rampa <N>              enrolamientos simultaneos [por defecto 200]
    --calentamiento <SEG>    arranque que no cuenta    [por defecto 10]
    --objetivo-ms <MS>       objetivo de latencia p99  [por defecto 50]
    -h, --help               esta ayuda"
    );
    std::process::exit(2)
}

fn config() -> Config {
    let mut c = Config {
        servidor: "127.0.0.1:8443".parse().expect("direccion por defecto"),
        ca_dir: PathBuf::from("/var/lib/aegis/ca"),
        agentes: 1000,
        duracion: Duration::from_secs(60),
        intervalo_latido: Duration::from_secs(30),
        modo: Modo::Mixto,
        rampa: 200,
        objetivo_ms: 50.0,
        calentamiento: Duration::from_secs(10),
    };

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let siguiente =
            |i: usize| -> String { args.get(i + 1).cloned().unwrap_or_else(|| ayuda()) };
        match args[i].as_str() {
            "--servidor" => {
                c.servidor = siguiente(i).parse().unwrap_or_else(|_| ayuda());
                i += 2;
            }
            "--ca-dir" => {
                c.ca_dir = PathBuf::from(siguiente(i));
                i += 2;
            }
            "--agentes" => {
                c.agentes = siguiente(i).parse().unwrap_or_else(|_| ayuda());
                i += 2;
            }
            "--duracion" => {
                c.duracion = Duration::from_secs(siguiente(i).parse().unwrap_or_else(|_| ayuda()));
                i += 2;
            }
            "--intervalo" => {
                c.intervalo_latido =
                    Duration::from_secs(siguiente(i).parse().unwrap_or_else(|_| ayuda()));
                i += 2;
            }
            "--modo" => {
                c.modo = match siguiente(i).as_str() {
                    "latidos" => Modo::Latidos,
                    "suscripciones" => Modo::Suscripciones,
                    "mixto" => Modo::Mixto,
                    _ => ayuda(),
                };
                i += 2;
            }
            "--rampa" => {
                c.rampa = siguiente(i).parse().unwrap_or_else(|_| ayuda());
                i += 2;
            }
            "--calentamiento" => {
                c.calentamiento =
                    Duration::from_secs(siguiente(i).parse().unwrap_or_else(|_| ayuda()));
                i += 2;
            }
            "--objetivo-ms" => {
                c.objetivo_ms = siguiente(i).parse().unwrap_or_else(|_| ayuda());
                i += 2;
            }
            "-h" | "--help" => ayuda(),
            _ => ayuda(),
        }
    }
    c
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = config();

    // --- Identidades ---------------------------------------------------------
    // Se emiten con la CA REAL del plano de control: el servidor las autentica
    // exactamente igual que a un endpoint de produccion.
    println!(
        "Cargando la CA del plano de control desde {}",
        cfg.ca_dir.display()
    );
    let cert = std::fs::read_to_string(cfg.ca_dir.join("flota-ca.crt"))?;
    let clave = std::fs::read_to_string(cfg.ca_dir.join("flota-ca.key"))?;
    let ca = Arc::new(AutoridadCertificadora::desde_pem(&cert, &clave)?);
    let ancla = ca.cert_der();

    println!("Emitiendo {} identidades de agente...", cfg.agentes);
    let inicio_emision = Instant::now();
    let identidades = emitir_identidades(ca.clone(), cfg.agentes).await?;
    println!(
        "  {} identidades en {:.1}s ({:.0}/s)",
        identidades.len(),
        inicio_emision.elapsed().as_secs_f64(),
        identidades.len() as f64 / inicio_emision.elapsed().as_secs_f64().max(0.001)
    );

    let metricas = Arc::new(Metricas::default());
    let hist_enrolamiento = Arc::new(Histograma::nuevo());
    let hist_latido = Arc::new(Histograma::nuevo());
    let hist_evento = Arc::new(Histograma::nuevo());
    // El arranque se mide aparte: es una fase distinta con otra pregunta.
    let hist_arranque = Arc::new(Histograma::nuevo());

    println!();
    println!("Simulacion:");
    println!("  servidor        : {}", cfg.servidor);
    println!("  agentes         : {}", cfg.agentes);
    println!("  modo            : {:?}", cfg.modo);
    println!("  duracion        : {}s", cfg.duracion.as_secs());
    println!("  latido cada     : {}s", cfg.intervalo_latido.as_secs());
    println!(
        "  carga esperada  : {:.0} latidos/s",
        cfg.agentes as f64 / cfg.intervalo_latido.as_secs_f64()
    );
    println!();

    // --- Lanzamiento ---------------------------------------------------------
    let inicio = Instant::now();
    let mut tareas = Vec::with_capacity(cfg.agentes);
    // El semaforo limita la RAMPA de arranque, no el regimen: sin el, la
    // avalancha inicial dominaria las medidas.
    let freno = Arc::new(tokio::sync::Semaphore::new(cfg.rampa));

    for (indice, identidad) in identidades.into_iter().enumerate() {
        let ancla_agente = ancla.clone();
        let m = metricas.clone();
        let (he, hl, hv, ha) = (
            hist_enrolamiento.clone(),
            hist_latido.clone(),
            hist_evento.clone(),
            hist_arranque.clone(),
        );
        let freno = freno.clone();
        let servidor = cfg.servidor;
        let duracion = cfg.duracion;
        let intervalo = cfg.intervalo_latido;
        let modo = cfg.modo;
        let total = cfg.agentes;
        let fin_calentamiento = inicio + cfg.calentamiento;

        tareas.push(tokio::spawn(async move {
            agente_virtual(
                indice,
                total,
                identidad,
                servidor,
                ancla_agente,
                m,
                he,
                hl,
                hv,
                ha,
                freno,
                duracion,
                intervalo,
                modo,
                fin_calentamiento,
            )
            .await;
        }));
    }

    // --- Informe periodico ---------------------------------------------------
    let m_informe = metricas.clone();
    let hl_informe = hist_latido.clone();
    let fin = inicio + cfg.duracion + Duration::from_secs(15);
    let informador = tokio::spawn(async move {
        let mut ultimo_latidos = 0u64;
        let mut tic = tokio::time::interval(Duration::from_secs(5));
        tic.tick().await;
        while Instant::now() < fin {
            tic.tick().await;
            let latidos = m_informe.latidos.load(Ordering::Relaxed);
            let por_segundo = (latidos - ultimo_latidos) as f64 / 5.0;
            ultimo_latidos = latidos;
            println!(
                "  [{:>4}s] enrolados={} latidos={} ({:.0}/s) eventos={} suscritos={} empujes={} fallos={}+{}",
                inicio.elapsed().as_secs(),
                m_informe.enrolados.load(Ordering::Relaxed),
                latidos,
                por_segundo,
                m_informe.eventos.load(Ordering::Relaxed),
                m_informe.suscritos.load(Ordering::Relaxed),
                m_informe.empujes.load(Ordering::Relaxed),
                m_informe.fallos_conexion.load(Ordering::Relaxed),
                m_informe.fallos_operacion.load(Ordering::Relaxed),
            );
            if hl_informe.muestras() > 0 {
                println!("           latido: {}", hl_informe.resumen());
            }
        }
    });

    for t in tareas {
        let _ = t.await;
    }
    informador.abort();

    // --- Veredicto -----------------------------------------------------------
    let transcurrido = inicio.elapsed();
    println!();
    println!("=== RESULTADO ===");
    println!("  duracion real       : {:.1}s", transcurrido.as_secs_f64());
    println!(
        "  agentes enrolados   : {}",
        metricas.enrolados.load(Ordering::Relaxed)
    );
    println!(
        "  latidos             : {}",
        metricas.latidos.load(Ordering::Relaxed)
    );
    println!(
        "  eventos             : {}",
        metricas.eventos.load(Ordering::Relaxed)
    );
    println!(
        "  canales suscritos   : {}",
        metricas.suscritos.load(Ordering::Relaxed)
    );
    println!(
        "  empujes recibidos   : {}",
        metricas.empujes.load(Ordering::Relaxed)
    );
    println!(
        "  fallos de conexion  : {}",
        metricas.fallos_conexion.load(Ordering::Relaxed)
    );
    println!(
        "  fallos de operacion : {}",
        metricas.fallos_operacion.load(Ordering::Relaxed)
    );
    println!();
    println!("  enrolamiento : {}", hist_enrolamiento.resumen());
    println!("  arranque     : {}", hist_arranque.resumen());
    println!("                 (la avalancha inicial; no decide el veredicto)");
    println!("  latido       : {}", hist_latido.resumen());
    println!("  evento       : {}", hist_evento.resumen());
    println!();

    // El rendimiento se calcula sobre el REGIMEN, descontando el calentamiento.
    let segundos_regimen =
        (transcurrido.as_secs_f64() - cfg.calentamiento.as_secs_f64()).max(0.001);
    let rendimiento = hist_latido.muestras() as f64 / segundos_regimen;
    println!("  rendimiento  : {rendimiento:.0} latidos/s");

    // El p99 del latido es la medida que importa: es la operacion mas frecuente
    // del sistema y la que sufre cualquier atasco de la base de datos.
    let p99 = hist_latido.percentil_ms(99.0);
    let objetivo_cumplido = hist_latido.muestras() == 0 || p99 <= cfg.objetivo_ms;
    let sin_fallos = metricas.fallos_conexion.load(Ordering::Relaxed) == 0
        && metricas.fallos_operacion.load(Ordering::Relaxed) == 0;

    println!();
    if objetivo_cumplido && sin_fallos {
        println!(
            "VEREDICTO: SUPERADO. p99 del latido < {:.0} ms con {} agentes y sin fallos.",
            cfg.objetivo_ms, cfg.agentes
        );
        Ok(())
    } else {
        if !objetivo_cumplido {
            println!(
                "VEREDICTO: NO CUMPLE. p99 del latido < {p99:.2} ms, objetivo {:.0} ms.",
                cfg.objetivo_ms
            );
        }
        if !sin_fallos {
            println!("VEREDICTO: NO CUMPLE. Hubo fallos; ver los contadores de arriba.");
        }
        std::process::exit(1);
    }
}

/// Emite las identidades en paralelo.
///
/// Firmar miles de certificados es costoso y secuencialmente dominaria el
/// arranque. Se reparte entre los nucleos con tareas bloqueantes, que es lo
/// correcto para trabajo de CPU dentro de un runtime asincrono.
async fn emitir_identidades(
    ca: Arc<AutoridadCertificadora>,
    cuantos: usize,
) -> Result<Vec<Identidad>, Box<dyn std::error::Error>> {
    let nucleos = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let por_nucleo = cuantos.div_ceil(nucleos);

    let mut lotes = Vec::new();
    for n in 0..nucleos {
        let desde = n * por_nucleo;
        let hasta = ((n + 1) * por_nucleo).min(cuantos);
        if desde >= hasta {
            break;
        }
        let ca = ca.clone();
        lotes.push(tokio::task::spawn_blocking(move || {
            let mut v = Vec::with_capacity(hasta - desde);
            for i in desde..hasta {
                // Validez larga: el simulador no ejercita la rotacion, y un
                // certificado que caduca a mitad de la prueba falsearia los
                // resultados con errores que no son del sistema medido.
                v.push(ca.emitir(&format!("sim-{i:06}.carga.local"), 86_400)?);
            }
            Ok::<_, aegis_fleet::FleetError>(v)
        }));
    }

    let mut todas = Vec::with_capacity(cuantos);
    for l in lotes {
        todas.extend(l.await??);
    }
    Ok(todas)
}

/// Un agente virtual completo: se enrola, late, reporta y se suscribe.
#[allow(clippy::too_many_arguments)]
async fn agente_virtual(
    indice: usize,
    total: usize,
    identidad: Identidad,
    servidor: SocketAddr,
    ancla: CertificateDer<'static>,
    metricas: Arc<Metricas>,
    hist_enrolamiento: Arc<Histograma>,
    hist_latido: Arc<Histograma>,
    hist_evento: Arc<Histograma>,
    hist_arranque: Arc<Histograma>,
    freno: Arc<tokio::sync::Semaphore>,
    duracion: Duration,
    intervalo: Duration,
    modo: Modo,
    fin_calentamiento: Instant,
) {
    let cn = identidad.cn.clone();

    // Se reutiliza la configuracion TLS AUTENTICA del agente
    // (`aegis_fleet::tls::config_cliente`), no una equivalente escrita aqui:
    // asi el handshake, las suites y la validacion son exactamente los de un
    // endpoint de produccion, y no una aproximacion que podria medir otra cosa.
    let cfg_con_identidad = match aegis_fleet::tls::config_cliente(&identidad, &ancla) {
        Ok(c) => c,
        Err(_) => {
            metricas.fallos_conexion.fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    // --- Enrolamiento, con la rampa acotada ---------------------------------
    {
        let _permiso = freno.acquire().await;
        let t0 = Instant::now();
        let solicitud = SolicitudEnrolamiento {
            id_agente: cn.clone(),
            hostname: format!("carga-{indice:06}"),
            version_agente: "1.0.0".into(),
            huella_cert: identidad.huella(),
        };
        match llamada(
            servidor,
            &cfg_con_identidad,
            metodo::ENROLAR,
            &solicitud.codificar(),
        )
        .await
        {
            Ok(_) => {
                hist_enrolamiento.registrar(t0.elapsed().as_micros() as u64);
                metricas.enrolados.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                metricas.fallos_operacion.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
    }

    // --- Canal de politica ---------------------------------------------------
    let canal = if matches!(modo, Modo::Suscripciones | Modo::Mixto) {
        match abrir_suscripcion(servidor, &cfg_con_identidad, &cn).await {
            Ok(flujo) => {
                metricas.suscritos.fetch_add(1, Ordering::Relaxed);
                Some(tokio::spawn(escuchar_empujes(flujo, metricas.clone())))
            }
            Err(_) => {
                metricas.fallos_conexion.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    } else {
        None
    };

    // --- Regimen estacionario ------------------------------------------------
    if matches!(modo, Modo::Latidos | Modo::Mixto) {
        // Cada agente arranca su ciclo en un punto distinto del intervalo,
        // repartido sobre el intervalo ENTERO. Una flota real no late al
        // unisono; concentrarla en parte de la ventana produciria picos y valles
        // que no existen en produccion —y que se veian en las primeras medidas
        // como un ritmo oscilando entre 88 y 12 latidos por segundo—.
        let desfase = intervalo.mul_f64(indice as f64 / total.max(1) as f64);
        tokio::time::sleep(desfase).await;

        let fin = Instant::now() + duracion;
        let mut ciclo = 0u64;
        while Instant::now() < fin {
            let t0 = Instant::now();
            let latido = Latido {
                id_agente: cn.clone(),
                momento_unix: 0,
                rss_kb: 21_000 + (indice as u64 % 4000),
                amenazas_activas: 0,
                version_politica: 1,
            };
            match llamada(
                servidor,
                &cfg_con_identidad,
                metodo::LATIR,
                &latido.codificar(),
            )
            .await
            {
                Ok(_) => {
                    let us = t0.elapsed().as_micros() as u64;
                    // Durante el calentamiento la medida va al histograma de
                    // arranque: cuenta, pero no decide el veredicto.
                    if Instant::now() < fin_calentamiento {
                        hist_arranque.registrar(us);
                    } else {
                        hist_latido.registrar(us);
                    }
                    metricas.latidos.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    metricas.fallos_operacion.fetch_add(1, Ordering::Relaxed);
                }
            }

            // Uno de cada veinte ciclos reporta un evento: es el orden de
            // magnitud de una flota real, donde la mayoria de los latidos no
            // traen nada.
            ciclo += 1;
            if ciclo % 20 == 0 {
                let t0 = Instant::now();
                let evento = ReporteEvento {
                    id_agente: cn.clone(),
                    severidad: 2,
                    categoria: "inyeccion".into(),
                    descripcion: "deteccion sintetica del generador de carga".into(),
                    momento_unix: 0,
                };
                match llamada(
                    servidor,
                    &cfg_con_identidad,
                    metodo::EVENTO,
                    &evento.codificar(),
                )
                .await
                {
                    Ok(_) => {
                        hist_evento.registrar(t0.elapsed().as_micros() as u64);
                        metricas.eventos.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        metricas.fallos_operacion.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }

            tokio::time::sleep(intervalo).await;
        }
    } else {
        tokio::time::sleep(duracion).await;
    }

    if let Some(c) = canal {
        c.abort();
    }
}

/// Abre una conexion TLS y hace una llamada unaria.
async fn llamada(
    servidor: SocketAddr,
    config: &Arc<ClientConfig>,
    metodo: u8,
    cuerpo: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let flujo = conectar(servidor, config).await?;
    let mut flujo = flujo;
    marco::escribir(&mut flujo, metodo, cuerpo).await?;
    let (estado, respuesta) = marco::leer(&mut flujo).await?;
    if estado != 0 {
        return Err(format!("el plano de control respondio estado {estado}").into());
    }
    Ok(respuesta)
}

/// Abre el canal de suscripcion de politica.
async fn abrir_suscripcion(
    servidor: SocketAddr,
    config: &Arc<ClientConfig>,
    cn: &str,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Box<dyn std::error::Error + Send + Sync>> {
    let mut flujo = conectar(servidor, config).await?;
    let peticion = SuscripcionPolitica {
        id_agente: cn.to_string(),
        version_conocida: 1,
    };
    marco::escribir(&mut flujo, metodo::SUSCRIBIR, &peticion.codificar()).await?;
    Ok(flujo)
}

/// Lee empujes del canal hasta que se cierre.
async fn escuchar_empujes(
    mut flujo: tokio_rustls::client::TlsStream<TcpStream>,
    metricas: Arc<Metricas>,
) {
    loop {
        match marco::leer(&mut flujo).await {
            Ok(_) => {
                metricas.empujes.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => return,
        }
    }
}

/// Establece la conexion TLS.
async fn conectar(
    servidor: SocketAddr,
    config: &Arc<ClientConfig>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Box<dyn std::error::Error + Send + Sync>> {
    let tcp = TcpStream::connect(servidor).await?;
    // Sin retardo de Nagle: el protocolo son mensajes pequenos de ida y vuelta,
    // y agruparlos anadiria decenas de milisegundos a cada latido.
    tcp.set_nodelay(true)?;
    let nombre = ServerName::try_from(NOMBRE_SERVIDOR)?;
    let conector = TlsConnector::from(config.clone());
    Ok(conector.connect(nombre, tcp).await?)
}
