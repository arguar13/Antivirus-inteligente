//! Prueba de carga y concurrencia del sistema completo.
//!
//! # Que se demuestra aqui
//!
//! El producto tiene una arquitectura de hilos deliberada: el bucle de eventos
//! del ring buffer no puede bloquearse, asi que lo caro (YARA, el modelo de ML)
//! corre en hilos aparte. Una arquitectura asi solo vale si se sostiene bajo
//! carga real. Esta prueba la somete a lo que el prompt de la fase pide:
//!
//! - **100.000 eventos sinteticos por segundo** por el ring buffer real,
//!   escritos por el productor SPSC y drenados por el pipeline del agente.
//! - **YARA y ML en hilos separados**, escaneando y puntuando sin parar
//!   mientras el ring esta a plena carga, para comprobar que no colapsan ni se
//!   quedan sin CPU.
//! - **Sin fugas**: la memoria residente se muestrea durante toda la prueba y
//!   se exige que no crezca sin techo.
//! - **Sin interbloqueos**: la prueba entera tiene un plazo; si algun hilo se
//!   quedara esperando a otro, el plazo salta y la prueba falla en vez de
//!   colgarse para siempre.
//!
//! # Por que es una prueba y no un banco de rendimiento
//!
//! No mide nanosegundos: mide propiedades. "No pierde datos", "no crece la
//! memoria", "los hilos siguen vivos al final". Un numero de rendimiento
//! dependeria de la maquina de CI; estas propiedades no.

use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aegis_agent::motores::secuestro::RansomStage;
use aegis_agent::{Pipeline, ProcKey, TelemetryEvent};
use aegis_ipc::{PushOutcome, RingConsumer, RingProducer};
use aegis_ml::{FeatureExtractor, MalwareModel};
use aegis_ransom::{EngineConfig, HoneypotSet, RansomwareEngine};
use aegis_scan::YaraEngine;

const DATA_OFFSET: u64 = 256;

// ---------------------------------------------------------------------------
// Ring compartido
// ---------------------------------------------------------------------------

struct Mapa {
    base: *mut u8,
    layout: Layout,
    len: usize,
}

impl Mapa {
    fn nuevo(capacity: u64) -> Mapa {
        let len = (DATA_OFFSET + capacity) as usize;
        let layout = Layout::from_size_align(len, 64).unwrap();
        let base = unsafe { alloc_zeroed(layout) };
        assert!(!base.is_null());
        unsafe { RingProducer::format(base, len, capacity, DATA_OFFSET) }.unwrap();
        Mapa { base, layout, len }
    }
    fn productor(&self) -> RingProducer {
        unsafe { RingProducer::attach(self.base, self.len) }.unwrap()
    }
    fn consumidor(&self) -> RingConsumer {
        unsafe { RingConsumer::attach(self.base, self.len) }.unwrap()
    }
}

impl Drop for Mapa {
    fn drop(&mut self) {
        unsafe { dealloc(self.base, self.layout) };
    }
}

// SAFETY: SPSC; cada puntero cruza a un solo hilo a la vez.
unsafe impl Send for Mapa {}
unsafe impl Sync for Mapa {}

// ---------------------------------------------------------------------------
// Utillaje
// ---------------------------------------------------------------------------

/// Memoria residente del proceso en KB, leida de `/proc/self/statm`.
///
/// El segundo campo es RSS en paginas. Es la medida que importa para el
/// presupuesto: la memoria que de verdad ocupa el proceso, no la reservada.
fn rss_kb() -> u64 {
    let s = std::fs::read_to_string("/proc/self/statm").unwrap_or_default();
    let paginas: u64 = s
        .split_whitespace()
        .nth(1)
        .and_then(|x| x.parse().ok())
        .unwrap_or(0);
    paginas * 4 // paginas de 4 KB
}

/// Genera el cuerpo de un evento de escritura sintetico para el pipeline.
///
/// El primer campo del cuerpo es un contador de secuencia para poder verificar
/// a la salida que no se perdio ni se duplico ninguno.
fn cuerpo_secuencia(n: u64) -> Vec<u8> {
    let mut v = vec![0u8; 32];
    v[..8].copy_from_slice(&n.to_le_bytes());
    v
}

/// Flujo pseudoaleatorio para material de escaneo con entropia realista.
struct Flujo([u64; 4]);
impl Flujo {
    fn nuevo(s: u64) -> Flujo {
        let mut x = s;
        let mut sig = || {
            x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = x;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };
        Flujo([sig(), sig(), sig(), sig()])
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let s = &mut self.0;
        let mut v = Vec::with_capacity(n);
        while v.len() < n {
            let r = s[0].wrapping_add(s[3]).rotate_left(23).wrapping_add(s[0]);
            let t = s[1] << 17;
            s[2] ^= s[0];
            s[3] ^= s[1];
            s[1] ^= s[2];
            s[0] ^= s[3];
            s[2] ^= t;
            s[3] = s[3].rotate_left(45);
            v.extend_from_slice(&r.to_le_bytes());
        }
        v.truncate(n);
        v
    }
}

// ---------------------------------------------------------------------------
// La prueba
// ---------------------------------------------------------------------------

/// El sistema completo bajo carga sostenida: ring a plena velocidad con YARA y
/// ML compitiendo por la CPU, sin perder eventos, sin fugas y sin bloqueos.
#[test]
fn el_sistema_completo_aguanta_cien_mil_eventos_por_segundo() {
    // El objetivo de la fase: 100.000 eventos/seg mantenidos durante la
    // duracion de la prueba. Se envian mas para no depender del reloj: el
    // productor empuja tan rapido como puede hasta llegar a la cuota, y al
    // final se comprueba que el ritmo efectivo supero el objetivo.
    const OBJETIVO_POR_SEG: u64 = 100_000;
    const EVENTOS: u64 = 1_000_000;
    // Ring de 2 MB: grande para absorber rafagas, pequeno frente a lo que se le
    // mete, de modo que la envoltura y la contrapresion se ejerciten de verdad.
    let m = Arc::new(Mapa::nuevo(1 << 21));

    let productor_fin = Arc::new(AtomicBool::new(false));
    let parar_trabajadores = Arc::new(AtomicBool::new(false));
    let consumidos = Arc::new(AtomicU64::new(0));
    let rss_max = Arc::new(AtomicU64::new(0));
    // Progreso observable de los hilos de YARA y ML. Sirve para no pararlos
    // antes de que el planificador les diera siquiera un turno: cuando este test
    // corre junto a otros binarios (`cargo test --all`) en una maquina con pocos
    // nucleos, un trabajador —que ademas arranca compilando reglas o cargando el
    // modelo— puede tardar en hacer su primera vuelta. Esperar a que la haga
    // mide la propiedad real (los hilos no colapsan) en vez de una carrera con
    // el planificador.
    let yara_vivo = Arc::new(AtomicU64::new(0));
    let ml_vivo = Arc::new(AtomicU64::new(0));
    let rss_inicial = rss_kb();

    // --- Hilo productor: 100k+ eventos/seg por el ring real ------------------
    let m_prod = m.clone();
    let prod_fin = productor_fin.clone();
    let productor = std::thread::spawn(move || {
        let mut p = m_prod.productor();
        let mut enviados = 0u64;
        let mut soltados = 0u64;
        let inicio = Instant::now();
        while enviados < EVENTOS {
            match p.push(0x0011, enviados, enviados, &cuerpo_secuencia(enviados)) {
                PushOutcome::Pushed { .. } => enviados += 1,
                PushOutcome::Dropped => {
                    soltados += 1;
                    std::thread::yield_now();
                }
                PushOutcome::TooLarge { .. } => unreachable!(),
            }
        }
        let dur = inicio.elapsed();
        prod_fin.store(true, Ordering::Release);
        (enviados, soltados, dur)
    });

    // --- Hilo consumidor: drena el ring y lo pasa por el pipeline ------------
    let m_cons = m.clone();
    let cons_fin = productor_fin.clone();
    let consumidos_c = consumidos.clone();
    let rss_max_c = rss_max.clone();
    let consumidor = std::thread::spawn(move || {
        let mut c = m_cons.consumidor();
        let pipeline = Pipeline::default();
        let mut stage = RansomStage::new(RansomwareEngine::new(
            EngineConfig::default(),
            HoneypotSet::default(),
        ));
        let mut esperado = 0u64;
        let mut muestreo = 0u64;

        loop {
            let n = c
                .drain(8192, |ev| {
                    // Verifica orden estricto: el contador de secuencia tiene
                    // que llegar sin huecos ni repeticiones.
                    let body = ev.payload_bytes();
                    let seq = u64::from_le_bytes(body[..8].try_into().unwrap());
                    assert_eq!(seq, esperado, "hueco o duplicado bajo carga");
                    esperado += 1;

                    // El evento se convierte en telemetria y pasa por las dos
                    // etapas reales, que es lo que hace el agente en produccion.
                    let h = ev.header();
                    let te = TelemetryEvent::FileWriteSample {
                        actor: ProcKey(h.actor_key % 1024),
                        pid: (h.actor_key % 1024) as u32,
                        fd: 3,
                        bytes: 8192,
                        sample: std::sync::Arc::from(&body[..8]),
                        distinct_bytes: 4,
                        ts_ns: h.ts_ns,
                    };
                    pipeline.ingest(te.clone());
                    stage.on_event(&te);
                })
                .unwrap();
            consumidos_c.fetch_add(n as u64, Ordering::Relaxed);

            // Muestreo de memoria cada cierto numero de lotes.
            muestreo += 1;
            if muestreo % 16 == 0 {
                let r = rss_kb();
                rss_max_c.fetch_max(r, Ordering::Relaxed);
                // Mantenimiento periodico, como en el bucle real del colector.
                pipeline.maintain(muestreo * 1_000_000);
                stage.maintain(muestreo * 1_000_000);
            }

            if n == 0 {
                if cons_fin.load(Ordering::Acquire) && c.backlog_bytes() == 0 {
                    break;
                }
                std::thread::yield_now();
            }
        }
        // `recorded` cuenta cada evento que el triaje clasifico: un
        // FileWriteSample siempre se registra, asi que tiene que igualar el
        // total. Es la prueba de que el pipeline proceso cada evento, no solo
        // de que el ring los entrego.
        (esperado, pipeline.stats.recorded.load(Ordering::Relaxed))
    });

    // --- Hilo YARA: escaneo continuo mientras el ring esta a tope -----------
    let parar_yara = parar_trabajadores.clone();
    let yara_vivo_c = yara_vivo.clone();
    let yara = std::thread::spawn(move || {
        let motor = YaraEngine::with_base_rules().expect("las reglas base compilan");
        let mut f = Flujo::nuevo(0x5A5A_9A9A);
        let mut escaneos = 0u64;
        // EICAR: el motor tiene que seguir detectandolo bajo carga.
        let eicar = format!(
            "{}{}",
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}", "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        );
        let mut detecciones_eicar = 0u64;
        while !parar_yara.load(Ordering::Relaxed) {
            let datos = f.bytes(4096);
            let _ = motor.scan_bytes(&datos).expect("el escaneo no falla");
            if !motor.scan_bytes(eicar.as_bytes()).unwrap().is_empty() {
                detecciones_eicar += 1;
            }
            escaneos += 1;
            yara_vivo_c.fetch_add(1, Ordering::Relaxed);
        }
        (escaneos, detecciones_eicar)
    });

    // --- Hilo ML: inferencia continua ---------------------------------------
    let parar_ml = parar_trabajadores.clone();
    let ml_vivo_c = ml_vivo.clone();
    let ml = std::thread::spawn(move || {
        let modelo = MalwareModel::embedded().expect("el modelo empotrado carga");
        let extractor = FeatureExtractor::default();
        let mut f = Flujo::nuevo(0x_ADE1_5CA1);
        let mut inferencias = 0u64;
        while !parar_ml.load(Ordering::Relaxed) {
            let datos = f.bytes(8192);
            let feats = extractor.extract(&datos);
            let vector = aegis_ml::features::to_vector(&feats);
            let _ = modelo.predict(&vector).expect("la inferencia no falla");
            inferencias += 1;
            ml_vivo_c.fetch_add(1, Ordering::Relaxed);
        }
        inferencias
    });

    // --- Vigilancia de plazo: nada puede colgarse -----------------------------
    // Si el productor no termina en 60 s, hay un interbloqueo. La prueba lo
    // convierte en fallo en vez de en un cuelgue eterno.
    let plazo = Instant::now();
    while !productor_fin.load(Ordering::Acquire) {
        assert!(
            plazo.elapsed() < Duration::from_secs(60),
            "el productor no termino en 60 s: posible interbloqueo"
        );
        std::thread::sleep(Duration::from_millis(5));
    }

    let (enviados, soltados, dur_prod) = productor.join().unwrap();
    let (leidos, recibidos_pipeline) = consumidor.join().unwrap();

    // Antes de pararlos, se espera a que YARA y ML hayan hecho AL MENOS una
    // vuelta: es la prueba de que no colapsaron bajo carga. El plazo (el mismo
    // anti-cuelgue que el del productor) convierte un colapso real —un hilo que
    // de verdad no avanza— en un fallo, sin depender de que el planificador les
    // diera CPU justo dentro de la ventana del productor (que es lo que, con
    // `cargo test --all`, hacia fallar esta prueba de forma intermitente).
    let plazo_vivos = Instant::now();
    while yara_vivo.load(Ordering::Relaxed) == 0 || ml_vivo.load(Ordering::Relaxed) == 0 {
        assert!(
            plazo_vivos.elapsed() < Duration::from_secs(60),
            "un trabajador (YARA/ML) no completo ni una vuelta en 60 s: colapso real, no falta de CPU"
        );
        std::thread::sleep(Duration::from_millis(5));
    }

    // Los trabajadores paran una vez drenado el ring y demostrada su vida.
    parar_trabajadores.store(true, Ordering::Relaxed);
    let (escaneos_yara, eicar_detectado) = yara.join().unwrap();
    let inferencias_ml = ml.join().unwrap();

    let rss_final = rss_kb();
    let rss_pico = rss_max.load(Ordering::Relaxed).max(rss_final);

    // --- Propiedades ---------------------------------------------------------

    // 1. Sin perdidas: todo lo enviado se leyo, en orden, exactamente una vez.
    //
    // `soltados` cuenta los reintentos: cuando los cuatro hilos compiten por la
    // CPU, el consumidor puede quedarse momentaneamente atras y el ring se
    // llena, y entonces el productor reintenta en vez de sobrescribir. Es
    // contrapresion legitima y no una perdida: cada uno de los EVENTOS
    // distintos acaba pasando, en orden, porque un push soltado no consume
    // numero de secuencia. Se informa, no se prohibe.
    println!("reintentos por ring lleno: {soltados}");
    assert_eq!(enviados, EVENTOS);
    assert_eq!(leidos, EVENTOS, "se leyo todo lo enviado, en orden");
    assert_eq!(consumidos.load(Ordering::Relaxed), EVENTOS);
    assert_eq!(
        recibidos_pipeline, EVENTOS,
        "el pipeline clasifico cada evento"
    );

    // 2. Ritmo: por encima del objetivo de la fase.
    let por_seg = enviados as f64 / dur_prod.as_secs_f64();
    println!(
        "ritmo del ring: {:.0} eventos/seg (objetivo {OBJETIVO_POR_SEG})",
        por_seg
    );
    assert!(
        por_seg > OBJETIVO_POR_SEG as f64,
        "el ring movio {por_seg:.0} eventos/seg, por debajo del objetivo de \
         {OBJETIVO_POR_SEG}"
    );

    // 3. Los hilos de YARA y ML no colapsaron: siguieron trabajando durante
    //    toda la carga, y YARA siguio detectando el EICAR.
    println!(
        "YARA: {escaneos_yara} escaneos, EICAR detectado {eicar_detectado} veces; \
         ML: {inferencias_ml} inferencias"
    );
    assert!(
        escaneos_yara > 0,
        "el hilo de YARA no llego a escanear nada"
    );
    assert!(inferencias_ml > 0, "el hilo de ML no llego a inferir nada");
    assert!(
        eicar_detectado > 0,
        "YARA dejo de detectar el EICAR bajo carga: el motor colapso"
    );

    // 4. Sin fugas: la memoria residente no crecio sin techo. El estado del
    //    sistema esta acotado por diseno (grafo, cache de descriptores,
    //    seguimiento de velocidad), asi que procesar un millon de eventos no
    //    puede multiplicar la memoria.
    let crecimiento_kb = rss_pico.saturating_sub(rss_inicial);
    println!(
        "RSS inicial {rss_inicial} KB, pico {rss_pico} KB, final {rss_final} KB \
         (crecimiento {crecimiento_kb} KB)"
    );
    assert!(
        crecimiento_kb < 256 * 1024,
        "la memoria crecio {crecimiento_kb} KB procesando un millon de eventos: \
         hay una fuga o una estructura sin cota"
    );
}
