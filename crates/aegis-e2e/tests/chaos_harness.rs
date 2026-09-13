//! Ingenieria del caos: que pasa cuando todo falla a la vez.
//!
//! Las pruebas normales comprueban que el producto hace lo que debe cuando el
//! entorno se porta. Estas comprueban lo contrario: que **no hace nada
//! catastrofico** cuando el entorno se rompe. Un EDR que se cuelga, que crece
//! sin limite o que corrompe su propia memoria ante una entrada rara es peor que
//! no tener EDR, porque el equipo cree estar protegido.
//!
//! Cuatro familias, que son los cuatro modos de fallo que de verdad ocurren en
//! produccion:
//!
//! 1. **Corrupcion del buffer de IPC**: memoria compartida con el kernel que
//!    alguien —un fallo de hardware, un atacante con el mapeo— altera.
//! 2. **Caidas de red**: datagramas perdidos, alterados en transito y pares que
//!    desaparecen.
//! 3. **Saturacion de memoria**: inundaciones pensadas para que el detector se
//!    convierta en el objetivo.
//! 4. **Cuelgues de hilos**: un consumidor que deja de consumir.
//!
//! El caos es DETERMINISTA: la corrupcion y las perdidas siguen un patron
//! reproducible en vez de un generador aleatorio. Una prueba de caos que falla
//! una vez de cada cien y no se puede reproducir no se arregla: se desactiva.

use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aegis_ipc::{PushOutcome, RingConsumer, RingProducer};

const DATA_OFFSET: u64 = 256;

/// Generador congruencial lineal: caos reproducible.
///
/// No se usa `rand` a proposito: una prueba de caos con semilla desconocida que
/// falla una vez de cada cien no se arregla, se desactiva.
struct Lcg(u64);

impl Lcg {
    fn new(semilla: u64) -> Lcg {
        Lcg(semilla)
    }
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() >> 33) as usize % n.max(1)
    }
}

/// Mapeo compartido para el ring, con desmontaje al salir.
struct Mapa {
    base: *mut u8,
    layout: Layout,
    len: usize,
}

impl Mapa {
    fn nuevo(capacity: u64) -> Mapa {
        let len = (DATA_OFFSET + capacity) as usize;
        let layout = Layout::from_size_align(len, 64).unwrap();
        // SAFETY: se reserva con una disposicion valida y no nula.
        let base = unsafe { alloc_zeroed(layout) };
        assert!(!base.is_null());
        // SAFETY: `base` tiene `len` bytes recien reservados y a cero.
        unsafe { RingProducer::format(base, len, capacity, DATA_OFFSET) }.unwrap();
        Mapa { base, layout, len }
    }
    fn productor(&self) -> RingProducer {
        // SAFETY: el protocolo es SPSC y esta prueba usa un solo productor.
        unsafe { RingProducer::attach(self.base, self.len) }.unwrap()
    }
    fn consumidor(&self) -> RingConsumer {
        // SAFETY: idem, un solo consumidor.
        unsafe { RingConsumer::attach(self.base, self.len) }.unwrap()
    }
    /// Altera `n` bytes del area de DATOS en posiciones deterministas.
    fn corromper_datos(&self, rng: &mut Lcg, n: usize) {
        let inicio = DATA_OFFSET as usize;
        for _ in 0..n {
            let pos = inicio + rng.below(self.len - inicio);
            // SAFETY: `pos` esta dentro del mapeo por construccion.
            unsafe {
                let p = self.base.add(pos);
                *p = (*p).wrapping_add(rng.next() as u8 | 1);
            }
        }
    }
    /// Altera bytes de la CABECERA de control: indices, magia, capacidad.
    fn corromper_control(&self, rng: &mut Lcg, n: usize) {
        for _ in 0..n {
            let pos = rng.below(DATA_OFFSET as usize);
            // SAFETY: `pos` esta dentro de la cabecera del mapeo.
            unsafe {
                let p = self.base.add(pos);
                *p = (*p).wrapping_add(rng.next() as u8 | 1);
            }
        }
    }
}

impl Drop for Mapa {
    fn drop(&mut self) {
        // SAFETY: se libera con la misma disposicion con la que se reservo.
        unsafe { dealloc(self.base, self.layout) };
    }
}

// SAFETY: el protocolo es SPSC; cada puntero cruza a un solo hilo a la vez.
unsafe impl Send for Mapa {}
unsafe impl Sync for Mapa {}

fn cuerpo(n: u64, extra: usize) -> Vec<u8> {
    let mut v = vec![0u8; 8 + extra];
    v[..8].copy_from_slice(&n.to_le_bytes());
    v
}

/// Memoria residente del proceso, en KB.
fn rss_kb() -> u64 {
    let Ok(t) = std::fs::read_to_string("/proc/self/statm") else {
        return 0;
    };
    let paginas: u64 = t
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    // SAFETY: consulta pura del tamano de pagina del sistema.
    let pagina = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
    paginas * pagina / 1024
}

// ---------------------------------------------------------------------------
// 1. Corrupcion del buffer de IPC
// ---------------------------------------------------------------------------

#[test]
fn caos_el_consumidor_sobrevive_a_datos_corrompidos() {
    // El ring es memoria compartida con el kernel. Un fallo de hardware, o un
    // atacante con el mapeo, puede alterarla. El consumidor tiene que
    // sobrevivir: leer basura no puede convertirse en leer FUERA del buffer.
    for semilla in [1u64, 7, 42, 1337, 99_991] {
        let m = Mapa::nuevo(1 << 16);
        let mut p = m.productor();
        for i in 0..200u64 {
            p.push(0x0011, i, i, &cuerpo(i, (i % 48) as usize));
        }

        let mut rng = Lcg::new(semilla);
        m.corromper_datos(&mut rng, 400);

        let mut c = m.consumidor();
        let mut leidos = 0usize;
        // Lo unico que se exige es que no haya comportamiento indefinido y que
        // la llamada TERMINE: interpretar basura como eventos es aceptable, y
        // el triaje de arriba ya los descarta por malformados.
        let r = c.drain(10_000, |ev| {
            let cuerpo = ev.payload_bytes();
            // Tocar todos los bytes obliga a que el rango sea valido de verdad:
            // un desbordamiento se manifestaria aqui y no en una comprobacion
            // superficial de la longitud.
            let suma: u64 = cuerpo.iter().map(|b| *b as u64).sum();
            std::hint::black_box(suma);
            leidos += 1;
        });
        assert!(
            r.is_ok() || r.is_err(),
            "la semilla {semilla} tiene que terminar de una forma o de otra"
        );
        assert!(leidos <= 10_000);
    }
}

#[test]
fn caos_el_consumidor_sobrevive_a_una_cabecera_corrompida() {
    // Peor caso: los INDICES del ring alterados. Un `tail` inventado podria
    // hacer que el consumidor leyera fuera del mapeo.
    for semilla in [3u64, 11, 777, 60_013] {
        let m = Mapa::nuevo(1 << 14);
        let mut p = m.productor();
        for i in 0..50u64 {
            p.push(0x0011, i, i, &cuerpo(i, 16));
        }
        let mut rng = Lcg::new(semilla);
        m.corromper_control(&mut rng, 24);

        // `attach` puede rechazar el mapeo, que es la respuesta correcta: una
        // cabecera que no cuadra no se interpreta.
        // SAFETY: el mapeo sigue vivo y tiene el tamano declarado.
        let attach = unsafe { RingConsumer::attach(m.base, m.len) };
        if let Ok(mut c) = attach {
            let mut n = 0usize;
            let _ = c.drain(5_000, |ev| {
                let suma: u64 = ev.payload_bytes().iter().map(|b| *b as u64).sum();
                std::hint::black_box(suma);
                n += 1;
            });
            assert!(n <= 5_000);
        }
    }
}

#[test]
fn caos_un_ring_saturado_suelta_en_vez_de_bloquear_o_corromper() {
    // Si el ring bloqueara al llenarse, el hilo que drena eBPF se pararia y el
    // kernel empezaria a descartar eventos: un punto ciego mucho peor que
    // perder unos cuantos aqui.
    let m = Mapa::nuevo(1 << 12);
    let mut p = m.productor();
    let inicio = Instant::now();
    let mut soltados = 0u64;
    for i in 0..50_000u64 {
        match p.push(0x0011, i, i, &cuerpo(i, 32)) {
            PushOutcome::Dropped => soltados += 1,
            PushOutcome::Pushed { .. } => {}
            PushOutcome::TooLarge { .. } => unreachable!(),
        }
    }
    assert!(soltados > 0, "un ring sin drenar tiene que soltar");
    assert!(
        inicio.elapsed() < Duration::from_secs(5),
        "y no puede bloquear: tardo {:?}",
        inicio.elapsed()
    );

    // Y lo que SI entro se sigue leyendo bien: soltar no corrompe el flujo.
    let mut c = m.consumidor();
    let mut anterior: Option<u64> = None;
    c.drain(100_000, |ev| {
        let n = u64::from_le_bytes(ev.payload_bytes()[..8].try_into().unwrap());
        if let Some(a) = anterior {
            assert!(n > a, "el orden se conserva entre lo que si entro");
        }
        anterior = Some(n);
    })
    .unwrap();
}

// ---------------------------------------------------------------------------
// 2. Caidas de red
// ---------------------------------------------------------------------------

const CLAVE: [u8; 32] = [0x5a; 32];
const AHORA: u64 = 1_700_000_000;

fn cfg_malla(peers: Vec<SocketAddr>) -> aegis_mesh::MeshConfig {
    aegis_mesh::MeshConfig {
        bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        peers,
        key: CLAVE,
        ..aegis_mesh::MeshConfig::default()
    }
}

fn vacuna(n: u64) -> aegis_mesh::Vaccine {
    aegis_mesh::Vaccine::new(
        aegis_sync::ioc::Ioc::new(aegis_sync::ioc::IocKind::FileSha256, format!("{n:064}")),
        aegis_mesh::Severity::Confirmed,
        AHORA,
    )
}

#[test]
fn caos_la_vacuna_llega_aunque_se_pierda_el_70_por_ciento() {
    // Un rele que descarta cuatro de cada cinco datagramas, de forma
    // determinista. La malla no retransmite —es un protocolo de inundacion, no
    // de entrega fiable—, asi que lo que se comprueba es que la REPETICION del
    // emisor converge, que es como funciona el rumor en una red local.
    let mut b = aegis_mesh::Mesh::bind(cfg_malla(vec![])).unwrap();
    let dir_b = b.local_addr();

    let rele = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
    rele.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let dir_rele = rele.local_addr().unwrap();
    let mut a = aegis_mesh::Mesh::bind(cfg_malla(vec![dir_rele])).unwrap();

    let v = vacuna(1);
    let mut entregados = 0usize;
    let mut buf = [0u8; 1200];
    for intento in 0..20u32 {
        a.broadcast(&v).unwrap();
        if let Ok((n, _)) = rele.recv_from(&mut buf) {
            // Solo uno de cada cinco pasa. Determinista: la prueba falla o pasa
            // siempre igual.
            if intento % 5 == 0 {
                rele.send_to(&buf[..n], dir_b).unwrap();
                entregados += 1;
            }
        }
    }
    assert!(entregados > 0, "el rele tiene que haber dejado pasar algo");

    let r = b.poll(Duration::from_millis(500), AHORA);
    assert_eq!(r.len(), 1, "la vacuna acaba llegando pese a la perdida");
    assert_eq!(r[0].vaccine.ioc, v.ioc);
    // Y las copias que si llegaron despues se reconocen como duplicadas en vez
    // de reprocesarse.
    let extra = b.poll(Duration::from_millis(200), AHORA);
    assert!(extra.is_empty());
}

#[test]
fn caos_los_datagramas_alterados_en_transito_no_cuelan() {
    // Un rele que voltea un bit de cada mensaje: es lo que hace una red con un
    // enlace defectuoso, y tambien lo que haria un atacante con acceso al medio.
    let mut b = aegis_mesh::Mesh::bind(cfg_malla(vec![])).unwrap();
    let dir_b = b.local_addr();
    let rele = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
    rele.set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let mut a = aegis_mesh::Mesh::bind(cfg_malla(vec![rele.local_addr().unwrap()])).unwrap();

    let mut rng = Lcg::new(2024);
    let mut buf = [0u8; 1200];
    for i in 0..10u64 {
        a.broadcast(&vacuna(i)).unwrap();
        if let Ok((n, _)) = rele.recv_from(&mut buf) {
            let pos = 36 + rng.below(n - 36); // dentro del texto cifrado
            buf[pos] ^= 1 << (rng.below(8) as u8);
            rele.send_to(&buf[..n], dir_b).unwrap();
        }
    }
    let r = b.poll(Duration::from_millis(500), AHORA);
    assert!(r.is_empty(), "ni una sola puede colar: {r:?}");
    assert!(b.stats().drops_of(aegis_mesh::DropReason::NotAuthentic) > 0);

    // Y la malla sigue viva para el trafico bueno.
    let mut c = aegis_mesh::Mesh::bind(cfg_malla(vec![dir_b])).unwrap();
    c.broadcast(&vacuna(999)).unwrap();
    assert_eq!(b.poll(Duration::from_millis(500), AHORA).len(), 1);
}

#[test]
fn caos_todos_los_pares_caidos_no_cuelgan_al_emisor() {
    // Un agente aislado en una red donde nadie mas responde no puede quedarse
    // esperando: seguiria sin detectar mientras espera a hablar.
    let muertos: Vec<SocketAddr> = (0..8)
        .map(|_| {
            let s = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
            let d = s.local_addr().unwrap();
            drop(s);
            d
        })
        .collect();
    let mut a = aegis_mesh::Mesh::bind(cfg_malla(muertos)).unwrap();

    let inicio = Instant::now();
    for i in 0..100u64 {
        let _ = a.broadcast(&vacuna(i));
    }
    assert!(
        inicio.elapsed() < Duration::from_secs(5),
        "difundir a pares caidos tardo {:?}",
        inicio.elapsed()
    );

    // Y el sondeo devuelve el control aunque no llegue nada.
    let inicio = Instant::now();
    let r = a.poll(Duration::from_millis(120), AHORA);
    assert!(r.is_empty());
    assert!(
        inicio.elapsed() < Duration::from_secs(2),
        "el sondeo tiene que respetar su plazo: {:?}",
        inicio.elapsed()
    );
}

// ---------------------------------------------------------------------------
// 3. Saturacion de memoria
// ---------------------------------------------------------------------------

#[test]
fn caos_la_inundacion_no_hace_crecer_la_memoria_sin_limite() {
    // Todas las estructuras que guardan estado por origen son un objetivo: si
    // crecieran sin cota, el detector se convertiria en el objetivo del ataque.
    use aegis_behavior::engine::{BehavioralGraphEngine, EngineConfig};
    use aegis_behavior::technique::Technique;
    use aegis_deception::decoy::{DecoyKind, Interaction};
    use aegis_deception::sensor::{ReconSensor, SensorConfig};
    use aegis_scal::process::{ProcessInfo, ProcessKey, ProcessState};

    let antes = rss_kb();

    // a) Sensor de senuelos con direcciones falsificadas.
    let mut sensor = ReconSensor::new(SensorConfig {
        max_peers: 256,
        ..SensorConfig::default()
    });
    for i in 0..100_000u32 {
        sensor.observe(&Interaction {
            peer: IpAddr::V4(Ipv4Addr::from(i.wrapping_mul(2_654_435_761))),
            peer_port: 1024 + (i % 60_000) as u16,
            kind: DecoyKind::Ssh,
            port: 22,
            ts_ns: i as u64,
            evidence: Vec::new(),
        });
    }
    assert!(sensor.tracked() <= 256, "seguidos: {}", sensor.tracked());

    // b) Grafo conductual con procesos que nacen y mueren sin parar.
    let mut motor = BehavioralGraphEngine::new(EngineConfig {
        limits: aegis_behavior::dag::GraphLimits {
            max_nodes: 512,
            dead_grace_ns: 1,
            max_depth: 16,
        },
        autonomous: true,
    });
    for i in 0..50_000u32 {
        let info = ProcessInfo {
            key: ProcessKey::new(i, i as u64),
            parent_pid: if i == 0 { 1 } else { i - 1 },
            image: Some(std::path::PathBuf::from("/usr/bin/efimero")),
            cmdline: vec!["efimero".into()],
            uid: 0,
            gid: 0,
            threads: 1,
            state: ProcessState::Running,
        };
        motor.track(&info, i as u64);
        let _ = motor.observe(info.key, Technique::CommandInterpreter);
        motor.on_process(
            &aegis_scal::process::ProcessEvent::Exited {
                key: info.key,
                exit_code: None,
            },
            i as u64 + 1,
        );
        if i % 1000 == 0 {
            motor.maintain(i as u64 + 1_000_000);
        }
    }
    motor.maintain(u64::MAX / 2);
    assert!(motor.graph().len() <= 512, "nodos: {}", motor.graph().len());

    // c) Memoria de vacunas de la malla.
    let mut malla = aegis_mesh::Mesh::bind(aegis_mesh::MeshConfig {
        dedup_capacity: 512,
        ..cfg_malla(vec![])
    })
    .unwrap();
    for i in 0..50_000u64 {
        let _ = malla.broadcast(&vacuna(i));
    }
    assert!(malla.remembered() <= 512);

    let despues = rss_kb();
    let crecimiento = despues.saturating_sub(antes);
    assert!(
        crecimiento < 131_072,
        "la memoria crecio {crecimiento} KB con 200.000 entradas hostiles"
    );
}

// ---------------------------------------------------------------------------
// 4. Cuelgues de hilos
// ---------------------------------------------------------------------------

#[test]
fn caos_un_consumidor_colgado_no_bloquea_al_productor() {
    // Es la propiedad que sostiene todo el pipeline: si el consumidor se cuelga,
    // el productor —el hilo que drena el ring de eBPF— tiene que seguir
    // avanzando y soltar, no quedarse esperando. Si se parara, el kernel
    // empezaria a descartar eventos y el agente se quedaria ciego.
    let m = Arc::new(Mapa::nuevo(1 << 13));
    let colgado = Arc::new(AtomicBool::new(true));
    let leidos = Arc::new(AtomicU64::new(0));

    let m_c = Arc::clone(&m);
    let colgado_c = Arc::clone(&colgado);
    let leidos_c = Arc::clone(&leidos);
    let consumidor = std::thread::spawn(move || {
        // El "cuelgue": el consumidor no drena durante un buen rato.
        while colgado_c.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(5));
        }
        let mut c = m_c.consumidor();
        let _ = c.drain(1_000_000, |_| {
            leidos_c.fetch_add(1, Ordering::Relaxed);
        });
    });

    let mut p = m.productor();
    let inicio = Instant::now();
    let mut enviados = 0u64;
    let mut soltados = 0u64;
    for i in 0..200_000u64 {
        match p.push(0x0011, i, i, &cuerpo(i, 24)) {
            PushOutcome::Pushed { .. } => enviados += 1,
            PushOutcome::Dropped => soltados += 1,
            PushOutcome::TooLarge { .. } => unreachable!(),
        }
    }
    let transcurrido = inicio.elapsed();
    colgado.store(false, Ordering::Release);
    consumidor.join().unwrap();

    assert!(
        transcurrido < Duration::from_secs(10),
        "el productor tardo {transcurrido:?} con el consumidor colgado"
    );
    assert!(soltados > 0, "con el consumidor parado tiene que soltar");
    assert!(enviados > 0);
    assert!(p.dropped_events() >= soltados, "y los drops se cuentan");
}

#[test]
fn caos_el_watchdog_distingue_colgado_de_muerto() {
    // Un proceso presente pero colgado es el fallo mas dificil de ver: el PID
    // existe, asi que cualquier comprobacion basada solo en su presencia dice
    // que todo va bien.
    use aegis_watchdog::supervisor::{decide, Decision, TargetState};

    let max = 15_000u64;
    assert_eq!(
        decide(
            TargetState {
                alive: true,
                heartbeat_age_ms: Some(30_000),
                shutdown_requested: false,
                ..TargetState::default()
            },
            max
        ),
        Decision::RestartHung,
        "vivo pero con el latido parado es un cuelgue"
    );
    assert_eq!(
        decide(
            TargetState {
                alive: false,
                heartbeat_age_ms: Some(0),
                shutdown_requested: false,
                ..TargetState::default()
            },
            max
        ),
        Decision::RestartDead
    );
    // Y una parada autorizada manda sobre todo: reiniciar lo que alguien apago a
    // proposito es peor que no reiniciar nada.
    assert_eq!(
        decide(
            TargetState {
                alive: false,
                heartbeat_age_ms: None,
                shutdown_requested: true,
                ..TargetState::default()
            },
            max
        ),
        Decision::Stop
    );
}

#[test]
fn caos_ningun_sondeo_se_queda_esperando_para_siempre() {
    // Todos los bucles del producto sondean con plazo. Uno que ignorara su
    // plazo dejaria al agente sin poder atender ni siquiera su propia senal de
    // parada.
    let mut malla = aegis_mesh::Mesh::bind(cfg_malla(vec![])).unwrap();
    let inicio = Instant::now();
    assert!(malla.poll(Duration::from_millis(100), AHORA).is_empty());
    assert!(inicio.elapsed() < Duration::from_secs(2));

    let net = aegis_deception::decoy::DecoyNet::bind(aegis_deception::decoy::DecoyConfig {
        bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
        services: vec![(aegis_deception::decoy::DecoyKind::Ssh, 0)],
        speak_timeout: Duration::from_millis(50),
        max_evidence: 64,
        max_per_poll: 8,
    });
    let inicio = Instant::now();
    assert!(net.poll(Duration::from_millis(100), 0).is_empty());
    assert!(inicio.elapsed() < Duration::from_secs(2));

    // Y un sondeo con plazo cero devuelve el control de inmediato.
    let inicio = Instant::now();
    let _ = malla.poll(Duration::ZERO, AHORA);
    assert!(inicio.elapsed() < Duration::from_millis(500));
}

#[test]
fn caos_todo_a_la_vez() {
    // Las cuatro familias juntas, que es como se presentan en produccion: la red
    // falla mientras la memoria se llena mientras el consumidor se atasca.
    let m = Mapa::nuevo(1 << 14);
    let mut p = m.productor();
    let mut rng = Lcg::new(31_337);

    let mut b = aegis_mesh::Mesh::bind(aegis_mesh::MeshConfig {
        dedup_capacity: 128,
        ..cfg_malla(vec![])
    })
    .unwrap();
    let dir_b = b.local_addr();
    let atacante = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
    let mut a = aegis_mesh::Mesh::bind(cfg_malla(vec![dir_b])).unwrap();

    let antes = rss_kb();
    let inicio = Instant::now();

    for i in 0..20_000u64 {
        // Ring que se llena sin drenar.
        p.push(0x0011, i, i, &cuerpo(i, (i % 64) as usize));
        // Corrupcion esporadica de la memoria compartida.
        if i % 2_000 == 0 {
            m.corromper_datos(&mut rng, 8);
        }
        // Trafico bueno y basura mezclados.
        if i % 500 == 0 {
            let _ = a.broadcast(&vacuna(i));
            let basura = vec![rng.next() as u8; 1 + rng.below(600)];
            let _ = atacante.send_to(&basura, dir_b);
            let _ = b.poll(Duration::from_millis(1), AHORA);
        }
    }

    let transcurrido = inicio.elapsed();
    let crecimiento = rss_kb().saturating_sub(antes);

    assert!(
        transcurrido < Duration::from_secs(30),
        "el caos combinado tardo {transcurrido:?}"
    );
    assert!(
        crecimiento < 131_072,
        "la memoria crecio {crecimiento} KB bajo caos combinado"
    );
    assert!(b.remembered() <= 128);
    assert!(p.dropped_events() > 0, "el ring lleno tiene que soltar");

    // Y despues de todo, el consumidor drena lo que quedo sin colgarse.
    let mut c = m.consumidor();
    let r = c.drain(1_000_000, |ev| {
        let suma: u64 = ev.payload_bytes().iter().map(|b| *b as u64).sum();
        std::hint::black_box(suma);
    });
    assert!(r.is_ok() || r.is_err());
}
