//! La etapa anti-ransomware conectada a eventos de telemetria reales.
//!
//! Aqui se prueba la union: que un `write` que solo trae un descriptor acabe
//! atribuido a la ruta correcta, que un senuelo se confirme en la apertura, y
//! que las tablas no crezcan sin techo.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use aegis_agent::ransom::{RansomAction, RansomStage};
use aegis_agent::{ProcKey, TelemetryEvent};
use aegis_ransom::engine::{ContainmentOutcome, Responder};
use aegis_ransom::honeypot::HoneypotConfig;
use aegis_ransom::{EngineConfig, HoneypotSet, RansomwareEngine};

const O_WRONLY: u32 = 0o1;
const O_RDONLY: u32 = 0o0;
const MS: u64 = 1_000_000;

struct Lab(PathBuf);

impl Lab {
    fn nuevo(n: &str) -> Lab {
        let p = std::env::temp_dir().join(format!("aegis-stage-{n}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Lab(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Respondedor que registra los PID sobre los que se pidio contencion.
#[derive(Debug, Default)]
struct Espia(std::sync::Mutex<Vec<u32>>);

#[derive(Debug, Clone)]
struct EspiaRef(Arc<Espia>);

impl Responder for EspiaRef {
    fn contain(&self, pid: u32) -> ContainmentOutcome {
        self.0 .0.lock().unwrap().push(pid);
        ContainmentOutcome::Killed { processes: 1 }
    }
}

/// Flujo pseudoaleatorio de calidad suficiente para que la entropia medida sea
/// la de datos cifrados de verdad.
struct Flujo([u64; 4]);

impl Flujo {
    fn nuevo(semilla: u64) -> Flujo {
        let mut x = semilla;
        let mut sig = || {
            x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = x;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };
        Flujo([sig(), sig(), sig(), sig()])
    }
    fn siguiente(&mut self) -> u64 {
        let s = &mut self.0;
        let r = s[0].wrapping_add(s[3]).rotate_left(23).wrapping_add(s[0]);
        let t = s[1] << 17;
        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];
        s[2] ^= t;
        s[3] = s[3].rotate_left(45);
        r
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        while v.len() < n {
            v.extend_from_slice(&self.siguiente().to_le_bytes());
        }
        v.truncate(n);
        v
    }
}

fn texto(n: usize) -> Vec<u8> {
    const F: &str = "Acta de la reunion del comite, con anexos y presupuesto.\n";
    F.as_bytes().iter().copied().cycle().take(n).collect()
}

fn bind(actor: u64, pid: u32, fd: i32, path: &str, flags: u32, ts_ns: u64) -> TelemetryEvent {
    TelemetryEvent::FdBind {
        actor: ProcKey(actor),
        pid,
        fd,
        path: Arc::from(path),
        open_flags: flags,
        ts_ns,
    }
}

fn write(actor: u64, pid: u32, fd: i32, sample: &[u8], ts_ns: u64) -> TelemetryEvent {
    TelemetryEvent::FileWriteSample {
        actor: ProcKey(actor),
        pid,
        fd,
        bytes: 8192,
        sample: Arc::from(sample),
        distinct_bytes: 0,
        ts_ns,
    }
}

/// Una escritura llega con descriptor y sin ruta. Si la asociacion no se
/// resolviese, el motor no veria ni velocidad ni dispersion: todas las
/// escrituras del sistema pareceria que van al mismo sitio.
#[test]
fn la_ruta_de_una_escritura_se_resuelve_desde_el_descriptor() {
    let mut etapa = RansomStage::new(RansomwareEngine::new(
        EngineConfig::default(),
        HoneypotSet::default(),
    ));

    let mut f = Flujo::nuevo(1);
    let cifrado = f.bytes(512);
    let mut t = 0u64;

    for i in 0..30u64 {
        let ruta = format!("/home/u/docs{}/informe-{i}.docx", i % 6);
        let fd = 3 + (i as i32 % 4);
        t += MS;
        etapa.on_event(&bind(0xA1, 100, fd, &ruta, O_WRONLY, t));
        t += MS;
        etapa.on_event(&write(0xA1, 100, fd, &cifrado, t));
    }

    let s = etapa.stats();
    assert_eq!(s.writes, 30);
    assert_eq!(
        s.writes_sin_ruta, 0,
        "todas las escrituras tenian su descriptor asociado"
    );

    let estado = etapa.engine().tracker().state(0xA1).unwrap();
    assert_eq!(estado.distinct_files(), 30, "30 rutas distintas");
    assert_eq!(estado.distinct_dirs(), 6, "6 directorios distintos");
}

/// Un `write` sobre un descriptor que el agente nunca vio abrir (el proceso ya
/// existia al arrancar el agente) se cuenta igual, sin ruta. Descartarlo seria
/// dejar ciego al agente durante su primer minuto de vida.
#[test]
fn una_escritura_sin_asociacion_previa_se_cuenta_sin_ruta() {
    let mut etapa = RansomStage::new(RansomwareEngine::new(
        EngineConfig::default(),
        HoneypotSet::default(),
    ));
    let mut f = Flujo::nuevo(2);
    let m = f.bytes(512);
    etapa.on_event(&write(0xB2, 200, 7, &m, 1_000));

    let s = etapa.stats();
    assert_eq!(s.writes, 1);
    assert_eq!(s.writes_sin_ruta, 1);
    let estado = etapa.engine().tracker().state(0xB2).unwrap();
    assert_eq!(estado.writes(), 1, "la escritura si cuenta");
    assert_eq!(estado.distinct_files(), 0, "pero no aporta ninguna ruta");
    assert_eq!(estado.high_entropy_writes(), 1, "y su entropia si se mide");
}

/// La confirmacion en la APERTURA: el senuelo se detecta antes de que el
/// cifrador escriba un solo byte.
#[test]
fn abrir_un_senuelo_para_escritura_confirma_y_contiene() {
    let lab = Lab::nuevo("senuelo");
    let docs = lab.path().join("Documentos");
    std::fs::create_dir_all(&docs).unwrap();
    let set = HoneypotSet::deploy(&HoneypotConfig {
        directories: vec![docs],
        per_directory: 2,
    })
    .unwrap();
    let canario = set.paths().next().unwrap().to_str().unwrap().to_string();

    let espia = Arc::new(Espia::default());
    let mut etapa = RansomStage::new(
        RansomwareEngine::new(EngineConfig::default(), set)
            .with_responder(Box::new(EspiaRef(espia.clone()))),
    );

    let accion = etapa
        .on_event(&bind(0xC3, 4242, 9, &canario, O_WRONLY, 5_000))
        .expect("abrir un senuelo para escritura tiene que confirmar");
    let RansomAction {
        detection,
        containment,
    } = accion;
    assert!(detection.verdict.is_ransomware(), "{:?}", detection.verdict);
    assert_eq!(
        containment,
        Some(ContainmentOutcome::Killed { processes: 1 })
    );
    assert_eq!(espia.0.lock().unwrap().as_slice(), &[4242]);
    assert_eq!(etapa.stats().confirmadas, 1);
}

/// Abrir un senuelo para LECTURA no es ransomware. Un indexador de escritorio o
/// una copia de seguridad lo leeran, y matarlos por eso seria peor que no tener
/// senuelos.
#[test]
fn leer_un_senuelo_no_dispara_nada() {
    let lab = Lab::nuevo("lectura");
    let docs = lab.path().join("Documentos");
    std::fs::create_dir_all(&docs).unwrap();
    let set = HoneypotSet::deploy(&HoneypotConfig {
        directories: vec![docs],
        per_directory: 2,
    })
    .unwrap();
    let canario = set.paths().next().unwrap().to_str().unwrap().to_string();

    let espia = Arc::new(Espia::default());
    let mut etapa = RansomStage::new(
        RansomwareEngine::new(EngineConfig::default(), set)
            .with_responder(Box::new(EspiaRef(espia.clone()))),
    );

    assert!(etapa
        .on_event(&bind(0xD4, 555, 3, &canario, O_RDONLY, 1_000))
        .is_none());
    assert!(espia.0.lock().unwrap().is_empty());
    assert_eq!(etapa.stats().confirmadas, 0);
}

/// Un `openat` fallido devuelve un descriptor negativo. Si se registrase, la
/// siguiente escritura sobre un `fd` cualquiera se atribuiria a esa ruta.
#[test]
fn un_openat_fallido_no_asocia_nada() {
    let mut etapa = RansomStage::new(RansomwareEngine::new(
        EngineConfig::default(),
        HoneypotSet::default(),
    ));
    etapa.on_event(&bind(0xE5, 1, -13, "/etc/shadow", O_WRONLY, 100));
    assert_eq!(etapa.fds().tracked_fds(), 0);
    assert_eq!(etapa.fds().resolve(0xE5, -13), None);
}

/// El PID se reutiliza; la clave de actor no. Si la tabla estuviese indexada
/// por PID, el proceso nuevo heredaria los descriptores del muerto.
#[test]
fn dos_actores_con_el_mismo_pid_no_comparten_descriptores() {
    let mut etapa = RansomStage::new(RansomwareEngine::new(
        EngineConfig::default(),
        HoneypotSet::default(),
    ));
    etapa.on_event(&bind(
        0x1111,
        4242,
        3,
        "/home/u/secreto.docx",
        O_WRONLY,
        100,
    ));
    etapa.on_event(&bind(0x2222, 4242, 4, "/home/u/otro.docx", O_WRONLY, 200));

    assert_eq!(etapa.fds().resolve(0x1111, 3), Some("/home/u/secreto.docx"));
    assert_eq!(
        etapa.fds().resolve(0x2222, 3),
        None,
        "el actor nuevo no puede ver el descriptor del anterior aunque \
         compartan PID"
    );
}

/// Al morir el proceso se descarta su tabla entera: retenerla seria una fuga
/// proporcional al numero de procesos que ha visto la maquina.
#[test]
fn el_fin_de_proceso_libera_la_tabla_de_descriptores() {
    let mut etapa = RansomStage::new(RansomwareEngine::new(
        EngineConfig::default(),
        HoneypotSet::default(),
    ));
    for fd in 3..40 {
        etapa.on_event(&bind(0xF6, 1, fd, &format!("/tmp/f{fd}"), O_WRONLY, 10));
    }
    assert_eq!(etapa.fds().tracked_fds(), 37);

    etapa.on_event(&TelemetryEvent::Exit {
        actor: ProcKey(0xF6),
        ts_ns: 20,
    });
    assert_eq!(etapa.fds().tracked_fds(), 0);
    assert_eq!(etapa.fds().tracked_processes(), 0);
    assert!(etapa.engine().tracker().state(0xF6).is_none());
}

/// El evento de fin de proceso se pierde cuando el ring se llena, que es justo
/// lo que pasa durante un ataque. Sin poda por antiguedad, la tabla se quedaria
/// llena de rutas de procesos muertos.
#[test]
fn la_poda_por_antiguedad_recupera_las_tablas_huerfanas() {
    let mut etapa = RansomStage::new(RansomwareEngine::new(
        EngineConfig::default(),
        HoneypotSet::default(),
    ));
    for i in 0..500u64 {
        etapa.on_event(&bind(
            i,
            i as u32,
            3,
            &format!("/tmp/a{i}"),
            O_WRONLY,
            1_000,
        ));
    }
    assert_eq!(etapa.fds().tracked_processes(), 500);

    // Nada vencido todavia.
    let m = etapa.maintain(2_000);
    assert_eq!(m.pruned_fd_tables, 0);

    // Muy por encima de la edad maxima.
    let m = etapa.maintain(10_000_000_000_000);
    assert_eq!(m.pruned_fd_tables, 500);
    assert_eq!(etapa.fds().tracked_processes(), 0);
}

/// El caso completo por la etapa: fase de texto plano, luego cifrado, y
/// confirmacion dentro del presupuesto de dano.
#[test]
fn un_cifrador_visto_por_la_etapa_se_confirma_y_se_contiene_una_vez() {
    let espia = Arc::new(Espia::default());
    let mut etapa = RansomStage::new(
        RansomwareEngine::new(EngineConfig::default(), HoneypotSet::default())
            .with_responder(Box::new(EspiaRef(espia.clone()))),
    );

    let plano = texto(512);
    let mut f = Flujo::nuevo(9);
    let mut t = 0u64;
    let actor = 0xC1F4;

    // Fase ofimatica: 24 escrituras de texto plano.
    for i in 0..24u64 {
        let fd = 3 + (i as i32 % 3);
        t += 20 * MS;
        etapa.on_event(&bind(
            actor,
            777,
            fd,
            &format!("/home/u/docs/borrador-{i}.odt"),
            O_WRONLY,
            t,
        ));
        t += MS;
        assert!(
            etapa.on_event(&write(actor, 777, fd, &plano, t)).is_none(),
            "escribir texto plano no puede confirmar (escritura {i})"
        );
    }

    // Fase de cifrado.
    let mut confirmada = None;
    for i in 0..200u64 {
        let fd = 3 + (i as i32 % 3);
        t += 2 * MS;
        etapa.on_event(&bind(
            actor,
            777,
            fd,
            &format!("/home/u/docs{}/victima-{i}.odt", i % 5),
            O_WRONLY,
            t,
        ));
        t += MS;
        let cifrado = f.bytes(512);
        if let Some(a) = etapa.on_event(&write(actor, 777, fd, &cifrado, t)) {
            confirmada = Some((i + 1, a));
            break;
        }
    }

    let (ficheros, accion) = confirmada.expect("el cifrador no fue confirmado");
    assert!(
        ficheros <= 20,
        "presupuesto de dano excedido: {ficheros} ficheros"
    );
    assert_eq!(
        accion.containment,
        Some(ContainmentOutcome::Killed { processes: 1 })
    );

    // Sigue escribiendo mientras muere: no puede volver a contenerse.
    for i in 0..20u64 {
        t += MS;
        let cifrado = f.bytes(512);
        if let Some(a) = etapa.on_event(&write(actor, 777, 3, &cifrado, t)) {
            assert_eq!(
                a.containment, None,
                "contencion duplicada en la escritura {i} posterior"
            );
        }
    }
    assert_eq!(
        espia.0.lock().unwrap().len(),
        1,
        "el respondedor solo puede invocarse una vez por incidente"
    );
    assert_eq!(etapa.stats().contenciones, 1);
}
