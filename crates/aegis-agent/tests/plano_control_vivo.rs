//! De extremo a extremo: el agente publicado contra el plano de control REAL
//! (H-23, E6.5 del MP-16).
//!
//! Sin dobles en ningun punto:
//!
//! - el binario `aegis-server` de verdad, contra PostgreSQL y Redis reales, con
//!   una CA de flota provisionada en disco como la deja el despliegue;
//! - el enlace del agente (`aegis_agent::plano`) con su configuracion por
//!   fichero, su certificado y su clave en disco y el cliente mTLS de
//!   `aegis-fleet`;
//! - la comprobacion se hace en la BASE DE DATOS, con `psql`: el veredicto tiene
//!   que estar en `alertas` con el CN del certificado del agente.
//!
//! Despues se mata el servidor con SIGKILL, se ofrecen veredictos durante el
//! corte, se relanza, y todo tiene que llegar sin perdida y con la cuenta del
//! enlace cuadrada.
//!
//! Si falta el servidor o algun servicio, lo decide `aegis_prueba`: make ci
//! exige los servicios (la prueba falla) y anota cualquier otra omision. La lanza
//! `tools/verificar-flota-viva.sh` (grupo `flota-viva` de make ci), que compila
//! el servidor y pone `AEGIS_SERVER_BIN`.

#![cfg(unix)]

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use aegis_agent::plano::{self, PlanoControl, CATEGORIA};
use aegis_entidad::entidad::maquina;
use aegis_entidad::{Confianza, Juicio, Motor, Plano, Resultado, Senal, Severidad, Veredicto};
use aegis_fleet::AutoridadCertificadora;

/// Holgura sobre lo que el enlace declara que cuesta (coste fijo mas cola)
/// para el crecimiento del proceso: el asignador y la inicializacion de TLS no
/// devuelven la memoria al byte.
const TOLERANCIA_MEMORIA: u64 = 4 * 1024 * 1024;

use aegis_prueba::{omitir, Requisito};

fn url_pg() -> String {
    std::env::var("AEGIS_TEST_PG_URL")
        .unwrap_or_else(|_| "postgres://postgres@%2Fvar%2Frun%2Fpostgresql/aegis_test".to_string())
}

fn url_redis() -> String {
    std::env::var("AEGIS_TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string())
}

/// Una consulta de una sola fila con `psql`; campos separados por `|`.
fn psql(sql: &str) -> Option<String> {
    let salida = Command::new("psql")
        .arg(url_pg())
        .args(["-X", "-A", "-t", "-q", "-v", "ON_ERROR_STOP=1", "-c", sql])
        .output()
        .ok()?;
    salida
        .status
        .success()
        .then(|| String::from_utf8_lossy(&salida.stdout).trim().to_string())
}

fn redis_vivo() -> bool {
    let url = url_redis();
    let destino = url
        .trim_start_matches("redis://")
        .split('/')
        .next()
        .unwrap_or("")
        .rsplit('@')
        .next()
        .unwrap_or("")
        .to_string();
    let Ok(mut s) = TcpStream::connect(destino.as_str()) else {
        return false;
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    if s.write_all(b"PING\r\n").is_err() {
        return false;
    }
    let mut b = [0u8; 16];
    matches!(s.read(&mut b), Ok(n) if b[..n].starts_with(b"+PONG"))
}

fn unico() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:x}{:x}", std::process::id(), nanos)
}

/// Directorio propio de la prueba, que se borra al terminar.
struct Temporal(PathBuf);

impl Temporal {
    fn nuevo() -> Temporal {
        let d = std::env::temp_dir().join(format!("aegis-flota-viva-{}", unico()));
        fs::create_dir_all(&d).expect("directorio temporal");
        fs::set_permissions(&d, fs::Permissions::from_mode(0o700)).expect("permisos");
        Temporal(d)
    }
}

impl Drop for Temporal {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Crea un fichero con su modo desde el principio, como hace el despliegue.
fn escribir(ruta: &Path, contenido: &str, modo: u32) {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(modo)
        .open(ruta)
        .unwrap_or_else(|e| panic!("crear {}: {e}", ruta.display()));
    f.write_all(contenido.as_bytes()).expect("escribir");
    // `mode()` pasa por la umask: se fija ademas a mano.
    fs::set_permissions(ruta, fs::Permissions::from_mode(modo)).expect("permisos");
}

fn puerto_libre() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("puerto libre")
}

fn cola_del_log(log: &Path) -> String {
    let texto = fs::read_to_string(log).unwrap_or_default();
    let lineas: Vec<&str> = texto.lines().collect();
    lineas[lineas.len().saturating_sub(40)..].join("\n")
}

/// El binario `aegis-server`, como proceso hijo. Muere con la prueba.
struct Servidor {
    hijo: Child,
}

impl Servidor {
    fn lanzar(bin: &Path, ca_dir: &Path, puertos: [u16; 3], log: &Path) -> Servidor {
        let salida = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log)
            .expect("log del servidor");
        let hijo = Command::new(bin)
            .env("AEGIS_PG_URL", url_pg())
            .env("AEGIS_REDIS_URL", url_redis())
            .env("AEGIS_API_ADDR", format!("127.0.0.1:{}", puertos[0]))
            .env("AEGIS_GRPC_ADDR", format!("127.0.0.1:{}", puertos[1]))
            .env("AEGIS_FLEET_ADDR", format!("127.0.0.1:{}", puertos[2]))
            .env("AEGIS_CA_DIR", ca_dir)
            .env("AEGIS_INTERVALO_LATIDO_SEG", "1")
            .env("AEGIS_LOG", "info,sqlx=warn")
            .env_remove("AEGIS_FIREHOSE_DIR")
            .env_remove("AEGIS_SYSLOG_SERVIDOR")
            .stdin(Stdio::null())
            .stdout(salida.try_clone().expect("log"))
            .stderr(salida)
            .spawn()
            .unwrap_or_else(|e| panic!("lanzar {}: {e}", bin.display()));
        let mut s = Servidor { hijo };
        let limite = Instant::now() + Duration::from_secs(120);
        while TcpStream::connect(("127.0.0.1", puertos[2])).is_err() {
            if let Ok(Some(estado)) = s.hijo.try_wait() {
                panic!(
                    "aegis-server salio ({estado}) antes de escuchar:\n{}",
                    cola_del_log(log)
                );
            }
            assert!(
                Instant::now() < limite,
                "aegis-server no escucha la flota en 120 s:\n{}",
                cola_del_log(log)
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        s
    }

    /// SIGKILL: un corte de verdad, sin cierre ordenado.
    fn matar(mut self) {
        let _ = self.hijo.kill();
        let _ = self.hijo.wait();
    }
}

impl Drop for Servidor {
    fn drop(&mut self) {
        let _ = self.hijo.kill();
        let _ = self.hijo.wait();
    }
}

fn esperar(que: &str, plazo: Duration, log: &Path, mut cond: impl FnMut() -> bool) {
    let limite = Instant::now() + plazo;
    while !cond() {
        assert!(
            Instant::now() < limite,
            "no llego a pasar en {plazo:?}: {que}\n--- log del servidor ---\n{}",
            cola_del_log(log)
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn veredicto(porque: &str) -> Veredicto {
    let entidad = maquina("flota-viva");
    Veredicto {
        entidad: entidad.clone(),
        resultado: Resultado::Malicioso,
        severidad: Severidad::Critica,
        confianza: Confianza::ALTA,
        porque: porque.to_string(),
        planos: vec![Plano::Conductual],
        senales: vec![Senal {
            motor: Motor::Conductual,
            entidad,
            juicio: Juicio::Malicioso,
            severidad: Severidad::Critica,
            confianza: Confianza::ALTA,
            porque: porque.to_string(),
            cuando_ns: 1,
        }],
    }
}

#[test]
#[ignore = "necesita aegis-server, PostgreSQL, Redis y psql: lo ejerce `make ci SOLO=flota-viva`"]
fn el_agente_publicado_reporta_al_plano_de_control_real_y_reconcilia_tras_un_corte() {
    let Some(bin) = std::env::var_os("AEGIS_SERVER_BIN").map(PathBuf::from) else {
        omitir(
            "sin AEGIS_SERVER_BIN (lo pone tools/verificar-flota-viva.sh)",
            Requisito::Herramienta("aegis-server"),
        );
        return;
    };
    if psql("SELECT 1").as_deref() != Some("1") {
        omitir(
            &format!("no hay PostgreSQL (o psql) en {}", url_pg()),
            Requisito::Postgresql,
        );
        return;
    }
    if !redis_vivo() {
        omitir(
            &format!("no hay Redis en {}", url_redis()),
            Requisito::Redis,
        );
        return;
    }

    let tmp = Temporal::nuevo();

    // 1. La CA de flota, provisionada en disco como la deja el despliegue.
    let ca = AutoridadCertificadora::nueva("AegisFleet Root CA").expect("CA de flota");
    let ca_dir = tmp.0.join("ca");
    fs::create_dir(&ca_dir).expect("directorio de la CA");
    fs::set_permissions(&ca_dir, fs::Permissions::from_mode(0o700)).expect("permisos");
    let ca_crt = ca_dir.join("flota-ca.crt");
    escribir(&ca_crt, &ca.cert_pem(), 0o644);
    escribir(&ca_dir.join("flota-ca.key"), &ca.clave_pem(), 0o600);

    // 2. La identidad del agente, en ficheros: certificado y clave 0600.
    let cn = format!("agente-e2e-{}", unico());
    let identidad = ca.emitir(&cn, 3600).expect("identidad del agente");
    let pki = tmp.0.join("pki");
    fs::create_dir(&pki).expect("directorio pki");
    let (crt, key) = (pki.join("agente.crt"), pki.join("agente.key"));
    escribir(&crt, &identidad.cert_pem(), 0o644);
    escribir(&key, &identidad.clave_pem(), 0o600);

    // 3. El plano de control de verdad.
    let puertos = [puerto_libre(), puerto_libre(), puerto_libre()];
    let log = tmp.0.join("servidor.log");
    let servidor = Servidor::lanzar(&bin, &ca_dir, puertos, &log);

    // 4. La configuracion del agente, por fichero, leida como en produccion.
    let ruta_cfg = tmp.0.join("plano-control.toml");
    escribir(
        &ruta_cfg,
        &format!(
            "[flota]\nservidor = \"127.0.0.1:{}\"\nca = \"{}\"\ncertificado = \"{}\"\n\
             clave = \"{}\"\nreintento_max_seg = 1\nplazo_red_seg = 5\n",
            puertos[2],
            ca_crt.display(),
            crt.display(),
            key.display()
        ),
        0o644,
    );
    let cfg = plano::cargar(&ruta_cfg, true)
        .expect("configuracion valida")
        .expect("hay configuracion");

    let antes = aegis_presupuesto::uso_propio();
    let (agente, avisos) =
        PlanoControl::arrancar_con(&cfg, aegis_presupuesto::efectivo(), "e2e").expect("enlace");
    assert!(avisos.is_empty(), "{avisos:?}");
    assert_eq!(agente.cn(), cn);
    let capacidad = agente.capacidad_bytes();
    agente.publicar_estado(plano::estado_motores_json(&[], &[], 1, 0, 0));

    // 5. Un veredicto sintetico: tiene que quedar en la base con el CN del
    //    certificado.
    agente.ofrecer(&veredicto("flota viva: veredicto sintetico 1"));
    esperar(
        "el primer veredicto llega",
        Duration::from_secs(60),
        &log,
        || agente.instantanea().enviados == 1,
    );
    let fila = psql(&format!(
        "SELECT a.cn_agente, a.categoria, a.severidad, a.detalles->>'id_veredicto', \
                a.detalles->>'solo_auditoria', g.id_agente \
           FROM alertas a JOIN agentes g ON g.cn = a.cn_agente \
          WHERE a.cn_agente = '{cn}'"
    ))
    .expect("consulta de la alerta");
    let campos: Vec<&str> = fila.split('|').collect();
    assert_eq!(
        campos.len(),
        6,
        "una sola alerta y con todos sus campos: «{fila}»"
    );
    assert_eq!(campos[0], cn, "la alerta es del CN del certificado");
    assert_eq!(campos[1], CATEGORIA);
    assert_eq!(campos[2], "4", "critica en la escala del cable");
    assert!(campos[3].ends_with("-1"), "id_veredicto «{}»", campos[3]);
    assert_eq!(campos[4], "true");
    assert_eq!(campos[5], cn, "el inventario tiene al agente por su CN");

    // 6. El corte: SIGKILL al servidor, y tres veredictos mientras no esta.
    servidor.matar();
    for i in 2..=4 {
        agente.ofrecer(&veredicto(&format!("flota viva: durante el corte {i}")));
    }
    esperar(
        "el enlace nota el corte",
        Duration::from_secs(30),
        &log,
        || {
            let i = agente.instantanea();
            !i.conectado && i.en_cola == 3
        },
    );
    assert_eq!(agente.instantanea().enviados, 1);

    // 7. Vuelve, en los mismos puertos, y la cola se reconcilia.
    let servidor = Servidor::lanzar(&bin, &ca_dir, puertos, &log);
    esperar("la reconciliacion", Duration::from_secs(60), &log, || {
        agente.instantanea().enviados == 4
    });
    let recuento = psql(&format!(
        "SELECT count(*), count(DISTINCT detalles->>'id_veredicto') \
           FROM alertas WHERE cn_agente = '{cn}'"
    ))
    .expect("recuento");
    let (total, distintos) = recuento.split_once('|').expect("dos columnas");
    assert_eq!(
        distintos, "4",
        "los cuatro veredictos, cada uno una vez al menos"
    );
    assert!(total.parse::<u64>().is_ok_and(|n| n >= 4), "{recuento}");

    // 8. El estado de los motores y del enlace, en el inventario del agente.
    esperar(
        "el estado con la cuenta al dia",
        Duration::from_secs(30),
        &log,
        || {
            psql(&format!(
                "SELECT estado_agente->'enlace'->>'enviados' FROM agentes WHERE cn = '{cn}'"
            ))
            .as_deref()
                == Some("4")
        },
    );
    let motores = psql(&format!(
        "SELECT estado_agente->'agente'->>'veredictos', estado_agente->'enlace'->>'cuadra' \
           FROM agentes WHERE cn = '{cn}'"
    ));
    assert_eq!(motores.as_deref(), Some("1|true"));

    // 9. La cuenta cuadra, nada se perdio, y el enlace cabe en lo que declara.
    let fin = agente.parar();
    assert!(fin.cuadra(), "{fin:?}");
    assert_eq!((fin.perdidos(), fin.en_cola), (0, 0), "{fin:?}");
    assert!(
        fin.conexiones >= 2,
        "una sesion antes del corte y otra despues: {fin:?}"
    );
    if let (Some(a), Some(d)) = (antes, aegis_presupuesto::uso_propio()) {
        let crecimiento = d.anonima.saturating_sub(a.anonima);
        let declarado = (aegis_fleet::enlace::COSTE_FIJO + capacidad) as u64;
        println!(
            "AEGIS-MEDIDA flota_viva crecimiento_bytes={crecimiento} declarado_bytes={declarado} \
             pico_cola_bytes={} reenviados={} conexiones={} fallos_conexion={}",
            fin.pico_bytes, fin.reenviados, fin.conexiones, fin.fallos_conexion
        );
        assert!(
            crecimiento <= declarado + TOLERANCIA_MEMORIA,
            "el enlace hizo crecer el proceso {crecimiento} bytes y declara {declarado}"
        );
    }

    // Limpieza: el agente de prueba sale del inventario (y sus alertas, en
    // cascada), para no ensuciar la base que comparten las pruebas.
    let _ = psql(&format!("DELETE FROM agentes WHERE cn = '{cn}'"));
    drop(servidor);
}
