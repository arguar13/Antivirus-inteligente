//! Caos del plano de control con PROCESOS REALES (E6.17, FASE 6.4 del MP-16).
//!
//! Invariante 7 extendida: **ninguna caida de una dependencia del plano de
//! control produce perdida silenciosa**. Cada veredicto ofrecido por un agente
//! acaba, al final de cada escenario, en uno de tres sitios, y la cuenta es
//! EXACTA:
//!
//! ```text
//! ofrecidos = persistidos (distintos, en PostgreSQL) + pendientes (colas) + perdidos declarados
//! ```
//!
//! y, hacia el SIEM:
//!
//! ```text
//! persistidos = recibidos por el SIEM (distintos) + pendientes del diario + perdidos declarados
//! ```
//!
//! Sin dobles: el binario `aegis-server` de verdad (`CARGO_BIN_EXE`), un
//! PostgreSQL PROPIO de cada escenario (initdb en un temporal, para poder
//! tumbarlo con `pg_ctl stop -m immediate` sin tocar el del CI), un
//! `redis-server` propio, agentes con el enlace de produccion
//! (`aegis_fleet::enlace`, mTLS real) y, para el SIEM, un colector syslog-TLS
//! que es OTRO PROCESO (este mismo binario de pruebas en el papel
//! `papel_sumidero_siem`) al que se le hace `kill -9` y `SIGSTOP` de verdad.
//!
//! El reloj desviado usa libfaketime sobre otro proceso agente (papel
//! `papel_agente_desviado`): mueve `CLOCK_REALTIME` solo para ese proceso, que
//! es lo que un espacio de nombres de tiempo de Linux no puede hacer.
//!
//! Todo lleva `#[ignore]`: lo lanza `tools/verificar-caos.sh` (grupo
//! `caos-plano` de make ci), en serie. Sin PostgreSQL, Redis o libfaketime se
//! omite diciendolo; con `AEGIS_EXIGIR=servicios,programa` (el del grupo), la
//! omision es un FALLO.

#![cfg(unix)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aegis_fleet::enlace::{ConectorFlota, ConfigEnlace, Enlace, Instantanea, Medida, Reportable};
use aegis_fleet::proto::ReporteEvento;
use aegis_fleet::{
    ahora_unix, AutoridadCertificadora, EmisorIdentidad, Identidad, PoliticaRotacion,
    RotadorCertificados,
};
use aegis_prueba::{omitir, Requisito};

/// Binario del plano de control, el recien compilado por cargo.
const SERVIDOR: &str = env!("CARGO_BIN_EXE_aegis-server");

/// Segundos de corte de PostgreSQL. El PLAN pide 60; por defecto 20 para que el
/// grupo quepa en make ci. `AEGIS_CAOS_CORTE_SEG` lo sube.
fn corte_seg() -> u64 {
    std::env::var("AEGIS_CAOS_CORTE_SEG")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20)
}

/// Segundos de colector SIEM muerto. El PLAN pide 300 (`AEGIS_CAOS_SIEM_SEG`).
fn siem_seg() -> u64 {
    std::env::var("AEGIS_CAOS_SIEM_SEG")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(15)
}

// ---------------------------------------------------------------------------
// Utilidades
// ---------------------------------------------------------------------------

fn unico() -> String {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:x}{:x}", std::process::id(), n % 0xffff_ffff)
}

fn puerto_libre() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("puerto libre")
}

fn esperar(que: &str, plazo: Duration, mut cond: impl FnMut() -> bool) {
    let limite = Instant::now() + plazo;
    while !cond() {
        assert!(
            Instant::now() < limite,
            "no llego a pasar en {plazo:?}: {que}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn es_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .map(|s| String::from_utf8_lossy(&s.stdout).trim() == "0")
        .unwrap_or(false)
}

/// Busca un ejecutable en el PATH.
fn en_path(nombre: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|p| {
        std::env::split_paths(&p)
            .map(|d| d.join(nombre))
            .find(|c| c.is_file())
    })
}

/// Senal a un proceso por su PID, con `kill`: sin `libc` en el arbol.
fn senal(pid: u32, s: &str) {
    let _ = Command::new("kill").args([s, &pid.to_string()]).status();
}

/// Directorio del escenario: 0755 para que el usuario `postgres` lo atraviese.
struct Temporal(PathBuf);

impl Temporal {
    fn nuevo(etiqueta: &str) -> Temporal {
        let d = std::env::temp_dir().join(format!("aegis-caos-{etiqueta}-{}", unico()));
        fs::create_dir_all(&d).expect("temporal");
        fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).expect("permisos");
        Temporal(d)
    }
}

impl Drop for Temporal {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn cola_de(log: &Path) -> String {
    let t = fs::read_to_string(log).unwrap_or_default();
    let l: Vec<&str> = t.lines().collect();
    l[l.len().saturating_sub(40)..].join("\n")
}

// ---------------------------------------------------------------------------
// PostgreSQL propio
// ---------------------------------------------------------------------------

/// Directorio de binarios de PostgreSQL: `AEGIS_PG_BIN`, o la version mas alta
/// de `/usr/lib/postgresql/*/bin` (Debian y Ubuntu no los ponen en el PATH).
fn bin_pg() -> Option<PathBuf> {
    if let Some(d) = std::env::var_os("AEGIS_PG_BIN") {
        return Some(PathBuf::from(d));
    }
    if let Some(initdb) = en_path("initdb") {
        return initdb.parent().map(Path::to_path_buf);
    }
    let mut versiones: Vec<(u32, PathBuf)> = fs::read_dir("/usr/lib/postgresql")
        .ok()?
        .flatten()
        .filter_map(|e| {
            let v: u32 = e.file_name().to_string_lossy().parse().ok()?;
            let bin = e.path().join("bin");
            bin.join("initdb").is_file().then_some((v, bin))
        })
        .collect();
    versiones.sort();
    versiones.pop().map(|(_, b)| b)
}

struct Pg {
    bin: PathBuf,
    datos: PathBuf,
    puerto: u16,
    root: bool,
}

impl Pg {
    /// `initdb` en `dir/pg`. Como root, todo lo hace el usuario `postgres`.
    fn crear(dir: &Path) -> Result<Pg, String> {
        let bin = bin_pg().ok_or("no hay binarios de PostgreSQL (initdb, pg_ctl)")?;
        let root = es_root();
        let datos = dir.join("pg");
        fs::create_dir_all(&datos).map_err(|e| e.to_string())?;
        if root {
            let ok = Command::new("chown")
                .args(["-R", "postgres:postgres"])
                .arg(&datos)
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if !ok {
                return Err("como root hace falta el usuario postgres (chown fallo)".into());
            }
        }
        let pg = Pg {
            bin,
            datos,
            puerto: puerto_libre(),
            root,
        };
        let salida = pg
            .orden("initdb")
            .args([
                "-A",
                "trust",
                "-U",
                "postgres",
                "-E",
                "UTF8",
                "--no-sync",
                "-D",
            ])
            .arg(&pg.datos)
            .output()
            .map_err(|e| format!("initdb: {e}"))?;
        if !salida.status.success() {
            return Err(format!(
                "initdb fallo: {}",
                String::from_utf8_lossy(&salida.stderr)
            ));
        }
        Ok(pg)
    }

    fn orden(&self, programa: &str) -> Command {
        let ruta = self.bin.join(programa);
        if self.root {
            let mut c = Command::new("runuser");
            c.args(["-u", "postgres", "--"]).arg(ruta);
            c
        } else {
            Command::new(ruta)
        }
    }

    fn arrancar(&self) {
        let opciones = format!(
            "-p {} -c listen_addresses=127.0.0.1 -c unix_socket_directories='' \
             -c fsync=off -c full_page_writes=off -c max_connections=60",
            self.puerto
        );
        // El log lo escribe postgres: va dentro de su directorio de datos.
        let ok = self
            .orden("pg_ctl")
            .args(["-w", "-t", "60", "-D"])
            .arg(&self.datos)
            .args(["-o", &opciones, "-l"])
            .arg(self.datos.join("arranque.log"))
            .arg("start")
            .stdout(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(
            ok,
            "pg_ctl start fallo:\n{}",
            cola_de(&self.datos.join("arranque.log"))
        );
    }

    /// Caida de verdad: `-m immediate` es un SIGQUIT al postmaster, sin
    /// punto de control ni despedida a los clientes.
    fn tumbar(&self) {
        let _ = self
            .orden("pg_ctl")
            .args(["-D"])
            .arg(&self.datos)
            .args(["-m", "immediate", "stop"])
            .stdout(Stdio::null())
            .status();
    }

    fn url(&self) -> String {
        format!("postgres://postgres@127.0.0.1:{}/postgres", self.puerto)
    }
}

impl Drop for Pg {
    fn drop(&mut self) {
        self.tumbar();
    }
}

// ---------------------------------------------------------------------------
// Redis propio
// ---------------------------------------------------------------------------

struct Redis {
    bin: PathBuf,
    puerto: u16,
    hijo: Option<Child>,
}

impl Redis {
    fn nuevo() -> Result<Redis, String> {
        let bin = std::env::var_os("AEGIS_REDIS_SERVER")
            .map(PathBuf::from)
            .or_else(|| en_path("redis-server"))
            .ok_or("no hay redis-server")?;
        Ok(Redis {
            bin,
            puerto: puerto_libre(),
            hijo: None,
        })
    }

    /// Sin persistencia: al volver, las sesiones se han perdido de verdad.
    fn arrancar(&mut self) {
        let hijo = Command::new(&self.bin)
            .args([
                "--port",
                &self.puerto.to_string(),
                "--bind",
                "127.0.0.1",
                "--save",
                "",
                "--appendonly",
                "no",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("redis-server");
        self.hijo = Some(hijo);
        let p = self.puerto;
        esperar("redis escucha", Duration::from_secs(20), || {
            TcpStream::connect(("127.0.0.1", p)).is_ok()
        });
    }

    fn matar(&mut self) {
        if let Some(mut h) = self.hijo.take() {
            let _ = h.kill();
            let _ = h.wait();
        }
    }

    fn url(&self) -> String {
        format!("redis://127.0.0.1:{}", self.puerto)
    }
}

impl Drop for Redis {
    fn drop(&mut self) {
        self.matar();
    }
}

// ---------------------------------------------------------------------------
// El plano de control
// ---------------------------------------------------------------------------

struct Servidor {
    hijo: Child,
    log: PathBuf,
    api: u16,
    flota: u16,
}

impl Servidor {
    fn lanzar(dir: &Path, pg: &str, redis: &str, extra: &[(&str, String)]) -> Servidor {
        let ca = dir.join("ca");
        let log = dir.join("servidor.log");
        let salida = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)
            .expect("log");
        let (api, grpc, flota) = (puerto_libre(), puerto_libre(), puerto_libre());
        let mut c = Command::new(SERVIDOR);
        c.env("AEGIS_PG_URL", pg)
            .env("AEGIS_REDIS_URL", redis)
            .env("AEGIS_API_ADDR", format!("127.0.0.1:{api}"))
            .env("AEGIS_GRPC_ADDR", format!("127.0.0.1:{grpc}"))
            .env("AEGIS_FLEET_ADDR", format!("127.0.0.1:{flota}"))
            .env("AEGIS_CA_DIR", &ca)
            .env("AEGIS_INTERVALO_LATIDO_SEG", "1")
            .env("AEGIS_PG_MAX_CONEXIONES", "8")
            .env("AEGIS_RETENCION_MESES", "0")
            .env("AEGIS_LOG", "info,sqlx=warn")
            .env_remove("AEGIS_FIREHOSE_DIR")
            .env_remove("AEGIS_SYSLOG_SERVIDOR");
        for (k, v) in extra {
            c.env(k, v);
        }
        let hijo = c
            .stdin(Stdio::null())
            .stdout(salida.try_clone().expect("log"))
            .stderr(salida)
            .spawn()
            .expect("lanzar aegis-server");
        let mut s = Servidor {
            hijo,
            log,
            api,
            flota,
        };
        let limite = Instant::now() + Duration::from_secs(180);
        while TcpStream::connect(("127.0.0.1", s.flota)).is_err()
            || TcpStream::connect(("127.0.0.1", s.api)).is_err()
        {
            if let Ok(Some(e)) = s.hijo.try_wait() {
                panic!("aegis-server salio ({e}):\n{}", cola_de(&s.log));
            }
            assert!(
                Instant::now() < limite,
                "aegis-server no escucha en 180 s:\n{}",
                cola_de(&s.log)
            );
            std::thread::sleep(Duration::from_millis(200));
        }
        s
    }

    /// Sigue vivo: el mismo proceso, sin reinicio.
    fn vivo(&mut self) -> bool {
        matches!(self.hijo.try_wait(), Ok(None))
    }

    /// `GET /salud`: codigo y cuerpo JSON.
    fn salud(&self) -> Option<(u16, serde_json::Value)> {
        http(self.api, "GET", "/salud", None, None)
    }

    fn ca(&self, dir: &Path) -> AutoridadCertificadora {
        let ca = dir.join("ca");
        let cert = fs::read_to_string(ca.join("flota-ca.crt")).expect("CA de flota");
        let clave = fs::read_to_string(ca.join("flota-ca.key")).expect("clave de la CA");
        AutoridadCertificadora::desde_pem(&cert, &clave).expect("CA legible")
    }
}

impl Drop for Servidor {
    fn drop(&mut self) {
        let _ = self.hijo.kill();
        let _ = self.hijo.wait();
    }
}

/// Un cliente HTTP/1.1 minimo: `Connection: close` y cuerpo hasta el cierre.
fn http(
    puerto: u16,
    metodo: &str,
    ruta: &str,
    token: Option<&str>,
    cuerpo: Option<&serde_json::Value>,
) -> Option<(u16, serde_json::Value)> {
    let mut s = TcpStream::connect(("127.0.0.1", puerto)).ok()?;
    let _ = s.set_read_timeout(Some(Duration::from_secs(15)));
    let cuerpo = cuerpo.map(|c| c.to_string()).unwrap_or_default();
    let mut p = format!("{metodo} {ruta} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
    if let Some(t) = token {
        p.push_str(&format!("Authorization: Bearer {t}\r\n"));
    }
    if !cuerpo.is_empty() {
        p.push_str("Content-Type: application/json\r\n");
    }
    p.push_str(&format!("Content-Length: {}\r\n\r\n{cuerpo}", cuerpo.len()));
    s.write_all(p.as_bytes()).ok()?;
    let mut r = Vec::new();
    let _ = s.read_to_end(&mut r);
    let texto = String::from_utf8_lossy(&r);
    let codigo: u16 = texto.split_whitespace().nth(1)?.parse().ok()?;
    let json = texto
        .split_once("\r\n\r\n")
        .and_then(|(_, b)| serde_json::from_str(b).ok())
        .unwrap_or(serde_json::Value::Null);
    Some((codigo, json))
}

// ---------------------------------------------------------------------------
// Agentes: el enlace de produccion
// ---------------------------------------------------------------------------

/// Un veredicto de prueba con su identificador.
struct Veredicto {
    id: String,
}

impl Reportable for Veredicto {
    fn peso(&self) -> usize {
        256 + self.id.len()
    }
    fn prioridad(&self) -> u8 {
        3
    }
    fn reporte(&self, id_agente: &str) -> ReporteEvento {
        ReporteEvento {
            id_agente: id_agente.to_string(),
            severidad: 3,
            categoria: "caos".to_string(),
            descripcion: format!("caos {}", self.id),
            momento_unix: ahora_unix(),
            detalles_json: format!("{{\"id_veredicto\":\"{}\"}}", self.id),
        }
    }
}

/// Emisor que, mientras `caducados` este puesto, solo da certificados YA
/// caducados: el agente cuyo certificado vencio y aun no se renovo.
struct EmisorControlado {
    ca: Arc<AutoridadCertificadora>,
    caducados: Arc<AtomicBool>,
}

impl EmisorIdentidad for EmisorControlado {
    fn emitir(&self, cn: &str, validez_seg: u64) -> aegis_fleet::Resultado<Identidad> {
        if self.caducados.load(Ordering::SeqCst) {
            let id = self.ca.emitir(cn, 1)?;
            // Pasado su `notAfter`: ningun verificador X.509 lo acepta ya.
            std::thread::sleep(Duration::from_millis(2_100));
            Ok(id)
        } else {
            self.ca.emitir(cn, validez_seg)
        }
    }
}

/// Emisor que entrega siempre la identidad provisionada en ficheros.
struct EmisorFijo {
    cert: String,
    clave: String,
}

impl EmisorIdentidad for EmisorFijo {
    fn emitir(&self, _cn: &str, _validez: u64) -> aegis_fleet::Resultado<Identidad> {
        Identidad::desde_pem(&self.cert, &self.clave)
    }
}

fn config_enlace() -> ConfigEnlace {
    ConfigEnlace {
        // De sobra para el corte: la prueba exige CERO perdidos.
        capacidad_bytes: 8 * 1024 * 1024,
        capacidad_elementos: 50_000,
        latido: Duration::from_secs(1),
        reintento_base: Duration::from_millis(200),
        reintento_tope: Duration::from_secs(2),
        ventana_desfase: Duration::from_millis(500),
        max_rechazos: 5,
        lote: 64,
    }
}

fn agente(
    emisor: Arc<dyn EmisorIdentidad>,
    ca_der: rustls::pki_types::CertificateDer<'static>,
    cn: &str,
    puerto: u16,
) -> (Enlace<Veredicto>, Arc<RotadorCertificados>) {
    let rotador = Arc::new(
        RotadorCertificados::nuevo(
            cn,
            PoliticaRotacion {
                validez_seg: 3600,
                renovar_al_pct: 60,
            },
            emisor,
        )
        .expect("identidad del agente"),
    );
    let conector = ConectorFlota::nuevo(
        &format!("127.0.0.1:{puerto}"),
        ca_der,
        rotador.clone(),
        "caos",
        "caos",
        Duration::from_secs(10),
    );
    let enlace =
        Enlace::arrancar(conector, config_enlace(), Box::new(Medida::default)).expect("enlace");
    (enlace, rotador)
}

/// Productores: cada agente ofrece un veredicto cada `cada` hasta `parar`.
struct Flota {
    enlaces: Vec<Arc<Enlace<Veredicto>>>,
    cns: Vec<String>,
    parar: Arc<AtomicBool>,
    hilos: Vec<std::thread::JoinHandle<()>>,
    ofrecidos: Arc<AtomicU64>,
}

impl Flota {
    fn arrancar(
        ca: &Arc<AutoridadCertificadora>,
        prefijo: &str,
        n: usize,
        puerto: u16,
        cada: Duration,
    ) -> Flota {
        let parar = Arc::new(AtomicBool::new(false));
        let ofrecidos = Arc::new(AtomicU64::new(0));
        let mut enlaces = Vec::new();
        let mut cns = Vec::new();
        let mut hilos = Vec::new();
        for i in 0..n {
            let cn = format!("{prefijo}-{i}.caos");
            let emisor: Arc<dyn EmisorIdentidad> =
                Arc::new(aegis_fleet::EmisorLocal::nuevo(ca.clone()));
            let (e, _) = agente(emisor, ca.cert_der(), &cn, puerto);
            let e = Arc::new(e);
            let (e2, p2, o2, cn2) = (e.clone(), parar.clone(), ofrecidos.clone(), cn.clone());
            hilos.push(std::thread::spawn(move || {
                let mut k = 0u64;
                while !p2.load(Ordering::SeqCst) {
                    e2.ofrecer(Veredicto {
                        id: format!("{cn2}#{k}"),
                    });
                    o2.fetch_add(1, Ordering::SeqCst);
                    k += 1;
                    std::thread::sleep(cada);
                }
            }));
            enlaces.push(e);
            cns.push(cn);
        }
        Flota {
            enlaces,
            cns,
            parar,
            hilos,
            ofrecidos,
        }
    }

    fn dejar_de_producir(&mut self) {
        self.parar.store(true, Ordering::SeqCst);
        for h in self.hilos.drain(..) {
            let _ = h.join();
        }
    }

    fn instantaneas(&self) -> Vec<Instantanea> {
        self.enlaces.iter().map(|e| e.instantanea()).collect()
    }

    fn vaciada(&self) -> bool {
        self.instantaneas().iter().all(|i| i.en_cola == 0)
    }
}

/// Lo persistido de un conjunto de agentes: veredictos distintos y filas.
fn persistidos(pg: &str, cns: &[String]) -> (i64, i64) {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    rt.block_on(async {
        let pool = sqlx::PgPool::connect(pg)
            .await
            .expect("PostgreSQL de la prueba");
        let fila: (i64, i64) = sqlx::query_as(
            "SELECT count(DISTINCT detalles->>'id_veredicto'), count(*)
               FROM alertas WHERE cn_agente = ANY($1)",
        )
        .bind(cns)
        .fetch_one(&pool)
        .await
        .expect("consulta de alertas");
        pool.close().await;
        fila
    })
}

/// La cuenta exacta de la invariante 7 extendida, del lado de la ingesta.
fn cuadrar(
    escenario: &str,
    insts: &[Instantanea],
    distintos: i64,
    filas: i64,
    exigir_cero_perdidos: bool,
) {
    for (n, i) in insts.iter().enumerate() {
        assert!(
            i.cuadra(),
            "{escenario}: el enlace {n} no cuadra: {}",
            i.json()
        );
    }
    let ofrecidos: u64 = insts.iter().map(|i| i.ofrecidos).sum();
    let en_cola: u64 = insts.iter().map(|i| i.en_cola).sum();
    let perdidos: u64 = insts.iter().map(|i| i.perdidos()).sum();
    let aplazados: u64 = insts.iter().map(|i| i.aplazados_por_servidor).sum();
    let reenviados: u64 = insts.iter().map(|i| i.reenviados).sum();
    println!(
        "AEGIS-MEDIDA caos escenario={escenario} ofrecidos={ofrecidos} persistidos={distintos} \
         filas={filas} duplicados={} en_cola={en_cola} perdidos={perdidos} \
         aplazados_por_servidor={aplazados} reenviados={reenviados}",
        filas - distintos
    );
    assert_eq!(
        ofrecidos as i64,
        distintos + en_cola as i64 + perdidos as i64,
        "{escenario}: ofrecidos != persistidos + pendientes + perdidos declarados"
    );
    if exigir_cero_perdidos {
        assert_eq!(
            perdidos, 0,
            "{escenario}: hubo perdida (declarada, pero perdida)"
        );
        assert_eq!(en_cola, 0, "{escenario}: quedo algo sin entregar");
    }
}

/// Requisitos comunes: PostgreSQL y Redis propios.
fn montar(etiqueta: &str) -> Option<(Temporal, Pg, Redis)> {
    let tmp = Temporal::nuevo(etiqueta);
    let pg = match Pg::crear(&tmp.0) {
        Ok(p) => p,
        Err(e) => {
            omitir(&format!("PostgreSQL propio: {e}"), Requisito::Postgresql);
            return None;
        }
    };
    let redis = match Redis::nuevo() {
        Ok(r) => r,
        Err(e) => {
            omitir(&format!("Redis propio: {e}"), Requisito::Redis);
            return None;
        }
    };
    pg.arrancar();
    Some((tmp, pg, redis))
}

// ---------------------------------------------------------------------------
// 1. PostgreSQL cae y vuelve
// ---------------------------------------------------------------------------

#[test]
#[ignore = "caos con procesos reales: tools/verificar-caos.sh (make ci SOLO=caos-plano)"]
fn caos_postgresql_cae_y_vuelve_sin_perdida_y_con_contrapresion() {
    let Some((tmp, pg, mut redis)) = montar("pg") else {
        return;
    };
    redis.arrancar();
    let mut srv = Servidor::lanzar(&tmp.0, &pg.url(), &redis.url(), &[]);
    let ca = Arc::new(srv.ca(&tmp.0));
    let mut flota = Flota::arrancar(
        &ca,
        &format!("pg{}", unico()),
        8,
        srv.flota,
        Duration::from_millis(50),
    );

    esperar("la flota entrega", Duration::from_secs(60), || {
        flota.instantaneas().iter().all(|i| i.enviados > 10)
    });

    // Caida de verdad, con la ingesta en marcha.
    pg.tumbar();
    let fin_corte = Instant::now() + Duration::from_secs(corte_seg());
    let mut vio_503 = false;
    while Instant::now() < fin_corte {
        assert!(
            srv.vivo(),
            "el servidor murio con PostgreSQL caido:\n{}",
            cola_de(&srv.log)
        );
        if let Some((c, cuerpo)) = srv.salud() {
            if c == 503 && cuerpo["postgres"] == false {
                vio_503 = true;
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    assert!(vio_503, "/salud no dijo 503 con PostgreSQL caido");
    let durante = flota.instantaneas();
    assert!(
        durante.iter().map(|i| i.en_cola).sum::<u64>() > 0,
        "con la base caida lo ofrecido tiene que esperar en las colas"
    );
    assert_eq!(
        durante
            .iter()
            .map(|i| i.rechazados_por_servidor)
            .sum::<u64>(),
        0,
        "una caida de la base no puede convertirse en descartes: es contrapresion"
    );

    // Vuelve: el MISMO proceso servidor se recupera solo.
    pg.arrancar();
    esperar(
        "/salud vuelve a 200 sin reiniciar el servidor",
        Duration::from_secs(90),
        || srv.salud().is_some_and(|(c, _)| c == 200),
    );
    assert!(srv.vivo());
    // La escucha de avisos (LISTEN) tambien vuelve: H-42.
    {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let url = pg.url();
        let log = srv.log.clone();
        let limite = Instant::now() + Duration::from_secs(60);
        loop {
            rt.block_on(async {
                if let Ok(pool) = sqlx::PgPool::connect(&url).await {
                    let _ = sqlx::query("SELECT pg_notify('aegis_caza', 'caos')")
                        .execute(&pool)
                        .await;
                    pool.close().await;
                }
            });
            if fs::read_to_string(&log)
                .unwrap_or_default()
                .contains("escucha de avisos restablecida")
            {
                break;
            }
            assert!(
                Instant::now() < limite,
                "la escucha de avisos no se restablecio tras el corte:\n{}",
                cola_de(&log)
            );
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    std::thread::sleep(Duration::from_secs(3));
    flota.dejar_de_producir();
    esperar("las colas se vacian", Duration::from_secs(180), || {
        flota.vaciada()
    });
    let insts = flota.instantaneas();
    assert!(
        insts.iter().map(|i| i.aplazados_por_servidor).sum::<u64>() > 0,
        "no se observo contrapresion del servidor durante el corte"
    );
    let (distintos, filas) = persistidos(&pg.url(), &flota.cns);
    cuadrar("postgresql", &insts, distintos, filas, true);
    assert_eq!(
        flota.ofrecidos.load(Ordering::SeqCst) as i64,
        distintos,
        "todo lo ofrecido esta en PostgreSQL"
    );
}

// ---------------------------------------------------------------------------
// 2. Redis cae y vuelve
// ---------------------------------------------------------------------------

#[test]
#[ignore = "caos con procesos reales: tools/verificar-caos.sh (make ci SOLO=caos-plano)"]
fn caos_redis_cae_y_vuelve_las_sesiones_caducan_y_la_ingesta_sigue() {
    let Some((tmp, pg, mut redis)) = montar("redis") else {
        return;
    };
    redis.arrancar();
    let mut srv = Servidor::lanzar(&tmp.0, &pg.url(), &redis.url(), &[]);
    let ca = Arc::new(srv.ca(&tmp.0));

    // Un operador con sesion, dado de alta por el camino de produccion.
    let usuario = format!("caos-{}", unico());
    {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let pool = sqlx::PgPool::connect(&pg.url()).await.unwrap();
            let hash = aegis_server::credenciales::derivar_con("una clave larga de prueba", 1_000)
                .unwrap();
            aegis_server::credenciales::alta_operador(&pool, &usuario, &hash)
                .await
                .unwrap();
            aegis_server::autorizacion::asignar_rol(
                &pool,
                &usuario,
                aegis_server::autorizacion::Rol::Analista,
                "flota-caos",
            )
            .await
            .unwrap();
            pool.close().await;
        });
    }
    let api = srv.api;
    let entrar = || {
        let (c, v) = http(
            api,
            "POST",
            "/api/sesion",
            None,
            Some(&serde_json::json!({ "usuario": usuario, "clave": "una clave larga de prueba" })),
        )?;
        (c == 200)
            .then(|| v["token"].as_str().map(str::to_string))
            .flatten()
    };
    let token = entrar().expect("sesion antes del corte");
    assert_eq!(
        http(srv.api, "GET", "/api/resumen", Some(&token), None).map(|r| r.0),
        Some(200)
    );

    let mut flota = Flota::arrancar(
        &ca,
        &format!("rd{}", unico()),
        4,
        srv.flota,
        Duration::from_millis(50),
    );
    esperar("la flota entrega", Duration::from_secs(60), || {
        flota.instantaneas().iter().all(|i| i.enviados > 5)
    });

    redis.matar();
    let (antes, _) = persistidos(&pg.url(), &flota.cns);
    let mut vio_503 = false;
    let fin = Instant::now() + Duration::from_secs(10);
    while Instant::now() < fin {
        if let Some((c, v)) = srv.salud() {
            vio_503 |= c == 503 && v["redis"] == false;
        }
        // Sin Redis la API no puede validar sesiones: nunca 200 a ciegas.
        let r = http(srv.api, "GET", "/api/resumen", Some(&token), None).map(|r| r.0);
        assert_ne!(
            r,
            Some(200),
            "sin Redis la API dio por buena una sesion que no pudo comprobar"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    assert!(vio_503, "/salud no dijo 503 con Redis caido");
    let (durante, _) = persistidos(&pg.url(), &flota.cns);
    assert!(
        durante > antes,
        "la ingesta se detuvo con Redis caido ({antes} -> {durante})"
    );
    assert!(srv.vivo());

    redis.arrancar();
    esperar("/salud vuelve a 200", Duration::from_secs(60), || {
        srv.salud().is_some_and(|(c, _)| c == 200)
    });
    // Redis sin persistencia: la sesion vieja ya no existe. Caducidad
    // controlada: 401, y una sesion nueva funciona.
    esperar("la sesion vieja da 401", Duration::from_secs(30), || {
        http(srv.api, "GET", "/api/resumen", Some(&token), None).map(|r| r.0) == Some(401)
    });
    let nuevo = entrar().expect("sesion nueva tras volver Redis");
    assert_eq!(
        http(srv.api, "GET", "/api/resumen", Some(&nuevo), None).map(|r| r.0),
        Some(200)
    );

    flota.dejar_de_producir();
    esperar("las colas se vacian", Duration::from_secs(120), || {
        flota.vaciada()
    });
    let (distintos, filas) = persistidos(&pg.url(), &flota.cns);
    cuadrar("redis", &flota.instantaneas(), distintos, filas, true);
}

// ---------------------------------------------------------------------------
// 3. El certificado del agente caduca
// ---------------------------------------------------------------------------

#[test]
#[ignore = "caos con procesos reales: tools/verificar-caos.sh (make ci SOLO=caos-plano)"]
fn caos_certificado_de_agente_caducado_se_rechaza_y_tras_renovar_no_falta_nada() {
    let Some((tmp, pg, mut redis)) = montar("certag") else {
        return;
    };
    redis.arrancar();
    let srv = Servidor::lanzar(&tmp.0, &pg.url(), &redis.url(), &[]);
    let ca = Arc::new(srv.ca(&tmp.0));
    let caducados = Arc::new(AtomicBool::new(true));
    let cn = format!("caducado-{}.caos", unico());
    let emisor: Arc<dyn EmisorIdentidad> = Arc::new(EmisorControlado {
        ca: ca.clone(),
        caducados: caducados.clone(),
    });
    let (enlace, rotador) = agente(emisor, ca.cert_der(), &cn, srv.flota);
    for k in 0..20 {
        enlace.ofrecer(Veredicto {
            id: format!("{cn}#{k}"),
        });
    }
    esperar(
        "el handshake con certificado caducado se rechaza",
        Duration::from_secs(60),
        || enlace.instantanea().fallos_conexion >= 2,
    );
    let i = enlace.instantanea();
    assert!(!i.conectado);
    assert_eq!(i.enviados, 0);
    assert_eq!(
        i.en_cola,
        20,
        "lo ofrecido espera; no se descarta: {}",
        i.json()
    );
    let (n, _) = persistidos(&pg.url(), std::slice::from_ref(&cn));
    assert_eq!(n, 0, "con un certificado caducado no entra nada");

    // Renovacion: la CA vuelve a emitir certificados vigentes.
    caducados.store(false, Ordering::SeqCst);
    rotador.rotar().expect("rotar");
    esperar("tras renovar, todo llega", Duration::from_secs(60), || {
        enlace.instantanea().en_cola == 0
    });
    let (distintos, filas) = persistidos(&pg.url(), std::slice::from_ref(&cn));
    cuadrar(
        "certificado-agente",
        &[enlace.instantanea()],
        distintos,
        filas,
        true,
    );
    assert_eq!(distintos, 20);
}

// ---------------------------------------------------------------------------
// 4. El certificado del servidor vence en mitad (H-39)
// ---------------------------------------------------------------------------

#[test]
#[ignore = "caos con procesos reales: tools/verificar-caos.sh (make ci SOLO=caos-plano)"]
fn caos_certificado_del_servidor_vence_y_el_servidor_lo_renueva_solo() {
    let Some((tmp, pg, mut redis)) = montar("certsrv") else {
        return;
    };
    redis.arrancar();
    // Seis segundos de vida: en la prueba vence dos veces.
    let srv = Servidor::lanzar(
        &tmp.0,
        &pg.url(),
        &redis.url(),
        &[("AEGIS_VALIDEZ_CERT_SERVIDOR_SEG", "6".to_string())],
    );
    let ca = Arc::new(srv.ca(&tmp.0));
    let pref = format!("certsrv{}", unico());
    let mut primera = Flota::arrancar(
        &ca,
        &format!("{pref}a"),
        1,
        srv.flota,
        Duration::from_millis(200),
    );
    esperar("antes de vencer entrega", Duration::from_secs(60), || {
        primera.instantaneas()[0].enviados >= 3
    });
    primera.dejar_de_producir();

    // Pasadas dos vidas del certificado, un agente NUEVO tiene que poder
    // conectar: el servidor renovo el suyo sin reiniciar.
    std::thread::sleep(Duration::from_secs(15));
    let mut segunda = Flota::arrancar(
        &ca,
        &format!("{pref}b"),
        1,
        srv.flota,
        Duration::from_millis(200),
    );
    esperar(
        "un agente nuevo conecta con el certificado renovado",
        Duration::from_secs(60),
        || segunda.instantaneas()[0].enviados >= 3,
    );
    segunda.dejar_de_producir();
    esperar("vaciado", Duration::from_secs(60), || {
        segunda.vaciada() && primera.vaciada()
    });
    let mut cns = primera.cns.clone();
    cns.extend(segunda.cns.clone());
    let mut insts = primera.instantaneas();
    insts.extend(segunda.instantaneas());
    let (distintos, filas) = persistidos(&pg.url(), &cns);
    cuadrar("certificado-servidor", &insts, distintos, filas, true);
    assert!(
        fs::read_to_string(&srv.log)
            .unwrap_or_default()
            .contains("certificado del plano de control renovado"),
        "el servidor no dejo constancia de la renovacion:\n{}",
        cola_de(&srv.log)
    );
}

// ---------------------------------------------------------------------------
// 5. Reloj desviado +-10 minutos (otro proceso, con libfaketime)
// ---------------------------------------------------------------------------

fn libfaketime() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("AEGIS_LIBFAKETIME") {
        return Some(PathBuf::from(p));
    }
    [
        "/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1",
        "/usr/lib/aarch64-linux-gnu/faketime/libfaketime.so.1",
        "/usr/lib/faketime/libfaketime.so.1",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.is_file())
}

#[test]
#[ignore = "caos con procesos reales: tools/verificar-caos.sh (make ci SOLO=caos-plano)"]
fn caos_reloj_del_agente_desviado_diez_minutos_en_los_dos_sentidos() {
    let Some(lib) = libfaketime() else {
        omitir(
            "no hay libfaketime (apt install libfaketime): sin el no se desvia el reloj de un proceso",
            Requisito::Herramienta("libfaketime"),
        );
        return;
    };
    let Some((tmp, pg, mut redis)) = montar("reloj") else {
        return;
    };
    redis.arrancar();
    let srv = Servidor::lanzar(&tmp.0, &pg.url(), &redis.url(), &[]);
    let ca = srv.ca(&tmp.0);
    let ca_crt = tmp.0.join("ca").join("flota-ca.crt");
    let rt = tokio::runtime::Runtime::new().unwrap();

    for desvio in [600i64, -600] {
        let cn = format!(
            "reloj{}{}.caos",
            if desvio > 0 { "mas" } else { "menos" },
            unico()
        );
        let id = ca.emitir(&cn, 3600).expect("identidad");
        let (crt, key) = (
            tmp.0.join(format!("{cn}.crt")),
            tmp.0.join(format!("{cn}.key")),
        );
        fs::write(&crt, id.cert_pem()).unwrap();
        fs::write(&key, id.clave_pem().as_bytes()).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();

        let salida = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "papel_agente_desviado",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("AEGIS_CAOS_PAPEL", "agente")
            .env("LD_PRELOAD", &lib)
            .env("FAKETIME", format!("{desvio:+}"))
            .env("FAKETIME_DONT_FAKE_MONOTONIC", "1")
            .env("AEGIS_CAOS_FLOTA", srv.flota.to_string())
            .env("AEGIS_CAOS_CA", &ca_crt)
            .env("AEGIS_CAOS_CRT", &crt)
            .env("AEGIS_CAOS_KEY", &key)
            .env("AEGIS_CAOS_N", "5")
            .output()
            .expect("agente desviado");
        let texto = String::from_utf8_lossy(&salida.stdout);
        // Con --nocapture el arnes escribe «test papel_agente_desviado ... » en
        // la MISMA linea, delante de lo que imprime el hijo: la marca se busca
        // dentro de la linea, no al principio.
        let linea = texto
            .lines()
            .find_map(|l| l.split_once("AEGIS-CAOS-AGENTE ").map(|(_, resto)| resto))
            .unwrap_or_else(|| {
                panic!(
                    "el agente desviado ({desvio:+} s) no informo:\n{texto}\n{}",
                    String::from_utf8_lossy(&salida.stderr)
                )
            });
        let v: serde_json::Value = serde_json::from_str(linea).unwrap();
        let ahora = ahora_unix() as i64;
        let su_ahora = v["ahora_unix"].as_i64().unwrap();
        assert!(
            ((su_ahora - ahora) - desvio).abs() < 60,
            "libfaketime no surtio efecto: el agente cree que son las {su_ahora} y son las {ahora}"
        );
        assert_eq!(
            v["enlace"]["enviados"], 5,
            "con el reloj a {desvio:+} s el agente no pudo entregar: {linea}"
        );
        assert_eq!(v["enlace"]["cuadra"], true);

        // Las marcas: `recibido_en` es la hora del SERVIDOR (la que decide la
        // particion), `ocurrido_en` la del agente, desviada.
        let (n, desvio_medio, recibido_desfase): (i64, f64, f64) = rt.block_on(async {
            let pool = sqlx::PgPool::connect(&pg.url()).await.unwrap();
            let f = sqlx::query_as(
                "SELECT count(*),
                        COALESCE(avg(extract(epoch FROM ocurrido_en - recibido_en)), 0)::float8,
                        COALESCE(max(abs(extract(epoch FROM recibido_en - now()))), 0)::float8
                   FROM alertas WHERE cn_agente = $1",
            )
            .bind(&cn)
            .fetch_one(&pool)
            .await
            .unwrap();
            pool.close().await;
            f
        });
        assert_eq!(n, 5, "{cn}: llegaron {n} de 5");
        assert!(
            recibido_desfase < 300.0,
            "recibido_en no es la hora del servidor"
        );
        println!(
            "AEGIS-MEDIDA caos escenario=reloj desvio_seg={desvio} ocurrido_menos_recibido_seg={desvio_medio:.0}"
        );
    }
}

/// Papel de AGENTE con el reloj desviado: lo lanza el escenario 5 como otro
/// proceso. Sin `AEGIS_CAOS_PAPEL=agente` no hace nada.
#[test]
#[ignore = "papel de proceso hijo del caos"]
fn papel_agente_desviado() {
    if std::env::var("AEGIS_CAOS_PAPEL").as_deref() != Ok("agente") {
        return;
    }
    let var = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("falta {k}"));
    let ca_pem = fs::read_to_string(var("AEGIS_CAOS_CA")).unwrap();
    let ca_der = aegis_fleet::pki::certificado_desde_pem(&ca_pem).expect("CA");
    let emisor = EmisorFijo {
        cert: fs::read_to_string(var("AEGIS_CAOS_CRT")).unwrap(),
        clave: fs::read_to_string(var("AEGIS_CAOS_KEY")).unwrap(),
    };
    let cn = Identidad::desde_pem(&emisor.cert, &emisor.clave)
        .unwrap()
        .cn;
    let puerto: u16 = var("AEGIS_CAOS_FLOTA").parse().unwrap();
    let n: u64 = var("AEGIS_CAOS_N").parse().unwrap();
    let (enlace, _) = agente(Arc::new(emisor), ca_der, &cn, puerto);
    for k in 0..n {
        enlace.ofrecer(Veredicto {
            id: format!("{cn}#{k}"),
        });
    }
    let limite = Instant::now() + Duration::from_secs(45);
    while enlace.instantanea().enviados < n && Instant::now() < limite {
        std::thread::sleep(Duration::from_millis(200));
    }
    let i = enlace.parar();
    println!(
        "AEGIS-CAOS-AGENTE {{\"ahora_unix\":{},\"enlace\":{}}}",
        ahora_unix(),
        i.json()
    );
}

// ---------------------------------------------------------------------------
// 6. El SIEM muere y se ahoga
// ---------------------------------------------------------------------------

/// El colector como proceso aparte.
struct Sumidero {
    hijo: Child,
}

impl Sumidero {
    fn lanzar(dir: &Path, puerto: u16) -> Sumidero {
        let mut hijo = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "papel_sumidero_siem",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("AEGIS_CAOS_PAPEL", "sumidero")
            .env("AEGIS_CAOS_SIEM_PUERTO", puerto.to_string())
            .env("AEGIS_CAOS_SIEM_CRT", dir.join("siem.crt"))
            .env("AEGIS_CAOS_SIEM_KEY", dir.join("siem.key"))
            .env("AEGIS_CAOS_SIEM_SALIDA", dir.join("siem.recibidos"))
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("sumidero");
        let salida = hijo.stdout.take().unwrap();
        let mut lineas = BufReader::new(salida).lines();
        let limite = Instant::now() + Duration::from_secs(60);
        loop {
            match lineas.next() {
                Some(Ok(l)) if l.contains("SUMIDERO-LISTO") => break,
                Some(_) => {}
                None => panic!("el sumidero termino sin escuchar"),
            }
            assert!(Instant::now() < limite, "el sumidero no escucha");
        }
        Sumidero { hijo }
    }

    fn matar(mut self) {
        let _ = self.hijo.kill();
        let _ = self.hijo.wait();
    }
}

impl Drop for Sumidero {
    fn drop(&mut self) {
        let _ = self.hijo.kill();
        let _ = self.hijo.wait();
    }
}

/// Lo que recibio el colector: identificador -> veces.
fn recibidos(dir: &Path) -> BTreeMap<String, u64> {
    let mut m = BTreeMap::new();
    for l in fs::read_to_string(dir.join("siem.recibidos"))
        .unwrap_or_default()
        .lines()
    {
        // El MSGID lleva el UUID en forma compacta (32 hexadecimales, el tope
        // de RFC 5424); se compara como UUID con los de la base de datos.
        let id = uuid::Uuid::parse_str(l).map_or_else(|_| l.to_string(), |u| u.to_string());
        *m.entry(id).or_insert(0) += 1;
    }
    m
}

#[test]
#[ignore = "caos con procesos reales: tools/verificar-caos.sh (make ci SOLO=caos-plano)"]
fn caos_siem_muere_y_se_ahoga_y_la_salida_se_reconcilia_sin_perdida() {
    let Some((tmp, pg, mut redis)) = montar("siem") else {
        return;
    };
    redis.arrancar();

    // El colector: su propia CA y su certificado para «siem.local».
    let ca_clave = rcgen::KeyPair::generate().unwrap();
    let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_siem = p.self_signed(&ca_clave).unwrap();
    let hoja_clave = rcgen::KeyPair::generate().unwrap();
    let hoja = rcgen::CertificateParams::new(vec!["siem.local".to_string()])
        .unwrap()
        .signed_by(&hoja_clave, &ca_siem, &ca_clave)
        .unwrap();
    fs::write(tmp.0.join("siem-ca.crt"), ca_siem.pem()).unwrap();
    fs::write(tmp.0.join("siem.crt"), hoja.pem()).unwrap();
    fs::write(tmp.0.join("siem.key"), hoja_clave.serialize_pem()).unwrap();

    let puerto_siem = puerto_libre();
    let mut sumidero = Some(Sumidero::lanzar(&tmp.0, puerto_siem));
    let srv = Servidor::lanzar(
        &tmp.0,
        &pg.url(),
        &redis.url(),
        &[
            (
                "AEGIS_FIREHOSE_DIR",
                tmp.0.join("diario").display().to_string(),
            ),
            ("AEGIS_SYSLOG_SERVIDOR", format!("127.0.0.1:{puerto_siem}")),
            ("AEGIS_SYSLOG_NOMBRE", "siem.local".to_string()),
            (
                "AEGIS_SYSLOG_CA",
                tmp.0.join("siem-ca.crt").display().to_string(),
            ),
            ("AEGIS_FIREHOSE_RETENCION_MS", "2000".to_string()),
        ],
    );
    let ca = Arc::new(srv.ca(&tmp.0));
    let mut flota = Flota::arrancar(
        &ca,
        &format!("siem{}", unico()),
        4,
        srv.flota,
        Duration::from_millis(40),
    );
    std::thread::sleep(Duration::from_secs(8));

    // kill -9 al colector con el trafico en marcha.
    sumidero.take().unwrap().matar();
    std::thread::sleep(Duration::from_secs(siem_seg()));
    let estado = srv.salud().map(|r| r.1).unwrap_or_default();
    assert!(
        estado["firehose"]["pendientes"].as_u64().unwrap_or(0)
            + estado["firehose"]["retenidos"].as_u64().unwrap_or(0)
            > 0,
        "con el SIEM muerto la auditoria tiene que esperar en el diario: {estado}"
    );
    let vivo = Sumidero::lanzar(&tmp.0, puerto_siem);

    // Ahogado: acepta y no lee.
    std::thread::sleep(Duration::from_secs(5));
    senal(vivo.hijo.id(), "-STOP");
    std::thread::sleep(Duration::from_secs(15));
    senal(vivo.hijo.id(), "-CONT");

    flota.dejar_de_producir();
    esperar(
        "las colas de los agentes se vacian",
        Duration::from_secs(120),
        || flota.vaciada(),
    );

    // Reconciliacion: todo lo persistido llega al SIEM o queda contado.
    let rt = tokio::runtime::Runtime::new().unwrap();
    let ids: BTreeSet<String> = rt.block_on(async {
        let pool = sqlx::PgPool::connect(&pg.url()).await.unwrap();
        let v: Vec<(uuid::Uuid,)> =
            sqlx::query_as("SELECT id FROM alertas WHERE cn_agente = ANY($1)")
                .bind(&flota.cns)
                .fetch_all(&pool)
                .await
                .unwrap();
        pool.close().await;
        v.into_iter().map(|(i,)| i.to_string()).collect()
    });
    assert!(!ids.is_empty());
    let limite = Instant::now() + Duration::from_secs(240);
    let ultimo = loop {
        let estado = srv.salud().map(|r| r.1).unwrap_or_default();
        let f = &estado["firehose"];
        let llegados = recibidos(&tmp.0);
        let faltan = ids.iter().filter(|i| !llegados.contains_key(*i)).count();
        if f["pendientes"] == 0 && f["retenidos"] == 0 && faltan == 0 {
            break estado;
        }
        // Si no se reconcilia, el fallo tiene que decir en que estado quedo:
        // pendientes en el diario, retenidos sin confirmar o huecos en el SIEM.
        assert!(
            Instant::now() < limite,
            "la salida al SIEM no se reconcilio en 240 s: faltan {faltan} de {} en el \
             colector; firehose = {}",
            ids.len(),
            f
        );
        std::thread::sleep(Duration::from_millis(500));
    };
    let f = &ultimo["firehose"];
    let llegados = recibidos(&tmp.0);
    let recibidos_distintos = ids.iter().filter(|i| llegados.contains_key(*i)).count() as u64;
    let perdidos =
        f["no_exportados"].as_u64().unwrap_or(0) + f["descartados"].as_u64().unwrap_or(0);
    let pendientes = f["pendientes"].as_u64().unwrap_or(0) + f["retenidos"].as_u64().unwrap_or(0);
    let duplicados: u64 = llegados.values().map(|n| n - 1).sum();
    println!(
        "AEGIS-MEDIDA caos escenario=siem persistidos={} recibidos={recibidos_distintos} \
         pendientes={pendientes} perdidos={perdidos} duplicados={duplicados} reentregados={}",
        ids.len(),
        f["reentregados"]
    );
    assert_eq!(
        ids.len() as u64,
        recibidos_distintos + pendientes + perdidos,
        "persistidos != recibidos + pendientes + perdidos declarados"
    );
    assert_eq!(perdidos, 0, "el SIEM perdio auditoria");
    let ajenos: Vec<_> = llegados
        .keys()
        .filter(|k| uuid::Uuid::parse_str(k).is_ok() && !ids.contains(*k))
        .collect();
    assert!(
        ajenos.is_empty(),
        "el SIEM recibio identificadores que no existen: {ajenos:?}"
    );
    let (distintos, filas) = persistidos(&pg.url(), &flota.cns);
    cuadrar(
        "siem-ingesta",
        &flota.instantaneas(),
        distintos,
        filas,
        true,
    );
    drop(vivo);
}

/// Papel de COLECTOR syslog-TLS: lo lanza el escenario 6 como otro proceso.
/// Anota el MSGID (el identificador de la alerta) de cada mensaje, uno por
/// linea, en cuanto lo lee: lo escrito sobrevive a su `kill -9`.
#[test]
#[ignore = "papel de proceso hijo del caos"]
fn papel_sumidero_siem() {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    if std::env::var("AEGIS_CAOS_PAPEL").as_deref() != Ok("sumidero") {
        return;
    }
    let var = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("falta {k}"));
    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_file_iter(var("AEGIS_CAOS_SIEM_CRT"))
            .unwrap()
            .map(|c| c.unwrap())
            .collect();
    let clave = PrivateKeyDer::from_pem_file(var("AEGIS_CAOS_SIEM_KEY")).unwrap();
    let cfg = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, clave)
        .unwrap(),
    );
    let salida = Arc::new(std::sync::Mutex::new(
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(var("AEGIS_CAOS_SIEM_SALIDA"))
            .unwrap(),
    ));
    let escucha = TcpListener::bind((
        "127.0.0.1",
        var("AEGIS_CAOS_SIEM_PUERTO").parse::<u16>().unwrap(),
    ))
    .unwrap();
    println!("SUMIDERO-LISTO");
    let _ = std::io::stdout().flush();
    for flujo in escucha.incoming() {
        let Ok(sock) = flujo else { continue };
        let (cfg, salida) = (cfg.clone(), salida.clone());
        std::thread::spawn(move || {
            let Ok(conn) = rustls::ServerConnection::new(cfg) else {
                return;
            };
            let mut tls = rustls::StreamOwned::new(conn, sock);
            let mut pendiente: Vec<u8> = Vec::new();
            let mut buf = [0u8; 16 * 1024];
            loop {
                match tls.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => pendiente.extend_from_slice(&buf[..n]),
                }
                // RFC 6587: «LONGITUD MENSAJE».
                while let Some(esp) = pendiente.iter().position(|b| *b == b' ') {
                    let Some(largo) = std::str::from_utf8(&pendiente[..esp])
                        .ok()
                        .and_then(|s| s.parse::<usize>().ok())
                    else {
                        return;
                    };
                    if pendiente.len() < esp + 1 + largo {
                        break;
                    }
                    let msg =
                        String::from_utf8_lossy(&pendiente[esp + 1..esp + 1 + largo]).into_owned();
                    pendiente.drain(..esp + 1 + largo);
                    // <PRI>1 MOMENTO HOST APP PROCID MSGID ...
                    if let Some(msgid) = msg.split_whitespace().nth(5) {
                        let mut f = salida.lock().unwrap();
                        let _ = f.write_all(format!("{msgid}\n").as_bytes());
                    }
                }
            }
        });
    }
}
