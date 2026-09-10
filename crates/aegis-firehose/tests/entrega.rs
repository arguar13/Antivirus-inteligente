//! Entrega de extremo a extremo contra un colector Syslog TLS REAL.
//!
//! El colector de estas pruebas es un servidor TLS de verdad —con su
//! certificado, su handshake y su socket— que interpreta el marcado por conteo
//! de octetos de la RFC 6587 exactamente como lo haria un SIEM. No imita el
//! protocolo: lo habla. Lo unico que tiene de prueba es que se le puede ordenar
//! caerse en un momento concreto, que es justo el escenario que hay que
//! demostrar.

use std::io::Read;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use aegis_firehose::bomba::Bomba;
use aegis_firehose::diario::{Config, Diario, MAX_REGISTRO};
use aegis_firehose::reintento::Politica;
use aegis_firehose::syslog::{enmarcar, mensaje, Cabecera, Severidad};
use aegis_firehose::syslog_tls::{ConfigSyslog, DestinoSyslog};

// ---------------------------------------------------------------------------
// Utilidades
// ---------------------------------------------------------------------------

struct Temporal(std::path::PathBuf);

impl Temporal {
    fn nuevo(etiqueta: &str) -> Temporal {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let d = std::env::temp_dir().join(format!("aegis-entrega-{etiqueta}-{n}"));
        std::fs::create_dir_all(&d).unwrap();
        Temporal(d)
    }
}

impl Drop for Temporal {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn config_diario(dir: &std::path::Path) -> Config {
    Config {
        bytes_por_segmento: (MAX_REGISTRO + 64) as u64,
        presupuesto_bytes: (MAX_REGISTRO + 64) as u64 * 16,
        registros_por_sincronizacion: 1,
        ..Config::nueva(dir)
    }
}

fn cabecera() -> Cabecera {
    Cabecera {
        severidad: Severidad::Alerta,
        momento: "2026-09-10T09:00:00Z".to_string(),
        hostname: "control-plane".to_string(),
        app: "aegiscore".to_string(),
        procid: "firehose".to_string(),
        msgid: "AUDIT".to_string(),
    }
}

/// Traduce un registro del diario a un marco syslog listo para el cable.
fn marcar(carga: &[u8]) -> Vec<u8> {
    enmarcar(&mensaje(&cabecera(), None, &String::from_utf8_lossy(carga)))
}

// ---------------------------------------------------------------------------
// Un colector syslog de verdad
// ---------------------------------------------------------------------------

/// Lo que el colector ha recibido y como se comporta.
struct Colector {
    /// Mensajes ya desenmarcados.
    recibidos: Mutex<Vec<String>>,
    /// Conexiones aceptadas: delata las reconexiones.
    conexiones: AtomicUsize,
    /// Si esta puesto, el colector corta la conexion nada mas aceptarla.
    caido: AtomicBool,
}

/// Levanta un colector Syslog TLS real y devuelve `(direccion, ca_pem, estado)`.
fn levantar_colector() -> (String, Vec<u8>, Arc<Colector>) {
    // Certificado autofirmado de verdad: el cliente lo verifica de verdad.
    let cert = rcgen::generate_simple_self_signed(vec!["colector.local".to_string()]).unwrap();
    let pem_cert = cert.cert.pem();
    let pem_clave = cert.key_pair.serialize_pem();

    let certs: Vec<_> = rustls_pemfile::certs(&mut pem_cert.as_bytes())
        .map(|c| c.unwrap())
        .collect();
    let clave = rustls_pemfile::private_key(&mut pem_clave.as_bytes())
        .unwrap()
        .unwrap();
    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, clave)
        .unwrap();
    let cfg = Arc::new(cfg);

    let escucha = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let direccion = escucha.local_addr().unwrap().to_string();
    let estado = Arc::new(Colector {
        recibidos: Mutex::new(Vec::new()),
        conexiones: AtomicUsize::new(0),
        caido: AtomicBool::new(false),
    });

    let hilo_estado = estado.clone();
    std::thread::spawn(move || {
        for flujo in escucha.incoming() {
            let Ok(sock) = flujo else { break };
            hilo_estado.conexiones.fetch_add(1, Ordering::SeqCst);
            if hilo_estado.caido.load(Ordering::SeqCst) {
                // El SIEM esta caido: acepta y cuelga. Es el comportamiento
                // real de un balanceador delante de un servicio muerto, y el
                // mas dificil de manejar, porque el TCP parece sano.
                drop(sock);
                continue;
            }
            let cfg = cfg.clone();
            let estado = hilo_estado.clone();
            std::thread::spawn(move || {
                let Ok(conn) = rustls::ServerConnection::new(cfg) else {
                    return;
                };
                let mut tls = rustls::StreamOwned::new(conn, sock);
                let mut pendiente: Vec<u8> = Vec::new();
                let mut buf = [0u8; 8192];
                loop {
                    if estado.caido.load(Ordering::SeqCst) {
                        return; // corta a mitad de sesion
                    }
                    match tls.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => pendiente.extend_from_slice(&buf[..n]),
                    }
                    // Desenmarcado por conteo de octetos (RFC 6587), igual que
                    // un SIEM: LONGITUD ESPACIO MENSAJE.
                    loop {
                        let Some(esp) = pendiente.iter().position(|b| *b == b' ') else {
                            break;
                        };
                        let Ok(cabecera) = std::str::from_utf8(&pendiente[..esp]) else {
                            return;
                        };
                        let Ok(largo) = cabecera.parse::<usize>() else {
                            return;
                        };
                        if pendiente.len() < esp + 1 + largo {
                            break; // aun no esta entero
                        }
                        let cuerpo = pendiente[esp + 1..esp + 1 + largo].to_vec();
                        pendiente.drain(..esp + 1 + largo);
                        estado
                            .recibidos
                            .lock()
                            .unwrap()
                            .push(String::from_utf8_lossy(&cuerpo).into_owned());
                    }
                }
            });
        }
    });

    (direccion, pem_cert.into_bytes(), estado)
}

fn destino(direccion: &str, ca: &[u8]) -> DestinoSyslog {
    DestinoSyslog::nuevo(ConfigSyslog {
        servidor: direccion.to_string(),
        nombre_esperado: "colector.local".to_string(),
        ca_pem: ca.to_vec(),
        plazo: std::time::Duration::from_secs(5),
    })
    .unwrap()
}

fn esperar_hasta(cuantos: usize, colector: &Colector) -> usize {
    let limite = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < limite {
        let n = colector.recibidos.lock().unwrap().len();
        if n >= cuantos {
            return n;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    colector.recibidos.lock().unwrap().len()
}

// ---------------------------------------------------------------------------
// Pruebas
// ---------------------------------------------------------------------------

#[test]
fn la_auditoria_llega_al_colector_por_tls_y_se_desenmarca_entera() {
    let t = Temporal::nuevo("feliz");
    let (direccion, ca, colector) = levantar_colector();
    let mut diario = Diario::abrir(config_diario(&t.0)).unwrap();
    for i in 0..40u32 {
        diario
            .admitir(format!("evento numero {i}").as_bytes())
            .unwrap();
    }

    let mut bomba = Bomba::nueva(destino(&direccion, &ca), Politica::default()).con_lote(16);
    for _ in 0..5 {
        bomba.vuelta(&mut diario, &marcar).unwrap();
    }

    assert_eq!(esperar_hasta(40, &colector), 40);
    let recibidos = colector.recibidos.lock().unwrap();
    assert!(recibidos[0].contains("evento numero 0"));
    assert!(recibidos[39].contains("evento numero 39"));
    assert_eq!(bomba.entregados(), 40);
}

#[test]
fn un_salto_de_linea_en_la_evidencia_no_se_convierte_en_un_evento_falso() {
    // La prueba del ataque real, ahora de extremo a extremo: la linea de
    // comandos la escribe el atacante. Con delimitacion por salto de linea, el
    // colector veria DOS eventos y el segundo lo habria escrito el. Con conteo
    // de octetos ve UNO, con el salto dentro.
    let t = Temporal::nuevo("inyeccion");
    let (direccion, ca, colector) = levantar_colector();
    let mut diario = Diario::abrir(config_diario(&t.0)).unwrap();
    diario
        .admitir(
            b"cmd.exe /c whoami\n<134>1 2026-01-01T00:00:00Z x - - - evento fabricado por el atacante",
        )
        .unwrap();

    let mut bomba = Bomba::nueva(destino(&direccion, &ca), Politica::default());
    bomba.vuelta(&mut diario, &marcar).unwrap();

    assert_eq!(esperar_hasta(1, &colector), 1);
    let recibidos = colector.recibidos.lock().unwrap();
    assert_eq!(
        recibidos.len(),
        1,
        "el colector tiene que ver UN evento, no dos"
    );
    assert!(
        recibidos[0].contains("evento fabricado por el atacante"),
        "y el texto inyectado tiene que quedar DENTRO de ese evento"
    );
}

#[test]
fn si_el_colector_se_cae_no_se_pierde_nada_y_se_entrega_al_volver() {
    // El caso que justifica el diario entero. El SIEM se reinicia por
    // mantenimiento un martes por la noche; el EDR no puede perder lo de ese
    // rato, que es con demasiada frecuencia el rato que importa.
    let t = Temporal::nuevo("caida");
    let (direccion, ca, colector) = levantar_colector();
    colector.caido.store(true, Ordering::SeqCst);

    let mut diario = Diario::abrir(config_diario(&t.0)).unwrap();
    for i in 0..30u32 {
        diario.admitir(format!("critico-{i}").as_bytes()).unwrap();
    }

    // Con el colector caido, la bomba falla y NO confirma nada.
    let mut bomba = Bomba::nueva(destino(&direccion, &ca), Politica::default()).con_lote(10);
    let mut fallos = 0;
    for _ in 0..3 {
        let v = bomba.vuelta(&mut diario, &marcar).unwrap();
        if v.fallo {
            fallos += 1;
        }
        assert_eq!(v.entregados, 0, "no se puede confirmar lo que no llego");
    }
    assert!(fallos > 0, "la caida tiene que notarse");
    assert!(
        colector.recibidos.lock().unwrap().is_empty(),
        "el colector caido no recibio nada"
    );

    // El SIEM vuelve.
    colector.caido.store(false, Ordering::SeqCst);
    for _ in 0..6 {
        bomba.vuelta(&mut diario, &marcar).unwrap();
    }

    assert_eq!(
        esperar_hasta(30, &colector),
        30,
        "al volver el SIEM tienen que llegar los TREINTA registros del apagon"
    );
    assert!(
        colector.conexiones.load(Ordering::SeqCst) > 1,
        "tras un fallo hay que reconectar, no reutilizar el socket roto"
    );
}

#[test]
fn lo_entregado_pero_sin_confirmar_se_reenvia_en_vez_de_perderse() {
    // El proceso muere entre entregar y confirmar. Se elige DUPLICAR antes que
    // perder: un duplicado el SIEM lo desduplica por el identificador del
    // evento; un registro perdido no lo recupera nadie.
    let t = Temporal::nuevo("sinconfirmar");
    let (direccion, ca, colector) = levantar_colector();

    {
        let mut diario = Diario::abrir(config_diario(&t.0)).unwrap();
        for i in 0..5u32 {
            diario.admitir(format!("reg-{i}").as_bytes()).unwrap();
        }
        // Se entrega pero la bomba se destruye sin llegar a persistir nada:
        // equivale a morir despues de escribir en el socket. El diario NO se
        // toco, porque confirmar es lo ultimo.
        let mut bomba = Bomba::nueva(destino(&direccion, &ca), Politica::default());
        bomba.vuelta(&mut diario, &marcar).unwrap();
        assert_eq!(esperar_hasta(5, &colector), 5);
    }

    // Arranca de nuevo: el diario sigue teniendo los registros.
    let mut diario = Diario::abrir(config_diario(&t.0)).unwrap();
    let mut bomba = Bomba::nueva(destino(&direccion, &ca), Politica::default());
    bomba.vuelta(&mut diario, &marcar).unwrap();

    assert_eq!(
        esperar_hasta(10, &colector),
        10,
        "al reiniciar hay que REENVIAR lo no confirmado, aunque duplique"
    );
}

#[test]
fn un_colector_con_otra_ca_no_recibe_la_telemetria() {
    // Sin verificar el servidor, cualquiera que pueda responder en ese puerto
    // recibe la telemetria de seguridad completa del cliente —un mapa de su
    // infraestructura— y puede ademas dejar de reenviarla, que es una forma
    // silenciosa de cegar el SOC.
    let t = Temporal::nuevo("impostor");
    let (direccion, _ca_buena, colector) = levantar_colector();
    let otra = rcgen::generate_simple_self_signed(vec!["colector.local".to_string()]).unwrap();

    let mut diario = Diario::abrir(config_diario(&t.0)).unwrap();
    diario.admitir(b"secreto").unwrap();

    let mut bomba = Bomba::nueva(
        destino(&direccion, otra.cert.pem().as_bytes()),
        Politica::default(),
    );
    let v = bomba.vuelta(&mut diario, &marcar).unwrap();
    assert!(v.fallo, "un certificado de otra CA no puede aceptarse");
    assert!(
        colector.recibidos.lock().unwrap().is_empty(),
        "no puede haber salido ni un byte de auditoria"
    );

    // Y lo importante: lo que no se entrego SIGUE en el diario.
    assert_eq!(diario.leer_desde(None, 10).unwrap().len(), 1);
}

#[test]
fn sin_ancla_de_confianza_el_destino_no_llega_a_construirse() {
    // Fallar al configurar es lo correcto: la alternativa es conectar sin
    // verificar, y eso no puede ser un valor por defecto en un producto de
    // seguridad.
    assert!(DestinoSyslog::nuevo(ConfigSyslog {
        servidor: "127.0.0.1:1".to_string(),
        nombre_esperado: "colector.local".to_string(),
        ca_pem: Vec::new(),
        plazo: std::time::Duration::from_secs(1),
    })
    .is_err());
}

#[test]
fn la_espera_del_reintento_crece_mientras_el_colector_siga_caido() {
    // Sin crecimiento, diez mil productores martillearian un SIEM que intenta
    // levantarse y lo tumbarian otra vez.
    let t = Temporal::nuevo("espera");
    let (direccion, ca, colector) = levantar_colector();
    colector.caido.store(true, Ordering::SeqCst);

    let mut diario = Diario::abrir(config_diario(&t.0)).unwrap();
    diario.admitir(b"x").unwrap();

    let mut bomba = Bomba::nueva(
        destino(&direccion, &ca),
        Politica {
            base: std::time::Duration::from_millis(50),
            techo: std::time::Duration::from_secs(30),
            factor: 2,
        },
    );
    // La espera devuelta esta dispersada, asi que se compara el TECHO de la
    // ventana: las primeras esperas no pueden superar lo que la ventana
    // permitia entonces, y las ultimas si pueden llegar mas alto.
    let mut esperas = Vec::new();
    for _ in 0..8 {
        let v = bomba.vuelta(&mut diario, &marcar).unwrap();
        assert!(v.fallo);
        esperas.push(v.espera);
    }
    assert!(
        esperas[..3]
            .iter()
            .all(|e| *e <= std::time::Duration::from_millis(200)),
        "los primeros reintentos tienen que ser rapidos: {esperas:?}"
    );
    assert!(
        esperas
            .iter()
            .any(|e| *e > std::time::Duration::from_millis(200)),
        "y la espera tiene que crecer si el destino no vuelve: {esperas:?}"
    );
    assert_eq!(bomba.fallos(), 8);
}
