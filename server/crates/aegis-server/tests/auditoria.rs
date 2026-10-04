//! El camino completo de la auditoria: del agente al SIEM del cliente.
//!
//! Es la prueba que une las dos mitades de la FASE 46. Las del crate
//! `aegis-firehose` comprueban el diario y el transporte por separado; esta
//! comprueba lo que el cliente compra: **que una alerta reportada por un
//! endpoint acaba en su SIEM, y que sigue ahi aunque el SIEM estuviera caido
//! cuando ocurrio**.

use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use aegis_firehose::diario::Config as ConfigDiario;
use aegis_firehose::reintento::Politica;
use aegis_firehose::syslog_tls::{ConfigSyslog, DestinoSyslog};
mod comun;
use aegis_server::dominio::ServicioFlota;
use aegis_server::firehose::Firehose;
use comun::almacen_real;

struct Temporal(std::path::PathBuf);

impl Drop for Temporal {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn temporal(etiqueta: &str) -> Temporal {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let d = std::env::temp_dir().join(format!("aegis-audit-{etiqueta}-{n}"));
    std::fs::create_dir_all(&d).unwrap();
    Temporal(d)
}

/// Colector syslog TLS real, con interruptor de caida.
struct Colector {
    recibidos: Mutex<Vec<String>>,
    caido: AtomicBool,
}

fn levantar_colector() -> (String, Vec<u8>, Arc<Colector>) {
    let cert = rcgen::generate_simple_self_signed(vec!["siem.local".to_string()]).unwrap();
    let pem_cert = cert.cert.pem();
    let pem_clave = cert.key_pair.serialize_pem();
    let certs: Vec<_> = CertificateDer::pem_slice_iter(pem_cert.as_bytes())
        .map(|c| c.unwrap())
        .collect();
    let clave = PrivateKeyDer::from_pem_slice(pem_clave.as_bytes()).unwrap();
    let cfg = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, clave)
            .unwrap(),
    );

    let escucha = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let direccion = escucha.local_addr().unwrap().to_string();
    let estado = Arc::new(Colector {
        recibidos: Mutex::new(Vec::new()),
        caido: AtomicBool::new(false),
    });
    let hilo = estado.clone();
    std::thread::spawn(move || {
        for flujo in escucha.incoming() {
            let Ok(sock) = flujo else { break };
            if hilo.caido.load(Ordering::SeqCst) {
                drop(sock);
                continue;
            }
            let cfg = cfg.clone();
            let estado = hilo.clone();
            std::thread::spawn(move || {
                let Ok(conn) = rustls::ServerConnection::new(cfg) else {
                    return;
                };
                let mut tls = rustls::StreamOwned::new(conn, sock);
                let mut pendiente: Vec<u8> = Vec::new();
                let mut buf = [0u8; 8192];
                loop {
                    if estado.caido.load(Ordering::SeqCst) {
                        return;
                    }
                    match tls.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => pendiente.extend_from_slice(&buf[..n]),
                    }
                    // Conteo de octetos (RFC 6587), igual que un SIEM.
                    while let Some(esp) = pendiente.iter().position(|b| *b == b' ') {
                        let Ok(cab) = std::str::from_utf8(&pendiente[..esp]) else {
                            return;
                        };
                        let Ok(largo) = cab.parse::<usize>() else {
                            return;
                        };
                        if pendiente.len() < esp + 1 + largo {
                            break;
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

fn esperar(cuantos: usize, c: &Colector) -> usize {
    let limite = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while std::time::Instant::now() < limite {
        let n = c.recibidos.lock().unwrap().len();
        if n >= cuantos {
            return n;
        }
        std::thread::sleep(std::time::Duration::from_millis(30));
    }
    c.recibidos.lock().unwrap().len()
}

fn arrancar_firehose(dir: &std::path::Path, direccion: &str, ca: &[u8]) -> Arc<Firehose> {
    let f =
        Arc::new(Firehose::abrir(ConfigDiario::nueva(dir), "control-plane-de-pruebas").unwrap());
    let destino = DestinoSyslog::nuevo(ConfigSyslog {
        servidor: direccion.to_string(),
        nombre_esperado: "siem.local".to_string(),
        ca_pem: ca.to_vec(),
        plazo: std::time::Duration::from_secs(5),
    })
    .unwrap();
    let exportador = f.clone();
    std::thread::spawn(move || {
        exportador.exportar(
            destino,
            Politica {
                base: std::time::Duration::from_millis(50),
                techo: std::time::Duration::from_millis(500),
                factor: 2,
            },
        )
    });
    f
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn una_alerta_de_un_endpoint_acaba_en_el_siem_del_cliente() {
    let Some(almacen) = almacen_real(4).await else {
        return;
    };
    let t = temporal("feliz");
    let (direccion, ca, colector) = levantar_colector();
    let firehose = arrancar_firehose(&t.0, &direccion, &ca);

    let servicio = ServicioFlota::nuevo(almacen.clone(), 30).con_firehose(firehose);
    let cn = format!("audit-{}", uuid::Uuid::new_v4().simple());
    almacen
        .enrolar(&cn, &cn, "host", "1.0", &[], "")
        .await
        .unwrap();

    let id = servicio
        .evento(&cn, 4, "ransomware", "cifrado masivo detectado", 0, "")
        .await
        .unwrap();

    assert_eq!(
        esperar(1, &colector),
        1,
        "la alerta tiene que llegar al SIEM"
    );
    let recibidos = colector.recibidos.lock().unwrap();
    assert!(
        recibidos[0].contains(&id.to_string()),
        "con su identificador"
    );
    assert!(recibidos[0].contains("cifrado masivo detectado"));
    // La severidad 4 tiene que viajar como alerta de syslog (local0.alert = 129)
    // y no como informativa: de eso dependen las reglas de enrutado del cliente.
    assert!(
        recibidos[0].starts_with("<129>1 "),
        "la severidad no puede degradarse: {}",
        &recibidos[0][..recibidos[0].len().min(40)]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lo_ocurrido_con_el_siem_caido_llega_cuando_el_siem_vuelve() {
    // El caso que justifica la fase entera: el SIEM se reinicia por
    // mantenimiento y el atacante actua en ese rato. Sin diario, esa evidencia
    // no existiria en la plataforma del cliente.
    let Some(almacen) = almacen_real(4).await else {
        return;
    };
    let t = temporal("caida");
    let (direccion, ca, colector) = levantar_colector();
    colector.caido.store(true, Ordering::SeqCst);
    let firehose = arrancar_firehose(&t.0, &direccion, &ca);

    let servicio = ServicioFlota::nuevo(almacen.clone(), 30).con_firehose(firehose.clone());
    let cn = format!("audit-{}", uuid::Uuid::new_v4().simple());
    almacen
        .enrolar(&cn, &cn, "host", "1.0", &[], "")
        .await
        .unwrap();

    for i in 0..12 {
        servicio
            .evento(&cn, 3, "inyeccion", &format!("inyeccion {i}"), 0, "")
            .await
            .unwrap();
    }
    // Se deja reintentar contra el SIEM caido.
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    assert!(
        colector.recibidos.lock().unwrap().is_empty(),
        "con el SIEM caido no puede haber llegado nada"
    );
    assert_eq!(
        firehose.no_exportados(),
        0,
        "lo que no se pudo enviar SI se pudo escribir en el diario"
    );

    // El SIEM vuelve.
    colector.caido.store(false, Ordering::SeqCst);
    assert_eq!(
        esperar(12, &colector),
        12,
        "las doce alertas del apagon tienen que llegar cuando el SIEM vuelve"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sin_firehose_configurado_el_producto_sigue_funcionando() {
    // Un despliegue sin SIEM tiene que detectar igual. El producto no puede
    // dejar de funcionar porque el cliente aun no haya integrado su plataforma.
    let Some(almacen) = almacen_real(4).await else {
        return;
    };
    let servicio = ServicioFlota::nuevo(almacen.clone(), 30);
    assert!(servicio.firehose().is_none());
    let cn = format!("audit-{}", uuid::Uuid::new_v4().simple());
    almacen
        .enrolar(&cn, &cn, "host", "1.0", &[], "")
        .await
        .unwrap();
    assert!(servicio
        .evento(&cn, 2, "rootkit", "sin siem", 0, "")
        .await
        .is_ok());
}
