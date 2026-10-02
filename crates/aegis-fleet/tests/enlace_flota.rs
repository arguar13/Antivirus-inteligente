//! El enlace del agente sobre el mTLS REAL de la flota, y la identidad leida de
//! ficheros (H-23, E6.5 del MP-16).
//!
//! No necesita base de datos: el plano de control es un [`ManejadorFlota`] que
//! apunta lo que recibe y con que CN autenticado. Corre en cada `make ci`
//! (grupo `rust`), asi que el camino de produccion del enlace —`ConectorFlota`,
//! `ClienteFlota` con plazo, `EmisorFichero`, el metodo `ReportarEstado`— se
//! ejerce siempre, haya o no servicios en la maquina.

#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::net::TcpListener;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aegis_fleet::enlace::{ConectorFlota, ConfigEnlace, Enlace, Medida, Reportable};
use aegis_fleet::proto::{
    AckEstado, AckEvento, AckLatido, EstadoAgente, Latido, ReporteEvento, RespuestaEnrolamiento,
    SolicitudEnrolamiento,
};
use aegis_fleet::{
    certificado_desde_pem, AutoridadCertificadora, EmisorFichero, EmisorIdentidad, Identidad,
    ManejadorFlota, PoliticaRotacion, RotadorCertificados, ServidorFlota,
};

/// Un plano de control que apunta lo que le llega y de quien.
#[derive(Default)]
struct Registro {
    eventos: Mutex<Vec<(String, String)>>,
    estados: Mutex<Vec<(String, String)>>,
}

impl ManejadorFlota for Registro {
    fn enrolar(&self, cn: &str, _req: &SolicitudEnrolamiento) -> RespuestaEnrolamiento {
        RespuestaEnrolamiento {
            aceptado: true,
            id_flota: format!("fleet:{cn}"),
            intervalo_latido_seg: 1,
            motivo: String::new(),
        }
    }

    fn latido(&self, _cn: &str, _req: &Latido) -> AckLatido {
        AckLatido {
            recibido: true,
            ..Default::default()
        }
    }

    fn evento(&self, cn: &str, req: &ReporteEvento) -> AckEvento {
        self.eventos
            .lock()
            .unwrap()
            .push((cn.to_string(), req.descripcion.clone()));
        AckEvento {
            recibido: true,
            id_incidente: "i".to_string(),
            reintentar: false,
        }
    }

    fn estado(&self, cn: &str, req: &EstadoAgente) -> AckEstado {
        self.estados
            .lock()
            .unwrap()
            .push((cn.to_string(), req.estado_json.clone()));
        AckEstado { recibido: true }
    }
}

/// Un elemento que DICE ser otro agente en el cuerpo del mensaje.
struct Mentiroso(String);

impl Reportable for Mentiroso {
    fn peso(&self) -> usize {
        64 + self.0.len()
    }
    fn prioridad(&self) -> u8 {
        1
    }
    fn reporte(&self, _id_agente: &str) -> ReporteEvento {
        ReporteEvento {
            id_agente: "otro-agente-inventado".to_string(),
            descripcion: self.0.clone(),
            ..Default::default()
        }
    }
}

struct Temporal(PathBuf);

impl Temporal {
    fn nuevo(nombre: &str) -> Temporal {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let d = std::env::temp_dir().join(format!(
            "aegis-enlace-{nombre}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&d).unwrap();
        Temporal(d)
    }
}

impl Drop for Temporal {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn escribir(ruta: &Path, contenido: &str, modo: u32) {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(modo)
        .open(ruta)
        .unwrap();
    f.write_all(contenido.as_bytes()).unwrap();
    // El modo se fija ademas a mano: `mode()` pasa por la umask, y con una umask
    // 077 una clave «0640» saldria 0600 y la prueba del rechazo no probaria nada.
    fs::set_permissions(ruta, fs::Permissions::from_mode(modo)).unwrap();
}

/// Deja en disco el certificado y la clave de `id`, como el despliegue.
fn provisionar(dir: &Path, id: &Identidad, modo_clave: u32) -> (PathBuf, PathBuf) {
    let (crt, key) = (dir.join("agente.crt"), dir.join("agente.key"));
    escribir(&crt, &id.cert_pem(), 0o644);
    escribir(&key, &id.clave_pem(), modo_clave);
    (crt, key)
}

fn esperar(que: &str, mut cond: impl FnMut() -> bool) {
    let limite = Instant::now() + Duration::from_secs(20);
    while !cond() {
        assert!(Instant::now() < limite, "no llego a pasar: {que}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn el_estado_del_agente_hace_ida_y_vuelta_por_el_cable() {
    let e = EstadoAgente {
        id_agente: "agente-fichero".to_string(),
        momento_unix: 1_700_000_000,
        estado_json: "{\"enlace\":{\"cuadra\":true}}".to_string(),
    };
    assert_eq!(EstadoAgente::decodificar(&e.codificar()).unwrap(), e);
    let a = AckEstado { recibido: true };
    assert_eq!(AckEstado::decodificar(&a.codificar()).unwrap(), a);
    assert!(!AckEstado::decodificar(&[]).unwrap().recibido);
}

#[test]
fn la_identidad_provisionada_se_lee_entera_y_la_clave_tiene_que_ser_la_suya() {
    let ca = AutoridadCertificadora::nueva("AegisFleet Test CA").unwrap();
    let id = ca.emitir("agente-fichero", 600).unwrap();
    let leida = Identidad::desde_pem(&id.cert_pem(), &id.clave_pem()).unwrap();
    assert_eq!(leida.cn, "agente-fichero");
    assert_eq!(leida.cert_der, id.cert_der);
    assert_eq!(leida.no_antes_unix, id.no_antes_unix);
    assert_eq!(leida.no_despues_unix, id.no_despues_unix);

    // La clave de OTRO certificado no vale, aunque sea de la misma CA.
    let otra = ca.emitir("agente-fichero", 600).unwrap();
    let e = Identidad::desde_pem(&id.cert_pem(), &otra.clave_pem()).unwrap_err();
    assert!(e.to_string().contains("no corresponde"), "{e}");

    // Un PEM que no es un certificado no pasa por uno.
    assert!(certificado_desde_pem(&id.clave_pem()).is_err());
    assert_eq!(certificado_desde_pem(&id.cert_pem()).unwrap(), id.cert_der);
}

#[test]
fn el_emisor_de_fichero_exige_clave_privada_de_verdad_y_el_mismo_cn() {
    let ca = AutoridadCertificadora::nueva("AegisFleet Test CA").unwrap();
    let id = ca.emitir("agente-fichero", 600).unwrap();

    let bueno = Temporal::nuevo("bueno");
    let (crt, key) = provisionar(&bueno.0, &id, 0o600);
    let emisor = EmisorFichero::nuevo(&crt, &key);
    assert_eq!(
        emisor.emitir("agente-fichero", 0).unwrap().cn,
        "agente-fichero"
    );
    // La identidad de un agente no cambia en caliente.
    let e = emisor.emitir("otro-cn", 0).unwrap_err();
    assert!(e.to_string().contains("otro-cn"), "{e}");

    // Una clave que puede leer el grupo se rechaza, con el modo en el mensaje.
    let abierto = Temporal::nuevo("abierto");
    let (crt, key) = provisionar(&abierto.0, &id, 0o640);
    let e = EmisorFichero::nuevo(&crt, &key).leer().unwrap_err();
    assert!(e.to_string().contains("640"), "{e}");
}

#[test]
fn el_enlace_espera_al_servidor_y_entrega_con_la_identidad_del_certificado() {
    let ca = Arc::new(AutoridadCertificadora::nueva("AegisFleet Test CA").unwrap());
    let id = ca.emitir("agente-fichero", 3600).unwrap();
    let dir = Temporal::nuevo("enlace");
    let (crt, key) = provisionar(&dir.0, &id, 0o600);

    // Un puerto donde AUN no escucha nadie: el agente arranca antes que el
    // plano de control, que es lo normal tras un corte de luz.
    let puerto = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let direccion = format!("127.0.0.1:{puerto}");

    let emisor = Arc::new(EmisorFichero::nuevo(&crt, &key));
    let rotador = RotadorCertificados::nuevo(
        "agente-fichero",
        PoliticaRotacion {
            validez_seg: 3600,
            renovar_al_pct: 60,
        },
        emisor,
    )
    .unwrap();
    let conector = ConectorFlota::nuevo(
        &direccion,
        certificado_desde_pem(&ca.cert_pem()).unwrap(),
        Arc::new(rotador),
        "host-de-prueba",
        "1.0.0",
        Duration::from_secs(5),
    );
    let enlace: Enlace<Mentiroso> = Enlace::arrancar(
        conector,
        ConfigEnlace {
            reintento_base: Duration::from_millis(50),
            reintento_tope: Duration::from_millis(200),
            ventana_desfase: Duration::from_millis(50),
            ..ConfigEnlace::default()
        },
        Box::new(|| Medida {
            rss_kb: 1234,
            ..Medida::default()
        }),
    )
    .unwrap();
    enlace.publicar_estado("{\"motores\":[]}".to_string());
    for i in 0..3 {
        enlace.ofrecer(Mentiroso(format!("veredicto {i}")));
    }
    esperar("fallos de conexion sin servidor", || {
        enlace.instantanea().fallos_conexion >= 1
    });
    assert_eq!(enlace.instantanea().en_cola, 3);

    // Llega el plano de control.
    let registro = Arc::new(Registro::default());
    let id_servidor = ca.emitir("control-plane", 3600).unwrap();
    let servidor = ServidorFlota::nuevo(&id_servidor, &ca.cert_der(), registro.clone())
        .unwrap()
        .escuchar(&direccion)
        .unwrap();

    esperar("entrega completa", || enlace.instantanea().enviados == 3);
    esperar("un estado con el enlace", || {
        registro
            .estados
            .lock()
            .unwrap()
            .iter()
            .any(|(_, e)| e.contains("\"enlace\":{"))
    });
    let fin = enlace.parar();
    assert!(fin.cuadra(), "{fin:?}");
    assert!(fin.conectado);

    // El plano de control atribuye TODO al CN del certificado, no al
    // `id_agente` que el mensaje dice.
    let eventos = registro.eventos.lock().unwrap().clone();
    assert_eq!(
        eventos,
        (0..3)
            .map(|i| ("agente-fichero".to_string(), format!("veredicto {i}")))
            .collect::<Vec<_>>()
    );
    assert!(registro
        .estados
        .lock()
        .unwrap()
        .iter()
        .all(|(cn, e)| cn == "agente-fichero" && e.starts_with("{\"agente\":{\"motores\":[]}")));
    servidor.parar();
}
