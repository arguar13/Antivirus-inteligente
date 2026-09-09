//! Siembra una flota de demostracion contra un plano de control en marcha.
//!
//! Enrola agentes REALES —el mismo `ClienteFlota` que corre en un endpoint— con
//! certificados emitidos por la CA que el servidor tiene persistida, y les hace
//! latir, reportar alertas y entregar el linaje de procesos de una deteccion.
//!
//! Sirve para dos cosas: dejar la consola con datos con los que trabajar, y
//! comprobar de extremo a extremo que la cadena entera —mTLS, protobuf,
//! PostgreSQL, WebSocket, consola— funciona junta.
//!
//! Uso:
//!   AEGIS_CA_DIR=<dir> AEGIS_FLEET_ADDR=127.0.0.1:8443 \
//!     cargo run -p aegis-server --example poblar_flota -- [numero_de_agentes]

use std::sync::Arc;

use aegis_fleet::pki::AutoridadCertificadora;
use aegis_fleet::proto::{Latido, NodoProceso, ReporteEvento, ReporteGrafo, ReporteStix};
use aegis_fleet::{ClienteFlota, EmisorLocal, PoliticaRotacion, RotadorCertificados};

/// Un incidente que el endpoint reporta.
struct Incidente {
    /// Categoria observada, que el plano de control traduce a MITRE ATT&CK.
    categoria: &'static str,
    /// Descripcion legible.
    descripcion: &'static str,
    /// Severidad 0..4.
    severidad: u64,
}

/// Perfil de un endpoint de la flota de demostracion.
struct Maquina {
    /// Nombre de la maquina.
    hostname: &'static str,
    /// Version del agente instalada.
    version: &'static str,
    /// Memoria residente que reporta.
    rss_kb: u64,
    /// Amenazas activas que reporta.
    amenazas: u64,
    /// Incidente que reporta, si lo hay.
    incidente: Option<Incidente>,
}

/// Constructor breve, para que la tabla de abajo se lea de un vistazo.
const fn maq(
    hostname: &'static str,
    version: &'static str,
    rss_kb: u64,
    amenazas: u64,
    incidente: Option<Incidente>,
) -> Maquina {
    Maquina {
        hostname,
        version,
        rss_kb,
        amenazas,
        incidente,
    }
}

/// Constructor breve de incidente.
const fn inc(
    categoria: &'static str,
    descripcion: &'static str,
    severidad: u64,
) -> Option<Incidente> {
    Some(Incidente {
        categoria,
        descripcion,
        severidad,
    })
}

/// Perfiles de endpoint, para que la consola muestre una flota plausible.
const MAQUINAS: &[Maquina] = &[
    maq("srv-nomina-01", "1.0.0", 21_800, 0, None),
    maq("srv-ficheros-02", "1.0.0", 22_400, 0, None),
    maq(
        "pc-contabilidad-07",
        "1.0.0",
        23_100,
        2,
        inc("ransomware", "cifrado masivo de documentos en red", 4),
    ),
    maq("srv-web-03", "1.0.0", 20_900, 0, None),
    maq(
        "pc-direccion-01",
        "1.0.0",
        24_500,
        1,
        inc("inyeccion", "codigo inyectado en proceso de ofimatica", 3),
    ),
    maq("srv-copias-01", "0.9.8", 19_700, 0, None),
    maq("pc-taller-12", "1.0.0", 22_000, 0, None),
    maq(
        "srv-dominio-01",
        "1.0.0",
        25_300,
        3,
        inc(
            "rootkit",
            "modulo oculto detectado por verificacion cruzada",
            4,
        ),
    ),
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir_ca = std::env::var("AEGIS_CA_DIR").unwrap_or_else(|_| "/var/lib/aegis/ca".into());
    let destino = std::env::var("AEGIS_FLEET_ADDR").unwrap_or_else(|_| "127.0.0.1:8443".into());
    let cuantos: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(MAQUINAS.len())
        .min(MAQUINAS.len());

    // La CA del plano de control: es la que hace validos los certificados de los
    // agentes. En un despliegue real esto lo hace la herramienta de
    // aprovisionamiento, no cada endpoint.
    let cert = std::fs::read_to_string(format!("{dir_ca}/flota-ca.crt"))?;
    let clave = std::fs::read_to_string(format!("{dir_ca}/flota-ca.key"))?;
    let ca = Arc::new(AutoridadCertificadora::desde_pem(&cert, &clave)?);
    let ancla = ca.cert_der();
    let direccion: std::net::SocketAddr = destino.parse()?;

    println!("sembrando {cuantos} endpoint(s) contra {destino}");

    for m in MAQUINAS.iter().take(cuantos) {
        let hostname = m.hostname;
        let cn = format!("{hostname}.empresa.local");
        let emisor = Arc::new(EmisorLocal::nuevo(ca.clone()));
        let rotador = Arc::new(RotadorCertificados::nuevo(
            &cn,
            PoliticaRotacion::default(),
            emisor,
        )?);
        let agente = ClienteFlota::nuevo(direccion, ancla.clone(), rotador, hostname, m.version);

        // Enrolar.
        let mut s = agente.abrir_sesion()?;
        let r = s.enrolar(&agente.solicitud_enrolamiento()?)?;
        if !r.aceptado {
            eprintln!("  {hostname}: rechazado ({})", r.motivo);
            continue;
        }

        // Latir con telemetria.
        let mut s = agente.abrir_sesion()?;
        s.latir(&Latido {
            id_agente: cn.clone(),
            momento_unix: 0,
            rss_kb: m.rss_kb,
            amenazas_activas: m.amenazas,
            version_politica: 1,
        })?;

        let mut detalle = String::from("sin incidentes");

        if let Some(inc) = &m.incidente {
            // Alerta.
            let mut s = agente.abrir_sesion()?;
            let ack = s.reportar_evento(&ReporteEvento {
                id_agente: cn.clone(),
                severidad: inc.severidad,
                categoria: inc.categoria.to_string(),
                descripcion: inc.descripcion.to_string(),
                momento_unix: 0,
            })?;

            // El linaje que da contexto a la alerta: sin el, «python abrio un
            // socket» no concluye nada.
            let mut s = agente.abrir_sesion()?;
            let g = s.reportar_grafo(&ReporteGrafo {
                id_agente: cn.clone(),
                raiz: 300,
                momento_unix: 0,
                nodos: linaje(inc.categoria),
            })?;

            // Inteligencia asociada, en STIX 2.1.
            let mut s = agente.abrir_sesion()?;
            let _ = s.reportar_stix(&ReporteStix {
                id_agente: cn.clone(),
                bundle_json: bundle(inc.categoria),
                momento_unix: 0,
            })?;

            detalle = format!(
                "alerta {} ({}), linaje {} con {} nodos",
                ack.id_incidente, inc.categoria, g.id_grafo, g.nodos_ingeridos
            );
        }

        println!("  {hostname:<20} enrolado · {detalle}");
    }

    println!("hecho: la consola deberia mostrar la flota en tiempo real");
    Ok(())
}

/// Construye un linaje de procesos plausible para la categoria dada.
fn linaje(categoria: &str) -> Vec<NodoProceso> {
    let cadena: &[(u64, u64, &str, &str, u32)] = match categoria {
        "ransomware" => &[
            (100, 0, "/usr/lib/thunderbird/thunderbird", "thunderbird", 0),
            (200, 100, "/usr/bin/unzip", "unzip factura.zip", 10),
            (250, 200, "/bin/sh", "sh -c ./factura.pdf.sh", 45),
            (
                300,
                250,
                "/tmp/.x/cifrador",
                "cifrador --recursivo /red",
                95,
            ),
        ],
        "inyeccion" => &[
            (
                100,
                0,
                "/usr/lib/libreoffice/soffice.bin",
                "soffice --headless informe.odt",
                0,
            ),
            (200, 100, "/bin/sh", "sh -c curl | sh", 40),
            (300, 200, "/usr/bin/python3", "python3 -c import socket", 88),
        ],
        _ => &[
            (100, 0, "/usr/sbin/sshd", "sshd: root@pts/0", 0),
            (200, 100, "/bin/bash", "-bash", 15),
            (250, 200, "/usr/bin/insmod", "insmod /tmp/.k/mod.ko", 70),
            (300, 250, "/proc/self/exe", "[kworker/u8:2]", 92),
        ],
    };

    cadena
        .iter()
        .enumerate()
        .map(
            |(i, (clave, padre, imagen, cmdline, puntuacion))| NodoProceso {
                clave: *clave,
                pid: (*clave / 10) as u32 + 1000,
                padre: *padre,
                creador: *padre,
                profundidad: i as u32,
                imagen: (*imagen).to_string(),
                cmdline: (*cmdline).to_string(),
                clase: i as u32,
                iniciado_ns: 1_000_000 * (i as u64 + 1),
                terminado_ns: 0,
                taints: if *puntuacion > 40 { 0b111 } else { 0 },
                puntuacion: *puntuacion,
            },
        )
        .collect()
}

/// Bundle STIX 2.1 minimo asociado a la deteccion.
fn bundle(categoria: &str) -> String {
    let uuid = |n: u8| format!("0000{n:04}-1111-4222-8333-444444444444");
    format!(
        r#"{{"type":"bundle","id":"bundle--{}","objects":[
            {{"type":"indicator","spec_version":"2.1","id":"indicator--{}",
             "name":"{categoria}","pattern":"[file:hashes.'SHA-256' = '{}']",
             "pattern_type":"stix","valid_from":"2026-01-01T00:00:00Z"}}
        ]}}"#,
        uuid(1),
        // Identificador estable por categoria: dos endpoints que ven la misma
        // amenaza suman avistamientos en vez de duplicar el objeto.
        uuid(categoria.len() as u8),
        "ab".repeat(32)
    )
}
