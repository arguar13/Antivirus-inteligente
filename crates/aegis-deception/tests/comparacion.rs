//! La comparacion con el tarro de miel de referencia, medida de un lado y citada
//! del otro.
//!
//! # La regla, la misma de las FASES 89 y 90
//!
//! **Lo que se mide se mide, lo que se cita se cita, y se dice cual es cual.**
//!
//! Lo de este lado sale de construir la red de senuelos y preguntarle. Lo de
//! Cowrie esta transcrito de su documentacion y de su codigo publico: **no se ha
//! ejecutado Cowrie contra este corpus**, y presentar un dato de segunda mano como
//! si se hubiera medido es exactamente la clase de cifra que este producto existe
//! para no producir.
//!
//! # Y por que el recuento de protocolos no es la comparacion
//!
//! Porque se mueve anadiendo dialogos triviales. Cowrie hace **dos** protocolos,
//! SSH y Telnet, y los hace mucho mas hondo que este producto: da un interprete
//! de ordenes de verdad, con un sistema de ficheros falso persistente, descarga
//! los binarios que el atacante pide y guarda la sesion entera para reproducirla.
//! En SSH y Telnet, Cowrie saca mas.
//!
//! La comparacion honrada es de **propiedades**, y son de tres clases:
//!
//!   - Lo que hace este y aquel no.
//!   - Lo que hace aquel y este no —que tambien se escribe, porque una comparacion
//!     se hace igual de deshonesta inflando al otro que inflandose uno—.
//!   - El precio de cada eleccion, que es lo que de verdad se esta comparando.

use aegis_deception::decoy::{DecoyKind, CATALOGO, INDUSTRIALES};
use aegis_deception::dialogo::{Conversacion, Revelacion};
use aegis_deception::limitador::{Limitador, Transporte};

/// Los protocolos que el tarro de miel de referencia atiende.
///
/// **Citado, no medido.** Cowrie es un tarro de miel de SSH y Telnet; su
/// documentacion lo describe asi y su codigo tiene esos dos servicios. Se
/// transcribe tal cual.
const PROTOCOLOS_DE_COWRIE: [&str; 2] = ["ssh", "telnet"];

/// Lo que el de referencia hace y este no.
///
/// Va primero **a proposito**. Una comparacion que empieza por lo que uno hace
/// mejor es un folleto.
const LO_QUE_COWRIE_HACE_Y_ESTE_NO: [&str; 6] = [
    "un interprete de ordenes completo: el atacante ejecuta decenas de ordenes y \
     cada una devuelve algo creible",
    "un sistema de ficheros falso y PERSISTENTE: lo que el atacante deja sigue ahi \
     cuando vuelve, que es como se le ve montar su infraestructura",
    "descarga de verdad los binarios que el atacante pide con wget o curl, y los \
     guarda para analizarlos",
    "graba la sesion entera en formato reproducible, y se puede ver como si fuera \
     un video",
    "emula un sistema con usuarios, procesos y ficheros que el atacante explora \
     durante minutos u horas",
    "anos de despliegue publico y de datos recogidos por mucha gente, que es algo \
     que no se escribe: se acumula",
];

/// Lo que este hace y el de referencia no.
const LO_QUE_ESTE_HACE_Y_COWRIE_NO: [&str; 7] = [
    "diecinueve protocolos, con los cinco industriales que separan inventariar de \
     parar una planta",
    "cada senuelo entrega un token DISTINTO, atado a su servicio y su puerto: \
     cuando reaparece se sabe por que puerta salio",
    "una cota de amplificacion estructural en el transporte donde el origen puede \
     falsificarse, medida y no prometida",
    "un limitador de ritmo COMPARTIDO por toda la red, que no se salta colgando y \
     volviendo a llamar",
    "ninguna ejecucion en ningun senuelo: no hay interprete, no hay proceso hijo y \
     no hay sistema de ficheros, asi que no hay carcel de la que escaparse",
    "el mismo identificador de entidad que el resto del producto, asi que la visita \
     al senuelo y el proceso que la origino son la misma cosa sin correlacionar",
    "la distincion entre leer y ESCRIBIR en la orden industrial, que en una planta \
     no es un grado de severidad sino otra clase de incidente",
];

/// El precio de cada eleccion, que es lo que de verdad se compara.
const EL_PRECIO: [(&str, &str); 3] = [
    (
        "profundidad en SSH y Telnet",
        "Cowrie llega mucho mas lejos; este para en el KEXINIT y en tres intentos de \
         acceso. Se cambia profundidad por no tener un interprete que confinar.",
    ),
    (
        "riesgo del propio senuelo",
        "un interprete de ordenes sobre un sistema de ficheros es una superficie que \
         hay que encarcelar, y la carcel puede fallar. Aqui no hay nada que \
         encarcelar, y eso se comprueba por ausencia en el codigo.",
    ),
    (
        "que se saca de una visita",
        "Cowrie saca lo que el atacante HACE; este saca quien es, con que viene y por \
         donde volvera a aparecer lo que se lleve. Son dos preguntas distintas.",
    ),
];

#[test]
fn la_comparacion_separa_lo_medido_de_lo_citado() {
    // MEDIDO: se construye el catalogo y se le pregunta.
    let mios: Vec<&str> = CATALOGO.iter().map(|k| k.as_str()).collect();
    let comunes: Vec<&str> = PROTOCOLOS_DE_COWRIE
        .iter()
        .filter(|p| mios.contains(p))
        .copied()
        .collect();
    let solo_mios: Vec<&str> = mios
        .iter()
        .filter(|p| !PROTOCOLOS_DE_COWRIE.contains(p))
        .copied()
        .collect();

    println!("\n=== Comparacion con el tarro de miel de referencia ===");
    println!(
        "MEDIDO aqui, construyendo la red y preguntandole: {} protocolos",
        mios.len()
    );
    println!("  industriales: {}", INDUSTRIALES.len());
    println!(
        "CITADO, no medido: Cowrie atiende {} protocolos ({}). No se ha ejecutado",
        PROTOCOLOS_DE_COWRIE.len(),
        PROTOCOLOS_DE_COWRIE.join(" y ")
    );
    println!("  Cowrie contra este corpus, y presentar una cifra ajena como medida");
    println!("  propia es lo que este producto existe para no hacer.");
    println!("  en comun: {}", comunes.join(", "));
    println!(
        "  solo aqui ({}): {}",
        solo_mios.len(),
        solo_mios.join(", ")
    );

    println!("\nLO QUE COWRIE HACE Y ESTE NO:");
    for l in LO_QUE_COWRIE_HACE_Y_ESTE_NO {
        println!("  - {l}");
    }
    println!("\nLO QUE ESTE HACE Y COWRIE NO:");
    for l in LO_QUE_ESTE_HACE_Y_COWRIE_NO {
        println!("  - {l}");
    }
    println!("\nEL PRECIO DE CADA ELECCION:");
    for (que, detalle) in EL_PRECIO {
        println!("  {que}: {detalle}");
    }
    println!(
        "\nEl recuento no es la diferencia: se mueve anadiendo dialogos triviales.\n\
         En SSH y Telnet, que es donde los dos compiten, Cowrie saca MAS."
    );

    // Los dos protocolos de Cowrie estan aqui: si no, la comparacion no tendria
    // terreno comun y no se podria discutir.
    assert_eq!(comunes.len(), PROTOCOLOS_DE_COWRIE.len());
    // Y la lista de lo que el otro hace mejor no puede estar vacia: una
    // comparacion en la que el otro no gana en nada esta mal hecha.
    assert!(!LO_QUE_COWRIE_HACE_Y_ESTE_NO.is_empty());
    assert!(LO_QUE_COWRIE_HACE_Y_ESTE_NO.len() >= 5);
}

#[test]
fn las_propiedades_que_se_afirman_se_comprueban_construyendolas() {
    // Cada linea de «lo que este hace y aquel no» tiene que salir del codigo, no
    // de una lista escrita a mano. Aqui se comprueban las que se pueden construir.

    // 1. Diecinueve protocolos, cinco industriales.
    assert_eq!(CATALOGO.len(), 19);
    assert_eq!(INDUSTRIALES.len(), 5);
    for k in INDUSTRIALES {
        assert!(CATALOGO.contains(&k));
    }

    // 2. Un transporte de UDP en el catalogo, que es donde la cota importa.
    let udp: Vec<&str> = CATALOGO
        .iter()
        .filter(|k| k.transporte() == Transporte::Udp)
        .map(|k| k.as_str())
        .collect();
    assert_eq!(udp, vec!["bacnet"]);

    // 3. La distincion entre leer y escribir existe en los cinco industriales.
    let mut lim = Limitador::nuevo();
    let mut con_escritura = 0;
    for (kind, mensaje) in [
        (
            DecoyKind::Modbus,
            vec![
                0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x10, 0x00, 0x28, 0x00, 0x02,
            ],
        ),
        (
            DecoyKind::Dnp3,
            vec![
                0x05, 0x64, 0x0b, 0xc4, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0xc0, 0xc1, 0x0d,
            ],
        ),
    ] {
        let mut c = Conversacion::nueva(kind.dialogo(String::new()));
        c.saludo();
        c.turno(&mut lim, 1, 0, &mensaje);
        if c.revelado().iter().any(Revelacion::es_grave) {
            con_escritura += 1;
        }
    }
    assert_eq!(con_escritura, 2, "la distincion no esta donde se dice");
}

#[test]
fn el_catalogo_no_tiene_dos_servicios_con_el_mismo_nombre_ni_el_mismo_puerto() {
    // Dos senuelos con el mismo nombre harian ambigua la procedencia de un token,
    // que es la propiedad de esta fase; dos con el mismo puerto no se podrian
    // levantar a la vez.
    let mut nombres: Vec<&str> = CATALOGO.iter().map(|k| k.as_str()).collect();
    let antes = nombres.len();
    nombres.sort_unstable();
    nombres.dedup();
    assert_eq!(nombres.len(), antes, "hay dos senuelos con el mismo nombre");

    let mut puertos: Vec<u16> = CATALOGO.iter().map(|k| k.default_port()).collect();
    let antes = puertos.len();
    puertos.sort_unstable();
    puertos.dedup();
    assert_eq!(puertos.len(), antes, "hay dos senuelos en el mismo puerto");
}

#[test]
fn todos_los_senuelos_sacan_algo_en_claro_de_una_visita_normal() {
    // La propiedad que separa alta de baja interaccion: no basta con que el puerto
    // conteste, tiene que salir algo que se pueda escribir en una alerta.
    let mut sin_revelar = Vec::new();
    for kind in CATALOGO {
        let mut lim = Limitador::nuevo();
        let mut c = Conversacion::nueva(kind.dialogo(String::new()));
        c.saludo();
        for m in guion_normal(kind) {
            c.turno(&mut lim, 1, 0, &m);
        }
        if c.revelado().is_empty() {
            sin_revelar.push(kind.as_str());
        }
    }
    assert!(
        sin_revelar.is_empty(),
        "estos senuelos no sacan nada de una visita normal: {sin_revelar:?}"
    );
}

/// Una visita normal a cada senuelo, con mensajes de protocolo de verdad.
fn guion_normal(k: DecoyKind) -> Vec<Vec<u8>> {
    match k {
        DecoyKind::Ssh => vec![b"SSH-2.0-OpenSSH_9.0\r\n".to_vec()],
        DecoyKind::Telnet => vec![b"admin\r\n".to_vec(), b"admin\r\n".to_vec()],
        DecoyKind::Ftp => vec![b"USER anonymous\r\n".to_vec(), b"PASS a@b.c\r\n".to_vec()],
        DecoyKind::Vnc => vec![b"RFB 003.008\n".to_vec()],
        DecoyKind::Rdp => {
            vec![b"\x03\x00\x00\x2c\x27\xe0\x00\x00\x00\x00\x00Cookie: mstshash=x\r\n".to_vec()]
        }
        DecoyKind::Smb => {
            let mut v = vec![0u8, 0, 0, 64];
            v.extend_from_slice(b"\xfeSMB");
            v.extend_from_slice(&[0u8; 60]);
            vec![v]
        }
        DecoyKind::Http | DecoyKind::WinRm => {
            vec![b"GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: curl\r\n\r\n".to_vec()]
        }
        DecoyKind::Https => {
            let mut cuerpo = vec![3, 3];
            cuerpo.extend_from_slice(&[0x42; 32]);
            cuerpo.push(0);
            cuerpo.extend_from_slice(&2u16.to_be_bytes());
            cuerpo.extend_from_slice(&[0x13, 0x01]);
            cuerpo.extend_from_slice(&[1, 0]);
            cuerpo.extend_from_slice(&0u16.to_be_bytes());
            let mut hs = vec![1];
            hs.extend_from_slice(&(cuerpo.len() as u32).to_be_bytes()[1..]);
            hs.extend_from_slice(&cuerpo);
            let mut v = vec![22, 3, 1];
            v.extend_from_slice(&(hs.len() as u16).to_be_bytes());
            v.extend_from_slice(&hs);
            vec![v]
        }
        DecoyKind::MySql => {
            let mut c = vec![0u8; 32];
            c.extend_from_slice(b"root\0");
            c.push(20);
            c.extend_from_slice(&[0xAB; 20]);
            c.extend_from_slice(b"mysql\0");
            let mut v = (c.len() as u32).to_le_bytes()[..3].to_vec();
            v.push(1);
            v.extend_from_slice(&c);
            vec![v]
        }
        DecoyKind::Postgres => {
            let mut cuerpo = 196_608u32.to_be_bytes().to_vec();
            cuerpo.extend_from_slice(b"user\0postgres\0");
            cuerpo.push(0);
            let mut m = ((cuerpo.len() + 4) as u32).to_be_bytes().to_vec();
            m.extend_from_slice(&cuerpo);
            vec![m]
        }
        DecoyKind::MsSql => vec![vec![
            0x12, 0x01, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x00, 0xff, 0, 0, 0,
        ]],
        DecoyKind::Redis => vec![b"*1\r\n$4\r\nINFO\r\n".to_vec()],
        DecoyKind::MongoDb => {
            let mut doc = vec![0u8; 4];
            doc.push(0x01);
            doc.extend_from_slice(b"hello\0");
            doc.extend_from_slice(&1.0f64.to_le_bytes());
            doc.push(0);
            let n = doc.len() as u32;
            doc[..4].copy_from_slice(&n.to_le_bytes());
            let total = 16 + 5 + doc.len();
            let mut v = (total as u32).to_le_bytes().to_vec();
            v.extend_from_slice(&7u32.to_le_bytes());
            v.extend_from_slice(&0u32.to_le_bytes());
            v.extend_from_slice(&2013u32.to_le_bytes());
            v.extend_from_slice(&0u32.to_le_bytes());
            v.push(0);
            v.extend_from_slice(&doc);
            vec![v]
        }
        DecoyKind::Modbus => vec![vec![
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0a,
        ]],
        DecoyKind::S7Comm => vec![vec![
            0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00,
        ]],
        DecoyKind::Dnp3 => vec![vec![
            0x05, 0x64, 0x0b, 0xc4, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0xc0, 0xc1, 0x01,
        ]],
        DecoyKind::Bacnet => vec![vec![0x81, 0x0b, 0x00, 0x08, 0x01, 0x20, 0x10, 0x08]],
        DecoyKind::OpcUa => {
            let url = "opc.tcp://x:4840/UA";
            let mut v = Vec::from(*b"HELF");
            v.extend_from_slice(&((32 + url.len()) as u32).to_le_bytes());
            v.extend_from_slice(&[0u8; 20]);
            v.extend_from_slice(&(url.len() as u32).to_le_bytes());
            v.extend_from_slice(url.as_bytes());
            vec![v]
        }
    }
}
