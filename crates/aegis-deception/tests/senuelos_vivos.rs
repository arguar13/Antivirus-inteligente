//! Los diecinueve senuelos, hablados por un socket de verdad.
//!
//! # Por que esta prueba abre sockets y las de los dialogos no
//!
//! Los dialogos son sans-IO y se prueban sin red: es lo que permite meterles
//! entradas hostiles a millares sin condiciones de carrera. Pero eso deja un
//! hueco, y el hueco es justo donde fallan los productos de este tipo: **el
//! dialogo puede estar perfecto y el senuelo no levantarse**, o levantarse y no
//! mandar el saludo, o mandarlo y no leer la respuesta.
//!
//! Aqui se levanta la red de senuelos en `localhost` con puerto efimero, se
//! conecta un cliente de verdad a cada uno y se comprueba que la conversacion
//! ocurre de principio a fin. Sin simulaciones: si esto pasa, un atacante que se
//! conecte encuentra lo mismo.
//!
//! El puerto es efimero (`0`) a proposito: una prueba que pidiera el 22 o el 445
//! necesitaria privilegios y chocaria con los servicios de la maquina, que es
//! exactamente lo que un senuelo no debe hacer.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

use aegis_deception::decoy::{DecoyConfig, DecoyKind, DecoyNet, CATALOGO, INDUSTRIALES};
use aegis_deception::dialogo::Revelacion;
use aegis_deception::Interaction;

/// Lo que se manda a cada senuelo para que la conversacion avance.
///
/// Son mensajes de protocolo de verdad, no relleno: lo que se comprueba es que el
/// senuelo **entiende** lo que le llega y contesta en consecuencia.
fn guion(k: DecoyKind) -> Vec<Vec<u8>> {
    match k {
        DecoyKind::Ssh => vec![b"SSH-2.0-libssh2_1.10.0\r\n".to_vec()],
        DecoyKind::Telnet => vec![b"root\r\n".to_vec(), b"toor\r\n".to_vec()],
        DecoyKind::Ftp => vec![
            b"USER admin\r\n".to_vec(),
            b"PASS Verano2024\r\n".to_vec(),
            b"RETR clientes.sql\r\n".to_vec(),
        ],
        DecoyKind::Vnc => vec![b"RFB 003.008\n".to_vec(), vec![2], vec![0xAB; 16]],
        DecoyKind::Rdp => {
            vec![b"\x03\x00\x00\x2c\x27\xe0\x00\x00\x00\x00\x00Cookie: mstshash=ADMIN\r\n".to_vec()]
        }
        DecoyKind::Smb => {
            let mut v = vec![0u8, 0, 0, 64];
            v.extend_from_slice(b"\xfeSMB");
            v.extend_from_slice(&[0u8; 60]);
            vec![v]
        }
        DecoyKind::Http | DecoyKind::WinRm => {
            vec![b"GET /.env HTTP/1.1\r\nHost: x\r\nUser-Agent: curl/8.0\r\n\r\n".to_vec()]
        }
        DecoyKind::Https => vec![hello_tls()],
        DecoyKind::MySql => {
            let mut c = vec![0u8; 32];
            c.extend_from_slice(b"root\0");
            c.push(20);
            c.extend_from_slice(&[0xAB; 20]);
            c.extend_from_slice(b"produccion\0");
            let mut v = (c.len() as u32).to_le_bytes()[..3].to_vec();
            v.push(1);
            v.extend_from_slice(&c);
            vec![v]
        }
        DecoyKind::Postgres => {
            let mut cuerpo = 196_608u32.to_be_bytes().to_vec();
            for (a, b) in [("user", "postgres"), ("database", "prod")] {
                cuerpo.extend_from_slice(a.as_bytes());
                cuerpo.push(0);
                cuerpo.extend_from_slice(b.as_bytes());
                cuerpo.push(0);
            }
            cuerpo.push(0);
            let mut m = ((cuerpo.len() + 4) as u32).to_be_bytes().to_vec();
            m.extend_from_slice(&cuerpo);
            vec![m]
        }
        DecoyKind::MsSql => {
            let mut v = vec![0x12, 0x01, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x00, 0xff];
            v.extend_from_slice(&[0, 0, 0]);
            vec![v]
        }
        DecoyKind::Redis => vec![
            b"*1\r\n$4\r\nINFO\r\n".to_vec(),
            b"*2\r\n$3\r\nGET\r\n$10\r\nconfig:api\r\n".to_vec(),
        ],
        DecoyKind::MongoDb => vec![mensaje_mongo("hello")],
        DecoyKind::Modbus => vec![vec![
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x10, 0x00, 0x28, 0x00, 0x02,
        ]],
        DecoyKind::S7Comm => vec![
            vec![
                0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00,
            ],
            {
                let mut v = vec![0x03, 0x00, 0x00, 0x20, 0x02, 0xf0, 0x80];
                v.extend_from_slice(&[0x32, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00, 0x00]);
                v.push(0x29);
                v.extend_from_slice(&[0u8; 8]);
                v
            },
        ],
        DecoyKind::Dnp3 => vec![vec![
            0x05, 0x64, 0x0b, 0xc4, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0xc0, 0xc1, 0x05,
        ]],
        // BACnet va sobre UDP de verdad; aqui el oyente es TCP, asi que se le
        // manda el mismo mensaje. Lo que importa de este senuelo —que no
        // amplifique— se mide en `autoataque_senuelos.rs`, que es donde toca.
        DecoyKind::Bacnet => vec![vec![0x81, 0x0b, 0x00, 0x08, 0x01, 0x20, 0x10, 0x08]],
        DecoyKind::OpcUa => {
            let url = "opc.tcp://scada-1:4840/UA";
            let mut v = Vec::from(*b"HELF");
            v.extend_from_slice(&((32 + url.len()) as u32).to_le_bytes());
            v.extend_from_slice(&[0u8; 20]);
            v.extend_from_slice(&(url.len() as u32).to_le_bytes());
            v.extend_from_slice(url.as_bytes());
            vec![v]
        }
    }
}

fn hello_tls() -> Vec<u8> {
    let nombre = b"intranet.empresa.es";
    let mut ext = Vec::new();
    ext.extend_from_slice(&((nombre.len() + 3) as u16).to_be_bytes());
    ext.push(0);
    ext.extend_from_slice(&(nombre.len() as u16).to_be_bytes());
    ext.extend_from_slice(nombre);
    let mut exts = 0u16.to_be_bytes().to_vec();
    exts.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    exts.extend_from_slice(&ext);

    let mut cuerpo = vec![3, 3];
    cuerpo.extend_from_slice(&[0x42; 32]);
    cuerpo.push(0);
    cuerpo.extend_from_slice(&4u16.to_be_bytes());
    cuerpo.extend_from_slice(&[0x13, 0x01, 0xc0, 0x2f]);
    cuerpo.extend_from_slice(&[1, 0]);
    cuerpo.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    cuerpo.extend_from_slice(&exts);

    let mut hs = vec![1];
    hs.extend_from_slice(&(cuerpo.len() as u32).to_be_bytes()[1..]);
    hs.extend_from_slice(&cuerpo);
    let mut v = vec![22, 3, 1];
    v.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    v.extend_from_slice(&hs);
    v
}

fn mensaje_mongo(mando: &str) -> Vec<u8> {
    let mut doc = vec![0u8; 4];
    doc.push(0x01);
    doc.extend_from_slice(mando.as_bytes());
    doc.push(0);
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
    v
}

/// Levanta la red en localhost con puertos efimeros.
fn red(servicios: &[DecoyKind], cebo: &str) -> DecoyNet {
    DecoyNet::bind(DecoyConfig {
        bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
        services: servicios.iter().map(|k| (*k, 0u16)).collect(),
        speak_timeout: Duration::from_millis(120),
        max_evidence: 2048,
        max_per_poll: 32,
        cebo: cebo.to_owned(),
    })
}

/// Habla con un senuelo desde otro hilo, siguiendo su guion.
///
/// Devuelve lo que el senuelo contesto, junto, para poder comprobarlo.
///
/// **Solo espera saludo si el servicio saluda.** Un cliente que se quedara
/// esperando un saludo de SMB o de Modbus —que no lo mandan, porque sus servicios
/// reales tampoco— agotaria antes la paciencia del senuelo que la suya, y la
/// conversacion no llegaria a empezar. Es un error del cliente de prueba, no del
/// senuelo, y merece decirse porque es facil de cometer con un guion generico.
fn hablar(kind: DecoyKind, puerto: u16, guion: Vec<Vec<u8>>) -> std::thread::JoinHandle<Vec<u8>> {
    let saluda = kind.banner().is_some();
    std::thread::spawn(move || {
        let destino = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), puerto);
        let Ok(mut s) = TcpStream::connect_timeout(&destino, Duration::from_secs(2)) else {
            return Vec::new();
        };
        let _ = s.set_read_timeout(Some(Duration::from_millis(250)));
        let mut oido = Vec::new();
        let mut buf = [0u8; 4096];
        if saluda {
            if let Ok(n) = s.read(&mut buf) {
                oido.extend_from_slice(&buf[..n]);
            }
        }
        for mensaje in guion {
            if s.write_all(&mensaje).is_err() {
                break;
            }
            match s.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => oido.extend_from_slice(&buf[..n]),
            }
        }
        oido
    })
}

/// Atiende hasta que llegue una interaccion o se agote la paciencia.
fn recoger(net: &DecoyNet, ahora: u64) -> Vec<Interaction> {
    let mut todas = Vec::new();
    for _ in 0..40 {
        let v = net.poll(Duration::from_millis(100), ahora);
        if !v.is_empty() {
            todas.extend(v);
            break;
        }
    }
    todas
}

#[test]
fn los_diecinueve_senuelos_hablan_por_un_socket_de_verdad() {
    let mut conversados = 0;
    let mut sin_levantar = Vec::new();

    for kind in CATALOGO {
        let net = red(&[kind], "");
        let Some((_, puerto)) = net.active().first().copied() else {
            sin_levantar.push(kind.as_str());
            continue;
        };
        let cliente = hablar(kind, puerto, guion(kind));
        let interacciones = recoger(&net, 1_000);
        let oido = cliente.join().unwrap_or_default();

        assert_eq!(
            interacciones.len(),
            1,
            "el senuelo de {} no registro la conexion",
            kind.as_str()
        );
        let i = &interacciones[0];
        assert_eq!(i.kind, kind);
        assert!(
            i.spoke(),
            "el senuelo de {} no recogio nada de lo que le dijeron",
            kind.as_str()
        );
        assert!(
            !i.revelado.is_empty(),
            "el senuelo de {} no saco nada en claro del visitante",
            kind.as_str()
        );
        assert!(
            !oido.is_empty(),
            "el senuelo de {} no contesto nada: un servicio mudo se descarta",
            kind.as_str()
        );
        conversados += 1;
    }

    println!("\n=== Senuelos hablados por socket ===");
    println!(
        "  {conversados} de {} conversaron de verdad",
        CATALOGO.len()
    );
    if !sin_levantar.is_empty() {
        println!("  no se levantaron: {}", sin_levantar.join(", "));
    }
    assert_eq!(
        conversados,
        CATALOGO.len(),
        "no se levantaron: {sin_levantar:?}"
    );
}

#[test]
fn el_senuelo_industrial_distingue_al_que_mira_del_que_toca() {
    // **La cifra que importa en una planta.** Una lectura es reconocimiento; una
    // escritura es un intento de actuar sobre un proceso fisico, y eso no es una
    // alerta mas grave: es otra clase de incidente.
    let leer = vec![vec![
        0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x64, 0x00, 0x0a,
    ]];
    let escribir = vec![vec![
        0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x10, 0x00, 0x28, 0x00, 0x02,
    ]];

    for (mensajes, esperado) in [(leer, false), (escribir, true)] {
        let net = red(&[DecoyKind::Modbus], "");
        let (_, puerto) = net.active()[0];
        let cliente = hablar(DecoyKind::Modbus, puerto, mensajes);
        let i = recoger(&net, 1);
        let _ = cliente.join();
        assert_eq!(i.len(), 1);
        assert_eq!(i[0].intento_escribir(), esperado, "{:?}", i[0].revelado);
    }
}

#[test]
fn los_senuelos_de_acceso_entregan_las_credenciales_que_probaron() {
    // Telnet y FTP mandan usuario y clave en claro, y eso es lo que un senuelo
    // tiene que llevarse: no que alguien toco el puerto, sino con que credenciales.
    for (kind, usuario, clave) in [
        (DecoyKind::Telnet, "root", "toor"),
        (DecoyKind::Ftp, "admin", "Verano2024"),
    ] {
        let net = red(&[kind], "");
        let (_, puerto) = net.active()[0];
        let cliente = hablar(kind, puerto, guion(kind));
        let i = recoger(&net, 1);
        let _ = cliente.join();

        let creds = i[0].credenciales();
        assert!(
            creds.iter().any(|(u, c)| u == usuario && c == clave),
            "el senuelo de {} no se quedo con la credencial: {:?}",
            kind.as_str(),
            i[0].revelado
        );
    }
}

#[test]
fn el_cebo_llega_a_quien_se_lo_lleva() {
    // Lo que hace atribuible al senuelo: el visitante se lleva un texto que solo
    // existe aqui.
    const CEBO: &str = "API_KEY=AKIA0000EJEMPLO:marcador0123456789abcdef01234567";
    let net = red(&[DecoyKind::Http], CEBO);
    let (_, puerto) = net.active()[0];
    let cliente = hablar(DecoyKind::Http, puerto, guion(DecoyKind::Http));
    let _ = recoger(&net, 1);
    let oido = cliente.join().unwrap_or_default();
    let texto = String::from_utf8_lossy(&oido);
    assert!(
        texto.contains("AKIA0000EJEMPLO"),
        "el visitante no se llevo el cebo: {texto}"
    );
}

#[test]
fn un_senuelo_no_tapa_un_servicio_de_verdad() {
    // La regla que hace que este producto se pueda instalar: si el puerto ya lo
    // usa alguien, el senuelo NO lo toma. Se comprueba ocupandolo antes.
    let ocupado = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("se ocupa");
    let puerto = ocupado.local_addr().unwrap().port();

    let net = DecoyNet::bind(DecoyConfig {
        bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
        services: vec![(DecoyKind::Ssh, puerto)],
        ..Default::default()
    });
    assert!(net.active().is_empty(), "el senuelo tapo un servicio vivo");
    assert_eq!(net.skipped().len(), 1);
    assert_eq!(net.skipped()[0].port, puerto);
}

#[test]
fn una_pasarela_industrial_levanta_sus_cinco_senuelos() {
    let net = red(&INDUSTRIALES, "");
    assert_eq!(
        net.active().len(),
        INDUSTRIALES.len(),
        "faltan senuelos industriales: {:?}",
        net.skipped()
    );
    // Y cada uno en su propio puerto, que es lo que permite decir cual tocaron.
    let mut puertos: Vec<u16> = net.active().iter().map(|(_, p)| *p).collect();
    puertos.sort_unstable();
    puertos.dedup();
    assert_eq!(puertos.len(), INDUSTRIALES.len());
}

#[test]
fn el_saludo_que_se_manda_es_el_que_el_dialogo_espera_haber_mandado() {
    // Con dos fuentes —una tabla de saludos y una maquina de estados— se
    // separan en cuanto alguien toca una: el senuelo saluda como un OpenSSH y
    // sigue como otra cosa, y eso se nota en el primer turno.
    for kind in CATALOGO {
        let del_catalogo = kind.banner();
        let del_dialogo = kind.dialogo(String::new()).saludo();
        assert_eq!(
            del_catalogo,
            del_dialogo,
            "el saludo de {} sale de dos sitios distintos",
            kind.as_str()
        );
    }
}

#[test]
fn la_revelacion_de_un_escaner_se_distingue_de_la_de_alguien_sentado() {
    // Un turno es un escaner; varios son alguien probando. La diferencia decide
    // si se mira hoy o el lunes, asi que tiene que estar en la interaccion.
    let net = red(&[DecoyKind::Ftp], "");
    let (_, puerto) = net.active()[0];
    let cliente = hablar(DecoyKind::Ftp, puerto, guion(DecoyKind::Ftp));
    let i = recoger(&net, 1);
    let _ = cliente.join();
    assert!(i[0].turnos >= 3, "turnos: {}", i[0].turnos);

    let net = red(&[DecoyKind::Ftp], "");
    let (_, puerto) = net.active()[0];
    let cliente = hablar(DecoyKind::Ftp, puerto, vec![b"QUIT\r\n".to_vec()]);
    let i = recoger(&net, 1);
    let _ = cliente.join();
    assert_eq!(i[0].turnos, 1);
}

#[test]
fn lo_revelado_se_puede_leer_en_una_frase() {
    // Una alerta que hay que descifrar no se lee. Cada revelacion se cuenta sola.
    let net = red(&[DecoyKind::Telnet], "");
    let (_, puerto) = net.active()[0];
    let cliente = hablar(DecoyKind::Telnet, puerto, guion(DecoyKind::Telnet));
    let i = recoger(&net, 1);
    let _ = cliente.join();
    let frases: Vec<String> = i[0].revelado.iter().map(Revelacion::frase).collect();
    assert!(
        frases
            .iter()
            .any(|f| f.contains("root") && f.contains("toor")),
        "{frases:?}"
    );
}
