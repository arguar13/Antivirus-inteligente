//! De la siembra al uso: un token sembrado en un senuelo, usado despues en otro
//! sitio, y la pregunta contestada.
//!
//! # La pregunta
//!
//! No es «¿alguien toco el senuelo?», que la contesta cualquier tarro de miel. Es
//! **«¿por donde entraron, y donde ha estado despues lo que se llevaron?»**, que
//! es la que se hace en un incidente de verdad y la que decide por donde se
//! empieza a tirar del hilo.
//!
//! El recorrido que se ejercita aqui es el entero:
//!
//!   1. Se siembra un token distinto en cada senuelo, atado a su servicio y su
//!      puerto.
//!   2. Un visitante conversa con uno de ellos por un socket de verdad y se lleva
//!      lo que el senuelo le sirve.
//!   3. Ese texto reaparece **en otro sitio** — en un volcado de memoria, en un
//!      registro de acceso, en un aviso de un tercero.
//!   4. Y de el sale, sin consultar ninguna tabla, de que senuelo salio.
//!
//! El paso 4 es el que no hace nadie, y es el unico que convierte un senuelo en
//! algo que sirve tres semanas despues.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

use aegis_deception::decoy::{DecoyConfig, DecoyKind, DecoyNet};
use aegis_deception::plantado::Plantacion;
use aegis_honeytoken::credformat::Artefacto;
use aegis_honeytoken::destino::Destino;
use aegis_honeytoken::token::Atribucion;
use aegis_honeytoken::trip::{clasificar, ComoDisparo, Evento};

/// El secreto de flota de la prueba.
const SECRETO: [u8; 32] = [0x5e; 32];

fn plantacion() -> Plantacion {
    Plantacion::nueva(SECRETO, "pasarela-planta-01")
}

/// Levanta un senuelo con su cebo y conversa con el por un socket.
///
/// Devuelve lo que el visitante se llevo.
fn visitar(kind: DecoyKind, cebo: &str, guion: &[&[u8]]) -> Vec<u8> {
    let net = DecoyNet::bind(DecoyConfig {
        bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
        services: vec![(kind, 0)],
        speak_timeout: Duration::from_millis(120),
        max_evidence: 1024,
        max_per_poll: 8,
        cebo: cebo.to_owned(),
    });
    let (_, puerto) = net.active()[0];
    let destino = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), puerto);
    let saluda = kind.banner().is_some();
    let guion: Vec<Vec<u8>> = guion.iter().map(|m| m.to_vec()).collect();

    let ladron = std::thread::spawn(move || {
        let Ok(mut s) = TcpStream::connect_timeout(&destino, Duration::from_secs(2)) else {
            return Vec::new();
        };
        let _ = s.set_read_timeout(Some(Duration::from_millis(250)));
        let mut llevado = Vec::new();
        let mut buf = [0u8; 8192];
        if saluda {
            if let Ok(n) = s.read(&mut buf) {
                llevado.extend_from_slice(&buf[..n]);
            }
        }
        for m in guion {
            if s.write_all(&m).is_err() {
                break;
            }
            match s.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => llevado.extend_from_slice(&buf[..n]),
            }
        }
        llevado
    });

    for _ in 0..40 {
        if !net.poll(Duration::from_millis(100), 1).is_empty() {
            break;
        }
    }
    ladron.join().unwrap_or_default()
}

#[test]
fn lo_que_se_lleva_del_senuelo_dice_despues_de_que_senuelo_salio() {
    // **El recorrido entero de la fase.**
    let mut p = plantacion();
    let sembrado = p
        .sembrar_en_senuelo("http", 80, Artefacto::FicheroEnv)
        .expect("se siembra")
        .clone();

    let llevado = visitar(
        DecoyKind::Http,
        &sembrado.texto,
        &[b"GET /.env HTTP/1.1\r\nHost: intranet\r\nUser-Agent: curl/8.4.0\r\n\r\n"],
    );
    let texto = String::from_utf8_lossy(&llevado).to_string();
    assert!(
        texto.contains(&sembrado.marcador.hex()),
        "el visitante no se llevo el token: {texto}"
    );

    // Tres semanas despues: la credencial aparece en un volcado de memoria de una
    // maquina distinta. No se consulta ninguna tabla — el sitio esta dentro.
    let mut volcado = vec![0xAB; 4096];
    volcado.extend_from_slice(texto.as_bytes());
    volcado.extend_from_slice(&[0xCD; 4096]);

    let de_donde = p.de_donde_salio(&volcado).expect("se atribuye");
    assert_eq!(
        de_donde.destino,
        Destino::Senuelo {
            servicio: "http".to_owned(),
            puerto: 80
        }
    );
    assert_eq!(de_donde.host, "pasarela-planta-01");
    println!("\n=== De la siembra al uso ===");
    println!(
        "  reaparecio en un volcado de 8 KiB y salio de: {}",
        de_donde.frase()
    );
}

#[test]
fn dos_senuelos_sembrados_a_la_vez_no_se_confunden_al_volver() {
    // Si los dos entregaran lo mismo, al volver no se sabria por cual entraron —
    // que es justo lo que hace inutil a un senuelo pasada la primera semana.
    let mut p = plantacion();
    let del_web = p
        .sembrar_en_senuelo("http", 80, Artefacto::ClaveDeApi)
        .expect("web")
        .clone();
    let del_redis = p
        .sembrar_en_senuelo("redis", 6379, Artefacto::ClaveDeApi)
        .expect("redis")
        .clone();
    assert_ne!(del_web.texto, del_redis.texto);

    let llevado_web = visitar(
        DecoyKind::Http,
        &del_web.texto,
        &[b"GET /api/v1/config HTTP/1.1\r\nHost: x\r\n\r\n"],
    );
    let llevado_redis = visitar(
        DecoyKind::Redis,
        &del_redis.texto,
        &[b"*2\r\n$3\r\nGET\r\n$10\r\nconfig:api\r\n"],
    );

    let sitio = |bytes: &[u8]| p.de_donde_salio(bytes).map(|a| a.destino.clone());
    assert_eq!(
        sitio(&llevado_web),
        Some(Destino::Senuelo {
            servicio: "http".to_owned(),
            puerto: 80
        })
    );
    assert_eq!(
        sitio(&llevado_redis),
        Some(Destino::Senuelo {
            servicio: "redis".to_owned(),
            puerto: 6379
        })
    );
}

#[test]
fn un_token_sembrado_en_un_fichero_dispara_al_abrirlo_con_su_marcador() {
    // La otra superficie: no todo se siembra en un senuelo de red. Un fichero
    // sembrado dispara al abrirse, y el disparo lleva **su** marcador, no un
    // relleno de ceros que seria igual para todos los senuelos.
    let mut p = plantacion();
    let s = p
        .sembrar(
            Destino::Fichero {
                ruta: "/root/.pgpass".to_owned(),
            },
            Artefacto::PgpassLinea,
        )
        .expect("se siembra")
        .clone();

    let disparos = clasificar(
        &Evento::AperturaFichero {
            lector: "cat".to_owned(),
            ruta: "/root/.pgpass".to_owned(),
        },
        p.registro(),
    );
    assert_eq!(disparos.len(), 1);
    assert_eq!(disparos[0].marcador, s.marcador);
    assert_eq!(disparos[0].token, s.atribucion);
    assert!(matches!(
        disparos[0].como,
        ComoDisparo::FicheroAbierto { .. }
    ));

    // Y un fichero que NO se sembro no dispara: es el otro lado del cero falsos
    // positivos.
    assert!(clasificar(
        &Evento::AperturaFichero {
            lector: "cat".to_owned(),
            ruta: "/etc/hosts".to_owned(),
        },
        p.registro(),
    )
    .is_empty());
}

#[test]
fn el_dns_es_el_unico_que_delata_sin_que_toquen_la_maquina() {
    // Y esa diferencia cambia la respuesta: los demas se disparan con el atacante
    // todavia dentro; este significa que la credencial ya salio de la
    // organizacion, que es cuando hay que notificarlo.
    let mut p = plantacion();
    let s = p
        .sembrar(
            Destino::Dns {
                nombre: "backup.interno.empresa.es".to_owned(),
            },
            Artefacto::NombreDns,
        )
        .expect("se siembra")
        .clone();
    assert!(s.atribucion.destino.implica_que_salio());

    // Una consulta de DNS que llega al servidor autoritativo propio.
    let consulta = format!("QUERY {} IN A desde 203.0.113.45", s.texto);
    let de_donde = p.de_donde_salio(consulta.as_bytes()).expect("se atribuye");
    assert!(de_donde.destino.implica_que_salio());
    println!("\n=== El token que delata desde fuera ===");
    println!("  {}", de_donde.frase());
}

#[test]
fn una_fila_de_una_tabla_distingue_que_fila_se_llevaron() {
    // Un `SELECT *` se lleva la tabla entera; saber QUE filas reaparecen dice si
    // se llevaron la tabla o solo consultaron una.
    let mut p = plantacion();
    let mut filas = Vec::new();
    for n in [7u64, 42, 991] {
        filas.push(
            p.sembrar(
                Destino::Fila {
                    base: "crm".to_owned(),
                    tabla: "clientes".to_owned(),
                    columna: "notas".to_owned(),
                    fila: n,
                },
                Artefacto::FilaDeTabla,
            )
            .expect("cabe")
            .clone(),
        );
    }

    // Reaparece una sola: no se llevaron la tabla entera.
    let d = p
        .de_donde_salio(filas[1].texto.as_bytes())
        .expect("se atribuye");
    assert_eq!(
        d.destino,
        Destino::Fila {
            base: "crm".to_owned(),
            tabla: "clientes".to_owned(),
            columna: "notas".to_owned(),
            fila: 42
        }
    );
    // Y las otras dos no se dan por tocadas.
    for otra in [&filas[0], &filas[2]] {
        assert_ne!(d.destino, otra.atribucion.destino);
    }
}

#[test]
fn un_marcador_de_otra_flota_no_se_atribuye_a_esta() {
    // Sin esto, quien conozca el formato podria sembrar marcadores propios y
    // mandarnos a perseguir fantasmas. El marcador va firmado con el secreto de
    // flota y no se puede fabricar sin el.
    let mut mia = plantacion();
    mia.sembrar_en_senuelo("ssh", 22, Artefacto::ClaveSshAutorizada);

    let mut ajena = Plantacion::nueva([0x01; 32], "pasarela-planta-01");
    let suyo = ajena
        .sembrar_en_senuelo("ssh", 22, Artefacto::ClaveSshAutorizada)
        .expect("se siembra")
        .clone();

    assert!(
        mia.de_donde_salio(suyo.texto.as_bytes()).is_none(),
        "un marcador ajeno se atribuyo como propio"
    );
}

#[test]
fn la_atribucion_de_memoria_no_se_confunde_con_la_de_fichero() {
    // El mismo texto sembrado en dos clases de destino distintas tiene que dar
    // dos marcadores distintos: si no, «lo leyeron de la memoria de sshd» y «lo
    // leyeron del disco» serian el mismo hallazgo, y son dos incidentes de
    // gravedad muy distinta.
    let mut p = plantacion();
    let en_memoria = p
        .sembrar(
            Destino::Memoria {
                proceso: "sshd".to_owned(),
            },
            Artefacto::PgpassLinea,
        )
        .expect("memoria")
        .clone();
    let en_disco = p
        .sembrar(
            Destino::Fichero {
                ruta: "sshd".to_owned(),
            },
            Artefacto::PgpassLinea,
        )
        .expect("fichero")
        .clone();

    assert_ne!(en_memoria.marcador, en_disco.marcador);

    let disparos = clasificar(
        &Evento::LecturaMemoria {
            lector: "volcador".to_owned(),
            contenido: en_memoria.texto.clone().into_bytes(),
        },
        p.registro(),
    );
    assert_eq!(disparos.len(), 1);
    assert_eq!(disparos[0].token.destino, en_memoria.atribucion.destino);
    assert!(matches!(
        disparos[0].como,
        ComoDisparo::LeidoDeMemoria { .. }
    ));
}

#[test]
fn la_alerta_se_lee_sin_descifrarla() {
    // Una alerta que hay que interpretar con el manual delante no se lee a las
    // tres de la manana, que es cuando se leen.
    let a = Atribucion {
        host: "pasarela-planta-01".to_owned(),
        destino: Destino::Senuelo {
            servicio: "modbus".to_owned(),
            puerto: 502,
        },
        token_id: 3,
    };
    let f = a.frase();
    assert!(f.contains("pasarela-planta-01"), "{f}");
    assert!(f.contains("modbus"), "{f}");
    assert!(f.contains("502"), "{f}");
}
