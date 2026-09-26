//! El senuelo usado contra su dueno.
//!
//! # Las tres formas de volver una trampa contra quien la puso
//!
//! Un senuelo es una capacidad nueva, y como toda capacidad nueva de un producto
//! de seguridad, es tambien una capacidad nueva para quien lo comprometa. Aqui se
//! intentan las tres que habilita, y **el intento tiene que fallar donde se
//! intenta**, no mas tarde y no por casualidad:
//!
//!   1. **Como amplificador.** Un servicio que contesta mas de lo que le
//!      preguntan, sobre un transporte donde el origen puede falsificarse, manda
//!      trafico a una victima que no pidio nada. La direccion que aparece en los
//!      registros de esa victima es la nuestra. BACnet es el caso real: su
//!      `Who-Is` mide ocho bytes y su `I-Am` bastante mas.
//!   2. **Como forma de agotar el agente.** Quien genere conexiones decide cuanta
//!      CPU y cuanta memoria gasta la maquina que le esta vigilando.
//!   3. **Como via de entrada.** Es la que hunde a los tarros de miel de alta
//!      interaccion clasicos: dan un interprete de ordenes de verdad sobre un
//!      sistema de ficheros de verdad, y un fallo de la carcel deja al atacante
//!      dentro de una maquina que existe.
//!
//! La tercera aqui no se para con una carcel: **no hay nada que encarcelar**. Los
//! dialogos son maquinas de estados que transforman bytes en bytes, y esta prueba
//! lo comprueba por AUSENCIA, que es la unica garantia que no depende de que el
//! codigo de comprobacion este bien. Ver la seccion correspondiente.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use aegis_deception::decoy::{DecoyConfig, DecoyKind, DecoyNet, CATALOGO};
use aegis_deception::dialogo::{Conversacion, Final, MAX_ESTADO, MAX_TURNOS};
use aegis_deception::limitador::{
    Limitador, Recorte, Transporte, BYTES_POR_SEGUNDO, MENSAJES_POR_SEGUNDO_Y_ORIGEN,
    ORIGENES_RECORDADOS,
};

/// Mensajes hostiles con los que se golpea a todos los dialogos.
///
/// No son entradas al azar: son las formas que rompen un analizador escrito con
/// prisa —longitudes imposibles, cabeceras a medias, campos que apuntan fuera— y
/// las que un atacante manda cuando sospecha que hay un senuelo delante.
fn hostiles() -> Vec<Vec<u8>> {
    let mut v = vec![
        Vec::new(),
        vec![0x00],
        vec![0xff; 1],
        vec![0xff; 65535],
        vec![0x00; 65535],
        b"A".repeat(100_000),
        b"\x00\x00\x00\x00".to_vec(),
        // Longitudes que dicen ser enormes.
        vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        // Un principio creible de cada familia, cortado justo despues.
        b"SSH-2.0-".to_vec(),
        b"RFB 003.".to_vec(),
        b"GET ".to_vec(),
        b"*1\r\n$99999999\r\n".to_vec(),
        vec![0x81, 0x0b, 0xff, 0xff],
        vec![0x03, 0x00, 0xff, 0xff, 0x11, 0xe0],
        vec![0x05, 0x64, 0xff, 0xff],
        vec![22, 3, 1, 0xff, 0xff],
        vec![0x10, 0x01, 0xff, 0xff],
        vec![0x12, 0x01, 0xff, 0xff],
    ];
    // Y texto con caracteres multibyte partidos, que es donde revienta un
    // recortado ingenuo.
    v.push("n".repeat(500).into_bytes());
    let mut partido = "n".repeat(10).into_bytes();
    partido.truncate(15);
    v.push(partido);

    // Mensajes VALIDOS de cada protocolo. Sin ellos, el barrido solo mide lo que
    // pasa cuando el senuelo rechaza la entrada —que es contestar poco o nada— y
    // daria por buena una amplificacion que solo ocurre en el camino bueno. El
    // `Who-Is` de BACnet es justo ese caso: es el mensaje corto que devuelve un
    // `I-Am` largo, y es el unico que de verdad prueba la cota de UDP.
    v.push(vec![0x81, 0x0b, 0x00, 0x08, 0x01, 0x20, 0x10, 0x08]); // BACnet Who-Is
    v.push(vec![0x81, 0x0b, 0x00, 0x06, 0x01, 0x20]); // BACnet minimo
    v.push(b"SSH-2.0-OpenSSH_9.0\r\n".to_vec());
    v.push(b"RFB 003.008\n".to_vec());
    v.push(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".to_vec());
    v.push(b"*1\r\n$4\r\nINFO\r\n".to_vec());
    v.push(b"USER a\r\n".to_vec());
    v.push(vec![
        0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0a,
    ]); // Modbus leer diez registros
    v.push(vec![
        0x05, 0x64, 0x0b, 0xc4, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0xc0, 0xc1, 0x01,
    ]); // DNP3 leer
    v.push(vec![
        0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00,
    ]); // S7 conexion COTP
    v
}

/// Como se escribe un factor de amplificacion, incluido el caso sin division.
///
/// Contestar a un mensaje vacio no tiene factor: es infinito. Escribirlo como el
/// numero que sale de `u64::MAX` daria una cifra absurda en una tabla que se
/// publica, y una tabla con una cifra absurda no se lee.
fn factor(n: u64) -> String {
    if n == u64::MAX {
        "infinito".to_owned()
    } else {
        format!("x{}.{:02}", n / 100, n % 100)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. El senuelo como amplificador
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ningun_senuelo_amplifica_donde_el_origen_puede_ser_falso() {
    // **La cifra de la invariante 10 aplicada a esta fase.** Se golpea cada
    // dialogo con todo lo hostil y se mide cuanto devuelve por cada byte que
    // recibe. En UDP el factor tiene que quedar en uno o por debajo, pase lo que
    // pase: si sube, el senuelo es un arma apuntando a un tercero.
    //
    // Lo que se mide es el PEOR mensaje, no la media de todos. Un factor medio se
    // hunde solo con mandar basura grande que no se contesta —cien kilobytes de
    // ceros bajan cualquier media a cero— y taparia justo el mensaje que si
    // amplifica, que es el unico que el atacante va a repetir. La media aqui seria
    // una cifra tranquilizadora y falsa.
    let mut peor_udp = (0u64, "", Vec::new());
    let mut peor_tcp = (0u64, "", Vec::new());
    let mut lineas = Vec::new();

    for kind in CATALOGO {
        let mut c = Conversacion::nueva(kind.dialogo(String::new()));
        let saludo = c.saludo();
        // El saludo sale sin que nadie pregunte: en UDP no puede existir.
        if kind.transporte() == Transporte::Udp {
            assert!(
                saludo.is_empty(),
                "el senuelo de {} saluda por UDP: son bytes a quien no los pidio",
                kind.as_str()
            );
        }

        let mut peor = 0u64;
        let mut peor_mensaje = Vec::new();
        let mut lim = Limitador::nuevo();
        for (n, h) in hostiles().into_iter().enumerate() {
            let mut c = Conversacion::nueva(kind.dialogo(String::new()));
            // Cada mensaje en su propio segundo y con su propio origen: lo que se
            // mide aqui es la amplificacion, no el ritmo, y mezclarlas daria un
            // aprobado que en realidad viene del cubo de fichas.
            let (salida, _) = c.turno(&mut lim, n as u128, n as u64 * 1_000_000_000, &h);
            let factor = if h.is_empty() {
                // Contestar a un mensaje vacio es amplificacion infinita.
                if salida.is_empty() {
                    0
                } else {
                    u64::MAX
                }
            } else {
                salida.len() as u64 * 100 / h.len() as u64
            };
            if factor > peor {
                peor = factor;
                peor_mensaje = h.clone();
            }
        }

        lineas.push(format!(
            "  {:10} {:>4}  peor {} (con {} bytes de entrada)",
            kind.as_str(),
            kind.transporte().nombre(),
            factor(peor),
            peor_mensaje.len()
        ));
        let destino = if kind.transporte() == Transporte::Udp {
            &mut peor_udp
        } else {
            &mut peor_tcp
        };
        if peor > destino.0 {
            *destino = (peor, kind.as_str(), peor_mensaje);
        }
    }

    println!("\n=== Factor de amplificacion por senuelo (el PEOR mensaje de cada uno) ===");
    for l in lineas {
        println!("{l}");
    }
    println!("  peor en UDP: {} con {}", peor_udp.1, factor(peor_udp.0));
    println!(
        "  peor en TCP: {} con {} (aqui el origen lo verifica el saludo de tres vias,\n\
         \x20              asi que la respuesta no puede acabar en una victima ajena)",
        peor_tcp.1,
        factor(peor_tcp.0)
    );

    assert!(
        peor_udp.0 <= 100,
        "el senuelo de {} amplifica {} con un mensaje de {} bytes: \
         es un arma apuntando a un tercero",
        peor_udp.1,
        factor(peor_udp.0),
        peor_udp.2.len()
    );
    // Y que el barrido haya llegado de verdad al camino bueno del senuelo de UDP:
    // una prueba que solo mida rechazos no prueba la cota.
    assert!(
        peor_udp.0 > 0,
        "el barrido no llego a hacer contestar al senuelo de UDP: no se midio nada"
    );
}

#[test]
fn el_senuelo_de_bacnet_no_se_puede_usar_para_reflejar() {
    // El caso concreto y documentado: `Who-Is` de ocho bytes, `I-Am` mayor.
    let who_is = vec![0x81, 0x0b, 0x00, 0x08, 0x01, 0x20, 0x10, 0x08];
    let mut lim = Limitador::nuevo();
    let mut c = Conversacion::nueva(DecoyKind::Bacnet.dialogo(String::new()));

    assert!(
        c.saludo().is_empty(),
        "un servicio de UDP que saluda manda bytes a quien no los pidio"
    );
    let (salida, motivo) = c.turno(&mut lim, 0x0a00_0001, 0, &who_is);
    assert_eq!(motivo, Recorte::PorAmplificacion);
    assert!(salida.len() <= who_is.len());

    // Y repetido mil veces, que es como se usa un amplificador de verdad. Cada
    // segundo cuenta aparte para no chocar con el ritmo por origen, que es otra
    // proteccion y se mide en su propia prueba.
    for i in 0..1000u64 {
        let mut c = Conversacion::nueva(DecoyKind::Bacnet.dialogo(String::new()));
        let (s, _) = c.turno(&mut lim, 0x0a00_0001, i * 1_000_000_000, &who_is);
        assert!(s.len() <= who_is.len());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. El senuelo como forma de agotar el agente
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn quien_habla_con_el_senuelo_no_decide_cuanta_memoria_gasta() {
    // Se le echa a cada dialogo lo mas grande y lo mas repetido que se puede, y se
    // le pregunta por su estado. Un dialogo que guarde lo que le manden es quien
    // habla eligiendo la memoria del agente.
    for kind in CATALOGO {
        let mut lim = Limitador::nuevo();
        let mut c = Conversacion::nueva(kind.dialogo(String::new()));
        c.saludo();
        for i in 0..50u64 {
            let mut grande = b"USER ".to_vec();
            grande.extend_from_slice(&vec![b'A'; 60_000]);
            c.turno(&mut lim, 1, i * 1_000_000_000, &grande);
        }
        assert!(
            c.dialogo().estado() <= MAX_ESTADO,
            "el senuelo de {} guarda {} bytes, y el techo es {MAX_ESTADO}",
            kind.as_str(),
            c.dialogo().estado()
        );
    }
}

#[test]
fn una_conversacion_no_puede_durar_para_siempre() {
    for kind in CATALOGO {
        let mut lim = Limitador::nuevo();
        let mut c = Conversacion::nueva(kind.dialogo(String::new()));
        c.saludo();
        for i in 0..1000u64 {
            c.turno(&mut lim, 1, i * 1_000_000_000, b"sigue hablando");
        }
        assert!(
            c.turnos() <= MAX_TURNOS,
            "{}: {}",
            kind.as_str(),
            c.turnos()
        );
        assert_ne!(c.como_acabo(), Final::Abierta, "{}", kind.as_str());
    }
}

#[test]
fn el_que_inunda_se_limita_a_si_mismo_y_no_al_vecino() {
    // Igual que el indice de la FASE 90: quien grita se queda sin fichas, y la
    // maquina callada sigue teniendo servicio. Si fuera al reves, inundar el
    // senuelo dejaria ciego al sensor para todos los demas.
    let mut lim = Limitador::nuevo();
    let peticion = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    let mut atendidas_del_ruidoso = 0;
    // Cada vuelta abre una CONEXION NUEVA, que es como se salta un limite mal
    // puesto: si el cubo viviera en la conversacion, aqui se atenderian las
    // ciento cincuenta.
    for _ in 0..(MENSAJES_POR_SEGUNDO_Y_ORIGEN * 3) {
        let mut c = Conversacion::nueva(DecoyKind::Http.dialogo(String::new()));
        let (s, _) = c.turno(&mut lim, 0x0a00_0009, 0, peticion);
        if !s.is_empty() {
            atendidas_del_ruidoso += 1;
        }
    }
    assert_eq!(
        atendidas_del_ruidoso, MENSAJES_POR_SEGUNDO_Y_ORIGEN as usize,
        "el ruidoso no se limito: abrir conexiones nuevas se salta el cubo"
    );

    let mut vecino = Conversacion::nueva(DecoyKind::Http.dialogo(String::new()));
    let (s, motivo) = vecino.turno(&mut lim, 0x0a00_000a, 0, peticion);
    assert_eq!(motivo, Recorte::Nada, "el vecino callado perdio servicio");
    assert!(!s.is_empty());
}

#[test]
fn el_recuerdo_de_origenes_tiene_techo() {
    // La estructura que crece con el numero de direcciones que escriba el
    // atacante. Sin techo, mil millones de origenes falsos son mil millones de
    // cubos de fichas.
    let mut lim = Limitador::nuevo();
    let peticion = vec![
        0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01,
    ];
    for o in 0..(ORIGENES_RECORDADOS as u128 * 2) {
        let mut c = Conversacion::nueva(DecoyKind::Modbus.dialogo(String::new()));
        let _ = c.turno(&mut lim, o, 0, &peticion);
        assert!(lim.origenes() <= ORIGENES_RECORDADOS);
    }
    // El cupo total tambien: lo emitido en un segundo esta acotado.
    assert!(
        lim.cuentas().bytes_emitidos <= BYTES_POR_SEGUNDO,
        "{}",
        lim.cuentas().frase()
    );
}

#[test]
fn ningun_dialogo_entra_en_panico_con_entradas_hostiles() {
    // Un panico en un senuelo es una caida del agente provocada desde la red, que
    // es el mejor resultado posible para el atacante: apaga la defensa mandando
    // un paquete raro.
    let mut golpes = 0u64;
    for kind in CATALOGO {
        for h in hostiles() {
            // Enteros y recortados por todos los puntos: los desbordamientos por
            // un byte viven justo en los limites.
            let mut lim = Limitador::nuevo();
            let mut c = Conversacion::nueva(kind.dialogo(String::new()));
            c.saludo();
            c.turno(&mut lim, 1, 0, &h);
            golpes += 1;
            let hasta = h.len().min(80);
            for n in 0..hasta {
                let mut c = Conversacion::nueva(kind.dialogo(String::new()));
                c.turno(&mut lim, 1, 0, &h[..n]);
                golpes += 1;
            }
        }
    }
    println!("\n=== Autoataque a los dialogos ===");
    println!(
        "  {golpes} entradas hostiles contra {} senuelos, sin panico",
        CATALOGO.len()
    );
    assert!(golpes > 5_000);
}

#[test]
fn el_coste_de_atender_no_crece_con_lo_hostil_que_sea_la_entrada() {
    // Un senuelo que tarde mas cuanto mas raro sea lo que le mandan es un
    // amplificador de CPU: el atacante elige el relleno y multiplica el coste. Es
    // el mismo fallo que tenia el redactor de la FASE 90 y se mide igual.
    let normal = b"GET /index.html HTTP/1.1\r\nHost: intranet\r\n\r\n".to_vec();
    let hostil = {
        let mut v = b"GET /".to_vec();
        v.extend_from_slice(&vec![b'A'; 4000]);
        v.extend_from_slice(b" HTTP/1.1\r\n");
        for _ in 0..60 {
            v.extend_from_slice(b"X-Relleno: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
        }
        v.extend_from_slice(b"\r\n");
        v
    };

    let medir = |entrada: &[u8]| -> Duration {
        let mut lim = Limitador::nuevo();
        let empezo = Instant::now();
        for i in 0..2000u64 {
            let mut c = Conversacion::nueva(DecoyKind::Http.dialogo(String::new()));
            c.turno(&mut lim, i as u128, 0, entrada);
        }
        empezo.elapsed()
    };

    let t_normal = medir(&normal);
    let t_hostil = medir(&hostil);
    let por_byte_normal = t_normal.as_nanos() / normal.len() as u128;
    let por_byte_hostil = t_hostil.as_nanos() / hostil.len() as u128;

    println!("\n=== Coste de atender, normal contra hostil ===");
    println!(
        "  normal: {} bytes, {t_normal:?} ({por_byte_normal} ns/byte)",
        normal.len()
    );
    println!(
        "  hostil: {} bytes, {t_hostil:?} ({por_byte_hostil} ns/byte)",
        hostil.len()
    );

    assert!(
        por_byte_hostil <= por_byte_normal.max(1) * 4,
        "atender lo hostil cuesta {por_byte_hostil} ns/byte contra {por_byte_normal}: \
         el atacante multiplica el coste eligiendo el relleno"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. El senuelo como via de entrada
// ─────────────────────────────────────────────────────────────────────────────

/// Lo que un dialogo NO puede contener, comprobado sobre el codigo fuente.
///
/// # Por que se comprueba por ausencia y no probando que no pasa
///
/// Porque probar que un interprete de ordenes confinado no se escapa exige
/// anticipar todas las formas de escaparse, y la que hunde el producto es
/// siempre la que no se anticipo. Comprobar que **no hay interprete** no depende
/// de anticipar nada: si `Command` no aparece en el codigo, no hay proceso hijo
/// que confinar, lo intente quien lo intente.
///
/// Es la invariante 12 del producto —la ausencia es la frontera— aplicada aqui.
#[test]
fn los_dialogos_no_pueden_ejecutar_ni_escribir_nada() {
    let dir = std::path::Path::new(&raiz_crate()).join("src/dialogos");
    let prohibido = [
        "Command",
        "std::process",
        "std::fs",
        "File::",
        "TcpStream",
        "UdpSocket",
        "std::net",
        "unsafe",
        "SystemTime::now",
        "Instant::now",
    ];

    let mut revisados = 0;
    let mut hallazgos = Vec::new();
    let entradas = std::fs::read_dir(&dir).expect("el directorio de dialogos existe");
    for e in entradas {
        let ruta = e.expect("entrada").path();
        if ruta.extension().and_then(|x| x.to_str()) != Some("rs") {
            continue;
        }
        let texto = std::fs::read_to_string(&ruta).expect("se lee");
        revisados += 1;
        for (n, linea) in texto.lines().enumerate() {
            let limpia = linea.trim_start();
            // Los comentarios hablan de lo que NO se hace, y un filtro que no los
            // distinga convierte una explicacion honesta en un fallo inventado.
            if limpia.starts_with("//") {
                continue;
            }
            for p in prohibido {
                if linea.contains(p) {
                    hallazgos.push(format!(
                        "{}:{}: {}",
                        ruta.file_name().unwrap().to_string_lossy(),
                        n + 1,
                        limpia
                    ));
                }
            }
        }
    }

    println!("\n=== Lo que los dialogos no pueden hacer ===");
    println!("  {revisados} ficheros de dialogo revisados");
    println!("  sin ejecucion, sin ficheros, sin sockets, sin reloj y sin unsafe");
    assert!(revisados >= 4, "faltan ficheros de dialogo por revisar");
    assert!(
        hallazgos.is_empty(),
        "un dialogo ha ganado una capacidad que no debe tener:\n{}",
        hallazgos.join("\n")
    );
}

#[test]
fn el_senuelo_no_abre_puertos_que_no_le_pidieron() {
    // Un senuelo que abriera un canal de datos porque el visitante lo pide —que es
    // lo que hace un FTP de verdad con `PASV`— le estaria dejando elegir recursos
    // del agente. Aqui se contesta al `PASV` sin abrir nada.
    let mut lim = Limitador::nuevo();
    let mut c = Conversacion::nueva(DecoyKind::Ftp.dialogo(String::new()));
    c.saludo();
    let (salida, _) = c.turno(&mut lim, 1, 0, b"PASV\r\n");
    let texto = String::from_utf8_lossy(&salida);
    assert!(
        texto.starts_with("425"),
        "el senuelo contesto algo que implica un puerto abierto: {texto}"
    );
    assert!(
        !texto.contains('(') || !texto.contains(','),
        "la respuesta trae una direccion y un puerto: {texto}"
    );
}

#[test]
fn un_ataque_por_socket_de_verdad_no_tumba_la_red_de_senuelos() {
    // Lo mismo que arriba, pero por la red: cien conexiones seguidas con basura,
    // contra un senuelo levantado de verdad. La red tiene que seguir en pie y
    // seguir contando.
    let net = DecoyNet::bind(DecoyConfig {
        bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
        services: vec![(DecoyKind::Http, 0)],
        speak_timeout: Duration::from_millis(30),
        max_evidence: 256,
        max_per_poll: 64,
        cebo: String::new(),
    });
    let (_, puerto) = net.active()[0];
    let destino = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), puerto);

    let atacante = std::thread::spawn(move || {
        for i in 0..100u32 {
            if let Ok(mut s) = TcpStream::connect_timeout(&destino, Duration::from_millis(500)) {
                let _ = s.write_all(&vec![0xff; (i as usize % 7) * 1000 + 1]);
                let mut b = [0u8; 256];
                let _ = s.set_read_timeout(Some(Duration::from_millis(20)));
                let _ = s.read(&mut b);
            }
        }
    });

    let mut vistas = 0usize;
    for _ in 0..200 {
        vistas += net.poll(Duration::from_millis(20), 1).len();
        if atacante.is_finished() && vistas > 0 {
            break;
        }
    }
    let _ = atacante.join();
    // Se sigue atendiendo despues del ataque, que es lo que hay que comprobar.
    vistas += net.poll(Duration::from_millis(50), 2).len();

    println!("\n=== Inundacion por socket ===");
    println!("  {vistas} conexiones hostiles atendidas; la red sigue en pie");
    assert!(vistas > 0, "la red dejo de contar");
    assert!(!net.is_empty(), "la red se cayo");
}

/// La raiz del crate, leida al EJECUTAR y no congelada al compilar.
///
/// Con `env!("CARGO_MANIFEST_DIR")` la ruta quedaba fijada en el binario, y
/// Cargo no lo recompila al mover el repositorio de carpeta (el hash de un
/// paquete de ruta es relativo al workspace): la prueba seguia buscando sus
/// ficheros en la ruta vieja y fallaba diciendo que no existian. Cargo define la
/// variable al lanzar pruebas y ejemplos; el valor de compilacion queda solo para
/// quien ejecute el binario a mano.
fn raiz_crate() -> String {
    std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").to_string())
}
