//! La red falsa: dejarle creer al malware que llego a su C2.
//!
//! # Por que no basta con cortar la red
//!
//! Lo mas contenido seria no darle red ninguna. El problema es que entonces el
//! informe casi siempre dice lo mismo: la muestra resuelve su dominio, falla,
//! y **sale sin hacer nada**. Eso no es «la muestra es inofensiva», es «no le
//! dejamos empezar», y confundir las dos cosas es la forma mas comun de que un
//! sandbox mienta sin querer.
//!
//! Asi que se le contesta. A todo. Un DNS que resuelve cualquier nombre a una
//! direccion de sumidero y un HTTP que devuelve 200 a cualquier peticion bastan
//! para que la mayoria de las familias pasen de la fase de contacto a la fase en
//! la que hacen lo que vinieron a hacer, que es justo lo que se quiere ver.
//!
//! # Lo que se gana ademas
//!
//! El nombre que la muestra pregunta **es** el indicador mas valioso del informe:
//! es el dominio de su C2. Un sandbox sin DNS falso no lo consigue nunca, porque
//! la resolucion falla antes de llegar al cable.
//!
//! # La direccion de sumidero
//!
//! `203.0.113.x`, de TEST-NET-3 (RFC 5737). No es una eleccion estetica: si un
//! dia una detonacion se escapara de su frontera y esa direccion llegara a una
//! red de verdad, no lleva a ningun sitio que exista. Una direccion privada
//! cualquiera podria ser la de alguien.
//!
//! # Lo que el malware puede notar, declarado
//!
//! Esto es una red falsa y un malware que mire lo sabe: el certificado de TLS no
//! valida contra nada, las respuestas de HTTP son genericas, y todos los nombres
//! resuelven. Se cuenta entero en [`crate::antivm`]; aqui solo se hace notar que
//! el objetivo no es enganar a un adversario que examina, es no bloquear al que
//! solo comprueba que hay linea.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Red de sumidero, TEST-NET-3 (RFC 5737).
pub const SUMIDERO: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 13);

/// Tiempo de vida que se da en las respuestas de DNS, en segundos.
///
/// Corto a proposito: con un TTL largo, una muestra que resuelve una vez y cachea
/// no vuelve a preguntar, y se pierde la secuencia de dominios que consulta —que
/// en un algoritmo de generacion de dominios es el dato entero.
pub const TTL: u32 = 1;

/// Consultas maximas que se atienden antes de dejar de responder.
///
/// Una muestra que consulta en bucle no puede tener al anfitrion respondiendole
/// para siempre ni llenar su memoria de nombres.
pub const MAX_CONSULTAS: usize = 10_000;

/// Bytes maximos que se leen de una peticion HTTP.
pub const MAX_PETICION: usize = 16 * 1024;

/// Lo que la muestra pregunto o pidio.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Observado {
    /// Nombres consultados por DNS, con cuantas veces cada uno.
    ///
    /// Es el indicador mas valioso del informe: el dominio del C2.
    pub nombres: BTreeMap<String, u64>,
    /// Peticiones HTTP vistas.
    pub peticiones: Vec<PeticionHttp>,
    /// Consultas de DNS que no se atendieron por llegar al tope.
    pub consultas_descartadas: u64,
}

impl Observado {
    /// Si no se vio nada.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nombres.is_empty() && self.peticiones.is_empty()
    }

    /// Nombres consultados, ordenados.
    #[must_use]
    pub fn dominios(&self) -> Vec<&str> {
        self.nombres.keys().map(String::as_str).collect()
    }
}

/// Una peticion HTTP que la muestra hizo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeticionHttp {
    /// Metodo.
    pub metodo: String,
    /// Ruta pedida.
    pub ruta: String,
    /// Cabecera `Host`, si la habia.
    pub host: String,
    /// Cabecera `User-Agent`, si la habia.
    ///
    /// Muchas familias llevan una cadena fija y rara, y es una firma en si misma.
    pub agente: String,
    /// Bytes de cuerpo.
    pub cuerpo: u64,
}

/// Los servicios falsos en marcha.
#[derive(Debug)]
pub struct RedSimulada {
    observado: Arc<Mutex<Observado>>,
    parar: Arc<AtomicBool>,
    /// Puerto de DNS, por si se eligio automaticamente.
    pub puerto_dns: u16,
    /// Puerto de HTTP.
    pub puerto_http: u16,
    hilos: Vec<std::thread::JoinHandle<()>>,
}

impl RedSimulada {
    /// Levanta los servicios falsos en `direccion`, con puertos automaticos.
    ///
    /// # Errores
    /// El error de E/S si no se pueden abrir los sockets.
    pub fn levantar(direccion: &str) -> Result<RedSimulada, std::io::Error> {
        let observado = Arc::new(Mutex::new(Observado::default()));
        let parar = Arc::new(AtomicBool::new(false));

        let udp = UdpSocket::bind(format!("{direccion}:0"))?;
        udp.set_read_timeout(Some(Duration::from_millis(100)))?;
        let puerto_dns = udp.local_addr()?.port();

        let tcp = TcpListener::bind(format!("{direccion}:0"))?;
        tcp.set_nonblocking(true)?;
        let puerto_http = tcp.local_addr()?.port();

        let hilos = vec![
            hilo_dns(udp, Arc::clone(&observado), Arc::clone(&parar)),
            hilo_http(tcp, Arc::clone(&observado), Arc::clone(&parar)),
        ];

        Ok(RedSimulada {
            observado,
            parar,
            puerto_dns,
            puerto_http,
            hilos,
        })
    }

    /// Lo observado hasta ahora.
    #[must_use]
    pub fn observado(&self) -> Observado {
        self.observado.lock().map(|g| g.clone()).unwrap_or_default()
    }

    /// Para los servicios y entrega lo observado.
    #[must_use]
    pub fn parar(mut self) -> Observado {
        self.parar.store(true, Ordering::Relaxed);
        for h in self.hilos.drain(..) {
            let _ = h.join();
        }
        self.observado.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

impl Drop for RedSimulada {
    fn drop(&mut self) {
        // Los hilos tienen que morir aunque nadie llame a `parar`: un servicio
        // falso que sobrevive a su detonacion sigue escuchando en el anfitrion,
        // y eso es una superficie abierta que nadie sabe que tiene.
        self.parar.store(true, Ordering::Relaxed);
        for h in self.hilos.drain(..) {
            let _ = h.join();
        }
    }
}

fn hilo_dns(
    socket: UdpSocket,
    observado: Arc<Mutex<Observado>>,
    parar: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut bufer = [0u8; 512];
        while !parar.load(Ordering::Relaxed) {
            let (n, de) = match socket.recv_from(&mut bufer) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let Some((nombre, respuesta)) = responder_dns(&bufer[..n]) else {
                continue;
            };
            if let Ok(mut o) = observado.lock() {
                if o.nombres.len() >= MAX_CONSULTAS {
                    o.consultas_descartadas += 1;
                    continue;
                }
                *o.nombres.entry(nombre).or_insert(0) += 1;
            }
            let _ = socket.send_to(&respuesta, de);
        }
    })
}

/// Construye la respuesta a una consulta de DNS, y saca el nombre preguntado.
///
/// Devuelve `None` si lo que llego no es una consulta que se pueda entender: el
/// paquete lo escribe la muestra, asi que puede ser cualquier cosa.
#[must_use]
pub fn responder_dns(consulta: &[u8]) -> Option<(String, Vec<u8>)> {
    // Cabecera: id(2) banderas(2) qd(2) an(2) ns(2) ar(2)
    if consulta.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([consulta[4], consulta[5]]);
    if qdcount == 0 {
        return None;
    }

    // Las etiquetas del nombre. El bucle tiene tope porque el paquete lo escribe
    // la muestra: sin el, un nombre construido a mano puede dejar al anfitrion
    // dando vueltas.
    let mut pos = 12usize;
    let mut etiquetas: Vec<String> = Vec::new();
    for _ in 0..128 {
        if pos >= consulta.len() {
            return None;
        }
        let largo = consulta[pos] as usize;
        if largo == 0 {
            pos += 1;
            break;
        }
        // En una CONSULTA no hay punteros de compresion. Uno aqui solo puede ser
        // un intento de confundir al analizador, asi que se rechaza el paquete
        // en vez de seguirlo.
        if largo & 0xC0 != 0 {
            return None;
        }
        pos += 1;
        if pos + largo > consulta.len() {
            return None;
        }
        etiquetas.push(
            String::from_utf8_lossy(&consulta[pos..pos + largo])
                .chars()
                // Un nombre puede traer bytes que no son texto; se limpian para
                // que el informe no acabe con caracteres de control dentro.
                .filter(|c| !c.is_control())
                .collect(),
        );
        pos += largo;
    }
    if etiquetas.is_empty() {
        return None;
    }
    if pos + 4 > consulta.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([consulta[pos], consulta[pos + 1]]);
    let fin_pregunta = pos + 4;
    let nombre = etiquetas.join(".");

    let mut r = Vec::with_capacity(fin_pregunta + 16);
    r.extend_from_slice(&consulta[0..2]); // mismo identificador
                                          // Respuesta, recursion disponible, sin error.
    r.extend_from_slice(&0x8180u16.to_be_bytes());
    r.extend_from_slice(&1u16.to_be_bytes()); // qd
                                              // Solo se contesta con una direccion a las preguntas de tipo A. A las demas
                                              // se responde sin respuestas, que es lo que haria un resolutor de verdad, en
                                              // vez de inventarse un registro que la muestra podria usar para detectarnos.
    let responde_a = qtype == 1;
    r.extend_from_slice(&u16::from(responde_a).to_be_bytes()); // an
    r.extend_from_slice(&0u16.to_be_bytes()); // ns
    r.extend_from_slice(&0u16.to_be_bytes()); // ar
    r.extend_from_slice(&consulta[12..fin_pregunta]); // la pregunta, tal cual

    if responde_a {
        r.extend_from_slice(&0xC00Cu16.to_be_bytes()); // puntero al nombre
        r.extend_from_slice(&1u16.to_be_bytes()); // tipo A
        r.extend_from_slice(&1u16.to_be_bytes()); // clase IN
        r.extend_from_slice(&TTL.to_be_bytes());
        r.extend_from_slice(&4u16.to_be_bytes()); // largo
        r.extend_from_slice(&SUMIDERO.octets());
    }
    Some((nombre, r))
}

fn hilo_http(
    escucha: TcpListener,
    observado: Arc<Mutex<Observado>>,
    parar: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        while !parar.load(Ordering::Relaxed) {
            let mut flujo = match escucha.accept() {
                Ok((f, _)) => f,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(_) => continue,
            };
            let _ = flujo.set_read_timeout(Some(Duration::from_millis(500)));

            let mut bruto = Vec::new();
            let mut trozo = [0u8; 4096];
            while bruto.len() < MAX_PETICION {
                match flujo.read(&mut trozo) {
                    Ok(0) => break,
                    Ok(n) => {
                        bruto.extend_from_slice(&trozo[..n]);
                        // Se corta en el fin de cabeceras: esperar a que el
                        // cliente cierre dejaria al hilo colgado contra una
                        // muestra que abre la conexion y no la suelta.
                        if bruto.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }

            if let Some(p) = analizar_http(&bruto) {
                if let Ok(mut o) = observado.lock() {
                    if o.peticiones.len() < MAX_CONSULTAS {
                        o.peticiones.push(p);
                    }
                }
            }

            // Una respuesta minima y valida. Ni cabeceras de servidor ni nada que
            // identifique al sandbox: cada cadena de mas es una cadena que una
            // muestra puede buscar para saber donde esta.
            let _ = flujo.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\
                  Content-Length: 2\r\nConnection: close\r\n\r\nok",
            );
            let _ = flujo.flush();
        }
    })
}

/// Saca de una peticion HTTP lo que interesa al informe.
#[must_use]
pub fn analizar_http(bruto: &[u8]) -> Option<PeticionHttp> {
    let texto = String::from_utf8_lossy(&bruto[..bruto.len().min(MAX_PETICION)]);
    let mut lineas = texto.split("\r\n");
    let primera = lineas.next()?;
    let mut partes = primera.split_whitespace();
    let metodo = partes.next()?.to_string();
    let ruta = partes.next().unwrap_or("/").to_string();
    if metodo.is_empty() || !metodo.chars().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }

    let mut host = String::new();
    let mut agente = String::new();
    for l in lineas.by_ref() {
        if l.is_empty() {
            break;
        }
        let Some((clave, valor)) = l.split_once(':') else {
            continue;
        };
        match clave.trim().to_ascii_lowercase().as_str() {
            "host" => host = valor.trim().to_string(),
            "user-agent" => agente = valor.trim().to_string(),
            _ => {}
        }
    }

    let cuerpo = texto
        .split_once("\r\n\r\n")
        .map(|(_, c)| c.len() as u64)
        .unwrap_or(0);

    Some(PeticionHttp {
        metodo,
        ruta,
        host,
        agente,
        cuerpo,
    })
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use std::net::TcpStream;

    /// Construye una consulta de DNS de verdad para un nombre.
    fn consulta(nombre: &str, qtype: u16) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&0x1234u16.to_be_bytes()); // id
        v.extend_from_slice(&0x0100u16.to_be_bytes()); // consulta recursiva
        v.extend_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        for etiqueta in nombre.split('.') {
            v.push(etiqueta.len() as u8);
            v.extend_from_slice(etiqueta.as_bytes());
        }
        v.push(0);
        v.extend_from_slice(&qtype.to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes()); // IN
        v
    }

    // --- DNS ---------------------------------------------------------------

    #[test]
    fn el_nombre_del_c2_se_captura_y_se_responde_al_sumidero() {
        // El nombre que la muestra pregunta ES el indicador mas valioso del
        // informe. Un sandbox sin DNS falso no lo consigue nunca.
        let (nombre, r) = responder_dns(&consulta("panel.malicioso.example", 1)).unwrap();
        assert_eq!(nombre, "panel.malicioso.example");

        // Cabecera de respuesta con una contestacion.
        assert_eq!(
            u16::from_be_bytes([r[0], r[1]]),
            0x1234,
            "mismo identificador"
        );
        assert_eq!(r[2] & 0x80, 0x80, "el bit de respuesta");
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 1, "una respuesta");
        // Y los cuatro ultimos bytes son la direccion de sumidero.
        assert_eq!(&r[r.len() - 4..], &SUMIDERO.octets());
    }

    #[test]
    fn el_sumidero_esta_en_una_red_que_no_lleva_a_ningun_sitio() {
        // TEST-NET-3 (RFC 5737). Si un dia una detonacion se escapara de su
        // frontera, esta direccion no es la de nadie.
        assert_eq!(SUMIDERO.octets()[0], 203);
        assert_eq!(SUMIDERO.octets()[1], 0);
        assert_eq!(SUMIDERO.octets()[2], 113);
    }

    #[test]
    fn a_lo_que_no_es_una_direccion_no_se_le_inventa_respuesta() {
        // Contestar un registro inventado a una consulta MX le daria a la muestra
        // una forma de saber que el resolutor no es de verdad.
        let (_, r) = responder_dns(&consulta("correo.example", 15)).unwrap();
        assert_eq!(u16::from_be_bytes([r[6], r[7]]), 0, "sin respuestas");
    }

    #[test]
    fn un_paquete_que_no_es_dns_no_rompe_nada() {
        // El paquete lo escribe la muestra: puede ser cualquier cosa.
        assert!(responder_dns(b"").is_none());
        assert!(responder_dns(b"corto").is_none());
        assert!(responder_dns(&[0u8; 12]).is_none(), "sin preguntas");
        assert!(responder_dns(b"basura sin ninguna estructura de dns").is_none());
    }

    #[test]
    fn un_puntero_de_compresion_en_una_consulta_se_rechaza() {
        // En una consulta no hay punteros. Uno aqui solo puede ser un intento de
        // marear al analizador, y seguirlo seria darle vueltas a su ritmo.
        let mut c = consulta("x.example", 1);
        c[12] = 0xC0; // primera etiqueta convertida en puntero
        c[13] = 0x0C;
        assert!(responder_dns(&c).is_none());
    }

    #[test]
    fn un_nombre_interminable_no_deja_dando_vueltas_al_anfitrion() {
        let mut c = Vec::new();
        c.extend_from_slice(&0x1u16.to_be_bytes());
        c.extend_from_slice(&0x0100u16.to_be_bytes());
        c.extend_from_slice(&1u16.to_be_bytes());
        c.extend_from_slice(&[0u8; 6]);
        // Cientos de etiquetas de un byte, sin terminador.
        for _ in 0..500 {
            c.push(1);
            c.push(b'a');
        }
        // No cuelga: o responde o rechaza, pero vuelve.
        let _ = responder_dns(&c);
    }

    #[test]
    fn el_ttl_es_corto_para_no_perder_la_secuencia_de_dominios() {
        // Con un TTL largo, una muestra que resuelve una vez y cachea no vuelve a
        // preguntar, y en un algoritmo de generacion de dominios esa secuencia es
        // el dato entero.
        const _: () = assert!(
            TTL <= 5,
            "TTL demasiado largo: se pierde la secuencia de dominios"
        );
    }

    // --- HTTP --------------------------------------------------------------

    #[test]
    fn de_una_peticion_se_saca_lo_que_identifica_a_la_familia() {
        let bruto = b"POST /gate.php HTTP/1.1\r\nHost: c2.malicioso.example\r\n\
                      User-Agent: Mozilla/4.0 (compatible; MSIE 6.0)\r\n\
                      Content-Length: 4\r\n\r\ndata";
        let p = analizar_http(bruto).unwrap();
        assert_eq!(p.metodo, "POST");
        assert_eq!(p.ruta, "/gate.php");
        assert_eq!(p.host, "c2.malicioso.example");
        assert!(p.agente.contains("MSIE 6.0"), "{}", p.agente);
        assert_eq!(p.cuerpo, 4);
    }

    #[test]
    fn lo_que_no_es_http_no_se_inventa() {
        assert!(analizar_http(b"").is_none());
        assert!(analizar_http(b"\x16\x03\x01\x00\xa5 esto es TLS").is_none());
        assert!(analizar_http(b"1234 /x HTTP/1.1\r\n\r\n").is_none());
    }

    // --- Los servicios de verdad -------------------------------------------

    #[test]
    fn los_servicios_falsos_contestan_de_verdad_por_sus_sockets() {
        // Sin simulacion: sockets reales, paquetes reales, y el mismo codigo que
        // corre en produccion.
        let red = RedSimulada::levantar("127.0.0.1").unwrap();

        // DNS por UDP de verdad.
        let cliente = UdpSocket::bind("127.0.0.1:0").unwrap();
        cliente
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        cliente
            .send_to(
                &consulta("c2.malicioso.example", 1),
                ("127.0.0.1", red.puerto_dns),
            )
            .unwrap();
        let mut bufer = [0u8; 512];
        let (n, _) = cliente
            .recv_from(&mut bufer)
            .expect("el DNS falso no contesto");
        assert!(n > 12);
        assert_eq!(&bufer[n - 4..n], &SUMIDERO.octets());

        // HTTP por TCP de verdad.
        let mut flujo = TcpStream::connect(("127.0.0.1", red.puerto_http)).unwrap();
        flujo
            .write_all(
                b"GET /panel/gate.php HTTP/1.1\r\nHost: c2.malicioso.example\r\n\
                  User-Agent: AgenteRaro/1.0\r\n\r\n",
            )
            .unwrap();
        let mut respuesta = String::new();
        flujo
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let _ = flujo.read_to_string(&mut respuesta);
        assert!(respuesta.starts_with("HTTP/1.1 200"), "{respuesta}");

        // Y todo queda observado.
        std::thread::sleep(Duration::from_millis(200));
        let o = red.parar();
        assert!(
            o.dominios().contains(&"c2.malicioso.example"),
            "dominios vistos: {:?}",
            o.dominios()
        );
        assert!(
            o.peticiones.iter().any(|p| p.ruta == "/panel/gate.php"),
            "peticiones vistas: {:?}",
            o.peticiones
        );
    }

    #[test]
    fn la_respuesta_no_lleva_nada_que_identifique_al_sandbox() {
        // Cada cadena de mas en la respuesta es una cadena que una muestra puede
        // buscar para saber donde esta.
        let red = RedSimulada::levantar("127.0.0.1").unwrap();
        let mut flujo = TcpStream::connect(("127.0.0.1", red.puerto_http)).unwrap();
        flujo
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .unwrap();
        let mut r = String::new();
        flujo
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let _ = flujo.read_to_string(&mut r);

        let bajo = r.to_ascii_lowercase();
        for delator in ["aegis", "sandbox", "detonate", "server:"] {
            assert!(!bajo.contains(delator), "la respuesta delata: {r}");
        }
        let _ = red.parar();
    }

    #[test]
    fn los_hilos_mueren_aunque_nadie_llame_a_parar() {
        // Un servicio falso que sobrevive a su detonacion sigue escuchando en el
        // anfitrion: una superficie abierta que nadie sabe que tiene.
        let puerto = {
            let red = RedSimulada::levantar("127.0.0.1").unwrap();
            red.puerto_http
        };
        // Tras el Drop, el puerto tiene que poder volver a atarse.
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            TcpListener::bind(("127.0.0.1", puerto)).is_ok(),
            "el hilo de HTTP sobrevivio a su RedSimulada"
        );
    }
}
