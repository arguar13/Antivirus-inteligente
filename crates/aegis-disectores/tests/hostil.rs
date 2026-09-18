//! El barrido hostil: cada disector contra entrada preparada para romperlo.
//!
//! # Por que esto no es opcional
//!
//! Un disector es lo primero que toca los bytes de un desconocido. No hay
//! autenticacion antes, no hay filtro antes, y el agente corre con privilegios en
//! cada maquina de la flota. Un panico aqui **es** una denegacion de servicio
//! contra la propia defensa: el atacante manda un paquete preparado y apaga el
//! sensor de cien mil equipos.
//!
//! En Rust no hay lecturas fuera de rango, pero si hay cuatro formas de tumbar un
//! disector, y las cuatro se prueban aqui **contra todos**:
//!
//! 1. **Panico** por un indice, una resta con desbordamiento o un `unwrap`.
//! 2. **Bucle sin fin** por una longitud cero que no avanza o un puntero que
//!    vuelve atras.
//! 3. **Memoria** reservada segun un campo que escribe el emisor.
//! 4. **Tiempo** cuadratico por un bucle anidado sobre un campo del emisor.
//!
//! # Como se barre
//!
//! De cada vector valido se derivan: todos sus prefijos, todas sus mutaciones de
//! un byte en las primeras posiciones, sus campos de longitud puestos al maximo,
//! y las entradas degeneradas (vacio, ceros, unos, ruido reproducible). Cada
//! derivada se pasa por `reconoce` y por `disecar` de **cada** disector del
//! catalogo, no solo del suyo: un disector tiene que aguantar tambien el trafico
//! que no es suyo, porque en el registro lo va a ver igual.
//!
//! El proceso aborta con un panico, asi que no hace falta atraparlo: si alguno
//! panica, esta prueba falla.

use std::time::Instant;

use aegis_disectores::catalogo::{registro_completo, Familia};
use aegis_disectores::disector::{Contexto, Disector};

/// Un generador reproducible. Un barrido con datos que cambian en cada
/// ejecucion encuentra fallos que luego nadie sabe reproducir, y esa es la peor
/// clase de prueba: la que falla una vez y nadie puede arreglar.
struct Ruido(u64);

impl Ruido {
    fn nuevo(semilla: u64) -> Ruido {
        Ruido(semilla | 1)
    }

    fn siguiente(&mut self) -> u64 {
        // xorshift64*, que cabe en seis lineas y no trae dependencias.
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        while v.len() < n {
            v.extend_from_slice(&self.siguiente().to_le_bytes());
        }
        v.truncate(n);
        v
    }
}

/// Los vectores validos de los que se derivan los hostiles.
///
/// Son los mismos mensajes reales que las pruebas de cada modulo, reunidos aqui
/// para que el barrido los cruce **todos contra todos**.
fn vectores() -> Vec<(&'static str, Vec<u8>)> {
    let mut v: Vec<(&'static str, Vec<u8>)> = Vec::new();

    v.push((
        "modbus-leer",
        vec![
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0A,
        ],
    ));
    v.push((
        "modbus-escribir",
        vec![
            0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x01, 0x05, 0x00, 0x04, 0xFF, 0x00,
        ],
    ));
    v.push((
        "dnp3",
        vec![
            0x05, 0x64, 0x08, 0xC4, 0x01, 0x00, 0x02, 0x00, 0x9C, 0xB2, 0xC0, 0xC1, 0x01,
        ],
    ));
    v.push((
        "s7comm-parar",
        vec![
            0x03, 0x00, 0x00, 0x19, 0x02, 0xF0, 0x80, 0x32, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x10, 0x00, 0x00, 0x29, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x50,
        ],
    ));
    v.push((
        "bacnet-quien-es",
        vec![
            0x81, 0x0B, 0x00, 0x0C, 0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF, 0x10, 0x08,
        ],
    ));
    v.push(("opcua-hola", {
        let url = b"opc.tcp://planta:4840";
        let mut b = b"HELF".to_vec();
        b.extend_from_slice(&((8 + 20 + 4 + url.len()) as u32).to_le_bytes());
        b.extend_from_slice(&[0u8; 20]);
        b.extend_from_slice(&(url.len() as u32).to_le_bytes());
        b.extend_from_slice(url);
        b
    }));
    v.push(("redis", b"*2\r\n$3\r\nGET\r\n$5\r\nclave\r\n".to_vec()));
    v.push(("mysql-consulta", {
        let cuerpo = b"\x03SELECT 1 FROM t";
        let mut b = (cuerpo.len() as u32).to_le_bytes()[..3].to_vec();
        b.push(0);
        b.extend_from_slice(cuerpo);
        b
    }));
    v.push(("postgres-arranque", {
        let cuerpo = b"user\0ana\0database\0ventas\0\0";
        let mut b = ((cuerpo.len() + 8) as u32).to_be_bytes().to_vec();
        b.extend_from_slice(&196_608u32.to_be_bytes());
        b.extend_from_slice(cuerpo);
        b
    }));
    v.push(("tds-lote", {
        let sql: Vec<u8> = "SELECT 1"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let mut b = vec![0x01, 0x01];
        b.extend_from_slice(&((8 + sql.len()) as u16).to_be_bytes());
        b.extend_from_slice(&[0, 0, 1, 0]);
        b.extend_from_slice(&sql);
        b
    }));
    v.push(("mongodb", {
        let mut bson = vec![0x02u8];
        bson.extend_from_slice(b"find\0");
        bson.extend_from_slice(&9u32.to_le_bytes());
        bson.extend_from_slice(b"usuarios\0");
        bson.push(0x00);
        let mut doc = ((bson.len() + 4) as u32).to_le_bytes().to_vec();
        doc.extend_from_slice(&bson);
        let mut cuerpo = 0u32.to_le_bytes().to_vec();
        cuerpo.push(0);
        cuerpo.extend_from_slice(&doc);
        let mut b = ((16 + cuerpo.len()) as u32).to_le_bytes().to_vec();
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&2013u32.to_le_bytes());
        b.extend_from_slice(&cuerpo);
        b
    }));
    v.push(("ntlm", {
        let mut b = b"NTLMSSP\0".to_vec();
        b.extend_from_slice(&3u32.to_le_bytes());
        b.resize(64, 0);
        b.extend_from_slice(&[0u8; 32]);
        b
    }));
    v.push(("radius", {
        let mut b = vec![1u8, 42, 0, 26];
        b.extend_from_slice(&[0u8; 16]);
        b.extend_from_slice(&[1, 6]);
        b.extend_from_slice(b"vpn1");
        b
    }));
    v.push(("diameter", {
        let mut b = vec![1u8, 0, 0, 20, 0x80, 0, 1, 1];
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(&1u32.to_be_bytes());
        b.extend_from_slice(&1u32.to_be_bytes());
        b
    }));
    v.push(("dcerpc-bind", {
        let mut b = vec![0x05, 0x00, 0x0B, 0x03, 0x10, 0x00, 0x00, 0x00];
        b.extend_from_slice(&72u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&4280u16.to_le_bytes());
        b.extend_from_slice(&4280u16.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        b.push(1);
        b.extend_from_slice(&[0, 0, 0]);
        b.extend_from_slice(&0u16.to_le_bytes());
        b.push(1);
        b.push(0);
        b.extend_from_slice(&0xe351_4235u32.to_le_bytes());
        b.extend_from_slice(&0x4b06u16.to_le_bytes());
        b.extend_from_slice(&0x11d1u16.to_le_bytes());
        b.extend_from_slice(&[0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2]);
        b.extend_from_slice(&4u32.to_le_bytes());
        b.extend_from_slice(&[0u8; 20]);
        b
    }));
    v.push(("nfs", {
        let mut cuerpo = Vec::new();
        for n in [1u32, 0, 2, 100_003, 3, 7, 1, 28, 0, 8] {
            cuerpo.extend_from_slice(&n.to_be_bytes());
        }
        cuerpo.extend_from_slice(b"portatil");
        cuerpo.extend_from_slice(&0u32.to_be_bytes());
        cuerpo.extend_from_slice(&0u32.to_be_bytes());
        cuerpo.extend_from_slice(&0u32.to_be_bytes());
        let mut b = ((cuerpo.len() as u32) | 0x8000_0000).to_be_bytes().to_vec();
        b.extend_from_slice(&cuerpo);
        b
    }));
    v.push(("rdp", {
        let cookie = b"Cookie: mstshash=admin\r\n";
        let total = 4 + 7 + cookie.len() + 8;
        let mut b = vec![0x03, 0x00];
        b.extend_from_slice(&(total as u16).to_be_bytes());
        b.push((total - 5) as u8);
        b.push(0xE0);
        b.extend_from_slice(&[0, 0, 0, 0, 0]);
        b.extend_from_slice(cookie);
        b.extend_from_slice(&[0x01, 0x00, 0x08, 0x00]);
        b.extend_from_slice(&2u32.to_le_bytes());
        b
    }));
    v.push(("vnc", b"RFB 003.008\n\x02\x01\x02".to_vec()));
    v.push((
        "webdav",
        b"PROPFIND /a HTTP/1.1\r\nHost: x\r\nDepth: 1\r\n\r\n".to_vec(),
    ));
    v.push((
        "winrm",
        b"POST /wsman HTTP/1.1\r\nHost: pc\r\nAuthorization: Negotiate abc\r\n\r\nshell/Command"
            .to_vec(),
    ));
    v.push(("amqp-publicar", {
        let mut carga = vec![0u8, 60, 0, 40, 0, 0, 7];
        carga.extend_from_slice(b"eventos");
        carga.push(10);
        carga.extend_from_slice(b"planta.uno");
        carga.drain(..2);
        let mut b = vec![1u8, 0, 1];
        b.extend_from_slice(&(carga.len() as u32).to_be_bytes());
        b.extend_from_slice(&carga);
        b.push(0xCE);
        b
    }));
    v.push(("mqtt-conectar", {
        let mut cuerpo = vec![0u8, 4];
        cuerpo.extend_from_slice(b"MQTT");
        cuerpo.extend_from_slice(&[4, 0xC0, 0, 60, 0, 8]);
        cuerpo.extend_from_slice(b"sensor-7");
        let mut b = vec![0x10, cuerpo.len() as u8];
        b.extend_from_slice(&cuerpo);
        b
    }));
    v.push(("kafka", {
        let cliente = b"productor-1";
        let mut b = ((10 + cliente.len()) as u32).to_be_bytes().to_vec();
        b.extend_from_slice(&0u16.to_be_bytes());
        b.extend_from_slice(&9u16.to_be_bytes());
        b.extend_from_slice(&7u32.to_be_bytes());
        b.extend_from_slice(&(cliente.len() as u16).to_be_bytes());
        b.extend_from_slice(cliente);
        b
    }));
    v.push(("imap", b"a001 LOGIN ana secreta\r\n".to_vec()));
    v.push(("pop3", b"RETR 1\r\n".to_vec()));
    v.push(("http2", {
        let bloque = vec![0x83u8, 0x84];
        let mut b = (bloque.len() as u32).to_be_bytes()[1..].to_vec();
        b.extend_from_slice(&[0x01, 0x04]);
        b.extend_from_slice(&1u32.to_be_bytes());
        b.extend_from_slice(&bloque);
        b
    }));
    v.push(("http3", {
        let mut b = vec![0xC0u8];
        b.extend_from_slice(&1u32.to_be_bytes());
        b.push(8);
        b.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        b.push(0);
        b.push(0);
        b.extend_from_slice(&[0x40, 0x14]);
        b.extend_from_slice(&[0u8; 20]);
        b
    }));
    v.push(("websocket", vec![0x81, 0x85, 1, 2, 3, 4, 0, 0, 0, 0, 0]));
    v.push((
        "doh",
        {
            let mut b = b"POST /dns-query HTTP/1.1\r\nHost: doh\r\nContent-Type: application/dns-message\r\n\r\n".to_vec();
            b.extend_from_slice(&[0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
            b.push(7);
            b.extend_from_slice(b"ejemplo");
            b.push(2);
            b.extend_from_slice(b"es");
            b.extend_from_slice(&[0, 0, 1, 0, 1]);
            b
        },
    ));
    v.push(("dot", vec![0x16, 0x03, 0x01, 0x00, 0x2a]));
    v.push(("wireguard", {
        let mut b = vec![1u8, 0, 0, 0];
        b.extend_from_slice(&7u32.to_le_bytes());
        b.resize(148, 0);
        b
    }));
    v.push(("ikev2", {
        let mut b = 0x0102_0304_0506_0708u64.to_be_bytes().to_vec();
        b.extend_from_slice(&0u64.to_be_bytes());
        b.extend_from_slice(&[33, 0x20, 34, 0x08]);
        b.extend_from_slice(&0u32.to_be_bytes());
        b.extend_from_slice(&28u32.to_be_bytes());
        b
    }));
    v.push(("socks", {
        let mut b = vec![5u8, 1, 0, 3, 11];
        b.extend_from_slice(b"interno.red");
        b.extend_from_slice(&445u16.to_be_bytes());
        b
    }));
    v.push((
        "nube",
        b"GET /latest/meta-data/iam/security-credentials/rol HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n".to_vec(),
    ));
    v.push((
        "saml",
        b"POST /acs HTTP/1.1\r\nHost: idp\r\n\r\nSAMLResponse=PHNhbWxw".to_vec(),
    ));
    v.push((
        "oauth",
        b"POST /token HTTP/1.1\r\nHost: idp\r\n\r\ngrant_type=client_credentials".to_vec(),
    ));
    v.push((
        "elasticsearch",
        b"POST /indice/_search HTTP/1.1\r\nHost: es\r\n\r\n{}".to_vec(),
    ));
    v.push(("grpc", {
        let mut b = vec![0u8];
        b.extend_from_slice(&4u32.to_be_bytes());
        b.extend_from_slice(&[0x08, 0x96, 0x01, 0x00]);
        b
    }));
    v
}

/// Los contextos con los que se prueba cada entrada.
fn contextos() -> Vec<Contexto> {
    let mut v = Vec::new();
    for puerto in [80u16, 443, 502, 853, 1080, 3389, 5432, 20000, 47808, 65535] {
        v.push(Contexto::tcp_cliente(puerto));
        v.push(Contexto::tcp_servidor(puerto));
        v.push(Contexto::udp(puerto));
    }
    v
}

/// Todas las derivadas hostiles de un vector valido.
fn derivadas(base: &[u8], ruido: &mut Ruido) -> Vec<Vec<u8>> {
    let mut salida = Vec::new();

    // 1. Todos los prefijos. Un mensaje cortado es el caso mas comun de la red
    //    real y el que mas indices fuera de rango ha producido en este sector.
    for n in 0..=base.len() {
        salida.push(base[..n].to_vec());
    }

    // 2. Cada byte de la cabecera a cero, a 0xFF y a 0x80. Las cabeceras son
    //    donde viven los campos de longitud y de tipo.
    for i in 0..base.len().min(24) {
        for valor in [0x00u8, 0xFF, 0x80, 0x7F] {
            let mut m = base.to_vec();
            m[i] = valor;
            salida.push(m);
        }
    }

    // 3. Todos los pares de bytes de la cabecera a 0xFF, que es como se ponen al
    //    maximo los campos de longitud de dos bytes.
    for i in 0..base.len().saturating_sub(1).min(20) {
        let mut m = base.to_vec();
        m[i] = 0xFF;
        m[i + 1] = 0xFF;
        salida.push(m);
    }

    // 4. El vector alargado con ruido y el vector repetido: los dos revelan
    //    bucles que no avanzan.
    let mut alargado = base.to_vec();
    alargado.extend_from_slice(&ruido.bytes(256));
    salida.push(alargado);
    let mut repetido = Vec::new();
    for _ in 0..8 {
        repetido.extend_from_slice(base);
    }
    salida.push(repetido);

    salida
}

/// Las entradas degeneradas, que no vienen de ningun vector.
fn degeneradas(ruido: &mut Ruido) -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = vec![
        Vec::new(),
        vec![0x00],
        vec![0xFF],
        vec![0x00; 4096],
        vec![0xFF; 4096],
        vec![0x80; 1024],
        vec![b'A'; 8192],
    ];
    // Ruido puro de varios tamanos: es la entrada que ningun disector espera y
    // la que encuentra lo que las derivadas no.
    for n in [1usize, 2, 3, 7, 15, 63, 255, 1023, 4095] {
        v.push(ruido.bytes(n));
    }
    // Texto con muchas lineas y sin final: los disectores de texto tienen que
    // pararse en su tope, no recorrerlo entero por cada trozo.
    v.push(b"a: b\r\n".repeat(4096));
    // Una peticion HTTP con mil cabeceras.
    let mut muchas = b"GET / HTTP/1.1\r\n".to_vec();
    for i in 0..1000 {
        muchas.extend_from_slice(format!("X-{i}: valor\r\n").as_bytes());
    }
    v.push(muchas);
    v
}

/// Cuanto puede tardar el barrido entero antes de que se considere que algun
/// disector tiene un coste que no es lineal.
///
/// No es un banco de pruebas: es un techo grosero que solo salta si algo se ha
/// vuelto cuadratico. Un umbral fino fallaria en una maquina cargada y acabaria
/// desactivado, que es peor que no tenerlo.
const TOPE_DE_TIEMPO: std::time::Duration = std::time::Duration::from_secs(120);

#[test]
fn ningun_disector_se_rompe_con_entrada_hostil() {
    let mut ruido = Ruido::nuevo(0xAE15);
    let mut entradas: Vec<Vec<u8>> = degeneradas(&mut ruido);
    for (_, base) in vectores() {
        entradas.extend(derivadas(&base, &mut ruido));
    }

    let disectores: Vec<Box<dyn Disector + Send + Sync>> =
        Familia::TODAS.iter().flat_map(|f| f.disectores()).collect();
    assert!(disectores.len() >= 30, "el catalogo esta incompleto");

    let ctxs = contextos();
    let empezo = Instant::now();
    let mut probadas = 0u64;
    // Se acumulan TODAS las discrepancias y se cuentan al final. Un barrido que
    // pare en la primera obliga a dar una vuelta entera por cada una, y con
    // treinta y ocho disectores eso son treinta y ocho vueltas.
    let mut discrepantes: std::collections::BTreeSet<&'static str> =
        std::collections::BTreeSet::new();

    // Cada entrada contra CADA disector, no solo contra el suyo: en el registro
    // los va a ver todos, y uno que se rompa con trafico ajeno se rompe igual.
    for d in &disectores {
        for entrada in &entradas {
            for ctx in &ctxs {
                let reconocido = d.reconoce(entrada, ctx);
                let salida = d.disecar(entrada, ctx);
                probadas += 1;

                // Un disector que reconoce y luego no entiende nada NO es un
                // fallo: es justo lo que la cobertura declarada existe para
                // decir. Lo que si seria un fallo es emitir hechos sin haber
                // reconocido nada — salvo en los que DECLARAN que su diseccion
                // es mas ancha que su reconocimiento, que tienen su razon
                // escrita en el propio disector.
                if !reconocido && !salida.hechos.is_empty() && !d.disecar_es_mas_ancho() {
                    discrepantes.insert(d.nombre());
                }
                // Y toda diseccion tiene que contar exactamente un mensaje: ni
                // callarse ni contar de mas. Sin esto, la cifra de cobertura se
                // podria inflar sin que ninguna prueba lo viera.
                assert!(
                    salida.cobertura.vistos() >= 1 || salida.hechos.is_empty(),
                    "{} emitio hechos sin contar el mensaje",
                    d.nombre()
                );
            }
        }
    }

    assert!(
        discrepantes.is_empty(),
        "estos disectores emitieron hechos sobre entrada que NO habian reconocido, y \
         ninguno declara `disecar_es_mas_ancho`: {discrepantes:?}"
    );
    let tardo = empezo.elapsed();
    assert!(
        tardo < TOPE_DE_TIEMPO,
        "el barrido tardo {tardo:?} en {probadas} disecciones: algo dejo de ser lineal"
    );
    println!("{probadas} disecciones hostiles en {tardo:?}");
}

#[test]
fn el_registro_entero_aguanta_el_mismo_barrido() {
    // Y ademas hay que probarlo montado, porque el registro prueba por fuerza y
    // ese camino es otro codigo.
    let mut ruido = Ruido::nuevo(0xC0FFEE);
    let mut entradas = degeneradas(&mut ruido);
    for (_, base) in vectores() {
        entradas.extend(derivadas(&base, &mut ruido));
    }
    let mut r = registro_completo();
    let ctxs = contextos();
    for entrada in &entradas {
        for ctx in &ctxs {
            let s = r.disecar(entrada, ctx);
            // **Al menos uno**, no exactamente uno: un solo trozo puede llevar
            // varios mensajes —una respuesta de IMAP con tres adjuntos son
            // cuatro—, y exigir exactamente uno obligaria a mentir en la cifra.
            // Lo que no puede pasar nunca es que una diseccion no cuente nada:
            // ahi es donde un sensor deja de ver cosas en silencio.
            assert!(
                s.cobertura.vistos() >= 1,
                "una diseccion que no cuenta ningun mensaje es un hueco invisible"
            );
        }
    }
    assert!(r.cobertura.vistos() > 100_000);
    // Un barrido entero que saliera con cobertura completa querria decir que la
    // cifra no distingue nada. Aqui no se pone un umbral sobre la fraccion: la
    // mitad de estas entradas son mutaciones de mensajes validos, y muchas
    // siguen siendo validas —cambiar un byte del cuerpo de un Modbus no lo deja
    // de ser—, asi que un numero alto no significaria lo que parece. El umbral
    // va donde si significa algo: sobre ruido puro, en la prueba siguiente.
    assert!(
        !r.cobertura.completa(),
        "un barrido hostil no puede salir con cobertura completa"
    );
    println!("{}", r.frase());
}

/// Sobre **ruido puro** la cifra si tiene que ser baja: son bytes que no son de
/// ningun protocolo, y un sensor que diga entenderlos esta diciendo que si a
/// cualquier cosa. Es la medida que separa un reconocimiento por contenido de
/// uno que solo mira dos bytes.
#[test]
fn el_ruido_puro_casi_no_se_reconoce() {
    let mut ruido = Ruido::nuevo(0x5EED);
    let mut r = registro_completo();
    let ctxs = contextos();
    let mut reconocidos: Vec<&'static str> = Vec::new();

    for _ in 0..2000 {
        let n = (ruido.siguiente() % 2048) as usize + 1;
        let entrada = ruido.bytes(n);
        for ctx in &ctxs {
            let s = r.disecar(&entrada, ctx);
            if let Some(aegis_wire::hecho::Hecho::ProtocoloIdentificado(p)) = s.hechos.first() {
                reconocidos.push(p.nombre());
            }
        }
    }

    let vistos = r.cobertura.vistos();
    let entendidos = r.cobertura.entendidos;
    let fraccion = r.cobertura.fraccion().unwrap_or(0);
    reconocidos.sort_unstable();
    let mut cuenta: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for p in &reconocidos {
        *cuenta.entry(p).or_default() += 1;
    }
    println!(
        "ruido puro: {vistos} mensajes, {entendidos} dados por entendidos ({fraccion}%); \
         reclamados por: {cuenta:?}"
    );
    assert!(
        fraccion <= 2,
        "el {fraccion}% del ruido puro se dio por entendido, y lo reclamaron {cuenta:?}: \
         algun disector reconoce por dos bytes"
    );
}

#[test]
fn una_longitud_al_maximo_no_reserva_lo_que_diga_el_emisor() {
    // La forma mas barata de tumbar un sensor: un campo de longitud enorme y
    // cuatro bytes de mensaje. Si alguno reservara segun el campo, esto pediria
    // gigabytes; como ninguno lo hace, cuesta lo mismo que un mensaje corto.
    let mut r = registro_completo();
    let ctx = Contexto::tcp_cliente(80);
    let empezo = Instant::now();
    for cabecera in [
        vec![0x00u8, 0x01, 0x00, 0x00, 0xFF, 0xFF, 0x01, 0x03],
        vec![0x05, 0x64, 0xFF, 0xC4, 0xFF, 0xFF, 0xFF, 0xFF],
        vec![0x03, 0x00, 0xFF, 0xFF, 0x02, 0xF0, 0x80, 0x32],
        vec![0x81, 0x0A, 0xFF, 0xFF, 0x01, 0x00, 0x10, 0x08],
        vec![b'M', b'S', b'G', b'F', 0xFF, 0xFF, 0xFF, 0xFF],
        vec![0x05, 0x00, 0x0B, 0x03, 0x10, 0x00, 0x00, 0x00, 0xFF, 0xFF],
        vec![0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00],
    ] {
        for _ in 0..1000 {
            let s = r.disecar(&cabecera, &ctx);
            assert!(s.cobertura.vistos() == 1);
        }
    }
    let tardo = empezo.elapsed();
    assert!(
        tardo < std::time::Duration::from_secs(10),
        "siete mil mensajes con longitudes al maximo tardaron {tardo:?}"
    );
}

#[test]
fn cada_disector_declara_las_dos_mitades_de_su_cobertura() {
    // La propiedad que hace comparable este sensor: se puede saber que esperar
    // de el ANTES de mandarle trafico. Un disector que declarase una lista vacia
    // de «lo que no analiza» estaria diciendo que lo entiende todo.
    for f in Familia::TODAS {
        for d in f.disectores() {
            assert!(
                !d.mensajes_que_entiende().is_empty(),
                "{} no declara lo que entiende",
                d.nombre()
            );
            assert!(
                !d.mensajes_que_no_analiza().is_empty(),
                "{} dice que lo entiende todo, y eso hay que poder comprobarlo",
                d.nombre()
            );
            for m in d.mensajes_que_entiende() {
                assert!(m.len() > 3, "{}: «{m}» no dice nada", d.nombre());
            }
            for m in d.mensajes_que_no_analiza() {
                assert!(
                    m.len() > 10,
                    "{}: «{m}» no explica que hueco deja",
                    d.nombre()
                );
            }
            // La excepcion del contrato se declara, y solo la usa quien la
            // necesita: si esta lista crece, alguien tiene que explicarse.
            if d.disecar_es_mas_ancho() {
                assert_eq!(
                    d.nombre(),
                    "websocket",
                    "un disector nuevo con la diseccion mas ancha que el reconocimiento \
                     tiene que justificarlo aqui"
                );
            }
        }
    }
}
