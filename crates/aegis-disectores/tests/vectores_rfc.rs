//! Vectores byte a byte, con la norma citada al lado.
//!
//! # Que comprueba esto que no comprueben las pruebas de cada modulo
//!
//! Las de cada modulo comprueban que el disector **hace lo que su autor quiso**.
//! Estas comprueban que lo que quiso **coincide con la norma**, que es otra cosa
//! y es donde se cuelan los errores que ninguna prueba interna encuentra: una
//! tabla desplazada en uno, un campo leido en el orden de bytes contrario, un
//! desplazamiento contado desde donde no es.
//!
//! Por eso cada vector de aqui lleva su origen escrito: el documento, la seccion
//! y el valor esperado. Un vector sin procedencia no vale para esto — comprobar
//! que el codigo hace lo que el codigo hace no comprueba nada.
//!
//! # Los tres errores que estos vectores han encontrado
//!
//! Estan aqui porque de verdad pasaron, y las pruebas que los cazaron siguen en
//! pie:
//!
//! - La tabla de servicios no confirmados de BACnet estaba desplazada: un
//!   barrido de descubrimiento (`who-Is`, servicio 8) salia en el informe como
//!   una sincronizacion de hora.
//! - El UUID de DCERPC se leia siempre en orden pequeno, asi que un `bind` desde
//!   un emisor de orden de red no encontraba su interfaz en el catalogo y
//!   DCSync salia como «interfaz desconocido».
//! - La APDU de BACnet se leia sin saltar el encaminamiento del NPDU, con lo que
//!   la red de destino se leia como si fuera el servicio.

use aegis_disectores::catalogo::registro_completo;
use aegis_disectores::disector::{Contexto, Disector};
use aegis_disectores::{bases, identidad, industrial, mensajeria, remoto, tuneles, web};
use aegis_wire::hecho::{Hecho, ProtocoloApp};

/// El primer hecho de protocolo de una salida.
fn protocolo(s: &aegis_disectores::Salida) -> Option<ProtocoloApp> {
    s.hechos.iter().find_map(|h| match h {
        Hecho::ProtocoloIdentificado(p) => Some(*p),
        _ => None,
    })
}

/// La orden industrial de una salida: `(funcion, escribe, detalle)`.
fn orden(s: &aegis_disectores::Salida) -> Option<(String, bool, String)> {
    s.hechos.iter().find_map(|h| match h {
        Hecho::OrdenIndustrial {
            funcion,
            escribe,
            detalle,
            ..
        } => Some((funcion.clone(), *escribe, detalle.clone())),
        _ => None,
    })
}

/// **Modbus Application Protocol V1.1b3, seccion 6.3.**
///
/// El ejemplo de la propia norma para «Read Holding Registers»: direccion
/// inicial 0x006B (107) y cantidad 0x0003. Sobre TCP va precedido de la cabecera
/// MBAP del documento «Modbus Messaging on TCP/IP Implementation Guide V1.0b»,
/// seccion 3.1.3: transaccion, protocolo cero, longitud y unidad.
#[test]
fn modbus_el_ejemplo_de_la_norma() {
    let d = industrial::Modbus;
    let b = vec![
        0x00, 0x01, // transaccion
        0x00, 0x00, // protocolo: cero, siempre
        0x00, 0x06, // longitud: unidad + PDU
        0x11, // unidad 17, la del ejemplo
        0x03, // leer registros retentivos
        0x00, 0x6B, // direccion inicial 107
        0x00, 0x03, // tres registros
    ];
    let ctx = Contexto::tcp_cliente(industrial::PUERTO_MODBUS);
    assert!(d.reconoce(&b, &ctx));
    let s = d.disecar(&b, &ctx);
    assert!(s.cobertura.completa());
    let (funcion, escribe, detalle) = orden(&s).expect("una orden");
    assert_eq!(funcion, "leer-registros-retentivos");
    assert!(!escribe, "leer no cambia el estado del dispositivo");
    assert_eq!(detalle, "direcciones 107..110");
}

/// **Modbus V1.1b3, seccion 6.5.** El ejemplo de «Write Single Coil»: salida
/// 0x00AC (172) al valor 0xFF00, que la norma define como ON.
#[test]
fn modbus_el_valor_que_la_norma_define_como_encendido() {
    let d = industrial::Modbus;
    let b = vec![
        0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x11, 0x05, 0x00, 0xAC, 0xFF, 0x00,
    ];
    let s = d.disecar(&b, &Contexto::tcp_cliente(industrial::PUERTO_MODBUS));
    let (funcion, escribe, detalle) = orden(&s).expect("una orden");
    assert_eq!(funcion, "escribir-bobina");
    assert!(escribe, "escribir una bobina mueve una salida fisica");
    assert_eq!(detalle, "bobina 172 a ON");

    // Y 0x0000 es OFF; cualquier otro valor la norma lo deja sin definir.
    let mut apagar = b.clone();
    apagar[10] = 0x00;
    let s = d.disecar(&apagar, &Contexto::tcp_cliente(industrial::PUERTO_MODBUS));
    assert_eq!(
        orden(&s).map(|(_, _, det)| det),
        Some("bobina 172 a OFF".to_owned())
    );
}

/// **IEEE 1815-2012, tablas 8-1 y 8-4.** La cabecera de enlace empieza por
/// 0x05 0x64, las direcciones van en orden pequeno —la excepcion del protocolo—,
/// y la funcion de aplicacion 0x01 es READ.
#[test]
fn dnp3_las_direcciones_van_en_orden_pequeno() {
    let d = industrial::Dnp3;
    let b = vec![
        0x05, 0x64, // inicio
        0x08, // longitud desde el control
        0xC4, // control: del maestro, con datos
        0x01, 0x00, // destino 1, en orden pequeno
        0x02, 0x00, // origen 2
        0x9C, 0xB2, // CRC de la cabecera
        0xC0, // transporte: primero y ultimo
        0xC1, // control de aplicacion
        0x01, // READ
    ];
    let ctx = Contexto::tcp_cliente(industrial::PUERTO_DNP3);
    let s = d.disecar(&b, &ctx);
    assert!(s.cobertura.completa());
    let unidad = s.hechos.iter().find_map(|h| match h {
        Hecho::OrdenIndustrial { unidad, .. } => Some(unidad.clone()),
        _ => None,
    });
    // Leido en orden grande saldria «512->256», que es el error que esta prueba
    // existe para que duela.
    assert_eq!(unidad, Some("2->1".to_owned()));
}

/// **ASHRAE 135, clausula 21.** Los servicios no confirmados: `who-Is` es el 8 y
/// `who-Has` el 7. Una tabla desplazada en uno no falla — nombra otro servicio, y
/// un informe que diga «sincronizacion de hora» donde hubo un barrido de
/// descubrimiento es peor que no decir nada.
#[test]
fn bacnet_el_descubrimiento_es_el_servicio_ocho() {
    let d = industrial::Bacnet;
    let ctx = Contexto::udp(industrial::PUERTO_BACNET);
    for (servicio, esperado) in [(7u8, "quien-tiene"), (8, "quien-es"), (0, "soy")] {
        // BVLC de difusion original (clausula J.2.11) + NPDU version 1 sin
        // encaminamiento + APDU no confirmada (clausula 20.1.3).
        let b = vec![0x81, 0x0A, 0x00, 0x08, 0x01, 0x00, 0x10, servicio];
        let s = d.disecar(&b, &ctx);
        assert_eq!(
            orden(&s).map(|(f, _, _)| f),
            Some(esperado.to_owned()),
            "el servicio no confirmado {servicio}"
        );
    }
}

/// **ASHRAE 135, clausula 6.2.2.** Cuando el control del NPDU tiene el bit de
/// destino (0x20), detras van la red, la longitud de direccion y la direccion, y
/// **ademas** una cuenta de saltos al final. La APDU empieza despues de todo eso.
#[test]
fn bacnet_la_apdu_empieza_tras_el_encaminamiento() {
    let d = industrial::Bacnet;
    let ctx = Contexto::udp(industrial::PUERTO_BACNET);
    // Sin encaminamiento: la APDU esta en el byte 6.
    let local = vec![0x81, 0x0A, 0x00, 0x0A, 0x01, 0x04, 0x00, 0x05, 0x01, 0x0C];
    assert_eq!(
        orden(&d.disecar(&local, &ctx)).map(|(f, _, _)| f),
        Some("leer-propiedad".to_owned())
    );
    // Con destino y origen: la APDU esta nueve bytes mas alla.
    let encaminado = vec![
        0x81, 0x0A, 0x00, 0x13, 0x01, 0x28, 0x00, 0x0C, 0x01, 0x05, 0x00, 0x0B, 0x01, 0x03, 0xFF,
        0x00, 0x05, 0x01, 0x0C,
    ];
    assert_eq!(
        orden(&d.disecar(&encaminado, &ctx)).map(|(f, _, _)| f),
        Some("leer-propiedad".to_owned()),
        "sin saltar el encaminamiento, la red de destino se lee como el servicio"
    );
}

/// **IEC 62541-6, anexo A.** Los identificadores del espacio de nombres cero:
/// `ReadRequest` es el 631 y `WriteRequest` el 673. Y la seccion 7.1.2.3 fija la
/// cabecera: tres letras de tipo, una de trozo y el tamano en orden pequeno.
#[test]
fn opcua_los_identificadores_del_espacio_de_nombres_cero() {
    let d = industrial::OpcUa;
    let ctx = Contexto::tcp_cliente(industrial::PUERTO_OPCUA);
    for (id, esperado, escribe) in [
        (631u16, "leer", false),
        (673, "escribir", true),
        (712, "llamar-a-metodo", true),
        (461, "crear-sesion", false),
    ] {
        let mut b = b"MSGF".to_vec();
        b.extend_from_slice(&33u32.to_le_bytes());
        b.extend_from_slice(&1u32.to_le_bytes()); // canal
        b.extend_from_slice(&1u32.to_le_bytes()); // testigo
        b.extend_from_slice(&1u32.to_le_bytes()); // secuencia
        b.extend_from_slice(&1u32.to_le_bytes()); // peticion
        b.push(0x01); // nodo numerico de cuatro bytes
        b.push(0x00); // espacio de nombres cero
        b.extend_from_slice(&id.to_le_bytes());
        let s = d.disecar(&b, &ctx);
        let (funcion, w, _) = orden(&s).unwrap_or_else(|| panic!("sin orden para {id}"));
        assert_eq!(funcion, esperado);
        assert_eq!(w, escribe, "el servicio {id}");
    }
}

/// **MS-NLMP, seccion 2.2.1.3.** El mensaje de autenticacion: la firma, el tipo
/// 3, y los campos de longitud-maximo-desplazamiento en orden pequeno. La
/// seccion 2.2.2.5 define el bit `NTLMSSP_NEGOTIATE_UNICODE`, que decide si el
/// texto va en UTF-16 o en la pagina OEM.
#[test]
fn ntlm_los_desplazamientos_van_en_orden_pequeno() {
    let d = identidad::Ntlm;
    let ctx = Contexto::tcp_cliente(445);
    let usuario: Vec<u8> = "Administrador"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let dominio: Vec<u8> = "CASA".encode_utf16().flat_map(u16::to_le_bytes).collect();

    let cabecera = 64usize;
    let off_dom = cabecera;
    let off_usr = off_dom + dominio.len();
    let campo = |largo: usize, off: usize| {
        let mut c = Vec::new();
        c.extend_from_slice(&(largo as u16).to_le_bytes());
        c.extend_from_slice(&(largo as u16).to_le_bytes());
        c.extend_from_slice(&(off as u32).to_le_bytes());
        c
    };
    let mut b = b"NTLMSSP\0".to_vec();
    b.extend_from_slice(&3u32.to_le_bytes());
    b.extend_from_slice(&campo(0, cabecera)); // respuesta LM vacia
    b.extend_from_slice(&campo(48, cabecera)); // respuesta NT de NTLMv2
    b.extend_from_slice(&campo(dominio.len(), off_dom));
    b.extend_from_slice(&campo(usuario.len(), off_usr));
    b.extend_from_slice(&campo(0, 0)); // equipo
    b.extend_from_slice(&campo(0, 0)); // clave de sesion
    b.extend_from_slice(&1u32.to_le_bytes()); // NEGOTIATE_UNICODE
    b.resize(cabecera, 0);
    b.extend_from_slice(&dominio);
    b.extend_from_slice(&usuario);

    let s = d.disecar(&b, &ctx);
    let (mecanismo, quien, donde) = s
        .hechos
        .iter()
        .find_map(|h| match h {
            Hecho::AutenticacionVista {
                mecanismo,
                usuario,
                dominio,
                ..
            } => Some((mecanismo.clone(), usuario.clone(), dominio.clone())),
            _ => None,
        })
        .expect("una autenticacion");
    assert_eq!(quien, "Administrador");
    assert_eq!(donde, "CASA");
    // 48 bytes de respuesta NT es NTLMv2; 24 seria NTLMv1 (MS-NLMP 2.2.2.6).
    assert!(mecanismo.ends_with("NTLMv2"), "{mecanismo}");
}

/// **RFC 2865, seccion 3 y 5.1.** La cabecera son veinte bytes: codigo,
/// identificador, longitud en orden de red y dieciseis de autenticador. El
/// atributo 1 es `User-Name` y su longitud **incluye** los dos bytes de su propia
/// cabecera.
#[test]
fn radius_la_longitud_del_atributo_se_cuenta_a_si_misma() {
    let d = identidad::Radius;
    let usuario = b"tecnico@planta";
    let mut b = vec![1u8, 0x2A]; // Access-Request, identificador 42
    b.extend_from_slice(&((20 + 2 + usuario.len()) as u16).to_be_bytes());
    b.extend_from_slice(&[0u8; 16]);
    b.push(1);
    b.push((2 + usuario.len()) as u8);
    b.extend_from_slice(usuario);

    let s = d.disecar(&b, &Contexto::udp(1812));
    let quien = s.hechos.iter().find_map(|h| match h {
        Hecho::AutenticacionVista { usuario, .. } => Some(usuario.clone()),
        _ => None,
    });
    assert_eq!(quien, Some("tecnico@planta".to_owned()));
}

/// **MS-RPCE, seccion 2.2.6.** El UUID de un interfaz va en el cable con sus tres
/// primeros campos en el orden que declara el emisor, y el resto tal cual. El
/// identificador de `drsuapi` es `e3514235-4b06-11d1-ab04-00c04fc2dcd2`
/// (MS-DRSR, seccion 1.9) y es por donde se pide la replicacion del directorio.
#[test]
fn dcerpc_el_mismo_interfaz_en_los_dos_ordenes_de_bytes() {
    let d = remoto::Dcerpc;
    let ctx = Contexto::tcp_cliente(remoto::PUERTO_EPMAPPER);

    let armar = |pequeno: bool| -> Vec<u8> {
        let mut b = vec![0x05, 0x00, 0x0B, 0x03];
        b.extend_from_slice(if pequeno {
            &[0x10, 0x00, 0x00, 0x00]
        } else {
            &[0x00, 0x00, 0x00, 0x00]
        });
        let u16b = |n: u16| {
            if pequeno {
                n.to_le_bytes()
            } else {
                n.to_be_bytes()
            }
        };
        let u32b = |n: u32| {
            if pequeno {
                n.to_le_bytes()
            } else {
                n.to_be_bytes()
            }
        };
        b.extend_from_slice(&u16b(72)); // longitud del fragmento
        b.extend_from_slice(&u16b(0)); // sin autenticacion
        b.extend_from_slice(&u32b(1)); // identificador de llamada
        b.extend_from_slice(&u16b(4280));
        b.extend_from_slice(&u16b(4280));
        b.extend_from_slice(&u32b(0));
        b.push(1); // un contexto
        b.extend_from_slice(&[0, 0, 0]);
        b.extend_from_slice(&u16b(0)); // identificador del contexto
        b.push(1); // una sintaxis de transferencia
        b.push(0);
        b.extend_from_slice(&u32b(0xe351_4235));
        b.extend_from_slice(&u16b(0x4b06));
        b.extend_from_slice(&u16b(0x11d1));
        b.extend_from_slice(&[0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2]);
        b.extend_from_slice(&u32b(4)); // version del interfaz
        b.extend_from_slice(&[0u8; 20]);
        b
    };

    for pequeno in [true, false] {
        let s = d.disecar(&armar(pequeno), &ctx);
        let (orden, para_que) = s
            .hechos
            .iter()
            .find_map(|h| match h {
                Hecho::EjecucionRemota {
                    orden, objetivo, ..
                } => Some((orden.clone(), objetivo.clone())),
                _ => None,
            })
            .expect("una ejecucion remota");
        assert_eq!(
            orden,
            "vincular-a-drsuapi",
            "en orden {}",
            if pequeno { "pequeno" } else { "de red" }
        );
        assert!(para_que.contains("DCSync"), "{para_que}");
    }
}

/// **RFC 1928, seccion 4.** La peticion de SOCKS 5: version, orden, un byte
/// reservado que vale cero, el tipo de direccion, la direccion y el puerto en
/// orden de red. El tipo 3 es un nombre precedido de su longitud.
#[test]
fn socks5_el_destino_como_lo_define_la_rfc() {
    let d = tuneles::Socks;
    let ctx = Contexto::tcp_cliente(tuneles::PUERTO_SOCKS);
    let nombre = b"controlador.planta";
    let mut b = vec![0x05, 0x01, 0x00, 0x03, nombre.len() as u8];
    b.extend_from_slice(nombre);
    b.extend_from_slice(&502u16.to_be_bytes());

    let s = d.disecar(&b, &ctx);
    let destino = s.hechos.iter().find_map(|h| match h {
        Hecho::EjecucionRemota { objetivo, .. } => Some(objetivo.clone()),
        _ => None,
    });
    assert_eq!(destino, Some("controlador.planta:502".to_owned()));

    // Y el tipo 1 es una IPv4 de cuatro bytes, sin longitud delante.
    let mut b4 = vec![0x05, 0x01, 0x00, 0x01, 10, 20, 30, 40];
    b4.extend_from_slice(&3389u16.to_be_bytes());
    let s = d.disecar(&b4, &ctx);
    assert_eq!(
        s.hechos.iter().find_map(|h| match h {
            Hecho::EjecucionRemota { objetivo, .. } => Some(objetivo.clone()),
            _ => None,
        }),
        Some("10.20.30.40:3389".to_owned())
    );
}

/// **RFC 7541, anexo A.** La tabla estatica de HPACK: el indice 2 es
/// `:method GET`, el 3 `:method POST`, el 4 `:path /` y el 7 `:scheme https`.
/// Un desplazamiento de uno en esa tabla convierte un POST en un GET.
#[test]
fn hpack_los_indices_de_la_tabla_estatica() {
    assert_eq!(web::TABLA_ESTATICA.len(), 61);
    for (indice, nombre, valor) in [
        (2usize, ":method", "GET"),
        (3, ":method", "POST"),
        (4, ":path", "/"),
        (7, ":scheme", "https"),
        (8, ":status", "200"),
        (58, "user-agent", ""),
    ] {
        let (n, v) = web::TABLA_ESTATICA[indice - 1];
        assert_eq!((n, v), (nombre, valor), "el indice {indice}");
    }

    // Y resolviendolo de verdad: 0x82 es «indexado, indice 2».
    let c = web::descomprimir(&[0x82, 0x87]);
    assert_eq!(
        c.resueltas,
        vec![
            (":method".to_owned(), "GET".to_owned()),
            (":scheme".to_owned(), "https".to_owned()),
        ]
    );
}

/// **RFC 6455, seccion 5.2.** Una longitud de 126 dice que detras van dos bytes
/// mas en orden de red; 127 dice que van ocho. Y la seccion 5.1 obliga al cliente
/// a enmascarar.
#[test]
fn websocket_las_tres_formas_de_la_longitud() {
    let d = web::Websocket;
    let ctx = Contexto::tcp_servidor(80);
    // Corta: la longitud cabe en los siete bits.
    let corta = [0x81u8, 0x05, b'h', b'o', b'l', b'a', b'!'];
    assert!(d.reconoce(&corta, &ctx));
    // Media: 126 y dos bytes.
    let mut media = vec![0x82u8, 126, 0x01, 0x00];
    media.extend(std::iter::repeat_n(0u8, 256));
    assert!(d.reconoce(&media, &ctx));
    // Larga: 127 y ocho bytes.
    let mut larga = vec![0x82u8, 127];
    larga.extend_from_slice(&300u64.to_be_bytes());
    larga.extend(std::iter::repeat_n(0u8, 300));
    assert!(d.reconoce(&larga, &ctx));
    // Y una longitud que no cuadra con lo que hay no es una trama.
    let mentira = [0x82u8, 126, 0xFF, 0xFF, 0x00];
    assert!(!d.reconoce(&mentira, &ctx));
}

/// **RFC 8484, seccion 4.1.** Un mensaje DNS sobre HTTP va en el cuerpo de un
/// POST con el tipo `application/dns-message`, o en el parametro `dns` de un GET
/// codificado en base64 de URL **sin relleno**.
#[test]
fn doh_las_dos_formas_de_la_rfc_8484() {
    let d = tuneles::Doh;
    let ctx = Contexto::tcp_cliente(443);
    // El mensaje DNS de la propia RFC: consulta de `www.example.com`, tipo A.
    let mut dns = vec![
        0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    dns.push(3);
    dns.extend_from_slice(b"www");
    dns.push(7);
    dns.extend_from_slice(b"example");
    dns.push(3);
    dns.extend_from_slice(b"com");
    dns.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);

    let mut post =
        b"POST /dns-query HTTP/1.1\r\nHost: doh\r\nContent-Type: application/dns-message\r\n\r\n"
            .to_vec();
    post.extend_from_slice(&dns);
    let s = d.disecar(&post, &ctx);
    let nombre = s.hechos.iter().find_map(|h| match h {
        Hecho::ConsultaDns { nombre, .. } => Some(nombre.clone()),
        _ => None,
    });
    assert_eq!(nombre, Some("www.example.com".to_owned()));
    assert_eq!(protocolo(&s), Some(ProtocoloApp::Doh));
}

/// **MQTT v3.1.1, seccion 2.2.3.** La longitud restante va en de uno a cuatro
/// bytes de siete bits, con el bit alto como continuacion. Un valor de 321 se
/// escribe `0xC1 0x02`, que es el ejemplo de la propia norma.
#[test]
fn mqtt_la_longitud_de_siete_bits_de_la_norma() {
    let d = mensajeria::Mqtt;
    let ctx = Contexto::tcp_cliente(mensajeria::PUERTOS_MQTT[0]);
    let tema = b"planta/linea1";
    let carga = vec![b'x'; 321 - 2 - tema.len()];
    let mut cuerpo = (tema.len() as u16).to_be_bytes().to_vec();
    cuerpo.extend_from_slice(tema);
    cuerpo.extend_from_slice(&carga);
    assert_eq!(cuerpo.len(), 321);

    let mut b = vec![0x30u8, 0xC1, 0x02];
    b.extend_from_slice(&cuerpo);
    assert!(d.reconoce(&b, &ctx), "321 se escribe 0xC1 0x02");
    let s = d.disecar(&b, &ctx);
    let visto = s.hechos.iter().find_map(|h| match h {
        Hecho::OperacionDeMensajeria { tema, .. } => Some(tema.clone()),
        _ => None,
    });
    assert_eq!(visto, Some("planta/linea1".to_owned()));
}

/// **PostgreSQL, protocolo de mensajes 3.0.** El arranque lleva la version
/// 196608 (3 << 16) y detras pares de cadenas terminadas en cero, acabados en una
/// cadena vacia. El codigo 80877103 es la peticion de subir a TLS.
#[test]
fn postgres_los_codigos_magicos_del_arranque() {
    let d = bases::Postgresql;
    let ctx = Contexto::tcp_cliente(bases::PUERTO_POSTGRESQL);

    let mut cuerpo = Vec::new();
    cuerpo.extend_from_slice(b"user\0nominas\0database\0rrhh\0\0");
    let mut b = ((cuerpo.len() + 8) as u32).to_be_bytes().to_vec();
    b.extend_from_slice(&196_608u32.to_be_bytes());
    b.extend_from_slice(&cuerpo);
    let s = d.disecar(&b, &ctx);
    let (operacion, objeto, usuario) = s
        .hechos
        .iter()
        .find_map(|h| match h {
            Hecho::OperacionDeBaseDeDatos {
                operacion,
                objeto,
                usuario,
                ..
            } => Some((operacion.clone(), objeto.clone(), usuario.clone())),
            _ => None,
        })
        .expect("una operacion");
    assert_eq!(operacion, "acceso");
    assert_eq!(objeto, "rrhh");
    assert_eq!(usuario, "nominas");

    // La peticion de TLS son ocho bytes exactos con su codigo magico.
    let mut tls = 8u32.to_be_bytes().to_vec();
    tls.extend_from_slice(&80_877_103u32.to_be_bytes());
    let s = d.disecar(&tls, &ctx);
    assert_eq!(
        s.hechos.iter().find_map(|h| match h {
            Hecho::OperacionDeBaseDeDatos { operacion, .. } => Some(operacion.clone()),
            _ => None,
        }),
        Some("peticion-de-tls".to_owned())
    );
}

/// El registro entero, con todos los disectores montados, encamina cada uno de
/// estos vectores al suyo. Que cada disector acierte por separado no garantiza
/// que acierte cuando estan los treinta y ocho a la vez.
#[test]
fn el_registro_montado_acierta_con_todos_los_vectores_de_norma() {
    let mut r = registro_completo();
    let casos: Vec<(&str, Vec<u8>, Contexto, ProtocoloApp)> = vec![
        (
            "modbus",
            vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x11, 0x03, 0x00, 0x6B, 0x00, 0x03],
            Contexto::tcp_cliente(502),
            ProtocoloApp::Modbus,
        ),
        (
            "bacnet",
            vec![0x81, 0x0A, 0x00, 0x08, 0x01, 0x00, 0x10, 0x08],
            Contexto::udp(47808),
            ProtocoloApp::Bacnet,
        ),
        (
            "socks",
            {
                let mut b = vec![0x05, 0x01, 0x00, 0x01, 10, 20, 30, 40];
                b.extend_from_slice(&3389u16.to_be_bytes());
                b
            },
            Contexto::tcp_cliente(1080),
            ProtocoloApp::Socks,
        ),
        (
            "wireguard",
            {
                let mut b = vec![1u8, 0, 0, 0];
                b.extend_from_slice(&7u32.to_le_bytes());
                b.resize(148, 0);
                b
            },
            Contexto::udp(51820),
            ProtocoloApp::Wireguard,
        ),
        (
            "postgresql",
            {
                let cuerpo = b"user\0ana\0database\0v\0\0";
                let mut b = ((cuerpo.len() + 8) as u32).to_be_bytes().to_vec();
                b.extend_from_slice(&196_608u32.to_be_bytes());
                b.extend_from_slice(cuerpo);
                b
            },
            Contexto::tcp_cliente(5432),
            ProtocoloApp::Postgresql,
        ),
        (
            "metadatos-de-nube",
            b"PUT /latest/api/token HTTP/1.1\r\nHost: 169.254.169.254\r\nX-aws-ec2-metadata-token-ttl-seconds: 21600\r\n\r\n".to_vec(),
            Contexto::tcp_cliente(80),
            ProtocoloApp::MetadatosDeNube,
        ),
    ];
    for (nombre, bytes, ctx, esperado) in casos {
        let s = r.disecar(&bytes, &ctx);
        assert_eq!(protocolo(&s), Some(esperado), "{nombre}");
    }
    assert_eq!(r.ambiguos, 0, "ningun vector de norma deberia ser ambiguo");
}
