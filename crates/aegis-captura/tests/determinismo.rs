//! Reproduccion determinista: los mismos bytes dan el mismo veredicto.
//!
//! # Por que esta es la prueba que justifica guardar el trafico
//!
//! No se guarda para mirarlo: se guarda para poder **contradecir al sistema con
//! sus propios datos**. Un analista que no esta de acuerdo con un veredicto puede
//! volver a pasar el flujo y ver exactamente que senales salieron y cual pesó.
//! Eso solo vale si el resultado es el mismo, y eso no se puede comprobar con
//! entradas fabricadas para la ocasion: hay que comprobarlo con el camino
//! completo, desde los bytes del cable hasta el veredicto, pasando por la
//! redaccion, el anillo, el PCAP y el almacen.
//!
//! # El camino que se recorre aqui
//!
//! ```text
//!   bytes ─► Redactor ─► Anillo ─► PCAP ─► leer ─► disectores ─► arbitro
//!                                            │
//!                                            └─► y otra vez, y otra
//! ```
//!
//! Si en cualquiera de esos pasos se colara un `HashMap` sin orden, una marca de
//! tiempo del reloj o una capacidad que dependa del tamano, esta prueba lo veria.

use aegis_captura::pcap::{self, Escritor};
use aegis_captura::redaccion::{Donde, Redactor};
use aegis_captura::reproduccion::{reproducir, Fidelidad, FlujoGuardado};
use aegis_captura::retencion::{Autorizacion, Decision};
use aegis_captura::{Capturador, Flujo, Paquete};
use aegis_disectores::catalogo::registro_completo;
use aegis_disectores::disector::Contexto;
use aegis_entidad::arbitro::{Resultado, Veredicto};
use aegis_entidad::entidad;
use aegis_entidad::escala::{Confianza, Severidad};

fn veredicto_malicioso() -> Veredicto {
    Veredicto {
        entidad: entidad::maquina("pasarela-ot-1"),
        resultado: Resultado::Malicioso,
        severidad: Severidad::Critica,
        confianza: Confianza::nueva(90),
        porque: "una estacion de oficina escribio en un PLC".to_owned(),
        planos: Vec::new(),
        senales: Vec::new(),
    }
}

/// Una conversacion real: alguien entra por WinRM a una pasarela y desde ahi
/// escribe en un PLC y para su CPU. Es el salto de IT a OT, en cuatro paquetes.
fn conversacion() -> Vec<(Vec<u8>, Contexto)> {
    vec![
        (
            b"POST /wsman HTTP/1.1\r\nHost: pasarela\r\nAuthorization: Negotiate YII\r\nContent-Type: application/soap+xml\r\n\r\n<a:Action>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command</a:Action>".to_vec(),
            Contexto::tcp_cliente(5985),
        ),
        (
            // Leer registros: telemetria.
            vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x11, 0x03, 0x00, 0x6B, 0x00, 0x03],
            Contexto::tcp_cliente(502),
        ),
        (
            // Escribir una bobina: esto mueve algo en el mundo fisico.
            vec![0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x11, 0x05, 0x00, 0xAC, 0xFF, 0x00],
            Contexto::tcp_cliente(502),
        ),
        (
            // Y parar la CPU del S7: la orden que para una planta.
            vec![
                0x03, 0x00, 0x00, 0x19, 0x02, 0xF0, 0x80, 0x32, 0x01, 0x00, 0x00, 0x00, 0x01,
                0x00, 0x10, 0x00, 0x00, 0x29, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x50,
            ],
            Contexto::tcp_cliente(102),
        ),
    ]
}

/// El camino entero, veinte veces, y el mismo veredicto las veinte.
#[test]
fn el_camino_entero_reproduce_el_mismo_veredicto() {
    let a = Autorizacion::del_veredicto(&veredicto_malicioso()).expect("malicioso autoriza");
    let eid = entidad::maquina("pasarela-ot-1");

    // 1. Se captura de verdad: redaccion, retencion, anillo.
    let mut c = Capturador::nuevo(Redactor::nuevo(), 1024 * 1024);
    let mut f = Flujo::nuevo(eid.clone(), Donde::default());
    f.decidir(Decision::autorizada(&a));
    // La conversacion va por tres puertos; el flujo que se reproduce es el de
    // Modbus, que es donde esta lo que mueve el mundo fisico.
    for (i, (bytes, _)) in conversacion().iter().enumerate() {
        c.capturar(&mut f, i as u64 * 1_000_000, bytes, bytes.len());
    }
    let capturados = c.vaciar();
    assert_eq!(capturados.len(), 4);

    // 2. Se escribe a PCAP y se vuelve a leer: el viaje por el disco.
    let mut e = Escritor::nuevo(pcap::ENLACE_IP_CRUDA, u32::MAX);
    for p in &capturados {
        e.anadir(p.cuando_ns, &p.datos, p.datos.len());
    }
    let fichero = e.terminar();
    let leidos = pcap::leer(&fichero, 1000).expect("se lee lo que se escribio");
    assert!(!leidos.cortado);
    assert_eq!(leidos.paquetes.len(), 4);

    // 3. Y se reproduce, veinte veces.
    let guardado = FlujoGuardado {
        entidad: eid,
        paquetes: leidos
            .paquetes
            .iter()
            .map(|l| Paquete {
                cuando_ns: l.cuando_ns,
                datos: l.datos.clone(),
            })
            .collect(),
        contexto: Contexto::tcp_cliente(502),
        bytes_tapados: f.tapados(),
        bytes_originales: f.vistos(),
    };

    let primera = reproducir(&guardado, &mut registro_completo(), 7_000_000);
    for vuelta in 1..20 {
        let otra = reproducir(&guardado, &mut registro_completo(), 7_000_000);
        assert_eq!(
            otra.veredicto,
            primera.veredicto,
            "la vuelta {vuelta} dio otro veredicto:\n  {}\n  {}",
            primera.veredicto.resumen(),
            otra.veredicto.resumen()
        );
        assert_eq!(otra.hechos, primera.hechos, "la vuelta {vuelta}");
        assert_eq!(otra.cobertura, primera.cobertura, "la vuelta {vuelta}");
    }

    // Y el veredicto reproducido dice algo: una reproduccion que no encontrara
    // nada seria determinista y no probaria nada.
    assert!(!primera.veredicto.porque.is_empty());
    assert!(
        primera
            .veredicto
            .senales
            .iter()
            .any(|s| s.porque.contains("cambia el estado del dispositivo")),
        "la escritura al PLC tiene que aparecer: {:?}",
        primera.veredicto.senales
    );
    println!("{}", primera.frase());
}

/// Un flujo intacto promete igualdad; uno con bytes tapados no, y lo dice.
#[test]
fn la_fidelidad_decide_que_se_puede_exigir() {
    let eid = entidad::maquina("portal");
    let con_credencial =
        b"POST /entrar HTTP/1.1\r\nHost: portal\r\n\r\nusuario=ana&password=lasecreta".to_vec();
    let sin_credencial = b"GET /index.html HTTP/1.1\r\nHost: portal\r\n\r\n".to_vec();

    let r = Redactor::nuevo();
    for (bytes, espera_tapado) in [(con_credencial, true), (sin_credencial, false)] {
        let limpio = r.limpiar(&bytes, Donde::default());
        assert_eq!(!limpio.intacto(), espera_tapado);

        let g = FlujoGuardado {
            entidad: eid.clone(),
            paquetes: vec![Paquete {
                cuando_ns: 1,
                datos: limpio.bytes().to_vec(),
            }],
            contexto: Contexto::tcp_cliente(80),
            bytes_tapados: limpio.bytes_tapados() as u64,
            bytes_originales: bytes.len() as u64,
        };
        if espera_tapado {
            assert!(matches!(g.fidelidad(), Fidelidad::ConTapados { .. }));
            assert!(!g.fidelidad().autoriza_exigir_igualdad());
        } else {
            assert_eq!(g.fidelidad(), Fidelidad::Exacta);
            assert!(g.fidelidad().autoriza_exigir_igualdad());
            // Y donde la fidelidad es exacta, se exige: dos reproducciones
            // iguales, byte a byte.
            let a = reproducir(&g, &mut registro_completo(), 1);
            let b = reproducir(&g, &mut registro_completo(), 1);
            assert_eq!(a.veredicto, b.veredicto);
            assert_eq!(a.hechos, b.hechos);
        }
    }
}

/// El determinismo tiene que aguantar el volumen: mil flujos distintos, cada uno
/// reproducido dos veces, y las dos mil veces el mismo resultado. Un `HashMap`
/// sin orden en cualquier punto del camino se nota aqui y no en cuatro paquetes.
#[test]
fn mil_flujos_distintos_reproducen_igual_los_dos_veces() {
    let mut registro = registro_completo();
    let mut diferencias = 0usize;

    for n in 0..1000u64 {
        // Trafico variado a proposito: cada familia de disectores por su camino.
        let bytes: Vec<u8> = match n % 5 {
            0 => vec![
                0x00,
                (n % 250) as u8 + 1,
                0x00,
                0x00,
                0x00,
                0x06,
                0x11,
                0x03,
                0x00,
                0x6B,
                0x00,
                0x03,
            ],
            1 => format!("*2\r\n$3\r\nGET\r\n$5\r\nc{n:04}\r\n").into_bytes(),
            2 => format!("GET /r{n} HTTP/1.1\r\nHost: web\r\n\r\n").into_bytes(),
            3 => vec![0x81, 0x0A, 0x00, 0x08, 0x01, 0x00, 0x10, 0x08],
            _ => format!("basura numero {n} que no es ningun protocolo").into_bytes(),
        };
        let ctx = match n % 5 {
            0 => Contexto::tcp_cliente(502),
            1 => Contexto::tcp_cliente(6379),
            2 => Contexto::tcp_cliente(80),
            3 => Contexto::udp(47808),
            _ => Contexto::tcp_cliente(31337),
        };
        let g = FlujoGuardado {
            entidad: entidad::maquina(&format!("m{n}")),
            paquetes: vec![Paquete {
                cuando_ns: n,
                datos: bytes,
            }],
            contexto: ctx,
            bytes_tapados: 0,
            bytes_originales: 0,
        };
        let a = reproducir(&g, &mut registro, n);
        let b = reproducir(&g, &mut registro_completo(), n);
        if a.veredicto != b.veredicto || a.hechos != b.hechos {
            diferencias += 1;
        }
    }
    assert_eq!(
        diferencias, 0,
        "hubo {diferencias} flujos que no reprodujeron igual"
    );
}

/// El orden de los paquetes es parte de la conversacion: un almacen que los
/// reordenara reproduciria otra cosa. Se comprueba invirtiendo el orden y
/// exigiendo que el resultado **cambie**, que es lo que demuestra que el orden
/// se esta conservando de verdad y no se esta ignorando.
#[test]
fn el_orden_de_los_paquetes_se_conserva_y_se_nota() {
    let eid = entidad::maquina("m");
    let pares: Vec<Vec<u8>> = vec![
        b"*3\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$3\r\ndir\r\n".to_vec(),
        b"*2\r\n$3\r\nGET\r\n$5\r\nclave\r\n".to_vec(),
    ];
    let hacer = |datos: Vec<Vec<u8>>| FlujoGuardado {
        entidad: eid.clone(),
        paquetes: datos
            .into_iter()
            .enumerate()
            .map(|(i, d)| Paquete {
                cuando_ns: i as u64,
                datos: d,
            })
            .collect(),
        contexto: Contexto::tcp_cliente(6379),
        bytes_tapados: 0,
        bytes_originales: 0,
    };
    let derecho = reproducir(&hacer(pares.clone()), &mut registro_completo(), 1);
    let del_reves = reproducir(
        &hacer(pares.into_iter().rev().collect()),
        &mut registro_completo(),
        1,
    );
    assert_ne!(
        derecho.hechos, del_reves.hechos,
        "si el orden no se notara, el almacen podria reordenar sin que nadie lo viera"
    );
    assert_eq!(derecho.hechos.len(), del_reves.hechos.len());
}
