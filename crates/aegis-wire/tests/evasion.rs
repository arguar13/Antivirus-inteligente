//! Los ataques de la FASE 70, ejercidos de extremo a extremo por la API publica.
//!
//! Esta suite no comprueba que las funciones internas hagan lo que dicen: eso ya
//! lo hacen las pruebas unitarias de cada modulo. Aqui se construyen **paquetes
//! de verdad, byte a byte**, se meten por el mismo sitio por el que entraria el
//! trafico real, y se comprueba que el sensor:
//!
//! 1. reconstruye lo que reconstruiria el destino,
//! 2. DELATA el intento, y
//! 3. sigue vivo y acotado despues.
//!
//! Las tres cosas juntas. Un sensor que resiste un ataque sin contarlo deja al
//! analista sin saber que le atacaron, y eso no es defensa: es un agujero con
//! buena cara.

use std::net::{IpAddr, Ipv4Addr};

use aegis_wire::hecho::Hecho;
use aegis_wire::motor::{ConfigMotor, Motor};
use aegis_wire::reensamblado::Politica;

const SYN: u8 = 0x02;
const ACK: u8 = 0x10;
const PSH: u8 = 0x08;
const FIN: u8 = 0x01;

/// Construye un paquete IPv4 + TCP completo, sin atajos.
fn tcp(
    origen: (u8, u16),
    destino: (u8, u16),
    secuencia: u32,
    banderas: u8,
    carga: &[u8],
) -> Vec<u8> {
    let total = 20 + 20 + carga.len();
    let mut p = vec![
        0x45,
        0x00,
        (total >> 8) as u8,
        total as u8,
        0x00,
        0x01,
        0x00,
        0x00,
        64,
        6,
        0x00,
        0x00,
        10,
        0,
        0,
        origen.0,
        10,
        0,
        0,
        destino.0,
    ];
    p.extend_from_slice(&origen.1.to_be_bytes());
    p.extend_from_slice(&destino.1.to_be_bytes());
    p.extend_from_slice(&secuencia.to_be_bytes());
    p.extend_from_slice(&0u32.to_be_bytes());
    p.push(5 << 4);
    p.push(banderas);
    p.extend_from_slice(&65535u16.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(carga);
    p
}

fn udp(origen: (u8, u16), destino: (u8, u16), carga: &[u8]) -> Vec<u8> {
    let total = 20 + 8 + carga.len();
    let mut p = vec![
        0x45,
        0x00,
        (total >> 8) as u8,
        total as u8,
        0x00,
        0x01,
        0x00,
        0x00,
        64,
        17,
        0x00,
        0x00,
        10,
        0,
        0,
        origen.0,
        10,
        0,
        0,
        destino.0,
    ];
    p.extend_from_slice(&origen.1.to_be_bytes());
    p.extend_from_slice(&destino.1.to_be_bytes());
    p.extend_from_slice(&((8 + carga.len()) as u16).to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(carga);
    p
}

/// EL ATAQUE DE PTACEK Y NEWSHAM, entero, por la puerta principal.
///
/// El atacante manda `GET /publico` y luego la misma secuencia con
/// `GET /secreto`. El sensor tiene que quedarse con lo mismo que el destino
/// —politica `PrimeroGana`— y ademas DECIR que vio la contradiccion.
#[test]
fn la_evasion_por_solape_se_resuelve_como_el_destino_y_se_delata() {
    let mut m = Motor::nuevo(ConfigMotor {
        politica: Politica::PrimeroGana,
        ..ConfigMotor::default()
    });
    m.alimentar_ip(1, &tcp((1, 50_000), (2, 80), 1000, SYN, &[]));
    m.alimentar_ip(2, &tcp((2, 80), (1, 50_000), 5000, SYN | ACK, &[]));

    let cabecera = b" HTTP/1.1\r\nHost: victima\r\n\r\n";
    // La cola primero: deja un hueco abierto.
    m.alimentar_ip(3, &tcp((1, 50_000), (2, 80), 1001 + 12, PSH, cabecera));
    // Y ahora las dos versiones contradictorias del principio.
    let hechos_a = m.alimentar_ip(4, &tcp((1, 50_000), (2, 80), 1001, PSH, b"GET /publico"));
    m.alimentar_ip(5, &tcp((1, 50_000), (2, 80), 1001, PSH, b"GET /secreto"));

    // 1. Se quedo con la PRIMERA, como haria el destino.
    let uri = hechos_a
        .iter()
        .find_map(|h| match &h.hecho {
            Hecho::PeticionHttp { uri, .. } => Some(uri.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no se vio la peticion: {hechos_a:?}"));
    assert_eq!(uri, "/publico", "la politica declarada es PrimeroGana");

    // 2. Y lo DELATA en el registro de la conexion.
    m.alimentar_ip(6, &tcp((1, 50_000), (2, 80), 1100, FIN | ACK, &[]));
    m.alimentar_ip(7, &tcp((2, 80), (1, 50_000), 5001, FIN | ACK, &[]));
    let registros = m.recolectar(8);
    assert_eq!(registros.len(), 1);
    assert!(
        registros[0].hay_indicio_de_evasion(),
        "resistir el ataque sin contarlo deja al analista sin saberlo: {:?}",
        registros[0]
    );
}

/// La MISMA forma de ataque con el mismo contenido es una retransmision
/// normalisima. Si levantara la señal, la señal no valdria para nada.
#[test]
fn la_retransmision_legitima_no_levanta_la_senal() {
    let mut m = Motor::nuevo(ConfigMotor::default());
    m.alimentar_ip(1, &tcp((1, 50_000), (2, 80), 1000, SYN, &[]));
    m.alimentar_ip(2, &tcp((2, 80), (1, 50_000), 5000, SYN | ACK, &[]));

    let peticion = b"GET /index HTTP/1.1\r\nHost: v\r\n\r\n";
    m.alimentar_ip(3, &tcp((1, 50_000), (2, 80), 1001, PSH, peticion));
    m.alimentar_ip(4, &tcp((1, 50_000), (2, 80), 1001, PSH, peticion));

    m.alimentar_ip(5, &tcp((1, 50_000), (2, 80), 1100, FIN | ACK, &[]));
    m.alimentar_ip(6, &tcp((2, 80), (1, 50_000), 5001, FIN | ACK, &[]));
    let registros = m.recolectar(7);
    assert_eq!(registros.len(), 1);
    assert!(
        !registros[0].hay_indicio_de_evasion(),
        "el trafico normal no puede parecer un ataque: {:?}",
        registros[0]
    );
}

/// La politica se declara y se OBEDECE: con `UltimoGana` el sensor imita a la
/// otra familia de pilas. Elegir mal abre la evasion; por eso se elige aparte y
/// por eso esto se comprueba.
#[test]
fn la_politica_declarada_cambia_de_verdad_lo_que_se_reconstruye() {
    let mut reconstruido = Vec::new();
    for politica in [Politica::PrimeroGana, Politica::UltimoGana] {
        let mut m = Motor::nuevo(ConfigMotor {
            politica,
            ..ConfigMotor::default()
        });
        m.alimentar_ip(1, &tcp((1, 50_000), (2, 80), 1000, SYN, &[]));
        // Dos versiones RETENIDAS en la misma secuencia, del mismo largo para
        // que la unica diferencia sea cual gana. Hay un hueco de cuatro bytes
        // por delante, asi que las dos esperan.
        let publico = b"/publico HTTP/1.1\r\nHost: v\r\n\r\n";
        let secreto = b"/secreto HTTP/1.1\r\nHost: v\r\n\r\n";
        assert_eq!(publico.len(), secreto.len());
        m.alimentar_ip(2, &tcp((1, 50_000), (2, 80), 1005, PSH, publico));
        m.alimentar_ip(3, &tcp((1, 50_000), (2, 80), 1005, PSH, secreto));
        // Y ahora se tapa el hueco: se entrega lo que la politica haya elegido.
        let hechos = m.alimentar_ip(4, &tcp((1, 50_000), (2, 80), 1001, PSH, b"GET "));
        let todo: Vec<String> = hechos
            .iter()
            .filter_map(|h| match &h.hecho {
                Hecho::PeticionHttp { uri, .. } => Some(uri.clone()),
                _ => None,
            })
            .collect();
        reconstruido.push(todo);
    }
    assert_ne!(
        reconstruido[0], reconstruido[1],
        "si las dos politicas reconstruyen lo mismo, la politica no existe"
    );
}

/// El contrabando de peticiones HTTP: `Content-Length` y `Transfer-Encoding` a
/// la vez. Es como se cuela una peticion entera por delante de un proxy.
#[test]
fn el_contrabando_de_peticiones_http_se_delata() {
    let mut m = Motor::nuevo(ConfigMotor::default());
    m.alimentar_ip(1, &tcp((1, 50_000), (2, 80), 1000, SYN, &[]));
    let peticion = b"POST /a HTTP/1.1\r\nHost: v\r\nContent-Length: 6\r\n\
                     Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    let hechos = m.alimentar_ip(2, &tcp((1, 50_000), (2, 80), 1001, PSH, peticion));
    assert!(
        hechos.iter().any(|h| matches!(
            &h.hecho,
            Hecho::AnomaliaDeFlujo {
                codigo: "http-contrabando-cl-te",
                ..
            }
        )),
        "{hechos:?}"
    );
}

/// Un bucle de punteros de compresion DNS: el clasico que cuelga a un disector
/// ingenuo. Tiene que cortar, no colgarse, y no dar un nombre inventado.
#[test]
fn un_bucle_de_punteros_dns_no_cuelga_al_sensor() {
    let mut m = Motor::nuevo(ConfigMotor::default());
    let mut consulta = Vec::new();
    consulta.extend_from_slice(&0x1234u16.to_be_bytes());
    consulta.extend_from_slice(&0x0100u16.to_be_bytes());
    consulta.extend_from_slice(&1u16.to_be_bytes());
    consulta.extend_from_slice(&[0u8; 6]);
    // Un puntero en el offset 12 que apunta a si mismo.
    consulta.extend_from_slice(&[0xC0, 0x0C]);
    consulta.extend_from_slice(&1u16.to_be_bytes());
    consulta.extend_from_slice(&1u16.to_be_bytes());

    // Si esto no termina, la prueba no termina: ese ES el ataque.
    let hechos = m.alimentar_ip(1, &udp((1, 40_000), (2, 53), &consulta));
    assert!(
        !hechos
            .iter()
            .any(|h| matches!(&h.hecho, Hecho::ConsultaDns { .. })),
        "un nombre que no se pudo leer no puede salir como si se hubiera leido: {hechos:?}"
    );
}

/// Un fichero descargado por HTTP se extrae con su tipo REAL y su hash, aunque
/// venga anunciado como otra cosa y troceado en muchos paquetes.
#[test]
fn un_ejecutable_disfrazado_de_pdf_se_extrae_y_se_delata() {
    let mut m = Motor::nuevo(ConfigMotor::default());
    m.alimentar_ip(1, &tcp((1, 50_000), (2, 80), 1000, SYN, &[]));
    m.alimentar_ip(2, &tcp((2, 80), (1, 50_000), 5000, SYN | ACK, &[]));

    let mut cuerpo = b"MZ\x90\x00".to_vec();
    cuerpo.resize(4096, 0x90);
    let cabeceras = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/pdf\r\n\
         Content-Disposition: attachment; filename=\"..\\\\..\\\\informe.pdf\"\r\n\
         Content-Length: {}\r\n\r\n",
        cuerpo.len()
    );

    let mut sec = 5001u32;
    let mut hechos = m.alimentar_ip(
        3,
        &tcp((2, 80), (1, 50_000), sec, PSH | ACK, cabeceras.as_bytes()),
    );
    sec = sec.wrapping_add(cabeceras.len() as u32);
    for trozo in cuerpo.chunks(512) {
        hechos.extend(m.alimentar_ip(4, &tcp((2, 80), (1, 50_000), sec, PSH, trozo)));
        sec = sec.wrapping_add(trozo.len() as u32);
    }

    let (nombre, tamano) = hechos
        .iter()
        .find_map(|h| match &h.hecho {
            Hecho::FicheroTransferido { nombre, tamano, .. } => Some((nombre.clone(), *tamano)),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no se extrajo: {hechos:?}"));
    assert_eq!(tamano, cuerpo.len());
    assert_eq!(
        nombre, "informe.pdf",
        "el nombre se queda sin ruta: un nombre con «..» es un intento de escribir fuera de sitio"
    );
    assert!(
        hechos.iter().any(|h| matches!(
            &h.hecho,
            Hecho::AnomaliaDeFlujo {
                codigo: "fichero-tipo-contradictorio",
                ..
            }
        )),
        "{hechos:?}"
    );
}

/// UN MENSAJE SE CUENTA UNA VEZ. El disector siempre empieza por el principio
/// del bufer, asi que conservar lo ya interpretado haria que cada paquete
/// volviera a emitir los mismos hechos: ruido que entierra lo que si es nuevo.
#[test]
fn un_mismo_mensaje_no_se_cuenta_dos_veces() {
    let mut m = Motor::nuevo(ConfigMotor::default());
    m.alimentar_ip(1, &tcp((1, 50_000), (2, 80), 1000, SYN, &[]));

    let peticion = b"GET /una-sola-vez HTTP/1.1\r\nHost: v\r\n\r\n";
    let primeros = m.alimentar_ip(2, &tcp((1, 50_000), (2, 80), 1001, PSH, peticion));
    assert_eq!(cuantas_peticiones(&primeros), 1);

    // Llegan mas bytes del mismo sentido, que NO forman un mensaje nuevo.
    let despues = m.alimentar_ip(
        3,
        &tcp(
            (1, 50_000),
            (2, 80),
            1001 + peticion.len() as u32,
            PSH,
            b"GET /a-medi",
        ),
    );
    assert_eq!(
        cuantas_peticiones(&despues),
        0,
        "la peticion anterior no puede volver a contarse: {despues:?}"
    );
}

/// Y EL REVERSO, que es el que deja ciego al sensor: con reutilizacion de
/// conexion —lo normal desde HTTP/1.1— detras de una peticion viene otra. Si la
/// primera no se aparta, la segunda no se llega a ver NUNCA.
#[test]
fn en_una_conexion_reutilizada_se_ven_todas_las_peticiones() {
    let mut m = Motor::nuevo(ConfigMotor::default());
    m.alimentar_ip(1, &tcp((1, 50_000), (2, 80), 1000, SYN, &[]));

    let mut vistas = Vec::new();
    let mut sec = 1001u32;
    for i in 0..5u32 {
        let peticion = format!("GET /recurso-{i} HTTP/1.1\r\nHost: v\r\n\r\n");
        let hechos = m.alimentar_ip(
            u64::from(i) + 2,
            &tcp((1, 50_000), (2, 80), sec, PSH, peticion.as_bytes()),
        );
        sec = sec.wrapping_add(peticion.len() as u32);
        for h in &hechos {
            if let Hecho::PeticionHttp { uri, .. } = &h.hecho {
                vistas.push(uri.clone());
            }
        }
    }
    assert_eq!(
        vistas,
        vec![
            "/recurso-0",
            "/recurso-1",
            "/recurso-2",
            "/recurso-3",
            "/recurso-4"
        ],
        "hay que ver TODAS, una vez cada una"
    );
}

/// Y las cinco pegadas en un solo tramo, que es como llegan de verdad cuando el
/// cliente encadena peticiones sin esperar respuesta.
#[test]
fn cinco_peticiones_pegadas_en_un_tramo_se_ven_las_cinco() {
    let mut m = Motor::nuevo(ConfigMotor::default());
    m.alimentar_ip(1, &tcp((1, 50_000), (2, 80), 1000, SYN, &[]));

    let mut tramo = Vec::new();
    for i in 0..5u32 {
        tramo.extend_from_slice(format!("GET /p{i} HTTP/1.1\r\nHost: v\r\n\r\n").as_bytes());
    }
    let hechos = m.alimentar_ip(2, &tcp((1, 50_000), (2, 80), 1001, PSH, &tramo));
    assert_eq!(cuantas_peticiones(&hechos), 5, "{hechos:?}");
}

/// Una sesion TLS larga no puede hacer crecer la memoria del motor. Los
/// registros cifrados no se pueden leer, pero SI se pueden enmarcar, y
/// apartarlos es lo unico que impide que la memoria se vaya en justo lo que
/// nunca se va a poder interpretar.
#[test]
fn una_sesion_tls_larga_no_acumula_lo_que_no_puede_leer() {
    let mut m = Motor::nuevo(ConfigMotor::default());
    m.alimentar_ip(1, &tcp((1, 50_000), (2, 443), 1000, SYN, &[]));
    m.alimentar_ip(2, &tcp((2, 443), (1, 50_000), 5000, SYN | ACK, &[]));

    let mut sec = 1001u32;
    for i in 0..2_000u32 {
        // Un registro de datos de aplicacion: tipo 23, version 0x0303.
        let carga = vec![0xA5u8; 1024];
        let mut registro = vec![23u8, 0x03, 0x03];
        registro.extend_from_slice(&(carga.len() as u16).to_be_bytes());
        registro.extend_from_slice(&carga);
        m.alimentar_ip(
            u64::from(i) + 3,
            &tcp((1, 50_000), (2, 443), sec, PSH, &registro),
        );
        sec = sec.wrapping_add(registro.len() as u32);
    }
    assert!(
        m.memoria() < 64 * 1024,
        "una sesion cifrada no puede acumular: {} bytes",
        m.memoria()
    );
}

fn cuantas_peticiones(hechos: &[aegis_wire::hecho::HechoConContexto]) -> usize {
    hechos
        .iter()
        .filter(|h| matches!(&h.hecho, Hecho::PeticionHttp { .. }))
        .count()
}

/// LA COTA, ejercida como ataque: miles de flujos reteniendo a la vez. El sensor
/// tiene que seguir en pie, por debajo de su techo, y CONTAR lo que tiro.
#[test]
fn un_ataque_de_agotamiento_de_memoria_no_tumba_al_sensor() {
    const TECHO: usize = 512 * 1024;
    let mut m = Motor::nuevo(ConfigMotor {
        max_memoria: TECHO,
        max_memoria_app: TECHO,
        ..ConfigMotor::default()
    });

    let relleno = vec![b'Z'; 1400];
    for i in 0..5_000u32 {
        let puerto = (i % 60_000) as u16 + 1024;
        m.alimentar_ip(u64::from(i), &tcp((1, puerto), (2, 445), 1000, SYN, &[]));
        // Muy por delante: se retiene y no se libera nunca.
        m.alimentar_ip(
            u64::from(i),
            &tcp((1, puerto), (2, 445), 900_000, PSH, &relleno),
        );
    }

    assert!(
        m.memoria() <= TECHO * 2,
        "memoria = {} con techo {TECHO}",
        m.memoria()
    );
    assert!(
        m.tabla().contadores().expulsados_por_memoria > 0,
        "lo que se tira se cuenta: {:?}",
        m.tabla().contadores()
    );
    // Y sigue funcionando: un flujo limpio despues del ataque se ve igual.
    m.alimentar_ip(999_999, &tcp((3, 50_000), (4, 80), 1000, SYN, &[]));
    let hechos = m.alimentar_ip(
        1_000_000,
        &tcp(
            (3, 50_000),
            (4, 80),
            1001,
            PSH,
            b"GET /vivo HTTP/1.1\r\nHost: v\r\n\r\n",
        ),
    );
    assert!(
        hechos
            .iter()
            .any(|h| matches!(&h.hecho, Hecho::PeticionHttp { .. })),
        "el sensor tiene que seguir viendo despues del ataque: {hechos:?}"
    );
}

/// Un fragmento IP POSTERIOR no lleva cabecera de transporte. Analizarlo como
/// TCP leeria carga util como puertos y secuencia, e inyectaria bytes elegidos
/// por el atacante en el reensamblador.
#[test]
fn un_fragmento_posterior_no_se_analiza_como_transporte() {
    let mut m = Motor::nuevo(ConfigMotor::default());
    let mut p = tcp(
        (1, 50_000),
        (2, 80),
        1001,
        PSH,
        b"GET /real HTTP/1.1\r\n\r\n",
    );
    // Desplazamiento de fragmento distinto de cero: NO es el primer fragmento.
    p[6] = 0x00;
    p[7] = 0x10; // desplazamiento 16 (x8 = 128 bytes)
    let hechos = m.alimentar_ip(1, &p);

    assert!(hechos.is_empty(), "{hechos:?}");
    assert_eq!(
        m.contadores().fragmentados,
        1,
        "y se cuenta, para que el agujero de visibilidad se vea"
    );
    assert_eq!(m.flujos_vivos(), 0, "ni siquiera se abre el flujo");
}

/// La clave de flujo es la misma en los dos sentidos: si no lo fuera, cada
/// conversacion se partiria en dos y el reensamblado no funcionaria.
#[test]
fn los_dos_sentidos_caen_en_el_mismo_flujo() {
    let mut m = Motor::nuevo(ConfigMotor::default());
    m.alimentar_ip(1, &tcp((1, 50_000), (2, 80), 1000, SYN, &[]));
    m.alimentar_ip(2, &tcp((2, 80), (1, 50_000), 5000, SYN | ACK, &[]));
    assert_eq!(m.flujos_vivos(), 1);

    let ip_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let registros = {
        m.alimentar_ip(3, &tcp((1, 50_000), (2, 80), 1001, FIN | ACK, &[]));
        m.alimentar_ip(4, &tcp((2, 80), (1, 50_000), 5001, FIN | ACK, &[]));
        m.recolectar(5)
    };
    assert_eq!(registros.len(), 1);
    assert_eq!(registros[0].origen, ip_a.to_string());
    assert!(
        registros[0].inicio_visto,
        "con SYN y SYN+ACK se sabe quien abrio, y se dice"
    );
}

/// Ningun paquete arbitrario puede tumbar al motor. El atacante manda lo que
/// quiere; un panico en el camino de paquete es una denegacion de servicio.
#[test]
fn ninguna_secuencia_arbitraria_de_paquetes_provoca_panico() {
    let mut m = Motor::nuevo(ConfigMotor::default());
    let mut semilla = 0x243F_6A88_85A3_08D3u64;
    for i in 0..4_000u64 {
        semilla = semilla
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let n = (semilla % 200) as usize;
        let datos: Vec<u8> = (0..n)
            .map(|j| ((semilla >> (j % 56)) as u8).wrapping_add(j as u8))
            .collect();
        let _ = m.alimentar_ip(i, &datos);
        let _ = m.alimentar_ethernet(i, &datos);
    }
    let _ = m.recolectar(u64::MAX);
    let _ = m.vaciar();
}
