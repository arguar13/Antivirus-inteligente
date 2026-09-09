//! Pruebas de la malla.
//!
//! La propagacion se prueba con SOCKETS UDP DE VERDAD sobre la interfaz local:
//! tres agentes distintos, cada uno con su clave de sesion y su identidad, que
//! se hablan por la red. Los ataques —repeticion, clave equivocada, basura,
//! inundacion— se lanzan desde un socket externo, como los lanzaria alguien que
//! esta en la misma red local.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use aegis_mesh::crypto::{self, ReplayWindow};
use aegis_mesh::mesh::{DropReason, Mesh, MeshConfig};
use aegis_mesh::vaccine::{Severity, Vaccine};
use aegis_mesh::wire::{self, Header, MsgType, HEADER_LEN, MAX_DATAGRAM, VERSION};
use aegis_sync::ioc::{Ioc, IocKind};

const CLAVE: [u8; 32] = [0x5a; 32];
const AHORA: u64 = 1_700_000_000;

fn local(puerto: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), puerto)
}

fn config(peers: Vec<SocketAddr>) -> MeshConfig {
    MeshConfig {
        bind: local(0),
        peers,
        key: CLAVE,
        ..MeshConfig::default()
    }
}

fn vacuna() -> Vaccine {
    Vaccine::new(
        Ioc::new(IocKind::FileSha256, "e".repeat(64)),
        Severity::Confirmed,
        AHORA,
    )
    .with_techniques(vec!["T1055".into(), "T1486".into()])
}

// ---------------------------------------------------------------------------
// Formato
// ---------------------------------------------------------------------------

#[test]
fn la_cabecera_va_y_vuelve_identica() {
    let h = Header {
        version: VERSION,
        msg_type: MsgType::Vaccine,
        session: [1, 2, 3, 4, 5, 6, 7, 8],
        counter: 0xDEAD_BEEF,
        node: [9u8; 16],
    };
    let b = h.encode();
    assert_eq!(b.len(), HEADER_LEN);
    assert_eq!(Header::decode(&b), Some(h));
    // El nonce es sesion mas contador, sin solaparse.
    let n = h.nonce();
    assert_eq!(&n[..8], &h.session);
    assert_eq!(&n[8..], &h.counter.to_le_bytes());
}

#[test]
fn una_cabecera_que_no_es_de_la_malla_se_rechaza() {
    assert_eq!(Header::decode(&[]), None);
    assert_eq!(Header::decode(&[0u8; HEADER_LEN - 1]), None);
    let mut b = Header {
        version: VERSION,
        msg_type: MsgType::Announce,
        session: [0; 8],
        counter: 1,
        node: [0; 16],
    }
    .encode();
    b[0] ^= 0xff; // magia rota
    assert_eq!(Header::decode(&b), None);

    let mut b2 = b;
    b2[0] ^= 0xff;
    b2[5] = 99; // tipo desconocido
    assert_eq!(Header::decode(&b2), None);
}

#[test]
fn la_vacuna_va_y_vuelve_identica() {
    let v = vacuna();
    let b = wire::encode_vaccine(&v);
    assert_eq!(wire::decode_vaccine(&b), Some(v.clone()));

    // Y sin tecnicas tambien, que es el caso mas comun.
    let simple = Vaccine::new(
        Ioc::new(IocKind::Ip, "198.51.100.9"),
        Severity::Contained,
        5,
    );
    let b = wire::encode_vaccine(&simple);
    assert_eq!(wire::decode_vaccine(&b), Some(simple));
}

#[test]
fn un_cuerpo_manipulado_no_desborda_ni_panica() {
    // Longitudes elegidas por un atacante: `16 + valor + tecnicas` puede
    // desbordar y dar un total pequeno que pase una validacion ingenua.
    let mut b = wire::encode_vaccine(&vacuna());
    b[12..14].copy_from_slice(&u16::MAX.to_le_bytes());
    b[14..16].copy_from_slice(&u16::MAX.to_le_bytes());
    assert_eq!(wire::decode_vaccine(&b), None);

    for corte in 0..b.len() {
        // Ningun truncamiento puede provocar un panico.
        let _ = wire::decode_vaccine(&b[..corte]);
    }
    assert_eq!(wire::decode_vaccine(&[]), None);
}

// ---------------------------------------------------------------------------
// Cifrado
// ---------------------------------------------------------------------------

#[test]
fn el_sellado_protege_el_contenido_y_la_cabecera() {
    let nonce = [7u8; 12];
    let aad = b"cabecera";
    let sellado = crypto::seal(&CLAVE, &nonce, aad, b"vacuna").unwrap();
    assert_eq!(
        crypto::open(&CLAVE, &nonce, aad, &sellado).unwrap(),
        b"vacuna"
    );

    // Otra clave, no.
    assert!(crypto::open(&[0u8; 32], &nonce, aad, &sellado).is_err());
    // Otro nonce, no.
    assert!(crypto::open(&CLAVE, &[8u8; 12], aad, &sellado).is_err());
    // Cabecera manipulada: es lo que impide cambiar el remitente de un mensaje
    // valido y hacer que la flota atribuya la vacuna a otro equipo.
    assert!(crypto::open(&CLAVE, &nonce, b"cabecerA", &sellado).is_err());
    // Un solo bit del texto cifrado.
    let mut roto = sellado.clone();
    roto[0] ^= 1;
    assert!(crypto::open(&CLAVE, &nonce, aad, &roto).is_err());
}

#[test]
fn la_ventana_de_repeticion_hace_su_trabajo() {
    let mut w = ReplayWindow::new();
    assert!(w.accept(10), "el primero siempre entra");
    assert!(!w.accept(10), "y no dos veces");
    assert!(w.accept(11));
    assert!(w.accept(9), "fuera de orden pero dentro de la ventana");
    assert!(!w.accept(9));
    assert_eq!(w.highest(), 11);

    // Demasiado viejo: no se puede afirmar que no se vio, asi que se rechaza.
    assert!(w.accept(200));
    assert!(!w.accept(100));
    assert!(w.accept(190), "190 sigue dentro de la ventana de 64");

    // Un salto enorme reinicia el mapa sin perder la garantia.
    let mut w2 = ReplayWindow::new();
    assert!(w2.accept(1));
    assert!(w2.accept(1_000_000));
    assert!(!w2.accept(1), "lo viejo ya no se acepta");
    assert!(!w2.accept(1_000_000));
}

// ---------------------------------------------------------------------------
// Propagacion real
// ---------------------------------------------------------------------------

#[test]
fn una_vacuna_llega_al_vecino_y_este_la_reenvia() {
    // Tres agentes en cadena: A conoce a B, B conoce a C. C solo puede
    // enterarse si B reenvia, que es la razon de existir de la malla.
    let mut c = Mesh::bind(config(vec![])).unwrap();
    let dir_c = c.local_addr();
    let mut b = Mesh::bind(config(vec![dir_c])).unwrap();
    let dir_b = b.local_addr();
    let mut a = Mesh::bind(config(vec![dir_b])).unwrap();

    let v = vacuna();
    assert_eq!(a.broadcast(&v).unwrap(), 1);

    let en_b = b.poll(Duration::from_millis(500), AHORA);
    assert_eq!(en_b.len(), 1, "B tiene que recibirla");
    assert_eq!(en_b[0].vaccine.ioc, v.ioc);
    assert_eq!(en_b[0].vaccine.hops, 0, "le llego de primera mano");
    assert!(en_b[0].relayed, "y la reenvio");
    assert_eq!(en_b[0].from_node, a.node_id());

    let en_c = c.poll(Duration::from_millis(500), AHORA);
    assert_eq!(en_c.len(), 1, "C se entera por el reenvio de B");
    assert_eq!(en_c[0].vaccine.ioc, v.ioc);
    assert_eq!(en_c[0].vaccine.hops, 1, "ha dado un salto");
    assert_eq!(en_c[0].from_node, b.node_id());

    assert_eq!(b.stats().accepted, 1);
    assert_eq!(b.stats().relayed, 1);
}

#[test]
fn la_misma_vacuna_no_da_vueltas_para_siempre() {
    // Dos agentes que se conocen mutuamente: sin deduplicacion se reenviarian
    // lo mismo el uno al otro hasta saturar la red local.
    let mut a = Mesh::bind(config(vec![])).unwrap();
    let dir_a = a.local_addr();
    let mut b = Mesh::bind(config(vec![dir_a])).unwrap();
    a.add_peer(b.local_addr());

    a.broadcast(&vacuna()).unwrap();
    assert_eq!(b.poll(Duration::from_millis(300), AHORA).len(), 1);

    // El reenvio de B vuelve a A, que ya la conoce.
    let vuelta = a.poll(Duration::from_millis(300), AHORA);
    assert!(vuelta.is_empty(), "A ya la habia visto: {vuelta:?}");
    assert!(a.stats().drops_of(DropReason::Duplicate) >= 1);

    // Y B no la vuelve a aceptar por el eco.
    let eco = b.poll(Duration::from_millis(200), AHORA);
    assert!(eco.is_empty());
}

#[test]
fn el_limite_de_saltos_corta_la_propagacion() {
    let mut c = Mesh::bind(config(vec![])).unwrap();
    let mut b = Mesh::bind(MeshConfig {
        max_hops: 0, // B no puede reenviar nada
        ..config(vec![c.local_addr()])
    })
    .unwrap();
    let mut a = Mesh::bind(config(vec![b.local_addr()])).unwrap();

    a.broadcast(&vacuna()).unwrap();
    let en_b = b.poll(Duration::from_millis(300), AHORA);
    assert_eq!(en_b.len(), 1, "B si la recibe");
    assert!(!en_b[0].relayed, "pero no la reenvia");
    assert!(b.stats().drops_of(DropReason::HopsExhausted) >= 1);
    assert!(c.poll(Duration::from_millis(200), AHORA).is_empty());
}

// ---------------------------------------------------------------------------
// Ataques
// ---------------------------------------------------------------------------

#[test]
fn un_intruso_sin_la_clave_no_puede_inyectar_vacunas() {
    let mut b = Mesh::bind(config(vec![])).unwrap();
    let dir_b = b.local_addr();
    // Un agente de otra malla, con otra clave.
    let mut intruso = Mesh::bind(MeshConfig {
        key: [0xAA; 32],
        ..config(vec![dir_b])
    })
    .unwrap();

    intruso.broadcast(&vacuna()).unwrap();
    let r = b.poll(Duration::from_millis(300), AHORA);
    assert!(r.is_empty(), "no puede colar nada: {r:?}");
    assert_eq!(b.stats().drops_of(DropReason::NotAuthentic), 1);
}

#[test]
fn repetir_un_datagrama_capturado_no_cuela_dos_veces() {
    // Alguien en la misma red captura un datagrama valido y lo reenvia. El AEAD
    // no lo impide —el mensaje ES autentico—, asi que hace falta la ventana.
    let espia = UdpSocket::bind(local(0)).unwrap();
    let dir_espia = espia.local_addr().unwrap();
    let mut a = Mesh::bind(config(vec![dir_espia])).unwrap();
    let mut b = Mesh::bind(config(vec![])).unwrap();
    let dir_b = b.local_addr();

    a.broadcast(&vacuna()).unwrap();
    let mut buf = [0u8; MAX_DATAGRAM];
    espia
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let (n, _) = espia
        .recv_from(&mut buf)
        .expect("el espia captura el datagrama");

    // Lo entrega dos veces a B.
    espia.send_to(&buf[..n], dir_b).unwrap();
    assert_eq!(b.poll(Duration::from_millis(300), AHORA).len(), 1);

    espia.send_to(&buf[..n], dir_b).unwrap();
    let segunda = b.poll(Duration::from_millis(300), AHORA);
    assert!(
        segunda.is_empty(),
        "la repeticion no puede colar: {segunda:?}"
    );
    assert_eq!(b.stats().drops_of(DropReason::Replay), 1);
}

#[test]
fn la_basura_no_tumba_la_malla() {
    let atacante = UdpSocket::bind(local(0)).unwrap();
    let mut b = Mesh::bind(config(vec![])).unwrap();
    let dir_b = b.local_addr();

    // Basura de todos los tamanos, incluida la que empieza como un mensaje
    // valido y se corta a mitad.
    let valido = {
        let mut a = Mesh::bind(config(vec![dir_b])).unwrap();
        a.broadcast(&vacuna()).unwrap();
        b.poll(Duration::from_millis(300), AHORA)
    };
    assert_eq!(valido.len(), 1);

    for n in [0usize, 1, 4, 35, 36, 37, 100, 1199] {
        let basura = vec![0xABu8; n];
        let _ = atacante.send_to(&basura, dir_b);
    }
    let r = b.poll(Duration::from_millis(300), AHORA);
    assert!(r.is_empty(), "nada de eso puede pasar por vacuna: {r:?}");

    // Y despues de todo eso, la malla sigue funcionando.
    let mut a2 = Mesh::bind(config(vec![dir_b])).unwrap();
    let otra = Vaccine::new(
        Ioc::new(IocKind::Domain, "malo.example"),
        Severity::Confirmed,
        AHORA,
    );
    a2.broadcast(&otra).unwrap();
    let r = b.poll(Duration::from_millis(500), AHORA);
    assert_eq!(r.len(), 1, "la malla tiene que seguir viva");
}

#[test]
fn un_par_que_inunda_se_descarta_sin_descifrar() {
    // La comprobacion de tasa va ANTES del descifrado: dejar que un atacante
    // fuerce un AES-GCM por datagrama es regalarle un amplificador de CPU.
    let mut b = Mesh::bind(MeshConfig {
        rate_per_peer: 3,
        rate_window: Duration::from_secs(60),
        ..config(vec![])
    })
    .unwrap();
    let dir_b = b.local_addr();
    let mut a = Mesh::bind(config(vec![dir_b])).unwrap();

    for i in 0..20u64 {
        let v = Vaccine::new(
            Ioc::new(IocKind::FileSha256, format!("{i:064}")),
            Severity::Confirmed,
            AHORA,
        );
        a.broadcast(&v).unwrap();
    }
    let r = b.poll(Duration::from_millis(500), AHORA);
    assert!(r.len() <= 3, "la tasa acota lo aceptado: {}", r.len());
    assert!(b.stats().drops_of(DropReason::RateLimited) > 0);
}

#[test]
fn una_vacuna_vieja_o_del_futuro_no_se_acepta() {
    let mut b = Mesh::bind(config(vec![])).unwrap();
    let dir_b = b.local_addr();
    let mut a = Mesh::bind(config(vec![dir_b])).unwrap();

    // Capturada hace un ano y reinyectada.
    let vieja = Vaccine::new(Ioc::new(IocKind::Ip, "203.0.113.1"), Severity::Confirmed, 1);
    a.broadcast(&vieja).unwrap();
    assert!(b.poll(Duration::from_millis(300), AHORA).is_empty());
    assert!(b.stats().drops_of(DropReason::Stale) >= 1);

    // Fechada en el futuro para que no caduque nunca.
    let futura = Vaccine::new(
        Ioc::new(IocKind::Ip, "203.0.113.2"),
        Severity::Confirmed,
        AHORA + 100_000,
    );
    a.broadcast(&futura).unwrap();
    assert!(b.poll(Duration::from_millis(300), AHORA).is_empty());
    assert!(b.stats().drops_of(DropReason::Stale) >= 2);
}

#[test]
fn la_memoria_de_vacunas_vistas_esta_acotada() {
    // Sin cota, un atacante con la clave haria crecer la memoria del agente sin
    // limite emitiendo vacunas distintas.
    let mut a = Mesh::bind(MeshConfig {
        dedup_capacity: 16,
        ..config(vec![])
    })
    .unwrap();
    for i in 0..500u64 {
        let v = Vaccine::new(
            Ioc::new(IocKind::FileSha256, format!("{i:064}")),
            Severity::Suspicious,
            AHORA,
        );
        a.broadcast(&v).unwrap();
    }
    assert!(a.remembered() <= 16, "recordadas: {}", a.remembered());
}

#[test]
fn una_vacuna_solo_puede_anadir() {
    // Es la decision de seguridad que define el crate: con clave compartida, un
    // atacante que comprometa UN equipo puede emitir mensajes validos, y si
    // pudiera retirar indicadores desactivaria la flota entera con un datagrama.
    // La prueba es estructural: el formato no tiene forma de expresar una
    // retirada, asi que ninguna combinacion de bytes la produce.
    let v = vacuna();
    let b = wire::encode_vaccine(&v);
    let recuperada = wire::decode_vaccine(&b).unwrap();
    assert_eq!(recuperada.severity, v.severity);
    // Todas las gravedades representables son grados de "esto es malo".
    for t in 1..=3u8 {
        assert!(Severity::from_tag(t).is_some());
    }
    assert!(Severity::from_tag(0).is_none());
    assert!(Severity::from_tag(4).is_none());
}

#[test]
fn el_nodo_ignora_sus_propios_mensajes() {
    // En una malla con multidifusion, el propio anuncio vuelve. No es un ataque.
    let mut a = Mesh::bind(config(vec![])).unwrap();
    let dir = a.local_addr();
    a.add_peer(dir);
    a.announce().unwrap();
    let r = a.poll(Duration::from_millis(300), AHORA);
    assert!(r.is_empty());
    assert!(a.stats().drops_of(DropReason::Loopback) >= 1);
}

#[test]
fn un_par_caido_no_impide_avisar_a_los_demas() {
    // En una red local, "puerto no alcanzable" es lo normal cuando un equipo se
    // apaga. No puede dejar sin vacuna a los que si estan.
    let mut vivo = Mesh::bind(config(vec![])).unwrap();
    let muerto = {
        let s = UdpSocket::bind(local(0)).unwrap();
        let d = s.local_addr().unwrap();
        drop(s); // el puerto queda sin nadie escuchando
        d
    };
    let mut a = Mesh::bind(config(vec![muerto, vivo.local_addr()])).unwrap();

    a.broadcast(&vacuna()).unwrap();
    let r = vivo.poll(Duration::from_millis(500), AHORA);
    assert_eq!(r.len(), 1, "el que esta vivo se entera igual");
}

#[test]
fn el_mensaje_no_cabe_si_es_enorme() {
    // Fragmentar seria peor: un fragmento perdido pierde el mensaje entero y
    // reensamblar es una superficie de ataque clasica.
    let mut a = Mesh::bind(config(vec![])).unwrap();
    let gigante = Vaccine::new(
        Ioc::new(IocKind::Domain, "x".repeat(2000)),
        Severity::Confirmed,
        AHORA,
    );
    let e = a.broadcast(&gigante).unwrap_err();
    assert!(
        matches!(e, aegis_mesh::MeshError::TooLarge { .. }),
        "llego {e:?}"
    );
}
