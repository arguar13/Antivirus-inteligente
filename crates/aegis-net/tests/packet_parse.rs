//! Pruebas del analizador de cabeceras.
//!
//! El enfasis esta en los paquetes MALFORMADOS. Un analizador que solo se prueba
//! con trafico bien formado se rompe con el primer paquete que un atacante
//! fabrica a proposito, y esos bytes los controla el atacante integramente.

use std::net::Ipv4Addr;

use aegis_net::packet::{
    EthHeader, Ipv4Header, PacketBuilder, ParseError, TcpFlags, TcpHeader, Transport,
    ETHERTYPE_IPV4, ETHERTYPE_IPV6, ETHERTYPE_VLAN, IPPROTO_TCP,
};
use aegis_net::Packet;

fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
    Ipv4Addr::new(a, b, c, d)
}

#[test]
fn analiza_un_syn_bien_formado() {
    let trama = PacketBuilder::tcp_syn(ip(10, 0, 0, 1), ip(10, 0, 0, 2), 12345, 443);
    let p = Packet::parse(&trama).expect("trama valida");

    assert_eq!(p.eth.ethertype, ETHERTYPE_IPV4);
    assert_eq!(p.ip.src, ip(10, 0, 0, 1));
    assert_eq!(p.ip.dst, ip(10, 0, 0, 2));
    assert_eq!(p.ip.protocol, IPPROTO_TCP);
    assert_eq!(p.src_port(), Some(12345));
    assert_eq!(p.dst_port(), Some(443));

    match p.transport {
        Transport::Tcp(t) => {
            assert!(t.flags.is_syn_only());
            assert!(!t.flags.is_anomalous());
        }
        otro => panic!("se esperaba TCP, no {otro:?}"),
    }
}

#[test]
fn la_suma_de_comprobacion_ip_se_valida() {
    let trama = PacketBuilder::tcp_syn(ip(192, 0, 2, 1), ip(192, 0, 2, 2), 1000, 80);
    let ip_off = 14;
    let h = Ipv4Header::parse(&trama[ip_off..]).unwrap();
    assert!(
        h.checksum_valid(&trama[ip_off..]),
        "el constructor debe generarla bien"
    );

    // Alterar un byte de la cabecera la invalida.
    let mut alterada = trama.clone();
    alterada[ip_off + 8] = 1; // TTL
    let h2 = Ipv4Header::parse(&alterada[ip_off..]).unwrap();
    assert!(!h2.checksum_valid(&alterada[ip_off..]));
}

#[test]
fn rechaza_ihl_por_debajo_del_minimo() {
    // Una cabecera que dice medir menos de 20 bytes se usa para que un
    // analizador que confia en IHL lea los campos desplazados.
    let mut trama = PacketBuilder::tcp_syn(ip(1, 1, 1, 1), ip(2, 2, 2, 2), 1, 2);
    trama[14] = 0x44; // version 4, IHL 4
    assert_eq!(
        Packet::parse(&trama).unwrap_err(),
        ParseError::BadIhl { ihl: 4 }
    );
}

#[test]
fn rechaza_longitud_total_menor_que_la_cabecera() {
    let mut trama = PacketBuilder::tcp_syn(ip(1, 1, 1, 1), ip(2, 2, 2, 2), 1, 2);
    // total_length = 10, imposible con una cabecera de 20 bytes.
    trama[16..18].copy_from_slice(&10u16.to_be_bytes());
    assert!(matches!(
        Packet::parse(&trama).unwrap_err(),
        ParseError::BadTotalLength {
            total: 10,
            header: 20
        }
    ));
}

#[test]
fn rechaza_offset_de_datos_tcp_invalido() {
    let mut trama = PacketBuilder::tcp_syn(ip(1, 1, 1, 1), ip(2, 2, 2, 2), 1, 2);
    // El offset de datos esta en el byte 12 de la cabecera TCP (14 + 20 + 12).
    trama[14 + 20 + 12] = 2 << 4; // offset 2, por debajo del minimo de 5
    assert!(matches!(
        Packet::parse(&trama).unwrap_err(),
        ParseError::BadDataOffset { offset: 2 }
    ));
}

#[test]
fn rechaza_buffers_truncados_en_cada_capa() {
    let trama = PacketBuilder::tcp_syn(ip(1, 1, 1, 1), ip(2, 2, 2, 2), 1, 2);

    // Truncado en Ethernet.
    assert!(matches!(
        Packet::parse(&trama[..10]).unwrap_err(),
        ParseError::TooShort {
            layer: "ethernet",
            ..
        }
    ));
    // Truncado dentro de IP.
    assert!(matches!(
        Packet::parse(&trama[..24]).unwrap_err(),
        ParseError::TooShort { layer: "ipv4", .. }
    ));
    // Truncado dentro de TCP.
    assert!(matches!(
        Packet::parse(&trama[..40]).unwrap_err(),
        ParseError::TooShort { layer: "tcp", .. }
    ));
    // Ningun caso debe entrar en panico: son bytes de un atacante.
}

#[test]
fn salta_etiquetas_vlan() {
    // Encapsular en VLAN es una via para que un analizador que solo mira el
    // primer ethertype no vea el IP que hay detras.
    let interior = PacketBuilder::tcp_syn(ip(10, 0, 0, 1), ip(10, 0, 0, 2), 1, 443);
    let mut con_vlan = Vec::new();
    con_vlan.extend_from_slice(&interior[..12]); // MACs
    con_vlan.extend_from_slice(&ETHERTYPE_VLAN.to_be_bytes());
    con_vlan.extend_from_slice(&0x0064u16.to_be_bytes()); // TCI, VLAN 100
    con_vlan.extend_from_slice(&interior[12..]); // ethertype IPv4 + resto

    let eth = EthHeader::parse(&con_vlan).expect("con VLAN");
    assert_eq!(eth.ethertype, ETHERTYPE_IPV4);
    assert_eq!(eth.header_len, 18, "14 + 4 de la etiqueta");

    let p = Packet::parse(&con_vlan).expect("debe analizarse a traves de la VLAN");
    assert_eq!(p.dst_port(), Some(443));
}

#[test]
fn no_analiza_ipv6_pero_lo_dice() {
    let trama = PacketBuilder::raw_ethertype(ETHERTYPE_IPV6, &[0u8; 40]);
    assert!(matches!(
        Packet::parse(&trama).unwrap_err(),
        ParseError::UnsupportedEthertype {
            ethertype: ETHERTYPE_IPV6
        }
    ));
}

#[test]
fn un_fragmento_posterior_no_se_analiza_como_tcp() {
    let mut trama = PacketBuilder::tcp_syn(ip(1, 1, 1, 1), ip(2, 2, 2, 2), 1111, 2222);
    // Offset de fragmento distinto de cero.
    trama[14 + 6..14 + 8].copy_from_slice(&0x0001u16.to_be_bytes());

    let p = Packet::parse(&trama).expect("el fragmento se analiza a nivel IP");
    assert!(p.ip.is_fragment);
    // Analizarlo como TCP leeria bytes de carga util interpretandolos como
    // puertos, que es justo la evasion que la fragmentacion permite.
    assert_eq!(p.transport, Transport::Fragment);
    assert_eq!(p.dst_port(), None);
}

#[test]
fn detecta_combinaciones_de_banderas_anomalas() {
    // NULL scan.
    assert!(TcpFlags(0).is_anomalous());
    // XMAS scan.
    assert!(TcpFlags(TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG).is_anomalous());
    // SYN+FIN: abrir y cerrar a la vez.
    assert!(TcpFlags(TcpFlags::SYN | TcpFlags::FIN).is_anomalous());
    assert!(TcpFlags(TcpFlags::SYN | TcpFlags::RST).is_anomalous());

    // Trafico normal.
    assert!(!TcpFlags(TcpFlags::SYN).is_anomalous());
    assert!(!TcpFlags(TcpFlags::SYN | TcpFlags::ACK).is_anomalous());
    assert!(!TcpFlags(TcpFlags::ACK | TcpFlags::PSH).is_anomalous());
    assert!(!TcpFlags(TcpFlags::FIN | TcpFlags::ACK).is_anomalous());
}

#[test]
fn el_constructor_produce_tramas_que_el_analizador_acepta() {
    // Si el constructor y el analizador divergen, todas las pruebas del filtro
    // XDP estarian ejercitando tramas que no se parecen al trafico real.
    for (sport, dport, flags) in [
        (1u16, 80u16, TcpFlags::SYN),
        (65535, 1, TcpFlags::SYN | TcpFlags::ACK),
        (12345, 443, TcpFlags::ACK | TcpFlags::PSH),
    ] {
        let t = PacketBuilder::tcp(
            ip(203, 0, 113, 1),
            ip(198, 51, 100, 1),
            sport,
            dport,
            flags,
            b"x",
        );
        let p = Packet::parse(&t).expect("trama construida valida");
        assert_eq!(p.src_port(), Some(sport));
        assert_eq!(p.dst_port(), Some(dport));
        match p.transport {
            Transport::Tcp(TcpHeader { flags: f, .. }) => assert_eq!(f.0, flags),
            otro => panic!("se esperaba TCP, no {otro:?}"),
        }
    }
}
