//! Pruebas del filtro XDP contra el kernel real.
//!
//! Usan `BPF_PROG_TEST_RUN`, que ejecuta el programa cargado en el kernel
//! contra tramas fabricadas, sin engancharlo a ninguna interfaz. Es la unica
//! forma de comprobar de manera determinista que el filtro descarta lo que
//! debe: generar trafico real depende del entorno, no es reproducible y
//! arriesga la conectividad de la maquina donde corren las pruebas.
//!
//! Si no hay privilegios para cargar BPF, las pruebas se saltan con un aviso en
//! vez de fallar. Una prueba que falla por el entorno ensena al equipo a
//! ignorar el rojo del CI.

#![cfg(all(target_os = "linux", feature = "xdp"))]

use std::net::Ipv4Addr;
use std::time::Duration;

use aegis_net::packet::PacketBuilder;
use aegis_net::xdp::{BlockReason, XdpAction, XdpConfig, XdpFilter};
use aegis_net::NetError;

fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
    Ipv4Addr::new(a, b, c, d)
}

/// Carga el filtro, o devuelve `None` si el entorno no lo permite.
fn cargar(config: XdpConfig) -> Option<XdpFilter> {
    match XdpFilter::load(&config) {
        Ok(f) => Some(f),
        Err(NetError::InsufficientPrivileges) => {
            eprintln!("SALTADA: hacen falta CAP_BPF y CAP_NET_ADMIN para cargar el filtro XDP");
            None
        }
        Err(e) => panic!("no se pudo cargar el filtro XDP: {e}"),
    }
}

#[test]
fn el_trafico_normal_pasa() {
    let Some(mut f) = cargar(XdpConfig::default()) else {
        return;
    };
    let trama = PacketBuilder::tcp_syn(ip(203, 0, 113, 5), ip(198, 51, 100, 1), 40000, 443);
    assert_eq!(f.test_packet(&trama).unwrap(), XdpAction::Pass);
}

#[test]
fn una_ip_bloqueada_se_descarta_y_las_demas_no() {
    let Some(mut f) = cargar(XdpConfig::default()) else {
        return;
    };
    let malo = ip(203, 0, 113, 66);
    let bueno = ip(203, 0, 113, 67);
    let victima = ip(198, 51, 100, 1);

    let t_malo = PacketBuilder::tcp_syn(malo, victima, 40000, 22);
    let t_bueno = PacketBuilder::tcp_syn(bueno, victima, 40000, 22);

    assert_eq!(
        f.test_packet(&t_malo).unwrap(),
        XdpAction::Pass,
        "antes de bloquear"
    );

    f.block(malo, Some(Duration::from_secs(300)), BlockReason::Manual)
        .expect("bloquear");

    assert_eq!(f.test_packet(&t_malo).unwrap(), XdpAction::Drop);
    // Un bloqueo que afectara a otras direcciones seria peor que no bloquear.
    assert_eq!(f.test_packet(&t_bueno).unwrap(), XdpAction::Pass);
}

#[test]
fn el_desbloqueo_devuelve_el_trafico() {
    let Some(mut f) = cargar(XdpConfig::default()) else {
        return;
    };
    let addr = ip(203, 0, 113, 90);
    let trama = PacketBuilder::tcp_syn(addr, ip(198, 51, 100, 1), 40000, 80);

    f.block(addr, None, BlockReason::Manual).unwrap();
    assert_eq!(f.test_packet(&trama).unwrap(), XdpAction::Drop);

    f.unblock(addr).unwrap();
    // Toda accion del producto tiene que ser reversible.
    assert_eq!(f.test_packet(&trama).unwrap(), XdpAction::Pass);
}

#[test]
fn un_bloqueo_caducado_deja_pasar_el_trafico() {
    let Some(mut f) = cargar(XdpConfig::default()) else {
        return;
    };
    let addr = ip(203, 0, 113, 91);
    let trama = PacketBuilder::tcp_syn(addr, ip(198, 51, 100, 1), 40000, 80);

    // Bloqueo de 1 ns: ya ha caducado cuando llega el paquete.
    f.block(addr, Some(Duration::from_nanos(1)), BlockReason::PortScan)
        .unwrap();
    std::thread::sleep(Duration::from_millis(5));

    assert_eq!(
        f.test_packet(&trama).unwrap(),
        XdpAction::Pass,
        "un bloqueo temporal que no caduca es un bloqueo permanente por accidente"
    );
}

#[test]
fn la_lista_de_bloqueo_se_puede_consultar() {
    let Some(mut f) = cargar(XdpConfig::default()) else {
        return;
    };
    let a = ip(203, 0, 113, 10);
    let b = ip(203, 0, 113, 11);
    f.block(a, None, BlockReason::Manual).unwrap();
    f.block(b, Some(Duration::from_secs(60)), BlockReason::PortScan)
        .unwrap();

    let lista = f.blocklist().unwrap();
    assert_eq!(lista.len(), 2);
    assert_eq!(lista[0].address, a);
    assert_eq!(lista[0].reason, BlockReason::Manual);
    assert_eq!(lista[0].remaining_ns, None, "sin TTL es permanente");
    assert_eq!(lista[1].reason, BlockReason::PortScan);
    assert!(lista[1].remaining_ns.unwrap() > 0);

    // El contador de aciertos refleja los descartes reales.
    let trama = PacketBuilder::tcp_syn(a, ip(198, 51, 100, 1), 1234, 80);
    for _ in 0..5 {
        assert_eq!(f.test_packet(&trama).unwrap(), XdpAction::Drop);
    }
    let e = f.block_entry(a).unwrap().expect("entrada presente");
    assert_eq!(e.hits, 5);
}

#[test]
fn el_kernel_detecta_un_barrido_de_puertos() {
    let Some(mut f) = cargar(XdpConfig {
        scan_port_threshold: 15,
        scan_syn_threshold: 15,
        autoblock: false,
        ..Default::default()
    }) else {
        return;
    };

    let atacante = ip(203, 0, 113, 200);
    let victima = ip(198, 51, 100, 20);

    let antes = f.stats().unwrap().scans;
    // Barrido de 40 puertos consecutivos.
    for puerto in 1..=40u16 {
        let t = PacketBuilder::tcp_syn(atacante, victima, 40000, puerto);
        // Sin autoblock, el kernel detecta pero no descarta: la decision de
        // bloquear es de userland.
        assert_eq!(f.test_packet(&t).unwrap(), XdpAction::Pass);
    }
    let despues = f.stats().unwrap();
    assert!(
        despues.scans > antes,
        "el kernel debe contabilizar el barrido (antes={antes}, despues={})",
        despues.scans
    );
    assert!(despues.syn >= 40);
}

#[test]
fn el_bloqueo_automatico_esta_desactivado_por_defecto() {
    // La IP origen de un SYN se falsifica trivialmente. Bloquear en automatico
    // es el mecanismo con el que un atacante consigue que bloqueemos a un
    // tercero, asi que el valor por defecto tiene que ser NO bloquear.
    assert!(!XdpConfig::default().autoblock);
}

#[test]
fn con_autoblock_el_barrido_se_corta_en_el_kernel() {
    let Some(mut f) = cargar(XdpConfig {
        scan_port_threshold: 10,
        scan_syn_threshold: 10,
        autoblock: true,
        autoblock_duration: Duration::from_secs(60),
        ..Default::default()
    }) else {
        return;
    };

    let atacante = ip(203, 0, 113, 210);
    let victima = ip(198, 51, 100, 21);

    let mut primer_drop = None;
    for puerto in 1..=40u16 {
        let t = PacketBuilder::tcp_syn(atacante, victima, 40000, puerto);
        if f.test_packet(&t).unwrap() == XdpAction::Drop {
            primer_drop = Some(puerto);
            break;
        }
    }
    let p = primer_drop.expect("con autoblock el barrido debe cortarse");
    assert!(
        p >= 10,
        "no debe cortarse antes de cruzar el umbral (corto en {p})"
    );

    // Y la direccion queda en la lista con el motivo correcto.
    let e = f.block_entry(atacante).unwrap().expect("entrada creada");
    assert_eq!(e.reason, BlockReason::PortScan);
}

#[test]
fn el_trafico_no_ipv4_pasa_y_se_contabiliza() {
    let Some(mut f) = cargar(XdpConfig::default()) else {
        return;
    };
    let antes = f.stats().unwrap().ipv6_uninspected;

    let trama = PacketBuilder::raw_ethertype(0x86DD, &[0u8; 60]);
    assert_eq!(f.test_packet(&trama).unwrap(), XdpAction::Pass);

    let despues = f.stats().unwrap().ipv6_uninspected;
    // El punto ciego se cuenta: uno que nadie mide es uno que nadie arregla.
    assert!(despues > antes, "IPv6 sin inspeccionar debe contabilizarse");
}

#[test]
fn una_trama_malformada_no_tumba_el_filtro() {
    let Some(mut f) = cargar(XdpConfig::default()) else {
        return;
    };

    // Cabecera IP que declara IHL 15 (60 bytes) en un paquete que no los tiene.
    let mut corta = PacketBuilder::tcp_syn(ip(1, 1, 1, 1), ip(2, 2, 2, 2), 1, 2);
    corta[14] = 0x4F;
    corta.truncate(30);
    assert_eq!(
        f.test_packet(&corta).unwrap(),
        XdpAction::Pass,
        "ante una cabecera incoherente hay que dejar pasar, no interpretar basura"
    );

    // Cabecera Ethernet que anuncia IPv4 pero sin ningun byte de IP detras.
    // Ejercita la comprobacion `(void *)(ip + 1) > data_end` del programa.
    //
    // No se prueba con menos de 14 bytes porque BPF_PROG_TEST_RUN exige al
    // menos una cabecera Ethernet completa y devuelve EINVAL antes de ejecutar
    // nada: seria probar la validacion de entrada del kernel, no la nuestra. Un
    // driver de red tampoco entrega a XDP tramas mas cortas que eso.
    let solo_eth = PacketBuilder::raw_ethertype(0x0800, &[]);
    assert_eq!(solo_eth.len(), 14);
    assert_eq!(f.test_packet(&solo_eth).unwrap(), XdpAction::Pass);

    // IP declarada pero truncada a la mitad.
    let ip_truncado = PacketBuilder::raw_ethertype(0x0800, &[0x45, 0x00, 0x00, 0x28]);
    assert_eq!(f.test_packet(&ip_truncado).unwrap(), XdpAction::Pass);

    // El filtro sigue funcionando despues.
    let buena = PacketBuilder::tcp_syn(ip(10, 0, 0, 1), ip(10, 0, 0, 2), 1, 443);
    assert_eq!(f.test_packet(&buena).unwrap(), XdpAction::Pass);
}
