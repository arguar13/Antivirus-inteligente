//! El circuito entero: paquetes de red → hechos → decision → CORTE EN EL KERNEL.
//!
//! Las pruebas del decisor comprueban que se decide bien y las de `corte_vivo`
//! que el kernel corta lo que se le marca. Lo que se comprueba aqui es **la
//! union**, que es donde de verdad se rompen las cosas: que la clave de flujo que
//! calcula el disector sea la misma que escribe userland y la misma que busca el
//! kernel.
//!
//! Si esas tres no coincidieran, cada pieza pasaria sus pruebas por separado y el
//! producto no cortaria nada — sin un solo error visible. Es exactamente el tipo
//! de fallo que solo aparece cuando se ejercita el camino completo.
//!
//! Aqui no se inventa ningun hecho: se construyen **paquetes de verdad**, se
//! meten por `aegis_wire`, y lo que salga de ahi es lo que juzga el IPS.

#![cfg(all(target_os = "linux", feature = "kernel"))]

use std::net::{IpAddr, Ipv4Addr};

use aegis_ips::confianza::Confianza;
use aegis_ips::decisor::{ConfigDecisor, Decisor};
use aegis_ips::limitador::Limitador;
use aegis_ips::modo::Modo;
use aegis_ips::plano::PlanoIps;
use aegis_ips::protegidos::MotivoProteccion;
use aegis_ips::regla::{Criterio, Regla};
use aegis_ips::veredicto::Accion;
use aegis_wire::motor::{ConfigMotor, Motor};

const PASA: u32 = 0;
const CORTA: u32 = 2;
const MOTIVO_C2: u32 = 3;
const UNA_HORA_NS: u64 = 3_600_000_000_000;

fn ip(d: u8) -> Ipv4Addr {
    Ipv4Addr::new(10, 0, 0, d)
}

/// Un datagrama IPv4 + UDP con una consulta DNS de verdad dentro.
fn consulta_dns(origen: (Ipv4Addr, u16), destino: (Ipv4Addr, u16), nombre: &str) -> Vec<u8> {
    let mut dns = Vec::new();
    dns.extend_from_slice(&0x1234u16.to_be_bytes());
    dns.extend_from_slice(&0x0100u16.to_be_bytes());
    dns.extend_from_slice(&1u16.to_be_bytes());
    dns.extend_from_slice(&[0u8; 6]);
    for etiqueta in nombre.split('.') {
        dns.push(etiqueta.len() as u8);
        dns.extend_from_slice(etiqueta.as_bytes());
    }
    dns.push(0);
    dns.extend_from_slice(&1u16.to_be_bytes());
    dns.extend_from_slice(&1u16.to_be_bytes());

    let total = 20 + 8 + dns.len();
    let mut p = vec![0x45, 0x00];
    p.extend_from_slice(&(total as u16).to_be_bytes());
    p.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 64, 17, 0x00, 0x00]);
    p.extend_from_slice(&origen.0.octets());
    p.extend_from_slice(&destino.0.octets());
    p.extend_from_slice(&origen.1.to_be_bytes());
    p.extend_from_slice(&destino.1.to_be_bytes());
    p.extend_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(&dns);
    p
}

/// La misma conversacion, pero como trama Ethernet, que es lo que ve el kernel.
fn trama_udp(origen: (Ipv4Addr, u16), destino: (Ipv4Addr, u16)) -> Vec<u8> {
    let mut t = vec![0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1];
    t.extend_from_slice(&0x0800u16.to_be_bytes());
    let total = 20 + 8;
    t.extend_from_slice(&[0x45, 0x00]);
    t.extend_from_slice(&(total as u16).to_be_bytes());
    t.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 64, 17, 0x00, 0x00]);
    t.extend_from_slice(&origen.0.octets());
    t.extend_from_slice(&destino.0.octets());
    t.extend_from_slice(&origen.1.to_be_bytes());
    t.extend_from_slice(&destino.1.to_be_bytes());
    t.extend_from_slice(&8u16.to_be_bytes());
    t.extend_from_slice(&0u16.to_be_bytes());
    t
}

fn regla_c2() -> Regla {
    Regla {
        id: 1000,
        nombre: "c2-por-dns".to_string(),
        confianza: Confianza::Alta,
        criterio: Criterio::SufijoDns("evil.com".to_string()),
    }
}

fn plano(modo: Modo) -> Option<PlanoIps> {
    match PlanoIps::cargar(modo, true) {
        Ok(p) => Some(p),
        Err(e) => {
            println!(
                "OMITIDA: no se pudo cargar el programa eBPF ({e}).\n\
                 El CIRCUITO no se ejercio aqui. Sus dos mitades si se prueban por\n\
                 separado: la decision en las pruebas del decisor, sin privilegios,\n\
                 y el corte en `corte_vivo` cuando el kernel esta disponible."
            );
            None
        }
    }
}

/// EL CIRCUITO ENTERO: un paquete DNS hacia un C2 entra por el disector, el
/// motor de decision lo juzga, el veredicto baja al kernel, y el siguiente
/// paquete de esa conversacion **se corta de verdad**.
#[test]
fn de_un_paquete_dns_a_un_corte_en_el_kernel() {
    let Some(mut p) = plano(Modo::Bloqueo) else {
        return;
    };

    let mut motor = Motor::nuevo(ConfigMotor::default());
    let mut d = Decisor::nuevo(ConfigDecisor {
        modo: Modo::Bloqueo,
        ..ConfigDecisor::default()
    });
    d.cargar_reglas(vec![regla_c2()]);

    // 1. Un paquete de verdad entra por el disector.
    let hechos = motor.alimentar_ip(1, &consulta_dns((ip(1), 40_000), (ip(2), 53), "a.evil.com"));
    assert!(!hechos.is_empty(), "el disector tiene que ver la consulta");

    // 2. El motor de decision lo juzga.
    let mut aplicados = 0;
    for h in &hechos {
        if let Some(v) = d.juzgar(h) {
            assert_eq!(v.accion, Accion::Cortar, "{}", v.explicacion());
            // 3. El veredicto baja al kernel.
            if p.aplicar(&v, MOTIVO_C2, UNA_HORA_NS).expect("aplicar") {
                aplicados += 1;
            }
        }
    }
    assert_eq!(aplicados, 1, "tenia que bajarse UN veredicto");

    // 4. Y el kernel corta esa conversacion. AQUI es donde se demuestra que las
    //    tres claves de flujo —disector, userland y kernel— son la misma.
    assert_eq!(
        p.probar_paquete(false, &trama_udp((ip(1), 40_000), (ip(2), 53)))
            .unwrap(),
        CORTA,
        "el kernel tiene que cortar la conversacion que se juzgo"
    );

    // Y una conversacion distinta de la misma maquina sigue pasando: cortar de
    // mas seria cortar al cliente su propio DNS.
    assert_eq!(
        p.probar_paquete(false, &trama_udp((ip(1), 40_001), (ip(2), 53)))
            .unwrap(),
        PASA
    );
}

/// Un nombre legitimo recorre el mismo camino entero y NO corta nada. Sin esta
/// mitad, la prueba de arriba solo demostraria que el motor corta.
#[test]
fn un_nombre_legitimo_recorre_el_circuito_y_no_corta_nada() {
    let Some(mut p) = plano(Modo::Bloqueo) else {
        return;
    };
    let mut motor = Motor::nuevo(ConfigMotor::default());
    let mut d = Decisor::nuevo(ConfigDecisor {
        modo: Modo::Bloqueo,
        ..ConfigDecisor::default()
    });
    d.cargar_reglas(vec![regla_c2()]);

    let hechos = motor.alimentar_ip(
        1,
        &consulta_dns((ip(1), 40_010), (ip(2), 53), "www.ejemplo.com"),
    );
    for h in &hechos {
        assert!(d.juzgar(h).is_none(), "no puede casar ninguna regla");
    }
    assert_eq!(
        p.probar_paquete(false, &trama_udp((ip(1), 40_010), (ip(2), 53)))
            .unwrap(),
        PASA
    );
}

/// EL CIRCUITO DE LA SALVAGUARDA: el activo protegido se para en las DOS capas.
/// Userland no emite el corte, y aunque lo emitiera el kernel no lo aplicaria.
#[test]
fn un_activo_protegido_se_para_en_las_dos_capas() {
    let Some(mut p) = plano(Modo::Bloqueo) else {
        return;
    };
    let mut motor = Motor::nuevo(ConfigMotor::default());
    let mut d = Decisor::nuevo(ConfigDecisor {
        modo: Modo::Bloqueo,
        ..ConfigDecisor::default()
    });
    d.cargar_reglas(vec![regla_c2()]);
    d.protegidos_mut()
        .proteger(IpAddr::V4(ip(2)), MotivoProteccion::ServidorDns);

    // La lista se baja al kernel, y se dice cuantas entradas bajaron.
    let (bajadas, omitidas) = p
        .sincronizar_protegidos(d.protegidos())
        .expect("sincronizar");
    assert_eq!(bajadas, 1);
    assert_eq!(omitidas, 0);

    // CAPA 1: userland no emite el corte.
    let hechos = motor.alimentar_ip(1, &consulta_dns((ip(1), 40_020), (ip(2), 53), "a.evil.com"));
    for h in &hechos {
        if let Some(v) = d.juzgar(h) {
            assert_eq!(v.accion, Accion::Alertar, "{}", v.explicacion());
            assert!(
                v.explicacion().contains("servidor-dns"),
                "{}",
                v.explicacion()
            );
        }
    }
    assert_eq!(d.contadores().no_por_protegido, 1);

    // CAPA 2: y si alguien escribiera el corte a mano —un fallo de logica, una
    // via que nadie previo—, el kernel TAMPOCO lo aplica.
    let flujo = aegis_ips::veredicto::Flujo::normalizado(
        (IpAddr::V4(ip(1)), 40_020),
        (IpAddr::V4(ip(2)), 53),
        17,
    );
    p.escribir_veredicto(&flujo, Accion::Cortar, MOTIVO_C2, 999, UNA_HORA_NS)
        .expect("escribir a mano");
    assert_eq!(
        p.probar_paquete(false, &trama_udp((ip(1), 40_020), (ip(2), 53)))
            .unwrap(),
        PASA,
        "la segunda capa tiene que aguantar aunque la primera falle"
    );
}

/// LA DEGRADACION, de extremo a extremo: el motor se pasa del tope, se degrada,
/// y el KERNEL deja de cortar porque userland le baja el modo nuevo.
///
/// Es la prueba de que la degradacion no es una nota en un registro: cambia de
/// verdad lo que hace el plano de datos.
#[test]
fn la_degradacion_llega_hasta_el_kernel_y_deja_de_cortar() {
    let Some(mut p) = plano(Modo::Bloqueo) else {
        return;
    };
    let mut motor = Motor::nuevo(ConfigMotor::default());
    let mut d = Decisor::nuevo(ConfigDecisor {
        modo: Modo::Bloqueo,
        ..ConfigDecisor::default()
    })
    .con_limitador(Limitador::nuevo(3, 60_000_000));
    d.cargar_reglas(vec![regla_c2()]);

    let mut cortes = 0;
    let mut degradado_en = None;
    for i in 0..8u16 {
        let puerto = 41_000 + i;
        let hechos = motor.alimentar_ip(
            u64::from(i),
            &consulta_dns((ip(1), puerto), (ip(2), 53), "a.evil.com"),
        );
        for h in &hechos {
            let Some(v) = d.juzgar(h) else { continue };
            if v.accion == Accion::Cortar {
                p.aplicar(&v, MOTIVO_C2, UNA_HORA_NS).expect("aplicar");
                cortes += 1;
            }
        }
        // Userland refleja en el kernel el modo EFECTIVO. Sin este paso, la
        // degradacion seria una opinion de userland y el kernel seguiria
        // cortando con los veredictos ya escritos.
        if d.degradado() && degradado_en.is_none() {
            degradado_en = Some(i);
            p.configurar(d.modo(), true)
                .expect("reflejar la degradacion");
        }
    }

    assert_eq!(cortes, 3, "solo caben tres cortes en la ventana");
    assert!(d.degradado(), "y el motor tiene que haberse degradado");
    assert_eq!(d.modo(), Modo::SoloDeteccion);

    // Y AHORA LO QUE IMPORTA: los veredictos siguen en el mapa, pero el kernel
    // ya no corta, porque el modo bajo con la degradacion.
    assert_eq!(
        p.probar_paquete(false, &trama_udp((ip(1), 41_000), (ip(2), 53)))
            .unwrap(),
        PASA,
        "degradado, el kernel no corta ni los veredictos que ya estaban"
    );
    let c = p.contadores().expect("contadores");
    assert!(
        c.habria_cortado > 0,
        "pero SI cuenta lo que habria cortado: {c:?}"
    );
}

/// Una direccion IPv6 protegida no se puede bajar a este plano de datos, y la
/// sincronizacion lo DICE en vez de dejar creer que quedo protegida abajo.
#[test]
fn una_proteccion_ipv6_se_declara_como_no_bajada() {
    let Some(p) = plano(Modo::Bloqueo) else {
        return;
    };
    let mut protegidos = aegis_ips::protegidos::Protegidos::nueva();
    protegidos.proteger(IpAddr::V4(ip(2)), MotivoProteccion::ServidorDns);
    protegidos.proteger(
        "2001:db8::53".parse().unwrap(),
        MotivoProteccion::ServidorDns,
    );

    let (bajadas, omitidas) = p.sincronizar_protegidos(&protegidos).expect("sincronizar");
    assert_eq!(bajadas, 1);
    assert_eq!(
        omitidas, 1,
        "lo que no se pudo bajar se CUENTA: creer que un activo esta protegido \
         abajo cuando no lo esta es justo lo que esta lista existe para evitar"
    );
}
