//! El corte, ejercido contra el PROGRAMA DE KERNEL DE VERDAD.
//!
//! # Por que `BPF_PROG_RUN` y no un par `veth`
//!
//! Las dos formas ejecutan el mismo bytecode en el mismo kernel. La diferencia
//! esta en lo que se puede AFIRMAR despues:
//!
//! - Con `veth` hay que montar interfaces, generar trafico, esperar, y deducir
//!   el veredicto de si un paquete llego o no. Si no llega, puede ser porque el
//!   programa lo corto... o por el encaminamiento, o por el temporizador, o
//!   porque el contenedor no tenia `CAP_NET_ADMIN`. Una prueba cuyo fallo tiene
//!   cuatro explicaciones posibles no demuestra ninguna de ellas.
//! - Con `BPF_PROG_RUN` el kernel ejecuta el programa contra el paquete que se
//!   le da y **devuelve el codigo de accion**. Es determinista, no toca la red
//!   de la maquina, y el resultado es el veredicto literal del programa.
//!
//! Es la misma decision que ya tomo el filtro XDP de `aegis-net`, y por el mismo
//! motivo. Lo que NO se ejercita asi —que el kernel de verdad descarte el
//! paquete al recibir `TC_ACT_SHOT` en una NIC real— es comportamiento del
//! propio kernel, no de este codigo, y se declara en la tabla de honestidad.
//!
//! # Si no hay privilegios
//!
//! Cargar un programa eBPF exige `CAP_BPF` (o root). Sin eso estas pruebas se
//! DECLARAN OMITIDAS y no se dan por buenas: «no se pudo mirar» y «se miro y
//! estaba bien» no son lo mismo, y confundirlos es como se acaba creyendo que un
//! IPS corta cuando no corta.

#![cfg(all(target_os = "linux", feature = "kernel"))]

use std::net::{IpAddr, Ipv4Addr};

use aegis_ips::modo::Modo;
use aegis_ips::plano::PlanoIps;
use aegis_ips::protegidos::MotivoProteccion;
use aegis_ips::veredicto::{Accion, Flujo};
use aegis_prueba::{omitir, Requisito};

/// `TC_ACT_OK`: el paquete sigue su camino.
const PASA: u32 = 0;
/// `TC_ACT_SHOT`: el paquete se descarta.
const CORTA: u32 = 2;

/// `AEGIS_BLOCK_REASON_C2`.
const MOTIVO_C2: u32 = 3;

fn ip(d: u8) -> Ipv4Addr {
    Ipv4Addr::new(10, 0, 0, d)
}

/// Construye una trama Ethernet + IPv4 + TCP completa, byte a byte.
fn trama(origen: (Ipv4Addr, u16), destino: (Ipv4Addr, u16)) -> Vec<u8> {
    let mut t = Vec::new();
    // Ethernet: destino, origen, ethertype IPv4.
    t.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    t.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    t.extend_from_slice(&0x0800u16.to_be_bytes());

    // IPv4.
    let total = 20 + 20;
    t.extend_from_slice(&[0x45, 0x00]);
    t.extend_from_slice(&(total as u16).to_be_bytes());
    t.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 64, 6, 0x00, 0x00]);
    t.extend_from_slice(&origen.0.octets());
    t.extend_from_slice(&destino.0.octets());

    // TCP.
    t.extend_from_slice(&origen.1.to_be_bytes());
    t.extend_from_slice(&destino.1.to_be_bytes());
    t.extend_from_slice(&1000u32.to_be_bytes());
    t.extend_from_slice(&0u32.to_be_bytes());
    t.push(5 << 4);
    t.push(0x10); // ACK
    t.extend_from_slice(&65535u16.to_be_bytes());
    t.extend_from_slice(&0u16.to_be_bytes());
    t.extend_from_slice(&0u16.to_be_bytes());
    t
}

fn flujo(origen: (Ipv4Addr, u16), destino: (Ipv4Addr, u16)) -> Flujo {
    Flujo::normalizado(
        (IpAddr::V4(origen.0), origen.1),
        (IpAddr::V4(destino.0), destino.1),
        6,
    )
}

/// Carga el plano, o declara por que no se pudo.
fn plano(modo: Modo) -> Option<PlanoIps> {
    match PlanoIps::cargar(modo, true) {
        Ok(p) => Some(p),
        Err(e) => {
            omitir(
                &format!(
                    "no se pudo cargar el programa eBPF ({e}). Cargar codigo en el \
                     kernel exige CAP_BPF o root. El corte NO se ejercio aqui; la \
                     DECISION de cortar si se prueba, sin privilegios, en el decisor"
                ),
                Requisito::Ebpf,
            );
            None
        }
    }
}

/// EL CASO CENTRAL: un flujo marcado se corta, y uno limpio no.
///
/// Las dos mitades importan igual. Un IPS que corta lo marcado pero tambien lo
/// limpio no es un IPS, es un corte de red.
#[test]
fn un_flujo_marcado_se_corta_y_uno_limpio_no() {
    let Some(mut p) = plano(Modo::Bloqueo) else {
        return;
    };

    let sucio = flujo((ip(1), 50_000), (ip(2), 443));
    p.escribir_veredicto(&sucio, Accion::Cortar, MOTIVO_C2, 42, 3_600_000_000_000)
        .expect("escribir el veredicto");

    let corte = p
        .probar_paquete(false, &trama((ip(1), 50_000), (ip(2), 443)))
        .expect("ejecutar el programa");
    assert_eq!(corte, CORTA, "el flujo marcado TIENE que cortarse");

    let paso = p
        .probar_paquete(false, &trama((ip(1), 50_001), (ip(3), 443)))
        .expect("ejecutar el programa");
    assert_eq!(paso, PASA, "el flujo limpio NO puede cortarse");
}

/// Y EN LOS DOS SENTIDOS: el veredicto se escribio viendo la ida, y tiene que
/// cortar tambien la vuelta — que es por donde llega la respuesta del C2.
#[test]
fn el_corte_alcanza_los_dos_sentidos_de_la_conversacion() {
    let Some(mut p) = plano(Modo::Bloqueo) else {
        return;
    };
    let f = flujo((ip(1), 50_010), (ip(2), 443));
    p.escribir_veredicto(&f, Accion::Cortar, MOTIVO_C2, 1, 3_600_000_000_000)
        .expect("escribir");

    let ida = p
        .probar_paquete(false, &trama((ip(1), 50_010), (ip(2), 443)))
        .unwrap();
    let vuelta = p
        .probar_paquete(false, &trama((ip(2), 443), (ip(1), 50_010)))
        .unwrap();
    assert_eq!(ida, CORTA);
    assert_eq!(vuelta, CORTA, "la vuelta es por donde responde el C2");
}

/// Y EN EGRESO, que es el sentido que XDP no puede cubrir y el que mas importa
/// en un endpoint: la baliza al C2 sale por aqui.
#[test]
fn el_corte_funciona_tambien_en_egreso() {
    let Some(mut p) = plano(Modo::Bloqueo) else {
        return;
    };
    let f = flujo((ip(1), 50_020), (ip(2), 8443));
    p.escribir_veredicto(&f, Accion::Cortar, MOTIVO_C2, 1, 3_600_000_000_000)
        .expect("escribir");

    let saliendo = p
        .probar_paquete(true, &trama((ip(1), 50_020), (ip(2), 8443)))
        .unwrap();
    assert_eq!(saliendo, CORTA);
}

/// LA SALVAGUARDA MAS IMPORTANTE, ejercida en el kernel: un activo protegido no
/// se corta **aunque el mapa de veredictos diga que si**.
///
/// Esto es lo que protege del caso que de verdad importa, que no es que la regla
/// sea mala: es que el codigo de decision de arriba tenga un fallo.
#[test]
fn un_activo_protegido_no_se_corta_ni_con_el_veredicto_escrito() {
    let Some(mut p) = plano(Modo::Bloqueo) else {
        return;
    };
    let f = flujo((ip(1), 50_030), (ip(9), 53));
    p.escribir_veredicto(&f, Accion::Cortar, MOTIVO_C2, 1, 3_600_000_000_000)
        .expect("escribir");

    // Antes de proteger, se corta: asi se demuestra que el veredicto estaba
    // puesto de verdad y que lo que cambia el resultado es la proteccion.
    assert_eq!(
        p.probar_paquete(false, &trama((ip(1), 50_030), (ip(9), 53)))
            .unwrap(),
        CORTA,
        "sin proteger, el veredicto corta"
    );

    p.proteger(ip(9), MotivoProteccion::ServidorDns)
        .expect("proteger");
    assert_eq!(
        p.probar_paquete(false, &trama((ip(1), 50_030), (ip(9), 53)))
            .unwrap(),
        PASA,
        "protegido, el MISMO veredicto ya no corta"
    );

    // Y la salvaguarda CUENTA las veces que hizo falta: es la cifra que dice si
    // el motor de decision se esta equivocando en algo grave.
    let salvadas = p.salvadas(ip(9)).expect("leer").unwrap_or(0);
    assert!(salvadas >= 1, "salvadas = {salvadas}");
}

/// Protege el ORIGEN, no el destino: cortarle la salida a un controlador de
/// dominio lo deja igual de inutil que cortarle la entrada.
#[test]
fn proteger_el_origen_tambien_salva_el_flujo() {
    let Some(mut p) = plano(Modo::Bloqueo) else {
        return;
    };
    let f = flujo((ip(7), 50_040), (ip(2), 443));
    p.escribir_veredicto(&f, Accion::Cortar, MOTIVO_C2, 1, 3_600_000_000_000)
        .expect("escribir");
    p.proteger(ip(7), MotivoProteccion::ControladorDeDominio)
        .expect("proteger");

    assert_eq!(
        p.probar_paquete(false, &trama((ip(7), 50_040), (ip(2), 443)))
            .unwrap(),
        PASA
    );
}

/// EL MODO LO APLICA EL KERNEL: con el veredicto de corte escrito y el modo en
/// solo deteccion, no se corta — y se CUENTA lo que se habria cortado.
///
/// Esa cifra es la que un cliente mira antes de atreverse a activar el bloqueo.
#[test]
fn en_solo_deteccion_el_kernel_no_corta_y_cuenta_lo_que_habria_cortado() {
    let Some(mut p) = plano(Modo::SoloDeteccion) else {
        return;
    };
    let f = flujo((ip(1), 50_050), (ip(2), 443));
    p.escribir_veredicto(&f, Accion::Cortar, MOTIVO_C2, 1, 3_600_000_000_000)
        .expect("escribir");

    let antes = p.contadores().expect("contadores");
    assert_eq!(
        p.probar_paquete(false, &trama((ip(1), 50_050), (ip(2), 443)))
            .unwrap(),
        PASA,
        "en solo deteccion NO se corta, pase lo que pase en el mapa"
    );
    let despues = p.contadores().expect("contadores");

    assert_eq!(despues.cortados, antes.cortados, "no se corto nada");
    assert!(
        despues.habria_cortado > antes.habria_cortado,
        "pero SI se anota lo que se habria cortado: {antes:?} -> {despues:?}"
    );
}

/// Y el modo aprendizaje se comporta igual respecto al trafico: no corta.
#[test]
fn el_modo_aprendizaje_tampoco_corta_en_el_kernel() {
    let Some(mut p) = plano(Modo::BloqueoConAprendizaje) else {
        return;
    };
    let f = flujo((ip(1), 50_060), (ip(2), 443));
    p.escribir_veredicto(&f, Accion::Cortar, MOTIVO_C2, 1, 3_600_000_000_000)
        .expect("escribir");
    assert_eq!(
        p.probar_paquete(false, &trama((ip(1), 50_060), (ip(2), 443)))
            .unwrap(),
        PASA
    );
}

/// Cambiar el modo en caliente cambia lo que hace el kernel, sin recargar nada.
#[test]
fn cambiar_el_modo_en_caliente_cambia_el_comportamiento() {
    let Some(mut p) = plano(Modo::SoloDeteccion) else {
        return;
    };
    let f = flujo((ip(1), 50_070), (ip(2), 443));
    p.escribir_veredicto(&f, Accion::Cortar, MOTIVO_C2, 1, 3_600_000_000_000)
        .expect("escribir");
    let paquete = trama((ip(1), 50_070), (ip(2), 443));

    assert_eq!(p.probar_paquete(false, &paquete).unwrap(), PASA);
    p.configurar(Modo::Bloqueo, true).expect("reconfigurar");
    assert_eq!(p.probar_paquete(false, &paquete).unwrap(), CORTA);
    p.configurar(Modo::SoloDeteccion, true)
        .expect("reconfigurar");
    assert_eq!(p.probar_paquete(false, &paquete).unwrap(), PASA);
}

/// UN VEREDICTO CADUCADO DEJA DE APLICARSE SOLO. Un corte sin caducidad util es
/// un bloqueo permanente por accidente: la maquina se limpia y sigue sin
/// conectar, y nadie recuerda por que.
#[test]
fn un_veredicto_caducado_deja_de_cortar() {
    let Some(mut p) = plano(Modo::Bloqueo) else {
        return;
    };
    let f = flujo((ip(1), 50_080), (ip(2), 443));
    // Vigencia de un nanosegundo: ya ha caducado cuando llega el paquete.
    p.escribir_veredicto(&f, Accion::Cortar, MOTIVO_C2, 1, 1)
        .expect("escribir");

    assert_eq!(
        p.probar_paquete(false, &trama((ip(1), 50_080), (ip(2), 443)))
            .unwrap(),
        PASA,
        "lo caducado no corta"
    );
}

/// Retirar un veredicto lo deja de aplicar de inmediato: es como se levanta una
/// contencion cuando resulta que fue un error.
#[test]
fn retirar_un_veredicto_levanta_el_corte() {
    let Some(mut p) = plano(Modo::Bloqueo) else {
        return;
    };
    let f = flujo((ip(1), 50_090), (ip(2), 443));
    let paquete = trama((ip(1), 50_090), (ip(2), 443));

    p.escribir_veredicto(&f, Accion::Cortar, MOTIVO_C2, 1, 3_600_000_000_000)
        .expect("escribir");
    assert_eq!(p.probar_paquete(false, &paquete).unwrap(), CORTA);

    p.retirar_veredicto(&f).expect("retirar");
    assert_eq!(p.probar_paquete(false, &paquete).unwrap(), PASA);
    // Y retirarlo otra vez no es un error: el resultado que se buscaba ya esta.
    p.retirar_veredicto(&f).expect("retirar lo que ya no esta");
}

/// LO QUE HACE QUE BLOQUEAR NO CUESTE RENDIMIENTO: el corte lo resuelve el
/// kernel con una busqueda de mapa, sin subir a userland ni una vez.
///
/// Se demuestra con los contadores del propio programa: mil paquetes del mismo
/// flujo dan mil aciertos de cache y mil cortes, y userland no ha intervenido
/// entre medias.
#[test]
fn el_corte_lo_resuelve_el_kernel_sin_subir_a_userland() {
    let Some(mut p) = plano(Modo::Bloqueo) else {
        return;
    };
    let f = flujo((ip(1), 50_100), (ip(2), 443));
    p.escribir_veredicto(&f, Accion::Cortar, MOTIVO_C2, 7, 3_600_000_000_000)
        .expect("escribir");
    let paquete = trama((ip(1), 50_100), (ip(2), 443));

    let antes = p.contadores().expect("contadores");
    const CUANTOS: u64 = 1_000;
    for _ in 0..CUANTOS {
        assert_eq!(p.probar_paquete(false, &paquete).unwrap(), CORTA);
    }
    let despues = p.contadores().expect("contadores");

    assert_eq!(
        despues.cortados - antes.cortados,
        CUANTOS,
        "los {CUANTOS} paquetes se cortaron"
    );
    assert_eq!(
        despues.cache_acierto - antes.cache_acierto,
        CUANTOS,
        "y los {CUANTOS} los resolvio la cache del kernel"
    );

    // Y el contador de golpes del propio veredicto lleva la cuenta, para poder
    // medir el efecto sin recibir un evento por paquete.
    let hits = p.hits(&f).expect("leer").unwrap_or(0);
    assert!(hits >= CUANTOS, "hits = {hits}");
}

/// NO SE PIERDE NI UN PAQUETE, medido y no prometido: todo lo que entra sale
/// contado en alguna de las categorias, sin huecos.
#[test]
fn el_plano_de_datos_no_pierde_ningun_paquete() {
    let Some(mut p) = plano(Modo::Bloqueo) else {
        return;
    };
    let sucio = flujo((ip(1), 50_110), (ip(2), 443));
    p.escribir_veredicto(&sucio, Accion::Cortar, MOTIVO_C2, 1, 3_600_000_000_000)
        .expect("escribir");

    let antes = p.contadores().expect("contadores");
    const CORTABLES: u64 = 400;
    const LIMPIOS: u64 = 400;
    // Un paquete que ni siquiera es IPv4: tiene que contarse como no clasificado
    // y no desaparecer de la cuenta.
    const RAROS: u64 = 200;

    for _ in 0..CORTABLES {
        p.probar_paquete(false, &trama((ip(1), 50_110), (ip(2), 443)))
            .unwrap();
    }
    for i in 0..LIMPIOS {
        p.probar_paquete(false, &trama((ip(1), 51_000 + i as u16), (ip(3), 443)))
            .unwrap();
    }
    let arp = {
        let mut t = vec![0u8; 14];
        t[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        t
    };
    for _ in 0..RAROS {
        p.probar_paquete(false, &arp).unwrap();
    }
    let despues = p.contadores().expect("contadores");

    let total = CORTABLES + LIMPIOS + RAROS;
    assert_eq!(
        despues.paquetes - antes.paquetes,
        total,
        "todo lo que entra se cuenta"
    );
    assert_eq!(despues.cortados - antes.cortados, CORTABLES);
    assert_eq!(despues.cache_fallo - antes.cache_fallo, LIMPIOS);
    assert_eq!(
        despues.no_clasificados - antes.no_clasificados,
        RAROS,
        "y lo que no se puede clasificar SE CUENTA, no se calla"
    );
}

/// UNA TRAMA TRUNCADA NUNCA PUEDE CORTAR.
///
/// Es la mitad que importa de la robustez: que el programa no se caiga lo
/// garantiza el verificador del kernel, que rechaza cualquier acceso al paquete
/// sin comprobar contra `data_end`. Lo que el verificador NO puede decir es que
/// la decision sea la correcta, y cortar «por si acaso» un paquete que no se ha
/// podido leer entero seria cortar trafico legitimo.
///
/// # El hueco de la propia herramienta, declarado
///
/// `BPF_PROG_RUN` construye un `sk_buff` de verdad antes de ejecutar el
/// programa, y el kernel **se niega** a construirlo cuando la trama declara
/// IPv4 y la cabecera IP viene cortada (en esta maquina, de 13 a 33 bytes). Eso
/// es la herramienta de pruebas diciendo que no, no el programa portandose mal:
/// esas longitudes se cuentan aparte y se declaran en vez de darlas por
/// probadas. En una NIC real esas tramas SI llegan, y quien las cubre son las
/// comprobaciones contra `data_end` que el verificador exige.
#[test]
fn ninguna_trama_truncada_provoca_un_corte() {
    let Some(mut p) = plano(Modo::Bloqueo) else {
        return;
    };
    // Con el veredicto PUESTO para ese flujo: asi la prueba no pasa por no
    // haber nada que cortar, sino porque una trama incompleta no se juzga.
    let f = flujo((ip(1), 50_120), (ip(2), 443));
    p.escribir_veredicto(&f, Accion::Cortar, MOTIVO_C2, 1, 3_600_000_000_000)
        .expect("escribir");

    let completa = trama((ip(1), 50_120), (ip(2), 443));
    let mut ejercidas = 0usize;
    let mut rechazadas_por_el_kernel = 0usize;

    for corte in 0..completa.len() {
        match p.probar_paquete(false, &completa[..corte]) {
            Ok(accion) => {
                ejercidas += 1;
                assert_eq!(
                    accion, PASA,
                    "una trama de {corte} bytes no se puede juzgar, y menos cortar"
                );
            }
            Err(_) => rechazadas_por_el_kernel += 1,
        }
    }

    // La trama entera SI corta: si no, la prueba estaria pasando por un motivo
    // equivocado —que el veredicto no estuviera puesto— y no probaria nada.
    assert_eq!(
        p.probar_paquete(false, &completa).unwrap(),
        CORTA,
        "el veredicto tiene que estar puesto de verdad"
    );
    assert!(
        ejercidas > 0,
        "alguna longitud truncada tiene que haberse podido ejercer"
    );
    println!(
        "truncamientos ejercidos: {ejercidas}; rechazados por el propio \
         BPF_PROG_RUN al no poder construir el skb: {rechazadas_por_el_kernel}"
    );
}
