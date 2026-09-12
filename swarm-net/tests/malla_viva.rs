//! Dos nodos libp2p **de verdad**, hablando por loopback.
//!
//! Esto no es una simulación del transporte: son dos `Swarm` completos, con
//! apretón de manos Noise auténtico, multiplexado Yamux y difusión gossipsub
//! real sobre TCP. Existe porque la alternativa —declarar el transporte como
//! muro y probar sólo el núcleo— dejaría sin verificar justo la unión entre los
//! dos, que es donde se esconden los fallos de integración: un tema mal
//! suscrito, un tope de mensaje incoherente, o una identidad de par que no llega
//! al núcleo y hace que el quorum cuente mal.
//!
//! El descubrimiento se hace marcando la dirección explícitamente en vez de por
//! mDNS: mDNS necesita multicast en la red local, que un contenedor de CI no
//! tiene, y una prueba que dependiera de eso sería una prueba que se salta sola.
//! Lo que se ejercita —difusión, identidad autenticada, entrega al núcleo— es lo
//! mismo por los dos caminos.

use std::time::Duration;

use aegis_pqc::firma_hibrida::ClaveFirmaHibrida;
use aegis_swarm::enjambre::{ConfigEnjambre, Enjambre, EstadoEnlace, Salida};
use aegis_swarm::mensaje::{Sobre, TipoMensaje};
use aegis_swarm::orden::{Accion, Orden, CTX_ORDEN};
use aegis_swarm_net::{ComportamientoEvent, Nodo};
use aegis_update::signature::ClaveActualizacion;
use futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use libp2p::{gossipsub, Multiaddr};

/// El plano de control. Su clave privada no está en ningún agente.
fn plano_de_control() -> ClaveFirmaHibrida {
    ClaveFirmaHibrida::desde_semillas(&[42u8; 32], &[99u8; 32])
}

fn config(pc: &ClaveFirmaHibrida) -> ConfigEnjambre {
    ConfigEnjambre {
        clave_plano_control: ClaveActualizacion::Hibrida(Box::new(pc.clave_verificacion())),
        saltos: 3,
        tasa: 1024,
        umbral_corroboro: 3,
        ventana_corroboro_seg: 3600,
    }
}

/// Espera a que un nodo anuncie por dónde escucha.
async fn direccion_de(nodo: &mut Nodo) -> Multiaddr {
    loop {
        if let SwarmEvent::NewListenAddr { address, .. } = nodo.swarm.select_next_some().await {
            return address;
        }
    }
}

/// EL CIRCUITO COMPLETO: el plano de control firma una orden de aislamiento, un
/// agente la publica en la malla, y **otro agente la recibe por libp2p de verdad
/// y su núcleo la aplica**, sin consola por medio.
#[tokio::test(flavor = "multi_thread")]
async fn una_orden_firmada_cruza_una_malla_libp2p_real_y_se_aplica_en_el_otro_extremo() {
    let pc = plano_de_control();

    let mut emisor = Nodo::nuevo(Enjambre::nuevo(config(&pc)), "/ip4/127.0.0.1/tcp/0")
        .expect("el nodo emisor levanta");
    let mut receptor = Nodo::nuevo(Enjambre::nuevo(config(&pc)), "/ip4/127.0.0.1/tcp/0")
        .expect("el nodo receptor levanta");

    // Los dos están aislados del plano de control: es el escenario de la fase.
    emisor.enjambre.declarar_enlace(EstadoEnlace::Aislado);
    receptor.enjambre.declarar_enlace(EstadoEnlace::Aislado);

    let dir_receptor = direccion_de(&mut receptor).await;
    emisor
        .swarm
        .dial(dir_receptor.clone())
        .expect("se marca la direccion del vecino");

    // La orden que el plano de control emitió antes de que se cayera el enlace.
    let orden = Orden {
        accion: Accion::AislarRed,
        sujeto: "endpoint-17".to_string(),
        incidente: "inc-2026-0042".to_string(),
        epoca: 1,
        emitida_en: 1_000_000,
        caduca_en: 1_003_600,
    };
    let firma = pc
        .firmar(&orden.bytes_firmados(), CTX_ORDEN)
        .expect("el plano de control firma")
        .a_bytes()
        .to_vec();
    let mensaje = Sobre {
        tipo: TipoMensaje::Orden,
        saltos: 3,
        cuerpo: orden.a_bytes(),
        firma,
    }
    .a_bytes();

    let resultado = tokio::time::timeout(Duration::from_secs(30), async {
        let mut publicado = false;
        loop {
            tokio::select! {
                ev = emisor.swarm.select_next_some() => {
                    // En cuanto el vecino se suscribe al tema, se publica. Antes
                    // no: gossipsub no tendria a quien entregarselo.
                    if let SwarmEvent::Behaviour(ComportamientoEvent::Gossipsub(
                        gossipsub::Event::Subscribed { .. })) = ev
                    {
                        if !publicado {
                            publicado = emisor.publicar(mensaje.clone());
                        }
                    }
                }
                ev = receptor.swarm.select_next_some() => {
                    if let SwarmEvent::Behaviour(ComportamientoEvent::Gossipsub(
                        gossipsub::Event::Message { propagation_source, message, .. })) = ev
                    {
                        // La identidad se la da el TRANSPORTE, autenticada por
                        // Noise; no viene dentro del mensaje.
                        let salidas = receptor.enjambre.recibir(
                            &propagation_source.to_string(),
                            &message.data,
                            1_000_000,
                        );
                        if let Some(o) = salidas.iter().find_map(|s| match s {
                            Salida::AplicarOrden(o) => Some((**o).clone()),
                            _ => None,
                        }) {
                            return o;
                        }
                    }
                }
            }
        }
    })
    .await
    .expect("la orden tiene que cruzar la malla dentro del plazo");

    assert_eq!(resultado, orden, "la orden llega intacta al otro extremo");
}

/// El mismo camino, pero con una orden firmada por **otra** clave: cruza la
/// malla igual —el transporte no juzga— y el núcleo del receptor la rechaza.
/// Es la demostración de que la seguridad no está en el transporte.
#[tokio::test(flavor = "multi_thread")]
async fn una_orden_de_un_impostor_cruza_la_malla_y_el_nucleo_la_rechaza() {
    let pc = plano_de_control();
    let impostor = ClaveFirmaHibrida::desde_semillas(&[1u8; 32], &[2u8; 32]);

    let mut emisor =
        Nodo::nuevo(Enjambre::nuevo(config(&pc)), "/ip4/127.0.0.1/tcp/0").expect("emisor");
    let mut receptor =
        Nodo::nuevo(Enjambre::nuevo(config(&pc)), "/ip4/127.0.0.1/tcp/0").expect("receptor");

    let dir = direccion_de(&mut receptor).await;
    emisor.swarm.dial(dir).expect("marcar");

    let orden = Orden {
        accion: Accion::AislarRed,
        sujeto: "el-salto-del-soc".to_string(),
        incidente: "fabricado".to_string(),
        epoca: 1,
        emitida_en: 1_000_000,
        caduca_en: 1_003_600,
    };
    let firma = impostor
        .firmar(&orden.bytes_firmados(), CTX_ORDEN)
        .expect("el impostor firma con SU clave")
        .a_bytes()
        .to_vec();
    let mensaje = Sobre {
        tipo: TipoMensaje::Orden,
        saltos: 3,
        cuerpo: orden.a_bytes(),
        firma,
    }
    .a_bytes();

    let rechazada = tokio::time::timeout(Duration::from_secs(30), async {
        let mut publicado = false;
        loop {
            tokio::select! {
                ev = emisor.swarm.select_next_some() => {
                    if let SwarmEvent::Behaviour(ComportamientoEvent::Gossipsub(
                        gossipsub::Event::Subscribed { .. })) = ev
                    {
                        if !publicado {
                            publicado = emisor.publicar(mensaje.clone());
                        }
                    }
                }
                ev = receptor.swarm.select_next_some() => {
                    if let SwarmEvent::Behaviour(ComportamientoEvent::Gossipsub(
                        gossipsub::Event::Message { propagation_source, message, .. })) = ev
                    {
                        let salidas = receptor.enjambre.recibir(
                            &propagation_source.to_string(),
                            &message.data,
                            1_000_000,
                        );
                        assert!(
                            !salidas.iter().any(|s| matches!(s, Salida::AplicarOrden(_))),
                            "una orden de un impostor JAMAS puede aplicarse"
                        );
                        return salidas;
                    }
                }
            }
        }
    })
    .await
    .expect("el mensaje llega, aunque sea para rechazarlo");

    assert!(
        rechazada.iter().any(|s| matches!(
            s,
            Salida::Descartado(aegis_swarm::MotivoDescarte::FirmaInvalida)
        )),
        "el nucleo tiene que decir POR QUE lo rechaza: {rechazada:?}"
    );
}

/// Publicar sin vecinos **no es un error**. Es el estado normal de un endpoint
/// recién arrancado en una red rota, que es el escenario de esta fase; un nodo
/// que se cayera aquí sería inútil justo cuando hace falta.
#[tokio::test(flavor = "multi_thread")]
async fn publicar_sin_vecinos_no_rompe_el_nodo() {
    let pc = plano_de_control();
    let mut solo = Nodo::nuevo(Enjambre::nuevo(config(&pc)), "/ip4/127.0.0.1/tcp/0")
        .expect("el nodo levanta aunque no haya nadie mas");

    for _ in 0..100 {
        assert!(
            !solo.publicar(b"cualquier cosa".to_vec()),
            "sin vecinos no se entrega, pero tampoco se rompe"
        );
    }
    // Y el nodo sigue vivo y usable.
    assert!(!solo.id().to_string().is_empty());
}

/// Un vecino que se cae a mitad no deja al otro colgado ni lo hace entrar en
/// pánico: la malla lo nota y sigue.
#[tokio::test(flavor = "multi_thread")]
async fn la_caida_de_un_vecino_no_tumba_al_que_queda() {
    let pc = plano_de_control();
    let mut a = Nodo::nuevo(Enjambre::nuevo(config(&pc)), "/ip4/127.0.0.1/tcp/0").expect("a");
    let mut b = Nodo::nuevo(Enjambre::nuevo(config(&pc)), "/ip4/127.0.0.1/tcp/0").expect("b");

    let dir = direccion_de(&mut b).await;
    a.swarm.dial(dir).expect("marcar");

    // Se espera a que se conecten de verdad.
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            tokio::select! {
                ev = a.swarm.select_next_some() => {
                    if matches!(ev, SwarmEvent::ConnectionEstablished { .. }) { return; }
                }
                _ = b.swarm.select_next_some() => {}
            }
        }
    })
    .await
    .expect("los dos nodos se conectan");

    // El vecino desaparece.
    drop(b);

    // El que queda sigue procesando eventos sin panico durante un rato.
    let _ = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let _ = a.swarm.select_next_some().await;
        }
    })
    .await;

    assert!(!a.publicar(b"algo".to_vec()), "sin vecinos, pero vivo");
}
