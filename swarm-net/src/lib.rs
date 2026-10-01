//! Transporte libp2p del enjambre: **mueve bytes, no toma decisiones**.
//!
//! # El reparto de responsabilidades, que es todo el diseño
//!
//! Este crate no decide nada. No sabe qué es una orden, no verifica firmas, no
//! cuenta testigos y no conoce el umbral de corroboro. Recibe bytes de la red,
//! se los da a [`aegis_swarm::Enjambre`] junto con la identidad del par que los
//! entregó, y hace lo que el núcleo le diga.
//!
//! Esa frontera es deliberada y es lo que permite que la FASE 68 esté de verdad
//! verificada: todos los ataques —reproducción, Sybil, inundación,
//! envenenamiento de trozos— se ejercen contra el núcleo *sans-io*, sin red y
//! sin condiciones de carrera, en `crates/aegis-swarm`. Si las decisiones
//! vivieran aquí dentro, probarlas exigiría levantar una red y se acabarían
//! quedando sin probar.
//!
//! # Por qué gossipsub y no una inundación propia
//!
//! La FASE 23 inunda con UDP y tres saltos, y para su caso —un datagrama de 200
//! bytes en un segmento local— está bien. Aquí el caso es otro: repartir
//! paquetes de reglas de cientos de kilobytes entre sedes, con pares que
//! aparecen y desaparecen. Gossipsub aporta lo que una inundación propia tendría
//! que reimplementar: malla con grado controlado, *heartbeat* que la repara
//! cuando un par se cae, y propagación que no degenera en difusión total.
//!
//! # Dos identidades distintas, y ninguna la elige el mensaje
//!
//! Al núcleo se le pasa el `PeerId` de libp2p del vecino que ENTREGÓ el
//! mensaje, autenticado por el apretón de manos Noise. Sirve para **repartir la
//! cuota de tasa**: un vecino no puede gastarle la cuota a otro.
//!
//! **No sirve para contar testigos**, y el núcleo no lo usa para eso: el
//! `PeerId` es efímero (`with_new_identity`), mDNS acepta a cualquiera de la red
//! local y en una malla quien entrega casi nunca es quien emitió. El corroboro de
//! [`aegis_swarm::quorum`] cuenta la identidad de la **credencial de par** que el
//! plano de control firmó al matricular ([`aegis_swarm::credencial`]), que viaja
//! con cada observación y se verifica en cualquier salto (H-04).

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;

use aegis_swarm::enjambre::{Enjambre, Salida};
use libp2p::swarm::NetworkBehaviour;
use libp2p::{gossipsub, mdns, noise, tcp, yamux};

/// Tema de gossipsub por el que viaja todo el enjambre.
pub const TEMA: &str = "aegis-swarm/v1";

/// Intervalo del *heartbeat* de la malla.
pub const LATIDO: Duration = Duration::from_secs(1);

/// Tope de mensaje que el transporte acepta.
///
/// Coincide a propósito con el del núcleo: dejar que el transporte acepte más
/// significaría gastar memoria y CPU en algo que el núcleo va a rechazar de
/// todas formas, y regalar así un amplificador.
pub const MAX_MENSAJE: usize = 64 * 1024;

/// Comportamiento de red del nodo.
#[derive(NetworkBehaviour)]
pub struct Comportamiento {
    /// Difusión por malla.
    pub gossipsub: gossipsub::Behaviour,
    /// Descubrimiento en red local, sin infraestructura.
    pub mdns: mdns::tokio::Behaviour,
}

/// Errores de la puesta en marcha del transporte.
#[derive(Debug)]
pub enum ErrorTransporte {
    /// No se pudo construir el swarm de libp2p.
    Construccion(String),
    /// No se pudo suscribir al tema.
    Suscripcion(String),
    /// No se pudo escuchar en la dirección pedida.
    Escucha(String),
}

impl std::fmt::Display for ErrorTransporte {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorTransporte::Construccion(m) => write!(f, "no se pudo construir el swarm: {m}"),
            ErrorTransporte::Suscripcion(m) => write!(f, "no se pudo suscribir al tema: {m}"),
            ErrorTransporte::Escucha(m) => write!(f, "no se pudo escuchar: {m}"),
        }
    }
}

impl std::error::Error for ErrorTransporte {}

/// Identificador de mensaje para gossipsub.
///
/// Se deriva del **contenido**, no de quién lo envía ni de cuándo: así el mismo
/// mensaje que llega por dos caminos se reconoce como uno solo y la malla no lo
/// vuelve a difundir. Es la misma razón por la que
/// [`aegis_swarm::Sobre::id`] ignora los saltos.
fn id_de_mensaje(m: &gossipsub::Message) -> gossipsub::MessageId {
    let mut h = DefaultHasher::new();
    m.data.hash(&mut h);
    gossipsub::MessageId::from(h.finish().to_string())
}

/// Construye el comportamiento de red.
///
/// # Errores
/// [`ErrorTransporte::Construccion`] si la configuración de gossipsub o mDNS no
/// se puede montar.
pub fn comportamiento(
    clave: &libp2p::identity::Keypair,
) -> Result<Comportamiento, ErrorTransporte> {
    let config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(LATIDO)
        // Estricta: sólo se acepta lo que viene firmado por el par que lo envía.
        // Es lo que hace que el `PeerId` que se le pasa al núcleo signifique
        // algo para la cuota de tasa. El quorum NO depende de él: cuenta la
        // credencial de par que viaja dentro de cada observación.
        .validation_mode(gossipsub::ValidationMode::Strict)
        .max_transmit_size(MAX_MENSAJE)
        .message_id_fn(id_de_mensaje)
        .build()
        .map_err(|e| ErrorTransporte::Construccion(e.to_string()))?;

    let gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(clave.clone()),
        config,
    )
    .map_err(|e| ErrorTransporte::Construccion(e.to_string()))?;

    let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), clave.public().to_peer_id())
        .map_err(|e| ErrorTransporte::Construccion(e.to_string()))?;

    Ok(Comportamiento { gossipsub, mdns })
}

/// Un nodo del enjambre: transporte libp2p enchufado al núcleo de decisiones.
pub struct Nodo {
    /// El swarm de libp2p.
    pub swarm: libp2p::Swarm<Comportamiento>,
    /// El núcleo que decide.
    pub enjambre: Enjambre,
    tema: gossipsub::IdentTopic,
}

impl Nodo {
    /// Levanta un nodo escuchando en `direccion`.
    ///
    /// # Errores
    /// [`ErrorTransporte`] si el swarm no se puede construir, suscribir o poner
    /// a escuchar.
    pub fn nuevo(enjambre: Enjambre, direccion: &str) -> Result<Nodo, ErrorTransporte> {
        let mut swarm = libp2p::SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| ErrorTransporte::Construccion(e.to_string()))?
            .with_behaviour(|clave| {
                comportamiento(clave)
                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })
            })
            .map_err(|e| ErrorTransporte::Construccion(e.to_string()))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        let tema = gossipsub::IdentTopic::new(TEMA);
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&tema)
            .map_err(|e| ErrorTransporte::Suscripcion(format!("{e:?}")))?;
        swarm
            .listen_on(
                direccion
                    .parse()
                    .map_err(|e| ErrorTransporte::Escucha(format!("{e:?}")))?,
            )
            .map_err(|e| ErrorTransporte::Escucha(e.to_string()))?;

        Ok(Nodo {
            swarm,
            enjambre,
            tema,
        })
    }

    /// El identificador de este nodo.
    #[must_use]
    pub fn id(&self) -> libp2p::PeerId {
        *self.swarm.local_peer_id()
    }

    /// Publica bytes ya preparados por el núcleo.
    ///
    /// # Los fallos transitorios no son fallos
    ///
    /// Esta es la función donde un enjambre mal escrito se rompe. En una malla
    /// los vecinos aparecen y desaparecen constantemente, y **el escenario para
    /// el que existe esta fase es precisamente el de la red rota**: publicar sin
    /// vecinos, o con las colas llenas porque un vecino va lento, es lo normal,
    /// no una anomalía. Un nodo que tratara eso como error —y mucho menos que
    /// entrara en pánico— se caería justo cuando hace falta.
    ///
    /// Por eso se distinguen tres clases:
    ///
    /// - **Transitorias** (sin vecinos aún, colas llenas): se reintenta luego,
    ///   nivel `debug`. No son un problema del nodo.
    /// - **Duplicado**: la malla ya lo tiene. Es el mecanismo funcionando, no un
    ///   fallo; se cuenta como éxito.
    /// - **Persistentes** (mensaje demasiado grande, fallo de firma o de
    ///   transformación): eso sí es un defecto y se registra como aviso, porque
    ///   reintentarlo daría el mismo resultado para siempre.
    ///
    /// Devuelve `true` si el mensaje está en la malla o ya estaba.
    pub fn publicar(&mut self, bytes: Vec<u8>) -> bool {
        match self
            .swarm
            .behaviour_mut()
            .gossipsub
            .publish(self.tema.clone(), bytes)
        {
            Ok(_) => true,
            // Ya estaba: la malla funcionando, no un fallo.
            Err(gossipsub::PublishError::Duplicate) => true,
            // Transitorio: la malla todavia no esta formada, o un vecino va
            // lento. Es el estado NORMAL de una red degradada.
            Err(gossipsub::PublishError::NoPeersSubscribedToTopic) => {
                tracing::debug!("aun no hay vecinos suscritos; se reintentara");
                false
            }
            Err(gossipsub::PublishError::AllQueuesFull(pares)) => {
                tracing::debug!("las colas de los {pares} vecinos estan llenas; se reintentara");
                false
            }
            // Persistente: reintentar daria lo mismo siempre.
            Err(e) => {
                tracing::warn!("no se pudo publicar en la malla, y no es transitorio: {e:?}");
                false
            }
        }
    }

    /// Entrega a la malla lo que el núcleo haya decidido reenviar.
    pub fn aplicar(&mut self, salidas: &[Salida]) {
        for s in salidas {
            if let Salida::Reenviar(bytes) = s {
                self.publicar(bytes.clone());
            }
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn el_identificador_de_mensaje_se_deriva_del_contenido_y_no_del_emisor() {
        // Dos mensajes con el mismo contenido y distinto emisor tienen que dar
        // el mismo identificador: si no, el mismo mensaje reenviado por dos
        // vecinos se difundiria dos veces y la malla no convergeria.
        let mut a = DefaultHasher::new();
        b"contenido".hash(&mut a);
        let mut b = DefaultHasher::new();
        b"contenido".hash(&mut b);
        assert_eq!(a.finish(), b.finish());

        let mut c = DefaultHasher::new();
        b"otro".hash(&mut c);
        assert_ne!(a.finish(), c.finish());
    }

    #[test]
    fn el_tope_del_transporte_coincide_con_el_del_nucleo() {
        assert_eq!(
            MAX_MENSAJE,
            aegis_swarm::mensaje::MAX_MENSAJE,
            "si el transporte aceptara mas que el nucleo, gastaria memoria y CPU \
             en algo que el nucleo va a rechazar igual"
        );
    }
}
