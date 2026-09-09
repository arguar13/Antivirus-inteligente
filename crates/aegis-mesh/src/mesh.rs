//! La malla: descubrimiento, propagacion y reenvio controlado.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use crate::crypto::{self, ReplayWindow};
use crate::error::MeshError;
use crate::vaccine::Vaccine;
use crate::wire::{self, Header, MsgType, HEADER_LEN, MAX_DATAGRAM, VERSION};

/// Identidad de un nodo de la malla.
pub type NodeId = [u8; 16];

/// Configuracion de la malla.
#[derive(Debug, Clone)]
pub struct MeshConfig {
    /// Direccion en la que escuchar.
    pub bind: SocketAddr,
    /// Pares conocidos a los que enviar directamente.
    pub peers: Vec<SocketAddr>,
    /// Grupo de multidifusion para el descubrimiento, si se usa.
    pub multicast: Option<(Ipv4Addr, u16)>,
    /// Clave compartida de la malla.
    pub key: [u8; 32],
    /// Saltos maximos de una vacuna.
    ///
    /// Tres bastan para cubrir una red local con reenvio; mas solo multiplica el
    /// trafico, porque la deduplicacion ya corta los caminos redundantes.
    pub max_hops: u8,
    /// Vacunas recordadas para deduplicar.
    pub dedup_capacity: usize,
    /// Mensajes por par y ventana antes de empezar a descartar.
    pub rate_per_peer: u32,
    /// Duracion de la ventana de tasa.
    pub rate_window: Duration,
    /// Edad maxima de una vacuna aceptable, en segundos.
    pub max_age_secs: u64,
    /// Holgura admitida hacia el futuro, en segundos.
    pub clock_skew_secs: u64,
    /// Si es falso, la malla no reenvia lo que recibe.
    pub relay: bool,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            peers: Vec::new(),
            multicast: None,
            key: [0u8; 32],
            max_hops: 3,
            dedup_capacity: 4096,
            rate_per_peer: 64,
            rate_window: Duration::from_secs(10),
            // 24 horas: una vacuna mas vieja ya llego por el canal de
            // sincronizacion, que es el que garantiza convergencia.
            max_age_secs: 86_400,
            clock_skew_secs: 300,
            relay: true,
        }
    }
}

/// Por que se descarto un datagrama.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DropReason {
    /// No es un mensaje de la malla o esta truncado.
    Malformed,
    /// Version del protocolo que este agente no habla.
    Version,
    /// No supero el cifrado autenticado.
    NotAuthentic,
    /// Contador repetido o fuera de la ventana.
    Replay,
    /// Vacuna ya conocida.
    Duplicate,
    /// El par supero su tasa.
    RateLimited,
    /// Vacuna caducada o fechada en el futuro.
    Stale,
    /// Vino de este mismo nodo.
    Loopback,
    /// Agoto los saltos.
    HopsExhausted,
}

/// Contadores de la malla.
#[derive(Debug, Default, Clone)]
pub struct MeshStats {
    /// Datagramas enviados.
    pub sent: u64,
    /// Datagramas recibidos.
    pub received: u64,
    /// Vacunas aceptadas.
    pub accepted: u64,
    /// Vacunas reenviadas.
    pub relayed: u64,
    /// Descartes por motivo.
    pub drops: HashMap<DropReason, u64>,
}

impl MeshStats {
    /// Descartes totales.
    pub fn dropped(&self) -> u64 {
        self.drops.values().sum()
    }

    /// Descartes de un motivo concreto.
    pub fn drops_of(&self, r: DropReason) -> u64 {
        self.drops.get(&r).copied().unwrap_or(0)
    }
}

/// Una vacuna aceptada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Received {
    /// La vacuna.
    pub vaccine: Vaccine,
    /// Nodo que la envio (el ultimo salto, no necesariamente el origen).
    pub from_node: NodeId,
    /// Direccion desde la que llego.
    pub from_addr: SocketAddr,
    /// Cierto si esta malla la reenvio.
    pub relayed: bool,
}

/// Estado que se guarda de cada par.
#[derive(Debug)]
struct PeerState {
    ventana: ReplayWindow,
    /// Sesion a la que corresponde la ventana. Una sesion nueva reinicia la
    /// ventana, porque los contadores vuelven a empezar.
    sesion: [u8; 8],
    tokens: u32,
    ultima_recarga: Instant,
    ultima_vista: Instant,
    addr: SocketAddr,
}

/// Malla P2P de la red local.
#[derive(Debug)]
pub struct Mesh {
    sock: UdpSocket,
    config: MeshConfig,
    node: NodeId,
    session: [u8; 8],
    counter: u32,
    peers: HashMap<NodeId, PeerState>,
    /// Vacunas ya vistas, con el orden de llegada para poder expulsar.
    vistas: HashMap<[u8; 32], usize>,
    orden: std::collections::VecDeque<[u8; 32]>,
    stats: MeshStats,
}

impl Mesh {
    /// Levanta la malla.
    pub fn bind(config: MeshConfig) -> Result<Mesh, MeshError> {
        let sock =
            UdpSocket::bind(config.bind).map_err(|source| MeshError::Net { op: "bind", source })?;
        sock.set_nonblocking(true)
            .map_err(|source| MeshError::Net {
                op: "set_nonblocking",
                source,
            })?;

        if let Some((grupo, _)) = config.multicast {
            // Unirse al grupo puede fallar en un contenedor sin multidifusion.
            // No es fatal: la malla sigue funcionando con los pares estaticos, y
            // fallar aqui dejaria sin proteccion a una flota entera por un
            // detalle de red.
            let _ = sock.join_multicast_v4(&grupo, &Ipv4Addr::UNSPECIFIED);
        }

        let mut node = [0u8; 16];
        crypto::aleatorio(&mut node);
        let mut session = [0u8; 8];
        crypto::aleatorio(&mut session);

        Ok(Mesh {
            sock,
            config,
            node,
            session,
            counter: 0,
            peers: HashMap::new(),
            vistas: HashMap::new(),
            orden: std::collections::VecDeque::new(),
            stats: MeshStats::default(),
        })
    }

    /// Direccion en la que escucha.
    pub fn local_addr(&self) -> SocketAddr {
        self.sock
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
    }

    /// Identidad de este nodo.
    pub fn node_id(&self) -> NodeId {
        self.node
    }

    /// Contadores.
    pub fn stats(&self) -> &MeshStats {
        &self.stats
    }

    /// Pares de los que se ha recibido algo.
    pub fn known_peers(&self) -> usize {
        self.peers.len()
    }

    /// Anade un par al que enviar.
    pub fn add_peer(&mut self, addr: SocketAddr) {
        if !self.config.peers.contains(&addr) {
            self.config.peers.push(addr);
        }
    }

    /// Anuncia la presencia de este nodo.
    pub fn announce(&mut self) -> Result<usize, MeshError> {
        self.enviar(MsgType::Announce, &[])
    }

    /// Propaga una vacuna a la malla.
    pub fn broadcast(&mut self, v: &Vaccine) -> Result<usize, MeshError> {
        // Lo propio tambien se recuerda: si volviera por un reenvio de otro
        // agente, se reconoceria como duplicado en vez de reenviarse otra vez.
        self.recordar(v.id());
        let cuerpo = wire::encode_vaccine(v);
        self.enviar(MsgType::Vaccine, &cuerpo)
    }

    fn enviar(&mut self, tipo: MsgType, cuerpo: &[u8]) -> Result<usize, MeshError> {
        let contador = self
            .counter
            .checked_add(1)
            .ok_or(MeshError::SessionExhausted)?;
        let h = Header {
            version: VERSION,
            msg_type: tipo,
            session: self.session,
            counter: contador,
            node: self.node,
        };
        let aad = h.encode();
        let sellado = crypto::seal(&self.config.key, &h.nonce(), &aad, cuerpo)?;

        let total = HEADER_LEN + sellado.len();
        if total > MAX_DATAGRAM {
            return Err(MeshError::TooLarge {
                bytes: total,
                max: MAX_DATAGRAM,
            });
        }
        let mut datagrama = Vec::with_capacity(total);
        datagrama.extend_from_slice(&aad);
        datagrama.extend_from_slice(&sellado);

        // El contador solo avanza si el mensaje se llego a construir: gastarlo
        // en un mensaje que no se envia no rompe nada, pero no gastarlo cuando
        // si se envio repetiria un nonce.
        self.counter = contador;

        let mut destinos: Vec<SocketAddr> = self.config.peers.clone();
        if let Some((g, p)) = self.config.multicast {
            destinos.push(SocketAddr::new(IpAddr::V4(g), p));
        }
        // Los pares descubiertos tambien reciben: son los que no estaban en la
        // configuracion pero han hablado.
        for st in self.peers.values() {
            if !destinos.contains(&st.addr) {
                destinos.push(st.addr);
            }
        }

        let mut enviados = 0usize;
        for d in destinos {
            // Un par caido no puede impedir que los demas reciban la vacuna: un
            // error de envio se cuenta y se sigue. En una red local, "puerto no
            // alcanzable" es el caso normal cuando un equipo se apaga.
            if self.sock.send_to(&datagrama, d).is_ok() {
                enviados += 1;
                self.stats.sent += 1;
            }
        }
        Ok(enviados)
    }

    /// Atiende lo que haya llegado, esperando como mucho `timeout`.
    ///
    /// `ahora` es el reloj de pared en segundos, que el llamante aporta para que
    /// las pruebas puedan controlar la caducidad.
    pub fn poll(&mut self, timeout: Duration, ahora: u64) -> Vec<Received> {
        let limite = Instant::now() + timeout;
        let mut salida = Vec::new();
        let mut buf = [0u8; MAX_DATAGRAM];

        loop {
            match self.sock.recv_from(&mut buf) {
                Ok((n, origen)) => {
                    self.stats.received += 1;
                    if let Some(r) = self.procesar(&buf[..n], origen, ahora) {
                        salida.push(r);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if !salida.is_empty() || Instant::now() >= limite {
                        return salida;
                    }
                    // Espera corta: el socket es no bloqueante para poder
                    // atender la senal de parada del agente sin quedarse
                    // colgado en `recvfrom`.
                    std::thread::sleep(
                        Duration::from_millis(5)
                            .min(limite.saturating_duration_since(Instant::now())),
                    );
                }
                // Un ICMP de "puerto no alcanzable" de un envio anterior llega
                // como error en el siguiente `recv`. No es un fallo de este
                // datagrama: se sigue leyendo.
                Err(_) => {
                    if Instant::now() >= limite {
                        return salida;
                    }
                }
            }
        }
    }

    fn descartar(&mut self, r: DropReason) -> Option<Received> {
        *self.stats.drops.entry(r).or_insert(0) += 1;
        None
    }

    fn procesar(&mut self, datos: &[u8], origen: SocketAddr, ahora: u64) -> Option<Received> {
        let Some(h) = Header::decode(datos) else {
            return self.descartar(DropReason::Malformed);
        };
        if h.version != VERSION {
            return self.descartar(DropReason::Version);
        }
        if h.node == self.node {
            // El propio anuncio vuelve por multidifusion. No es un ataque.
            return self.descartar(DropReason::Loopback);
        }

        // Tasa y repeticion se comprueban ANTES de descifrar: descifrar es lo
        // caro, y dejar que un atacante fuerce un descifrado por datagrama es
        // regalarle un amplificador de CPU.
        if !self.consumir_token(h.node, h.session, origen) {
            return self.descartar(DropReason::RateLimited);
        }
        if !self.aceptar_contador(h.node, h.session, h.counter) {
            return self.descartar(DropReason::Replay);
        }

        let aad = &datos[..HEADER_LEN];
        let Ok(plano) = crypto::open(&self.config.key, &h.nonce(), aad, &datos[HEADER_LEN..])
        else {
            return self.descartar(DropReason::NotAuthentic);
        };

        if h.msg_type == MsgType::Announce {
            // El anuncio ya cumplio su funcion: dar de alta al par.
            return None;
        }

        let Some(v) = wire::decode_vaccine(&plano) else {
            return self.descartar(DropReason::Malformed);
        };
        if v.expired(ahora, self.config.max_age_secs)
            || v.from_future(ahora, self.config.clock_skew_secs)
        {
            return self.descartar(DropReason::Stale);
        }
        if self.vistas.contains_key(&v.id()) {
            return self.descartar(DropReason::Duplicate);
        }
        self.recordar(v.id());
        self.stats.accepted += 1;

        // Reenvio con limite de saltos: es lo que impide la tormenta de
        // difusion. La deduplicacion sola no basta, porque en el instante en que
        // tres agentes reciben algo nuevo a la vez, los tres lo reenvian.
        let mut relayed = false;
        if self.config.relay && v.hops < self.config.max_hops {
            let mut siguiente = v.clone();
            siguiente.hops += 1;
            let cuerpo = wire::encode_vaccine(&siguiente);
            if self.enviar(MsgType::Vaccine, &cuerpo).is_ok() {
                relayed = true;
                self.stats.relayed += 1;
            }
        } else if self.config.relay {
            *self
                .stats
                .drops
                .entry(DropReason::HopsExhausted)
                .or_insert(0) += 1;
        }

        Some(Received {
            vaccine: v,
            from_node: h.node,
            from_addr: origen,
            relayed,
        })
    }

    fn consumir_token(&mut self, node: NodeId, sesion: [u8; 8], addr: SocketAddr) -> bool {
        let cfg_tasa = self.config.rate_per_peer;
        let cfg_ventana = self.config.rate_window;
        let ahora = Instant::now();

        // Cota de memoria: un atacante que falsifique identidades de nodo haria
        // crecer esta tabla sin limite. Al llegar al tope se olvida al par mas
        // antiguo, que es el que menos informacion aporta.
        if self.peers.len() >= 1024 && !self.peers.contains_key(&node) {
            if let Some(k) = self
                .peers
                .iter()
                .min_by_key(|(_, s)| s.ultima_vista)
                .map(|(k, _)| *k)
            {
                self.peers.remove(&k);
            }
        }

        let st = self.peers.entry(node).or_insert_with(|| PeerState {
            ventana: ReplayWindow::new(),
            sesion,
            tokens: cfg_tasa,
            ultima_recarga: ahora,
            ultima_vista: ahora,
            addr,
        });
        st.ultima_vista = ahora;
        st.addr = addr;

        if ahora.duration_since(st.ultima_recarga) >= cfg_ventana {
            st.tokens = cfg_tasa;
            st.ultima_recarga = ahora;
        }
        if st.tokens == 0 {
            return false;
        }
        st.tokens -= 1;
        true
    }

    fn aceptar_contador(&mut self, node: NodeId, sesion: [u8; 8], contador: u32) -> bool {
        let Some(st) = self.peers.get_mut(&node) else {
            return false;
        };
        if st.sesion != sesion {
            // Sesion nueva: el par se reinicio y sus contadores vuelven a
            // empezar. La ventana se reinicia con ella, o el primer mensaje del
            // par reiniciado se leeria como una repeticion.
            st.sesion = sesion;
            st.ventana = ReplayWindow::new();
        }
        st.ventana.accept(contador)
    }

    fn recordar(&mut self, id: [u8; 32]) {
        if self.vistas.contains_key(&id) {
            return;
        }
        self.vistas.insert(id, 0);
        self.orden.push_back(id);
        while self.orden.len() > self.config.dedup_capacity {
            if let Some(viejo) = self.orden.pop_front() {
                self.vistas.remove(&viejo);
            }
        }
    }

    /// Vacunas recordadas ahora mismo.
    pub fn remembered(&self) -> usize {
        self.vistas.len()
    }
}
