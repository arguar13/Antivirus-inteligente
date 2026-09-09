//! Servicios senuelo: puertos que existen solo para ser tocados.
//!
//! # Por que esto no tiene falsos positivos
//!
//! Un detector de intrusiones normal decide si un trafico legitimo es
//! sospechoso, y por eso siempre se equivoca en algun caso. Un senuelo invierte
//! el problema: **el servicio no existe**. Ningun usuario, ninguna aplicacion y
//! ningun sistema de monitorizacion tiene motivo para conectar a un puerto que
//! no publica nada. Cualquier conexion es, por construccion, no autorizada.
//!
//! La unica fuente real de ruido son los escaneres autorizados de la propia
//! organizacion, y esos se conocen por direccion: van en la lista de
//! [`crate::guard::Guard`], no en la heuristica.
//!
//! # Lo que un senuelo NUNCA debe hacer
//!
//! Tapar un servicio de verdad. Si el puerto 22 lo esta usando el `sshd` real,
//! el senuelo **no** lo toma: dejaria la maquina sin administracion remota, y un
//! producto de seguridad que corta el acceso legitimo se desinstala el mismo
//! dia. Cuando eso pasa se informa, no se fuerza.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::os::unix::io::AsRawFd;
use std::time::Duration;

/// Servicio que se finge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DecoyKind {
    /// SSH (22): el objetivo numero uno de la fuerza bruta.
    Ssh,
    /// SMB (445): el vector de movimiento lateral en redes Windows.
    Smb,
    /// RDP (3389): escritorio remoto, la puerta de entrada mas buscada.
    Rdp,
    /// FTP (21).
    Ftp,
    /// Telnet (23).
    Telnet,
    /// MySQL (3306).
    MySql,
    /// PostgreSQL (5432).
    Postgres,
    /// VNC (5900).
    Vnc,
    /// WinRM (5985).
    WinRm,
}

/// Todos los senuelos del catalogo.
pub const CATALOGO: [DecoyKind; 9] = [
    DecoyKind::Ssh,
    DecoyKind::Smb,
    DecoyKind::Rdp,
    DecoyKind::Ftp,
    DecoyKind::Telnet,
    DecoyKind::MySql,
    DecoyKind::Postgres,
    DecoyKind::Vnc,
    DecoyKind::WinRm,
];

impl DecoyKind {
    /// Puerto habitual del servicio.
    pub fn default_port(self) -> u16 {
        match self {
            DecoyKind::Ftp => 21,
            DecoyKind::Ssh => 22,
            DecoyKind::Telnet => 23,
            DecoyKind::Smb => 445,
            DecoyKind::MySql => 3306,
            DecoyKind::Rdp => 3389,
            DecoyKind::Postgres => 5432,
            DecoyKind::Vnc => 5900,
            DecoyKind::WinRm => 5985,
        }
    }

    /// Nombre corto, para alertas y registros.
    pub fn as_str(self) -> &'static str {
        match self {
            DecoyKind::Ssh => "ssh",
            DecoyKind::Smb => "smb",
            DecoyKind::Rdp => "rdp",
            DecoyKind::Ftp => "ftp",
            DecoyKind::Telnet => "telnet",
            DecoyKind::MySql => "mysql",
            DecoyKind::Postgres => "postgres",
            DecoyKind::Vnc => "vnc",
            DecoyKind::WinRm => "winrm",
        }
    }

    /// Saludo que el servicio real enviaria nada mas aceptar.
    ///
    /// Se envia porque un escaner que no recibe nada anota "puerto abierto,
    /// servicio desconocido" y sigue; uno que recibe un saludo creible anota el
    /// servicio y la version, y **vuelve** con un exploit concreto. Esa segunda
    /// visita es informacion de altisimo valor: dice que herramientas usa y que
    /// vulnerabilidades busca.
    ///
    /// Los protocolos binarios (SMB, RDP, VNC) no saludan con texto; para ellos
    /// se acepta y se escucha, que es lo que hace el servicio real.
    pub fn banner(self) -> Option<&'static [u8]> {
        match self {
            DecoyKind::Ssh => Some(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"),
            DecoyKind::Ftp => Some(b"220 (vsFTPd 3.0.5)\r\n"),
            DecoyKind::Telnet => Some(b"\r\nUbuntu 22.04.3 LTS\r\nlogin: "),
            DecoyKind::MySql => Some(b"J\x00\x00\x00\x0a8.0.35\x00"),
            DecoyKind::Postgres => None,
            DecoyKind::Smb | DecoyKind::Rdp | DecoyKind::Vnc | DecoyKind::WinRm => None,
        }
    }
}

/// Una interaccion observada contra un senuelo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interaction {
    /// Direccion desde la que se conecto.
    pub peer: IpAddr,
    /// Puerto de origen, util para correlacionar con la telemetria del kernel.
    pub peer_port: u16,
    /// Senuelo tocado.
    pub kind: DecoyKind,
    /// Puerto en el que escuchaba el senuelo.
    pub port: u16,
    /// Instante en nanosegundos monotonos.
    pub ts_ns: u64,
    /// Primeros bytes que envio el cliente, si envio algo.
    ///
    /// Es la evidencia: distingue un barrido de puertos —que conecta y cierra—
    /// de un intento de explotacion, que manda una peticion concreta.
    pub evidence: Vec<u8>,
}

impl Interaction {
    /// Indica si el cliente llego a enviar datos.
    pub fn spoke(&self) -> bool {
        !self.evidence.is_empty()
    }
}

/// Configuracion de la red de senuelos.
#[derive(Debug, Clone)]
pub struct DecoyConfig {
    /// Direccion en la que escuchar.
    pub bind: IpAddr,
    /// Servicios a fingir, con el puerto en el que hacerlo.
    ///
    /// Un puerto de 0 pide uno efimero al sistema, que es lo que usan las
    /// pruebas para no chocar con nada.
    pub services: Vec<(DecoyKind, u16)>,
    /// Tiempo que se espera a que el cliente hable tras aceptar.
    ///
    /// Corto a proposito: el bucle es de un solo hilo y cada conexion ya es un
    /// incidente, asi que no interesa entretenerse, interesa contarlo.
    pub speak_timeout: Duration,
    /// Bytes maximos de evidencia por conexion.
    pub max_evidence: usize,
    /// Conexiones maximas atendidas por vuelta.
    ///
    /// Acota el trabajo de un ciclo: sin este limite, una inundacion contra los
    /// senuelos convertiria el detector en el objetivo.
    pub max_per_poll: usize,
}

impl Default for DecoyConfig {
    fn default() -> Self {
        Self {
            bind: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            services: [DecoyKind::Ssh, DecoyKind::Smb, DecoyKind::Rdp]
                .iter()
                .map(|k| (*k, k.default_port()))
                .collect(),
            speak_timeout: Duration::from_millis(200),
            max_evidence: 512,
            max_per_poll: 64,
        }
    }
}

/// Por que un senuelo no se pudo levantar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    /// El puerto ya lo usa otro proceso.
    ///
    /// Puede ser el servicio REAL: taparlo dejaria la maquina sin el.
    InUse,
    /// Faltan privilegios para un puerto por debajo de 1024.
    Privileged,
    /// Otro motivo del sistema.
    Other(String),
}

/// Un senuelo que no se pudo levantar, y por que.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// Servicio.
    pub kind: DecoyKind,
    /// Puerto que se intento.
    pub port: u16,
    /// Motivo.
    pub reason: SkipReason,
}

/// Red de senuelos en marcha.
#[derive(Debug)]
pub struct DecoyNet {
    listeners: Vec<(DecoyKind, u16, TcpListener)>,
    skipped: Vec<Skipped>,
    config: DecoyConfig,
}

impl DecoyNet {
    /// Levanta los senuelos que pueda.
    ///
    /// Los que no pueda quedan en [`DecoyNet::skipped`] con su motivo. No es un
    /// error: que el puerto 22 este ocupado por el `sshd` de verdad es lo normal
    /// en un servidor, y forzarlo seria destruir el acceso legitimo.
    pub fn bind(config: DecoyConfig) -> DecoyNet {
        let mut listeners = Vec::new();
        let mut skipped = Vec::new();

        for (kind, port) in &config.services {
            let addr = SocketAddr::new(config.bind, *port);
            match TcpListener::bind(addr) {
                Ok(l) => {
                    // No bloqueante: el bucle sondea todos los senuelos a la vez
                    // y no puede quedarse esperando en uno.
                    if let Err(e) = l.set_nonblocking(true) {
                        skipped.push(Skipped {
                            kind: *kind,
                            port: *port,
                            reason: SkipReason::Other(e.to_string()),
                        });
                        continue;
                    }
                    let real = l.local_addr().map(|a| a.port()).unwrap_or(*port);
                    listeners.push((*kind, real, l));
                }
                Err(e) => {
                    let reason = match e.kind() {
                        std::io::ErrorKind::AddrInUse => SkipReason::InUse,
                        std::io::ErrorKind::PermissionDenied => SkipReason::Privileged,
                        _ => SkipReason::Other(e.to_string()),
                    };
                    skipped.push(Skipped {
                        kind: *kind,
                        port: *port,
                        reason,
                    });
                }
            }
        }

        DecoyNet {
            listeners,
            skipped,
            config,
        }
    }

    /// Senuelos levantados, con el puerto real en el que escuchan.
    pub fn active(&self) -> Vec<(DecoyKind, u16)> {
        self.listeners.iter().map(|(k, p, _)| (*k, *p)).collect()
    }

    /// Senuelos que no se pudieron levantar.
    pub fn skipped(&self) -> &[Skipped] {
        &self.skipped
    }

    /// Indica si hay algun senuelo escuchando.
    pub fn is_empty(&self) -> bool {
        self.listeners.is_empty()
    }

    /// Atiende las conexiones pendientes, esperando como mucho `timeout`.
    ///
    /// `now_ns` lo aporta el llamante para que el reloj del motor sea uno solo y
    /// las pruebas puedan controlarlo.
    pub fn poll(&self, timeout: Duration, now_ns: u64) -> Vec<Interaction> {
        if self.listeners.is_empty() {
            return Vec::new();
        }
        let mut pfds: Vec<libc::pollfd> = self
            .listeners
            .iter()
            .map(|(_, _, l)| libc::pollfd {
                fd: l.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();

        let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        // SAFETY: `pfds` es un vector vivo de descriptores validos y se pasa su
        // longitud real.
        let r = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, ms) };
        if r <= 0 {
            return Vec::new();
        }

        let mut salida = Vec::new();
        for (i, pfd) in pfds.iter().enumerate() {
            if pfd.revents & libc::POLLIN == 0 {
                continue;
            }
            let (kind, port, listener) = &self.listeners[i];
            // Se acepta en bucle porque un solo aviso de `poll` puede
            // corresponder a varias conexiones encoladas.
            while salida.len() < self.config.max_per_poll {
                match listener.accept() {
                    Ok((stream, peer)) => {
                        salida.push(self.atender(*kind, *port, stream, peer, now_ns));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
        }
        salida
    }

    /// Saluda, escucha un momento y cierra.
    fn atender(
        &self,
        kind: DecoyKind,
        port: u16,
        mut stream: std::net::TcpStream,
        peer: SocketAddr,
        now_ns: u64,
    ) -> Interaction {
        if let Some(b) = kind.banner() {
            // Un error escribiendo el saludo no invalida la deteccion: la
            // conexion ya ocurrio, que es lo que importa.
            let _ = stream.write_all(b);
        }
        let _ = stream.set_read_timeout(Some(self.config.speak_timeout));

        let mut buf = vec![0u8; self.config.max_evidence];
        let leidos = stream.read(&mut buf).unwrap_or(0);
        buf.truncate(leidos);

        // Se cierra en cuanto se tiene la evidencia: mantener abierta la
        // conexion de un atacante consume un descriptor por nada.
        let _ = stream.shutdown(std::net::Shutdown::Both);

        Interaction {
            peer: peer.ip(),
            peer_port: peer.port(),
            kind,
            port,
            ts_ns: now_ns,
            evidence: buf,
        }
    }
}
