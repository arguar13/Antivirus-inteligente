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

use crate::dialogo::{Conversacion, Dialogo, Revelacion};
use crate::dialogos::{acceso, bases, industrial, web};
use crate::limitador::{Cuentas, Limitador, Transporte};
use std::cell::RefCell;

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
    /// HTTP (80): el unico puerto que esta abierto en todas partes.
    Http,
    /// HTTPS (443): del saludo TLS salen el nombre buscado y la huella.
    Https,
    /// Microsoft SQL Server (1433).
    MsSql,
    /// Redis (6379): el que se expone sin contrasena.
    Redis,
    /// MongoDB (27017).
    MongoDb,
    /// Modbus/TCP (502): el automata mas extendido del mundo.
    Modbus,
    /// S7comm (102): con el que se para una linea Siemens.
    S7Comm,
    /// DNP3 (20000): distribucion electrica y agua.
    Dnp3,
    /// BACnet/IP (47808), **sobre UDP**: climatizacion y edificios.
    Bacnet,
    /// OPC-UA (4840): la pasarela entre la planta y la oficina.
    OpcUa,
}

/// Todos los senuelos del catalogo.
pub const CATALOGO: [DecoyKind; 19] = [
    DecoyKind::Ssh,
    DecoyKind::Smb,
    DecoyKind::Rdp,
    DecoyKind::Ftp,
    DecoyKind::Telnet,
    DecoyKind::MySql,
    DecoyKind::Postgres,
    DecoyKind::Vnc,
    DecoyKind::WinRm,
    DecoyKind::Http,
    DecoyKind::Https,
    DecoyKind::MsSql,
    DecoyKind::Redis,
    DecoyKind::MongoDb,
    DecoyKind::Modbus,
    DecoyKind::S7Comm,
    DecoyKind::Dnp3,
    DecoyKind::Bacnet,
    DecoyKind::OpcUa,
];

/// Los senuelos industriales, que son los que se ponen en una pasarela de planta.
pub const INDUSTRIALES: [DecoyKind; 5] = [
    DecoyKind::Modbus,
    DecoyKind::S7Comm,
    DecoyKind::Dnp3,
    DecoyKind::Bacnet,
    DecoyKind::OpcUa,
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
            DecoyKind::Http => 80,
            DecoyKind::Https => 443,
            DecoyKind::MsSql => 1433,
            DecoyKind::Redis => 6379,
            DecoyKind::MongoDb => 27017,
            DecoyKind::Modbus => 502,
            DecoyKind::S7Comm => 102,
            DecoyKind::Dnp3 => 20000,
            DecoyKind::Bacnet => 47808,
            DecoyKind::OpcUa => 4840,
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
            DecoyKind::Http => "http",
            DecoyKind::Https => "https",
            DecoyKind::MsSql => "mssql",
            DecoyKind::Redis => "redis",
            DecoyKind::MongoDb => "mongodb",
            DecoyKind::Modbus => "modbus",
            DecoyKind::S7Comm => "s7comm",
            DecoyKind::Dnp3 => "dnp3",
            DecoyKind::Bacnet => "bacnet",
            DecoyKind::OpcUa => "opcua",
        }
    }

    /// Por donde habla este servicio.
    ///
    /// BACnet es el unico de UDP del catalogo, y por eso es el unico al que se le
    /// aplica la cota de amplificacion. Ver [`crate::limitador`].
    pub fn transporte(self) -> Transporte {
        match self {
            DecoyKind::Bacnet => Transporte::Udp,
            _ => Transporte::Tcp,
        }
    }

    /// El dialogo de este servicio, listo para conversar.
    ///
    /// # Por que hay uno para cada uno y no un dialogo generico
    ///
    /// Porque un senuelo que conteste lo mismo a todo se distingue de un servicio
    /// real en el primer turno, y entonces el atacante se va y no se averigua
    /// nada. Lo que hace util a un senuelo no es que el puerto responda: es que
    /// responda **como respondería ese servicio**, lo bastante para que el
    /// visitante siga hablando.
    ///
    /// `cebo` es el texto atribuible que el senuelo entrega a quien llegue lo
    /// bastante lejos; los que no sirven contenido lo ignoran. Ver
    /// [`crate::plantado`].
    pub fn dialogo(self, cebo: String) -> Box<dyn Dialogo> {
        match self {
            DecoyKind::Ssh => Box::new(acceso::Ssh::nuevo()),
            DecoyKind::Telnet => Box::new(acceso::Telnet::nuevo()),
            DecoyKind::Ftp => Box::new(acceso::Ftp::nuevo()),
            DecoyKind::Vnc => Box::new(acceso::Vnc::nuevo()),
            DecoyKind::Rdp => Box::new(acceso::Rdp::nuevo()),
            DecoyKind::Smb => Box::new(acceso::Smb::nuevo()),
            // WinRM es HTTP con otro puerto y otra ruta: el dialogo es el mismo,
            // y duplicarlo solo daria dos sitios donde arreglar el mismo fallo.
            DecoyKind::Http | DecoyKind::WinRm => Box::new(web::Http::con_cebo(cebo)),
            DecoyKind::Https => Box::new(web::Tls::nuevo()),
            DecoyKind::MySql => Box::new(bases::Mysql::nuevo()),
            DecoyKind::Postgres => Box::new(bases::Postgres::nuevo()),
            DecoyKind::MsSql => Box::new(bases::Mssql::nuevo()),
            DecoyKind::Redis => Box::new(bases::Redis::con_cebo(cebo)),
            DecoyKind::MongoDb => Box::new(bases::Mongo::nuevo()),
            DecoyKind::Modbus => Box::new(industrial::Modbus::nuevo()),
            DecoyKind::S7Comm => Box::new(industrial::S7::nuevo()),
            DecoyKind::Dnp3 => Box::new(industrial::Dnp3::nuevo()),
            DecoyKind::Bacnet => Box::new(industrial::Bacnet::nuevo()),
            DecoyKind::OpcUa => Box::new(industrial::OpcUa::nuevo()),
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
    pub fn banner(self) -> Option<Vec<u8>> {
        // Sale del DIALOGO y no de una tabla aparte. Con dos fuentes, el saludo
        // que manda el senuelo y el que su propia maquina de estados espera
        // haber mandado se separan en cuanto alguien toca uno de los dos — y un
        // servicio que saluda de una forma y sigue de otra se nota al instante.
        self.dialogo(String::new()).saludo()
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
    /// Lo que el visitante revelo de si mismo durante la conversacion.
    ///
    /// **Es el producto del senuelo de alta interaccion.** Los bytes crudos de
    /// `evidence` dicen que alguien hablo; esto dice QUE dijo: con que usuario,
    /// con que clave, que ruta pidio y si mando escribir. Ver
    /// [`crate::dialogo::Revelacion`].
    pub revelado: Vec<Revelacion>,
    /// Cuantos turnos duro la conversacion.
    ///
    /// Un turno es un escaner. Cinco es alguien que se ha sentado a probar, y esa
    /// diferencia decide si merece la pena mirarlo hoy o el lunes.
    pub turnos: u32,
}

impl Interaction {
    /// Indica si el cliente llego a enviar datos.
    pub fn spoke(&self) -> bool {
        !self.evidence.is_empty()
    }

    /// Si el visitante mando alguna orden que cambia el estado del dispositivo.
    ///
    /// En un senuelo industrial es la diferencia entre alguien inventariando y
    /// alguien intentando actuar sobre un proceso fisico.
    pub fn intento_escribir(&self) -> bool {
        self.revelado
            .iter()
            .any(crate::dialogo::Revelacion::es_grave)
    }

    /// Las credenciales que probo.
    pub fn credenciales(&self) -> Vec<(String, String)> {
        self.revelado
            .iter()
            .filter_map(|r| match r {
                Revelacion::Credencial { usuario, clave } => Some((usuario.clone(), clave.clone())),
                _ => None,
            })
            .collect()
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
    /// El texto atribuible que los senuelos que sirven contenido entregan.
    ///
    /// Sale de [`crate::plantado::Plantacion`] y es lo que hace que llevarse algo
    /// del senuelo deje rastro: cuando ese texto reaparezca en otro sitio, se
    /// sabra que salio de aqui y de que puerto. Vacio, los senuelos sirven un
    /// `404` y siguen valiendo para contar, pero no para atribuir.
    pub cebo: String,
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
            cebo: String::new(),
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
    /// **Uno para toda la red.** El ritmo por origen y el cupo de bytes solo
    /// significan algo si sobreviven a que el visitante cuelgue y vuelva a
    /// llamar; con un limitador por conexion, abrir otra da el cubo lleno. Ver
    /// [`crate::limitador::Limitador`].
    ///
    /// Va en una celda porque `poll` toma `&self` —es la forma del motor— y el
    /// limitador tiene que anotar. No hay hilos de por medio: la red se atiende
    /// desde el bucle del motor, en uno solo.
    limitador: RefCell<Limitador>,
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
            limitador: RefCell::new(Limitador::nuevo()),
        }
    }

    /// Lo que el limitador ha contado para toda la red.
    ///
    /// Es donde se ve si alguien esta intentando usar los senuelos como
    /// amplificador: `recortadas` mayor que cero significa que lo intento.
    #[must_use]
    pub fn cuentas(&self) -> Cuentas {
        self.limitador.borrow().cuentas()
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

    /// Conversa con quien ha llamado, hasta que el dialogo cierre.
    ///
    /// # Por que se conversa y no se saluda y se corta
    ///
    /// Porque saludar y cortar solo cuenta escaneos. Lo que interesa —con que
    /// credenciales viene, que ruta pide, si manda escribir— se dice en el tercer
    /// o cuarto turno, no en el primero. Ver [`crate::dialogo`].
    ///
    /// La conversacion la lleva [`Conversacion`], que es lo unico que escribe al
    /// cable: pasa por el limitador y por tanto **no hay forma de que un senuelo
    /// amplifique**, lo escriba quien lo escriba.
    fn atender(
        &self,
        kind: DecoyKind,
        port: u16,
        mut stream: std::net::TcpStream,
        peer: SocketAddr,
        now_ns: u64,
    ) -> Interaction {
        let mut charla = Conversacion::nueva(kind.dialogo(self.config.cebo.clone()));
        let origen = match peer.ip() {
            IpAddr::V4(v) => u128::from(u32::from(v)),
            IpAddr::V6(v) => u128::from(v),
        };

        let saludo = charla.saludo();
        if !saludo.is_empty() {
            // Un error escribiendo el saludo no invalida la deteccion: la
            // conexion ya ocurrio, que es lo que importa.
            let _ = stream.write_all(&saludo);
        }
        let _ = stream.set_read_timeout(Some(self.config.speak_timeout));

        let mut evidencia = Vec::new();
        let mut buf = vec![0u8; 8192];
        loop {
            let leidos = match stream.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let entrada = &buf[..leidos];
            // La evidencia se acota: lo que manda el visitante lo decide el
            // visitante, y guardarlo entero es dejarle elegir la memoria.
            if evidencia.len() < self.config.max_evidence {
                let cabe = self.config.max_evidence - evidencia.len();
                evidencia.extend_from_slice(&entrada[..leidos.min(cabe)]);
            }
            let (salida, _) = {
                let mut lim = self.limitador.borrow_mut();
                charla.turno(&mut lim, origen, now_ns, entrada)
            };
            if !salida.is_empty() && stream.write_all(&salida).is_err() {
                break;
            }
            if charla.como_acabo() != crate::dialogo::Final::Abierta {
                break;
            }
        }

        // Se cierra en cuanto acaba: mantener abierta la conexion de un atacante
        // consume un descriptor por nada.
        let _ = stream.shutdown(std::net::Shutdown::Both);

        Interaction {
            peer: peer.ip(),
            peer_port: peer.port(),
            kind,
            port,
            ts_ns: now_ns,
            evidence: evidencia,
            revelado: charla.revelado().to_vec(),
            turnos: charla.turnos(),
        }
    }
}
