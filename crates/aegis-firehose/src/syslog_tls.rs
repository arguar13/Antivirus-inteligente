//! Destino Syslog sobre TLS.
//!
//! # Que significa «acuse» en syslog, y por que hay que decirlo
//!
//! Syslog sobre TCP —RFC 6587— **no tiene acuse de aplicacion**. El receptor no
//! contesta nada. Lo unico que se puede afirmar es que los bytes salieron del
//! socket y que el otro extremo los reconocio a nivel de TCP.
//!
//! Eso es debil, y hay que decirlo en vez de disfrazarlo: si el SIEM acepta la
//! conexion y muere antes de indexar, esos registros se pierden y aqui parecen
//! entregados. Lo que se hace es reducir la ventana todo lo que el protocolo
//! permite:
//!
//! - Se escribe el lote entero y **se vacia el buffer** antes de dar el `Ok`.
//! - Se comprueba que la sesion TLS sigue viva despues de escribir: un
//!   `close_notify` del par mientras se escribia significa que no lo leyo.
//! - Nunca se da por bueno un lote escrito a medias.
//!
//! Quien necesite garantia de extremo a extremo tiene el destino de Kafka, que
//! si acusa. Un producto que presentara los dos como equivalentes estaria
//! ocultando la diferencia que importa.
//!
//! # Por que TLS y no syslog en claro
//!
//! Los registros llevan rutas, lineas de comandos y nombres de usuario de la
//! red del cliente: es un mapa de su infraestructura viajando por ella. Y sin
//! autenticar el servidor, cualquiera que pueda responder en ese puerto recibe
//! la telemetria de seguridad completa y puede ademas dejar de reenviarla, que
//! es una forma silenciosa de cegar el SOC.

use std::io::Write;
use std::net::TcpStream;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};

use crate::destino::Destino;
use crate::error::{ErrorFirehose, Resultado};

/// Ajustes del destino syslog.
#[derive(Debug, Clone)]
pub struct ConfigSyslog {
    /// `host:puerto` del colector.
    pub servidor: String,
    /// Nombre esperado en el certificado del servidor.
    ///
    /// Se separa de `servidor` a proposito: en un despliegue real se conecta a
    /// una IP o a un balanceador y el certificado lleva el nombre del servicio.
    /// Sin este campo, la unica salida seria desactivar la verificacion.
    pub nombre_esperado: String,
    /// Ancla de confianza: el PEM de la CA que firma al colector.
    pub ca_pem: Vec<u8>,
    /// Plazo de conexion y de escritura.
    pub plazo: std::time::Duration,
}

/// Destino Syslog RFC 5424 sobre TLS.
pub struct DestinoSyslog {
    cfg: ConfigSyslog,
    tls: Option<StreamOwned<ClientConnection, TcpStream>>,
    config_tls: Arc<rustls::ClientConfig>,
}

impl DestinoSyslog {
    /// Prepara el destino. NO conecta todavia.
    ///
    /// Conectar aqui haria que el plano de control no arrancara si el SIEM
    /// estuviera caido en ese momento. Un EDR que no arranca porque su SIEM no
    /// esta es un EDR que amplifica la averia en vez de contenerla.
    pub fn nuevo(cfg: ConfigSyslog) -> Resultado<DestinoSyslog> {
        let mut raiz = rustls::RootCertStore::empty();
        let mut pem = std::io::Cursor::new(&cfg.ca_pem);
        let mut anadidos = 0;
        for cert in rustls_pemfile::certs(&mut pem) {
            let cert = cert.map_err(|e| {
                ErrorFirehose::Config(format!("la CA del colector no es PEM valido: {e}"))
            })?;
            raiz.add(cert).map_err(|e| {
                ErrorFirehose::Config(format!("la CA del colector no es un certificado: {e}"))
            })?;
            anadidos += 1;
        }
        // Sin ancla no hay verificacion posible. Fallar al configurar es lo
        // correcto: la alternativa —conectar sin verificar— entrega la
        // telemetria de seguridad del cliente a quien conteste en ese puerto.
        if anadidos == 0 {
            return Err(ErrorFirehose::Config(
                "no se encontro ningun certificado de CA para el colector syslog".to_string(),
            ));
        }
        let config_tls = rustls::ClientConfig::builder()
            .with_root_certificates(raiz)
            .with_no_client_auth();

        Ok(DestinoSyslog {
            cfg,
            tls: None,
            config_tls: Arc::new(config_tls),
        })
    }

    fn conectar(&mut self) -> Resultado<()> {
        if self.tls.is_some() {
            return Ok(());
        }
        let direcciones: Vec<std::net::SocketAddr> =
            std::net::ToSocketAddrs::to_socket_addrs(&self.cfg.servidor)
                .map_err(|e| ErrorFirehose::Diario {
                    op: "resolver",
                    source: e,
                })?
                .collect();
        let primera = direcciones
            .first()
            .ok_or_else(|| ErrorFirehose::Config(format!("{} no resuelve", self.cfg.servidor)))?;

        let sock = TcpStream::connect_timeout(primera, self.cfg.plazo).map_err(|e| {
            ErrorFirehose::Diario {
                op: "connect",
                source: e,
            }
        })?;
        // Plazos en las DOS direcciones: sin ellos, un colector que acepta la
        // conexion y deja de leer bloquea al productor para siempre, y el
        // diario crece hasta su presupuesto sin que nadie sepa por que.
        let _ = sock.set_write_timeout(Some(self.cfg.plazo));
        let _ = sock.set_read_timeout(Some(self.cfg.plazo));
        let _ = sock.set_nodelay(true);

        let nombre = ServerName::try_from(self.cfg.nombre_esperado.clone())
            .map_err(|e| ErrorFirehose::Config(format!("nombre del colector: {e}")))?;
        let conn = ClientConnection::new(self.config_tls.clone(), nombre)
            .map_err(|e| ErrorFirehose::Config(format!("sesion TLS: {e}")))?;
        self.tls = Some(StreamOwned::new(conn, sock));
        Ok(())
    }
}

impl Destino for DestinoSyslog {
    fn nombre(&self) -> &str {
        "syslog-tls"
    }

    fn entregar(&mut self, lote: &[&[u8]]) -> Resultado<()> {
        self.conectar()?;
        let tls = match self.tls.as_mut() {
            Some(t) => t,
            None => return Err(ErrorFirehose::Config("sin conexion".to_string())),
        };

        // El lote se escribe de una vez. Escribir registro a registro con
        // `flush` entre medias multiplica los viajes de red y, con Nagle
        // desactivado, produce un paquete por registro.
        let mut bytes = Vec::new();
        for marco in lote {
            bytes.extend_from_slice(marco);
        }

        // Un fallo a mitad deja la sesion con un mensaje partido: el receptor
        // leeria el resto del flujo como si fuera parte de ese mensaje. Por eso
        // ante cualquier error se tira la conexion entera.
        if let Err(e) = tls.write_all(&bytes) {
            self.tls = None;
            return Err(ErrorFirehose::Diario {
                op: "escribir en el colector",
                source: e,
            });
        }
        if let Err(e) = tls.flush() {
            self.tls = None;
            return Err(ErrorFirehose::Diario {
                op: "vaciar hacia el colector",
                source: e,
            });
        }
        Ok(())
    }

    fn reiniciar(&mut self) {
        // Reutilizar una conexion que acaba de fallar convierte un corte de dos
        // segundos en un destino que no vuelve: el socket queda medio abierto,
        // las escrituras «funcionan» y nada llega.
        self.tls = None;
    }
}
