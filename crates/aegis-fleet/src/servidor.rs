//! El plano de control: el servidor de la flota.
//!
//! Acepta conexiones mTLS, autentica cada agente por el CN de su certificado
//! —firmado por la CA de la flota— y despacha las llamadas del servicio
//! `AegisFleet`. La logica de negocio (a quien se enrola, que politica se
//! entrega) vive tras el trait [`ManejadorFlota`], de modo que las pruebas la
//! sustituyen sin tocar el transporte. El manejador por defecto,
//! [`PlanoDeControl`], mantiene un registro real de agentes en memoria.

use std::collections::HashMap;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use rustls::ServerConnection;

use crate::error::{FleetError, Resultado};
use crate::pki::{ahora_unix, Identidad};
use crate::proto::{
    AckEvento, AckLatido, Latido, ReporteEvento, RespuestaEnrolamiento, SolicitudEnrolamiento,
};
use crate::rpc::{
    escribir_marco, leer_marco, Metodo, ESTADO_INTERNO, ESTADO_METODO_DESCONOCIDO, ESTADO_OK,
    ESTADO_RECHAZADO,
};
use crate::tls::{cn_del_par, config_servidor};

/// Logica de negocio del plano de control.
///
/// Cada metodo recibe el CN AUTENTICADO del agente (extraido de su certificado,
/// no de lo que el agente diga en el cuerpo) y el mensaje.
pub trait ManejadorFlota: Send + Sync {
    /// Decide el enrolamiento de un agente.
    fn enrolar(&self, cn: &str, req: &SolicitudEnrolamiento) -> RespuestaEnrolamiento;
    /// Procesa un latido.
    fn latido(&self, cn: &str, req: &Latido) -> AckLatido;
    /// Registra un evento de seguridad.
    fn evento(&self, cn: &str, req: &ReporteEvento) -> AckEvento;
}

/// Registro de un agente enrolado.
#[derive(Debug, Clone, Default)]
pub struct RegistroAgente {
    /// Nombre de maquina.
    pub hostname: String,
    /// Version del agente.
    pub version: String,
    /// Instante del ultimo latido.
    pub ultimo_latido_unix: u64,
    /// Numero de latidos recibidos.
    pub latidos: u64,
    /// Numero de eventos reportados.
    pub eventos: u64,
}

/// Plano de control por defecto: registro de flota en memoria.
#[derive(Default)]
pub struct PlanoDeControl {
    agentes: Mutex<HashMap<String, RegistroAgente>>,
    version_politica: AtomicU64,
    incidentes: AtomicU64,
}

impl PlanoDeControl {
    /// Crea un plano de control vacio.
    pub fn nuevo() -> PlanoDeControl {
        PlanoDeControl {
            agentes: Mutex::new(HashMap::new()),
            version_politica: AtomicU64::new(1),
            incidentes: AtomicU64::new(0),
        }
    }

    /// Numero de agentes enrolados.
    pub fn num_agentes(&self) -> usize {
        self.agentes.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// Copia del registro de un agente.
    pub fn registro(&self, cn: &str) -> Option<RegistroAgente> {
        self.agentes.lock().ok()?.get(cn).cloned()
    }

    /// Publica una version de politica nueva (para probar el aviso en el ack).
    pub fn publicar_politica(&self, version: u64) {
        self.version_politica.store(version, Ordering::SeqCst);
    }
}

impl ManejadorFlota for PlanoDeControl {
    fn enrolar(&self, cn: &str, req: &SolicitudEnrolamiento) -> RespuestaEnrolamiento {
        // El cuerpo dice quien es; el certificado PRUEBA quien es. Si no
        // coinciden, es un agente con certificado valido intentando hacerse
        // pasar por otro: se rechaza.
        if req.id_agente != cn {
            return RespuestaEnrolamiento {
                aceptado: false,
                motivo: format!(
                    "el id declarado ({}) no coincide con la identidad del certificado ({cn})",
                    req.id_agente
                ),
                ..Default::default()
            };
        }
        if let Ok(mut m) = self.agentes.lock() {
            m.entry(cn.to_string()).or_default().hostname = req.hostname.clone();
            if let Some(r) = m.get_mut(cn) {
                r.version = req.version_agente.clone();
            }
        }
        RespuestaEnrolamiento {
            aceptado: true,
            id_flota: format!("fleet:{cn}"),
            intervalo_latido_seg: 30,
            motivo: String::new(),
        }
    }

    fn latido(&self, cn: &str, req: &Latido) -> AckLatido {
        let mut recibido = false;
        if let Ok(mut m) = self.agentes.lock() {
            if let Some(r) = m.get_mut(cn) {
                r.ultimo_latido_unix = if req.momento_unix != 0 {
                    req.momento_unix
                } else {
                    ahora_unix()
                };
                r.latidos += 1;
                recibido = true;
            }
        }
        let disponible = self.version_politica.load(Ordering::SeqCst);
        AckLatido {
            recibido,
            version_politica_disponible: disponible,
            hay_comando: false,
        }
    }

    fn evento(&self, cn: &str, _req: &ReporteEvento) -> AckEvento {
        let mut recibido = false;
        if let Ok(mut m) = self.agentes.lock() {
            if let Some(r) = m.get_mut(cn) {
                r.eventos += 1;
                recibido = true;
            }
        }
        let id = self.incidentes.fetch_add(1, Ordering::SeqCst) + 1;
        AckEvento {
            recibido,
            id_incidente: if recibido {
                format!("INC-{id:06}")
            } else {
                String::new()
            },
        }
    }
}

/// El servidor de flota, listo para escuchar.
pub struct ServidorFlota {
    cfg: Arc<rustls::ServerConfig>,
    manejador: Arc<dyn ManejadorFlota>,
}

impl ServidorFlota {
    /// Construye el servidor con su identidad y la CA de la flota.
    pub fn nuevo(
        id: &Identidad,
        ca_der: &rustls::pki_types::CertificateDer<'static>,
        manejador: Arc<dyn ManejadorFlota>,
    ) -> Resultado<ServidorFlota> {
        let cfg = config_servidor(id, ca_der)?;
        Ok(ServidorFlota { cfg, manejador })
    }

    /// Empieza a escuchar en `addr` y devuelve el servidor en ejecucion.
    ///
    /// El bucle de aceptacion corre en su propio hilo; cada conexion se atiende
    /// en un hilo aparte. La direccion real (util con el puerto 0) queda en
    /// [`ServidorEnEjecucion::direccion`].
    pub fn escuchar(self, addr: &str) -> Resultado<ServidorEnEjecucion> {
        let listener = TcpListener::bind(addr).map_err(|e| FleetError::Red {
            op: "bind",
            source: e,
        })?;
        let direccion = listener.local_addr().map_err(|e| FleetError::Red {
            op: "local_addr",
            source: e,
        })?;
        listener
            .set_nonblocking(true)
            .map_err(|e| FleetError::Red {
                op: "set_nonblocking",
                source: e,
            })?;

        let parar = Arc::new(AtomicBool::new(false));
        let parar_hilo = parar.clone();
        let cfg = self.cfg.clone();
        let manejador = self.manejador.clone();

        let handle = std::thread::spawn(move || {
            while !parar_hilo.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((sock, _)) => {
                        let cfg = cfg.clone();
                        let manejador = manejador.clone();
                        std::thread::spawn(move || {
                            let _ = atender_conexion(cfg, manejador, sock);
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(ServidorEnEjecucion {
            direccion,
            parar,
            handle: Some(handle),
        })
    }
}

/// Un servidor de flota en ejecucion. Al soltarse, para el bucle de aceptacion.
pub struct ServidorEnEjecucion {
    direccion: std::net::SocketAddr,
    parar: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl ServidorEnEjecucion {
    /// Direccion real en la que escucha (con el puerto ya resuelto).
    pub fn direccion(&self) -> std::net::SocketAddr {
        self.direccion
    }

    /// Para el servidor y espera a que el bucle de aceptacion termine.
    pub fn parar(mut self) {
        self.parar.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for ServidorEnEjecucion {
    fn drop(&mut self) {
        self.parar.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Atiende una conexion: handshake mTLS, autenticacion y despacho de RPCs.
fn atender_conexion(
    cfg: Arc<rustls::ServerConfig>,
    manejador: Arc<dyn ManejadorFlota>,
    sock: TcpStream,
) -> Resultado<()> {
    let conn = ServerConnection::new(cfg).map_err(|e| FleetError::Tls {
        op: "ServerConnection::new",
        detail: e.to_string(),
    })?;
    let mut tls = rustls::StreamOwned::new(conn, sock);
    let mut cn: Option<String> = None;

    loop {
        // La primera lectura completa el handshake; si el cliente no presenta un
        // certificado firmado por la CA, falla aqui y la conexion se cierra.
        let (enrutado, cuerpo) = match leer_marco(&mut tls) {
            Ok(x) => x,
            Err(_) => return Ok(()),
        };
        if cn.is_none() {
            cn = cn_del_par(tls.conn.peer_certificates());
        }
        let Some(identidad) = cn.clone() else {
            let _ = escribir_marco(&mut tls, ESTADO_RECHAZADO, b"sin identidad autenticada");
            return Ok(());
        };

        let (estado, respuesta) = despachar(&manejador, &identidad, enrutado, &cuerpo);
        escribir_marco(&mut tls, estado, &respuesta)?;
    }
}

// `atender_conexion` lee tramas con `leer_marco`, que exige `Read`; el
// `StreamOwned` de rustls lo implementa.

/// Despacha una llamada al metodo correspondiente.
fn despachar(
    manejador: &Arc<dyn ManejadorFlota>,
    cn: &str,
    enrutado: u8,
    cuerpo: &[u8],
) -> (u8, Vec<u8>) {
    let Some(metodo) = Metodo::de_codigo(enrutado) else {
        return (ESTADO_METODO_DESCONOCIDO, b"metodo desconocido".to_vec());
    };
    match metodo {
        Metodo::Enrolar => match SolicitudEnrolamiento::decodificar(cuerpo) {
            Ok(req) => {
                let resp = manejador.enrolar(cn, &req);
                if resp.aceptado {
                    (ESTADO_OK, resp.codificar())
                } else {
                    (ESTADO_RECHAZADO, resp.motivo.clone().into_bytes())
                }
            }
            Err(_) => (
                ESTADO_INTERNO,
                b"solicitud de enrolamiento invalida".to_vec(),
            ),
        },
        Metodo::Latir => match Latido::decodificar(cuerpo) {
            Ok(req) => (ESTADO_OK, manejador.latido(cn, &req).codificar()),
            Err(_) => (ESTADO_INTERNO, b"latido invalido".to_vec()),
        },
        Metodo::ReportarEvento => match ReporteEvento::decodificar(cuerpo) {
            Ok(req) => (ESTADO_OK, manejador.evento(cn, &req).codificar()),
            Err(_) => (ESTADO_INTERNO, b"reporte invalido".to_vec()),
        },
    }
}
