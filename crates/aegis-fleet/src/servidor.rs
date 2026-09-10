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
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use rustls::ServerConnection;

use crate::error::{FleetError, Resultado};
use crate::pki::{ahora_unix, Identidad};
use crate::proto::{
    AckCaza, AckEvento, AckGrafo, AckLatido, AckStix, EmpujePolitica, Latido, ReporteCaza,
    ReporteEvento, ReporteGrafo, ReporteStix, RespuestaEnrolamiento, SolicitudEnrolamiento,
    SuscripcionPolitica,
};
use crate::rpc::{
    escribir_marco, leer_marco, Metodo, ESTADO_INTERNO, ESTADO_METODO_DESCONOCIDO, ESTADO_OK,
    ESTADO_RECHAZADO,
};
use crate::tls::{cn_del_par, config_servidor};

/// Lo que un canal de suscripcion ya le ha entregado a su agente.
///
/// POR QUE HACE FALTA LLEVAR LA CUENTA
/// -----------------------------------
/// El canal decide si empujar comparando lo que hay con lo que el agente ya
/// tiene. Con la politica bastaba un numero de version. Con las cacerias no: una
/// caceria le corresponde a un agente hasta que la CONTESTA, y contestar lleva
/// su tiempo —puede tardar segundos en un endpoint cargado—.
///
/// Sin esta cuenta, el canal ve la caceria pendiente, la empuja, vuelve a mirar,
/// la sigue viendo pendiente, y la empuja otra vez: un bucle cerrado que satura
/// al agente y al servidor con la misma consulta. Multiplicado por diez mil
/// canales, es una denegacion de servicio que se provoca el propio producto al
/// lanzar una caceria.
#[derive(Debug, Clone, Default)]
pub struct EstadoCanal {
    /// Ultima version de politica entregada por este canal.
    pub version_entregada: u64,
    /// Identificador de la ultima caceria entregada, o vacio si ninguna.
    pub caza_entregada: String,
}

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

    /// Ingiere un bundle de inteligencia STIX 2.1.
    ///
    /// El defecto RECHAZA explicitamente en vez de fingir que ingirio: un
    /// manejador que no implemente esto debe decirlo, porque aceptar en
    /// silencio un bundle que se tira es perder inteligencia sin que nadie se
    /// entere.
    fn stix(&self, _cn: &str, _req: &ReporteStix) -> AckStix {
        AckStix {
            recibido: false,
            objetos_ingeridos: 0,
            motivo: "este plano de control no ingiere STIX".to_string(),
        }
    }

    /// Ingiere el subgrafo de linaje que rodea a una deteccion.
    fn grafo(&self, _cn: &str, _req: &ReporteGrafo) -> AckGrafo {
        AckGrafo {
            recibido: false,
            id_grafo: String::new(),
            nodos_ingeridos: 0,
        }
    }

    /// Espera a que haya politica o comandos que EMPUJAR a este agente.
    ///
    /// Bloquea hasta que haya novedad o venza `plazo`. Devuelve:
    ///
    /// - `Some(empuje)` con contenido nuevo, o con `es_keepalive` si solo vencio
    ///   el plazo y el canal sigue sano.
    /// - `None` para cerrar el canal de forma ordenada. Es lo que hace el
    ///   defecto: un manejador sin soporte de empuje cierra en vez de dejar al
    ///   agente esperando algo que no va a llegar nunca.
    fn esperar_empuje(
        &self,
        _cn: &str,
        _estado: &EstadoCanal,
        _plazo: Duration,
    ) -> Option<EmpujePolitica> {
        None
    }

    /// Recibe el resultado de una caceria AegisQL.
    ///
    /// El valor por defecto RECHAZA con un motivo en vez de aceptar en
    /// silencio. Un plano de control que no sabe agregar cacerias y responde
    /// "recibido" haria creer al agente que su trabajo sirvio de algo, y al
    /// analista que la flota respondio; el resultado se perderia sin que nadie
    /// se enterara.
    fn caza(&self, _cn: &str, _req: &ReporteCaza) -> AckCaza {
        AckCaza {
            recibido: false,
            motivo: "este plano de control no agrega cacerias".to_string(),
        }
    }
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
    /// Bundles STIX ingeridos.
    stix_recibidos: AtomicU64,
    /// Subgrafos de linaje ingeridos.
    grafos_recibidos: AtomicU64,
    /// Contenido de la politica vigente.
    politica: Mutex<String>,
    /// Version publicada y aviso a los suscriptores.
    ///
    /// La variable de condicion es lo que convierte la entrega en un EMPUJE: los
    /// hilos de las suscripciones duermen aqui y despiertan en cuanto el
    /// operador publica, no en el siguiente latido.
    cambio: (Mutex<u64>, Condvar),
}

impl PlanoDeControl {
    /// Crea un plano de control vacio.
    pub fn nuevo() -> PlanoDeControl {
        PlanoDeControl {
            agentes: Mutex::new(HashMap::new()),
            version_politica: AtomicU64::new(1),
            incidentes: AtomicU64::new(0),
            stix_recibidos: AtomicU64::new(0),
            grafos_recibidos: AtomicU64::new(0),
            politica: Mutex::new(String::new()),
            cambio: (Mutex::new(1), Condvar::new()),
        }
    }

    /// Numero de bundles STIX ingeridos.
    pub fn num_stix(&self) -> u64 {
        self.stix_recibidos.load(Ordering::SeqCst)
    }

    /// Numero de subgrafos ingeridos.
    pub fn num_grafos(&self) -> u64 {
        self.grafos_recibidos.load(Ordering::SeqCst)
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
        let (lock, cv) = &self.cambio;
        if let Ok(mut v) = lock.lock() {
            *v = version;
        }
        // Despertar a TODOS los suscriptores: la politica es global, asi que la
        // novedad le interesa a cada agente conectado.
        cv.notify_all();
    }

    /// Publica una politica con su contenido y despierta a los suscriptores.
    pub fn publicar_politica_con(&self, version: u64, politica_json: &str) {
        if let Ok(mut p) = self.politica.lock() {
            *p = politica_json.to_string();
        }
        self.publicar_politica(version);
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

    fn stix(&self, cn: &str, req: &ReporteStix) -> AckStix {
        // Un bundle vacio o que no sea JSON no se cuenta como ingerido: aceptar
        // basura contaminaria la inteligencia de la que despues se tiran hilos.
        let parece_bundle =
            req.bundle_json.trim_start().starts_with('{') && req.bundle_json.contains("\"type\"");
        if !parece_bundle {
            return AckStix {
                recibido: false,
                objetos_ingeridos: 0,
                motivo: "el cuerpo no parece un bundle STIX 2.1".to_string(),
            };
        }
        let conocido = self
            .agentes
            .lock()
            .map(|m| m.contains_key(cn))
            .unwrap_or(false);
        if !conocido {
            return AckStix {
                recibido: false,
                objetos_ingeridos: 0,
                motivo: "el agente no esta enrolado".to_string(),
            };
        }
        self.stix_recibidos.fetch_add(1, Ordering::SeqCst);
        // Recuento aproximado de objetos: el plano de referencia no analiza el
        // bundle entero, solo cuenta cuantos objetos declara.
        let objetos = req.bundle_json.matches("\"type\"").count() as u64;
        AckStix {
            recibido: true,
            objetos_ingeridos: objetos,
            motivo: String::new(),
        }
    }

    fn grafo(&self, cn: &str, req: &ReporteGrafo) -> AckGrafo {
        let conocido = self
            .agentes
            .lock()
            .map(|m| m.contains_key(cn))
            .unwrap_or(false);
        if !conocido || req.nodos.is_empty() {
            return AckGrafo::default();
        }
        let n = self.grafos_recibidos.fetch_add(1, Ordering::SeqCst) + 1;
        AckGrafo {
            recibido: true,
            id_grafo: format!("GRF-{n:06}"),
            nodos_ingeridos: req.nodos.len() as u64,
        }
    }

    fn esperar_empuje(
        &self,
        _cn: &str,
        estado: &EstadoCanal,
        plazo: Duration,
    ) -> Option<EmpujePolitica> {
        let version_conocida = estado.version_entregada;
        let (lock, cv) = &self.cambio;
        let guarda = lock.lock().ok()?;

        // Si el agente ya viene atrasado, se le entrega sin esperar: acaba de
        // reconectar y no tiene por que aguardar al siguiente cambio.
        if *guarda > version_conocida {
            return Some(self.empuje(*guarda));
        }

        let (guarda, _tiempo) = cv.wait_timeout(guarda, plazo).ok()?;
        if *guarda > version_conocida {
            Some(self.empuje(*guarda))
        } else {
            // Venció el plazo sin novedad: un latido del canal. Sin el, un canal
            // sano y uno muerto son indistinguibles.
            Some(EmpujePolitica {
                version: *guarda,
                es_keepalive: true,
                ..Default::default()
            })
        }
    }
}

impl PlanoDeControl {
    /// Construye el empuje con la politica vigente.
    fn empuje(&self, version: u64) -> EmpujePolitica {
        EmpujePolitica {
            version,
            politica_json: self.politica.lock().map(|p| p.clone()).unwrap_or_default(),
            comandos_json: String::new(),
            es_keepalive: false,
            ..Default::default()
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
        // Aceptacion BLOQUEANTE, no sondeo.
        //
        // Antes el escuchador era no bloqueante y el bucle dormia 20 ms cuando
        // no habia nada que aceptar. Eso anadia hasta 20 ms de espera a CADA
        // conexion nueva —y en este protocolo cada llamada abre una conexion—,
        // un coste invisible que en una flota de miles de endpoints se paga
        // multiplicado por cada latido. La parada ordenada se resuelve mas
        // abajo despertando el `accept` con una conexion local.

        let parar = Arc::new(AtomicBool::new(false));
        let parar_hilo = parar.clone();
        let cfg = self.cfg.clone();
        let manejador = self.manejador.clone();

        let handle = std::thread::spawn(move || {
            // `accept` solo devuelve Err cuando el escuchador ha quedado
            // inservible (descriptor cerrado, recursos agotados); ahi no hay
            // nada que reintentar y el hilo termina, igual que al pedir parada.
            while let Ok((sock, _)) = listener.accept() {
                // La conexion de despertar que envia `parar()` llega hasta
                // aqui; si ya se pidio parar, se descarta y se sale sin
                // atenderla.
                if parar_hilo.load(Ordering::SeqCst) {
                    break;
                }
                // Sin esto, el algoritmo de Nagle retiene la respuesta
                // esperando mas datos que nunca llegan, y su interaccion con el
                // ACK retardado del cliente anade ~40 ms a CADA llamada. El
                // protocolo son mensajes pequenos de ida y vuelta: agruparlos
                // no ahorra nada y cuesta muchisimo.
                let _ = sock.set_nodelay(true);
                let cfg = cfg.clone();
                let manejador = manejador.clone();
                std::thread::spawn(move || {
                    let _ = atender_conexion(cfg, manejador, sock);
                });
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
        self.despertar();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }

    /// Despierta el `accept` bloqueante con una conexion local que se descarta.
    ///
    /// Es el precio de no sondear: el hilo de aceptacion duerme dentro del
    /// nucleo hasta que llega una conexion, asi que para que note la orden de
    /// parada hay que darle exactamente eso, una conexion.
    fn despertar(&self) {
        let _ = std::net::TcpStream::connect(self.direccion);
    }
}

impl Drop for ServidorEnEjecucion {
    fn drop(&mut self) {
        self.parar.store(true, Ordering::SeqCst);
        let _ = std::net::TcpStream::connect(self.direccion);
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

        // La suscripcion rompe el patron peticion/respuesta: en vez de contestar
        // y volver a leer, la conexion se convierte en un canal por el que el
        // servidor escribe cuando hay novedad. Se detecta ANTES de despachar.
        if Metodo::de_codigo(enrutado) == Some(Metodo::SuscribirPolitica) {
            let req = match SuscripcionPolitica::decodificar(&cuerpo) {
                Ok(r) => r,
                Err(_) => {
                    let _ = escribir_marco(&mut tls, ESTADO_INTERNO, b"suscripcion invalida");
                    return Ok(());
                }
            };
            return atender_suscripcion(&manejador, &identidad, &req, &mut tls);
        }

        let (estado, respuesta) = despachar(&manejador, &identidad, enrutado, &cuerpo);
        escribir_marco(&mut tls, estado, &respuesta)?;
    }
}

/// Plazo tras el cual, sin novedad, se envia un latido por el canal de empuje.
///
/// Un canal que solo habla cuando hay novedades es indistinguible de uno muerto:
/// ni el agente sabe si sigue suscrito ni el servidor si el agente sigue ahi.
/// Treinta segundos detectan la caida pronto sin convertir el canal en trafico.
const PLAZO_KEEPALIVE: Duration = Duration::from_secs(30);

/// Atiende un canal de suscripcion: escribe empujes hasta que se cierre.
///
/// El hilo de esta conexion se queda dormido dentro de `esperar_empuje` y
/// despierta en cuanto el operador publica politica. Ese es el mecanismo que
/// hace que "bloquear el puerto 445 en toda la flota" llegue a los endpoints en
/// milisegundos y no en el siguiente latido.
fn atender_suscripcion(
    manejador: &Arc<dyn ManejadorFlota>,
    cn: &str,
    req: &SuscripcionPolitica,
    tls: &mut rustls::StreamOwned<ServerConnection, TcpStream>,
) -> Resultado<()> {
    let mut estado = EstadoCanal {
        version_entregada: req.version_conocida,
        caza_entregada: String::new(),
    };
    loop {
        let Some(empuje) = manejador.esperar_empuje(cn, &estado, PLAZO_KEEPALIVE) else {
            // El manejador cierra el canal de forma ordenada.
            return Ok(());
        };
        if !empuje.es_keepalive {
            estado.version_entregada = empuje.version;
        }
        if !empuje.caza_id.is_empty() {
            estado.caza_entregada = empuje.caza_id.clone();
        }
        // Un fallo de escritura significa que el agente se fue: se termina sin
        // ruido, que es lo normal cuando un endpoint se apaga.
        if escribir_marco(tls, ESTADO_OK, &empuje.codificar()).is_err() {
            return Ok(());
        }
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
        Metodo::ReportarStix => match ReporteStix::decodificar(cuerpo) {
            Ok(req) => {
                let ack = manejador.stix(cn, &req);
                if ack.recibido {
                    (ESTADO_OK, ack.codificar())
                } else {
                    (ESTADO_RECHAZADO, ack.motivo.clone().into_bytes())
                }
            }
            Err(_) => (ESTADO_INTERNO, b"bundle STIX invalido".to_vec()),
        },
        Metodo::ReportarGrafo => match ReporteGrafo::decodificar(cuerpo) {
            Ok(req) => (ESTADO_OK, manejador.grafo(cn, &req).codificar()),
            Err(_) => (ESTADO_INTERNO, b"grafo invalido".to_vec()),
        },
        // La suscripcion no pasa por aqui: no es peticion/respuesta, sino un
        // canal que queda abierto. La atiende `atender_conexion`.
        Metodo::SuscribirPolitica => (
            ESTADO_INTERNO,
            b"la suscripcion no se despacha como llamada unaria".to_vec(),
        ),
        Metodo::ReportarCaza => match ReporteCaza::decodificar(cuerpo) {
            Ok(req) => (ESTADO_OK, manejador.caza(cn, &req).codificar()),
            Err(_) => (ESTADO_INTERNO, b"informe de caza invalido".to_vec()),
        },
    }
}
