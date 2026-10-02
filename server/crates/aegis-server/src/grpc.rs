//! Superficie gRPC ESTANDAR sobre HTTP/2 (tonic), SOLO con mTLS.
//!
//! El agente de AegisCore no habla por aqui: habla por el transporte nativo
//! ([`crate::flota`]). Esta superficie existe para lo demas —integraciones de
//! terceros, conectores de SIEM, sondas escritas en otros lenguajes— que si
//! esperan gRPC canonico y no van a implementar un enmarcado propio.
//!
//! Los MENSAJES son los mismos: el `.proto` declara los mismos numeros de campo
//! que el codec del agente, asi que los dos transportes intercambian bytes de
//! mensaje identicos y solo difieren en como los envuelven.
//!
//! # Identidad (H-01)
//!
//! La identidad del par sale UNICAMENTE del certificado de cliente que el
//! handshake mTLS verifico contra la CA de la flota. No hay otra via: ni una
//! cabecera de metadatos que «inyecte un proxy», ni el cuerpo del mensaje. Antes
//! la habia —una cabecera que cualquiera podia escribir—, y con la superficie en
//! claro eso permitia enrolar, latir y reportar como CUALQUIER agente. Un
//! integrador de terceros recibe un certificado de la CA de flota, igual que un
//! agente; si no lo tiene, no pasa del handshake.
//!
//! # El mismo verificador que el transporte nativo
//!
//! La configuracion TLS NO se construye aqui: sale de
//! [`aegis_fleet::tls::config_servidor`], la misma que usa el transporte nativo
//! (verificador WebPKI con la CA de flota como UNICA raiz, proveedor `ring`
//! explicito, versiones seguras). Aqui solo se anade ALPN `h2`, que HTTP/2
//! necesita. Dos superficies con dos politicas de confianza fue la causa raiz de
//! H-01; ahora hay una.
//!
//! # No hay camino en claro
//!
//! [`servir`] recibe la configuracion TLS POR TIPO y es la unica funcion que
//! levanta esta superficie. [`configurar_mtls`] se niega a producir una
//! configuracion sin material mTLS y lo dice en su error.

use std::sync::Arc;
use std::time::Duration;

use aegis_fleet::pki::Identidad;
use rustls::pki_types::CertificateDer;
use tokio::net::{TcpListener, TcpStream};
use tonic::{Request, Response, Status};

use crate::dominio::ServicioFlota;
use crate::pb::aegis_fleet_server::{AegisFleet, AegisFleetServer};
use crate::pb::{
    AckEvento, AckLatido, Latido, ReporteEvento, RespuestaEnrolamiento, SolicitudEnrolamiento,
};

/// Plazo maximo de un handshake mTLS.
///
/// Sin plazo, un cliente que abre la conexion y no completa el handshake retiene
/// una tarea y un descriptor para siempre: es la forma mas barata de agotar un
/// servidor, y no exige ningun certificado.
pub const PLAZO_HANDSHAKE: Duration = Duration::from_secs(5);

/// Handshakes mTLS simultaneos como mucho.
///
/// Acota el trabajo que un cliente SIN certificado puede provocar: por encima,
/// el bucle de aceptacion espera y las conexiones nuevas se quedan en la cola
/// del kernel. Las conexiones ya autenticadas no cuentan aqui.
pub const HANDSHAKES_SIMULTANEOS: usize = 256;

/// Error al preparar o servir la superficie gRPC.
#[derive(Debug, thiserror::Error)]
pub enum ErrorGrpc {
    /// Falta el material mTLS (identidad del servidor o CA de flota).
    #[error(
        "la superficie gRPC exige mTLS con la CA de flota y no hay configuracion TLS: \
         NO se arranca en claro"
    )]
    SinMtls,
    /// La configuracion mTLS de la flota no se pudo construir.
    #[error("configuracion mTLS de la superficie gRPC: {0}")]
    Tls(#[from] aegis_fleet::error::FleetError),
    /// El transporte de tonic fallo.
    #[error("transporte gRPC: {0}")]
    Transporte(#[from] tonic::transport::Error),
}

/// Construye la configuracion TLS de la superficie gRPC.
///
/// Reutiliza [`aegis_fleet::tls::config_servidor`] —la verificacion del
/// certificado de cliente del transporte nativo, sin duplicarla— y le anade
/// ALPN `h2`. Sin identidad de servidor o sin CA de flota devuelve
/// [`ErrorGrpc::SinMtls`]: no existe una configuracion «sin TLS».
pub fn configurar_mtls(
    identidad: Option<&Identidad>,
    ca_flota: Option<&CertificateDer<'static>>,
) -> Result<Arc<rustls::ServerConfig>, ErrorGrpc> {
    let (Some(identidad), Some(ca_flota)) = (identidad, ca_flota) else {
        return Err(ErrorGrpc::SinMtls);
    };
    let base = aegis_fleet::tls::config_servidor(identidad, ca_flota)?;
    let mut cfg = (*base).clone();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Arc::new(cfg))
}

/// Sirve la superficie gRPC sobre `escucha`, SOLO con mTLS.
///
/// La configuracion TLS llega por tipo: no hay forma de llamar a esta funcion
/// sin ella, y no hay otra funcion que levante la superficie.
pub async fn servir(
    escucha: TcpListener,
    servicio: ServicioGrpc,
    tls: Arc<rustls::ServerConfig>,
) -> Result<(), ErrorGrpc> {
    tonic::transport::Server::builder()
        .add_service(AegisFleetServer::new(servicio))
        .serve_with_incoming(entrantes_mtls(escucha, tls))
        .await?;
    Ok(())
}

/// Convierte el escuchador TCP en un flujo de conexiones YA autenticadas.
///
/// Cada handshake corre en su propia tarea, con plazo y con cupo: uno lento no
/// retrasa a los demas, y uno fallido se registra y se descarta sin llegar
/// nunca a tonic. Al flujo solo salen conexiones cuyo certificado de cliente
/// verifico la CA de la flota.
fn entrantes_mtls(escucha: TcpListener, tls: Arc<rustls::ServerConfig>) -> Entrantes {
    let aceptador = tokio_rustls::TlsAcceptor::from(tls);
    let (tx, rx) = tokio::sync::mpsc::channel(HANDSHAKES_SIMULTANEOS);
    let cupo = Arc::new(tokio::sync::Semaphore::new(HANDSHAKES_SIMULTANEOS));

    tokio::spawn(async move {
        loop {
            let (socket, par) = match escucha.accept().await {
                Ok(x) => x,
                Err(e) => {
                    // Descriptores agotados u otro fallo transitorio: se espera
                    // un poco en vez de girar en vacio.
                    tracing::warn!(error = %e, "gRPC: fallo al aceptar una conexion");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            let Ok(permiso) = cupo.clone().acquire_owned().await else {
                break;
            };
            if tx.is_closed() {
                break;
            }
            let aceptador = aceptador.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let _permiso = permiso;
                match tokio::time::timeout(PLAZO_HANDSHAKE, aceptador.accept(socket)).await {
                    Ok(Ok(conexion)) => {
                        let _ = tx.send(Ok(conexion)).await;
                    }
                    Ok(Err(e)) => {
                        tracing::info!(par = %par, error = %e, "gRPC: handshake mTLS rechazado");
                    }
                    Err(_) => {
                        tracing::info!(par = %par, "gRPC: handshake mTLS fuera de plazo");
                    }
                }
            });
        }
    });

    Box::pin(futures::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|c| (c, rx))
    }))
}

/// Flujo de conexiones ya autenticadas por mTLS que se entrega a tonic.
///
/// Va en caja (y por tanto es `Unpin`) para no depender de si tonic exige o no
/// `Unpin` al flujo de entrada.
type Entrantes = std::pin::Pin<
    Box<
        dyn futures::Stream<
                Item = Result<tokio_rustls::server::TlsStream<TcpStream>, std::io::Error>,
            > + Send,
    >,
>;

/// Implementacion gRPC del servicio de flota.
pub struct ServicioGrpc {
    servicio: Arc<ServicioFlota>,
}

impl ServicioGrpc {
    /// Crea el servicio gRPC sobre el nucleo de dominio.
    pub fn nuevo(servicio: Arc<ServicioFlota>) -> ServicioGrpc {
        ServicioGrpc { servicio }
    }
}

/// Obtiene la identidad autenticada del par: el CN de su certificado.
///
/// El `Result<_, Status>` grande lo impone la API de tonic: el trait del
/// servicio devuelve exactamente ese tipo, asi que meterlo en un `Box` aqui solo
/// anadiria una indireccion y una conversion en cada uso, sin ahorrar nada.
///
/// Es la MISMA extraccion que usa el transporte nativo
/// ([`aegis_fleet::tls::cn_del_par`]). No hay alternativa: sin certificado
/// verificado no hay identidad, y sin identidad no se escribe nada.
#[allow(clippy::result_large_err)]
fn identidad_del_par<T>(req: &Request<T>) -> Result<String, Status> {
    let certs = req.peer_certs();
    aegis_fleet::tls::cn_del_par(certs.as_deref().map(Vec::as_slice)).ok_or_else(|| {
        Status::unauthenticated(
            "sin certificado de cliente verificado por la CA de flota: \
             la identidad solo sale del handshake mTLS",
        )
    })
}

#[tonic::async_trait]
impl AegisFleet for ServicioGrpc {
    async fn enrolar(
        &self,
        peticion: Request<SolicitudEnrolamiento>,
    ) -> Result<Response<RespuestaEnrolamiento>, Status> {
        let cn = identidad_del_par(&peticion)?;
        let req = peticion.into_inner();

        match self
            .servicio
            .enrolar(
                &cn,
                &req.id_agente,
                &req.hostname,
                &req.version_agente,
                &req.huella_cert,
            )
            .await
        {
            Ok(id_flota) => Ok(Response::new(RespuestaEnrolamiento {
                aceptado: true,
                id_flota,
                intervalo_latido_seg: self.servicio.intervalo_latido_seg(),
                motivo: String::new(),
            })),
            Err(e) => {
                tracing::error!(error = %e, "enrolamiento gRPC fallido");
                Err(Status::internal("no se pudo registrar el agente"))
            }
        }
    }

    async fn latir(&self, peticion: Request<Latido>) -> Result<Response<AckLatido>, Status> {
        let cn = identidad_del_par(&peticion)?;
        let req = peticion.into_inner();

        match self
            .servicio
            .latido(&cn, req.rss_kb, req.amenazas_activas, req.version_politica)
            .await
        {
            Ok(estado) => Ok(Response::new(AckLatido {
                recibido: true,
                version_politica_disponible: estado.version_politica.max(0) as u64,
                hay_comando: estado.hay_comando,
            })),
            Err(e) => {
                tracing::warn!(error = %e, "latido gRPC no persistido");
                Err(Status::unavailable(
                    "el plano de control no pudo registrar el latido",
                ))
            }
        }
    }

    async fn reportar_evento(
        &self,
        peticion: Request<ReporteEvento>,
    ) -> Result<Response<AckEvento>, Status> {
        let cn = identidad_del_par(&peticion)?;
        let req = peticion.into_inner();

        match self
            .servicio
            .evento(
                &cn,
                req.severidad,
                &req.categoria,
                &req.descripcion,
                req.momento_unix,
                &req.detalles_json,
            )
            .await
        {
            Ok(id) => Ok(Response::new(AckEvento {
                recibido: true,
                id_incidente: id.to_string(),
                reintentar: false,
            })),
            Err(e) => {
                tracing::error!(error = %e, "EVENTO DE SEGURIDAD NO PERSISTIDO (gRPC)");
                // Transitorio: UNAVAILABLE, que un cliente gRPC reintenta.
                if e.es_transitorio() {
                    return Err(Status::unavailable(
                        "base de datos no disponible; reintentar",
                    ));
                }
                Err(Status::internal("no se pudo registrar el evento"))
            }
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_fleet::pki::AutoridadCertificadora;

    #[test]
    fn sin_material_mtls_la_superficie_se_niega_y_lo_dice() {
        let e = configurar_mtls(None, None).unwrap_err();
        assert!(matches!(e, ErrorGrpc::SinMtls));
        assert!(
            e.to_string().contains("NO se arranca en claro"),
            "el error tiene que decir por que no arranca: {e}"
        );

        // Con solo una de las dos piezas, tampoco.
        let ca = AutoridadCertificadora::nueva("CA de pruebas").unwrap();
        let id = ca.emitir("control-plane", 60).unwrap();
        assert!(matches!(
            configurar_mtls(None, Some(&ca.cert_der())),
            Err(ErrorGrpc::SinMtls)
        ));
        assert!(matches!(
            configurar_mtls(Some(&id), None),
            Err(ErrorGrpc::SinMtls)
        ));
    }

    #[test]
    fn con_material_mtls_negocia_http2() {
        let ca = AutoridadCertificadora::nueva("CA de pruebas").unwrap();
        let id = ca.emitir("control-plane", 60).unwrap();
        let cfg = configurar_mtls(Some(&id), Some(&ca.cert_der())).unwrap();
        assert_eq!(cfg.alpn_protocols, vec![b"h2".to_vec()]);
    }
}
