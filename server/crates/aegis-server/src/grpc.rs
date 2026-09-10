//! Superficie gRPC ESTANDAR sobre HTTP/2 (tonic).
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
//! # Identidad
//!
//! El transporte nativo autentica por el CN del certificado del handshake mTLS.
//! Aqui, cuando tonic corre con TLS mutuo, la identidad del par se obtiene de
//! sus certificados; sin TLS mutuo, se exige la cabecera `x-aegis-agente` y el
//! despliegue debe poner esta superficie DETRAS de un proxy que autentique.
//! Nunca se toma el identificador del cuerpo del mensaje: ese lo controla quien
//! envia.

use std::sync::Arc;

use tonic::{Request, Response, Status};

use crate::dominio::ServicioFlota;
use crate::pb::aegis_fleet_server::AegisFleet;
use crate::pb::{
    AckEvento, AckLatido, Latido, ReporteEvento, RespuestaEnrolamiento, SolicitudEnrolamiento,
};

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

/// Obtiene la identidad autenticada del par.
///
/// El `Result<_, Status>` grande lo impone la API de tonic: el trait del
/// servicio devuelve exactamente ese tipo, asi que meterlo en un `Box` aqui solo
/// anadiria una indireccion y una conversion en cada uso, sin ahorrar nada.
///
/// Orden de preferencia: el CN del certificado de cliente (autenticado por la
/// CA de la flota) y, si no hay TLS mutuo, la cabecera que inyecta el proxy.
/// Si no hay ninguna de las dos, la peticion se rechaza: sin identidad
/// verificada no se escribe nada en el inventario.
#[allow(clippy::result_large_err)]
fn identidad_del_par<T>(req: &Request<T>) -> Result<String, Status> {
    if let Some(certs) = req.peer_certs() {
        if let Some(primero) = certs.first() {
            if let Some(cn) = aegis_fleet::x509::subject_cn(primero.as_ref()) {
                return Ok(cn);
            }
        }
    }
    match req.metadata().get("x-aegis-agente") {
        Some(v) => v
            .to_str()
            .map(|s| s.to_string())
            .map_err(|_| Status::invalid_argument("x-aegis-agente no es texto valido")),
        None => Err(Status::unauthenticated(
            "sin identidad: hace falta certificado de cliente o cabecera x-aegis-agente",
        )),
    }
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
            })),
            Err(e) => {
                tracing::error!(error = %e, "EVENTO DE SEGURIDAD NO PERSISTIDO (gRPC)");
                Err(Status::internal("no se pudo registrar el evento"))
            }
        }
    }
}
