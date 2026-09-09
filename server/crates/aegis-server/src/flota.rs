//! Transporte NATIVO de la flota: el que hablan los agentes reales.
//!
//! El agente (`aegis-fleet`, FASE 34) envia protobuf con el enmarcado de gRPC
//! —prefijo de cinco bytes— sobre un canal mTLS crudo, NO sobre HTTP/2. Este
//! modulo implementa el trait [`ManejadorFlota`] que define ese crate, asi que
//! el servidor decodifica exactamente con el mismo codigo con el que el agente
//! codifica. La compatibilidad de cable no es una promesa: es la misma
//! implementacion en los dos extremos.
//!
//! # El puente sincrono/asincrono
//!
//! El trait es SINCRONO (el listener del agente atiende cada conexion en su
//! propio hilo) y la persistencia es ASINCRONA (sqlx sobre tokio). El puente es
//! `Handle::block_on`, que es correcto AQUI precisamente porque estos metodos
//! corren en hilos propios del listener y no en un worker de tokio —bloquear un
//! worker seria un error grave que tokio detecta y castiga con un panico—.

use std::sync::Arc;

use aegis_fleet::proto::{
    AckEvento, AckLatido, Latido, ReporteEvento, RespuestaEnrolamiento, SolicitudEnrolamiento,
};
use aegis_fleet::servidor::ManejadorFlota;
use tokio::runtime::Handle;

use crate::dominio::ServicioFlota;

/// Manejador de flota respaldado por PostgreSQL.
pub struct ManejadorPersistente {
    servicio: Arc<ServicioFlota>,
    handle: Handle,
}

impl ManejadorPersistente {
    /// Crea el manejador con el runtime sobre el que ejecutar la persistencia.
    pub fn nuevo(servicio: Arc<ServicioFlota>, handle: Handle) -> ManejadorPersistente {
        ManejadorPersistente { servicio, handle }
    }
}

impl ManejadorFlota for ManejadorPersistente {
    fn enrolar(&self, cn: &str, req: &SolicitudEnrolamiento) -> RespuestaEnrolamiento {
        let servicio = self.servicio.clone();
        // Una copia para el closure y otra, acotada, para el registro: el CN lo
        // controla el par y no debe volcarse entero en el log.
        let cn_log = cn_seguro(cn);
        let cn_owned = cn.to_string();
        let req = req.clone();

        let resultado = self.handle.block_on(async move {
            servicio
                .enrolar(
                    &cn_owned,
                    &req.id_agente,
                    &req.hostname,
                    &req.version_agente,
                    &req.huella_cert,
                )
                .await
        });

        match resultado {
            Ok(id_flota) => RespuestaEnrolamiento {
                aceptado: true,
                id_flota,
                intervalo_latido_seg: self.servicio.intervalo_latido_seg(),
                motivo: String::new(),
            },
            Err(e) => {
                // Un fallo de la base de datos se convierte en un rechazo CON
                // motivo, no en una conexion cortada: el agente reintentara y,
                // mientras tanto, el operador ve por que no entra.
                tracing::error!(cn = %cn_log, error = %e, "enrolamiento fallido");
                RespuestaEnrolamiento {
                    aceptado: false,
                    id_flota: String::new(),
                    intervalo_latido_seg: self.servicio.intervalo_latido_seg(),
                    motivo: "el plano de control no pudo registrar el agente".to_string(),
                }
            }
        }
    }

    fn latido(&self, cn: &str, req: &Latido) -> AckLatido {
        let servicio = self.servicio.clone();
        let cn_owned = cn.to_string();
        let req = req.clone();

        let resultado = self.handle.block_on(async move {
            servicio
                .latido(
                    &cn_owned,
                    req.rss_kb,
                    req.amenazas_activas,
                    req.version_politica,
                )
                .await
        });

        match resultado {
            Ok(estado) => AckLatido {
                recibido: true,
                version_politica_disponible: estado.version_politica.max(0) as u64,
                hay_comando: estado.hay_comando,
            },
            Err(e) => {
                tracing::warn!(error = %e, "latido no persistido");
                // `recibido: false` le dice al agente que su latido no quedo
                // registrado; seguira latiendo y el inventario se recuperara
                // solo en cuanto la base de datos vuelva.
                AckLatido {
                    recibido: false,
                    version_politica_disponible: 0,
                    hay_comando: false,
                }
            }
        }
    }

    fn evento(&self, cn: &str, req: &ReporteEvento) -> AckEvento {
        let servicio = self.servicio.clone();
        let cn_owned = cn.to_string();
        let req = req.clone();

        let resultado = self.handle.block_on(async move {
            servicio
                .evento(
                    &cn_owned,
                    req.severidad,
                    &req.categoria,
                    &req.descripcion,
                    req.momento_unix,
                )
                .await
        });

        match resultado {
            Ok(id) => AckEvento {
                recibido: true,
                id_incidente: id.to_string(),
            },
            Err(e) => {
                // Un evento que no se persiste es una alerta perdida: se deja
                // constancia en el log del servidor con nivel de error.
                tracing::error!(error = %e, "EVENTO DE SEGURIDAD NO PERSISTIDO");
                AckEvento {
                    recibido: false,
                    id_incidente: String::new(),
                }
            }
        }
    }
}

/// Evita volcar en el log un CN de longitud arbitraria controlado por el par.
fn cn_seguro(cn: &str) -> String {
    cn.chars().take(64).collect()
}
