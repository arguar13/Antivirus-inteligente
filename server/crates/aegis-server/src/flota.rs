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
use std::time::Duration;

use aegis_fleet::proto::{
    AckEvento, AckGrafo, AckLatido, AckStix, EmpujePolitica, Latido, ReporteEvento, ReporteGrafo,
    ReporteStix, RespuestaEnrolamiento, SolicitudEnrolamiento,
};
use aegis_fleet::servidor::ManejadorFlota;
use tokio::runtime::Handle;

use crate::dominio::ServicioFlota;

/// Manejador de flota respaldado por PostgreSQL.
pub struct ManejadorPersistente {
    servicio: Arc<ServicioFlota>,
    handle: Handle,
    /// Receptor de avisos de politica; `None` desactiva el empuje.
    avisos: Option<tokio::sync::watch::Receiver<i64>>,
}

impl ManejadorPersistente {
    /// Crea el manejador con el runtime sobre el que ejecutar la persistencia.
    ///
    /// Sin notificador NO hay empuje: el canal de suscripcion se cerrara de
    /// forma ordenada en vez de dejar al agente esperando algo que no llegaria.
    pub fn nuevo(servicio: Arc<ServicioFlota>, handle: Handle) -> ManejadorPersistente {
        ManejadorPersistente {
            servicio,
            handle,
            avisos: None,
        }
    }

    /// Habilita el empuje de politica con el notificador dado.
    pub fn con_avisos(mut self, avisos: tokio::sync::watch::Receiver<i64>) -> ManejadorPersistente {
        self.avisos = Some(avisos);
        self
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

    fn stix(&self, cn: &str, req: &ReporteStix) -> AckStix {
        let servicio = self.servicio.clone();
        let cn_owned = cn.to_string();
        let bundle = req.bundle_json.clone();
        let momento = req.momento_unix;

        let resultado = self
            .handle
            .block_on(async move { servicio.ingerir_stix(&cn_owned, &bundle, momento).await });

        match resultado {
            Ok(ingesta) => AckStix {
                recibido: true,
                objetos_ingeridos: ingesta.objetos,
                motivo: String::new(),
            },
            Err(e) => {
                tracing::warn!(error = %e, "bundle STIX rechazado");
                AckStix {
                    recibido: false,
                    objetos_ingeridos: 0,
                    // El motivo viaja al agente: un endpoint que sabe POR QUE se
                    // le rechaza puede corregir; uno que solo recibe un no,
                    // reintenta lo mismo para siempre.
                    motivo: format!("{e}"),
                }
            }
        }
    }

    fn grafo(&self, cn: &str, req: &ReporteGrafo) -> AckGrafo {
        let servicio = self.servicio.clone();
        let cn_owned = cn.to_string();
        let raiz = req.raiz;
        let momento = req.momento_unix;
        let nodos = req.nodos.clone();

        let resultado = self.handle.block_on(async move {
            servicio
                .ingerir_grafo(&cn_owned, raiz, momento, &nodos)
                .await
        });

        match resultado {
            Ok((id, n)) => AckGrafo {
                recibido: true,
                id_grafo: id.to_string(),
                nodos_ingeridos: n,
            },
            Err(e) => {
                tracing::error!(error = %e, "LINAJE DE PROCESOS NO PERSISTIDO");
                AckGrafo::default()
            }
        }
    }

    fn esperar_empuje(
        &self,
        cn: &str,
        version_conocida: u64,
        plazo: Duration,
    ) -> Option<EmpujePolitica> {
        // Sin notificador no hay empuje: se cierra el canal en vez de dejar al
        // agente esperando indefinidamente algo que no va a llegar.
        let mut rx = self.avisos.as_ref()?.clone();
        let cn = cn.to_string();

        self.handle.block_on(async move {
            let version_anunciada = *rx.borrow();

            // Un agente que reconecta atrasado se pone al dia sin esperar al
            // siguiente cambio.
            if version_anunciada > version_conocida as i64 {
                return Some(self.componer_empuje(&cn, version_anunciada).await);
            }

            // Tambien puede haber comandos suyos esperando aunque la politica no
            // haya cambiado.
            let empuje = self.componer_empuje(&cn, version_anunciada).await;
            if !empuje.comandos_json.is_empty() {
                return Some(empuje);
            }

            match tokio::time::timeout(plazo, rx.changed()).await {
                Ok(Ok(())) => {
                    let v = *rx.borrow();
                    Some(self.componer_empuje(&cn, v).await)
                }
                // El emisor desaparecio: el servicio esta cerrando.
                Ok(Err(_)) => None,
                // Vencio el plazo: latido de canal. Sin el, un canal sano y uno
                // muerto son indistinguibles para los dos extremos.
                Err(_) => Some(EmpujePolitica {
                    version: version_anunciada.max(0) as u64,
                    es_keepalive: true,
                    ..Default::default()
                }),
            }
        })
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

impl ManejadorPersistente {
    /// Construye el empuje con la politica vigente y los comandos del agente.
    async fn componer_empuje(&self, cn: &str, version: i64) -> EmpujePolitica {
        let almacen = self.servicio.almacen();
        let (v, politica) = almacen
            .politica_activa()
            .await
            .unwrap_or((version, serde_json::Value::Null));

        // Los comandos se toman AQUI y se marcan entregados: `FOR UPDATE SKIP
        // LOCKED` garantiza que, con varias instancias atendiendo la misma
        // flota, ninguno se entrega dos veces.
        let mut comandos = Vec::new();
        while comandos.len() < 32 {
            match almacen.tomar_comando_pendiente(cn).await {
                Ok(Some(c)) => comandos.push(serde_json::json!({
                    "id": c.id, "accion": c.accion, "parametros": c.parametros
                })),
                _ => break,
            }
        }

        EmpujePolitica {
            version: v.max(0) as u64,
            politica_json: if politica.is_null() {
                String::new()
            } else {
                politica.to_string()
            },
            comandos_json: if comandos.is_empty() {
                String::new()
            } else {
                serde_json::Value::Array(comandos).to_string()
            },
            es_keepalive: false,
        }
    }
}

/// Evita volcar en el log un CN de longitud arbitraria controlado por el par.
fn cn_seguro(cn: &str) -> String {
    cn.chars().take(64).collect()
}
