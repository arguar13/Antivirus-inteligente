//! Contencion preventiva viva: de la prediccion a la orden en el endpoint.
//!
//! # Donde encaja
//!
//! [`aegis_predict`] calcula y **propone**. Este modulo es lo que convierte esa
//! propuesta en una orden que sale de verdad hacia un endpoint, reutilizando el
//! mismo ejecutor de la FASE 64 que ya usa la ruta de deteccion.
//!
//! Reutilizarlo no es comodidad: es que la orden de aislar que nace de una
//! prediccion tiene que ser **exactamente la misma** que la que nace de una
//! deteccion o la que lanza el analista desde la consola. Tres caminos distintos
//! para la misma orden serian tres sitios donde arreglar el mismo fallo, y el
//! dia que uno se quede atras el endpoint recibira algo que no entiende.
//!
//! # Lo que este modulo NO hace, y es deliberado
//!
//! No decide. La decision —con sus cinco frenos, el tope de radio y el escalado
//! a una persona— vive entera en [`aegis_predict::contencion`], donde se prueba
//! sin base de datos y sin flota. Aqui solo se ejecuta lo que ya se decidio.
//!
//! # Preventivo se marca como preventivo
//!
//! La orden lleva un **ordenante distinto** ([`ORDENANTE_PREVENTIVO`]) del de la
//! remediacion por deteccion. Eso no es cosmetica: cuando un analista abra el
//! informe a las tres de la manana, la diferencia entre «esto se aisló porque
//! detectamos un Golden Ticket» y «esto se aisló porque el modelo predijo un
//! camino» es la primera pregunta que va a hacer, y tiene que estar en el dato,
//! no en la memoria de quien lo montó.

use aegis_orchestrator::{AccionRemediacion, EjecutorRemediacion, Objetivo};
use aegis_predict::contencion::Veredicto;
use aegis_predict::{ConfigContencion, GrafoAtaque, InformePrediccion};

/// Quien consta como ordenante de una contencion preventiva.
///
/// Distinto de `ai-ro` (la remediacion por deteccion) a proposito: el informe
/// tiene que distinguir «se detectó» de «se predijo».
pub const ORDENANTE_PREVENTIVO: &str = "ai-predict";

/// El resultado de intentar contener preventivamente.
#[derive(Debug, Clone, PartialEq)]
pub enum ResultadoPreventivo {
    /// Se ejecuto la accion.
    Ejecutada {
        /// Sobre quien.
        sujeto: String,
        /// Que.
        accion: AccionRemediacion,
        /// Por que.
        justificacion: String,
    },
    /// Se intento y fallo. No se reintenta aqui: una contencion preventiva que
    /// falla no es una emergencia —no ha pasado nada todavia— y machacar un
    /// endpoint que no responde con reintentos es como se tira un plano de
    /// control durante un incidente.
    Fallida {
        /// Sobre quien se intento.
        sujeto: String,
        /// Por que fallo.
        motivo: String,
    },
    /// El motor decidio que esto lo tiene que ver una persona.
    Escalada {
        /// Que se vio.
        justificacion: String,
    },
    /// No habia nada que hacer.
    SinAccion,
}

/// Analiza un activo y, si procede, ejecuta **una** accion preventiva.
///
/// Devuelve tambien el informe completo, porque el panel lo necesita entero
/// aunque no se haya actuado: un camino de ataque que no llego al umbral sigue
/// siendo lo mas util que el analista puede mirar esta semana.
///
/// # Errores
/// Los de [`aegis_predict::analizar`]: activo desconocido o ausencia de joyas de
/// la corona declaradas.
pub async fn contener_preventivamente<E: EjecutorRemediacion>(
    grafo: &GrafoAtaque,
    origen: &str,
    config: &ConfigContencion,
    ejecutor: &E,
) -> Result<(InformePrediccion, ResultadoPreventivo), aegis_predict::ErrorPrediccion> {
    let informe = aegis_predict::analizar(grafo, origen, config)?;

    let resultado = match &informe.veredicto {
        Veredicto::NoActuar { .. } => ResultadoPreventivo::SinAccion,
        Veredicto::Escalar { justificacion, .. } => ResultadoPreventivo::Escalada {
            justificacion: justificacion.clone(),
        },
        Veredicto::Contener {
            sujeto,
            accion,
            justificacion,
            ..
        } => {
            let real: AccionRemediacion = (*accion).into();
            // El objetivo lleva el endpoint desde el que se analizo y el sujeto
            // sobre el que se actua. Son cosas distintas: se puede revocar los
            // tickets de una cuenta de servicio a raiz de un camino que empieza
            // en el portatil de otra persona.
            let objetivo = Objetivo {
                host: origen.to_string(),
                sujeto: sujeto.clone(),
            };
            match ejecutor.ejecutar(real, &objetivo).await {
                Ok(()) => ResultadoPreventivo::Ejecutada {
                    sujeto: sujeto.clone(),
                    accion: real,
                    justificacion: justificacion.clone(),
                },
                Err(motivo) => ResultadoPreventivo::Fallida {
                    sujeto: sujeto.clone(),
                    motivo,
                },
            }
        }
    };
    Ok((informe, resultado))
}

#[cfg(test)]
mod pruebas {
    use std::sync::Mutex;

    use aegis_itdr::grafo::Nivel;
    use aegis_predict::grafo::{Activo, ClaseActivo, Evidencia, Paso, RelacionSerializable, Via};

    use super::*;

    /// Ejecutor que anota lo que se le pide. Sustituye la FRONTERA (la flota),
    /// nunca una decision: todas las decisiones las ha tomado ya aegis-predict.
    #[derive(Default)]
    struct EjecutorAnotador {
        recibidas: Mutex<Vec<(AccionRemediacion, Objetivo)>>,
        falla: bool,
    }

    #[async_trait::async_trait]
    impl EjecutorRemediacion for EjecutorAnotador {
        async fn ejecutar(
            &self,
            accion: AccionRemediacion,
            objetivo: &Objetivo,
        ) -> Result<(), String> {
            self.recibidas
                .lock()
                .expect("sin envenenar")
                .push((accion, objetivo.clone()));
            if self.falla {
                Err("el endpoint no responde".to_string())
            } else {
                Ok(())
            }
        }
    }

    fn grafo_con_camino() -> GrafoAtaque {
        let mut g = GrafoAtaque::nuevo();
        g.agregar(Activo::nuevo(
            "pc-becario",
            ClaseActivo::Endpoint,
            Nivel::Usuario,
            0,
        ))
        .unwrap();
        g.agregar(Activo::nuevo(
            "svc-backup",
            ClaseActivo::Identidad,
            Nivel::Operador,
            40,
        ))
        .unwrap();
        g.agregar(Activo::nuevo(
            "Domain Admins",
            ClaseActivo::Identidad,
            Nivel::AdminDominio,
            100,
        ))
        .unwrap();
        g.conectar(Paso::nuevo(
            "pc-becario",
            "svc-backup",
            Via::Identidad(RelacionSerializable::ControlaCredencialesDe),
        ))
        .unwrap();
        g.conectar(Paso::nuevo(
            "svc-backup",
            "Domain Admins",
            Via::Identidad(RelacionSerializable::MiembroDe),
        ))
        .unwrap();
        g
    }

    #[tokio::test]
    async fn una_propuesta_de_contener_sale_de_verdad_hacia_el_ejecutor() {
        let g = grafo_con_camino();
        let ej = EjecutorAnotador::default();
        let (informe, r) =
            contener_preventivamente(&g, "pc-becario", &ConfigContencion::default(), &ej)
                .await
                .expect("analisis");

        match r {
            ResultadoPreventivo::Ejecutada { sujeto, accion, .. } => {
                assert_eq!(sujeto, "svc-backup");
                assert_eq!(accion, AccionRemediacion::RevocarTicketsKerberos);
            }
            otro => panic!("se esperaba ejecucion: {otro:?}"),
        }
        let recibidas = ej.recibidas.lock().unwrap();
        assert_eq!(recibidas.len(), 1, "UNA accion, no un playbook entero");
        assert_eq!(recibidas[0].1.host, "pc-becario");
        assert_eq!(recibidas[0].1.sujeto, "svc-backup");
        assert!(informe.camino_principal().is_some());
    }

    /// Una prediccion nunca lanza el playbook completo. Una deteccion confirmada
    /// si; una hipotesis, no.
    #[tokio::test]
    async fn una_prediccion_no_dispara_el_playbook_entero() {
        let g = grafo_con_camino();
        let ej = EjecutorAnotador::default();
        contener_preventivamente(&g, "pc-becario", &ConfigContencion::default(), &ej)
            .await
            .expect("analisis");
        assert_eq!(
            ej.recibidas.lock().unwrap().len(),
            1,
            "una prediccion es una hipotesis, no cuatro acciones"
        );
    }

    #[tokio::test]
    async fn un_escalado_no_manda_nada_al_ejecutor() {
        // Evidencia recien fabricada: el motor escala en vez de actuar.
        let mut g = GrafoAtaque::nuevo();
        g.agregar(Activo::nuevo(
            "pc-victima",
            ClaseActivo::Endpoint,
            Nivel::Usuario,
            0,
        ))
        .unwrap();
        g.agregar(Activo::nuevo(
            "Domain Admins",
            ClaseActivo::Identidad,
            Nivel::AdminDominio,
            100,
        ))
        .unwrap();
        g.conectar(
            Paso::nuevo(
                "pc-victima",
                "Domain Admins",
                Via::Identidad(RelacionSerializable::MiembroDe),
            )
            .con_evidencia(Evidencia::recien_vista()),
        )
        .unwrap();

        let ej = EjecutorAnotador::default();
        let cfg = ConfigContencion {
            probabilidad_minima: 0.01,
            ..Default::default()
        };
        let (_, r) = contener_preventivamente(&g, "pc-victima", &cfg, &ej)
            .await
            .expect("analisis");
        assert!(matches!(r, ResultadoPreventivo::Escalada { .. }), "{r:?}");
        assert!(
            ej.recibidas.lock().unwrap().is_empty(),
            "escalar significa NO tocar nada"
        );
    }

    /// Un fallo del endpoint no se reintenta ni se esconde: se reporta. Una
    /// contencion preventiva que falla no es una emergencia —no ha pasado nada
    /// todavia— y machacar con reintentos un endpoint que no responde es como se
    /// tira un plano de control durante un incidente.
    #[tokio::test]
    async fn un_fallo_del_endpoint_se_reporta_sin_reintentar() {
        let g = grafo_con_camino();
        let ej = EjecutorAnotador {
            falla: true,
            ..Default::default()
        };
        let (_, r) = contener_preventivamente(&g, "pc-becario", &ConfigContencion::default(), &ej)
            .await
            .expect("analisis");
        match r {
            ResultadoPreventivo::Fallida { sujeto, motivo } => {
                assert_eq!(sujeto, "svc-backup");
                assert!(motivo.contains("no responde"));
            }
            otro => panic!("se esperaba fallo reportado: {otro:?}"),
        }
        assert_eq!(
            ej.recibidas.lock().unwrap().len(),
            1,
            "un solo intento, sin reintentos"
        );
    }

    #[tokio::test]
    async fn el_ordenante_preventivo_se_distingue_del_de_deteccion() {
        assert_ne!(
            ORDENANTE_PREVENTIVO,
            crate::remediacion::ORDENANTE_AUTOMATICO,
            "el informe tiene que poder distinguir 'se detecto' de 'se predijo'"
        );
    }
}
