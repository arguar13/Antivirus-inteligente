//! Remediacion automatica: el puente VIVO entre el motor ITDR y el orquestador.
//!
//! Aqui se cierra el lazo de defensa del Control Plane. El motor ITDR
//! ([`crate::itdr`]) produce veredictos (Golden Ticket, Silver, escalada); este
//! modulo los conecta EN VIVO al [`Orquestador`] de la FASE 64: cada deteccion
//! sale por el bus del panel y, si supera el umbral, dispara automaticamente el
//! playbook de respuesta sobre la flota, SIN esperar a un humano.
//!
//! # Las dos piezas
//!
//! - [`EjecutorFlota`]: la implementacion REAL de [`EjecutorRemediacion`]. Traduce
//!   cada accion del playbook a un comando encolado para el agente
//!   ([`Almacen::encolar_comando`]) — el mismo mecanismo que ya usa el aislamiento
//!   manual del panel. El servidor SOLO ordena; el endpoint APLICA. Guarda solo el
//!   [`Almacen`] (un puntero al pool), NO el `ServicioFlota` entero, para no crear
//!   un ciclo de `Arc`.
//! - [`RespondedorItdr`]: el puente. Corre el motor sobre un lote de telemetria de
//!   identidad, publica cada deteccion al panel y remedia las criticas.
//!
//! # Honestidad de validacion
//!
//! Lo que puede estar MAL de forma peligrosa —que un veredicto dispare (o NO
//! dispare) el playbook correcto, con las acciones correctas— se prueba de verdad,
//! de extremo a extremo: un lote real de telemetria con un Golden Ticket entra, el
//! orquestador lanza sus cuatro acciones, y un doble de la FRONTERA (la flota)
//! registra que se le ordeno. No es un mock de la logica; es el sustituto del
//! agente, que es el muro. La ejecucion REAL del comando en el endpoint (aislar
//! por XDP, matar, revocar, volcar) ocurre en el agente y NO se ejercita aqui.
//!
//! Verbos de comando: el aislamiento ya existe ("aislar"/"liberar"); el resto son
//! verbos NUEVOS que el lado agente ira soportando (pendiente del agente, no del
//! Control Plane).

use aegis_orchestrator::{
    AccionRemediacion, Disparador, EjecutorRemediacion, EstadoPlaybook, InformeRemediacion,
    Objetivo, Orquestador,
};

use crate::almacen::Almacen;
use crate::eventos::{BusEventos, EventoPanel};
use crate::itdr::{a_evento_panel, MotorItdr, TelemetriaIdentidad};

/// Quien lo ordena, en el registro de auditoria de la tabla de comandos.
const ORDENADO_POR: &str = "orquestador-ai-ro";

/// El verbo de comando que el agente recibe por cada accion del playbook.
///
/// Es una cadena libre (como el aislamiento manual: "aislar"/"liberar"); el
/// endpoint la interpreta.
#[must_use]
pub fn verbo_de(accion: AccionRemediacion) -> &'static str {
    match accion {
        AccionRemediacion::AislarRed => "aislar",
        AccionRemediacion::MatarProcesosSospechosos => "matar_procesos",
        AccionRemediacion::RevocarTicketsKerberos => "revocar_tickets_kerberos",
        AccionRemediacion::VolcadoForenseMemoria => "volcado_forense",
    }
}

/// Los parametros JSON que acompanan al comando: el sujeto (la cuenta implicada),
/// para que el agente sepa que revocar/investigar, y la razon.
#[must_use]
pub fn parametros_de(accion: AccionRemediacion, objetivo: &Objetivo) -> serde_json::Value {
    serde_json::json!({
        "accion": verbo_de(accion),
        "sujeto": objetivo.sujeto,
        "razon": "remediacion automatica del orquestador ante deteccion critica de identidad",
    })
}

/// La implementacion REAL de [`EjecutorRemediacion`]: encola cada accion como un
/// comando para el agente. Guarda solo el [`Almacen`] (el pool), no el
/// `ServicioFlota` entero, para no crear un ciclo de `Arc`.
#[derive(Clone)]
pub struct EjecutorFlota {
    almacen: Almacen,
}

impl EjecutorFlota {
    /// Crea el ejecutor sobre el almacen del plano de control.
    #[must_use]
    pub fn nuevo(almacen: Almacen) -> Self {
        Self { almacen }
    }
}

#[async_trait::async_trait]
impl EjecutorRemediacion for EjecutorFlota {
    async fn ejecutar(&self, accion: AccionRemediacion, objetivo: &Objetivo) -> Result<(), String> {
        // Ok(_) = comando ENCOLADO (el endpoint lo aplicara en su proximo latido),
        // no aplicado. Consistente con el aislamiento manual del panel.
        self.almacen
            .encolar_comando(
                &objetivo.host,
                verbo_de(accion),
                parametros_de(accion, objetivo),
                ORDENADO_POR,
            )
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

/// El puente vivo entre el motor ITDR y el orquestador. Generico sobre el ejecutor
/// para que las pruebas puedan sustituir la flota real por un doble de la frontera.
pub struct RespondedorItdr<E: EjecutorRemediacion + Sync> {
    motor: tokio::sync::Mutex<MotorItdr>,
    orquestador: Orquestador,
    bus: BusEventos,
    ejecutor: E,
}

impl<E: EjecutorRemediacion + Sync> RespondedorItdr<E> {
    /// Crea el respondedor con un motor ITDR (grafo vivo entre lotes), el
    /// orquestador, el bus del panel y el ejecutor de la flota.
    pub fn nuevo(motor: MotorItdr, orquestador: Orquestador, bus: BusEventos, ejecutor: E) -> Self {
        Self {
            motor: tokio::sync::Mutex::new(motor),
            orquestador,
            bus,
            ejecutor,
        }
    }

    /// Procesa un lote de telemetria de identidad EN VIVO: correlaciona, publica
    /// cada deteccion al panel y remedia automaticamente las que superan el umbral
    /// del orquestador. Devuelve los informes de las remediaciones que se lanzaron.
    ///
    /// `origen_cn` es el agente/Controlador de Dominio que subio la telemetria; se
    /// usa como el endpoint objetivo de la remediacion (para un Golden Ticket, que
    /// compromete el dominio, el propio DC es un objetivo defendible; la resolucion
    /// fina cuenta -> endpoint via inventario es trabajo futuro).
    ///
    /// # Errores
    /// El error del motor si una relacion referencia una identidad desconocida.
    pub async fn procesar(
        &self,
        tel: &TelemetriaIdentidad,
        origen_cn: &str,
    ) -> Result<Vec<InformeRemediacion>, aegis_itdr::ItdrError> {
        // El grafo de identidad es vivo entre lotes: se toma el lock solo para
        // correlacionar, y se suelta ANTES de las llamadas de red de la remediacion
        // (no cruzar un guard de Mutex por un `.await` de I/O).
        let detecciones = {
            let mut motor = self.motor.lock().await;
            motor.analizar(tel)?
        };

        let mut informes = Vec::new();
        for (i, det) in detecciones.iter().enumerate() {
            // 1. Cada deteccion sale al panel por el mismo bus que el resto.
            self.bus.publicar(a_evento_panel(
                det,
                origen_cn,
                format!("itdr:{origen_cn}:{i}"),
            ));

            // 2. Remediacion automatica. El umbral del orquestador (Alta por
            //    defecto) filtra: por debajo, `remediar` devuelve NoAplica sin
            //    tocar la flota.
            let disparador = Disparador::from(det);
            let informe = self
                .orquestador
                .remediar(&disparador, origen_cn, &self.ejecutor)
                .await;

            if informe.estado != EstadoPlaybook::NoAplica {
                let (ok, fallidas) = cuenta_resultados(&informe);
                self.bus.publicar(EventoPanel::RemediacionAutomatica {
                    cn: origen_cn.to_string(),
                    clase: format!("{:?}", det.clase),
                    sujeto: det.sujeto.clone(),
                    acciones_ok: ok,
                    acciones_fallidas: fallidas,
                });
                informes.push(informe);
            }
        }
        Ok(informes)
    }
}

/// Cuenta las acciones con exito y las fallidas de un informe.
fn cuenta_resultados(informe: &InformeRemediacion) -> (usize, usize) {
    let ok = informe.resultados.iter().filter(|r| r.exito()).count();
    (ok, informe.resultados.len() - ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use aegis_itdr::kerberos::{EventoKdc, TipoCifrado};

    const T0: u64 = 1_800_000_000;
    const HORA: u64 = 3_600;

    /// Doble de la FRONTERA con la flota: registra `(host, accion)` de cada
    /// comando que se le ordena. No es un mock de la logica; es el sustituto del
    /// agente, que es el muro.
    #[derive(Clone)]
    struct EjecutorDoble {
        llamadas: Arc<Mutex<Vec<(String, AccionRemediacion)>>>,
    }

    impl EjecutorDoble {
        fn nuevo() -> Self {
            Self {
                llamadas: Arc::new(Mutex::new(Vec::new())),
            }
        }
        /// Un clon del registro para inspeccionarlo tras mover el doble al puente.
        fn registro(&self) -> Arc<Mutex<Vec<(String, AccionRemediacion)>>> {
            self.llamadas.clone()
        }
    }

    #[async_trait::async_trait]
    impl EjecutorRemediacion for EjecutorDoble {
        async fn ejecutar(
            &self,
            accion: AccionRemediacion,
            objetivo: &Objetivo,
        ) -> Result<(), String> {
            self.llamadas
                .lock()
                .unwrap()
                .push((objetivo.host.clone(), accion));
            Ok(())
        }
    }

    /// Un lote de telemetria con SOLO un Golden Ticket: 'administrator' pide 12 h
    /// el mismo servicio sin que la KDC emitiera un solo TGT.
    fn telemetria_golden() -> TelemetriaIdentidad {
        let mut tel = TelemetriaIdentidad::default();
        for i in 0..12u64 {
            tel.eventos_kdc.push(EventoKdc::solicitud_servicio(
                "administrator",
                "CIFS/dc.corp.local",
                TipoCifrado::Rc4Hmac,
                T0 + i * HORA,
            ));
        }
        tel
    }

    #[test]
    fn cada_accion_tiene_su_verbo_de_comando() {
        assert_eq!(verbo_de(AccionRemediacion::AislarRed), "aislar");
        assert_eq!(
            verbo_de(AccionRemediacion::MatarProcesosSospechosos),
            "matar_procesos"
        );
        assert_eq!(
            verbo_de(AccionRemediacion::RevocarTicketsKerberos),
            "revocar_tickets_kerberos"
        );
        assert_eq!(
            verbo_de(AccionRemediacion::VolcadoForenseMemoria),
            "volcado_forense"
        );
    }

    #[test]
    fn los_parametros_del_comando_llevan_el_sujeto() {
        let objetivo = Objetivo {
            host: "dc01".into(),
            sujeto: "krbtgt".into(),
        };
        let p = parametros_de(AccionRemediacion::RevocarTicketsKerberos, &objetivo);
        assert_eq!(p["sujeto"], "krbtgt");
        assert_eq!(p["accion"], "revocar_tickets_kerberos");
    }

    #[tokio::test]
    async fn un_golden_ticket_dispara_el_playbook_completo_en_la_flota() {
        let bus = BusEventos::nuevo();
        let mut rx = bus.suscribir();
        let doble = EjecutorDoble::nuevo();
        let registro = doble.registro();

        let respondedor =
            RespondedorItdr::nuevo(MotorItdr::nuevo(), Orquestador::nuevo(), bus, doble);
        let informes = respondedor
            .procesar(&telemetria_golden(), "dc01.corp.local")
            .await
            .expect("procesar");

        // Se lanzo exactamente un playbook (el del Golden Ticket), completo.
        assert_eq!(informes.len(), 1);
        assert_eq!(informes[0].estado, EstadoPlaybook::Completado);

        // El doble de la flota recibio las CUATRO acciones del Golden, todas
        // dirigidas al endpoint de origen.
        let llamadas = registro.lock().unwrap();
        assert_eq!(llamadas.len(), 4);
        assert!(llamadas.iter().all(|(h, _)| h == "dc01.corp.local"));
        let acciones: std::collections::HashSet<_> = llamadas.iter().map(|(_, a)| *a).collect();
        assert!(acciones.contains(&AccionRemediacion::AislarRed));
        assert!(acciones.contains(&AccionRemediacion::MatarProcesosSospechosos));
        assert!(acciones.contains(&AccionRemediacion::RevocarTicketsKerberos));
        assert!(acciones.contains(&AccionRemediacion::VolcadoForenseMemoria));

        // Y el panel vio tanto la alerta como el evento de remediacion automatica.
        let mut vistos = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            vistos.push(ev);
        }
        assert!(vistos
            .iter()
            .any(|e| matches!(e, EventoPanel::AlertaNueva { .. })));
        assert!(vistos
            .iter()
            .any(|e| matches!(e, EventoPanel::RemediacionAutomatica { .. })));
    }

    #[tokio::test]
    async fn una_telemetria_benigna_no_toca_la_flota() {
        // Un lote vacio no produce detecciones: ni alertas ni remediacion.
        let bus = BusEventos::nuevo();
        let doble = EjecutorDoble::nuevo();
        let registro = doble.registro();
        let respondedor =
            RespondedorItdr::nuevo(MotorItdr::nuevo(), Orquestador::nuevo(), bus, doble);

        let informes = respondedor
            .procesar(&TelemetriaIdentidad::default(), "dc01")
            .await
            .expect("procesar");
        assert!(informes.is_empty());
        assert!(registro.lock().unwrap().is_empty());
    }
}
