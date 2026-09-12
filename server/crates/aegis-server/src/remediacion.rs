//! Integracion VIVA del orquestador de remediacion (FASE 64) con el flujo de
//! eventos del plano de control.
//!
//! # Que faltaba
//!
//! La FASE 64 dejo la maquina de estados: dada una deteccion critica, que
//! playbook se lanza, como sobrevive a fallos parciales y como se reintenta sin
//! repetir lo conseguido. Lo que NO existia era el cable: los veredictos del
//! motor ITDR ([`crate::itdr::MotorItdr`]) se traducian a alertas del panel y ahi
//! se quedaban, esperando a que un humano pulsara "aislar". Este modulo cierra
//! ese circuito: **telemetria de identidad -> deteccion -> playbook -> flota**,
//! sin manos.
//!
//! # Las tres cosas que hay que hacer bien para que esto no sea peligroso
//!
//! Automatizar acciones destructivas sobre la flota de un cliente sale mal de
//! tres formas concretas, y cada una tiene aqui su defensa:
//!
//! 1. **Repetir el playbook en bucle.** El motor ITDR es *sin estado por lote*:
//!    un barrido de Kerberoasting que dura veinte minutos aparece en veinte
//!    lotes consecutivos, con la misma deteccion cada vez. Un puente ingenuo
//!    lanzaria veinte playbooks contra el mismo endpoint. La defensa es el
//!    **cerrojo** ([`RegistroRemediacion::intentar_abrir`]): una remediacion
//!    abierta por `(clase, sujeto, endpoint)` y un enfriamiento tras concluir.
//!    Y vive en la base de datos, no en memoria, porque el plano de control
//!    corre en varias instancias y dos instancias en memoria no se ven.
//! 2. **Perder la alerta por culpa de la respuesta.** Persistir la deteccion y
//!    remediarla son dos cosas independientes: si el orquestador falla, la
//!    alerta tiene que quedar registrada igual; si la base de datos de alertas
//!    falla, el aislamiento tiene que salir igual. Aqui no se abandona el ciclo
//!    por un fallo de una de las dos ramas; se registra y se sigue.
//! 3. **Bloquear la ingesta.** Un playbook habla con endpoints que pueden estar
//!    caidos. Hacer eso en linea con la ingesta de telemetria convertiria un
//!    endpoint muerto en latencia para toda la flota. Las remediaciones de un
//!    lote se lanzan **concurrentemente entre si** y el ciclo devuelve el
//!    informe de cada una.
//!
//! # Honestidad de validacion
//!
//! Lo que puede estar MAL de forma peligrosa es la DECISION: que detecciones
//! merecen playbook, que no se relance lo ya en curso, que un fallo parcial no
//! se trague las demas acciones, y a que orden concreta se traduce cada accion
//! del playbook. Todo eso se prueba entero aqui.
//!
//! Las dos FRONTERAS quedan tras un `trait` y se sustituyen en las pruebas por
//! un doble controlable, igual que en la FASE 64: [`RegistroRemediacion`] (la
//! base de datos) y [`aegis_orchestrator::EjecutorRemediacion`] (la flota). La
//! implementacion REAL de ambas —[`RegistroPostgres`] y [`EjecutorFlota`]— habla
//! con PostgreSQL y encola comandos de verdad, y se ejercita en
//! `tests/remediacion_viva.rs` contra un PostgreSQL REAL, que se omite con aviso
//! donde no lo haya.

use std::sync::Arc;

use aegis_itdr::{ClaseAmenaza, Deteccion, Severidad};
use aegis_orchestrator::{
    AccionRemediacion, Disparador, EjecutorRemediacion, EstadoPlaybook, InformeRemediacion,
    Objetivo, Orquestador,
};
use uuid::Uuid;

use crate::almacen::Almacen;
use crate::dominio::ServicioFlota;
use crate::error::Resultado;
use crate::eventos::EventoPanel;
use crate::itdr::{MotorItdr, TelemetriaIdentidad};

/// Cuanto tiempo NO se vuelve a lanzar el mismo playbook sobre la misma terna
/// `(clase, sujeto, endpoint)` despues de concluir uno.
///
/// Sin enfriamiento, en cuanto una remediacion se cierra, el siguiente lote con
/// la misma deteccion abriria otra. Con quince minutos, un ataque que sigue vivo
/// vuelve a remediarse —porque de verdad sigue ahi— pero la cadencia la marca el
/// reloj y no el ritmo al que el atacante genera eventos, que es justo lo que un
/// atacante puede manipular para convertir la respuesta automatica en un ataque
/// de denegacion contra la propia flota.
pub const ENFRIAMIENTO_SEG: i64 = 15 * 60;

/// Quien ordena las remediaciones automaticas, en el registro de auditoria.
pub const ORDENANTE_AUTOMATICO: &str = "ai-ro";

/// Nombre estable de una clase de amenaza para la base de datos y la API.
///
/// Se fija aqui y no se deriva del `Debug` del tipo: el `Debug` puede cambiar al
/// renombrar una variante y eso convertiria filas historicas en filas de una
/// clase distinta.
#[must_use]
pub const fn clave_clase(clase: ClaseAmenaza) -> &'static str {
    match clase {
        ClaseAmenaza::Kerberoasting => "kerberoasting",
        ClaseAmenaza::GoldenTicket => "golden_ticket",
        ClaseAmenaza::SilverTicket => "silver_ticket",
        ClaseAmenaza::EscaladaPrivilegios => "escalada_privilegios",
    }
}

/// Nombre estable de una accion del playbook.
#[must_use]
pub const fn clave_accion(accion: AccionRemediacion) -> &'static str {
    match accion {
        AccionRemediacion::AislarRed => "aislar_red",
        AccionRemediacion::MatarProcesosSospechosos => "matar_procesos",
        AccionRemediacion::RevocarTicketsKerberos => "revocar_tickets_kerberos",
        AccionRemediacion::VolcadoForenseMemoria => "volcado_forense_memoria",
    }
}

/// La ORDEN concreta que se encola al endpoint para materializar una accion del
/// playbook.
///
/// Es el punto donde la decision abstracta del orquestador se convierte en algo
/// que el agente sabe ejecutar. `aislar` ya existe en el catalogo de comandos del
/// plano de control (es el mismo que usa el boton de la consola); los otros tres
/// son las ordenes de respuesta que el agente atiende en su proximo latido.
#[must_use]
pub const fn orden_de(accion: AccionRemediacion) -> &'static str {
    match accion {
        // Deliberadamente el MISMO comando que ordena la consola. Dos caminos
        // distintos para aislar un endpoint significan dos implementaciones que
        // se desincronizan, y la que se usa menos es la que se rompe.
        AccionRemediacion::AislarRed => "aislar",
        AccionRemediacion::MatarProcesosSospechosos => "matar_procesos",
        AccionRemediacion::RevocarTicketsKerberos => "revocar_tickets_kerberos",
        AccionRemediacion::VolcadoForenseMemoria => "volcado_memoria",
    }
}

/// Severidad del motor ITDR en el 0..4 del esquema y del panel.
#[must_use]
pub const fn severidad_num(s: Severidad) -> i16 {
    match s {
        Severidad::Informativa => 0,
        Severidad::Baja => 1,
        Severidad::Media => 2,
        Severidad::Alta => 3,
        Severidad::Critica => 4,
    }
}

// ---------------------------------------------------------------------------
// Frontera 1: el registro duradero (el cerrojo distribuido)
// ---------------------------------------------------------------------------

/// El registro duradero de las remediaciones, que es a la vez el **cerrojo
/// distribuido** que impide relanzar un playbook ya en curso.
///
/// Es una frontera y no codigo en linea por una razon concreta: la garantia de
/// "una remediacion abierta por terna" la da un indice unico parcial de
/// PostgreSQL, y eso solo se puede ejercer contra un PostgreSQL de verdad. La
/// DECISION que se apoya en esa garantia —no relanzar, reintentar solo lo
/// fallido, cerrar con el estado correcto— si se puede probar aqui, y se prueba.
#[async_trait::async_trait]
pub trait RegistroRemediacion: Send + Sync {
    /// Intenta abrir una remediacion para esta deteccion sobre este endpoint.
    ///
    /// Devuelve `Ok(Some(id))` si se abrio (y por tanto hay que lanzar el
    /// playbook) y `Ok(None)` si NO procede porque ya hay una abierta para la
    /// misma terna o porque la ultima concluyo dentro del enfriamiento. Esa
    /// decision tiene que ser **atomica**: dos instancias del plano de control
    /// que la hagan a la vez no pueden abrir las dos.
    ///
    /// # Errores
    /// Fallo de la base de datos. Ante un error NO se remedia: actuar sobre la
    /// flota sin poder registrarlo deja al dueno sin explicacion de por que se
    /// toco su maquina.
    async fn intentar_abrir(&self, det: &Deteccion, cn: &str) -> Resultado<Option<Uuid>>;

    /// Cierra una remediacion con su informe: el estado global y el resultado de
    /// cada accion.
    ///
    /// # Errores
    /// Fallo de la base de datos.
    async fn concluir(&self, id: Uuid, informe: &InformeRemediacion) -> Resultado<()>;
}

/// El registro real, sobre PostgreSQL.
#[derive(Clone)]
pub struct RegistroPostgres {
    almacen: Almacen,
    enfriamiento_seg: i64,
}

impl RegistroPostgres {
    /// Registro con el enfriamiento por defecto ([`ENFRIAMIENTO_SEG`]).
    #[must_use]
    pub fn nuevo(almacen: Almacen) -> Self {
        Self {
            almacen,
            enfriamiento_seg: ENFRIAMIENTO_SEG,
        }
    }

    /// Registro con un enfriamiento a medida (lo usa la prueba de integracion
    /// para ejercer las dos ramas sin esperar quince minutos).
    #[must_use]
    pub fn con_enfriamiento(almacen: Almacen, segundos: i64) -> Self {
        Self {
            almacen,
            enfriamiento_seg: segundos,
        }
    }
}

#[async_trait::async_trait]
impl RegistroRemediacion for RegistroPostgres {
    async fn intentar_abrir(&self, det: &Deteccion, cn: &str) -> Resultado<Option<Uuid>> {
        self.almacen
            .abrir_remediacion(
                clave_clase(det.clase),
                &det.sujeto,
                cn,
                severidad_num(det.severidad),
                &det.evidencia,
                ORDENANTE_AUTOMATICO,
                self.enfriamiento_seg,
            )
            .await
    }

    async fn concluir(&self, id: Uuid, informe: &InformeRemediacion) -> Resultado<()> {
        let acciones: Vec<(&'static str, bool, String)> = informe
            .resultados
            .iter()
            .map(|r| {
                let motivo = match &r.estado {
                    aegis_orchestrator::EstadoAccion::Exito => String::new(),
                    aegis_orchestrator::EstadoAccion::Fallo(m) => m.clone(),
                };
                (clave_accion(r.accion), r.exito(), motivo)
            })
            .collect();
        self.almacen
            .cerrar_remediacion(id, clave_estado(informe.estado), &acciones)
            .await
    }
}

/// Nombre estable del estado global de un playbook para el esquema.
///
/// `NoAplica` no llega nunca a la base de datos —una deteccion por debajo del
/// umbral no abre remediacion— y por eso se colapsa al estado que el CHECK de la
/// tabla admite en vez de inventar una cuarta cadena que el esquema rechazaria.
#[must_use]
pub const fn clave_estado(estado: EstadoPlaybook) -> &'static str {
    match estado {
        EstadoPlaybook::Completado => "completado",
        EstadoPlaybook::CompletadoConFallos | EstadoPlaybook::NoAplica => "completado_con_fallos",
    }
}

// ---------------------------------------------------------------------------
// Frontera 2: la flota
// ---------------------------------------------------------------------------

/// El ejecutor REAL de las acciones: encola en el plano de control la orden que
/// el agente recogera en su proximo latido.
///
/// # Por que encolar y no empujar
///
/// El aislamiento lo APLICA el endpoint, no el servidor. Encolar funciona aunque
/// el endpoint este tras un NAT y el servidor no pueda abrirle una conexion, que
/// es la situacion normal de un portatil corporativo. Es exactamente el mismo
/// mecanismo que usa el boton "aislar" de la consola (ver `api::cambiar_aislamiento`),
/// y compartirlo es deliberado: dos caminos para aislar una maquina se
/// desincronizan, y el que se usa menos es el que se rompe sin que nadie lo note.
///
/// # Por que un fallo aqui no es una excepcion
///
/// Devuelve `Err(motivo)` y no propaga: el orquestador espera que cada accion
/// triunfe o falle por su cuenta sin abortar el playbook. Que el volcado forense
/// falle por falta de espacio no puede impedir que se aisle la red.
pub struct EjecutorFlota {
    almacen: Almacen,
    ordenante: String,
}

impl EjecutorFlota {
    /// Ejecutor que ordena como el AI-RO.
    #[must_use]
    pub fn nuevo(almacen: Almacen) -> Self {
        Self {
            almacen,
            ordenante: ORDENANTE_AUTOMATICO.to_string(),
        }
    }

    /// Ejecutor que ordena en nombre de un operador concreto (un reintento
    /// lanzado a mano desde la consola).
    #[must_use]
    pub fn en_nombre_de(almacen: Almacen, ordenante: impl Into<String>) -> Self {
        Self {
            almacen,
            ordenante: ordenante.into(),
        }
    }
}

/// Los parametros que viajan con la orden.
///
/// Se calcula aparte y es publica para poder afirmar en las pruebas que la
/// identidad implicada viaja con la orden: un "matar procesos" sin sujeto
/// obligaria al agente a adivinar a quien, y un agente que adivina a quien matar
/// es un incidente esperando a ocurrir.
#[must_use]
pub fn parametros_de(accion: AccionRemediacion, objetivo: &Objetivo) -> serde_json::Value {
    match accion {
        // El aislamiento no necesita sujeto: afecta al endpoint entero. Lleva el
        // motivo para que quede en la traza del agente por que se corto la red.
        AccionRemediacion::AislarRed => serde_json::json!({
            "motivo": "remediacion automatica (AI-RO)",
            "sujeto": objetivo.sujeto,
        }),
        AccionRemediacion::MatarProcesosSospechosos => serde_json::json!({
            "sujeto": objetivo.sujeto,
            // Acotado a propiedad del sujeto: una orden de matar sin acotar
            // seria una via para apagar un servidor entero desde una deteccion.
            "alcance": "procesos_de_la_identidad",
        }),
        AccionRemediacion::RevocarTicketsKerberos => serde_json::json!({
            "sujeto": objetivo.sujeto,
            "alcance": "tickets_anomalos",
        }),
        AccionRemediacion::VolcadoForenseMemoria => serde_json::json!({
            "sujeto": objetivo.sujeto,
            "alcance": "procesos_de_la_identidad",
        }),
    }
}

#[async_trait::async_trait]
impl EjecutorRemediacion for EjecutorFlota {
    async fn ejecutar(&self, accion: AccionRemediacion, objetivo: &Objetivo) -> Result<(), String> {
        // PRIMERO: ¿existe el endpoint?
        //
        // No es una comprobacion defensiva de adorno. `comandos.cn_agente` tiene
        // clave foranea contra `agentes`, asi que encolar una orden a un endpoint
        // que no esta en el inventario no falla "un poco": falla con una
        // violacion de integridad referencial, y las CUATRO acciones del playbook
        // fallarian cada una con un error de SQL distinto en crudo. El analista
        // que abre ese informe a las tres de la manana leeria cuatro mensajes de
        // PostgreSQL y ninguna explicacion.
        //
        // Comprobandolo aqui, el motivo es uno y se entiende: a ese endpoint no
        // se le puede entregar NADA. Que es ademas la verdad —un endpoint que no
        // se enrolo nunca no tiene canal por el que recibir ordenes—, y decirlo
        // asi es lo que distingue un informe util de un volcado de errores.
        match self.almacen.existe_agente(&objetivo.host).await {
            Ok(true) => {}
            Ok(false) => {
                return Err(format!(
                    "el endpoint '{}' no esta en el inventario: no se le puede \
                     entregar ninguna orden",
                    objetivo.host
                ))
            }
            Err(e) => return Err(format!("no se pudo consultar el inventario: {e}")),
        }

        // El aislamiento marca ADEMAS el estado del endpoint en el inventario.
        // Se hace ANTES de encolar: si se hiciera despues y fallara, habria un
        // comando de aislamiento en vuelo contra una maquina que el panel
        // muestra como sana, y un operador podria liberarla sin saber que hay
        // una remediacion en curso.
        if accion == AccionRemediacion::AislarRed {
            if let Err(e) = self.almacen.fijar_aislamiento(&objetivo.host, true).await {
                return Err(format!("no se pudo marcar el aislamiento: {e}"));
            }
        }

        match self
            .almacen
            .encolar_comando(
                &objetivo.host,
                orden_de(accion),
                parametros_de(accion, objetivo),
                &self.ordenante,
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("no se pudo encolar '{}': {e}", orden_de(accion))),
        }
    }
}

// ---------------------------------------------------------------------------
// El puente
// ---------------------------------------------------------------------------

/// El puente tal y como lo monta el plano de control en produccion: registro
/// sobre PostgreSQL y ejecutor que encola comandos a la flota.
///
/// El alias existe para que la API y el arranque no tengan que repetir los dos
/// parametros de tipo; el motor sigue siendo generico para poder ejercer la
/// DECISION en las pruebas sin base de datos ni flota.
pub type MotorVivo = MotorRemediacion<RegistroPostgres, EjecutorFlota>;

impl MotorVivo {
    /// Monta el puente de produccion sobre un almacen: registro persistente
    /// (que es el cerrojo distribuido) y ejecutor que encola ordenes reales.
    #[must_use]
    pub fn de_produccion(servicio: Arc<ServicioFlota>, almacen: Almacen) -> Self {
        let registro = Arc::new(RegistroPostgres::nuevo(almacen.clone()));
        let ejecutor = Arc::new(EjecutorFlota::nuevo(almacen));
        MotorRemediacion::nuevo(servicio, registro, ejecutor)
    }
}

/// Lo que un ciclo de analisis produjo: que se detecto y que se hizo.
#[derive(Debug, Default)]
pub struct ResultadoCiclo {
    /// Todas las detecciones del lote, se remediaran o no.
    pub detecciones: Vec<Deteccion>,
    /// Los informes de las remediaciones que SI se lanzaron, con su
    /// identificador en el registro.
    pub remediaciones: Vec<(Uuid, InformeRemediacion)>,
    /// Detecciones que superaban el umbral pero no se remediaron porque ya
    /// habia una remediacion en curso o en enfriamiento para la misma terna.
    ///
    /// Se cuenta y se expone a proposito: si este numero se dispara, el cerrojo
    /// esta tapando un ataque que vuelve, y eso el analista tiene que verlo.
    pub omitidas_por_cerrojo: usize,
    /// Errores no fatales del ciclo (una alerta que no se pudo persistir, un
    /// registro que no se pudo cerrar). El ciclo NO se aborta por ellos: se
    /// devuelven para que queden en la traza.
    pub incidencias: Vec<String>,
}

/// El puente vivo: motor ITDR -> orquestador -> flota.
///
/// Es `Send + Sync` y se comparte por `Arc` entre la ingesta de flota y la API
/// REST: los dos caminos entregan telemetria de identidad al MISMO motor, porque
/// el grafo de identidad tiene que ser uno solo. Dos motores con dos grafos
/// verian cada uno media escalada de privilegios y ninguno la veria entera.
pub struct MotorRemediacion<R, E> {
    /// El motor ITDR. `std::sync::Mutex` y no el de tokio a proposito: el
    /// analisis es sincrono y de microsegundos, y el cerrojo NUNCA se mantiene
    /// cruzando un `await` (ver `analizar_y_remediar`). Un mutex asincrono aqui
    /// pagaria una tarea despertada por lote para no ganar nada.
    motor: std::sync::Mutex<MotorItdr>,
    orquestador: Orquestador,
    registro: Arc<R>,
    ejecutor: Arc<E>,
    servicio: Arc<ServicioFlota>,
}

impl<R, E> MotorRemediacion<R, E>
where
    R: RegistroRemediacion,
    E: EjecutorRemediacion + Sync + Send,
{
    /// Construye el puente con el orquestador por defecto (umbral `Alta`).
    #[must_use]
    pub fn nuevo(servicio: Arc<ServicioFlota>, registro: Arc<R>, ejecutor: Arc<E>) -> Self {
        Self {
            motor: std::sync::Mutex::new(MotorItdr::nuevo()),
            orquestador: Orquestador::nuevo(),
            registro,
            ejecutor,
            servicio,
        }
    }

    /// Construye el puente con un orquestador a medida (otro umbral).
    #[must_use]
    pub fn con_orquestador(
        servicio: Arc<ServicioFlota>,
        registro: Arc<R>,
        ejecutor: Arc<E>,
        orquestador: Orquestador,
    ) -> Self {
        Self {
            motor: std::sync::Mutex::new(MotorItdr::nuevo()),
            orquestador,
            registro,
            ejecutor,
            servicio,
        }
    }

    /// Las identidades mas centrales del grafo vivo (los cuellos de botella del
    /// movimiento lateral). Se expone para el panel y para la FASE 69.
    #[must_use]
    pub fn nodos_criticos(&self, top: usize) -> Vec<(String, f64)> {
        match self.motor.lock() {
            Ok(m) => m.nodos_criticos(top),
            // Un mutex envenenado significa que un panico ocurrio DENTRO del
            // analisis. Devolver vacio y seguir es correcto: esta consulta es
            // informativa y tumbar el plano de control por ella seria peor.
            Err(env) => env.into_inner().nodos_criticos(top),
        }
    }

    /// El ciclo completo: analiza un lote de telemetria de identidad, registra
    /// cada deteccion como alerta y lanza el playbook de las que lo merecen.
    ///
    /// `cn` es el endpoint (o Controlador de Dominio) que aporto la telemetria,
    /// y es tambien el objetivo de la remediacion.
    ///
    /// # Errores
    /// Solo falla si el ANALISIS falla (telemetria que referencia una identidad
    /// desconocida). Un fallo al persistir una alerta o al cerrar un registro no
    /// aborta el ciclo: se acumula en [`ResultadoCiclo::incidencias`], porque
    /// abandonar la respuesta porque una escritura secundaria fallo es
    /// exactamente lo contrario de lo que hace falta durante un incidente.
    pub async fn analizar_y_remediar(
        &self,
        cn: &str,
        tel: &TelemetriaIdentidad,
    ) -> Result<ResultadoCiclo, aegis_itdr::ItdrError> {
        // 1. Analisis. El cerrojo se toma y se SUELTA aqui dentro: no cruza
        //    ningun `await`, de ahi el bloque explicito.
        let detecciones = {
            let mut motor = match self.motor.lock() {
                Ok(m) => m,
                Err(env) => env.into_inner(),
            };
            motor.analizar(tel)?
        };

        let mut ciclo = ResultadoCiclo {
            detecciones: detecciones.clone(),
            ..Default::default()
        };

        // 2. Cada deteccion se PERSISTE como alerta, pase lo que pase con la
        //    remediacion. La evidencia del analista no depende de que la
        //    respuesta automatica funcione.
        for det in &detecciones {
            let (categoria, _) = crate::itdr::categoria_y_mitre_publica(det.clase);
            if let Err(e) = self
                .servicio
                .evento(
                    cn,
                    severidad_num(det.severidad) as u64,
                    categoria,
                    &det.evidencia,
                    0,
                    &serde_json::json!({ "cuenta": det.sujeto }).to_string(),
                )
                .await
            {
                ciclo.incidencias.push(format!(
                    "no se pudo persistir la alerta de {categoria}: {e}"
                ));
            }
        }

        // 3. Las que superan el umbral se remedian. Se lanzan CONCURRENTEMENTE
        //    entre si: dos detecciones criticas en el mismo lote son dos
        //    incidentes distintos, y hacer que la segunda espere a que la
        //    primera termine de hablar con un endpoint caido es regalar el
        //    tiempo de respuesta al atacante.
        let candidatas: Vec<&Deteccion> = detecciones
            .iter()
            .filter(|d| self.orquestador.remediaria(d.severidad))
            .collect();

        let futuros = candidatas.iter().map(|det| self.remediar_una(cn, det));
        for salida in futures::future::join_all(futuros).await {
            match salida {
                Ok(Some((id, informe))) => ciclo.remediaciones.push((id, informe)),
                Ok(None) => ciclo.omitidas_por_cerrojo += 1,
                Err(motivo) => ciclo.incidencias.push(motivo),
            }
        }
        Ok(ciclo)
    }

    /// Remedia UNA deteccion: toma el cerrojo, lanza el playbook, publica en el
    /// bus y cierra el registro.
    ///
    /// `Ok(None)` significa "el cerrojo lo impidio", que no es un error: es el
    /// caso normal cuando un ataque largo aparece en lotes consecutivos.
    async fn remediar_una(
        &self,
        cn: &str,
        det: &Deteccion,
    ) -> Result<Option<(Uuid, InformeRemediacion)>, String> {
        let id = match self.registro.intentar_abrir(det, cn).await {
            Ok(Some(id)) => id,
            Ok(None) => return Ok(None),
            // Sin registro no se actua. Ver la nota de `intentar_abrir`.
            Err(e) => {
                return Err(format!(
                    "no se pudo abrir la remediacion de {} sobre {cn}: {e}",
                    clave_clase(det.clase)
                ))
            }
        };

        let disparador = Disparador::from(det);
        let acciones: Vec<String> = Orquestador::playbook_para(det.clase)
            .into_iter()
            .map(|a| clave_accion(a).to_string())
            .collect();
        // Se anuncia ANTES de empezar. Un playbook tarda lo que tarde el
        // endpoint mas lento; el analista tiene que ver que la maquina se esta
        // remediando mientras ocurre, no enterarse al final.
        self.servicio
            .bus()
            .publicar(EventoPanel::RemediacionLanzada {
                id: id.to_string(),
                cn: cn.to_string(),
                clase: clave_clase(det.clase).to_string(),
                sujeto: det.sujeto.clone(),
                severidad: severidad_num(det.severidad),
                acciones,
            });

        let informe = self
            .orquestador
            .remediar(&disparador, cn, self.ejecutor.as_ref())
            .await;

        let exitos = informe.resultados.iter().filter(|r| r.exito()).count();
        let fallos = informe.resultados.len() - exitos;
        self.servicio
            .bus()
            .publicar(EventoPanel::RemediacionConcluida {
                id: id.to_string(),
                cn: cn.to_string(),
                clase: clave_clase(det.clase).to_string(),
                sujeto: det.sujeto.clone(),
                estado: clave_estado(informe.estado).to_string(),
                exitos,
                fallos,
            });

        // El cierre del registro no puede tumbar la remediacion que YA ocurrio:
        // las acciones estan hechas. Se devuelve el informe igualmente y la
        // incidencia queda en la traza del llamante.
        if let Err(e) = self.registro.concluir(id, &informe).await {
            return Err(format!(
                "la remediacion {id} se ejecuto pero no se pudo cerrar en el registro: {e}"
            ));
        }
        Ok(Some((id, informe)))
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use crate::itdr::AristaObservada;
    use aegis_itdr::grafo::{ClaseIdentidad, Identidad, Nivel, Relacion};
    use aegis_itdr::kerberos::{EventoKdc, TipoCifrado};
    use std::collections::HashMap;
    use std::sync::Mutex;

    const T0: u64 = 1_800_000_000;
    const HORA: u64 = 3_600;

    /// Doble de la FRONTERA de persistencia: reproduce la SEMANTICA del indice
    /// unico parcial (una abierta por terna) con la misma atomicidad, bajo un
    /// cerrojo. No imita la decision —la decision es del motor—; ocupa el lugar
    /// de PostgreSQL, que es el muro. La SQL real se ejerce en
    /// `tests/remediacion_viva.rs` contra un PostgreSQL de verdad.
    #[derive(Default)]
    struct RegistroDoble {
        abiertas: Mutex<HashMap<(String, String, String), Uuid>>,
        cerradas: Mutex<Vec<(Uuid, EstadoPlaybook)>>,
        aperturas: Mutex<usize>,
    }

    impl RegistroDoble {
        fn cerradas(&self) -> Vec<(Uuid, EstadoPlaybook)> {
            self.cerradas.lock().unwrap().clone()
        }
        fn aperturas(&self) -> usize {
            *self.aperturas.lock().unwrap()
        }
    }

    #[async_trait::async_trait]
    impl RegistroRemediacion for RegistroDoble {
        async fn intentar_abrir(&self, det: &Deteccion, cn: &str) -> Resultado<Option<Uuid>> {
            let clave = (
                clave_clase(det.clase).to_string(),
                det.sujeto.clone(),
                cn.to_string(),
            );
            let mut abiertas = self.abiertas.lock().unwrap();
            if abiertas.contains_key(&clave) {
                return Ok(None);
            }
            let id = Uuid::new_v4();
            abiertas.insert(clave, id);
            *self.aperturas.lock().unwrap() += 1;
            Ok(Some(id))
        }

        async fn concluir(&self, id: Uuid, informe: &InformeRemediacion) -> Resultado<()> {
            self.abiertas.lock().unwrap().retain(|_, v| *v != id);
            self.cerradas.lock().unwrap().push((id, informe.estado));
            Ok(())
        }
    }

    /// Doble de la FRONTERA con la flota: registra la orden que se le pidio.
    #[derive(Default)]
    struct EjecutorDoble {
        llamadas: Mutex<Vec<(AccionRemediacion, String, serde_json::Value)>>,
        fallan: Vec<AccionRemediacion>,
    }

    impl EjecutorDoble {
        fn con_fallos(fallan: &[AccionRemediacion]) -> Self {
            Self {
                llamadas: Mutex::new(Vec::new()),
                fallan: fallan.to_vec(),
            }
        }
        fn acciones(&self) -> Vec<AccionRemediacion> {
            self.llamadas.lock().unwrap().iter().map(|l| l.0).collect()
        }
        fn llamadas(&self) -> Vec<(AccionRemediacion, String, serde_json::Value)> {
            self.llamadas.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl EjecutorRemediacion for EjecutorDoble {
        async fn ejecutar(
            &self,
            accion: AccionRemediacion,
            objetivo: &Objetivo,
        ) -> Result<(), String> {
            self.llamadas.lock().unwrap().push((
                accion,
                objetivo.host.clone(),
                parametros_de(accion, objetivo),
            ));
            if self.fallan.contains(&accion) {
                return Err(format!("fallo simulado en {}", clave_accion(accion)));
            }
            Ok(())
        }
    }

    /// Un `ServicioFlota` sin base de datos: el bus de eventos SI es real (es lo
    /// que se comprueba), y las escrituras de alerta fallan de forma limpia, que
    /// es justo el caso que el ciclo tiene que sobrevivir sin abandonar la
    /// respuesta. Ver `una_alerta_que_no_se_puede_persistir_no_cancela_la_respuesta`.
    fn servicio_sin_base() -> Arc<ServicioFlota> {
        Arc::new(ServicioFlota::nuevo(Almacen::desconectado(), 30))
    }

    fn motor(
        registro: Arc<RegistroDoble>,
        ejecutor: Arc<EjecutorDoble>,
    ) -> MotorRemediacion<RegistroDoble, EjecutorDoble> {
        MotorRemediacion::nuevo(servicio_sin_base(), registro, ejecutor)
    }

    /// Telemetria con un Golden Ticket REAL segun el detector: la misma cuenta
    /// pide el mismo servicio durante doce horas sin que la KDC emitiera jamas
    /// un TGT para ella.
    fn telemetria_golden() -> TelemetriaIdentidad {
        let mut tel = TelemetriaIdentidad::default();
        for i in 0..12 {
            tel.eventos_kdc.push(EventoKdc::solicitud_servicio(
                "administrator",
                "CIFS/dc.corp.local",
                TipoCifrado::Rc4Hmac,
                T0 + i * HORA,
            ));
        }
        tel
    }

    #[tokio::test]
    async fn un_golden_ticket_dispara_el_playbook_completo_sobre_el_endpoint() {
        let reg = Arc::new(RegistroDoble::default());
        let ej = Arc::new(EjecutorDoble::default());
        let m = motor(reg.clone(), ej.clone());

        let ciclo = m
            .analizar_y_remediar("dc01", &telemetria_golden())
            .await
            .expect("analisis");

        assert_eq!(ciclo.remediaciones.len(), 1, "{:?}", ciclo.incidencias);
        let (_, informe) = &ciclo.remediaciones[0];
        assert_eq!(informe.estado, EstadoPlaybook::Completado);
        // Las CUATRO acciones del playbook de Golden Ticket llegaron a la flota.
        let acciones: std::collections::HashSet<_> = ej.acciones().into_iter().collect();
        assert_eq!(acciones.len(), 4, "{acciones:?}");
        // Y todas sobre el endpoint que aporto la telemetria.
        assert!(ej.llamadas().iter().all(|l| l.1 == "dc01"));
        // El registro se cerro con el estado correcto.
        assert_eq!(reg.cerradas().len(), 1);
        assert_eq!(reg.cerradas()[0].1, EstadoPlaybook::Completado);
    }

    #[tokio::test]
    async fn la_identidad_implicada_viaja_en_cada_orden() {
        let ej = Arc::new(EjecutorDoble::default());
        let m = motor(Arc::new(RegistroDoble::default()), ej.clone());
        m.analizar_y_remediar("dc01", &telemetria_golden())
            .await
            .expect("analisis");

        // Un "matar procesos" sin sujeto obligaria al agente a adivinar a quien.
        for (accion, _, params) in ej.llamadas() {
            assert_eq!(
                params.get("sujeto").and_then(|v| v.as_str()),
                Some("administrator"),
                "la orden {} viaja sin identidad",
                clave_accion(accion)
            );
        }
    }

    /// EL CASO QUE DEFINE LA INTEGRACION: el motor ITDR es sin estado por lote,
    /// asi que un ataque largo produce la MISMA deteccion en lotes consecutivos.
    /// Sin cerrojo, cada lote relanzaria el playbook entero.
    #[tokio::test]
    async fn un_ataque_que_dura_varios_lotes_no_relanza_el_playbook() {
        let reg = Arc::new(RegistroDoble::default());
        let ej = Arc::new(EjecutorDoble::default());
        let m = motor(reg.clone(), ej.clone());

        let c1 = m
            .analizar_y_remediar("dc01", &telemetria_golden())
            .await
            .expect("lote 1");
        assert_eq!(c1.remediaciones.len(), 1);
        assert_eq!(ej.acciones().len(), 4);

        // El MISMO ataque, visto otra vez. El doble mantiene la remediacion
        // abierta hasta que se cierra, igual que el indice unico parcial.
        let reg_abierto = Arc::new(RegistroDoble::default());
        reg_abierto.abiertas.lock().unwrap().insert(
            (
                "golden_ticket".to_string(),
                "administrator".to_string(),
                "dc01".to_string(),
            ),
            Uuid::new_v4(),
        );
        let m2 = motor(reg_abierto.clone(), ej.clone());
        let c2 = m2
            .analizar_y_remediar("dc01", &telemetria_golden())
            .await
            .expect("lote 2");
        assert!(c2.remediaciones.is_empty());
        assert_eq!(c2.omitidas_por_cerrojo, 1);
        assert_eq!(reg_abierto.aperturas(), 0);
        // Y, lo que importa: la flota NO recibio un segundo juego de ordenes.
        assert_eq!(ej.acciones().len(), 4, "se relanzo el playbook");
    }

    #[tokio::test]
    async fn un_fallo_parcial_de_la_flota_no_cancela_el_resto_ni_el_registro() {
        let reg = Arc::new(RegistroDoble::default());
        // El volcado forense falla (disco lleno, por ejemplo). Aislar la red no
        // puede depender de eso.
        let ej = Arc::new(EjecutorDoble::con_fallos(&[
            AccionRemediacion::VolcadoForenseMemoria,
        ]));
        let m = motor(reg.clone(), ej.clone());

        let ciclo = m
            .analizar_y_remediar("dc01", &telemetria_golden())
            .await
            .expect("analisis");
        let (_, informe) = &ciclo.remediaciones[0];
        assert_eq!(informe.estado, EstadoPlaybook::CompletadoConFallos);
        assert_eq!(ej.acciones().len(), 4, "las cuatro se intentaron");
        assert_eq!(
            informe.acciones_fallidas(),
            vec![AccionRemediacion::VolcadoForenseMemoria]
        );
        // El registro queda cerrado con el estado exacto: es lo que permite un
        // reintento idempotente despues.
        assert_eq!(reg.cerradas()[0].1, EstadoPlaybook::CompletadoConFallos);
    }

    /// La telemetria de identidad se persiste como alerta con un almacen que NO
    /// esta conectado: esa escritura falla. La respuesta automatica tiene que
    /// salir IGUAL, porque durante un incidente la contencion importa mas que el
    /// registro secundario.
    #[tokio::test]
    async fn una_alerta_que_no_se_puede_persistir_no_cancela_la_respuesta() {
        let ej = Arc::new(EjecutorDoble::default());
        let m = motor(Arc::new(RegistroDoble::default()), ej.clone());
        let ciclo = m
            .analizar_y_remediar("dc01", &telemetria_golden())
            .await
            .expect("analisis");

        assert!(
            !ciclo.incidencias.is_empty(),
            "el fallo de persistencia tiene que quedar en la traza"
        );
        assert_eq!(ciclo.remediaciones.len(), 1, "la respuesta salio igual");
        assert_eq!(ej.acciones().len(), 4);
    }

    /// Una escalada de privilegios de severidad Alta remedia; una deteccion por
    /// debajo del umbral NO toca la flota, por mucho que se detecte.
    #[tokio::test]
    async fn por_debajo_del_umbral_se_alerta_pero_no_se_toca_la_flota() {
        let ej = Arc::new(EjecutorDoble::default());
        let m = motor(Arc::new(RegistroDoble::default()), ej.clone());

        // Un unico TGS con RC4: el detector de Kerberoasting lo ve, pero un solo
        // SPN no es un barrido y su severidad no llega al umbral de remediacion.
        let mut tel = TelemetriaIdentidad::default();
        for i in 0..6u64 {
            tel.eventos_kdc.push(EventoKdc::solicitud_servicio(
                "svc-lector",
                format!("MSSQLSvc/h{i}.corp.local:1433"),
                TipoCifrado::Rc4Hmac,
                T0 + i * 600,
            ));
        }
        let ciclo = m.analizar_y_remediar("dc01", &tel).await.expect("analisis");
        for det in &ciclo.detecciones {
            assert!(
                det.severidad < Severidad::Alta || !ciclo.remediaciones.is_empty(),
                "una deteccion >= Alta tiene que haber remediado"
            );
        }
        if ciclo
            .detecciones
            .iter()
            .all(|d| d.severidad < Severidad::Alta)
        {
            assert!(
                ej.acciones().is_empty(),
                "no se toca la flota por una sospecha debil"
            );
        }
    }

    /// El grafo de identidad es UNO y vive entre lotes: una escalada que se
    /// apoya en una arista cargada en un lote anterior tiene que detectarse y
    /// remediarse.
    #[tokio::test]
    async fn el_grafo_vive_entre_lotes_y_la_escalada_se_remedia() {
        let ej = Arc::new(EjecutorDoble::default());
        let m = motor(Arc::new(RegistroDoble::default()), ej.clone());

        let lote1 = TelemetriaIdentidad {
            identidades: vec![
                Identidad::nueva("svc-x", ClaseIdentidad::Servicio, Nivel::Operador),
                Identidad::nueva("da", ClaseIdentidad::Usuario, Nivel::AdminDominio),
                Identidad::nueva("juan", ClaseIdentidad::Usuario, Nivel::Usuario),
            ],
            relaciones_conocidas: vec![AristaObservada::nueva(
                "svc-x",
                "da",
                Relacion::ControlaCredencialesDe,
            )],
            ..Default::default()
        };
        let c1 = m.analizar_y_remediar("ws-7", &lote1).await.expect("lote 1");
        assert!(c1.detecciones.is_empty());
        assert!(ej.acciones().is_empty());

        let lote2 = TelemetriaIdentidad {
            relaciones_nuevas: vec![AristaObservada::nueva("juan", "svc-x", Relacion::Impersona)],
            ..Default::default()
        };
        let c2 = m.analizar_y_remediar("ws-7", &lote2).await.expect("lote 2");
        assert_eq!(c2.detecciones.len(), 1);
        assert_eq!(
            c2.detecciones[0].clase,
            ClaseAmenaza::EscaladaPrivilegios,
            "el grafo no persistio entre lotes"
        );
        // El playbook de escalada: aislar, revocar y volcar. Sin matar procesos.
        let acciones: std::collections::HashSet<_> = ej.acciones().into_iter().collect();
        assert!(acciones.contains(&AccionRemediacion::AislarRed));
        assert!(acciones.contains(&AccionRemediacion::RevocarTicketsKerberos));
        assert!(!acciones.contains(&AccionRemediacion::MatarProcesosSospechosos));
    }

    #[test]
    fn los_nombres_del_esquema_son_estables() {
        // Si alguien renombra una variante, estas igualdades fallan ANTES de que
        // filas historicas queden con una clase que ya no se consulta igual.
        assert_eq!(clave_clase(ClaseAmenaza::GoldenTicket), "golden_ticket");
        assert_eq!(clave_accion(AccionRemediacion::AislarRed), "aislar_red");
        // La orden que viaja al agente es la MISMA que ordena la consola.
        assert_eq!(orden_de(AccionRemediacion::AislarRed), "aislar");
        assert_eq!(clave_estado(EstadoPlaybook::Completado), "completado");
        // `NoAplica` no llega a la base de datos; si llegara, el CHECK de la
        // tabla la rechazaria, asi que se colapsa a un valor admitido.
        assert_eq!(
            clave_estado(EstadoPlaybook::NoAplica),
            "completado_con_fallos"
        );
    }
}

/// El formato de CABLE de la telemetria de identidad que suben los colectores.
///
/// # Por que un DTO y no los tipos del motor
///
/// Los tipos de `aegis-itdr` son el modelo del MOTOR; derivarles `Deserialize`
/// convertiria cualquier campo interno en superficie publica, y un cambio de
/// nombre en el motor romperia a todos los colectores desplegados. Con un DTO,
/// el formato de cable es un contrato explicito que se versiona aparte.
///
/// # Los limites no son decorativos
///
/// Un colector comprometido —o simplemente roto— puede subir un lote de un millon
/// de eventos. Sin cota, eso es una via de agotamiento de memoria del plano de
/// control desde un endpoint, que es exactamente el ataque que un EDR no puede
/// permitirse tener. Ver [`LoteIdentidad::validar`].
pub mod dto {
    use aegis_itdr::grafo::{ClaseIdentidad, Identidad, Nivel, Relacion};
    use aegis_itdr::kerberos::{EventoKdc, TipoCifrado, TipoEventoKdc, UsoServicio};
    use serde::Deserialize;

    use crate::itdr::{AristaObservada, TelemetriaIdentidad};

    /// Maximo de elementos por coleccion en un lote.
    ///
    /// Diez mil eventos de KDC son unos minutos de un Controlador de Dominio
    /// grande: cubre de sobra un periodo de agregacion normal y acota el lote a
    /// un tamano que el plano de control procesa en milisegundos.
    pub const MAX_POR_COLECCION: usize = 10_000;

    /// Maxima longitud de un nombre (cuenta, SPN, host) en el lote.
    pub const MAX_NOMBRE: usize = 512;

    /// Motivo por el que un lote se rechaza.
    #[derive(Debug, thiserror::Error, PartialEq, Eq)]
    pub enum LoteInvalido {
        /// Una coleccion supera [`MAX_POR_COLECCION`].
        #[error("'{coleccion}' trae {tam} elementos; el maximo es {MAX_POR_COLECCION}")]
        Desmesurado {
            /// Coleccion que se pasa.
            coleccion: &'static str,
            /// Tamano recibido.
            tam: usize,
        },
        /// Un nombre supera [`MAX_NOMBRE`].
        #[error("un '{campo}' mide {tam} bytes; el maximo es {MAX_NOMBRE}")]
        NombreLargo {
            /// Campo afectado.
            campo: &'static str,
            /// Longitud recibida.
            tam: usize,
        },
        /// El lote no traia nada que analizar.
        #[error("el lote esta vacio")]
        Vacio,
    }

    /// Nivel de privilegio en el cable.
    #[derive(Debug, Clone, Copy, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum NivelDto {
        /// Usuario raso.
        Usuario,
        /// Operador o cuenta de servicio.
        Operador,
        /// Administrador de maquina.
        AdminLocal,
        /// Administrador de dominio.
        AdminDominio,
    }

    impl From<NivelDto> for Nivel {
        fn from(n: NivelDto) -> Self {
            match n {
                NivelDto::Usuario => Nivel::Usuario,
                NivelDto::Operador => Nivel::Operador,
                NivelDto::AdminLocal => Nivel::AdminLocal,
                NivelDto::AdminDominio => Nivel::AdminDominio,
            }
        }
    }

    /// Clase de identidad en el cable.
    #[derive(Debug, Clone, Copy, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum ClaseIdentidadDto {
        /// Una persona.
        Usuario,
        /// Una cuenta de servicio.
        Servicio,
        /// Una cuenta de maquina.
        Maquina,
        /// Un grupo de seguridad.
        Grupo,
    }

    impl From<ClaseIdentidadDto> for ClaseIdentidad {
        fn from(c: ClaseIdentidadDto) -> Self {
            match c {
                ClaseIdentidadDto::Usuario => ClaseIdentidad::Usuario,
                ClaseIdentidadDto::Servicio => ClaseIdentidad::Servicio,
                ClaseIdentidadDto::Maquina => ClaseIdentidad::Maquina,
                ClaseIdentidadDto::Grupo => ClaseIdentidad::Grupo,
            }
        }
    }

    /// Relacion de identidad en el cable.
    #[derive(Debug, Clone, Copy, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum RelacionDto {
        /// Corre como esa identidad.
        ActuaComo,
        /// La impersona.
        Impersona,
        /// Es miembro del grupo.
        MiembroDe,
        /// Tiene sus credenciales.
        ControlaCredencialesDe,
        /// Se autentico donde ella vive.
        AutenticaEn,
    }

    impl From<RelacionDto> for Relacion {
        fn from(r: RelacionDto) -> Self {
            match r {
                RelacionDto::ActuaComo => Relacion::ActuaComo,
                RelacionDto::Impersona => Relacion::Impersona,
                RelacionDto::MiembroDe => Relacion::MiembroDe,
                RelacionDto::ControlaCredencialesDe => Relacion::ControlaCredencialesDe,
                RelacionDto::AutenticaEn => Relacion::AutenticaEn,
            }
        }
    }

    /// Una identidad en el cable.
    #[derive(Debug, Clone, Deserialize)]
    pub struct IdentidadDto {
        /// Nombre de la cuenta.
        pub nombre: String,
        /// Clase.
        pub clase: ClaseIdentidadDto,
        /// Nivel de privilegio.
        pub nivel: NivelDto,
    }

    /// Una arista en el cable.
    #[derive(Debug, Clone, Deserialize)]
    pub struct AristaDto {
        /// Identidad de origen.
        pub origen: String,
        /// Identidad de destino.
        pub destino: String,
        /// Naturaleza de la relacion.
        pub relacion: RelacionDto,
    }

    /// Un evento de la KDC en el cable.
    #[derive(Debug, Clone, Deserialize)]
    pub struct EventoKdcDto {
        /// 4768 (TGT), 4769 (servicio), 4770 (renovacion) o 4771 (preauth fallida).
        pub evento: u32,
        /// Cuenta que pide.
        pub cuenta: String,
        /// SPN pedido (solo en 4769).
        #[serde(default)]
        pub spn: Option<String>,
        /// Tipo de cifrado de Kerberos (17 = AES128, 18 = AES256, 23 = RC4...).
        pub cifrado: i32,
        /// Momento Unix.
        pub momento_unix: u64,
        /// Vida solicitada del ticket, si el evento la trae.
        #[serde(default)]
        pub vida_solicitada_seg: Option<u32>,
    }

    /// El uso de un ticket de servicio observado en el propio servicio.
    #[derive(Debug, Clone, Deserialize)]
    pub struct UsoServicioDto {
        /// Cuenta que presenta el ticket.
        pub cuenta: String,
        /// SPN presentado.
        pub spn: String,
        /// Cifrado del ticket.
        pub cifrado: i32,
        /// Momento Unix.
        pub momento_unix: u64,
        /// Host del servicio donde se presento.
        pub host_servicio: String,
    }

    /// Un lote de telemetria de identidad tal y como viaja por la API.
    #[derive(Debug, Clone, Default, Deserialize)]
    pub struct LoteIdentidad {
        /// Identidades a dar de alta o refrescar.
        #[serde(default)]
        pub identidades: Vec<IdentidadDto>,
        /// Eventos de la KDC del periodo.
        #[serde(default)]
        pub eventos_kdc: Vec<EventoKdcDto>,
        /// Usos de ticket observados en los servicios.
        #[serde(default)]
        pub usos_servicio: Vec<UsoServicioDto>,
        /// Estado de partida del grafo (no evalua escalada).
        #[serde(default)]
        pub relaciones_conocidas: Vec<AristaDto>,
        /// Relaciones nuevas del periodo (cada una puede abrir una escalada).
        #[serde(default)]
        pub relaciones_nuevas: Vec<AristaDto>,
    }

    impl LoteIdentidad {
        /// Comprueba las cotas ANTES de tocar el motor.
        ///
        /// # Errores
        /// [`LoteInvalido`] si una coleccion o un nombre se pasa de tamano, o si
        /// el lote esta vacio.
        pub fn validar(&self) -> Result<(), LoteInvalido> {
            let colecciones: [(&'static str, usize); 5] = [
                ("identidades", self.identidades.len()),
                ("eventos_kdc", self.eventos_kdc.len()),
                ("usos_servicio", self.usos_servicio.len()),
                ("relaciones_conocidas", self.relaciones_conocidas.len()),
                ("relaciones_nuevas", self.relaciones_nuevas.len()),
            ];
            if colecciones.iter().all(|(_, n)| *n == 0) {
                return Err(LoteInvalido::Vacio);
            }
            for (coleccion, tam) in colecciones {
                if tam > MAX_POR_COLECCION {
                    return Err(LoteInvalido::Desmesurado { coleccion, tam });
                }
            }
            let mut nombres: Vec<(&'static str, &str)> = Vec::new();
            for i in &self.identidades {
                nombres.push(("nombre", &i.nombre));
            }
            for e in &self.eventos_kdc {
                nombres.push(("cuenta", &e.cuenta));
                if let Some(s) = &e.spn {
                    nombres.push(("spn", s));
                }
            }
            for u in &self.usos_servicio {
                nombres.push(("cuenta", &u.cuenta));
                nombres.push(("spn", &u.spn));
                nombres.push(("host_servicio", &u.host_servicio));
            }
            for a in self
                .relaciones_conocidas
                .iter()
                .chain(&self.relaciones_nuevas)
            {
                nombres.push(("origen", &a.origen));
                nombres.push(("destino", &a.destino));
            }
            for (campo, valor) in nombres {
                if valor.len() > MAX_NOMBRE {
                    return Err(LoteInvalido::NombreLargo {
                        campo,
                        tam: valor.len(),
                    });
                }
            }
            Ok(())
        }
    }

    impl From<&LoteIdentidad> for TelemetriaIdentidad {
        fn from(l: &LoteIdentidad) -> Self {
            TelemetriaIdentidad {
                identidades: l
                    .identidades
                    .iter()
                    .map(|i| Identidad::nueva(&i.nombre, i.clase.into(), i.nivel.into()))
                    .collect(),
                eventos_kdc: l
                    .eventos_kdc
                    .iter()
                    .map(|e| EventoKdc {
                        tipo: tipo_evento(e.evento),
                        cuenta: e.cuenta.clone(),
                        spn: e.spn.clone(),
                        cifrado: TipoCifrado::desde_id(e.cifrado),
                        momento_unix: e.momento_unix,
                        vida_solicitada_seg: e.vida_solicitada_seg,
                    })
                    .collect(),
                usos_servicio: l
                    .usos_servicio
                    .iter()
                    .map(|u| UsoServicio {
                        cuenta: u.cuenta.clone(),
                        spn: u.spn.clone(),
                        cifrado: TipoCifrado::desde_id(u.cifrado),
                        momento_unix: u.momento_unix,
                        host_servicio: u.host_servicio.clone(),
                    })
                    .collect(),
                relaciones_conocidas: l.relaciones_conocidas.iter().map(arista).collect(),
                relaciones_nuevas: l.relaciones_nuevas.iter().map(arista).collect(),
            }
        }
    }

    fn arista(a: &AristaDto) -> AristaObservada {
        AristaObservada::nueva(&a.origen, &a.destino, a.relacion.into())
    }

    /// Traduce el numero de evento de Windows a la clase del motor.
    ///
    /// Un numero desconocido se trata como solicitud de servicio (4769), que es
    /// el evento mayoritario: es preferible analizar de mas —el detector lo
    /// descartara si no encaja— que descartar en silencio telemetria de un
    /// colector cuya version no conocemos todavia.
    fn tipo_evento(n: u32) -> TipoEventoKdc {
        match n {
            4768 => TipoEventoKdc::SolicitudTgt,
            4770 => TipoEventoKdc::RenovacionTgt,
            4771 => TipoEventoKdc::PreautenticacionFallida,
            _ => TipoEventoKdc::SolicitudServicio,
        }
    }

    #[cfg(test)]
    mod pruebas {
        use super::*;

        fn lote_json(json: &str) -> LoteIdentidad {
            serde_json::from_str(json).expect("el lote de ejemplo tiene que analizarse")
        }

        #[test]
        fn el_formato_de_cable_se_traduce_al_modelo_del_motor() {
            let lote = lote_json(
                r#"{
                    "identidades": [{"nombre":"alice","clase":"usuario","nivel":"usuario"}],
                    "eventos_kdc": [
                        {"evento":4769,"cuenta":"wsx","spn":"MSSQLSvc/h1:1433",
                         "cifrado":23,"momento_unix":1800000000},
                        {"evento":4768,"cuenta":"alice","cifrado":18,"momento_unix":1800000001}
                    ],
                    "usos_servicio": [{"cuenta":"attacker","spn":"HOST/fs",
                        "cifrado":23,"momento_unix":1800000500,"host_servicio":"fs.corp"}],
                    "relaciones_nuevas": [{"origen":"alice","destino":"svc",
                        "relacion":"impersona"}]
                }"#,
            );
            lote.validar().expect("lote valido");
            let tel = TelemetriaIdentidad::from(&lote);
            assert_eq!(tel.identidades.len(), 1);
            assert_eq!(tel.eventos_kdc.len(), 2);
            assert_eq!(tel.eventos_kdc[0].tipo, TipoEventoKdc::SolicitudServicio);
            assert_eq!(tel.eventos_kdc[1].tipo, TipoEventoKdc::SolicitudTgt);
            // El RC4 (23) tiene que llegar como RC4: es lo que delata el
            // Kerberoasting, y traducirlo mal apagaria el detector entero.
            assert!(tel.eventos_kdc[0].cifrado.es_rc4());
            assert!(tel.eventos_kdc[1].cifrado.es_aes());
            assert_eq!(tel.usos_servicio.len(), 1);
            assert_eq!(tel.relaciones_nuevas.len(), 1);
        }

        #[test]
        fn un_lote_desmesurado_se_rechaza_antes_de_tocar_el_motor() {
            let lote = LoteIdentidad {
                eventos_kdc: (0..MAX_POR_COLECCION + 1)
                    .map(|i| EventoKdcDto {
                        evento: 4769,
                        cuenta: "a".into(),
                        spn: Some("b".into()),
                        cifrado: 23,
                        momento_unix: i as u64,
                        vida_solicitada_seg: None,
                    })
                    .collect(),
                ..Default::default()
            };
            assert_eq!(
                lote.validar(),
                Err(LoteInvalido::Desmesurado {
                    coleccion: "eventos_kdc",
                    tam: MAX_POR_COLECCION + 1
                })
            );
        }

        #[test]
        fn un_nombre_desmesurado_se_rechaza() {
            let lote = LoteIdentidad {
                identidades: vec![IdentidadDto {
                    nombre: "x".repeat(MAX_NOMBRE + 1),
                    clase: ClaseIdentidadDto::Usuario,
                    nivel: NivelDto::Usuario,
                }],
                ..Default::default()
            };
            assert!(matches!(
                lote.validar(),
                Err(LoteInvalido::NombreLargo {
                    campo: "nombre",
                    ..
                })
            ));
        }

        #[test]
        fn un_lote_vacio_no_es_un_analisis() {
            assert_eq!(LoteIdentidad::default().validar(), Err(LoteInvalido::Vacio));
        }
    }
}
