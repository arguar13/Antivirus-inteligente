//! # `aegis-orchestrator` — AegisOrchestrator (AI-RO): remediacion automatica de
//! flota (FASE 64)
//!
//! ## De la deteccion a la respuesta, en segundos y sin manos
//!
//! Detectar un ataque de identidad grave —un **Golden Ticket**, la prueba de que
//! alguien forjo un TGT y controla el dominio— y esperar a que un humano lea la
//! alerta y reaccione es regalar minutos al atacante. El Control Plane tiene la
//! vista de toda la flota; puede responder solo. AegisOrchestrator es esa
//! respuesta: una **maquina de estados transaccional** que, ante una deteccion
//! critica, lanza un **playbook** de acciones sobre el endpoint afectado.
//!
//! Ante un Golden Ticket, el playbook son cuatro acciones **en paralelo**:
//!
//! - **A. Aislar la red** del endpoint (por XDP): cortarle el oxigeno al atacante.
//! - **B. Matar los procesos sospechosos** asociados.
//! - **C. Revocar los tickets Kerberos anomalos** de la identidad implicada.
//! - **D. Volcado forense de memoria** para la investigacion posterior.
//!
//! ## Transaccional y resiliente a fallos parciales
//!
//! Un agente puede estar caido, una red particionada, un volcado fallar por
//! espacio. La orquestacion **no se rinde a la primera**: lanza todas las
//! acciones, deja que cada una triunfe o falle por su cuenta, y compone un
//! **informe** con el estado exacto de cada una. Un fallo en una accion no aborta
//! las demas —aislar la red no depende de que el volcado forense funcione—.
//!
//! Y es **idempotente en el reintento**: [`Orquestador::reintentar`] re-ejecuta
//! SOLO las acciones que fallaron, nunca las que ya tuvieron exito. Reintentar un
//! aislamiento ya hecho es, en el mejor caso, ruido; en el peor, dispara efectos
//! colaterales. La maquina de estados recuerda lo conseguido.
//!
//! ## Honestidad de validacion
//!
//! Lo que puede estar MAL de forma peligrosa es la MAQUINA DE ESTADOS: elegir el
//! playbook correcto, lanzar todo en paralelo, sobrevivir a fallos parciales, no
//! repetir lo ya hecho y terminar en un estado consistente. Eso se prueba entero,
//! con la frontera de ejecucion ([`EjecutorRemediacion`]) representada por un
//! doble controlable —que registra que se le pidio y devuelve exito o fallo a
//! voluntad—: no es un mock de la logica, es el sustituto de los agentes, que es
//! justo el muro. La ejecucion REAL de cada accion (programar el XDP en el kernel
//! del endpoint, matar un proceso, revocar un ticket en la KDC, volcar la RAM)
//! ocurre en el agente, contra un sistema real, y NO se ejercita aqui: se declara.

use aegis_itdr::{ClaseAmenaza, Deteccion, Severidad};

pub mod orquestador;
pub use orquestador::Orquestador;

/// El disparador de una remediacion: los datos esenciales de una deteccion
/// critica. Es un tipo propio (y no la [`Deteccion`] de `aegis-itdr` directamente)
/// para desacoplar el orquestador del motor: la evidencia legible de la deteccion
/// no le hace falta a la maquina de estados, y asi el disparador se construye sin
/// depender de los constructores internos del motor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disparador {
    /// La familia de amenaza (decide el playbook).
    pub clase: ClaseAmenaza,
    /// La gravedad (decide si se remedia).
    pub severidad: Severidad,
    /// La cuenta o identidad implicada.
    pub sujeto: String,
}

impl From<&Deteccion> for Disparador {
    fn from(d: &Deteccion) -> Self {
        Self {
            clase: d.clase,
            severidad: d.severidad,
            sujeto: d.sujeto.clone(),
        }
    }
}

/// Una accion de remediacion que el Control Plane ordena sobre un endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccionRemediacion {
    /// (A) Aislar la red del endpoint con un filtro XDP: se descarta todo el
    /// trafico salvo el canal seguro con el Control Plane.
    AislarRed,
    /// (B) Terminar los procesos sospechosos asociados a la amenaza.
    MatarProcesosSospechosos,
    /// (C) Revocar los tickets Kerberos anomalos de la identidad implicada.
    RevocarTicketsKerberos,
    /// (D) Volcar la memoria del endpoint para el analisis forense.
    VolcadoForenseMemoria,
}

impl AccionRemediacion {
    /// Descripcion legible de la accion, para el informe del analista.
    #[must_use]
    pub const fn descripcion(self) -> &'static str {
        match self {
            AccionRemediacion::AislarRed => "aislar la red del endpoint (XDP)",
            AccionRemediacion::MatarProcesosSospechosos => "matar los procesos sospechosos",
            AccionRemediacion::RevocarTicketsKerberos => "revocar los tickets Kerberos anomalos",
            AccionRemediacion::VolcadoForenseMemoria => "volcado forense de memoria",
        }
    }
}

/// El objetivo de la remediacion: sobre que endpoint y que identidad se actua.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Objetivo {
    /// El endpoint afectado (el host donde se uso el ticket forjado, etc.).
    pub host: String,
    /// La cuenta o identidad implicada (el `sujeto` de la deteccion).
    pub sujeto: String,
}

/// El estado terminal de una accion tras intentarse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EstadoAccion {
    /// La accion se completo con exito.
    Exito,
    /// La accion fallo, con el motivo (para el informe y el reintento).
    Fallo(String),
}

/// El resultado de una accion del playbook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultadoAccion {
    /// Que accion.
    pub accion: AccionRemediacion,
    /// Como acabo.
    pub estado: EstadoAccion,
}

impl ResultadoAccion {
    /// `true` si la accion tuvo exito.
    #[must_use]
    pub fn exito(&self) -> bool {
        matches!(self.estado, EstadoAccion::Exito)
    }
}

/// El estado global de la ejecucion de un playbook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EstadoPlaybook {
    /// La deteccion no requeria remediacion automatica (no es critica).
    NoAplica,
    /// Todas las acciones del playbook tuvieron exito.
    Completado,
    /// Se intentaron todas, pero alguna fallo (resiliencia a fallo parcial).
    CompletadoConFallos,
}

/// El informe transaccional de una remediacion: sobre que se actuo, que se hizo y
/// como acabo cada accion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InformeRemediacion {
    /// La familia de amenaza que disparo la remediacion.
    pub clase: ClaseAmenaza,
    /// El objetivo sobre el que se actuo.
    pub objetivo: Objetivo,
    /// El resultado de cada accion, en el orden del playbook.
    pub resultados: Vec<ResultadoAccion>,
    /// El estado global.
    pub estado: EstadoPlaybook,
}

impl InformeRemediacion {
    /// Las acciones que fallaron (las candidatas a un reintento).
    #[must_use]
    pub fn acciones_fallidas(&self) -> Vec<AccionRemediacion> {
        self.resultados
            .iter()
            .filter(|r| !r.exito())
            .map(|r| r.accion)
            .collect()
    }

    /// `true` si todo el playbook se completo sin fallos.
    #[must_use]
    pub fn todo_ok(&self) -> bool {
        self.estado == EstadoPlaybook::Completado
    }
}

/// La frontera con los agentes: quien EJECUTA de verdad una accion de remediacion
/// sobre un endpoint. Es asincrono porque cada accion es una orden a la flota que
/// viaja por la red.
///
/// En produccion, la implementacion habla con el agente por el canal gRPC/mTLS y
/// programa el XDP, mata el proceso, revoca el ticket o dispara el volcado. En las
/// pruebas, un doble controlable ocupa su lugar: asi la MAQUINA DE ESTADOS se
/// prueba de verdad y la ejecucion real queda declarada como el muro.
#[async_trait::async_trait]
pub trait EjecutorRemediacion {
    /// Ejecuta `accion` sobre `objetivo`. `Ok(())` si se logro; `Err(motivo)` si
    /// no (y la orquestacion sigue con las demas: un fallo no aborta el playbook).
    async fn ejecutar(&self, accion: AccionRemediacion, objetivo: &Objetivo) -> Result<(), String>;
}
