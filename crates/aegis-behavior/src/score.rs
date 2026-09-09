//! Puntuacion de riesgo de un proceso, sobre 100.
//!
//! # Las tres partes y por que estan separadas
//!
//! - **Propia**: lo que el proceso hizo con sus manos.
//! - **Heredada**: lo que hizo quien lo causo, atenuado por la distancia y por
//!   la fuerza de la relacion. Un `sh` lanzado por un servidor web arrastra el
//!   riesgo del servidor; un proceso INYECTADO por otro arrastra casi todo el
//!   suyo, porque nadie inyecta codigo en otro proceso por accidente.
//! - **De cadena**: lo que aporta la FORMA de la secuencia, que no es la suma
//!   de sus partes.
//!
//! Van separadas en el informe a proposito: un analista que ve un 90 necesita
//! saber si viene de lo que el proceso hizo o de quien lo lanzo, porque la
//! respuesta correcta no es la misma.
//!
//! # Por que la suma propia decae
//!
//! Sumando pesos a pelo, diez tecnicas de peso 10 —todas ubicuas y todas
//! legitimas— darian 100 y aislarian un proceso normal. La suma se ordena de
//! mayor a menor y cada sumando siguiente vale un 60% del anterior: la tecnica
//! mas grave manda, y acumular ruido no lleva al umbral.

use aegis_scal::process::ProcessKey;

use crate::chain::ChainPattern;
use crate::dag::BehaviorGraph;
use crate::technique::Technique;

/// Factor de decaimiento de los sumandos de la puntuacion propia.
pub const DECAIMIENTO: f32 = 0.6;

/// Accion que el motor recomienda para un proceso.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Action {
    /// Nada que hacer: se sigue observando.
    Observe,
    /// Merece una alerta para un analista, no una accion automatica.
    Alert,
    /// Se aisla automaticamente.
    Isolate,
}

/// Umbral por encima del cual se aisla sin intervencion humana.
///
/// Es 85 y no 100 porque exigir la certeza absoluta significa no contener
/// nunca; y no es 50 porque una accion automatica sobre un falso positivo saca
/// de produccion algo que funcionaba. La franja intermedia va a un analista.
pub const UMBRAL_AISLAMIENTO: u8 = 85;

/// Umbral a partir del cual se alerta.
pub const UMBRAL_ALERTA: u8 = 40;

/// Puntuacion desglosada de un proceso.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskScore {
    /// Total, acotado a 100.
    pub total: u8,
    /// Parte que viene de lo que hizo el propio proceso.
    pub own: u8,
    /// Parte heredada de sus causas.
    pub inherited: u8,
    /// Parte que aporta la forma de la cadena.
    pub chain: u8,
    /// Tecnicas observadas sobre el propio proceso, de mayor peso a menor.
    pub techniques: Vec<Technique>,
    /// Nombres de las cadenas que casaron.
    pub chains: Vec<&'static str>,
}

impl RiskScore {
    /// Accion recomendada segun el total.
    pub fn action(&self) -> Action {
        if self.total > UMBRAL_AISLAMIENTO {
            Action::Isolate
        } else if self.total >= UMBRAL_ALERTA {
            Action::Alert
        } else {
            Action::Observe
        }
    }
}

/// Suma con decaimiento de una lista de pesos.
///
/// Se ordena de mayor a menor: el resultado no puede depender del orden en que
/// se observaron las tecnicas, o la misma actividad puntuaria distinto segun el
/// momento en que llego cada evento.
pub fn suma_decaida(mut pesos: Vec<u8>) -> f32 {
    pesos.sort_unstable_by(|a, b| b.cmp(a));
    let mut total = 0.0f32;
    let mut factor = 1.0f32;
    for p in pesos {
        total += p as f32 * factor;
        factor *= DECAIMIENTO;
    }
    total
}

/// Puntuacion propia de un nodo: solo lo que hizo el.
pub fn own_score(g: &BehaviorGraph, key: ProcessKey) -> f32 {
    let Some(n) = g.node(key) else { return 0.0 };
    suma_decaida(n.techniques.keys().map(|t| t.weight()).collect())
}

/// Puntuacion heredada de las causas de un nodo.
///
/// Se toma el MAXIMO de los ancestros atenuados, no la suma: si se sumaran, una
/// cadena larga de procesos inocuos acabaria superando el umbral solo por ser
/// larga, que es lo contrario de lo que se quiere medir.
pub fn inherited_score(g: &BehaviorGraph, key: ProcessKey) -> f32 {
    let camino = g.causal_path(key);
    // `camino` va de la raiz al nodo; se recorre hacia atras acumulando la
    // propagacion de cada arista.
    let mut maximo = 0.0f32;
    let mut factor = 1.0f32;
    for par in camino.windows(2).rev() {
        let (padre, hijo) = (par[0], par[1]);
        let arista = g
            .node(hijo)
            .and_then(|n| n.incoming.iter().find(|e| e.peer == padre))
            .map(|e| e.kind.propagation())
            .unwrap_or(0.0);
        factor *= arista;
        if factor <= 0.0 {
            break;
        }
        let contribucion = own_score(g, padre) * factor;
        if contribucion > maximo {
            maximo = contribucion;
        }
    }
    maximo
}

/// Calcula la puntuacion completa de un nodo.
pub fn score(g: &BehaviorGraph, key: ProcessKey, patrones: &[ChainPattern]) -> RiskScore {
    let own = own_score(g, key);
    let inherited = inherited_score(g, key);

    let casadas = crate::chain::matching(g, key, patrones);
    // Se toma el bono MAYOR, no la suma: dos patrones que describen la misma
    // intrusion desde angulos distintos no son dos intrusiones.
    let chain = casadas.iter().map(|p| p.bonus).max().unwrap_or(0);

    let mut techniques: Vec<Technique> = g
        .node(key)
        .map(|n| n.techniques.keys().copied().collect())
        .unwrap_or_default();
    techniques.sort_unstable_by(|a, b| b.weight().cmp(&a.weight()).then(a.cmp(b)));

    let a_u8 = |v: f32| v.round().clamp(0.0, 100.0) as u8;
    let total = (own + inherited + chain as f32).round().clamp(0.0, 100.0) as u8;

    RiskScore {
        total,
        own: a_u8(own),
        inherited: a_u8(inherited),
        chain,
        techniques,
        chains: casadas.iter().map(|p| p.name).collect(),
    }
}
