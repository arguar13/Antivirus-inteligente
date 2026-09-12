//! Errores del motor de prediccion.

use thiserror::Error;

/// Lo que puede salir mal al predecir.
///
/// No deriva `Eq` —y no se fuerza— porque [`ErrorPrediccion::ProbabilidadInvalida`]
/// lleva un `f64`, y el valor que la hace invalida puede ser NaN, que no es igual
/// ni a si mismo. Una igualdad total sobre eso seria una mentira comoda.
#[derive(Debug, Error, PartialEq, Clone)]
pub enum ErrorPrediccion {
    /// Se nombro un activo que no esta en el grafo.
    #[error("activo desconocido: {0}")]
    ActivoDesconocido(String),

    /// El grafo no tiene joyas de la corona declaradas.
    ///
    /// No es un detalle de configuracion: sin saber que hay que proteger, la
    /// criticidad no significa nada y el motor diria cualquier cosa con
    /// aplomo. Es preferible negarse.
    #[error("no hay ningun activo critico declarado: sin eso la criticidad no significa nada")]
    SinJoyasDeLaCorona,

    /// Una probabilidad fuera de (0, 1].
    ///
    /// El cero esta excluido a proposito: `-log 0` es infinito y un camino con
    /// una arista imposible no es un camino, es la ausencia de arista.
    #[error("probabilidad invalida en {arista}: {valor} (tiene que estar en (0, 1])")]
    ProbabilidadInvalida {
        /// Arista implicada.
        arista: String,
        /// Valor visto.
        valor: f64,
    },

    /// Se pidieron mas iteraciones de las que tiene sentido ejecutar.
    #[error("limite excedido en {campo}: {valor} > {tope}")]
    LimiteExcedido {
        /// Que limite.
        campo: &'static str,
        /// Valor pedido.
        valor: usize,
        /// Tope.
        tope: usize,
    },
}
