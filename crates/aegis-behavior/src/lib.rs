//! # aegis-behavior
//!
//! Motor conductual de AegisCore: grafo dirigido aciclico de procesos, tecnicas
//! de MITRE ATT&CK y puntuacion de riesgo con decision automatica.
//!
//! # Que problema resuelve
//!
//! La deteccion por evento aislado se acabo hace anos. Ninguna de las acciones
//! de una intrusion moderna es, por si sola, distinguible de trabajo legitimo:
//! un servidor lanza procesos, un interprete se ejecuta, alguien descarga un
//! fichero, alguien le da permisos de ejecucion. Lo que delata al ataque es la
//! **secuencia**, y para ver secuencias hace falta memoria estructurada de lo
//! que ha pasado.
//!
//! Este motor la mantiene: un grafo donde los nodos son procesos —identificados
//! por [`aegis_scal::ProcessKey`], que sobrevive al reciclado de PID— y las
//! aristas son relaciones de causa: quien lanzo a quien, quien inyecto en
//! quien, quien escribio lo que otro ejecuta.
//!
//! # Las tres decisiones de diseno que lo hacen util
//!
//! 1. **Es un DAG, no un arbol.** Inyectar codigo en otro proceso existe
//!    precisamente para romper el linaje. Modelar esa arista es lo que permite
//!    seguir atribuyendo la actividad a quien la origino. Y como eso puede
//!    cerrar ciclos, [`dag::BehaviorGraph::link`] los rechaza explicitamente en
//!    vez de confiar en que no ocurran.
//! 2. **Los pesos discriminan, no describen.** Un `bash` es T1059 y ocurre
//!    cientos de veces al dia en cualquier servidor; pesa 15. Cifrar ficheros
//!    del usuario pesa 60. Ninguna tecnica llega sola al umbral de aislamiento,
//!    porque una sola observacion siempre puede ser un falso positivo.
//! 3. **La cadena vale mas que la suma.** Servidor -> interprete -> descarga ->
//!    permisos -> ejecucion desde `/tmp` es un compromiso por ejecucion remota
//!    de codigo, y se puntua como tal aunque cada paso por separado sea
//!    defendible.
//!
//! # Independiente del sistema operativo
//!
//! El motor solo habla el vocabulario de [`aegis_scal`]. No sabe que existe
//! `/proc`, ni ETW, ni EndpointSecurity: recibe [`aegis_scal::ProcessEvent`] y
//! observaciones de tecnica, venga quien las traiga. Es lo que permite que la
//! parte del producto que mas valor tiene se compile igual en los tres sistemas.

#![deny(missing_docs)]

pub mod chain;
pub mod dag;
pub mod engine;
pub mod score;
pub mod technique;

pub use chain::{ChainPattern, Step, PATRONES};
pub use dag::{BehaviorGraph, Edge, EdgeKind, GraphError, GraphLimits, Node};
pub use engine::{Assessment, BehavioralGraphEngine, EngineConfig, EngineStats};
pub use score::{Action, RiskScore, UMBRAL_AISLAMIENTO, UMBRAL_ALERTA};
pub use technique::{Tactic, Technique, CATALOGO};
