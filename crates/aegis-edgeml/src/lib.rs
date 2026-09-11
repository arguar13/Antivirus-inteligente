//! Inferencia TinyML en el borde para detectar zero-day por comportamiento — FASE 53.
//!
//! # Por que en el agente y no en la nube
//!
//! La FASE 45 correlaciona comportamiento en toda la flota desde el plano de
//! control. Eso es potente, pero tiene una latencia y una dependencia: hace falta
//! red, y hace falta que el evento llegue, se agregue y vuelva un veredicto. Un
//! ransomware cifra miles de ficheros en ese viaje de ida y vuelta. Y un endpoint
//! aislado —una fabrica sin salida a internet, un portatil en un avion— no tiene
//! plano de control al que preguntar.
//!
//! Por eso el agente lleva su propio clasificador: un modelo pequeno EMBEBIDO en
//! el binario que, a partir de la secuencia de syscalls y del grafo de procesos,
//! emite un veredicto de aislamiento SIN preguntarle a nadie. No sustituye a la
//! nube; decide en los milisegundos en que la nube todavia no sabe nada.
//!
//! # Que detecta y por su forma, no por su nombre
//!
//! No busca firmas de familias conocidas —eso es lo que un zero-day no tiene—
//! sino la FORMA del comportamiento: una rafaga de leer-cifrar-borrar es
//! ransomware aunque la familia sea nueva; leer la memoria de otro proceso es robo
//! de credenciales lo haga quien lo haga. El modelo ([`modelo`]) es una red con
//! una capa oculta donde cada neurona es un concepto de ataque, con pesos
//! calibrados a mano —no aleatorios— para que su salida sea explicable y sus
//! pruebas tengan contenido.
//!
//! # Todo esto se prueba de verdad aqui
//!
//! No hay muro de hardware en esta fase: el modelo ONNX se carga con tract (Rust
//! puro) y se infiere sobre secuencias de syscalls reales en cada `make ci`. Lo
//! unico que un despliegue de produccion cambia es el modelo —entrenado sobre la
//! telemetria real de la flota— que llega por el canal firmado de `aegis-update`
//! con la misma forma de grafo.

#![forbid(unsafe_code)]

pub mod behavior;
pub mod modelo;

pub use behavior::{extraer, CatSyscall, Dag, EventoSyscall, Traza, DIM};
pub use modelo::{ModeloComportamiento, ModeloError, Prediccion, Veredicto};

/// El modelo de comportamiento empotrado en el binario del agente. Menos de 5 MB
/// (de hecho, unos pocos KB): cabe de sobra en el binario y no necesita fichero
/// externo que un atacante pueda borrar.
pub const MODELO_EMBEBIDO: &[u8] = include_bytes!("../models/aegis-behavior-v1.onnx");
