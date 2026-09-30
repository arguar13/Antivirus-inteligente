//! # aegis-ml
//!
//! Analisis estatico de binarios e inferencia local.
//!
//! Extrae 256 caracteristicas estructurales de un PE o un ELF **sin
//! ejecutarlo** y las pasa por un modelo ONNX residente. Las caracteristicas
//! son estructurales y no bytes crudos a proposito: un modelo sobre bytes se
//! evade anadiendo relleno al final del fichero, sin tocar una sola
//! instruccion, mientras que uno sobre la estructura obliga a modificar el
//! binario de verdad.

// SEGURIDAD DE MEMORIA IMPUESTA POR EL COMPILADOR (FASE 80).
//
// Este crate no necesita `unsafe`, asi que lo prohibe. No es una declaracion de
// intenciones: `forbid` no se puede levantar desde dentro ni con un `allow`, asi
// que el dia que alguien optimice un bucle con un puntero crudo, no compila.
//
// La invariante del producto no admite tercera opcion: todo crate del agente O
// declara esto, O esta en `tools/lineabase-unsafe.txt` con su razon escrita. Un
// crate que se cuele sin ninguna de las dos hace fallar
// `tools/verificar-invariantes.sh`.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod entropy;
pub mod features;
pub mod model;

pub use features::{BinaryFeatures, BinaryFormat, FeatureExtractor, SectionInfo, FEATURE_DIM};
pub use model::{MalwareModel, ModelError, Prediction, Thresholds, Verdict};

/// Modelo empotrado en el binario.
///
/// Va empotrado y no como fichero suelto por la misma razon que el objeto eBPF
/// y las reglas YARA: un `.onnx` junto al binario es algo que un atacante con
/// permisos de escritura puede sustituir, y el agente lo cargaria sin saberlo.
/// Un modelo decide si algo se bloquea; cambiarlo equivale a cambiar el agente.
pub const EMBEDDED_MODEL: &[u8] = include_bytes!("../models/aegis-static-v1.onnx");

/// Si el modelo empotrado es la LINEA BASE DE REFERENCIA y no un modelo
/// entrenado.
///
/// Lo es: una regresion logistica con pesos fijados a mano a partir de
/// heuristicas (`tools/build_model.py`), que existe para que la inferencia sea
/// real de extremo a extremo. Sus puntuaciones son explicables pero NO son
/// evidencia: sin corpus no hay calibracion, y el primer dia en el agente acuso
/// de sospechosos a `python3` y a `git` (FASE 1 del MP-16). Mientras esto sea
/// cierto, quien lo use publica la puntuacion como no concluyente. El modelo
/// entrenado —y el paso a acusar, gobernado por los falsos positivos medidos—
/// es la FASE 4.
pub const EMBEDDED_MODEL_ES_REFERENCIA: bool = true;
