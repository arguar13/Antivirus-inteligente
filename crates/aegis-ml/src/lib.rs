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
pub mod puerta;
pub mod vector;

pub use features::{BinaryFeatures, BinaryFormat, FeatureExtractor, SectionInfo, FEATURE_DIM};
pub use model::{MalwareModel, ModelError, Prediction, Thresholds, Verdict};
pub use puerta::{modelo_es_referencia, EstadoModelo};
pub use vector::{huella_extractor, vectorizar, VERSION_VECTOR};

/// Modelo empotrado en el binario.
///
/// Va empotrado y no como fichero suelto por la misma razon que el objeto eBPF
/// y las reglas YARA: un `.onnx` junto al binario es algo que un atacante con
/// permisos de escritura puede sustituir, y el agente lo cargaria sin saberlo.
/// Un modelo decide si algo se bloquea; cambiarlo equivale a cambiar el agente.
pub const EMBEDDED_MODEL: &[u8] = include_bytes!("../models/aegis-static-v1.onnx");

// Si el modelo empotrado es de REFERENCIA (su puntuacion no es evidencia) ya
// no lo dice una constante escrita a mano: lo decide la puerta
// (`puerta::estado`, `modelo_es_referencia`) con la tarjeta GENERADA por
// `tools/ml/entrenar.py`, el hash del modelo empotrado, la huella del
// extractor y el FPR objetivo de `tools/config/modelo.toml`. El modelo de
// referencia (pesos a mano, `tools/build_model.py`) no pasa: su tarjeta
// declara `clase = "referencia"` (FASE 4.4 del MP-16).
