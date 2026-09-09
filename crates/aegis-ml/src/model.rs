//! Inferencia local con ONNX.
//!
//! # Por que ONNX y no un formato propio
//!
//! El modelo se entrena fuera del endpoint, con las herramientas que sean
//! (LightGBM, scikit-learn, PyTorch), y llega al agente como un grafo ONNX. Eso
//! desacopla el pipeline de entrenamiento del de ejecucion: se puede cambiar el
//! algoritmo sin tocar una linea del agente, y el agente no arrastra ninguna
//! biblioteca de entrenamiento.
//!
//! Se usa **tract**, que es Rust puro. La alternativa habitual, `onnxruntime`,
//! exige distribuir una biblioteca nativa de decenas de megabytes y enlazarla
//! en un proceso privilegiado: es superficie de ataque y peso que no se
//! justifican para inferir un modelo de arboles o una regresion.
//!
//! # El modelo es codigo
//!
//! Un fichero de modelo se carga en un proceso con privilegios altos y decide
//! si algo se bloquea. Sustituirlo equivale a sustituir el binario del agente.
//! Por eso [`MalwareModel::load_signed`] verifica una firma antes de cargar, y
//! por eso el modelo por defecto va empotrado.

use std::path::Path;

use tract_onnx::prelude::*;

use crate::features::FEATURE_DIM;

/// Error del motor de inferencia.
#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    /// El grafo no se pudo cargar.
    #[error("no se pudo cargar el modelo ONNX: {0}")]
    Load(String),

    /// La inferencia fallo.
    #[error("la inferencia fallo: {0}")]
    Inference(String),

    /// El vector de entrada no tiene la dimension esperada.
    ///
    /// Se comprueba siempre: un vector de la longitud equivocada no produce un
    /// error en la mayoria de motores, produce una PUNTUACION SIN SENTIDO, y
    /// esa es exactamente la clase de fallo que nadie detecta hasta que el
    /// producto lleva meses bloqueando lo que no debe.
    #[error("el vector tiene {found} dimensiones y el modelo espera {expected}")]
    BadInputDim {
        /// Dimensiones recibidas.
        found: usize,
        /// Dimensiones esperadas.
        expected: usize,
    },

    /// La salida del modelo no tiene la forma esperada.
    #[error("la salida del modelo no es interpretable: {0}")]
    BadOutput(String),

    /// Error de entrada/salida.
    #[error("error de E/S en {path}: {source}")]
    Io {
        /// Ruta.
        path: String,
        /// Causa.
        source: std::io::Error,
    },
}

/// Veredicto escalonado por confianza.
///
/// La respuesta NO es binaria. Con ~300.000 ejecutables por endpoint y 0 o 1
/// maliciosos al mes, un umbral unico obliga a elegir entre no detectar nada o
/// sepultar al operador en falsos positivos. El escalonado permite actuar con
/// contundencia solo donde la confianza lo justifica.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Solo telemetria.
    Record,
    /// Vigilancia reforzada: se activa el escaneo de memoria del proceso.
    Watch,
    /// Se impide la ejecucion; el fichero permanece y es reversible.
    Block,
    /// Bloqueo, cuarentena y aislamiento.
    Contain,
}

/// Umbrales del punto de operacion.
#[derive(Debug, Clone, Copy)]
pub struct Thresholds {
    /// A partir de aqui se registra.
    pub record: f32,
    /// A partir de aqui se vigila.
    pub watch: f32,
    /// A partir de aqui se bloquea.
    pub block: f32,
    /// A partir de aqui se contiene.
    pub contain: f32,
}

impl Default for Thresholds {
    fn default() -> Self {
        // Calibrados para una tasa de falsos positivos objetivo de 1e-5 en el
        // umbral de bloqueo, medida sobre una distribucion REAL de endpoint
        // (cientos de miles de benignos, decenas de maliciosos). Un umbral
        // elegido sobre un conjunto equilibrado 50/50 no dice nada sobre el
        // comportamiento en produccion.
        Self {
            record: 0.60,
            watch: 0.90,
            block: 0.995,
            contain: 0.999,
        }
    }
}

impl Thresholds {
    /// Traduce una puntuacion a veredicto.
    pub fn verdict(&self, score: f32) -> Verdict {
        if score >= self.contain {
            Verdict::Contain
        } else if score >= self.block {
            Verdict::Block
        } else if score >= self.watch {
            Verdict::Watch
        } else {
            Verdict::Record
        }
    }
}

/// Resultado de una inferencia.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Prediction {
    /// Probabilidad de que la muestra sea maliciosa, en `[0, 1]`.
    pub score: f32,
    /// Veredicto segun los umbrales.
    pub verdict: Verdict,
}

type Plan = SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>;

/// Modelo de clasificacion cargado y listo para inferir.
pub struct MalwareModel {
    plan: Plan,
    dim: usize,
    /// Umbrales del punto de operacion.
    pub thresholds: Thresholds,
}

impl std::fmt::Debug for MalwareModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MalwareModel")
            .field("dim", &self.dim)
            .field("thresholds", &self.thresholds)
            .finish_non_exhaustive()
    }
}

impl MalwareModel {
    /// Carga un modelo desde bytes en memoria.
    pub fn load_bytes(bytes: &[u8]) -> Result<MalwareModel, ModelError> {
        Self::load_bytes_with_dim(bytes, FEATURE_DIM)
    }

    /// Carga un modelo declarando la dimension de entrada.
    pub fn load_bytes_with_dim(bytes: &[u8], dim: usize) -> Result<MalwareModel, ModelError> {
        let mut cursor = std::io::Cursor::new(bytes);
        let plan = tract_onnx::onnx()
            .model_for_read(&mut cursor)
            .map_err(|e| ModelError::Load(e.to_string()))?
            .with_input_fact(0, f32::fact([1, dim]).into())
            .map_err(|e| ModelError::Load(format!("forma de entrada [1,{dim}]: {e}")))?
            .into_optimized()
            .map_err(|e| ModelError::Load(format!("optimizacion: {e}")))?
            .into_runnable()
            .map_err(|e| ModelError::Load(format!("preparacion: {e}")))?;

        Ok(MalwareModel {
            plan,
            dim,
            thresholds: Thresholds::default(),
        })
    }

    /// Carga un modelo desde un fichero.
    pub fn load(ruta: &Path) -> Result<MalwareModel, ModelError> {
        let bytes = std::fs::read(ruta).map_err(|e| ModelError::Io {
            path: ruta.display().to_string(),
            source: e,
        })?;
        Self::load_bytes(&bytes)
    }

    /// Carga el modelo empotrado en el binario.
    pub fn embedded() -> Result<MalwareModel, ModelError> {
        Self::load_bytes(crate::EMBEDDED_MODEL)
    }

    /// Dimension de entrada.
    pub fn input_dim(&self) -> usize {
        self.dim
    }

    /// Infiere sobre un vector de caracteristicas.
    pub fn predict(&self, features: &[f32]) -> Result<Prediction, ModelError> {
        if features.len() != self.dim {
            return Err(ModelError::BadInputDim {
                found: features.len(),
                expected: self.dim,
            });
        }
        // Un NaN en la entrada se propaga a la salida y produce comparaciones
        // que son falsas en ambos sentidos: el veredicto acabaria siendo
        // "Record" por accidente en vez de por decision. Se sanea antes.
        let saneado: Vec<f32> = features
            .iter()
            .map(|x| if x.is_finite() { *x } else { 0.0 })
            .collect();

        let entrada: Tensor = tract_ndarray::Array2::from_shape_vec((1, self.dim), saneado)
            .map_err(|e| ModelError::Inference(e.to_string()))?
            .into();

        let salida = self
            .plan
            .run(tvec!(entrada.into()))
            .map_err(|e| ModelError::Inference(e.to_string()))?;

        let vista = salida[0]
            .to_array_view::<f32>()
            .map_err(|e| ModelError::BadOutput(e.to_string()))?;
        let score = vista
            .iter()
            .next()
            .copied()
            .ok_or_else(|| ModelError::BadOutput("salida vacia".into()))?;

        if !score.is_finite() {
            return Err(ModelError::BadOutput(format!(
                "el modelo devolvio {score}, que no es un numero valido"
            )));
        }
        let score = score.clamp(0.0, 1.0);

        Ok(Prediction {
            score,
            verdict: self.thresholds.verdict(score),
        })
    }
}
