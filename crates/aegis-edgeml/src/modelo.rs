//! Carga del modelo e inferencia con tract.
//!
//! Reutiliza el mismo motor (tract-onnx) que el clasificador estatico de
//! `aegis-ml`: Rust puro, sin dependencias nativas, corre en el borde sin
//! conexion. El modelo lleva la sigmoide DENTRO del grafo, asi que la salida ya
//! es una probabilidad [0,1]; aqui solo se traduce a un veredicto accionable.

use crate::behavior::{extraer, Traza, DIM};
use tract_onnx::prelude::*;

/// Un fallo del motor de inferencia.
#[derive(Debug, thiserror::Error)]
pub enum ModeloError {
    /// El modelo no se pudo cargar o preparar.
    #[error("cargando el modelo: {0}")]
    Carga(String),
    /// La inferencia fallo.
    #[error("la inferencia fallo: {0}")]
    Inferencia(String),
    /// El vector de entrada no tiene la dimension esperada.
    #[error("vector de {encontrado} features; se esperaban {esperado}")]
    Dimension {
        /// La que llego.
        encontrado: usize,
        /// La que el modelo espera.
        esperado: usize,
    },
}

/// El veredicto accionable derivado de la puntuacion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Veredicto {
    /// Comportamiento normal.
    Benigno,
    /// Sospechoso: vigilar y elevar telemetria, pero no aislar aun.
    Sospechoso,
    /// Malicioso: aislar sin esperar a la nube.
    Malicioso,
}

/// El resultado de una inferencia.
#[derive(Debug, Clone, Copy)]
pub struct Prediccion {
    /// Probabilidad de malicioso [0,1].
    pub score: f32,
    /// El veredicto derivado.
    pub veredicto: Veredicto,
}

type Plan = SimplePlan<TypedFact, Box<dyn TypedOp>, Graph<TypedFact, Box<dyn TypedOp>>>;

/// El modelo de comportamiento cargado y listo para inferir en el borde.
pub struct ModeloComportamiento {
    plan: Plan,
    /// Umbral por encima del cual se aisla. Por defecto 0,90.
    umbral_malicioso: f32,
    /// Umbral por encima del cual se vigila. Por defecto 0,50.
    umbral_sospechoso: f32,
}

impl ModeloComportamiento {
    /// Carga el modelo embebido en el binario.
    pub fn embebido() -> Result<ModeloComportamiento, ModeloError> {
        Self::desde_bytes(crate::MODELO_EMBEBIDO)
    }

    /// Carga un modelo desde bytes ONNX.
    pub fn desde_bytes(bytes: &[u8]) -> Result<ModeloComportamiento, ModeloError> {
        let mut cursor = std::io::Cursor::new(bytes);
        let plan = tract_onnx::onnx()
            .model_for_read(&mut cursor)
            .map_err(|e| ModeloError::Carga(e.to_string()))?
            .with_input_fact(0, f32::fact([1, DIM]).into())
            .map_err(|e| ModeloError::Carga(format!("forma de entrada [1,{DIM}]: {e}")))?
            .into_optimized()
            .map_err(|e| ModeloError::Carga(format!("optimizacion: {e}")))?
            .into_runnable()
            .map_err(|e| ModeloError::Carga(format!("preparacion: {e}")))?;
        Ok(ModeloComportamiento {
            plan,
            umbral_malicioso: 0.90,
            umbral_sospechoso: 0.50,
        })
    }

    /// Ajusta los umbrales de decision.
    pub fn con_umbrales(mut self, sospechoso: f32, malicioso: f32) -> ModeloComportamiento {
        self.umbral_sospechoso = sospechoso;
        self.umbral_malicioso = malicioso;
        self
    }

    /// Infiere sobre un vector de features ya extraido.
    pub fn inferir(&self, features: &[f32]) -> Result<Prediccion, ModeloError> {
        if features.len() != DIM {
            return Err(ModeloError::Dimension {
                encontrado: features.len(),
                esperado: DIM,
            });
        }
        let entrada = tract_ndarray::Array2::from_shape_vec((1, DIM), features.to_vec())
            .map_err(|e| ModeloError::Inferencia(e.to_string()))?;
        let tensor: Tensor = entrada.into();
        let salida = self
            .plan
            .run(tvec!(tensor.into()))
            .map_err(|e| ModeloError::Inferencia(e.to_string()))?;
        let score = salida[0]
            .to_array_view::<f32>()
            .map_err(|e| ModeloError::Inferencia(e.to_string()))?
            .iter()
            .next()
            .copied()
            .ok_or_else(|| ModeloError::Inferencia("salida vacia".to_string()))?;

        let veredicto = if score >= self.umbral_malicioso {
            Veredicto::Malicioso
        } else if score >= self.umbral_sospechoso {
            Veredicto::Sospechoso
        } else {
            Veredicto::Benigno
        };
        Ok(Prediccion { score, veredicto })
    }

    /// Extrae features de una traza y la clasifica: el camino completo que corre
    /// en el agente, en el borde, sin conexion.
    pub fn analizar(&self, traza: &Traza) -> Result<Prediccion, ModeloError> {
        let features = extraer(traza);
        self.inferir(&features)
    }
}
