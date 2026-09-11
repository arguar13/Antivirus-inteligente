//! Decision de respuesta ante un disparo.
//!
//! Separada del disparo, y pura, para poder probarla sin red ni kernel: dado un
//! disparo, decide si aislar el proceso, si volcar su memoria y con que
//! severidad. La ORQUESTACION real —aislar de la red (FASE 44), volcar la memoria
//! (aegis-forensics)— la hace quien llama con esas piezas ya existentes; aqui
//! solo se decide, que es lo que hay que poder razonar y probar.

use crate::trip::{ComoDisparo, Disparo};

/// Lo que hay que hacer ante un disparo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Respuesta {
    /// Aislar de la red al proceso/host (invoca la Cuarentena de FASE 44).
    pub aislar: bool,
    /// Volcar la memoria del proceso sospechoso para el analisis forense.
    pub volcar_memoria: bool,
    /// El proceso sobre el que actuar.
    pub sobre: String,
    /// Severidad 0..4.
    pub severidad: u8,
}

/// Decide la respuesta. Tocar un honey-token no tiene explicacion inocente, asi
/// que la respuesta por defecto es contundente: aislar y volcar. La severidad
/// distingue matices —leer credenciales de la memoria de LSASS es el corazon del
/// robo de credenciales; abrir un honey-file es reconocimiento, un paso antes—.
pub fn decidir_respuesta(disparo: &Disparo) -> Respuesta {
    match &disparo.como {
        ComoDisparo::LeidoDeMemoria { lector } => Respuesta {
            aislar: true,
            volcar_memoria: true,
            sobre: lector.clone(),
            // Robo de credenciales en marcha: lo mas alto.
            severidad: 4,
        },
        ComoDisparo::FicheroAbierto { lector, .. } => Respuesta {
            aislar: true,
            // Un fichero abierto aun no es memoria robada: se aisla y se observa,
            // pero el volcado se reserva por si escala.
            volcar_memoria: false,
            sobre: lector.clone(),
            severidad: 3,
        },
    }
}
