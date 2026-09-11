//! El plan de reversion: que copias-sombra restaurar y a donde.
//!
//! Se construye cuando el veredicto de ransomware se confirma, y separa el QUE
//! del COMO: el plan es datos puros —una lista de pasos— y el [`crate::revert`]
//! los ejecuta. Asi el plan se puede inspeccionar, contar y probar sin tocar el
//! disco.

use crate::shadowstore::SombraId;

/// Un paso: restaurar una copia-sombra a su ruta original.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasoReversion {
    /// La copia-sombra a restaurar.
    pub sombra: SombraId,
    /// La ruta original a la que vuelve.
    pub ruta_original: Vec<u8>,
}

/// El plan completo de una reversion.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlanReversion {
    /// Los pasos, en el orden en que se aplicaran.
    pub pasos: Vec<PasoReversion>,
}

impl PlanReversion {
    /// Un plan vacio.
    pub fn nuevo() -> PlanReversion {
        PlanReversion { pasos: Vec::new() }
    }

    /// Anade un paso.
    pub fn anadir(&mut self, sombra: SombraId, ruta_original: Vec<u8>) {
        self.pasos.push(PasoReversion {
            sombra,
            ruta_original,
        });
    }

    /// Cuantos ficheros restaurara.
    pub fn len(&self) -> usize {
        self.pasos.len()
    }

    /// `true` si no hay nada que restaurar.
    pub fn is_empty(&self) -> bool {
        self.pasos.is_empty()
    }
}
