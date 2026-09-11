//! Ejecucion de la reversion: restaurar los ficheros originales.
//!
//! Separado del plan a proposito: el plan decide QUE, el [`Reverter`] hace el
//! COMO. En produccion se restaura al sistema de ficheros; en las pruebas se usa
//! el mismo `ReverterFichero` sobre un directorio temporal real, asi que lo que
//! se prueba es exactamente lo que corre.

use crate::plan::PlanReversion;
use crate::shadowstore::{AlmacenSombra, SombraError};

/// Un fallo al revertir.
#[derive(Debug, thiserror::Error)]
pub enum RevertError {
    /// No se pudo leer la copia-sombra.
    #[error("recuperando la copia-sombra: {0}")]
    Sombra(#[from] SombraError),
    /// No se pudo escribir el fichero restaurado.
    #[error("escribiendo el fichero restaurado: {0}")]
    Io(#[from] std::io::Error),
    /// La ruta original no es UTF-8 valido y este reverter la necesita como ruta.
    #[error("la ruta original no es una ruta valida")]
    RutaInvalida,
}

/// Como se materializa un fichero restaurado. Un rasgo para que las pruebas y la
/// produccion compartan la logica de orquestacion y solo cambie el destino.
pub trait Reverter {
    /// Escribe el contenido original en su ruta.
    fn restaurar(&self, ruta_original: &[u8], contenido: &[u8]) -> Result<(), RevertError>;
}

/// Restaura al sistema de ficheros real.
pub struct ReverterFichero;

impl Reverter for ReverterFichero {
    fn restaurar(&self, ruta_original: &[u8], contenido: &[u8]) -> Result<(), RevertError> {
        let ruta = std::str::from_utf8(ruta_original).map_err(|_| RevertError::RutaInvalida)?;
        // Escritura + rename atomico: si el proceso muere a media restauracion,
        // el fichero no queda a medias entre cifrado y original.
        let tmp = format!("{ruta}.aegis-rollback-tmp");
        std::fs::write(&tmp, contenido)?;
        std::fs::rename(&tmp, ruta)?;
        Ok(())
    }
}

/// Ejecuta un plan de reversion: por cada paso, recupera la copia-sombra y la
/// restaura. Devuelve cuantos ficheros se restauraron.
///
/// No se detiene ante el primer error: en un incidente, restaurar 900 de 1000
/// ficheros es mejor que restaurar 0 porque el 456 fallo. Los errores se
/// acumulan y se devuelven al final.
pub fn ejecutar_plan(
    plan: &PlanReversion,
    almacen: &AlmacenSombra,
    reverter: &dyn Reverter,
) -> (usize, Vec<RevertError>) {
    let mut restaurados = 0;
    let mut errores = Vec::new();
    for paso in &plan.pasos {
        match almacen.recuperar(paso.sombra) {
            Ok((ruta, contenido)) => match reverter.restaurar(&ruta, &contenido) {
                Ok(()) => restaurados += 1,
                Err(e) => errores.push(e),
            },
            Err(e) => errores.push(e.into()),
        }
    }
    (restaurados, errores)
}
