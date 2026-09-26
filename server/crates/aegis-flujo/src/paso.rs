//! Un paso: lo que hace, lo que necesita, a quien toca y como se revierte.
//!
//! # Todo lo que un paso declara es obligatorio
//!
//! [`Paso`] no tiene metodos con cuerpo por defecto para lo que importa:
//!
//! - **`revertir`** es obligatorio. Un paso sin reversion declarada NO COMPILA:
//!
//! ```compile_fail,E0046
//! use aegis_flujo::paso::{Fut, Paso, Reversibilidad, SinFirma, ErrorPaso};
//! struct SinReversion;
//! impl Paso<()> for SinReversion {
//!     type Entrada = ();
//!     type Salida = ();
//!     type Deshacer = ();
//!     type Permiso = SinFirma;
//!     const REVERSIBILIDAD: Reversibilidad = Reversibilidad::Total;
//!     const TOCA_FLOTA: bool = false;
//!     fn nombre(&self) -> &'static str { "sin reversion" }
//!     fn objetivos<'a>(&'a self, _: &'a (), _: &'a ()) -> Fut<'a, Result<Vec<aegis_entidad::Eid>, ErrorPaso>> {
//!         Box::pin(async { Ok(Vec::new()) })
//!     }
//!     fn clave(&self, _: &()) -> String { String::new() }
//!     fn ejecutar<'a>(&'a self, _: &'a (), _: &'a ()) -> Fut<'a, Result<((), ()), ErrorPaso>> {
//!         Box::pin(async { Ok(((), ())) })
//!     }
//!     // Falta `revertir`.
//! }
//! ```
//!
//! - **`REVERSIBILIDAD`** es obligatoria, y un paso `Irreversible` —matar un
//!   proceso, revocar tickets— no se puede meter en un flujo sin exigir una
//!   [`crate::firma::Firma`]: lo comprueba el compilador (ver
//!   [`crate::flujo::Flujo::paso`]). Fingir que se deshace lo que no se puede
//!   deshacer seria peor que no declararlo.
//! - **`Permiso`** dice si el paso exige aprobacion humana firmada.

use std::future::Future;
use std::pin::Pin;

use aegis_entidad::Eid;

/// Un futuro que se puede enviar entre hilos.
pub type Fut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Lo que devuelve un paso al ejecutarse: su salida y lo que guardo para
/// deshacerse.
pub type Efecto<S, D> = Result<(S, D), ErrorPaso>;

/// Si lo que hace un paso se puede deshacer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reversibilidad {
    /// Se deshace entero: aislar se levanta, una cuarentena se restaura.
    Total,
    /// No se puede deshacer: un proceso matado no revive. Un paso asi exige
    /// firma humana, por construccion.
    Irreversible,
}

/// Un permiso para ejecutar un paso.
pub trait Permiso: Send + Sync + 'static {
    /// Si es una aprobacion humana firmada.
    const FIRMADO: bool;
    /// Si cubre la ejecucion concreta cuya huella se da (el paso y sus
    /// objetivos exactos). Una firma para aislar una maquina no sirve para
    /// aislar otra.
    fn cubre(&self, huella: &[u8; 32]) -> bool;
    /// Quien lo concedio, para el registro.
    fn quien(&self) -> Option<&str>;
}

/// El permiso de un paso de bajo impacto: no hace falta firma.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SinFirma;

impl Permiso for SinFirma {
    const FIRMADO: bool = false;
    fn cubre(&self, _: &[u8; 32]) -> bool {
        true
    }
    fn quien(&self) -> Option<&str> {
        None
    }
}

/// Un paso que fallo.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ErrorPaso {
    /// El efecto no se pudo aplicar.
    #[error("{0}")]
    Fallo(String),
    /// El paso recibio una entrada que no sirve (una entidad de otra clase que
    /// se colo por un camino no tipado, un objetivo que ya no existe).
    #[error("entrada no valida: {0}")]
    Entrada(String),
}

/// Un paso de un flujo, sobre un contexto `C` (los puertos con los que actua).
pub trait Paso<C>: Send + Sync + 'static {
    /// Lo que necesita.
    type Entrada: Clone + Send + Sync + 'static;
    /// Lo que produce para los pasos siguientes.
    type Salida: Clone + Send + Sync + 'static;
    /// Lo que guarda para poder revertir: el estado de ANTES. Revertir no es
    /// «hacer lo contrario»: una IP que ya estaba bloqueada antes del flujo no
    /// se desbloquea al revertir.
    type Deshacer: Send + Sync + 'static;
    /// El permiso que exige.
    type Permiso: Permiso;
    /// Si se puede deshacer.
    const REVERSIBILIDAD: Reversibilidad;
    /// Si actua sobre la flota: entonces pasa por los cinco frenos.
    const TOCA_FLOTA: bool;

    /// Nombre estable.
    fn nombre(&self) -> &'static str;

    /// Las entidades a las que afecta: lo que miran los frenos y lo que cubre
    /// una firma.
    ///
    /// Recibe el contexto porque el radio real no siempre esta en la entrada:
    /// bloquear una red corta a TODAS las maquinas de la flota que viven dentro
    /// de ella, y eso solo lo sabe el inventario. Un paso que declarara «un
    /// objetivo, la red» pasaria los frenos con un radio de uno mientras deja
    /// incomunicada media flota.
    ///
    /// # Errors
    ///
    /// [`ErrorPaso`] si no se pueden resolver: sin objetivos resueltos no hay
    /// frenos, y sin frenos no se actua.
    fn objetivos<'a>(
        &'a self,
        entrada: &'a Self::Entrada,
        ctx: &'a C,
    ) -> Fut<'a, Result<Vec<Eid>, ErrorPaso>>;

    /// Clave de idempotencia: dos ejecuciones con la misma clave en el mismo
    /// flujo son la misma, y la segunda no repite el efecto.
    fn clave(&self, entrada: &Self::Entrada) -> String;

    /// Aplica el efecto.
    ///
    /// # Errors
    ///
    /// [`ErrorPaso`] si no se pudo.
    fn ejecutar<'a>(
        &'a self,
        entrada: &'a Self::Entrada,
        ctx: &'a C,
    ) -> Fut<'a, Efecto<Self::Salida, Self::Deshacer>>;

    /// Deshace el efecto, a partir de lo que guardo [`Paso::ejecutar`].
    ///
    /// Obligatorio: un paso sin reversion declarada no compila. Un paso
    /// `Irreversible` lo implementa igualmente, diciendo que no hay nada que
    /// hacer; el motor no lo llama, y lo cuenta como irreversible ya hecho.
    ///
    /// # Errors
    ///
    /// [`ErrorPaso`] si la reversion falla: el flujo termina como revertido
    /// CON FALLOS y lo que no se pudo deshacer se escala a una persona.
    fn revertir<'a>(
        &'a self,
        deshacer: Self::Deshacer,
        ctx: &'a C,
    ) -> Fut<'a, Result<(), ErrorPaso>>;
}
