//! Atestacion de la malla: un par no acepta autoridad de un nodo no atestado.
//!
//! La malla de la FASE 68 deja a los agentes actuar sin el plano de control. Eso
//! es potente y peligroso: un nodo comprometido que conserve su sitio en la malla
//! puede dar ordenes a sus pares. La regla que lo cierra: un par NO acepta una
//! orden de un nodo cuyo estado de atestacion no sea bueno. La autoridad en la
//! malla se hereda de la atestacion, no de estar conectado.

use crate::revocacion::EstadoNodo;

/// Un par de la malla que decide si acepta ordenes de otro nodo.
#[derive(Debug, Clone, Copy, Default)]
pub struct Par;

impl Par {
    /// Decide si este par acepta la autoridad (una orden) de un nodo emisor, dado
    /// el estado de atestacion del emisor. Sin autoridad atestada, no.
    #[must_use]
    pub fn acepta_autoridad_de(&self, emisor: &EstadoNodo) -> bool {
        emisor.tiene_autoridad
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_entidad::Confianza;

    #[test]
    fn un_par_no_acepta_ordenes_de_un_nodo_no_atestado() {
        let par = Par;
        // Un nodo atestado: se le acepta.
        assert!(par.acepta_autoridad_de(&EstadoNodo::atestado(Confianza::nueva(80))));
        // Un nodo revocado (fallo la atestacion): NO.
        assert!(!par.acepta_autoridad_de(&EstadoNodo::revocado()));
    }
}
