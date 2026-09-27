//! Recuperacion: restaurar desde la linea base atestada, NUNCA en automatico.
//!
//! # Por que la restauracion no puede ser un automatismo
//!
//! Restaurar solo un fichero que el administrador acaba de cambiar A PROPOSITO
//! —una configuracion nueva, una clave rotada— es como se pierde la confianza del
//! cliente: el producto le pelea sus cambios legitimos. Por eso cada cambio
//! detectado OFRECE una restauracion, pero restaurar es una ACCION que pasa por
//! las salvaguardas de la FASE 71: se propone, la aprueba quien debe, y es
//! reversible. No hay un camino que restaure sin pasar por ahi.
//!
//! Ademas, solo se restaura desde una linea base ATESTADA: si la firma o el sello
//! de la linea base no verificaron, no hay «estado bueno» de confianza al que
//! volver, y proponer una restauracion seria restaurar hacia lo que diga un
//! atacante con root. En ese caso no se propone: se dice que no hay base fiable.

/// Una propuesta de restauracion. No es una restauracion: es lo que se le ofrece a
/// quien decide, con las salvaguardas ya exigidas por el tipo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropuestaRestauracion {
    /// La identidad del objeto a restaurar (ruta o identidad de objeto).
    pub objetivo: String,
    /// Por que se propone.
    pub motivo: String,
}

impl PropuestaRestauracion {
    /// Una restauracion JAMAS es automatica. Es una invariante del tipo, no una
    /// opcion de configuracion: no existe un `es_automatica() -> true`.
    #[must_use]
    pub fn es_automatica(&self) -> bool {
        false
    }

    /// Toda restauracion exige las salvaguardas de la FASE 71: aprobacion y
    /// reversibilidad. No hay forma de construir una que no las exija.
    #[must_use]
    pub fn requiere_aprobacion(&self) -> bool {
        true
    }

    /// Y es reversible: si la restauracion resulta ser el error, se puede deshacer.
    #[must_use]
    pub fn es_reversible(&self) -> bool {
        true
    }
}

/// Propone una restauracion para un cambio detectado.
///
/// `base_atestada` dice si la linea base de la que se restauraria abrio bien (firma
/// y sello verificados). Si no, no se propone nada: no hay estado bueno de
/// confianza, y se devuelve `None` con esa razon implicita.
#[must_use]
pub fn proponer_restauracion(objetivo: &str, base_atestada: bool) -> Option<PropuestaRestauracion> {
    if !base_atestada {
        // Sin linea base atestada no hay a donde volver con confianza.
        return None;
    }
    Some(PropuestaRestauracion {
        objetivo: objetivo.to_string(),
        motivo: "el objeto difiere de la linea base atestada; se ofrece restaurar \
                 con aprobacion y reversion (FASE 71)"
            .to_string(),
    })
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn la_restauracion_nunca_es_automatica_y_siempre_pasa_por_frenos() {
        let p = proponer_restauracion("/etc/sudoers", true).unwrap();
        assert!(
            !p.es_automatica(),
            "restaurar en automatico pierde al cliente"
        );
        assert!(p.requiere_aprobacion());
        assert!(p.es_reversible());
    }

    #[test]
    fn sin_linea_base_atestada_no_se_propone_restaurar() {
        // Si la base no atesta (firma/sello no verificaron), no hay estado bueno
        // de confianza: restaurar seria volver a lo que diga un atacante con root.
        assert_eq!(proponer_restauracion("/etc/sudoers", false), None);
    }
}
