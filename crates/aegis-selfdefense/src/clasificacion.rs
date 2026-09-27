//! Clasificacion de la manipulacion del agente, con su evidencia (FASE 104).
//!
//! No todo intento de cegar al agente es igual, y tratar igual a un script que
//! hace `kill` y a un rootkit que desengancha los programas del kernel pierde la
//! informacion que decide la respuesta. Se clasifica por SOFISTICACION, de la mas
//! torpe a la que llega al kernel, y cada clase se sostiene sobre la EVIDENCIA que
//! se observo —no sobre una corazonada—.

/// La sofisticacion de un intento de manipulacion, de menor a mayor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClaseManipulacion {
    /// Torpe: matar el proceso del agente. Lo ve cualquiera y lo para el reinicio.
    Torpe,
    /// Competente: parar el servicio y borrar su unidad para que no reinicie.
    Competente,
    /// Con root: tocar los ficheros del agente o reescribir la linea base.
    ConRoot,
    /// Con kernel: desenganchar los programas del kernel. La mas grave: quien
    /// llega aqui puede cegar la telemetria desde debajo del agente.
    ConKernel,
}

impl ClaseManipulacion {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            ClaseManipulacion::Torpe => "torpe",
            ClaseManipulacion::Competente => "competente",
            ClaseManipulacion::ConRoot => "con-root",
            ClaseManipulacion::ConKernel => "con-kernel",
        }
    }

    /// Una frase de que implica.
    #[must_use]
    pub fn descripcion(self) -> &'static str {
        match self {
            ClaseManipulacion::Torpe => "mato el proceso del agente",
            ClaseManipulacion::Competente => {
                "paro el servicio o borro su unidad para que no reinicie"
            }
            ClaseManipulacion::ConRoot => "toco los ficheros del agente o reescribio la linea base",
            ClaseManipulacion::ConKernel => "desengancho los programas del kernel",
        }
    }
}

/// La evidencia observada de un intento de manipulacion. Cada campo es algo que un
/// centinela vio de verdad.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EvidenciaManipulacion {
    /// Se envio una senal de muerte al proceso del agente.
    pub mato_proceso: bool,
    /// Se paro el servicio del agente.
    pub paro_servicio: bool,
    /// Se borro la unidad de servicio (para que no reinicie).
    pub borro_unidad: bool,
    /// Se tocaron los ficheros, la configuracion o las claves del agente.
    pub toco_ficheros_agente: bool,
    /// Se reescribio la linea base de integridad.
    pub reescribio_linea_base: bool,
    /// Se desengancharon los programas del kernel (el agente dejo de recibir
    /// eventos de una o mas familias sin haberlo pedido).
    pub desengancho_programas_kernel: bool,
}

impl EvidenciaManipulacion {
    /// Clasifica la manipulacion por la evidencia mas grave presente.
    ///
    /// Devuelve `None` si no hay evidencia de manipulacion: la ausencia de senales
    /// no es un ataque, y decir que lo es seria una falsa alarma.
    #[must_use]
    pub fn clasificar(&self) -> Option<ClaseManipulacion> {
        if self.desengancho_programas_kernel {
            Some(ClaseManipulacion::ConKernel)
        } else if self.toco_ficheros_agente || self.reescribio_linea_base {
            Some(ClaseManipulacion::ConRoot)
        } else if self.paro_servicio || self.borro_unidad {
            Some(ClaseManipulacion::Competente)
        } else if self.mato_proceso {
            Some(ClaseManipulacion::Torpe)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn cada_evidencia_da_su_clase_y_gana_la_mas_grave() {
        assert_eq!(EvidenciaManipulacion::default().clasificar(), None);
        assert_eq!(
            EvidenciaManipulacion {
                mato_proceso: true,
                ..Default::default()
            }
            .clasificar(),
            Some(ClaseManipulacion::Torpe)
        );
        assert_eq!(
            EvidenciaManipulacion {
                borro_unidad: true,
                ..Default::default()
            }
            .clasificar(),
            Some(ClaseManipulacion::Competente)
        );
        assert_eq!(
            EvidenciaManipulacion {
                reescribio_linea_base: true,
                ..Default::default()
            }
            .clasificar(),
            Some(ClaseManipulacion::ConRoot)
        );
        // Con evidencia de varios niveles, gana la mas grave.
        assert_eq!(
            EvidenciaManipulacion {
                mato_proceso: true,
                paro_servicio: true,
                toco_ficheros_agente: true,
                desengancho_programas_kernel: true,
                ..Default::default()
            }
            .clasificar(),
            Some(ClaseManipulacion::ConKernel)
        );
    }

    #[test]
    fn el_orden_de_gravedad_es_el_esperado() {
        assert!(ClaseManipulacion::Torpe < ClaseManipulacion::Competente);
        assert!(ClaseManipulacion::Competente < ClaseManipulacion::ConRoot);
        assert!(ClaseManipulacion::ConRoot < ClaseManipulacion::ConKernel);
    }
}
