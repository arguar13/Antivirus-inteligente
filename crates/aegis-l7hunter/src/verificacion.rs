//! Verificacion EN CALIENTE de un gancho antes de confiar en el (FASE 107).
//!
//! # Telemetria vs. adivinacion
//!
//! Derivar bien el desplazamiento (ver [`crate::desplazamiento`]) es necesario
//! pero no basta: el offset puede ser correcto y el gancho leer, aun asi, un
//! argumento equivocado —un cambio de convencion de llamada, un argumento en
//! registro y no en pila, una version que reordeno los parametros—. La unica
//! forma de SABER que un gancho ve lo que dice ver es probarlo.
//!
//! Antes de confiar en un gancho, el agente abre una conexion de prueba PROPIA,
//! envia un canario conocido a traves de la biblioteca enganchada, y comprueba que
//! lo que salio por el gancho es EXACTAMENTE el canario. Un gancho que no pasa esa
//! prueba NO SE USA: es la diferencia entre telemetria y adivinacion, y nadie lo
//! hace. Aqui esta la DECISION —lo capturado es o no es el canario—; abrir la
//! conexion real es la fontaneria en vivo, gated.

/// El estado de verificacion de un gancho.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EstadoGancho {
    /// Verificado: una conexion de prueba propia confirmo que lo que sale del
    /// gancho es lo que entro.
    Verificado,
    /// Sin verificar: el canario no salio igual. El gancho NO se usa.
    SinVerificar {
        /// Por que no se pudo confiar.
        motivo: String,
    },
}

impl EstadoGancho {
    /// Un gancho SOLO se usa si esta verificado. No hay «usar de todas formas».
    #[must_use]
    pub fn se_puede_usar(&self) -> bool {
        matches!(self, EstadoGancho::Verificado)
    }
}

/// Verifica un gancho con un canario de ida y vuelta: se envio `canario` por la
/// conexion de prueba y el gancho capturo `capturado`. El gancho es de fiar solo
/// si capturo EXACTAMENTE lo que se envio.
#[must_use]
pub fn verificar_canario(canario: &[u8], capturado: &[u8]) -> EstadoGancho {
    if canario.is_empty() {
        return EstadoGancho::SinVerificar {
            motivo: "canario vacio: la prueba no dice nada".to_string(),
        };
    }
    if canario == capturado {
        EstadoGancho::Verificado
    } else {
        EstadoGancho::SinVerificar {
            motivo: format!(
                "el gancho capturo {} byte(s) que no coinciden con el canario de {} byte(s): \
                 el offset o la convencion de llamada no son los que se creia",
                capturado.len(),
                canario.len()
            ),
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn un_gancho_que_devuelve_el_canario_se_verifica_y_se_usa() {
        let canario = b"AEGIS-CANARIO-7f3a";
        let e = verificar_canario(canario, canario);
        assert_eq!(e, EstadoGancho::Verificado);
        assert!(e.se_puede_usar());
    }

    #[test]
    fn un_gancho_que_lee_basura_no_se_verifica_y_no_se_usa() {
        // El offset era correcto pero el argumento estaba en otro sitio: sale
        // basura. No se usa.
        let e = verificar_canario(b"AEGIS-CANARIO-7f3a", b"\x00\x01\x02basura");
        assert!(matches!(e, EstadoGancho::SinVerificar { .. }));
        assert!(!e.se_puede_usar(), "un gancho no verificado no se usa");
    }

    #[test]
    fn un_canario_vacio_no_verifica_nada() {
        assert!(!verificar_canario(b"", b"").se_puede_usar());
    }
}
