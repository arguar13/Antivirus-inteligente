//! Revocacion que HACE algo, con freno contra la revocacion masiva (FASE 105).
//!
//! # En Keylime la revocacion es una notificacion; aqui cambia el producto
//!
//! Cuando un agente falla la atestacion, no basta con avisar. Aqui PIERDE
//! AUTORIDAD en la malla de la FASE 68 —sus pares dejan de aceptar sus ordenes— y
//! se le baja el TOPE DE CONFIANZA en el arbitro a cero: lo que diga deja de mover
//! un veredicto. La revocacion cambia el comportamiento del producto, no llena un
//! log.
//!
//! # La revocacion tambien es un arma: la degradacion pegajosa la frena
//!
//! Si un atacante puede provocar fallos de atestacion, revocar media flota es una
//! denegacion de servicio. Por eso la revocacion pasa por un freno: pasado un tope
//! de la flota, una oleada de revocaciones se trata como lo que casi seguro es —un
//! ataque a la propia atestacion, no media flota comprometida a la vez— y se CORTA.
//! El freno es PEGAJOSO (FASE 71): no se recupera solo; un operador lo revisa y lo
//! rearma a mano. Fallar cerrado aqui es no revocar de mas.

use aegis_entidad::Confianza;

/// El estado de un nodo tras la atestacion, en las dos escalas que importan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EstadoNodo {
    /// Si el nodo tiene autoridad en la malla (FASE 68): si sus pares aceptan sus
    /// ordenes.
    pub tiene_autoridad: bool,
    /// El tope de confianza del nodo en el arbitro. Un nodo revocado no puede
    /// mover un veredicto: su tope es nulo.
    pub tope_confianza: Confianza,
}

impl EstadoNodo {
    /// Un nodo atestado: con autoridad y con el tope de confianza dado.
    #[must_use]
    pub fn atestado(tope: Confianza) -> EstadoNodo {
        EstadoNodo {
            tiene_autoridad: true,
            tope_confianza: tope,
        }
    }

    /// Un nodo revocado: sin autoridad y con tope de confianza nulo.
    #[must_use]
    pub fn revocado() -> EstadoNodo {
        EstadoNodo {
            tiene_autoridad: false,
            tope_confianza: Confianza::NULA,
        }
    }

    /// Si el nodo esta revocado.
    #[must_use]
    pub fn esta_revocado(&self) -> bool {
        !self.tiene_autoridad && self.tope_confianza == Confianza::NULA
    }
}

/// Por que una revocacion no se aplico.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ErrorRevocacion {
    /// El freno pegajoso corto la oleada: se alcanzo el tope de revocaciones. Una
    /// oleada mas alla del tope es, casi seguro, un ataque a la atestacion.
    #[error("freno pegajoso: se alcanzo el tope de {0} revocaciones; una oleada mayor se trata como ataque a la atestacion, no como flota comprometida")]
    TopeAlcanzado(usize),
}

/// El freno de revocacion masiva, con degradacion pegajosa (FASE 71).
#[derive(Debug, Clone)]
pub struct LimitadorRevocacion {
    tope: usize,
    revocados: usize,
    pegado: bool,
}

impl LimitadorRevocacion {
    /// Un limitador para una flota de `tamano_flota`, que corta pasada la
    /// `fraccion_maxima_bps` (en puntos basicos: 2000 = 20 %). El tope es al menos
    /// 1: siempre se puede revocar un nodo de verdad comprometido.
    #[must_use]
    pub fn nuevo(tamano_flota: usize, fraccion_maxima_bps: u32) -> LimitadorRevocacion {
        let tope = ((tamano_flota as u64 * u64::from(fraccion_maxima_bps)) / 10_000) as usize;
        LimitadorRevocacion {
            tope: tope.max(1),
            revocados: 0,
            pegado: false,
        }
    }

    /// Intenta revocar un nodo. Si el freno esta pegado o se alcanza el tope,
    /// devuelve `Err` y NO revoca: fallar cerrado aqui es no revocar de mas.
    pub fn intentar_revocar(&mut self) -> Result<EstadoNodo, ErrorRevocacion> {
        if self.pegado || self.revocados >= self.tope {
            self.pegado = true;
            return Err(ErrorRevocacion::TopeAlcanzado(self.tope));
        }
        self.revocados += 1;
        Ok(EstadoNodo::revocado())
    }

    /// Cuantas revocaciones se han aplicado.
    #[must_use]
    pub fn revocados(&self) -> usize {
        self.revocados
    }

    /// Si el freno esta pegado (necesita rearme manual del operador).
    #[must_use]
    pub fn esta_pegado(&self) -> bool {
        self.pegado
    }

    /// Rearme manual: un operador reviso la oleada y decide seguir. Es explicito a
    /// proposito —la recuperacion no es automatica—.
    pub fn rearmar(&mut self) {
        self.pegado = false;
        self.revocados = 0;
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn una_atestacion_fallida_revoca_autoridad_y_confianza() {
        let n = EstadoNodo::revocado();
        assert!(!n.tiene_autoridad, "pierde autoridad en la malla");
        assert_eq!(n.tope_confianza, Confianza::NULA, "no mueve el veredicto");
        assert!(n.esta_revocado());
    }

    #[test]
    fn revocar_media_flota_lo_corta_la_degradacion_pegajosa() {
        // Flota de 1000, tope 20 % = 200. El atacante intenta revocar 500.
        let mut lim = LimitadorRevocacion::nuevo(1000, 2000);
        let mut aplicadas = 0;
        let mut cortadas = 0;
        for _ in 0..500 {
            match lim.intentar_revocar() {
                Ok(_) => aplicadas += 1,
                Err(ErrorRevocacion::TopeAlcanzado(_)) => cortadas += 1,
            }
        }
        assert_eq!(aplicadas, 200, "solo hasta el tope");
        assert_eq!(cortadas, 300, "el resto, cortado");
        assert!(
            lim.esta_pegado(),
            "el freno queda pegado: lo revisa un operador"
        );
    }

    #[test]
    fn el_freno_es_pegajoso_no_se_recupera_solo() {
        let mut lim = LimitadorRevocacion::nuevo(10, 1000); // tope 1
        assert!(lim.intentar_revocar().is_ok());
        assert!(lim.intentar_revocar().is_err());
        // Aunque se intente mas tarde, sigue cortado hasta el rearme manual.
        assert!(lim.intentar_revocar().is_err());
        lim.rearmar();
        assert!(
            lim.intentar_revocar().is_ok(),
            "tras el rearme, vuelve a permitir"
        );
    }
}
