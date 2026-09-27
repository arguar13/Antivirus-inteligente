//! Vigilancia mutua a tres bandas: proteger la CAPACIDAD DE AVISAR (FASE 104).
//!
//! # Que protege PPL, y que protege esto
//!
//! PPL protege el PROCESO: impide que se le mate. Pero un atacante con kernel no
//! mata el proceso: lo ciega —le corta la telemetria— y el proceso sigue vivo,
//! sano en apariencia, sin nada que contar. Lo que de verdad importa no es que el
//! proceso siga en pie, sino que la CAPACIDAD DE AVISAR sobreviva.
//!
//! Aqui tres centinelas se vigilan: el programa del KERNEL vigila al PROCESO, el
//! PROCESO vigila a los programas del kernel, y el PLANO DE CONTROL (remoto)
//! vigila a los dos. Silenciar a cualquiera de los tres produce una SENAL desde
//! otro. Y la muerte del agente es un EVENTO DE SEGURIDAD con su testigo, no la
//! ausencia de un latido interpretada a posteriori —que es lo que llega tarde—.

use std::collections::BTreeSet;

/// Uno de los tres centinelas que se vigilan entre si.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Centinela {
    /// El programa del kernel (eBPF): ve al proceso desde debajo.
    Kernel,
    /// El proceso del agente en espacio de usuario.
    Proceso,
    /// El plano de control, remoto: ve a los dos desde fuera de la maquina, y es
    /// el mas dificil de alcanzar para un atacante local.
    PlanoControl,
}

impl Centinela {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Centinela::Kernel => "kernel",
            Centinela::Proceso => "proceso",
            Centinela::PlanoControl => "plano-de-control",
        }
    }

    /// Los tres.
    #[must_use]
    pub fn todos() -> [Centinela; 3] {
        [
            Centinela::Kernel,
            Centinela::Proceso,
            Centinela::PlanoControl,
        ]
    }
}

/// La senal de que un centinela dejo de responder: un EVENTO, con su testigo y el
/// caido. No es «falto un latido»: es «yo, el kernel, vi morir al proceso».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SenalMuerteAgente {
    /// Quien lo vio.
    pub testigo: Centinela,
    /// Quien cayo.
    pub caido: Centinela,
}

/// El estado de la vigilancia mutua.
#[derive(Debug, Clone)]
pub struct VigilanciaMutua {
    vivos: BTreeSet<Centinela>,
}

impl Default for VigilanciaMutua {
    fn default() -> VigilanciaMutua {
        VigilanciaMutua::nueva()
    }
}

impl VigilanciaMutua {
    /// Los tres centinelas, vivos.
    #[must_use]
    pub fn nueva() -> VigilanciaMutua {
        VigilanciaMutua {
            vivos: Centinela::todos().into_iter().collect(),
        }
    }

    /// Si un centinela sigue vivo.
    #[must_use]
    pub fn vivo(&self, c: Centinela) -> bool {
        self.vivos.contains(&c)
    }

    /// Silencia (mata/ciega) a un centinela. Devuelve las senales que emiten los
    /// OTROS centinelas vivos que lo vigilaban: por eso matar a uno no es
    /// silencioso mientras quede otro en pie.
    ///
    /// Silenciar a uno ya caido no produce nada: no hay muerte nueva que avisar.
    pub fn silenciar(&mut self, c: Centinela) -> Vec<SenalMuerteAgente> {
        if !self.vivos.remove(&c) {
            return Vec::new();
        }
        // Los que siguen vivos son los testigos.
        self.vivos
            .iter()
            .map(|&testigo| SenalMuerteAgente { testigo, caido: c })
            .collect()
    }

    /// Cuantos centinelas siguen vivos.
    #[must_use]
    pub fn vivos(&self) -> usize {
        self.vivos.len()
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn matar_a_cualquiera_de_los_tres_produce_una_senal_desde_otro() {
        // La invariante de la fase: silenciar a cualquiera, mientras quede otro,
        // no es silencioso.
        for objetivo in Centinela::todos() {
            let mut v = VigilanciaMutua::nueva();
            let senales = v.silenciar(objetivo);
            assert_eq!(senales.len(), 2, "los otros dos lo avisan: {objetivo:?}");
            assert!(senales.iter().all(|s| s.caido == objetivo));
            assert!(senales.iter().all(|s| s.testigo != objetivo));
            assert!(!v.vivo(objetivo));
        }
    }

    #[test]
    fn la_muerte_es_un_evento_con_testigo_no_una_ausencia() {
        let mut v = VigilanciaMutua::nueva();
        let s = v.silenciar(Centinela::Proceso);
        // Cada senal DICE quien vio morir a quien; no es «no llego el latido».
        assert!(s.contains(&SenalMuerteAgente {
            testigo: Centinela::Kernel,
            caido: Centinela::Proceso,
        }));
        assert!(s.contains(&SenalMuerteAgente {
            testigo: Centinela::PlanoControl,
            caido: Centinela::Proceso,
        }));
    }

    #[test]
    fn para_no_dejar_ni_una_senal_hay_que_matar_a_los_tres() {
        // Matar al primero: 2 avisan. Al segundo: 1 avisa. Solo al matar al
        // ultimo no queda testigo —y para entonces ya hubo tres avisos antes—.
        let mut v = VigilanciaMutua::nueva();
        assert_eq!(v.silenciar(Centinela::Kernel).len(), 2);
        assert_eq!(v.silenciar(Centinela::Proceso).len(), 1);
        assert_eq!(v.silenciar(Centinela::PlanoControl).len(), 0);
        assert_eq!(v.vivos(), 0);
    }

    #[test]
    fn silenciar_a_uno_ya_caido_no_inventa_senales() {
        let mut v = VigilanciaMutua::nueva();
        let _ = v.silenciar(Centinela::Kernel);
        assert!(v.silenciar(Centinela::Kernel).is_empty());
    }
}
