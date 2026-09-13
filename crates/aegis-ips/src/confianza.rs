//! La confianza de una regla, y la unica regla que gobierna todas las demas.
//!
//! # Por que una regla lleva confianza
//!
//! No todas las deteccciones valen lo mismo. «El SHA-256 de este fichero esta en
//! la lista de indicadores» y «el nombre que ha resuelto tiene mucha entropia»
//! son las dos senales utiles, y no se parecen en nada:
//!
//! - La primera es una igualdad. O coincide o no; no hay falso positivo posible
//!   salvo que el indicador este mal.
//! - La segunda es una heuristica. Acierta mucho y falla con dominios legitimos
//!   que usan subdominios generados —redes de distribucion de contenido,
//!   telemetria, antivirus de la competencia—.
//!
//! Tratarlas igual obliga a elegir entre no cortar nunca (y entonces el IPS no
//! previene) o cortar con heuristicas (y entonces tira produccion). La confianza
//! es lo que permite no elegir.
//!
//! # LA REGLA QUE GOBIERNA LA FASE
//!
//! > **Solo una regla de confianza alta puede cortar.**
//!
//! Las demas alertan. No es una politica configurable: esta en el tipo, en
//! [`Confianza::puede_cortar`], y el motor de decision no ofrece ninguna via
//! para saltarsela. Una politica que se puede aflojar se afloja, normalmente el
//! dia que alguien tiene prisa.

/// Cuanto se fia el producto de una regla.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confianza {
    /// Heuristica util para investigar. Falsos positivos esperables.
    Baja,
    /// Indicio fuerte, pero con contexto legitimo posible.
    Media,
    /// Practicamente no admite falso positivo: igualdades exactas contra
    /// indicadores, o combinaciones que no ocurren en trafico legitimo.
    Alta,
}

impl Confianza {
    /// Si una regla con esta confianza puede llegar a cortar trafico.
    ///
    /// Ver la doctrina del modulo: **solo la alta**.
    #[must_use]
    pub fn puede_cortar(self) -> bool {
        matches!(self, Confianza::Alta)
    }

    /// Nombre estable, para registros e informes.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Confianza::Baja => "baja",
            Confianza::Media => "media",
            Confianza::Alta => "alta",
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// LA INVARIANTE DE LA FASE. Si esta prueba cae, el producto puede cortar la
    /// red de un cliente por una heuristica.
    #[test]
    fn solo_la_confianza_alta_puede_cortar() {
        assert!(Confianza::Alta.puede_cortar());
        assert!(!Confianza::Media.puede_cortar());
        assert!(!Confianza::Baja.puede_cortar());
    }

    /// El orden importa porque se usa para quedarse con el veredicto mas fuerte
    /// cuando varias reglas coinciden sobre el mismo flujo.
    #[test]
    fn la_confianza_esta_ordenada_de_menos_a_mas() {
        assert!(Confianza::Baja < Confianza::Media);
        assert!(Confianza::Media < Confianza::Alta);
    }
}
