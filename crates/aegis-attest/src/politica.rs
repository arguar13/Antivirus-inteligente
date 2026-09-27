//! La politica de PCR como TIPO, no como fichero de texto (FASE 105).
//!
//! # Por que un tipo y no un fichero
//!
//! En Keylime la politica de PCR es configuracion: un fichero que dice que valores
//! son aceptables. Un fichero se desincroniza —alguien actualiza el kernel y se
//! olvida de la politica, o dos ficheros en dos sitios dejan de coincidir—. Aqui
//! la politica es un TIPO: una contradiccion —exigir que el PCR 7 valga a la vez X
//! e Y— no llega a existir, porque construirla devuelve `Err` en el sitio, no un
//! comportamiento raro en produccion. Hay UNA exigencia por PCR, garantizada por
//! la estructura.

use std::collections::{BTreeMap, BTreeSet};

/// Lo que una politica exige de un PCR concreto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExigenciaPcr {
    /// El PCR tiene que ser EXACTAMENTE este valor (un valor dorado unico).
    Igual(Vec<u8>),
    /// El PCR tiene que ser UNO DE estos valores: varios arranques buenos
    /// conocidos (p. ej. dos versiones de kernel firmadas).
    UnoDe(BTreeSet<Vec<u8>>),
}

impl ExigenciaPcr {
    fn admite(&self, valor: &[u8]) -> bool {
        match self {
            ExigenciaPcr::Igual(v) => v.as_slice() == valor,
            ExigenciaPcr::UnoDe(s) => s.iter().any(|v| v.as_slice() == valor),
        }
    }
}

/// Por que una politica no se pudo construir o no se cumplio.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ErrorPolitica {
    /// Se intento anadir una exigencia que contradice la que ya habia para ese
    /// PCR. La contradiccion se rechaza AQUI, no en produccion.
    #[error("contradiccion en el PCR {0}: ya hay una exigencia incompatible")]
    Contradiccion(u32),
    /// La politica exige un PCR que el quote no presento.
    #[error("el PCR {0} que exige la politica no esta en el quote")]
    PcrAusente(u32),
    /// El PCR presentado no cumple la exigencia.
    #[error("el PCR {0} no cumple la politica")]
    PcrNoCumple(u32),
}

/// Una politica de PCR, expresada como tipo.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PoliticaPcr {
    exigencias: BTreeMap<u32, ExigenciaPcr>,
}

impl PoliticaPcr {
    /// Una politica vacia (no exige nada; toda presentacion la cumple).
    #[must_use]
    pub fn nueva() -> PoliticaPcr {
        PoliticaPcr::default()
    }

    /// Exige que un PCR sea exactamente `valor`. Si ya hay una exigencia
    /// incompatible para ese PCR, devuelve `Err`: la contradiccion no se guarda.
    pub fn exigir_igual(mut self, pcr: u32, valor: Vec<u8>) -> Result<PoliticaPcr, ErrorPolitica> {
        if let Some(ex) = self.exigencias.get(&pcr) {
            if !ex.admite(&valor) {
                return Err(ErrorPolitica::Contradiccion(pcr));
            }
        }
        self.exigencias.insert(pcr, ExigenciaPcr::Igual(valor));
        Ok(self)
    }

    /// Exige que un PCR sea uno de `valores`. Si ya habia una exigencia `Igual`
    /// cuyo valor no esta en el conjunto, es una contradiccion.
    pub fn exigir_uno_de(
        mut self,
        pcr: u32,
        valores: impl IntoIterator<Item = Vec<u8>>,
    ) -> Result<PoliticaPcr, ErrorPolitica> {
        let conjunto: BTreeSet<Vec<u8>> = valores.into_iter().collect();
        if let Some(ExigenciaPcr::Igual(v)) = self.exigencias.get(&pcr) {
            if !conjunto.contains(v) {
                return Err(ErrorPolitica::Contradiccion(pcr));
            }
        }
        self.exigencias.insert(pcr, ExigenciaPcr::UnoDe(conjunto));
        Ok(self)
    }

    /// Cuantos PCR gobierna la politica.
    #[must_use]
    pub fn len(&self) -> usize {
        self.exigencias.len()
    }

    /// Si no exige nada.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.exigencias.is_empty()
    }

    /// Evalua la politica contra los PCR presentados en un quote. Devuelve el
    /// primer incumplimiento, para que el operador sepa cual.
    pub fn evaluar(&self, presentados: &[(u32, Vec<u8>)]) -> Result<(), ErrorPolitica> {
        for (pcr, ex) in &self.exigencias {
            match presentados.iter().find(|(p, _)| p == pcr) {
                None => return Err(ErrorPolitica::PcrAusente(*pcr)),
                Some((_, valor)) if !ex.admite(valor) => {
                    return Err(ErrorPolitica::PcrNoCumple(*pcr))
                }
                Some(_) => {}
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn una_politica_contradictoria_no_llega_a_existir() {
        // Exigir PCR 7 == X y luego PCR 7 == Y es Err: la contradiccion se rechaza
        // en el sitio, no se descubre en produccion.
        let p = PoliticaPcr::nueva().exigir_igual(7, vec![0xAA]).unwrap();
        assert_eq!(
            p.exigir_igual(7, vec![0xBB]),
            Err(ErrorPolitica::Contradiccion(7))
        );
    }

    #[test]
    fn exigir_el_mismo_valor_dos_veces_no_es_contradiccion() {
        let p = PoliticaPcr::nueva()
            .exigir_igual(7, vec![0xAA])
            .unwrap()
            .exigir_igual(7, vec![0xAA])
            .unwrap();
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn evalua_igual_y_uno_de() {
        let p = PoliticaPcr::nueva()
            .exigir_igual(0, vec![1, 2, 3])
            .unwrap()
            .exigir_uno_de(7, [vec![0xAA], vec![0xBB]])
            .unwrap();
        // Un arranque bueno conocido.
        assert!(p.evaluar(&[(0, vec![1, 2, 3]), (7, vec![0xBB])]).is_ok());
        // PCR 0 cambiado: no cumple.
        assert_eq!(
            p.evaluar(&[(0, vec![9, 9]), (7, vec![0xAA])]),
            Err(ErrorPolitica::PcrNoCumple(0))
        );
        // Falta el PCR 7 en el quote: ausente.
        assert_eq!(
            p.evaluar(&[(0, vec![1, 2, 3])]),
            Err(ErrorPolitica::PcrAusente(7))
        );
    }
}
