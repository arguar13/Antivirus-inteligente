//! Una sola cadena de procedencia: fuente → ... → medida en el TPM (FASE 108).
//!
//! in-toto, SLSA y Sigstore reparten la procedencia en varios sistemas que se
//! apuntan entre si: uno firma, otro atestigua, otro publica. Aqui es UNA cadena,
//! con un `Eid` del modelo unico por eslabon, y se verifica que es contigua desde
//! la fuente hasta la medida en el TPM del endpoint (FASE 105). Un hueco —falta el
//! hash del compilador entre las dependencias y el artefacto— es un eslabon roto:
//! sin la cadena entera, no se sabe que el binario que corre salio de la fuente que
//! se audito.

use aegis_entidad::Eid;

/// Un eslabon de la cadena de procedencia, en orden de construccion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Eslabon {
    /// El codigo fuente (su hash / commit).
    Fuente,
    /// Las dependencias, cada una con su hash fijado.
    Dependencias,
    /// El compilador, con su hash: dos compiladores distintos dan binarios
    /// distintos, asi que forma parte de la procedencia.
    Compilador,
    /// El artefacto producido.
    Artefacto,
    /// La firma hibrida (clasica + post-cuantica) del artefacto.
    Firma,
    /// La atestacion de que ese artefacto salio de esa fuente con ese compilador.
    Atestacion,
    /// El despliegue en el endpoint.
    Despliegue,
    /// La medida en el TPM del endpoint (FASE 105): la cadena llega hasta el
    /// hardware.
    MedidaTpm,
}

impl Eslabon {
    /// Los eslabones en orden de cadena.
    #[must_use]
    pub fn en_orden() -> [Eslabon; 8] {
        [
            Eslabon::Fuente,
            Eslabon::Dependencias,
            Eslabon::Compilador,
            Eslabon::Artefacto,
            Eslabon::Firma,
            Eslabon::Atestacion,
            Eslabon::Despliegue,
            Eslabon::MedidaTpm,
        ]
    }

    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Eslabon::Fuente => "fuente",
            Eslabon::Dependencias => "dependencias",
            Eslabon::Compilador => "compilador",
            Eslabon::Artefacto => "artefacto",
            Eslabon::Firma => "firma",
            Eslabon::Atestacion => "atestacion",
            Eslabon::Despliegue => "despliegue",
            Eslabon::MedidaTpm => "medida-tpm",
        }
    }
}

/// La cadena de procedencia: cada eslabon con la entidad que lo encarna.
#[derive(Debug, Clone, Default)]
pub struct CadenaProcedencia {
    eslabones: Vec<(Eslabon, Eid)>,
}

impl CadenaProcedencia {
    /// Una cadena vacia.
    #[must_use]
    pub fn nueva() -> CadenaProcedencia {
        CadenaProcedencia::default()
    }

    /// Anade un eslabon.
    #[must_use]
    pub fn con(mut self, eslabon: Eslabon, eid: Eid) -> CadenaProcedencia {
        self.eslabones.push((eslabon, eid));
        self
    }

    /// Verifica que la cadena es contigua desde `Fuente` hasta el eslabon mas alto
    /// presente, sin huecos. Devuelve el primer eslabon que FALTA si esta rota.
    pub fn verificar(&self) -> Result<(), Eslabon> {
        let presentes: std::collections::BTreeSet<Eslabon> =
            self.eslabones.iter().map(|(e, _)| *e).collect();
        if presentes.is_empty() {
            return Err(Eslabon::Fuente);
        }
        let mas_alto = *presentes.iter().max().expect("no vacio");
        for e in Eslabon::en_orden() {
            if e > mas_alto {
                break;
            }
            if !presentes.contains(&e) {
                return Err(e);
            }
        }
        Ok(())
    }

    /// `true` si la cadena llega hasta la medida en el TPM: la procedencia esta
    /// atada al hardware del endpoint, no solo a una firma en un servidor.
    #[must_use]
    pub fn llega_al_tpm(&self) -> bool {
        self.verificar().is_ok() && self.eslabones.iter().any(|(e, _)| *e == Eslabon::MedidaTpm)
    }

    /// Los eslabones, en orden de insercion.
    #[must_use]
    pub fn eslabones(&self) -> &[(Eslabon, Eid)] {
        &self.eslabones
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_entidad::entidad;

    fn eid(n: u32) -> Eid {
        entidad::contenido(&format!("{n:064x}"))
    }

    fn cadena_completa() -> CadenaProcedencia {
        let mut c = CadenaProcedencia::nueva();
        for (i, e) in Eslabon::en_orden().into_iter().enumerate() {
            c = c.con(e, eid(i as u32));
        }
        c
    }

    #[test]
    fn una_cadena_completa_verifica_y_llega_al_tpm() {
        let c = cadena_completa();
        assert_eq!(c.verificar(), Ok(()));
        assert!(c.llega_al_tpm());
    }

    #[test]
    fn un_hueco_es_un_eslabon_roto() {
        // Falta el compilador: no se sabe con que se construyo el artefacto.
        let c = CadenaProcedencia::nueva()
            .con(Eslabon::Fuente, eid(1))
            .con(Eslabon::Dependencias, eid(2))
            .con(Eslabon::Artefacto, eid(4));
        assert_eq!(c.verificar(), Err(Eslabon::Compilador));
        assert!(!c.llega_al_tpm());
    }

    #[test]
    fn una_cadena_sin_tpm_verifica_pero_no_llega_al_hardware() {
        let mut c = CadenaProcedencia::nueva();
        for (i, e) in Eslabon::en_orden().into_iter().take(7).enumerate() {
            c = c.con(e, eid(i as u32));
        }
        assert_eq!(c.verificar(), Ok(()));
        assert!(
            !c.llega_al_tpm(),
            "sin la medida del TPM, no llega al hardware"
        );
    }
}
