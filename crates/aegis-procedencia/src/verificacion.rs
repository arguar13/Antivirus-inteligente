//! La atestacion se verifica EN EL ENDPOINT, ANTES de aplicar (FASE 108).
//!
//! SLSA es un marco de publicacion: alguien firma y alguien, quiza, comprueba.
//! Aqui la verificacion esta en el CAMINO CRITICO: el agente NO aplica una
//! actualizacion cuya atestacion no case con su SBOM y con su politica. No es un
//! informe que se lee despues; es una puerta que no se abre. Y cada rechazo se
//! REGISTRA: un rechazo silencioso es una actualizacion maliciosa que nadie
//! investiga.

/// La atestacion que acompana a una actualizacion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Atestacion {
    /// Huella (BLAKE3) del artefacto atestado.
    pub huella_artefacto: [u8; 32],
    /// Si la construccion es reproducible bit a bit (demostrado por dos builds).
    pub reproducible: bool,
    /// Si la firma hibrida del artefacto verifico (la hace `aegis-update`; aqui
    /// llega el resultado).
    pub firma_valida: bool,
    /// Si la cadena de procedencia (ver [`crate::cadena`]) esta completa.
    pub cadena_completa: bool,
}

/// Lo que el endpoint ESPERA: la huella del artefacto de su SBOM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sbom {
    /// Huella del artefacto que el endpoint espera aplicar.
    pub huella_esperada: [u8; 32],
}

/// Lo que la politica del endpoint EXIGE antes de aplicar.
#[derive(Debug, Clone, Copy)]
pub struct PoliticaAplicacion {
    /// Exigir que la construccion sea reproducible.
    pub exige_reproducible: bool,
    /// Exigir firma valida (siempre deberia ser `true`).
    pub exige_firma: bool,
    /// Exigir la cadena de procedencia completa.
    pub exige_cadena: bool,
}

impl PoliticaAplicacion {
    /// La politica estricta: lo exige todo. Es la que debe correr en produccion.
    #[must_use]
    pub fn estricta() -> PoliticaAplicacion {
        PoliticaAplicacion {
            exige_reproducible: true,
            exige_firma: true,
            exige_cadena: true,
        }
    }
}

/// La decision de la puerta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Se puede aplicar: la atestacion casa con el SBOM y cumple la politica.
    Aplicar,
    /// NO se aplica, con su motivo. El motivo se registra.
    Rechazar {
        /// Por que no se aplica.
        motivo: String,
    },
}

impl Decision {
    /// Si se aplica.
    #[must_use]
    pub fn se_aplica(&self) -> bool {
        matches!(self, Decision::Aplicar)
    }
}

/// La puerta: decide si aplicar una actualizacion. El orden comprueba primero la
/// firma (sin ella, todo lo demas son datos de un atacante), luego que el artefacto
/// sea el del SBOM, y luego el resto de la politica.
#[must_use]
pub fn verificar_antes_de_aplicar(
    atestacion: &Atestacion,
    sbom: &Sbom,
    politica: PoliticaAplicacion,
) -> Decision {
    if politica.exige_firma && !atestacion.firma_valida {
        return Decision::Rechazar {
            motivo: "la firma del artefacto no verifica: no se aplica".to_string(),
        };
    }
    if atestacion.huella_artefacto != sbom.huella_esperada {
        return Decision::Rechazar {
            motivo: "la huella del artefacto atestado NO coincide con la del SBOM del endpoint: \
                     la atestacion es de otro artefacto"
                .to_string(),
        };
    }
    if politica.exige_cadena && !atestacion.cadena_completa {
        return Decision::Rechazar {
            motivo: "la cadena de procedencia esta incompleta: hay un eslabon roto".to_string(),
        };
    }
    if politica.exige_reproducible && !atestacion.reproducible {
        return Decision::Rechazar {
            motivo: "la construccion no es reproducible: no se puede confirmar que el binario \
                     salio de la fuente auditada"
                .to_string(),
        };
    }
    Decision::Aplicar
}

/// La bitacora de rechazos: cada actualizacion no aplicada, con su motivo. Un
/// rechazo que no se registra es un ataque que nadie investiga.
#[derive(Debug, Clone, Default)]
pub struct Bitacora {
    rechazos: Vec<String>,
}

impl Bitacora {
    /// Una bitacora vacia.
    #[must_use]
    pub fn nueva() -> Bitacora {
        Bitacora::default()
    }

    /// Evalua y, si se rechaza, lo registra. Devuelve la decision.
    pub fn evaluar_y_registrar(
        &mut self,
        atestacion: &Atestacion,
        sbom: &Sbom,
        politica: PoliticaAplicacion,
    ) -> Decision {
        let d = verificar_antes_de_aplicar(atestacion, sbom, politica);
        if let Decision::Rechazar { motivo } = &d {
            self.rechazos.push(motivo.clone());
        }
        d
    }

    /// Cuantos rechazos se han registrado.
    #[must_use]
    pub fn rechazos(&self) -> usize {
        self.rechazos.len()
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn atest_buena() -> Atestacion {
        Atestacion {
            huella_artefacto: [7u8; 32],
            reproducible: true,
            firma_valida: true,
            cadena_completa: true,
        }
    }
    fn sbom() -> Sbom {
        Sbom {
            huella_esperada: [7u8; 32],
        }
    }

    #[test]
    fn una_atestacion_buena_se_aplica() {
        let d = verificar_antes_de_aplicar(&atest_buena(), &sbom(), PoliticaAplicacion::estricta());
        assert!(d.se_aplica());
    }

    #[test]
    fn una_atestacion_manipulada_se_rechaza_y_se_registra() {
        // El atacante cambia el artefacto pero deja la firma «valida»: la huella ya
        // no casa con el SBOM del endpoint.
        let mut mala = atest_buena();
        mala.huella_artefacto = [66u8; 32];
        let mut b = Bitacora::nueva();
        let d = b.evaluar_y_registrar(&mala, &sbom(), PoliticaAplicacion::estricta());
        assert!(!d.se_aplica());
        assert_eq!(b.rechazos(), 1, "el rechazo se registra");
    }

    #[test]
    fn sin_firma_no_se_aplica_aunque_todo_lo_demas_case() {
        let mut mala = atest_buena();
        mala.firma_valida = false;
        assert!(
            !verificar_antes_de_aplicar(&mala, &sbom(), PoliticaAplicacion::estricta()).se_aplica()
        );
    }

    #[test]
    fn sin_reproducibilidad_ni_cadena_se_rechaza_bajo_politica_estricta() {
        let mut a = atest_buena();
        a.reproducible = false;
        assert!(
            !verificar_antes_de_aplicar(&a, &sbom(), PoliticaAplicacion::estricta()).se_aplica()
        );
        let mut c = atest_buena();
        c.cadena_completa = false;
        assert!(
            !verificar_antes_de_aplicar(&c, &sbom(), PoliticaAplicacion::estricta()).se_aplica()
        );
    }
}
