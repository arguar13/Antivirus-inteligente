//! Construccion reproducible bit a bit, demostrada por DOS builds (FASE 108).
//!
//! in-toto atestigua lo que PASO; esto demuestra que se puede REPETIR, que es una
//! afirmacion mucho mas fuerte y que casi nadie sostiene. Dos construcciones del
//! mismo commit en maquinas distintas tienen que dar el MISMO binario, byte a byte.
//! Lo que no sea reproducible no se maquilla: se declara con su motivo exacto —una
//! marca de tiempo en un `build.rs`, una ruta absoluta incrustada— para que se
//! arregle la causa.
//!
//! Aqui esta la DECISION («dos huellas iguales ⇒ reproducible; distintas ⇒ se dice
//! por que»); las dos construcciones de verdad las hace `tools/construir-reproducible.sh`.

/// La huella (BLAKE3) de un artefacto construido.
pub type HuellaConstruccion = [u8; 32];

/// Huella de unos bytes de artefacto.
#[must_use]
pub fn huella(artefacto: &[u8]) -> HuellaConstruccion {
    *blake3::hash(artefacto).as_bytes()
}

/// El resultado de comparar dos construcciones del mismo commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reproducibilidad {
    /// Las dos construcciones dieron el mismo binario: reproducible.
    Reproducible {
        /// La huella comun.
        huella: HuellaConstruccion,
    },
    /// Difirieron: NO reproducible. Se declara el motivo para arreglar la causa.
    NoReproducible {
        /// Que se sabe de la diferencia (para el plan de arreglo).
        motivo: String,
    },
}

impl Reproducibilidad {
    /// Si es reproducible.
    #[must_use]
    pub fn es_reproducible(&self) -> bool {
        matches!(self, Reproducibilidad::Reproducible { .. })
    }
}

/// Compara dos construcciones del mismo commit hechas en maquinas distintas.
#[must_use]
pub fn comparar(a: HuellaConstruccion, b: HuellaConstruccion) -> Reproducibilidad {
    if a == b {
        Reproducibilidad::Reproducible { huella: a }
    } else {
        // Se dice el primer byte que difiere: es la pista para encontrar la causa
        // (una marca de tiempo, un orden no determinista, una ruta incrustada).
        let primer = a
            .iter()
            .zip(b.iter())
            .position(|(x, y)| x != y)
            .unwrap_or(0);
        Reproducibilidad::NoReproducible {
            motivo: format!(
                "las dos construcciones difieren (primer byte distinto de la huella: #{primer}): \
                 hay una fuente de no-determinismo (marca de tiempo, orden, ruta incrustada) que \
                 arreglar en la causa, no maquillar"
            ),
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn dos_construcciones_identicas_son_reproducibles() {
        let a = huella(b"el mismo binario, byte a byte");
        let b = huella(b"el mismo binario, byte a byte");
        let r = comparar(a, b);
        assert!(r.es_reproducible());
        assert_eq!(r, Reproducibilidad::Reproducible { huella: a });
    }

    #[test]
    fn una_diferencia_se_declara_no_se_maquilla() {
        let a = huella(b"binario con marca de tiempo 12:00");
        let b = huella(b"binario con marca de tiempo 12:01");
        let r = comparar(a, b);
        assert!(!r.es_reproducible());
        assert!(matches!(r, Reproducibilidad::NoReproducible { .. }));
    }
}
