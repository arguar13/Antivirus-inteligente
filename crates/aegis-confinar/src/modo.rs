//! Los tres modos, y por que el obligatorio no se puede construir por descuido.
//!
//! # El modo por defecto es el que no rompe nada
//!
//! [`Modo::default`] es [`Modo::Aprendiendo`]. No es una preferencia: un
//! confinamiento que se despliega obligatorio por defecto rompe al cliente la
//! primera vez que un programa hace algo que el perfil no vio, y el cliente lo
//! quita de toda la flota. Primero se aprende, luego se ensaya, y solo entonces
//! se impone.
//!
//! # El obligatorio exige una confirmacion, y el tipo lo hace cumplir
//!
//! [`Modo::Obligatorio`] lleva dentro una [`Confirmacion`], y una `Confirmacion`
//! solo se construye con [`Confirmacion::nueva`], que exige quien y por que. Sus
//! campos son privados, asi que no se puede fabricar una a mano (`E0451`):
//!
//! ```compile_fail,E0451
//! use aegis_confinar::modo::{Confirmacion, Modo};
//! let m = Modo::Obligatorio(Confirmacion {
//!     quien: String::new(),
//!     motivo: String::new(),
//!     cuando_ns: 0,
//! });
//! ```
//!
//! Y no tiene valor por defecto que sirva de atajo (`E0599`):
//!
//! ```compile_fail,E0599
//! use aegis_confinar::modo::Confirmacion;
//! let c = Confirmacion::default();
//! ```

/// Por que una confirmacion no vale.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfirmacionInvalida {
    /// No dice quien confirma.
    #[error("una confirmacion sin autor no confirma nada")]
    SinAutor,
    /// No dice por que.
    #[error("una confirmacion sin motivo no se puede revisar despues")]
    SinMotivo,
}

/// La confirmacion explicita de que un perfil se impone.
///
/// Queda en el rastro: cuando un perfil rompa algo, lo primero que se pregunta
/// es quien lo impuso y por que.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confirmacion {
    quien: String,
    motivo: String,
    cuando_ns: u64,
}

impl Confirmacion {
    /// Construye una confirmacion.
    ///
    /// # Errores
    /// Si falta el autor o el motivo.
    pub fn nueva(
        quien: &str,
        motivo: &str,
        cuando_ns: u64,
    ) -> Result<Confirmacion, ConfirmacionInvalida> {
        let (quien, motivo) = (quien.trim(), motivo.trim());
        if quien.is_empty() {
            return Err(ConfirmacionInvalida::SinAutor);
        }
        if motivo.is_empty() {
            return Err(ConfirmacionInvalida::SinMotivo);
        }
        Ok(Confirmacion {
            quien: quien.to_string(),
            motivo: motivo.to_string(),
            cuando_ns,
        })
    }

    /// Quien confirmo.
    #[must_use]
    pub fn quien(&self) -> &str {
        &self.quien
    }

    /// Por que.
    #[must_use]
    pub fn motivo(&self) -> &str {
        &self.motivo
    }

    /// Cuando.
    #[must_use]
    pub fn cuando_ns(&self) -> u64 {
        self.cuando_ns
    }
}

/// En que modo corre un proceso confinable.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Modo {
    /// Se observa todo y no se bloquea nada. El modo por defecto.
    #[default]
    Aprendiendo,
    /// Se deja pasar todo y se anota lo que el perfil habria bloqueado.
    Permisivo,
    /// Se impone el perfil. Solo con confirmacion.
    Obligatorio(Confirmacion),
}

impl Modo {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(&self) -> &'static str {
        match self {
            Modo::Aprendiendo => "aprendiendo",
            Modo::Permisivo => "permisivo",
            Modo::Obligatorio(_) => "obligatorio",
        }
    }

    /// Si este modo puede bloquear algo.
    #[must_use]
    pub fn bloquea(&self) -> bool {
        matches!(self, Modo::Obligatorio(_))
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn el_modo_por_defecto_es_el_que_no_bloquea_nada() {
        assert_eq!(Modo::default(), Modo::Aprendiendo);
        assert!(!Modo::default().bloquea());
        assert!(!Modo::Permisivo.bloquea());
    }

    #[test]
    fn una_confirmacion_exige_autor_y_motivo() {
        assert_eq!(
            Confirmacion::nueva("", "x", 0),
            Err(ConfirmacionInvalida::SinAutor)
        );
        assert_eq!(
            Confirmacion::nueva("  ", "x", 0),
            Err(ConfirmacionInvalida::SinAutor)
        );
        assert_eq!(
            Confirmacion::nueva("ana", " ", 0),
            Err(ConfirmacionInvalida::SinMotivo)
        );
        let c = Confirmacion::nueva(" ana ", " ensayo limpio 7 dias ", 5).expect("valida");
        assert_eq!(c.quien(), "ana");
        assert_eq!(c.motivo(), "ensayo limpio 7 dias");
        assert!(Modo::Obligatorio(c).bloquea());
    }
}
