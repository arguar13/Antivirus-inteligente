//! El rasgo de una tecnica emulable, con la reversion obligatoria por tipo, y las
//! catorce tacticas de ATT&CK Enterprise.
//!
//! # La reversion es parte del tipo
//!
//! [`Tecnica::revertir`] **no tiene cuerpo por defecto**. Una emulacion que no diga
//! como se deshace no implementa el rasgo, y no compila. No es una convencion que
//! se pueda olvidar: es la firma del rasgo. Una prueba de cobertura que deja una
//! puerta trasera abierta es un incidente, y esta es la barrera que lo impide de
//! raiz.
//!
//! # La ejecucion exige la prueba de estar en el rango
//!
//! [`Tecnica::ejecutar`] toma una [`PruebaDeRango`], que solo acuna un [`Rango`]
//! declarado. No hay forma de llamar a `ejecutar` fuera de un rango: el tipo no la
//! ofrece.
//!
//! Una tecnica sin reversion **no compila** (falta el item del rasgo, E0046):
//!
//! ```compile_fail,E0046
//! use aegis_rango::tecnica::{Tactica, Tecnica};
//! use aegis_rango::rango::{ErrorRango, Plataforma, PruebaDeRango, Rango};
//! use aegis_entidad::{entidad, Eid, Motor};
//! struct SinReversion;
//! impl Tecnica for SinReversion {
//!     fn id(&self) -> &str { "T0000" }
//!     fn nombre(&self) -> &str { "sin reversion" }
//!     fn tactica(&self) -> Tactica { Tactica::Impacto }
//!     fn plataformas(&self) -> &[Plataforma] { &[Plataforma::Linux] }
//!     fn deteccion_esperada(&self) -> Motor { Motor::Conductual }
//!     fn entidad_afectada(&self, _r: &Rango) -> Eid { entidad::contenido("x") }
//!     fn ejecutar(&self, _p: &PruebaDeRango, _r: &Rango) -> Result<(), ErrorRango> { Ok(()) }
//!     fn exito(&self, _r: &Rango) -> bool { false }
//!     // falta `revertir`: el rasgo no se implementa, y esto NO compila.
//! }
//! ```

use aegis_entidad::{Eid, Motor};

use crate::rango::{ErrorRango, Plataforma, PruebaDeRango, Rango};

/// Una tactica de ATT&CK Enterprise. Las catorce, para que el informe de cobertura
/// pueda decir «esta tactica no la mira ningun motor» en vez de callarla.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tactica {
    /// TA0043 — Reconnaissance.
    Reconocimiento,
    /// TA0042 — Resource Development.
    DesarrolloDeRecursos,
    /// TA0001 — Initial Access.
    AccesoInicial,
    /// TA0002 — Execution.
    Ejecucion,
    /// TA0003 — Persistence.
    Persistencia,
    /// TA0004 — Privilege Escalation.
    EscaladaDePrivilegios,
    /// TA0005 — Defense Evasion.
    EvasionDefensiva,
    /// TA0006 — Credential Access.
    AccesoACredenciales,
    /// TA0007 — Discovery.
    Descubrimiento,
    /// TA0008 — Lateral Movement.
    MovimientoLateral,
    /// TA0009 — Collection.
    Recoleccion,
    /// TA0011 — Command and Control.
    MandoYControl,
    /// TA0010 — Exfiltration.
    Exfiltracion,
    /// TA0040 — Impact.
    Impacto,
}

impl Tactica {
    /// El identificador ATT&CK de la tactica.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Tactica::Reconocimiento => "TA0043",
            Tactica::DesarrolloDeRecursos => "TA0042",
            Tactica::AccesoInicial => "TA0001",
            Tactica::Ejecucion => "TA0002",
            Tactica::Persistencia => "TA0003",
            Tactica::EscaladaDePrivilegios => "TA0004",
            Tactica::EvasionDefensiva => "TA0005",
            Tactica::AccesoACredenciales => "TA0006",
            Tactica::Descubrimiento => "TA0007",
            Tactica::MovimientoLateral => "TA0008",
            Tactica::Recoleccion => "TA0009",
            Tactica::MandoYControl => "TA0011",
            Tactica::Exfiltracion => "TA0010",
            Tactica::Impacto => "TA0040",
        }
    }

    /// Nombre legible.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Tactica::Reconocimiento => "reconocimiento",
            Tactica::DesarrolloDeRecursos => "desarrollo de recursos",
            Tactica::AccesoInicial => "acceso inicial",
            Tactica::Ejecucion => "ejecucion",
            Tactica::Persistencia => "persistencia",
            Tactica::EscaladaDePrivilegios => "escalada de privilegios",
            Tactica::EvasionDefensiva => "evasion defensiva",
            Tactica::AccesoACredenciales => "acceso a credenciales",
            Tactica::Descubrimiento => "descubrimiento",
            Tactica::MovimientoLateral => "movimiento lateral",
            Tactica::Recoleccion => "recoleccion",
            Tactica::MandoYControl => "mando y control",
            Tactica::Exfiltracion => "exfiltracion",
            Tactica::Impacto => "impacto",
        }
    }

    /// Las catorce tacticas, para recorrerlas sin olvidar ninguna.
    #[must_use]
    pub fn todas() -> &'static [Tactica] {
        &[
            Tactica::Reconocimiento,
            Tactica::DesarrolloDeRecursos,
            Tactica::AccesoInicial,
            Tactica::Ejecucion,
            Tactica::Persistencia,
            Tactica::EscaladaDePrivilegios,
            Tactica::EvasionDefensiva,
            Tactica::AccesoACredenciales,
            Tactica::Descubrimiento,
            Tactica::MovimientoLateral,
            Tactica::Recoleccion,
            Tactica::MandoYControl,
            Tactica::Exfiltracion,
            Tactica::Impacto,
        ]
    }
}

/// Una tecnica de ATT&CK que el rango sabe emular de forma benigna y reversible, y
/// medir si la deteccion la ve.
///
/// # Contrato
///
/// - [`Tecnica::ejecutar`] materializa el gesto minimo que la deteccion deberia
///   ver, **dentro de la jaula del rango** y nada mas.
/// - [`Tecnica::revertir`] lo deshace. **No tiene cuerpo por defecto**: sin ella no
///   se implementa el rasgo.
/// - [`Tecnica::exito`] comprueba, mirando el estado real del rango, que la
///   ejecucion (o la reversion) dejo lo que debia.
pub trait Tecnica {
    /// El identificador ATT&CK de la tecnica (p. ej. `T1053`).
    fn id(&self) -> &str;

    /// Nombre legible de la tecnica.
    fn nombre(&self) -> &str;

    /// La tactica a la que pertenece.
    fn tactica(&self) -> Tactica;

    /// Las plataformas donde la tecnica aplica.
    fn plataformas(&self) -> &[Plataforma];

    /// El motor del producto que **deberia** detectarla. Es contra lo que el rango
    /// contrasta el veredicto del arbitro para decidir detectada / hueco.
    fn deteccion_esperada(&self) -> Motor;

    /// La entidad sobre la que recae la emulacion, en el modelo unico. Es por la
    /// que el rango pregunta al arbitro.
    fn entidad_afectada(&self, rango: &Rango) -> Eid;

    /// Ejecuta la emulacion benigna dentro del rango.
    ///
    /// # Errores
    /// [`ErrorRango`] si el gesto no se pudo materializar.
    fn ejecutar(&self, prueba: &PruebaDeRango, rango: &Rango) -> Result<(), ErrorRango>;

    /// Deshace la emulacion. **Obligatoria: sin cuerpo por defecto.**
    ///
    /// # Errores
    /// [`ErrorRango`] si la reversion no se pudo completar.
    fn revertir(&self, prueba: &PruebaDeRango, rango: &Rango) -> Result<(), ErrorRango>;

    /// Comprueba, contra el estado real del rango, si la emulacion esta presente.
    /// El rango lo usa para verificar la ejecucion y, tras revertir, que no queda
    /// residuo.
    fn exito(&self, rango: &Rango) -> bool;

    /// Si la tecnica aplica en una plataforma. Con cuerpo por defecto: derivarlo de
    /// la lista es lo correcto y no hay motivo para reescribirlo por tecnica.
    fn aplica_en(&self, plataforma: Plataforma) -> bool {
        self.plataformas().contains(&plataforma)
    }
}
