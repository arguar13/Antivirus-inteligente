//! Cuando un perfil no basta: la microVM.
//!
//! # Hasta donde llega un perfil
//!
//! Un perfil de seccomp y Landlock reduce lo que un proceso puede pedirle al
//! kernel, pero lo que pide sigue ejecutandose en EL kernel de la maquina: una
//! vulnerabilidad en una de las llamadas que el perfil permite es un escape. Para
//! la mayoria de procesos es la proporcion correcta entre coste y proteccion.
//! Para un proceso de riesgo alto —el que el arbitro ya ha marcado, el que abre
//! lo que llega de fuera— la proporcion es otra: lo que toca es otro kernel, el
//! de una microVM, que es lo que hacen gVisor y Kata.
//!
//! El producto ya tiene esa jaula: la de detonacion (FASE 73). Aqui no se
//! construye otra; se decide cuando hace falta y se prepara la solicitud, que el
//! plano de control atiende. Lo que no se puede hacer en esta maquina —no hay
//! `/dev/kvm`— se dice, no se sustituye por un perfil en silencio.

use std::path::{Path, PathBuf};

use crate::perfil::Perfil;

/// El riesgo de un proceso, segun lo que el arbitro sabe de el.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Riesgo {
    /// Nada en contra.
    Bajo,
    /// Sospechoso o expuesto.
    Medio,
    /// Marcado por el arbitro, o que procesa entrada de fuera sin autenticar.
    Alto,
}

/// Lo que se pide al plano de control para aislar un proceso en la microVM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolicitudJaula {
    /// El ejecutable.
    pub ejecutable: PathBuf,
    /// El perfil aprendido, en texto: dentro de la jaula tambien se impone.
    pub perfil: String,
    /// Por que.
    pub motivo: String,
}

/// Como se aisla un proceso.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Aislamiento {
    /// Con el perfil, en esta maquina.
    Perfil,
    /// En la microVM de la jaula de detonacion, con el perfil dentro.
    MicroVm(SolicitudJaula),
}

/// Por que no se puede aislar como haria falta.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NoDisponible {
    /// Hace falta la microVM y aqui no hay virtualizacion.
    #[error("el riesgo exige una microVM y esta maquina no tiene /dev/kvm: se declara, no se sustituye por un perfil en silencio")]
    SinVirtualizacion,
}

/// Si esta maquina puede arrancar una microVM.
#[must_use]
pub fn kvm_disponible() -> bool {
    Path::new("/dev/kvm").exists()
}

/// Decide como aislar.
///
/// # Errores
/// [`NoDisponible`] si el riesgo exige la microVM y no la hay.
pub fn decidir(riesgo: Riesgo, perfil: &Perfil, kvm: bool) -> Result<Aislamiento, NoDisponible> {
    match riesgo {
        Riesgo::Bajo | Riesgo::Medio => Ok(Aislamiento::Perfil),
        Riesgo::Alto if !kvm => Err(NoDisponible::SinVirtualizacion),
        Riesgo::Alto => Ok(Aislamiento::MicroVm(SolicitudJaula {
            ejecutable: perfil.ejecutable.clone(),
            perfil: perfil.texto(),
            motivo: "riesgo alto: un perfil deja al proceso en el mismo kernel, la microVM no"
                .into(),
        })),
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn el_riesgo_alto_va_a_la_microvm_y_sin_kvm_se_dice() {
        let p = Perfil::nuevo(Path::new("/usr/bin/x"));
        assert_eq!(decidir(Riesgo::Bajo, &p, true), Ok(Aislamiento::Perfil));
        assert_eq!(decidir(Riesgo::Medio, &p, false), Ok(Aislamiento::Perfil));
        assert!(matches!(
            decidir(Riesgo::Alto, &p, true),
            Ok(Aislamiento::MicroVm(_))
        ));
        assert_eq!(
            decidir(Riesgo::Alto, &p, false),
            Err(NoDisponible::SinVirtualizacion)
        );
    }

    #[test]
    fn esta_maquina_dice_si_puede() {
        eprintln!("/dev/kvm en esta maquina: {}", kvm_disponible());
    }
}
