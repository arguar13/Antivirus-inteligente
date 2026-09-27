//! Exposiciones de identidad: las configuraciones debiles del directorio, cada
//! una con su remediacion, y los huecos declarados cuando no se pudo mirar.
//!
//! # Que hace esta fase, dicho sin rodeos
//!
//! Lee el directorio en **solo lectura** y senala lo que esta mal configurado
//! para que el dueno de la flota lo **arregle**: una delegacion sin restricciones,
//! un grupo privilegiado demasiado amplio, una cuenta cuya credencial no caduca,
//! una ACL que le da a un principal raso control sobre uno privilegiado, una
//! plantilla de certificado que cualquiera puede usar para suplantar a un
//! administrador. Cada hallazgo sale con su **remediacion concreta**: no «hay un
//! problema» sino «quita este bit», «saca a esta cuenta de este grupo», «exige
//! aprobacion del gestor en esta plantilla».
//!
//! # El tri-estado, que es la diferencia con las herramientas de reconocimiento
//!
//! Un atributo que no se pudo leer —sin privilegio, o el objeto cambio durante la
//! lectura— produce un [`Hueco`] con su motivo, **nunca** una ausencia silenciosa
//! que se leeria como «aqui no hay nada mal». Una lista de exposiciones vacia
//! junto a una lista de huecos vacia significa «se miro todo y esta bien»; una
//! lista de exposiciones vacia con huecos significa «no se pudo mirar esto».

use aegis_entidad::Eid;

use crate::Severidad;

/// La familia de una exposicion de identidad, con su identificador estable para
/// el informe y el seguimiento.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaseExposicion {
    /// Un equipo con delegacion Kerberos sin restricciones: guarda los tickets de
    /// todo el que se autentica en el.
    DelegacionSinRestricciones,
    /// Delegacion restringida basada en recursos configurada de forma que un
    /// principal de bajo privilegio puede actuar en nombre de uno alto.
    DelegacionBasadaEnRecursos,
    /// Un grupo privilegiado (Domain/Enterprise/Schema Admins) con demasiados
    /// miembros directos o anidados.
    GrupoPrivilegiadoAmplio,
    /// Una cuenta privilegiada cuya contrasena no caduca, o que no tiene fecha de
    /// caducidad de cuenta.
    CuentaSinCaducidad,
    /// Una ACL que da a un principal control sobre otro de mayor privilegio: el
    /// camino de escalada silenciosa.
    AclPeligrosa,
    /// Una plantilla de certificado configurada de forma que permite suplantar a
    /// otra identidad (familia ESC).
    PlantillaCertificadoDebil,
    /// Una relacion de confianza que abre un camino desde un dominio menos
    /// protegido.
    ConfianzaPeligrosa,
    /// Una cuenta privilegiada marcada como delegable (sin el bit «sensible, no
    /// delegable»): si un equipo con delegacion la captura, se suplanta.
    CuentaPrivilegiadaDelegable,
}

impl ClaseExposicion {
    /// El identificador estable de la clase, para el informe y el seguimiento.
    #[must_use]
    pub fn identificador(self) -> &'static str {
        match self {
            ClaseExposicion::DelegacionSinRestricciones => "AEGIS-DIR-DELEG-001",
            ClaseExposicion::DelegacionBasadaEnRecursos => "AEGIS-DIR-DELEG-002",
            ClaseExposicion::GrupoPrivilegiadoAmplio => "AEGIS-DIR-GRUPO-001",
            ClaseExposicion::CuentaSinCaducidad => "AEGIS-DIR-CUENTA-001",
            ClaseExposicion::AclPeligrosa => "AEGIS-DIR-ACL-001",
            ClaseExposicion::PlantillaCertificadoDebil => "AEGIS-DIR-CERT-001",
            ClaseExposicion::ConfianzaPeligrosa => "AEGIS-DIR-TRUST-001",
            ClaseExposicion::CuentaPrivilegiadaDelegable => "AEGIS-DIR-DELEG-003",
        }
    }

    /// La remediacion por defecto de esta clase: que hay que hacer para cerrarla.
    ///
    /// Es texto de defensa, no de ataque: dice como ENDURECER, no como explotar.
    #[must_use]
    pub fn remediacion(self) -> &'static str {
        match self {
            ClaseExposicion::DelegacionSinRestricciones => {
                "Quitar el bit TRUSTED_FOR_DELEGATION del equipo y usar delegacion \
                 restringida (msDS-AllowedToDelegateTo) o cuentas gMSA. Marcar las cuentas \
                 privilegiadas como «sensible, no delegable»."
            }
            ClaseExposicion::DelegacionBasadaEnRecursos => {
                "Revisar msDS-AllowedToActOnBehalfOfOtherIdentity del objeto y retirar los \
                 principales que no deban actuar en su nombre; restringir quien puede escribir \
                 ese atributo."
            }
            ClaseExposicion::GrupoPrivilegiadoAmplio => {
                "Reducir la pertenencia al minimo, usar cuentas dedicadas de administracion \
                 por niveles (tiering), y auditar la pertenencia anidada."
            }
            ClaseExposicion::CuentaSinCaducidad => {
                "Habilitar la caducidad de contrasena y fijar accountExpires en las cuentas \
                 temporales; para las de servicio, migrar a gMSA con rotacion automatica."
            }
            ClaseExposicion::AclPeligrosa => {
                "Retirar el permiso del principal que no deba tenerlo sobre el objeto \
                 privilegiado, y revisar el propietario del objeto."
            }
            ClaseExposicion::PlantillaCertificadoDebil => {
                "Exigir aprobacion del gestor en la plantilla, quitar el permiso de que el \
                 inscrito suministre el sujeto, y limitar los derechos de inscripcion."
            }
            ClaseExposicion::ConfianzaPeligrosa => {
                "Habilitar el filtrado de SID (quarantine) en la confianza, revisar su \
                 transitividad y su direccion, y retirarla si ya no hace falta."
            }
            ClaseExposicion::CuentaPrivilegiadaDelegable => {
                "Marcar la cuenta como «sensible, no delegable» (bit NOT_DELEGATED) o anadirla \
                 al grupo Protected Users."
            }
        }
    }
}

/// Una exposicion concreta encontrada en el directorio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exposicion {
    /// La familia.
    pub clase: ClaseExposicion,
    /// La gravedad, para priorizar la cola.
    pub severidad: Severidad,
    /// La entidad del principal implicado, si lo hay (una cuenta del modelo unico).
    /// Los objetos estructurales (GPO, plantillas) no llevan `Eid`.
    pub sujeto: Option<Eid>,
    /// El nombre legible del sujeto (para leer el informe sin descifrar el `Eid`).
    pub nombre: String,
    /// Por que se disparo, con los datos que la anclan.
    pub evidencia: String,
    /// Que hacer para cerrarla.
    pub remediacion: String,
}

impl Exposicion {
    /// Construye una exposicion con la remediacion por defecto de su clase.
    #[must_use]
    pub fn nueva(
        clase: ClaseExposicion,
        severidad: Severidad,
        sujeto: Option<Eid>,
        nombre: impl Into<String>,
        evidencia: impl Into<String>,
    ) -> Exposicion {
        Exposicion {
            clase,
            severidad,
            sujeto,
            nombre: nombre.into(),
            evidencia: evidencia.into(),
            remediacion: clase.remediacion().to_string(),
        }
    }
}

/// Un hueco: algo que no se pudo evaluar, con su motivo.
///
/// Es la parte del tri-estado que las herramientas de reconocimiento callan: «no
/// pude leer el descriptor de seguridad de este objeto» no es «este objeto no
/// tiene ACL peligrosas».
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hueco {
    /// Que no se pudo evaluar.
    pub que: String,
    /// Por que.
    pub motivo: String,
}

impl Hueco {
    /// Un hueco con su motivo.
    #[must_use]
    pub fn nuevo(que: impl Into<String>, motivo: impl Into<String>) -> Hueco {
        Hueco {
            que: que.into(),
            motivo: motivo.into(),
        }
    }
}

/// El resultado de auditar la exposicion de identidad: lo que se encontro mal y
/// lo que no se pudo mirar.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InformeExposicion {
    /// Las exposiciones encontradas, de mas grave a menos.
    pub exposiciones: Vec<Exposicion>,
    /// Los huecos: lo que no se pudo evaluar, con su motivo.
    pub huecos: Vec<Hueco>,
}

impl InformeExposicion {
    /// Ordena las exposiciones de mas grave a menos, con la clase como desempate
    /// estable, para que el informe sea determinista.
    pub fn ordenar(&mut self) {
        self.exposiciones.sort_by(|a, b| {
            b.severidad
                .cmp(&a.severidad)
                .then_with(|| a.clase.identificador().cmp(b.clase.identificador()))
                .then_with(|| a.nombre.cmp(&b.nombre))
        });
        self.huecos.sort_by(|a, b| a.que.cmp(&b.que));
    }

    /// «Se miro todo y esta bien»: sin exposiciones y sin huecos.
    #[must_use]
    pub fn limpio_y_completo(&self) -> bool {
        self.exposiciones.is_empty() && self.huecos.is_empty()
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn cada_clase_tiene_identificador_y_remediacion_no_vacios() {
        for c in [
            ClaseExposicion::DelegacionSinRestricciones,
            ClaseExposicion::DelegacionBasadaEnRecursos,
            ClaseExposicion::GrupoPrivilegiadoAmplio,
            ClaseExposicion::CuentaSinCaducidad,
            ClaseExposicion::AclPeligrosa,
            ClaseExposicion::PlantillaCertificadoDebil,
            ClaseExposicion::ConfianzaPeligrosa,
            ClaseExposicion::CuentaPrivilegiadaDelegable,
        ] {
            assert!(c.identificador().starts_with("AEGIS-DIR-"));
            assert!(
                !c.remediacion().is_empty(),
                "una exposicion sin remediacion es una alarma que nadie sabe cerrar"
            );
        }
    }

    #[test]
    fn el_informe_distingue_limpio_de_no_mirado() {
        // Tri-estado: vacio y sin huecos es «bien»; vacio con hueco es «no se».
        let bien = InformeExposicion::default();
        assert!(bien.limpio_y_completo());

        let no_se = InformeExposicion {
            exposiciones: Vec::new(),
            huecos: vec![Hueco::nuevo(
                "DACL de Domain Admins",
                "sin privilegio de lectura",
            )],
        };
        assert!(
            !no_se.limpio_y_completo(),
            "no haber podido mirar no es estar limpio"
        );
    }

    #[test]
    fn el_informe_ordena_por_gravedad_de_forma_estable() {
        let mut inf = InformeExposicion {
            exposiciones: vec![
                Exposicion::nueva(
                    ClaseExposicion::CuentaSinCaducidad,
                    Severidad::Baja,
                    None,
                    "svc-viejo",
                    "clave sin caducidad",
                ),
                Exposicion::nueva(
                    ClaseExposicion::AclPeligrosa,
                    Severidad::Critica,
                    None,
                    "Domain Admins",
                    "raso con WriteDacl",
                ),
            ],
            huecos: Vec::new(),
        };
        inf.ordenar();
        assert_eq!(inf.exposiciones[0].severidad, Severidad::Critica);
        assert_eq!(inf.exposiciones[1].severidad, Severidad::Baja);
    }
}
