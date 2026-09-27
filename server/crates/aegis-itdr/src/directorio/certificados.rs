//! Analisis de plantillas de certificado: la familia ESC, como exposiciones.
//!
//! # Por que un EDR mira las plantillas de certificado
//!
//! Los Servicios de Certificados de Active Directory (AD CS) emiten certificados
//! segun **plantillas**. Una plantilla mal configurada permite que un principal
//! obtenga un certificado que lo identifica como otra persona —incluida una
//! administradora— y con el se autentique. Es un camino de escalada que no toca
//! ningun grupo ni ninguna contrasena, y que las herramientas centradas en el
//! grafo de sesiones no ven.
//!
//! Aqui se leen los atributos **publicos y documentados** de cada plantilla y se
//! senalan las combinaciones peligrosas conocidas (la familia «ESC») **para que
//! se remedien**. No se emite ningun certificado ni se explota nada: se describe
//! la debilidad y como cerrarla, que es el trabajo de un auditor de postura.

use aegis_entidad::Eid;

use super::exposicion::{ClaseExposicion, Exposicion};
use crate::Severidad;

/// Banderas de `msPKI-Certificate-Name-Flag` que importan.
pub const NOMBRE_SUMINISTRADO_POR_INSCRITO: u32 = 0x0000_0001;

/// Banderas de `msPKI-Enrollment-Flag` que importan.
pub const REQUIERE_APROBACION_GESTOR: u32 = 0x0000_0002;

/// Un OID de uso extendido de clave (EKU) que permite autenticacion de cliente,
/// que es lo que convierte un certificado en algo con lo que iniciar sesion.
pub const EKU_AUTENTICACION_CLIENTE: &str = "1.3.6.1.5.5.7.3.2";
/// Inicio de sesion con tarjeta inteligente: tambien sirve para autenticarse.
pub const EKU_INICIO_TARJETA: &str = "1.3.6.1.4.1.311.20.2.2";
/// Autenticacion de cliente PKINIT.
pub const EKU_PKINIT: &str = "1.3.6.1.5.2.3.4";
/// Agente de solicitud de certificados (ESC3): permite pedir en nombre de otro.
pub const EKU_AGENTE_INSCRIPCION: &str = "1.3.6.1.4.1.311.20.2.1";

/// Una plantilla de certificado, con los atributos que deciden si es debil.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlantillaCertificado {
    /// El nombre de la plantilla.
    pub nombre: String,
    /// `msPKI-Certificate-Name-Flag`.
    pub bandera_nombre: u32,
    /// `msPKI-Enrollment-Flag`.
    pub bandera_inscripcion: u32,
    /// Cuantas firmas de autorizacion exige (`msPKI-RA-Signature`). Cero significa
    /// que no hace falta contrafirma.
    pub firmas_exigidas: u32,
    /// Los OID de uso extendido de clave de la plantilla. Vacio se interpreta como
    /// «cualquier proposito», que es lo mas permisivo.
    pub ekus: Vec<String>,
    /// Si un principal de bajo privilegio tiene derecho de inscripcion sobre ella.
    /// Sale del descriptor de seguridad de la plantilla.
    pub inscripcion_amplia: bool,
}

impl PlantillaCertificado {
    /// Si la plantilla emite un certificado con el que se puede autenticar: tiene
    /// un EKU de autenticacion, o no tiene ninguno (cualquier proposito).
    #[must_use]
    pub fn permite_autenticacion(&self) -> bool {
        self.ekus.is_empty()
            || self.ekus.iter().any(|e| {
                let e = e.trim();
                e == EKU_AUTENTICACION_CLIENTE || e == EKU_INICIO_TARJETA || e == EKU_PKINIT
            })
    }

    /// Si exige la aprobacion de un gestor antes de emitir (la mitigacion central).
    #[must_use]
    pub fn exige_aprobacion(&self) -> bool {
        self.bandera_inscripcion & REQUIERE_APROBACION_GESTOR != 0
    }

    /// Si el inscrito suministra el sujeto del certificado: puede pedir uno a
    /// nombre de otra identidad.
    #[must_use]
    pub fn inscrito_elige_sujeto(&self) -> bool {
        self.bandera_nombre & NOMBRE_SUMINISTRADO_POR_INSCRITO != 0
    }

    /// Si es una plantilla de agente de inscripcion (ESC3).
    #[must_use]
    pub fn es_agente_inscripcion(&self) -> bool {
        self.ekus.iter().any(|e| e.trim() == EKU_AGENTE_INSCRIPCION)
    }
}

/// Audita una plantilla y devuelve las exposiciones que representa.
///
/// `sujeto` es el `Eid` de la autoridad o del contexto al que atribuir el
/// hallazgo, si lo hay; una plantilla no es un principal, asi que puede ser `None`.
#[must_use]
pub fn auditar_plantilla(p: &PlantillaCertificado, sujeto: Option<Eid>) -> Vec<Exposicion> {
    let mut salida = Vec::new();

    // ESC1: el inscrito elige el sujeto, la plantilla sirve para autenticarse, no
    // exige aprobacion del gestor ni contrafirma, y cualquiera puede inscribirse.
    // Es la combinacion clasica que permite pedir un certificado a nombre de un
    // administrador.
    if p.inscrito_elige_sujeto()
        && p.permite_autenticacion()
        && !p.exige_aprobacion()
        && p.firmas_exigidas == 0
        && p.inscripcion_amplia
    {
        salida.push(Exposicion::nueva(
            ClaseExposicion::PlantillaCertificadoDebil,
            Severidad::Critica,
            sujeto.clone(),
            p.nombre.clone(),
            format!(
                "la plantilla «{}» permite que el inscrito suministre el sujeto, emite un \
                 certificado valido para autenticacion, no exige aprobacion del gestor ni \
                 contrafirma, y admite inscripcion amplia (patron ESC1): un principal raso \
                 puede obtener un certificado a nombre de otra identidad.",
                p.nombre
            ),
        ));
    }

    // ESC2: la plantilla vale para «cualquier proposito» (sin EKU) o es agente de
    // inscripcion, con inscripcion amplia y sin aprobacion.
    if (p.ekus.is_empty() || p.es_agente_inscripcion())
        && p.inscripcion_amplia
        && !p.exige_aprobacion()
    {
        salida.push(Exposicion::nueva(
            ClaseExposicion::PlantillaCertificadoDebil,
            Severidad::Alta,
            sujeto,
            p.nombre.clone(),
            format!(
                "la plantilla «{}» {} con inscripcion amplia y sin aprobacion del gestor \
                 (patron ESC2/ESC3): un certificado asi puede usarse mas alla de su proposito \
                 previsto.",
                p.nombre,
                if p.es_agente_inscripcion() {
                    "es un agente de inscripcion"
                } else {
                    "vale para cualquier proposito"
                }
            ),
        ));
    }

    salida
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn plantilla_esc1() -> PlantillaCertificado {
        PlantillaCertificado {
            nombre: "UsuarioWebVulnerable".into(),
            bandera_nombre: NOMBRE_SUMINISTRADO_POR_INSCRITO,
            bandera_inscripcion: 0,
            firmas_exigidas: 0,
            ekus: vec![EKU_AUTENTICACION_CLIENTE.into()],
            inscripcion_amplia: true,
        }
    }

    #[test]
    fn una_plantilla_esc1_se_senala_como_critica_con_remediacion() {
        let e = auditar_plantilla(&plantilla_esc1(), None);
        assert!(!e.is_empty());
        assert_eq!(e[0].clase, ClaseExposicion::PlantillaCertificadoDebil);
        assert_eq!(e[0].severidad, Severidad::Critica);
        assert!(e[0].evidencia.contains("ESC1"));
        assert!(e[0].remediacion.contains("aprobacion del gestor"));
    }

    #[test]
    fn exigir_aprobacion_del_gestor_cierra_el_esc1() {
        // LA PRUEBA DE QUE LA REMEDIACION FUNCIONA: con la mitigacion puesta, el
        // hallazgo critico desaparece.
        let mut p = plantilla_esc1();
        p.bandera_inscripcion = REQUIERE_APROBACION_GESTOR;
        let e = auditar_plantilla(&p, None);
        assert!(
            !e.iter().any(|x| x.severidad == Severidad::Critica),
            "con aprobacion del gestor la plantilla ya no es ESC1"
        );
    }

    #[test]
    fn restringir_la_inscripcion_tambien_lo_cierra() {
        let mut p = plantilla_esc1();
        p.inscripcion_amplia = false;
        let e = auditar_plantilla(&p, None);
        assert!(!e.iter().any(|x| x.severidad == Severidad::Critica));
    }

    #[test]
    fn una_plantilla_de_cualquier_proposito_es_esc2() {
        let p = PlantillaCertificado {
            nombre: "CualquierProposito".into(),
            bandera_nombre: 0,
            bandera_inscripcion: 0,
            firmas_exigidas: 0,
            ekus: Vec::new(),
            inscripcion_amplia: true,
        };
        let e = auditar_plantilla(&p, None);
        assert!(e
            .iter()
            .any(|x| x.evidencia.contains("cualquier proposito")));
    }

    #[test]
    fn una_plantilla_bien_configurada_no_da_hallazgos() {
        let p = PlantillaCertificado {
            nombre: "UsuarioSeguro".into(),
            bandera_nombre: 0,
            bandera_inscripcion: REQUIERE_APROBACION_GESTOR,
            firmas_exigidas: 1,
            ekus: vec![EKU_AUTENTICACION_CLIENTE.into()],
            inscripcion_amplia: false,
        };
        assert!(auditar_plantilla(&p, None).is_empty());
    }
}
