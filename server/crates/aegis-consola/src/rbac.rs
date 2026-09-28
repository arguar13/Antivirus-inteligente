//! RBAC: roles del SOC y permisos por accion (FASE 110).
//!
//! La API del plano de control tenia autenticacion pero NINGUNA autorizacion:
//! cualquier sesion valida podia aislar la flota entera, borrar reglas o publicar
//! politicas. Eso no es una consola de SOC, es una llave maestra. Aqui los roles
//! se corresponden con los del SOC y cada accion exige un permiso; una accion sin
//! el permiso se rechaza, y —como en el resto del producto— la decision es una
//! funcion pura sobre una tabla que se puede revisar de un vistazo.

/// Un rol del SOC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Rol {
    /// Analista: mira, investiga y trabaja casos. No ordena acciones destructivas
    /// por si solo.
    Analista,
    /// Responsable de turno: ademas puede ordenar contencion (aislar, cuarentena)
    /// y aprobar lo que un analista escala.
    Responsable,
    /// Administrador: ademas gestiona reglas, politicas y usuarios.
    Administrador,
    /// Auditor: SOLO lee, incluido el rastro; no toca nada. Existe para el
    /// regulador y la investigacion interna, y su poder es no tener poder.
    Auditor,
}

impl Rol {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Rol::Analista => "analista",
            Rol::Responsable => "responsable",
            Rol::Administrador => "administrador",
            Rol::Auditor => "auditor",
        }
    }

    /// Todos los roles.
    #[must_use]
    pub fn todos() -> [Rol; 4] {
        [
            Rol::Analista,
            Rol::Responsable,
            Rol::Administrador,
            Rol::Auditor,
        ]
    }
}

/// Una accion que la consola puede pedir, agrupada por lo que arriesga.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Permiso {
    /// Leer casos, alertas, entidades, veredictos, el grafo, el rastro.
    Leer,
    /// Trabajar un caso: cambiar estado, tareas, comentar, asignar, traspasar.
    TrabajarCaso,
    /// Lanzar una caza (consulta sobre la flota).
    LanzarCaza,
    /// Enriquecer con analizadores que salen al exterior.
    EnriquecerExterno,
    /// Ordenar contencion: aislar un agente, cuarentenar una IP.
    Contener,
    /// Aprobar o rechazar una remediacion escalada.
    AprobarRemediacion,
    /// Gestionar reglas, heuristicas y politicas.
    GestionarDeteccion,
    /// Gestionar usuarios y roles.
    GestionarUsuarios,
    /// Exportar datos fuera de la consola (pasa ademas por la FASE 78).
    Exportar,
}

impl Permiso {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(self) -> &'static str {
        match self {
            Permiso::Leer => "leer",
            Permiso::TrabajarCaso => "trabajar-caso",
            Permiso::LanzarCaza => "lanzar-caza",
            Permiso::EnriquecerExterno => "enriquecer-externo",
            Permiso::Contener => "contener",
            Permiso::AprobarRemediacion => "aprobar-remediacion",
            Permiso::GestionarDeteccion => "gestionar-deteccion",
            Permiso::GestionarUsuarios => "gestionar-usuarios",
            Permiso::Exportar => "exportar",
        }
    }
}

/// Si un rol tiene un permiso. Es la tabla de autorizacion, a la vista.
///
/// El auditor SOLO lee: su poder es no tener poder, y por eso no aparece en ningun
/// otro brazo. Los roles se ACUMULAN hacia arriba salvo esa excepcion: responsable
/// hace lo del analista y mas; administrador, lo del responsable y mas.
#[must_use]
pub fn puede(rol: Rol, permiso: Permiso) -> bool {
    use Permiso::{
        AprobarRemediacion, Contener, EnriquecerExterno, Exportar, GestionarDeteccion,
        GestionarUsuarios, LanzarCaza, Leer, TrabajarCaso,
    };
    match rol {
        // El auditor solo lee. Nada mas, a proposito.
        Rol::Auditor => permiso == Leer,
        Rol::Analista => matches!(
            permiso,
            Leer | TrabajarCaso | LanzarCaza | EnriquecerExterno | Exportar
        ),
        Rol::Responsable => matches!(
            permiso,
            Leer | TrabajarCaso
                | LanzarCaza
                | EnriquecerExterno
                | Exportar
                | Contener
                | AprobarRemediacion
        ),
        // El administrador puede todo.
        Rol::Administrador => matches!(
            permiso,
            Leer | TrabajarCaso
                | LanzarCaza
                | EnriquecerExterno
                | Exportar
                | Contener
                | AprobarRemediacion
                | GestionarDeteccion
                | GestionarUsuarios
        ),
    }
}

/// El motivo por el que una accion se rechaza, para el panel y el rastro.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denegado {
    /// Rol que lo intento.
    pub rol: Rol,
    /// Permiso que faltaba.
    pub permiso: Permiso,
}

impl Denegado {
    /// Frase legible.
    #[must_use]
    pub fn motivo(&self) -> String {
        format!(
            "el rol «{}» no tiene el permiso «{}»",
            self.rol.nombre(),
            self.permiso.nombre()
        )
    }
}

/// Autoriza una accion: `Ok` si el rol puede, `Err(Denegado)` con su motivo si no.
///
/// # Errors
/// [`Denegado`] si el rol carece del permiso.
pub fn autorizar(rol: Rol, permiso: Permiso) -> Result<(), Denegado> {
    if puede(rol, permiso) {
        Ok(())
    } else {
        Err(Denegado { rol, permiso })
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn el_auditor_solo_lee() {
        assert!(puede(Rol::Auditor, Permiso::Leer));
        // Nada mas: ni trabajar casos, ni contener, ni exportar.
        for p in [
            Permiso::TrabajarCaso,
            Permiso::LanzarCaza,
            Permiso::Contener,
            Permiso::Exportar,
            Permiso::GestionarUsuarios,
        ] {
            assert!(!puede(Rol::Auditor, p), "auditor NO puede {}", p.nombre());
        }
    }

    #[test]
    fn el_analista_no_contiene_ni_gestiona_pero_el_responsable_contiene() {
        // Aislar la flota no es cosa de un analista por si solo.
        assert!(!puede(Rol::Analista, Permiso::Contener));
        assert!(puede(Rol::Responsable, Permiso::Contener));
        assert!(puede(Rol::Responsable, Permiso::AprobarRemediacion));
        // Gestionar usuarios/deteccion es solo del administrador.
        assert!(!puede(Rol::Responsable, Permiso::GestionarUsuarios));
        assert!(puede(Rol::Administrador, Permiso::GestionarUsuarios));
        assert!(puede(Rol::Administrador, Permiso::GestionarDeteccion));
    }

    #[test]
    fn autorizar_da_el_motivo_cuando_deniega() {
        let e = autorizar(Rol::Analista, Permiso::Contener).unwrap_err();
        assert!(e.motivo().contains("analista"));
        assert!(e.motivo().contains("contener"));
        assert!(autorizar(Rol::Responsable, Permiso::Contener).is_ok());
    }

    #[test]
    fn todos_pueden_leer_menos_nadie() {
        for r in Rol::todos() {
            assert!(
                puede(r, Permiso::Leer),
                "{} tiene que poder leer",
                r.nombre()
            );
        }
    }
}
