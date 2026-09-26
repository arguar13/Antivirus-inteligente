//! El vocabulario de la postura: tri-estado, evidencia, naturaleza y catalogo.
//!
//! # Por que el tri-estado y no un booleano
//!
//! Una comprobacion de postura contesta una pregunta sobre una configuracion que
//! **no se ha leido**: se ha reconstruido de eventos. Y un evento que no llego no
//! dice «esta bien»; no dice nada. Con un booleano, «no se vio ningun
//! `PutBucketPolicy`» y «se vio y no es publica» saldrian iguales —verde—, y el
//! primero es exactamente el caso en el que un atacante que abrio el cubo hace
//! seis meses sigue dentro. Por eso hay un tercer valor, [`Estado::SinDatos`],
//! que lleva SIEMPRE su motivo: un hueco sin motivo es un hueco que alguien
//! acabara pintando de verde.
//!
//! # Por que la evidencia es una lista de identificadores de evento
//!
//! Porque es lo unico que un analista puede seguir. Un hallazgo que dice «el cubo
//! es publico» obliga a volver a la consola a buscar por que; uno que cita el
//! [`Evento::id`](aegis_ingest::esquema::Evento::id) exacto lleva directamente a
//! la llamada, a quien la hizo, desde que IP y con que clave. Y como el
//! identificador se deriva del contenido del evento, la cita se puede comprobar:
//! un identificador que no cuadra con su evento es un evento manipulado.

use aegis_entidad::{Eid, Severidad};
pub use aegis_pipeline::nube::Proveedor;

/// Los tres proveedores, en orden estable.
///
/// El informe los recorre TODOS, tenga o no eventos de cada uno: un proveedor
/// del que no llego nada tiene que aparecer diciendo que no llego nada, no
/// desaparecer del informe como si no hubiera nada que mirar.
pub const PROVEEDORES: [Proveedor; 3] = [Proveedor::Aws, Proveedor::Azure, Proveedor::Gcp];

/// Referencias maximas que se guardan en una evidencia.
///
/// Un cubo al que se le cambia la politica cada minuto produciria miles de
/// referencias; lo que el analista necesita son las que sostienen el veredicto,
/// y el resto se CUENTA en [`Evidencia::omitidas`] en vez de tirarse en
/// silencio.
pub const MAX_REFERENCIAS: usize = 16;

/// Bytes maximos del extracto legible.
///
/// El extracto cita nombres de recurso y de politica, que los escribe quien
/// llamo a la API: lleva tope como todo lo que viene de fuera.
pub const MAX_EXTRACTO: usize = 1024;

/// Bytes maximos del nombre legible de un recurso.
pub const MAX_RECURSO: usize = 512;

/// De que habla un incumplimiento.
///
/// Es el mismo eje que `aegis-fwaudit::comprobacion::Naturaleza` y por la misma
/// razon: un cubo publico es una puerta abierta, no alguien dentro. Juntar las
/// dos clases produce los dos errores clasicos a la vez: el analista recibe
/// «compromiso» por media cuenta mal configurada y aprende a ignorar la
/// categoria, y la exposicion real queda enterrada entre alarmas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Naturaleza {
    /// Hay indicios de que alguien actuo: el orden de los hechos no tiene una
    /// lectura benigna comoda.
    Compromiso,
    /// La configuracion permitiria actuar, pero no dice que nadie lo hiciera.
    Exposicion,
}

impl Naturaleza {
    /// Nombre estable.
    #[must_use]
    pub const fn nombre(self) -> &'static str {
        match self {
            Naturaleza::Compromiso => "compromiso",
            Naturaleza::Exposicion => "exposicion",
        }
    }
}

/// Algo concreto que sostiene un veredicto.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Referencia {
    /// Un evento del plano de control.
    Evento {
        /// El [`Evento::id`](aegis_ingest::esquema::Evento::id) exacto.
        id: String,
        /// Cuando ocurrio, en nanosegundos Unix.
        ocurrio_ns: u64,
        /// La accion de la API (`PutBucketPolicy`, `SetIamPolicy`...).
        accion: String,
    },
    /// Una fila del informe de credenciales de AWS IAM.
    InformeCredenciales {
        /// Numero de fila de datos, empezando en 1 (la cabecera no cuenta).
        fila: usize,
        /// Cuando se genero el informe, en nanosegundos Unix.
        generado_ns: u64,
    },
}

impl Referencia {
    /// El identificador de evento, si lo es.
    #[must_use]
    pub fn id_evento(&self) -> Option<&str> {
        match self {
            Referencia::Evento { id, .. } => Some(id),
            Referencia::InformeCredenciales { .. } => None,
        }
    }

    /// Una linea legible.
    #[must_use]
    pub fn texto(&self) -> String {
        match self {
            Referencia::Evento { id, accion, .. } => {
                // Los dieciseis primeros caracteres bastan para buscarlo en el
                // panel; el identificador entero sigue en la estructura.
                let corto: String = id.chars().take(16).collect();
                format!("evento {corto} ({accion})")
            }
            Referencia::InformeCredenciales { fila, .. } => {
                format!("informe de credenciales, fila {fila}")
            }
        }
    }
}

/// Lo que sostiene un veredicto: referencias exactas y un extracto legible.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Evidencia {
    /// Las referencias, en orden de ocurrencia y sin repetir.
    pub referencias: Vec<Referencia>,
    /// Que dicen, en una frase.
    pub extracto: String,
    /// Referencias que no cupieron en [`MAX_REFERENCIAS`]: se cuentan.
    pub omitidas: usize,
}

impl Evidencia {
    /// Una evidencia con una referencia.
    #[must_use]
    pub fn nueva(r: Referencia, extracto: &str) -> Evidencia {
        let mut e = Evidencia {
            referencias: Vec::new(),
            extracto: aegis_ingest::esquema::recortar(extracto, MAX_EXTRACTO),
            omitidas: 0,
        };
        e.anadir(r);
        e
    }

    /// Una evidencia sin referencias: solo para el agregado de una comprobacion
    /// sobre toda una ventana, donde lo que se cita es la ventana misma.
    #[must_use]
    pub fn solo_extracto(extracto: &str) -> Evidencia {
        Evidencia {
            referencias: Vec::new(),
            extracto: aegis_ingest::esquema::recortar(extracto, MAX_EXTRACTO),
            omitidas: 0,
        }
    }

    /// Anade una referencia. Idempotente: la misma referencia dos veces no
    /// duplica la evidencia —la entrega es al-menos-una-vez, asi que el mismo
    /// evento llegara dos veces por contrato—.
    pub fn anadir(&mut self, r: Referencia) {
        if self.referencias.contains(&r) {
            return;
        }
        if self.referencias.len() >= MAX_REFERENCIAS {
            self.omitidas = self.omitidas.saturating_add(1);
            return;
        }
        self.referencias.push(r);
    }

    /// Une otra evidencia a esta (sus referencias; el extracto se conserva).
    pub fn unir(&mut self, otra: &Evidencia) {
        for r in &otra.referencias {
            self.anadir(r.clone());
        }
        self.omitidas = self.omitidas.saturating_add(otra.omitidas);
    }

    /// Cambia el extracto, con tope.
    pub fn con_extracto(&mut self, extracto: &str) {
        self.extracto = aegis_ingest::esquema::recortar(extracto, MAX_EXTRACTO);
    }

    /// Los identificadores de evento citados, en orden.
    #[must_use]
    pub fn ids_de_evento(&self) -> Vec<&str> {
        self.referencias
            .iter()
            .filter_map(Referencia::id_evento)
            .collect()
    }
}

/// El resultado de una comprobacion: el tri-estado del producto.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Estado {
    /// Se observo lo bastante y esta bien. Lleva lo que lo sostiene: la
    /// correccion (`StartLogging`, `DetachUserPolicy`...) o la observacion.
    Cumple(Evidencia),
    /// Se observo y esta mal. Lleva los eventos que lo sostienen.
    Incumple(Evidencia),
    /// No hay datos para contestar, y se dice por que. **Nunca** se convierte en
    /// `Cumple` por defecto.
    SinDatos(String),
}

impl Estado {
    /// Nombre estable.
    #[must_use]
    pub fn nombre(&self) -> &'static str {
        match self {
            Estado::Cumple(_) => "cumple",
            Estado::Incumple(_) => "incumple",
            Estado::SinDatos(_) => "sin-datos",
        }
    }

    /// Si incumple.
    #[must_use]
    pub fn incumple(&self) -> bool {
        matches!(self, Estado::Incumple(_))
    }

    /// Si cumple.
    #[must_use]
    pub fn cumple(&self) -> bool {
        matches!(self, Estado::Cumple(_))
    }

    /// Si hubo datos para contestar.
    #[must_use]
    pub fn tiene_datos(&self) -> bool {
        !matches!(self, Estado::SinDatos(_))
    }

    /// La evidencia, si la hay.
    #[must_use]
    pub fn evidencia(&self) -> Option<&Evidencia> {
        match self {
            Estado::Cumple(e) | Estado::Incumple(e) => Some(e),
            Estado::SinDatos(_) => None,
        }
    }

    /// Una linea legible.
    #[must_use]
    pub fn linea(&self) -> String {
        match self {
            Estado::Cumple(e) => format!("CUMPLE: {}", e.extracto),
            Estado::Incumple(e) => format!("INCUMPLE: {}", e.extracto),
            Estado::SinDatos(m) => format!("SIN DATOS: {m}"),
        }
    }
}

/// Identificador de la comprobacion de identidades con privilegio de administrador.
pub const IAM_001: &str = "AEGIS-NUBE-IAM-001";
/// Identificador de la comprobacion de privilegios concedidos al publico.
pub const IAM_002: &str = "AEGIS-NUBE-IAM-002";
/// Identificador de la comprobacion de almacenamiento publico.
pub const ALM_001: &str = "AEGIS-NUBE-ALM-001";
/// Identificador de la comprobacion de claves sin rotar.
pub const CLV_001: &str = "AEGIS-NUBE-CLV-001";
/// Identificador de la comprobacion de registro de auditoria apagado.
pub const LOG_001: &str = "AEGIS-NUBE-LOG-001";
/// Identificador de la comprobacion de gestion de cuentas con el registro apagado.
pub const LOG_002: &str = "AEGIS-NUBE-LOG-002";
/// Identificador de la comprobacion de puertos de administracion abiertos.
pub const RED_001: &str = "AEGIS-NUBE-RED-001";

/// La definicion estable de una comprobacion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Definicion {
    /// Identificador estable. No cambia nunca: los clientes filtran por el.
    pub id: &'static str,
    /// Titulo corto.
    pub titulo: &'static str,
    /// Proveedores en los que se comprueba.
    pub proveedores: &'static [Proveedor],
    /// Que clase de cosa es si incumple.
    pub naturaleza: Naturaleza,
    /// Gravedad si incumple, en la escala unica del producto.
    pub severidad: Severidad,
    /// Que se hace para corregirlo.
    pub remediacion: &'static str,
}

/// El catalogo, en orden estable.
pub static CATALOGO: &[Definicion] = &[
    Definicion {
        id: IAM_001,
        titulo: "Identidad con privilegio de administrador",
        proveedores: &PROVEEDORES,
        naturaleza: Naturaleza::Exposicion,
        severidad: Severidad::Alta,
        remediacion: "Sustituir AdministratorAccess / Owner / Contributor / roles/owner / \
                      roles/editor por un rol con los permisos que la identidad usa de verdad; \
                      reservar el acceso total a identidades de emergencia con MFA.",
    },
    Definicion {
        id: IAM_002,
        titulo: "Rol de proyecto concedido al publico",
        proveedores: &[Proveedor::Gcp],
        naturaleza: Naturaleza::Exposicion,
        severidad: Severidad::Critica,
        remediacion: "Retirar allUsers y allAuthenticatedUsers de la politica IAM del \
                      proyecto; activar la restriccion de organizacion \
                      iam.allowedPolicyMemberDomains.",
    },
    Definicion {
        id: ALM_001,
        titulo: "Almacenamiento accesible publicamente",
        proveedores: &[Proveedor::Aws, Proveedor::Gcp],
        naturaleza: Naturaleza::Exposicion,
        severidad: Severidad::Critica,
        remediacion: "Activar los cuatro indicadores de S3 Block Public Access en el cubo y \
                      en la cuenta; en GCS retirar allUsers/allAuthenticatedUsers y activar \
                      la prevencion de acceso publico.",
    },
    Definicion {
        id: CLV_001,
        titulo: "Clave de acceso de larga duracion sin rotar en 90 dias",
        proveedores: &[Proveedor::Aws, Proveedor::Gcp],
        naturaleza: Naturaleza::Exposicion,
        severidad: Severidad::Media,
        remediacion: "Rotar la clave (crear la nueva, mover a quien la usa, desactivar y borrar \
                      la vieja) o, mejor, sustituirla por credenciales temporales (roles, \
                      federacion de identidad de carga de trabajo).",
    },
    Definicion {
        id: LOG_001,
        titulo: "Registro de auditoria del plano de control apagado",
        proveedores: &PROVEEDORES,
        naturaleza: Naturaleza::Exposicion,
        severidad: Severidad::Alta,
        remediacion: "Volver a encender el registro (StartLogging, restaurar la configuracion \
                      de diagnostico o el sink) y proteger su configuracion con una politica \
                      de organizacion que impida apagarlo.",
    },
    Definicion {
        id: LOG_002,
        titulo: "Gestion de cuentas con el registro de auditoria apagado",
        proveedores: &PROVEEDORES,
        naturaleza: Naturaleza::Compromiso,
        severidad: Severidad::Critica,
        remediacion: "Tratarlo como incidente: revisar cada identidad, clave y concesion creada \
                      despues del apagado, revocar las credenciales de quien lo apago y \
                      reconstruir la ventana ciega desde otras fuentes.",
    },
    Definicion {
        id: RED_001,
        titulo: "Puerto de administracion abierto a Internet",
        proveedores: &PROVEEDORES,
        naturaleza: Naturaleza::Exposicion,
        severidad: Severidad::Alta,
        remediacion: "Restringir el origen a los rangos de administracion o sustituir el acceso \
                      directo por un bastion o acceso gestionado (SSM, IAP, Bastion).",
    },
];

/// Busca una definicion por su identificador.
#[must_use]
pub fn definicion(id: &str) -> Option<&'static Definicion> {
    CATALOGO.iter().find(|d| d.id == id)
}

/// El veredicto sobre una entidad concreta: una concesion, un cubo, una clave,
/// una regla de red, un registro.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resultado {
    /// De que comprobacion.
    pub comprobacion: &'static str,
    /// De que nube.
    pub proveedor: Proveedor,
    /// El recurso o la concesion, legible y con tope.
    pub recurso: String,
    /// La entidad del modelo unico sobre la que recae.
    pub entidad: Eid,
    /// El veredicto.
    pub estado: Estado,
}

impl Resultado {
    /// La naturaleza, que es la de su comprobacion.
    #[must_use]
    pub fn naturaleza(&self) -> Naturaleza {
        definicion(self.comprobacion).map_or(Naturaleza::Exposicion, |d| d.naturaleza)
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    fn r(id: &str) -> Referencia {
        Referencia::Evento {
            id: id.into(),
            ocurrio_ns: 1,
            accion: "X".into(),
        }
    }

    #[test]
    fn la_misma_referencia_dos_veces_no_duplica_la_evidencia() {
        let mut e = Evidencia::nueva(r("a"), "x");
        e.anadir(r("a"));
        e.anadir(r("b"));
        assert_eq!(e.ids_de_evento(), vec!["a", "b"]);
    }

    #[test]
    fn lo_que_no_cabe_en_la_evidencia_se_cuenta() {
        let mut e = Evidencia::solo_extracto("x");
        for i in 0..(MAX_REFERENCIAS + 5) {
            e.anadir(r(&i.to_string()));
        }
        assert_eq!(e.referencias.len(), MAX_REFERENCIAS);
        assert_eq!(e.omitidas, 5);
    }

    #[test]
    fn el_extracto_tiene_tope() {
        let e = Evidencia::nueva(r("a"), &"x".repeat(100_000));
        assert!(e.extracto.len() <= MAX_EXTRACTO);
    }

    #[test]
    fn los_identificadores_del_catalogo_son_unicos_y_estables() {
        let mut v: Vec<_> = CATALOGO.iter().map(|d| d.id).collect();
        let n = v.len();
        v.sort_unstable();
        v.dedup();
        assert_eq!(v.len(), n);
        for id in &v {
            assert!(id.starts_with("AEGIS-NUBE-"), "{id}");
        }
    }

    #[test]
    fn solo_la_gestion_con_el_registro_apagado_es_compromiso() {
        // Todo lo demas es una puerta abierta, no alguien dentro.
        for d in CATALOGO {
            let esperado = if d.id == LOG_002 {
                Naturaleza::Compromiso
            } else {
                Naturaleza::Exposicion
            };
            assert_eq!(d.naturaleza, esperado, "{}", d.id);
        }
    }

    #[test]
    fn sin_datos_no_es_cumple() {
        let s = Estado::SinDatos("nada".into());
        assert!(!s.cumple());
        assert!(!s.incumple());
        assert!(!s.tiene_datos());
    }
}
