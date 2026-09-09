//! El evento de auditoria y su clasificacion.

/// Gravedad de un evento, ordenada de menor a mayor.
///
/// El orden importa: el registro filtra por gravedad minima, y un tipo ordenado
/// permite comparar sin una tabla de traduccion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Informativo: contexto, no incidente.
    Info = 0,
    /// Merece atencion pero no accion inmediata.
    Notice = 1,
    /// Actividad sospechosa.
    Warning = 2,
    /// Incidente confirmado.
    Critical = 3,
}

impl Severity {
    /// Reconstruye la gravedad desde su codigo entero.
    pub fn from_i64(v: i64) -> Option<Severity> {
        match v {
            0 => Some(Severity::Info),
            1 => Some(Severity::Notice),
            2 => Some(Severity::Warning),
            3 => Some(Severity::Critical),
            _ => None,
        }
    }

    /// Codigo entero.
    pub fn as_i64(self) -> i64 {
        self as i64
    }
}

/// Un evento a registrar.
///
/// La separacion entre metadatos (`ts_ns`, `severity`, `kind`, `actor`) y
/// cuerpo (`detail`) es deliberada: los metadatos se guardan en claro para
/// poder consultar e indexar sin descifrar nada, y el cuerpo —que es donde van
/// las rutas, las lineas de comandos y demas datos sensibles— se cifra. Ver el
/// modelo de amenaza en [`crate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// Instante del evento en nanosegundos.
    pub ts_ns: u64,
    /// Gravedad.
    pub severity: Severity,
    /// Tipo del evento, corto y estable (p. ej. "ransomware.contained").
    pub kind: String,
    /// Clave estable del proceso implicado, 0 si no aplica.
    pub actor: u64,
    /// Cuerpo con el detalle sensible. Se cifra en reposo.
    pub detail: String,
}

impl AuditEvent {
    /// Crea un evento con los campos minimos.
    pub fn new(ts_ns: u64, severity: Severity, kind: impl Into<String>) -> AuditEvent {
        AuditEvent {
            ts_ns,
            severity,
            kind: kind.into(),
            actor: 0,
            detail: String::new(),
        }
    }

    /// Fija el actor.
    pub fn with_actor(mut self, actor: u64) -> AuditEvent {
        self.actor = actor;
        self
    }

    /// Fija el detalle sensible.
    pub fn with_detail(mut self, detail: impl Into<String>) -> AuditEvent {
        self.detail = detail.into();
        self
    }
}

/// Un evento tal como sale del registro, con su identificador de fila.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEvent {
    /// Identificador de fila, monotono y creciente.
    pub id: i64,
    /// El evento.
    pub event: AuditEvent,
}
