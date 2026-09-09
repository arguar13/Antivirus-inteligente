//! La vacuna: lo que un agente propaga cuando descubre una amenaza.
//!
//! # Por que una vacuna solo puede ANADIR
//!
//! Es la decision de seguridad que define este crate. La malla se autentica con
//! una clave compartida por todos los agentes de la red local, asi que un
//! atacante que comprometa **un solo** equipo tiene la clave y puede emitir
//! mensajes validos. Si una vacuna pudiera RETIRAR un indicador, ese atacante
//! desactivaria la deteccion de toda la flota con un unico datagrama, y lo haria
//! desde dentro, con credenciales legitimas.
//!
//! Por eso el tipo no tiene variante de revocacion, y no es un olvido: quitar un
//! indicador es una operacion privilegiada que viaja por el canal de
//! actualizacion, firmado con Ed25519 por una clave que **no** esta en ningun
//! agente. La malla es rapida y horizontal; la revocacion es lenta y jerarquica,
//! y eso es lo correcto.

use aegis_sync::ioc::{Ioc, IocKind};

/// Gravedad con la que se propaga.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Sospecha: se anota, no se bloquea.
    Suspicious,
    /// Confirmado por un motor con evidencia.
    Confirmed,
    /// Confirmado y con contencion ya aplicada en el origen.
    Contained,
}

impl Severity {
    /// Byte para el formato de red.
    pub fn tag(self) -> u8 {
        match self {
            Severity::Suspicious => 1,
            Severity::Confirmed => 2,
            Severity::Contained => 3,
        }
    }

    /// Recupera la gravedad de su byte.
    pub fn from_tag(t: u8) -> Option<Severity> {
        match t {
            1 => Some(Severity::Suspicious),
            2 => Some(Severity::Confirmed),
            3 => Some(Severity::Contained),
            _ => None,
        }
    }

    /// Nombre estable.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Suspicious => "sospechoso",
            Severity::Confirmed => "confirmado",
            Severity::Contained => "contenido",
        }
    }
}

/// Un indicador propagado por la malla.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vaccine {
    /// Indicador que se propaga.
    pub ioc: Ioc,
    /// Gravedad.
    pub severity: Severity,
    /// Instante de emision, en segundos desde el epoch.
    ///
    /// Se usa para descartar vacunas viejas que un atacante haya capturado y
    /// reinyecte mas tarde, y para que un agente que acaba de arrancar sepa que
    /// lo que recibe es actual.
    pub issued_at: u64,
    /// Tecnicas de ATT&CK asociadas, por identificador.
    pub techniques: Vec<String>,
    /// Saltos que ha dado ya por la malla.
    ///
    /// Lo incrementa cada agente que la reenvia. Sin este limite, tres agentes
    /// que se reenvien lo mismo unos a otros saturan la red local en segundos:
    /// es la tormenta de difusion clasica de cualquier protocolo de inundacion.
    pub hops: u8,
}

impl Vaccine {
    /// Crea una vacuna recien emitida.
    pub fn new(ioc: Ioc, severity: Severity, issued_at: u64) -> Vaccine {
        Vaccine {
            ioc,
            severity,
            issued_at,
            techniques: Vec::new(),
            hops: 0,
        }
    }

    /// Anade las tecnicas asociadas.
    pub fn with_techniques(mut self, t: Vec<String>) -> Vaccine {
        self.techniques = t;
        self
    }

    /// Identidad de la vacuna, para deduplicar.
    ///
    /// **No incluye los saltos**: la misma vacuna que llega por dos caminos
    /// distintos tiene distinto contador de saltos y tiene que reconocerse como
    /// la misma, o el mecanismo de deduplicacion no evitaria nada.
    pub fn id(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(self.ioc.id());
        h.update([self.severity.tag()]);
        h.update(self.issued_at.to_le_bytes());
        for t in &self.techniques {
            h.update(t.as_bytes());
            h.update([0]);
        }
        h.finalize().into()
    }

    /// Tipo del indicador.
    pub fn kind(&self) -> IocKind {
        self.ioc.kind
    }

    /// Indica si la vacuna es demasiado vieja para aceptarla.
    ///
    /// Una vacuna capturada y reinyectada meses despues no aporta nada y si
    /// permite a un atacante reintroducir ruido en la flota.
    pub fn expired(&self, ahora: u64, max_edad: u64) -> bool {
        ahora.saturating_sub(self.issued_at) > max_edad
    }

    /// Indica si viene del futuro por mas de la holgura indicada.
    ///
    /// Los relojes de una red local difieren en segundos; una vacuna fechada
    /// horas por delante es un reloj roto o un intento de que nunca caduque.
    pub fn from_future(&self, ahora: u64, holgura: u64) -> bool {
        self.issued_at > ahora.saturating_add(holgura)
    }
}
