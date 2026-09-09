//! Veredictos de reputacion y sus tiempos de vida.

/// Lo que la nube sabe de un fichero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reputation {
    /// Conocido y limpio.
    Benign,
    /// Conocido y malicioso.
    Malicious,
    /// Aplicacion potencialmente no deseada.
    Unwanted,
    /// El servidor no lo conoce.
    ///
    /// Es informacion, no ausencia de informacion: sobre un corpus de mil
    /// millones de ficheros, que uno sea desconocido y ademas tenga baja
    /// prevalencia es exactamente el perfil del malware dirigido.
    Unknown,
}

impl Reputation {
    /// Analiza el codigo de un byte del protocolo.
    pub fn from_code(c: u8) -> Option<Reputation> {
        match c {
            b'b' => Some(Reputation::Benign),
            b'm' => Some(Reputation::Malicious),
            b'u' => Some(Reputation::Unwanted),
            b'?' => Some(Reputation::Unknown),
            _ => None,
        }
    }

    /// Codigo del protocolo.
    pub fn code(self) -> u8 {
        match self {
            Reputation::Benign => b'b',
            Reputation::Malicious => b'm',
            Reputation::Unwanted => b'u',
            Reputation::Unknown => b'?',
        }
    }
}

/// Prevalencia por debajo de la cual un fichero benigno no merece confianza a
/// largo plazo.
///
/// Un binario que solo han visto unos pocos equipos puede ser interno y
/// legitimo, o puede haber sido comprometido y aun no haberse revisado. Su
/// veredicto caduca antes.
pub const PREVALENCIA_ALTA: u32 = 1000;

/// Reputacion con sus metadatos.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record {
    /// Veredicto.
    pub reputation: Reputation,
    /// Confianza, 0-100.
    pub confidence: u8,
    /// Segundos desde que el corpus lo vio por primera vez.
    ///
    /// Un fichero visto por primera vez hace diez minutos es sospechoso por si
    /// mismo, aunque su veredicto sea desconocido.
    pub first_seen_age_s: u64,
    /// Cuantos equipos lo han visto.
    pub prevalence: u32,
}

impl Record {
    /// Registro para un fichero que el servidor no conoce.
    pub fn unknown() -> Record {
        Record {
            reputation: Reputation::Unknown,
            confidence: 0,
            first_seen_age_s: 0,
            prevalence: 0,
        }
    }

    /// Tiempo de vida en la cache, en segundos.
    ///
    /// Los plazos no son arbitrarios: cada uno responde a con que facilidad
    /// puede cambiar ese veredicto.
    pub fn ttl_s(&self) -> u64 {
        match self.reputation {
            // Un veredicto malicioso casi nunca se revoca.
            Reputation::Malicious => 7 * 24 * 3600,
            Reputation::Unwanted => 7 * 24 * 3600,
            Reputation::Benign if self.prevalence >= PREVALENCIA_ALTA => 30 * 24 * 3600,
            // Baja prevalencia: pudo haber sido comprometido desde la ultima
            // vez que alguien lo miro.
            Reputation::Benign => 24 * 3600,
            // Cache NEGATIVA. Sin ella, un fichero desconocido que se ejecuta
            // cada minuto genera una consulta por minuto para siempre, y la
            // repeticion de consultas es justo lo que rompe el k-anonimato.
            Reputation::Unknown => 3600,
        }
    }
}
