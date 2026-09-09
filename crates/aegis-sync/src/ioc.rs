//! Indicadores de compromiso y su identidad.

use sha2::{Digest, Sha256};

/// Tipo de indicador.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IocKind {
    /// Hash SHA-256 de un fichero malicioso.
    FileSha256,
    /// Dominio de mando y control.
    Domain,
    /// Direccion IP.
    Ip,
    /// Nombre de regla YARA que se ha revocado o anadido.
    YaraRule,
}

impl IocKind {
    /// Byte discriminante para el identificador.
    fn tag(self) -> u8 {
        match self {
            IocKind::FileSha256 => 1,
            IocKind::Domain => 2,
            IocKind::Ip => 3,
            IocKind::YaraRule => 4,
        }
    }

    /// Nombre estable.
    pub fn as_str(self) -> &'static str {
        match self {
            IocKind::FileSha256 => "file-sha256",
            IocKind::Domain => "domain",
            IocKind::Ip => "ip",
            IocKind::YaraRule => "yara-rule",
        }
    }
}

/// Un indicador de compromiso.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ioc {
    /// Tipo.
    pub kind: IocKind,
    /// Valor (hash, dominio, IP, nombre de regla).
    pub value: String,
}

impl Ioc {
    /// Crea un indicador.
    pub fn new(kind: IocKind, value: impl Into<String>) -> Ioc {
        Ioc {
            kind,
            value: value.into(),
        }
    }

    /// Identificador estable de 32 bytes: `SHA-256(tipo ‖ valor)`.
    ///
    /// Es la clave con la que el indicador se reparte en cubos y se compara. Dos
    /// indicadores iguales dan el mismo id; distintos, ids que se reparten de
    /// forma uniforme por el espacio, que es lo que mantiene los cubos
    /// equilibrados.
    pub fn id(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([self.kind.tag()]);
        h.update(self.value.as_bytes());
        h.finalize().into()
    }
}
