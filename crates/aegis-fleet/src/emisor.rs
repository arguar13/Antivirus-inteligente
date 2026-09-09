//! Fuentes de identidad para el rotador.
//!
//! El rotador ([`crate::rotacion`]) pide identidades nuevas a un
//! [`EmisorIdentidad`]. Aqui estan las dos implementaciones:
//!
//! - [`EmisorLocal`]: la CA firma directamente. Es lo correcto para el propio
//!   plano de control (que ES la CA) y para un despliegue de un solo nodo o las
//!   pruebas. La clave nace en memoria en cada emision.
//! - El flujo de produccion sobre varios nodos usa CSR ([`crate::csr`]): el
//!   endpoint genera su clave y una peticion de firma, y la CA —que jamas ve la
//!   clave privada— devuelve el certificado firmado. La clave nunca sale del
//!   endpoint ni toca el disco.

use std::sync::Arc;

use crate::error::Resultado;
use crate::pki::{AutoridadCertificadora, Identidad};
use crate::rotacion::EmisorIdentidad;

/// Emisor respaldado por una CA local.
pub struct EmisorLocal {
    ca: Arc<AutoridadCertificadora>,
}

impl EmisorLocal {
    /// Crea un emisor sobre una CA.
    pub fn nuevo(ca: Arc<AutoridadCertificadora>) -> EmisorLocal {
        EmisorLocal { ca }
    }
}

impl EmisorIdentidad for EmisorLocal {
    fn emitir(&self, cn: &str, validez_seg: u64) -> Resultado<Identidad> {
        self.ca.emitir(cn, validez_seg)
    }
}
