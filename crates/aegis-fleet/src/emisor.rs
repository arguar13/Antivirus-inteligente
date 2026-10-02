//! Fuentes de identidad para el rotador.
//!
//! El rotador ([`crate::rotacion`]) pide identidades nuevas a un
//! [`EmisorIdentidad`]. Aqui estan sus implementaciones:
//!
//! - [`EmisorLocal`]: la CA firma directamente. Es lo correcto para el propio
//!   plano de control (que ES la CA) y para un despliegue de un solo nodo o las
//!   pruebas. La clave nace en memoria en cada emision.
//! - El flujo de produccion sobre varios nodos usa CSR ([`crate::csr`]): el
//!   endpoint genera su clave y una peticion de firma, y la CA —que jamas ve la
//!   clave privada— devuelve el certificado firmado. La clave nunca sale del
//!   endpoint ni toca el disco.
//! - [`EmisorFichero`]: lee una identidad provisionada en ficheros. Es el
//!   camino del agente publicado hasta que haya matriculacion por CSR (H-23),
//!   y el unico de los tres en que la clave toca el disco: ver su documentacion.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::error::{FleetError, Resultado};
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

/// Emisor que LEE la identidad de ficheros provisionados (H-23).
///
/// El despliegue deja en el endpoint un certificado de la CA de flota y su
/// clave, y el agente los lee. Es el camino del agente publicado mientras no
/// exista la matriculacion por CSR contra el plano de control.
///
/// # El compromiso, dicho
///
/// Aqui la clave SI toca el disco, al contrario que con [`EmisorLocal`] o con
/// [`crate::csr`]. Para acotarlo:
///
/// - se exige que la clave no la pueda leer nadie mas que su dueno (modo `0600`
///   o mas estricto): con otro modo, se niega;
/// - la copia en memoria se borra al soltarse, como toda [`ClavePrivada`];
/// - se relee en cada rotacion, asi que un certificado renovado en disco se usa
///   sin reiniciar el agente;
/// - el CN no puede cambiar: la identidad de un agente no cambia en caliente.
///
/// [`ClavePrivada`]: crate::pki::ClavePrivada
pub struct EmisorFichero {
    certificado: PathBuf,
    clave: PathBuf,
}

impl EmisorFichero {
    /// Emisor sobre el certificado y la clave de esas rutas, en PEM.
    pub fn nuevo(certificado: impl Into<PathBuf>, clave: impl Into<PathBuf>) -> EmisorFichero {
        EmisorFichero {
            certificado: certificado.into(),
            clave: clave.into(),
        }
    }

    /// Lee y comprueba la identidad provisionada.
    pub fn leer(&self) -> Resultado<Identidad> {
        let cert = std::fs::read_to_string(&self.certificado).map_err(|e| {
            FleetError::ConfigTls(format!(
                "no se pudo leer el certificado {}: {e}",
                self.certificado.display()
            ))
        })?;
        comprobar_modo_clave(&self.clave)?;
        let clave = zeroize::Zeroizing::new(std::fs::read_to_string(&self.clave).map_err(|e| {
            FleetError::ConfigTls(format!(
                "no se pudo leer la clave {}: {e}",
                self.clave.display()
            ))
        })?);
        Identidad::desde_pem(&cert, &clave)
    }
}

/// Se niega a usar una clave que pueda leer alguien mas que su dueno.
#[cfg(unix)]
fn comprobar_modo_clave(ruta: &Path) -> Resultado<()> {
    use std::os::unix::fs::PermissionsExt;
    let modo = std::fs::metadata(ruta)
        .map_err(|e| {
            FleetError::ConfigTls(format!("no se pudo leer la clave {}: {e}", ruta.display()))
        })?
        .permissions()
        .mode()
        & 0o777;
    if modo & 0o077 != 0 {
        return Err(FleetError::ConfigTls(format!(
            "la clave {} tiene modo {modo:o}: la puede leer alguien mas que su dueno; \
             tiene que ser 0600",
            ruta.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn comprobar_modo_clave(_ruta: &Path) -> Resultado<()> {
    Ok(())
}

impl EmisorIdentidad for EmisorFichero {
    fn emitir(&self, cn: &str, _validez_seg: u64) -> Resultado<Identidad> {
        let id = self.leer()?;
        if id.cn != cn {
            return Err(FleetError::ConfigTls(format!(
                "el certificado {} es de «{}» y el agente arranco como «{cn}»: la \
                 identidad no cambia sin reiniciar",
                self.certificado.display(),
                id.cn
            )));
        }
        Ok(id)
    }
}
