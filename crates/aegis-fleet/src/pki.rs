//! Autoridad certificadora de la flota e identidades de agente.
//!
//! # El principio: la clave privada nunca toca el disco
//!
//! La identidad de un agente es un par (certificado X.509, clave privada). La
//! clave se genera EN MEMORIA con `rcgen`, se entrega a `rustls` como bytes en
//! memoria, y se borra ([`zeroize`]) al soltarse. En ningun momento se escribe
//! en un fichero: un atacante que lea el disco del endpoint no encuentra con que
//! suplantar al agente. Es la razon de que la rotacion ([`crate::rotacion`])
//! genere siempre una clave nueva en vez de releer una guardada.
//!
//! # La autoridad
//!
//! El plano de control tiene una CA. Firma un certificado por agente, con un CN
//! que es la identidad estable del agente y una validez corta. `rustls` en el
//! servidor exige que el certificado de cliente este firmado por esta CA: un
//! agente sin certificado de la flota no pasa del handshake.

use std::time::{SystemTime, UNIX_EPOCH};

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::{FleetError, Resultado};

/// Instante Unix actual en segundos.
pub fn ahora_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Clave privada en memoria que se borra al soltarse.
///
/// Guarda los bytes PKCS#8 DER. Al caer, se sobrescriben con ceros; el
/// compilador no puede eliminar ese borrado porque `zeroize` usa escrituras
/// volatiles. Es la garantia de que la clave no queda en un `free` sin limpiar
/// tras una rotacion.
pub struct ClavePrivada {
    der: Vec<u8>,
}

impl ClavePrivada {
    /// Envuelve unos bytes de clave.
    pub fn nueva(der: Vec<u8>) -> ClavePrivada {
        ClavePrivada { der }
    }

    /// Copia la clave al tipo que `rustls` consume.
    ///
    /// `rustls` necesita poseer los bytes; se le entrega una copia, y tanto esta
    /// copia como el original se borran cuando dejan de usarse.
    pub fn como_rustls(&self) -> Resultado<PrivateKeyDer<'static>> {
        PrivateKeyDer::try_from(self.der.clone())
            .map_err(|e| FleetError::Cripto(format!("clave privada invalida: {e}")))
    }
}

impl Drop for ClavePrivada {
    fn drop(&mut self) {
        self.der.zeroize();
    }
}

impl std::fmt::Debug for ClavePrivada {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Jamas se imprime el material de clave.
        write!(f, "ClavePrivada({} bytes, en memoria)", self.der.len())
    }
}

/// Identidad de un agente: su certificado y su clave, ambos en memoria.
#[derive(Debug)]
pub struct Identidad {
    /// Certificado X.509 en DER.
    pub cert_der: CertificateDer<'static>,
    /// Clave privada, que se borra al soltarse.
    pub clave: ClavePrivada,
    /// Nombre comun (identidad estable del agente).
    pub cn: String,
    /// Instante Unix a partir del cual el certificado es valido.
    pub no_antes_unix: u64,
    /// Instante Unix a partir del cual el certificado caduca.
    pub no_despues_unix: u64,
}

impl Identidad {
    /// Huella SHA-256 del certificado, para telemetria y correlacion.
    pub fn huella(&self) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(self.cert_der.as_ref());
        h.finalize().to_vec()
    }

    /// Segundos que faltan para la caducidad respecto a `ahora`.
    ///
    /// Cero si ya caduco. Es lo que mira el rotador para decidir cuando renovar.
    pub fn segundos_para_caducar(&self, ahora: u64) -> u64 {
        self.no_despues_unix.saturating_sub(ahora)
    }

    /// Indica si el certificado es valido en el instante `ahora`.
    pub fn vigente(&self, ahora: u64) -> bool {
        ahora >= self.no_antes_unix && ahora < self.no_despues_unix
    }
}

/// Autoridad certificadora del plano de control de la flota.
pub struct AutoridadCertificadora {
    cert: rcgen::Certificate,
    clave: rcgen::KeyPair,
    cert_der: CertificateDer<'static>,
}

impl AutoridadCertificadora {
    /// Genera una CA nueva en memoria.
    pub fn nueva(nombre: &str) -> Resultado<AutoridadCertificadora> {
        let mut params = rcgen::CertificateParams::new(vec![])
            .map_err(|e| FleetError::Cripto(format!("parametros de CA: {e}")))?;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, nombre);
        let clave = rcgen::KeyPair::generate()
            .map_err(|e| FleetError::Cripto(format!("clave de CA: {e}")))?;
        let cert = params
            .self_signed(&clave)
            .map_err(|e| FleetError::Cripto(format!("autofirma de CA: {e}")))?;
        let cert_der = CertificateDer::from(cert.der().to_vec());
        Ok(AutoridadCertificadora {
            cert,
            clave,
            cert_der,
        })
    }

    /// Recupera una CA ya existente a partir de su certificado y su clave en PEM.
    ///
    /// # Por que hace falta
    ///
    /// El plano de control ES la autoridad certificadora de la flota: la que
    /// firma los certificados con los que los agentes se autentican. Si esa CA
    /// se regenerase en cada arranque, TODOS los certificados emitidos dejarian
    /// de validar y la flota entera quedaria fuera al primer reinicio del
    /// servidor. Una CA de plano de control tiene que sobrevivir al proceso.
    ///
    /// # Sobre el certificado que se conserva
    ///
    /// `rcgen` no reabre un certificado: reconstruye uno equivalente a partir de
    /// sus parametros. Ese certificado reconstruido sirve para FIRMAR (mismo
    /// nombre distinguido y misma clave, luego las hojas encadenan igual), pero
    /// sus bytes no tienen por que coincidir con los originales. Por eso se
    /// conserva el DER ORIGINAL tal cual llego: es el que se distribuye a los
    /// endpoints como ancla de confianza, y tiene que ser byte a byte el mismo
    /// que ya tengan provisionado.
    pub fn desde_pem(cert_pem: &str, clave_pem: &str) -> Resultado<AutoridadCertificadora> {
        let clave = rcgen::KeyPair::from_pem(clave_pem)
            .map_err(|e| FleetError::Cripto(format!("clave de CA ilegible: {e}")))?;
        let params = rcgen::CertificateParams::from_ca_cert_pem(cert_pem)
            .map_err(|e| FleetError::Cripto(format!("certificado de CA ilegible: {e}")))?;

        // El DER autentico, el que ya conocen los agentes.
        let pem_analizado = pem::parse(cert_pem)
            .map_err(|e| FleetError::Cripto(format!("PEM de CA invalido: {e}")))?;
        let cert_der = CertificateDer::from(pem_analizado.contents().to_vec());

        let cert = params
            .self_signed(&clave)
            .map_err(|e| FleetError::Cripto(format!("reconstruccion de la CA: {e}")))?;

        Ok(AutoridadCertificadora {
            cert,
            clave,
            cert_der,
        })
    }

    /// Exporta el certificado de la CA en PEM.
    pub fn cert_pem(&self) -> String {
        self.cert.pem()
    }

    /// Exporta la clave privada de la CA en PEM.
    ///
    /// # Aviso
    ///
    /// Esto es el material mas sensible de todo el sistema: quien tenga esta
    /// clave puede emitir un certificado valido para CUALQUIER identidad de la
    /// flota y hacerse pasar por el plano de control. Solo debe escribirse en un
    /// fichero con permisos 0600 y, en un despliegue serio, vivir en un HSM o un
    /// gestor de claves.
    pub fn clave_pem(&self) -> String {
        self.clave.serialize_pem()
    }

    /// Certificado de la CA en DER, para los almacenes de confianza.
    pub fn cert_der(&self) -> CertificateDer<'static> {
        self.cert_der.clone()
    }

    /// Emite una identidad de agente firmada por la CA.
    ///
    /// `validez_seg` es la vida del certificado; corta a proposito, para que la
    /// rotacion sea frecuente y una clave comprometida caduque sola.
    pub fn emitir(&self, cn: &str, validez_seg: u64) -> Resultado<Identidad> {
        let ahora = ahora_unix();
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .map_err(|e| FleetError::Cripto(format!("parametros de hoja: {e}")))?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        params.not_before = marca_temporal(ahora)?;
        params.not_after = marca_temporal(ahora + validez_seg)?;

        let clave = rcgen::KeyPair::generate()
            .map_err(|e| FleetError::Cripto(format!("clave de hoja: {e}")))?;
        let cert = params
            .signed_by(&clave, &self.cert, &self.clave)
            .map_err(|e| FleetError::Cripto(format!("firma de hoja: {e}")))?;

        Ok(Identidad {
            cert_der: CertificateDer::from(cert.der().to_vec()),
            clave: ClavePrivada::nueva(clave.serialize_der()),
            cn: cn.to_string(),
            no_antes_unix: ahora,
            no_despues_unix: ahora + validez_seg,
        })
    }
}

/// Convierte un instante Unix en la marca temporal que `rcgen` espera.
fn marca_temporal(unix: u64) -> Resultado<time::OffsetDateTime> {
    time::OffsetDateTime::from_unix_timestamp(unix as i64)
        .map_err(|e| FleetError::Cripto(format!("marca temporal invalida: {e}")))
}

impl AutoridadCertificadora {
    /// Firma una peticion de certificado (CSR) y devuelve el certificado y su
    /// ventana de validez.
    ///
    /// Este es el camino de PRODUCCION: el endpoint genera su clave y una CSR
    /// ([`crate::csr`]) y envia SOLO la CSR. La CA nunca ve la clave privada;
    /// firma la peticion, fija una validez corta —la CA manda sobre la vida del
    /// certificado, no el solicitante— y devuelve el certificado. La clave no
    /// sale jamas del endpoint.
    pub fn firmar_csr(
        &self,
        csr_der: &[u8],
        validez_seg: u64,
    ) -> Resultado<(CertificateDer<'static>, u64, u64)> {
        let der = rustls::pki_types::CertificateSigningRequestDer::from(csr_der.to_vec());
        let mut peticion = rcgen::CertificateSigningRequestParams::from_der(&der)
            .map_err(|e| FleetError::Cripto(format!("CSR invalida: {e}")))?;

        let ahora = ahora_unix();
        // La CA fija la validez; no se toma del solicitante.
        peticion.params.not_before = marca_temporal(ahora)?;
        peticion.params.not_after = marca_temporal(ahora + validez_seg)?;

        let cert = peticion
            .signed_by(&self.cert, &self.clave)
            .map_err(|e| FleetError::Cripto(format!("firma de CSR: {e}")))?;
        Ok((
            CertificateDer::from(cert.der().to_vec()),
            ahora,
            ahora + validez_seg,
        ))
    }
}
