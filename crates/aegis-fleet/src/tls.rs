//! Construccion de las configuraciones TLS mutuas (mTLS) de flota.
//!
//! # mTLS: los dos extremos se autentican
//!
//! En un TLS normal solo el servidor prueba su identidad. En la flota, tambien
//! el agente: el servidor EXIGE un certificado de cliente firmado por la CA de
//! la flota. Un agente sin ese certificado —o con uno autofirmado, o de otra
//! CA— no pasa del handshake. Es lo que impide que cualquiera que alcance el
//! puerto del plano de control se registre como un endpoint.
//!
//! # Sin estado global de proceso
//!
//! `rustls` permite instalar un proveedor criptografico global, pero eso es
//! estado compartido de proceso y una fuente de sorpresas. Aqui cada
//! configuracion se construye con un proveedor EXPLICITO (`ring`), sin tocar
//! nada global: encaja con el control estricto de estado del resto del producto.

use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

use crate::error::{FleetError, Resultado};
use crate::pki::Identidad;

/// Proveedor criptografico del crate: `ring`, explicito.
pub fn proveedor() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Almacen de confianza con solo la CA de la flota.
fn raiz(ca_der: &CertificateDer<'static>) -> Resultado<RootCertStore> {
    let mut roots = RootCertStore::empty();
    roots
        .add(ca_der.clone())
        .map_err(|e| FleetError::ConfigTls(format!("no se pudo confiar en la CA: {e}")))?;
    Ok(roots)
}

/// Configuracion del servidor del plano de control: exige mTLS.
pub fn config_servidor(
    id: &Identidad,
    ca_der: &CertificateDer<'static>,
) -> Resultado<Arc<ServerConfig>> {
    let roots = Arc::new(raiz(ca_der)?);
    let verificador =
        rustls::server::WebPkiClientVerifier::builder_with_provider(roots, proveedor())
            .build()
            .map_err(|e| FleetError::ConfigTls(format!("verificador de cliente: {e}")))?;

    let cfg = ServerConfig::builder_with_provider(proveedor())
        .with_safe_default_protocol_versions()
        .map_err(|e| FleetError::ConfigTls(format!("versiones TLS: {e}")))?
        .with_client_cert_verifier(verificador)
        .with_single_cert(vec![id.cert_der.clone()], id.clave.como_rustls()?)
        .map_err(|e| FleetError::ConfigTls(format!("certificado de servidor: {e}")))?;
    Ok(Arc::new(cfg))
}

/// Configuracion del cliente-agente: presenta su certificado de flota.
pub fn config_cliente(
    id: &Identidad,
    ca_der: &CertificateDer<'static>,
) -> Resultado<Arc<ClientConfig>> {
    let roots = raiz(ca_der)?;
    let cfg = ClientConfig::builder_with_provider(proveedor())
        .with_safe_default_protocol_versions()
        .map_err(|e| FleetError::ConfigTls(format!("versiones TLS: {e}")))?
        .with_root_certificates(roots)
        .with_client_auth_cert(vec![id.cert_der.clone()], id.clave.como_rustls()?)
        .map_err(|e| FleetError::ConfigTls(format!("certificado de cliente: {e}")))?;
    Ok(Arc::new(cfg))
}

/// Extrae el CN del certificado de hoja del par autenticado.
pub fn cn_del_par(certs: Option<&[CertificateDer<'static>]>) -> Option<String> {
    let hoja = certs?.first()?;
    crate::x509::subject_cn(hoja.as_ref())
}
