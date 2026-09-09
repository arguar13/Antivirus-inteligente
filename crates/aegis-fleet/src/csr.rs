//! Peticiones de firma de certificado (CSR): el camino de produccion.
//!
//! # El principio
//!
//! El endpoint genera su par de claves EN SU MEMORIA y construye una peticion de
//! firma (CSR) que contiene solo su clave PUBLICA y su identidad. Envia la CSR
//! al plano de control; la CA la firma y devuelve el certificado. **La clave
//! privada nunca sale del endpoint ni toca el disco**, y la CA nunca la ve. Es
//! la diferencia con [`crate::emisor::EmisorLocal`], donde la CA y el agente
//! comparten maquina.
//!
//! Aqui esta el lado del endpoint: generar la CSR y, con el certificado que
//! devuelve la CA, ensamblar la identidad. El lado de la CA es
//! [`crate::pki::AutoridadCertificadora::firmar_csr`].

use rustls::pki_types::CertificateDer;

use crate::error::{FleetError, Resultado};
use crate::pki::{ClavePrivada, Identidad};

/// Peticion de firma generada en el endpoint, con la clave retenida en memoria.
pub struct PeticionFirmaLocal {
    /// CSR en DER, lista para enviar a la CA.
    pub csr_der: Vec<u8>,
    /// Clave privada, que NO se envia: se queda aqui, en memoria.
    clave: ClavePrivada,
    /// CN solicitado.
    cn: String,
}

impl PeticionFirmaLocal {
    /// Genera una clave nueva y una CSR para `cn`, todo en memoria.
    pub fn generar(cn: &str) -> Resultado<PeticionFirmaLocal> {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .map_err(|e| FleetError::Cripto(format!("parametros de CSR: {e}")))?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        let clave = rcgen::KeyPair::generate()
            .map_err(|e| FleetError::Cripto(format!("clave del endpoint: {e}")))?;
        let csr = params
            .serialize_request(&clave)
            .map_err(|e| FleetError::Cripto(format!("serializar CSR: {e}")))?;
        Ok(PeticionFirmaLocal {
            csr_der: csr.der().to_vec(),
            clave: ClavePrivada::nueva(clave.serialize_der()),
            cn: cn.to_string(),
        })
    }

    /// CN solicitado.
    pub fn cn(&self) -> &str {
        &self.cn
    }

    /// Ensambla la identidad uniendo la clave retenida con el certificado que la
    /// CA firmo. Consume la peticion: la clave pasa a la identidad.
    pub fn ensamblar(
        self,
        cert_der: CertificateDer<'static>,
        no_antes_unix: u64,
        no_despues_unix: u64,
    ) -> Identidad {
        Identidad {
            cert_der,
            clave: self.clave,
            cn: self.cn,
            no_antes_unix,
            no_despues_unix,
        }
    }
}
