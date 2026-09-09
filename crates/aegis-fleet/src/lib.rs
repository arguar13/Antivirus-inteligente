//! # aegis-fleet
//!
//! Agente de gestion de flota sobre **mTLS** con **certificados de rotacion
//! automatica** cuyas claves **nunca tocan el disco**.
//!
//! # El problema que resuelve
//!
//! Un antivirus de una sola maquina se administra a mano. Una flota de miles no:
//! necesita un plano de control que sepa que endpoints estan vivos, les entregue
//! politica y recoja sus eventos —sin que ese canal sea, el mismo, la via de
//! entrada del atacante—. Dos riesgos concretos:
//!
//! - **Quien habla con el plano de control.** Si basta con alcanzar el puerto,
//!   cualquiera se registra como endpoint y recibe la politica (o la envenena).
//! - **Una credencial de agente robada.** Un certificado de vida larga en el
//!   disco de un endpoint es una llave que sirve hasta que alguien la revoca.
//!
//! # Como se resuelve
//!
//! | Pieza | Que hace | Modulo |
//! |---|---|---|
//! | mTLS mutuo | los DOS extremos prueban su identidad con certificado de la CA de la flota | [`tls`] |
//! | Rotacion automatica | certificados de vida corta que se renuevan solos, con clave nueva en memoria | [`rotacion`] |
//! | Clave sin disco | la clave se genera en memoria y se borra al rotar; con CSR, ni la CA la ve | [`pki`], [`csr`] |
//! | Servicio gRPC | enrolar, latir, reportar eventos, como llamadas unarias protobuf | [`proto`], [`rpc`] |
//! | Plano de control | autentica por el CN del certificado y despacha el servicio | [`servidor`] |
//! | Agente | se conecta, se enrola y late, rotando su certificado | [`cliente`] |
//!
//! # Sobre el transporte
//!
//! El modelo es el de gRPC: llamadas unarias con peticion y respuesta protobuf,
//! sobre un canal mTLS. El enmarcado es el prefijo de longitud de gRPC sobre el
//! flujo TLS sincrono, no tramas HTTP/2: el resto de AegisCore es sincrono a
//! proposito —por el presupuesto de memoria y el control de la concurrencia— y
//! el unico HTTP/2 maduro de Rust exige un runtime asincrono. La seguridad
//! —autenticacion mutua, protobuf real, certificados rotativos— es la misma.
//! Los detalles y el razonamiento estan en [`rpc`].

#![deny(missing_docs)]

pub mod cliente;
pub mod csr;
pub mod emisor;
pub mod error;
pub mod pki;
pub mod proto;
pub mod rotacion;
pub mod rpc;
pub mod servidor;
pub mod tls;
pub mod x509;

pub use cliente::{ClienteFlota, SesionFlota};
pub use csr::PeticionFirmaLocal;
pub use emisor::EmisorLocal;
pub use error::{FleetError, Resultado};
pub use pki::{ahora_unix, AutoridadCertificadora, ClavePrivada, Identidad};
pub use rotacion::{EmisorIdentidad, PoliticaRotacion, RotadorCertificados};
pub use servidor::{ManejadorFlota, PlanoDeControl, ServidorEnEjecucion, ServidorFlota};
