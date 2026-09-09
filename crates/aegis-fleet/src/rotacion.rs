//! Rotacion automatica de la identidad del agente.
//!
//! # Por que rotar
//!
//! Un certificado de vida larga es una llave maestra: si se filtra, sirve hasta
//! que alguien lo revoca a mano. La flota emite certificados de vida CORTA y los
//! renueva solos antes de caducar. Una clave robada de la memoria de un endpoint
//! deja de valer en minutos, y no hay nada que revocar a mano.
//!
//! # La clave nueva se GENERA, no se reutiliza
//!
//! Cada rotacion produce un par de claves nuevo ([`crate::pki`]), en memoria.
//! La identidad vieja se suelta y su clave se borra ([`zeroize`]). Nunca hay una
//! clave en disco de la que tirar, ni una clave que sobreviva a su certificado.
//!
//! [`zeroize`]: https://docs.rs/zeroize

use std::sync::{Arc, Mutex};

use crate::error::{FleetError, Resultado};
use crate::pki::{ahora_unix, Identidad};

/// Politica de rotacion.
#[derive(Debug, Clone, Copy)]
pub struct PoliticaRotacion {
    /// Vida de cada certificado, en segundos.
    pub validez_seg: u64,
    /// Fraccion de la vida (0..=100) transcurrida tras la cual se renueva.
    ///
    /// Con 60, un certificado de 300 s se renueva a los 180 s, con 120 s de
    /// margen antes de caducar. El margen absorbe relojes desincronizados y
    /// reintentos de red sin que el agente se quede jamas sin certificado
    /// vigente.
    pub renovar_al_pct: u64,
}

impl Default for PoliticaRotacion {
    fn default() -> Self {
        PoliticaRotacion {
            validez_seg: 300,
            renovar_al_pct: 60,
        }
    }
}

impl PoliticaRotacion {
    /// Segundos de vida tras los cuales conviene renovar.
    fn umbral_renovar_seg(&self) -> u64 {
        self.validez_seg.saturating_mul(self.renovar_al_pct) / 100
    }
}

/// Fuente de identidades nuevas para el rotador.
///
/// En las pruebas y en el arranque local lo implementa la CA directamente; en
/// produccion, un re-enrolamiento sobre mTLS que pide al plano de control un
/// certificado nuevo. El rotador no necesita saber cual: solo pide «damelo».
pub trait EmisorIdentidad: Send + Sync {
    /// Emite una identidad nueva para el CN dado, con la validez de la politica.
    fn emitir(&self, cn: &str, validez_seg: u64) -> Resultado<Identidad>;
}

/// Rotador de la identidad de un agente.
///
/// Es seguro compartirlo entre hilos: la identidad vigente vive tras un `Mutex`,
/// y se entrega como `Arc` para que el consumidor la use sin retener el candado.
pub struct RotadorCertificados {
    cn: String,
    politica: PoliticaRotacion,
    emisor: Arc<dyn EmisorIdentidad>,
    actual: Mutex<Arc<Identidad>>,
}

impl RotadorCertificados {
    /// Crea un rotador con una identidad inicial recien emitida.
    pub fn nuevo(
        cn: &str,
        politica: PoliticaRotacion,
        emisor: Arc<dyn EmisorIdentidad>,
    ) -> Resultado<RotadorCertificados> {
        let inicial = emisor.emitir(cn, politica.validez_seg)?;
        Ok(RotadorCertificados {
            cn: cn.to_string(),
            politica,
            emisor,
            actual: Mutex::new(Arc::new(inicial)),
        })
    }

    /// Identidad vigente, sin retener el candado.
    pub fn actual(&self) -> Resultado<Arc<Identidad>> {
        self.actual
            .lock()
            .map(|g| g.clone())
            .map_err(|_| FleetError::Cripto("candado de rotacion envenenado".into()))
    }

    /// Indica si conviene rotar en el instante `ahora`.
    pub fn necesita_rotar(&self, ahora: u64) -> Resultado<bool> {
        let id = self.actual()?;
        let restante = id.segundos_para_caducar(ahora);
        // Renovar cuando lo que queda es menor que el margen de la politica.
        Ok(restante <= self.politica.validez_seg - self.politica.umbral_renovar_seg())
    }

    /// Rota si la politica lo pide; devuelve `true` si roto.
    ///
    /// La identidad vieja se suelta al reemplazarla: su clave se borra sola.
    pub fn rotar_si_procede(&self, ahora: u64) -> Resultado<bool> {
        if self.necesita_rotar(ahora)? {
            self.rotar()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Fuerza una rotacion: emite una identidad nueva y reemplaza la vigente.
    pub fn rotar(&self) -> Resultado<()> {
        let nueva = self.emisor.emitir(&self.cn, self.politica.validez_seg)?;
        let mut g = self
            .actual
            .lock()
            .map_err(|_| FleetError::Cripto("candado de rotacion envenenado".into()))?;
        // Al asignar, el `Arc` viejo pierde una referencia; cuando cae la ultima,
        // la `ClavePrivada` se borra en su `Drop`.
        *g = Arc::new(nueva);
        Ok(())
    }

    /// Asegura que la identidad vigente no esta a punto de caducar antes de
    /// usarla para una conexion nueva. Es la rotacion perezosa, sin hilos.
    pub fn asegurar_vigencia(&self) -> Resultado<Arc<Identidad>> {
        self.rotar_si_procede(ahora_unix())?;
        self.actual()
    }

    /// CN del agente.
    pub fn cn(&self) -> &str {
        &self.cn
    }
}
