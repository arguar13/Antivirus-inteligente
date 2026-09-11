//! Clasificacion ELAM (Early Launch Anti-Malware) de un driver de arranque.
//!
//! Un driver ELAM es de los primeros que el kernel de Windows carga en el
//! arranque —despues de los criticos del sistema— y clasifica los que vienen
//! detras como bueno / malo / desconocido, de modo que un rootkit de arranque no
//! se cargue antes que el EDR. La ejecucion real (registrar el callback ELAM,
//! con un certificado AM firmado por Microsoft) queda gated; la **clasificacion**
//! —la decision— es portable y se prueba aqui.
//!
//! # La linea etica dentro del arranque
//!
//! Bloquear un driver que resulta ser critico para el arranque dejaria la
//! maquina del **dueno** sin poder arrancar. Eso es pelear contra el dueno. Por
//! eso, ante un driver dudoso y de arranque critico, la clasificacion es
//! `MaloPeroCritico`: Windows lo deja cargar (para que la maquina arranque) pero
//! queda marcado para el analisis. Nunca se convierte una sospecha en un
//! ladrillo.

use crate::abi::BdcbClassification;
use sha2::{Digest, Sha256};

/// La clasificacion —la DECISION— de un driver de arranque.
///
/// Ojo: estos codigos internos NO son los que Windows espera en el callback. El
/// `BDCB_CLASSIFICATION` real del WDK numera distinto (en Windows, `0` es
/// "desconocida", no "buena"). El puente correcto a ese codigo de wire es
/// [`BdcbClassification::from`] (ver [`crate::abi`]); confundir una cosa con la
/// otra haria que el kernel bloqueara un driver bueno o cargara uno malo. Aqui se
/// separan a proposito: esto es la decision; el codigo de wire se deriva de ella.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ClasificacionElam {
    /// Medida en la lista buena: se carga.
    ConocidoBueno = 0,
    /// Medida en la lista mala y NO critico de arranque: se bloquea.
    ConocidoMalo = 1,
    /// Medida en la lista mala PERO critico de arranque: se deja cargar para no
    /// dejar la maquina sin arrancar, y se marca.
    MaloPeroCritico = 2,
    /// Ni bueno ni malo conocido: se deja cargar y se observa.
    Desconocido = 3,
}

impl ClasificacionElam {
    /// El codigo interno estable de esta decision. NO es el valor que se devuelve
    /// al kernel: para eso esta [`BdcbClassification::from`], que traduce esta
    /// decision al `BDCB_CLASSIFICATION` real del WDK.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// `true` si esta clasificacion impide que el driver se cargue.
    #[must_use]
    pub const fn bloquea(self) -> bool {
        matches!(self, ClasificacionElam::ConocidoMalo)
    }
}

/// El puente honesto de la DECISION al codigo de wire REAL del WDK. Es lo que un
/// driver ELAM devolveria de verdad en el callback: nuestra decision, traducida
/// al `BDCB_CLASSIFICATION` que Windows entiende.
impl From<ClasificacionElam> for BdcbClassification {
    fn from(c: ClasificacionElam) -> Self {
        match c {
            ClasificacionElam::ConocidoBueno => BdcbClassification::KnownGoodImage,
            ClasificacionElam::ConocidoMalo => BdcbClassification::KnownBadImage,
            ClasificacionElam::MaloPeroCritico => BdcbClassification::KnownBadImageBootCritical,
            ClasificacionElam::Desconocido => BdcbClassification::UnknownImage,
        }
    }
}

/// Politica de clasificacion: medidas (SHA-256) conocidas buenas y malas.
///
/// En produccion se rellena desde la inteligencia de la flota por el canal
/// firmado de actualizaciones; aqui la estructura y la decision son las mismas.
#[derive(Debug, Clone, Default)]
pub struct PoliticaElam {
    buenos: Vec<[u8; 32]>,
    malos: Vec<[u8; 32]>,
}

impl PoliticaElam {
    /// Crea una politica a partir de las listas de medidas buenas y malas.
    #[must_use]
    pub fn nueva(buenos: Vec<[u8; 32]>, malos: Vec<[u8; 32]>) -> Self {
        Self { buenos, malos }
    }

    /// Medida de un driver: SHA-256 de su imagen. Es lo que se coteja con las
    /// listas —no el nombre del fichero, que un atacante controla—.
    #[must_use]
    pub fn medir(imagen: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(imagen);
        h.finalize().into()
    }

    /// Clasifica un driver por su medida.
    ///
    /// `es_critico_de_arranque` lo aporta el kernel (por el registro del driver):
    /// si es cierto, un veredicto "malo" se degrada a `MaloPeroCritico` para no
    /// impedir el arranque de la maquina del dueno.
    #[must_use]
    pub fn clasificar(&self, medida: &[u8; 32], es_critico_de_arranque: bool) -> ClasificacionElam {
        if self.buenos.iter().any(|m| m == medida) {
            return ClasificacionElam::ConocidoBueno;
        }
        if self.malos.iter().any(|m| m == medida) {
            return if es_critico_de_arranque {
                ClasificacionElam::MaloPeroCritico
            } else {
                ClasificacionElam::ConocidoMalo
            };
        }
        ClasificacionElam::Desconocido
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn medida_es_el_sha256_de_la_imagen() {
        // Dos imagenes iguales miden igual; una distinta, distinto.
        let a = PoliticaElam::medir(b"driver bueno v1");
        let b = PoliticaElam::medir(b"driver bueno v1");
        let c = PoliticaElam::medir(b"driver bueno v2");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn bueno_malo_desconocido() {
        let bueno = PoliticaElam::medir(b"nvidia.sys legitimo");
        let malo = PoliticaElam::medir(b"rootkit de arranque");
        let raro = PoliticaElam::medir(b"driver nunca visto");
        let pol = PoliticaElam::nueva(vec![bueno], vec![malo]);

        assert_eq!(
            pol.clasificar(&bueno, false),
            ClasificacionElam::ConocidoBueno
        );
        assert_eq!(
            pol.clasificar(&malo, false),
            ClasificacionElam::ConocidoMalo
        );
        assert_eq!(pol.clasificar(&raro, false), ClasificacionElam::Desconocido);
    }

    #[test]
    fn un_malo_critico_de_arranque_no_deja_la_maquina_sin_arrancar() {
        let malo = PoliticaElam::medir(b"driver de disco dudoso");
        let pol = PoliticaElam::nueva(vec![], vec![malo]);
        // No critico -> se bloquea.
        assert_eq!(
            pol.clasificar(&malo, false),
            ClasificacionElam::ConocidoMalo
        );
        assert!(pol.clasificar(&malo, false).bloquea());
        // Critico de arranque -> se degrada, NO se bloquea (la maquina arranca).
        assert_eq!(
            pol.clasificar(&malo, true),
            ClasificacionElam::MaloPeroCritico
        );
        assert!(!pol.clasificar(&malo, true).bloquea());
    }

    #[test]
    fn la_decision_se_traduce_al_codigo_real_del_wdk() {
        // Los codigos internos son un detalle nuestro (estables, pero internos).
        assert_eq!(ClasificacionElam::ConocidoBueno.as_u8(), 0);
        assert_eq!(ClasificacionElam::Desconocido.as_u8(), 3);
        // Lo que se devuelve al kernel es el BDCB_CLASSIFICATION REAL del WDK, y
        // NO coincide con el codigo interno: "bueno" es 1 en Windows, no 0.
        assert_eq!(
            BdcbClassification::from(ClasificacionElam::ConocidoBueno),
            BdcbClassification::KnownGoodImage
        );
        assert_eq!(
            BdcbClassification::from(ClasificacionElam::ConocidoMalo),
            BdcbClassification::KnownBadImage
        );
        assert_eq!(
            BdcbClassification::from(ClasificacionElam::MaloPeroCritico),
            BdcbClassification::KnownBadImageBootCritical
        );
        assert_eq!(
            BdcbClassification::from(ClasificacionElam::Desconocido),
            BdcbClassification::UnknownImage
        );
        // La trampa que esta capa evita: "bueno" NO es 0 en el wire de Windows.
        assert_ne!(
            BdcbClassification::from(ClasificacionElam::ConocidoBueno).as_i32(),
            i32::from(ClasificacionElam::ConocidoBueno.as_u8())
        );
    }
}
