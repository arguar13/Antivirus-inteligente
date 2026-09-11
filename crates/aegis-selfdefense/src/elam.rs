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

use sha2::{Digest, Sha256};

/// Clasificacion de un driver, con los codigos que Windows espera del callback
/// ELAM (`BDCB_CLASSIFICATION`).
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
    /// El codigo numerico que se devuelve al kernel.
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
    fn codigos_como_los_de_windows() {
        assert_eq!(ClasificacionElam::ConocidoBueno.as_u8(), 0);
        assert_eq!(ClasificacionElam::ConocidoMalo.as_u8(), 1);
        assert_eq!(ClasificacionElam::MaloPeroCritico.as_u8(), 2);
        assert_eq!(ClasificacionElam::Desconocido.as_u8(), 3);
    }
}
