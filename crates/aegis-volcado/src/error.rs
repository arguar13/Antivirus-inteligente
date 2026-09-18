//! Los errores de este crate.
//!
//! Cada uno dice **que no se pudo hacer y por que**, porque en forense la
//! diferencia entre «no habia nada» y «no se pudo leer» es la diferencia entre
//! un informe y un informe equivocado.

use thiserror::Error;

/// Lo que puede salir mal analizando una memoria.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum VolcadoError {
    /// La direccion no cae en ninguna region del mapa.
    ///
    /// No es lo mismo que «ahi hay ceros»: es que ahi no hay nada mapeado, y
    /// devolver ceros haria que el analisis leyera como contenido una pagina que
    /// no existe.
    #[error("la direccion {direccion:#x} no esta mapeada en este volcado")]
    SinMapear {
        /// La direccion pedida.
        direccion: u64,
    },
    /// No se pudo abrir el fichero del volcado.
    #[error("no se pudo abrir {ruta}: {causa}")]
    NoSePudoAbrir {
        /// La ruta.
        ruta: String,
        /// Lo que dijo el sistema.
        causa: String,
    },
    /// No se pudo leer de una direccion que si estaba mapeada.
    #[error("no se pudo leer {direccion:#x}: {causa}")]
    NoSePudoLeer {
        /// La direccion.
        direccion: u64,
        /// Lo que dijo el sistema.
        causa: String,
    },
}
