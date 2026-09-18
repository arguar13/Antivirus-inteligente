//! Los fallos de la custodia, cada uno diciendo que NO quedo probado.
//!
//! Un error aqui no es una molestia operativa: es la diferencia entre evidencia
//! que sostiene una conclusion y evidencia que no. Por eso ninguno es generico
//! —«fallo la verificacion» no le sirve a nadie— y todos nombran la propiedad
//! concreta que no se pudo establecer.

use thiserror::Error;

/// Lo que puede salir mal al sellar, encadenar o verificar evidencia.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum CustodiaError {
    /// La clave no pudo firmar.
    #[error("no se pudo firmar: {0}")]
    NoSePudoFirmar(String),

    /// La firma no corresponde a los bytes que dice cubrir.
    ///
    /// Cubre los dos casos y a proposito no los distingue: los bytes cambiaron,
    /// o la firma es de otra cosa. Desde fuera son indistinguibles, y fingir que
    /// se sabe cual de los dos es seria inventar.
    #[error("la firma no cubre estos bytes: {que}")]
    FirmaQueNoCubre {
        /// Que documento se estaba verificando.
        que: String,
    },

    /// Los bytes presentados no son los que el sello cubre.
    #[error(
        "los bytes presentados no son los sellados: el sello cubre {esperado} \
         y se presentaron {recibido}"
    )]
    OtrosBytes {
        /// Resumen que el sello declara, en hexadecimal.
        esperado: String,
        /// Resumen de lo que se presento, en hexadecimal.
        recibido: String,
    },

    /// La longitud no coincide, aunque el resumen si.
    ///
    /// Es una comprobacion barata que no sobra: pilla un truncamiento antes de
    /// que nadie razone sobre el contenido, y no depende de la resistencia a
    /// colisiones de la funcion resumen.
    #[error(
        "la longitud no coincide: el sello cubre {esperado} bytes y se presentaron {recibido}"
    )]
    OtraLongitud {
        /// Longitud que el sello declara.
        esperado: u64,
        /// Longitud de lo que se presento.
        recibido: u64,
    },

    /// Un eslabon no engancha con el anterior.
    #[error(
        "la cadena esta rota en el eslabon {posicion}: dice venir de {declarado} \
         y el anterior es {real}"
    )]
    CadenaRota {
        /// Posicion del eslabon que no engancha, desde cero.
        posicion: usize,
        /// Resumen del anterior segun el eslabon, en hexadecimal.
        declarado: String,
        /// Resumen real del anterior, en hexadecimal.
        real: String,
    },

    /// La cadena no arranca del sello que dice custodiar.
    #[error("la cadena no arranca de este sello: ancla en {declarado} y el sello es {real}")]
    CadenaSinAncla {
        /// Ancla declarada, en hexadecimal.
        declarado: String,
        /// Identidad real del sello, en hexadecimal.
        real: String,
    },

    /// Una cadena vacia no custodia nada.
    ///
    /// No es lo mismo que una cadena intacta: una cadena sin un solo eslabon no
    /// dice que nadie toco la evidencia, dice que nadie anoto nada.
    #[error("la cadena no tiene ni un eslabon: no consta la recogida")]
    CadenaVacia,

    /// No hay clave publica para quien firmo.
    #[error("no consta clave para el firmante «{firmante}»: su firma no se puede comprobar")]
    FirmanteDesconocido {
        /// Identidad que el documento dice tener.
        firmante: String,
    },
}
