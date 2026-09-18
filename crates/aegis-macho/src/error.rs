//! Los fallos de lectura, cada uno diciendo que campo no cuadra.

use thiserror::Error;

/// Lo que puede salir mal al leer un binario de macOS.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum MachoError {
    /// El numero magico no es de Mach-O ni de un binario universal.
    #[error("no es un binario de macOS: empieza por {0:#010x}")]
    MagicDesconocida(u32),

    /// Es un Mach-O de 32 bits.
    ///
    /// Se rechaza a proposito y con su propio error: macOS no ejecuta binarios
    /// de 32 bits desde Catalina (2019). Aceptarlo obligaria a mantener dos
    /// recorridos de encabezados —con sus dos juegos de desplazamientos— para
    /// leer algo que ninguna maquina de la flota puede ejecutar.
    #[error("es un Mach-O de 32 bits, que macOS no ejecuta desde Catalina")]
    TreintaYDosBits,

    /// El fichero se acaba antes de lo que un campo prometia.
    #[error(
        "el fichero se acaba antes de {que}: hacen falta {necesita} bytes en {desde} y hay {hay}"
    )]
    SeAcabaElFichero {
        /// Que se estaba leyendo.
        que: &'static str,
        /// Desde donde.
        desde: u64,
        /// Cuantos bytes hacian falta.
        necesita: u64,
        /// Cuantos quedaban.
        hay: u64,
    },

    /// Un comando de carga declara un tamano imposible.
    ///
    /// Es el campo que mueve el cursor del recorrido. Un `cmdsize` de cero deja
    /// el bucle sin avanzar —cuelgue con un fichero de treinta y dos bytes bien
    /// puestos— y uno que no este alineado a ocho rompe todo lo que venga
    /// detras.
    #[error("el comando {indice} declara cmdsize {tamano}, que es imposible")]
    ComandoImposible {
        /// Posicion del comando.
        indice: u32,
        /// Tamano declarado.
        tamano: u32,
    },

    /// Una rodaja del binario universal apunta fuera del fichero.
    #[error("la rodaja {indice} dice estar en {offset}+{tamano} y el fichero mide {fichero}")]
    RodajaFueraDelFichero {
        /// Posicion en la tabla.
        indice: u32,
        /// Desplazamiento declarado.
        offset: u64,
        /// Tamano declarado.
        tamano: u64,
        /// Tamano real.
        fichero: u64,
    },

    /// El numero de rodajas es imposible.
    #[error("declara {0} rodajas; ningun binario universal real tiene tantas")]
    DemasiadasRodajas(u32),

    /// Dos rodajas se solapan en el fichero.
    ///
    /// No es solo malformacion: es una forma de que dos herramientas de analisis
    /// lean cosas distintas del mismo fichero segun por donde entren.
    #[error("las rodajas {una} y {otra} ocupan el mismo tramo del fichero")]
    RodajasQueSeSolapan {
        /// Primera.
        una: u32,
        /// Segunda.
        otra: u32,
    },
}
