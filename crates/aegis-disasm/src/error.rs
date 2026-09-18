//! Los fallos del analisis, cada uno diciendo que no se pudo establecer.

use thiserror::Error;

/// Lo que puede salir mal desensamblando o analizando.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum DisasmError {
    /// No se pudo decodificar en esa direccion.
    ///
    /// **No es un error del fichero**: en un binario real hay datos entre
    /// funciones, tablas de saltos y relleno, y el desensamblado lineal pasa por
    /// encima de todo eso. Se devuelve para que quien recorre decida —seguir
    /// desde la siguiente direccion, o parar— y se cuenta en la cobertura.
    #[error("no se pudo decodificar en {direccion:#x}")]
    NoDecodificable {
        /// Donde.
        direccion: u64,
    },

    /// La direccion pedida no cae en los bytes que se estan analizando.
    #[error("la direccion {direccion:#x} no cae en el tramo [{base:#x}, {fin:#x})")]
    FueraDelTramo {
        /// La pedida.
        direccion: u64,
        /// Principio del tramo.
        base: u64,
        /// Final del tramo.
        fin: u64,
    },

    /// El contenedor no se pudo leer.
    #[error("no se pudo leer el contenedor: {0}")]
    ContenedorIlegible(String),

    /// La arquitectura del binario no es ninguna de las tres que se soportan.
    ///
    /// Se dice cual es, en vez de un «no soportado» generico: saber que llega un
    /// MIPS o un RISC-V es informacion de inventario, y un lote de ficheros
    /// rechazados sin decir por que no se puede triar.
    #[error("arquitectura no soportada: {0}")]
    ArquitecturaNoSoportada(String),
}
