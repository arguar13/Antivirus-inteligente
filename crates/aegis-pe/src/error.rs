//! Los fallos de lectura, cada uno diciendo QUE campo no cuadra.
//!
//! # Por que ninguno es generico
//!
//! Un parser de formato binario en un proceso privilegiado lee **entrada que
//! escribe el atacante**. Cuando algo no cuadra hay dos respuestas posibles y se
//! parecen mucho: «este fichero esta corrupto» y «este fichero esta construido
//! para romperme». La segunda es una deteccion.
//!
//! Un `Err(ParseError)` a secas las funde en una sola y pierde justo la
//! informacion que las separa. Por eso cada variante nombra el campo, el valor
//! que traia y contra que se comprobo: un `PointerToRawData` que apunta mas alla
//! del fichero no es lo mismo que un `SizeOfHeaders` de cero, y el analista que
//! mira un lote de mil ficheros rechazados necesita poder agruparlos.

use thiserror::Error;

/// Lo que puede salir mal al leer un PE.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum PeError {
    /// No empieza por `MZ`.
    #[error("no es un ejecutable de Windows: empieza por {0:02x?} y no por MZ")]
    NoEsMZ([u8; 2]),

    /// El fichero se acaba antes de lo que el campo anterior prometia.
    ///
    /// Es el error mas comun con entrada hostil y el mas peligroso de tratar a
    /// la ligera: en C seria una lectura fuera de limites; aqui es esto.
    #[error("el fichero se acaba antes de {que}: hacen falta {necesita} bytes en {desde} y solo hay {hay}")]
    SeAcabaElFichero {
        /// Que se estaba leyendo.
        que: &'static str,
        /// Desplazamiento desde el que se queria leer.
        desde: u64,
        /// Cuantos bytes hacian falta.
        necesita: u64,
        /// Cuantos quedaban de verdad.
        hay: u64,
    },

    /// `e_lfanew` no apunta a una firma `PE\0\0`.
    #[error("e_lfanew apunta a {offset}, donde no hay firma PE sino {encontrado:02x?}")]
    SinFirmaPe {
        /// Donde decia el encabezado DOS que estaba la firma.
        offset: u64,
        /// Lo que habia de verdad.
        encontrado: [u8; 4],
    },

    /// La `Magic` del encabezado opcional no es PE32 ni PE32+.
    #[error("el encabezado opcional dice magic {0:#06x}, que no es PE32 (0x10b) ni PE32+ (0x20b)")]
    MagicDesconocida(u16),

    /// `SizeOfOptionalHeader` no llega ni para los campos obligatorios.
    #[error("SizeOfOptionalHeader vale {0} y no cabe ni el encabezado opcional minimo")]
    EncabezadoOpcionalCorto(u16),

    /// El numero de secciones es imposible.
    ///
    /// El cargador de Windows rechaza por encima de 96. Un valor mayor no es un
    /// fichero valido que no entendemos: es un fichero que nadie va a ejecutar,
    /// y aceptarlo solo sirve para que alguien nos haga reservar memoria.
    #[error("declara {0} secciones; el cargador de Windows admite 96 como maximo")]
    DemasiadasSecciones(u16),

    /// Un directorio de datos apunta fuera del fichero.
    #[error("el directorio {indice} apunta a {offset}+{tamano}, y el fichero mide {fichero}")]
    DirectorioFueraDelFichero {
        /// Indice del directorio de datos.
        indice: usize,
        /// Desplazamiento declarado.
        offset: u64,
        /// Tamano declarado.
        tamano: u64,
        /// Tamano real del fichero.
        fichero: u64,
    },

    /// Una seccion apunta fuera del fichero.
    #[error("la seccion «{nombre}» dice estar en {offset}+{tamano} y el fichero mide {fichero}")]
    SeccionFueraDelFichero {
        /// Nombre de la seccion, tal cual viene.
        nombre: String,
        /// `PointerToRawData`.
        offset: u64,
        /// `SizeOfRawData`.
        tamano: u64,
        /// Tamano real del fichero.
        fichero: u64,
    },

    /// `SizeOfHeaders` no cuadra con el fichero.
    #[error("SizeOfHeaders vale {declarado} y el fichero mide {fichero}")]
    CabecerasFueraDelFichero {
        /// Valor declarado.
        declarado: u64,
        /// Tamano real del fichero.
        fichero: u64,
    },

    /// Una entrada de certificado de la tabla de firmas no cuadra.
    #[error("la entrada de certificado en {offset} declara longitud {longitud}, que no cabe en la tabla de {tabla} bytes")]
    CertificadoMalFormado {
        /// Desplazamiento de la entrada dentro del fichero.
        offset: u64,
        /// Longitud declarada en `dwLength`.
        longitud: u64,
        /// Tamano de la tabla completa.
        tabla: u64,
    },
}
