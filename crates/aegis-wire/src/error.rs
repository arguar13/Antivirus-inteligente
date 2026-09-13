//! Errores de la diseccion.
//!
//! Cada variante nombra **que campo** y **por que** fallo. En un disector eso no
//! es cortesia: el motivo por el que un paquete no se pudo analizar es en si
//! mismo una senal —un protocolo malformado a proposito es una tecnica de
//! evasion conocida—, y «error de parseo» a secas la borra.

use thiserror::Error;

/// Lo que puede salir mal al disecar.
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum ErrorDiseccion {
    /// El buffer se acabo antes que el campo que se estaba leyendo.
    #[error("truncado en {campo}: se esperaban {esperados} bytes y quedaban {habia}")]
    Truncado {
        /// Campo que se estaba leyendo.
        campo: &'static str,
        /// Bytes que hacian falta.
        esperados: usize,
        /// Bytes disponibles.
        habia: usize,
    },

    /// Un campo declara una longitud que no cabe en lo que queda.
    ///
    /// Distinto de [`ErrorDiseccion::Truncado`] a proposito: aqui el emisor
    /// **mintio** sobre una longitud, alli simplemente falto contenido. Lo
    /// primero es sospechoso; lo segundo puede ser una captura cortada.
    #[error("longitud imposible en {campo}: declara {declarada} y hay {disponible}")]
    LongitudImposible {
        /// Campo cuya longitud miente.
        campo: &'static str,
        /// Lo que declara.
        declarada: usize,
        /// Lo que hay.
        disponible: usize,
    },

    /// Un valor fuera del rango que la especificacion permite.
    #[error("valor invalido en {campo}: {valor}")]
    ValorInvalido {
        /// Campo implicado.
        campo: &'static str,
        /// Valor visto.
        valor: u64,
    },

    /// Se supero un limite duro del disector.
    ///
    /// No es un fallo del disector: es el disector negandose a que una entrada
    /// preparada le haga reservar memoria o iterar sin fin.
    #[error("limite excedido en {campo}: {valor} > {tope}")]
    LimiteExcedido {
        /// Que limite.
        campo: &'static str,
        /// Valor visto.
        valor: usize,
        /// Tope.
        tope: usize,
    },

    /// Anidamiento excesivo (cabeceras de extension, etiquetas, ASN.1).
    ///
    /// El ataque clasico: una cadena de cabeceras de extension IPv6 que apuntan
    /// unas a otras, o una etiqueta DNS comprimida que apunta a si misma. Sin
    /// un tope, el disector entra en un bucle infinito o agota la pila.
    #[error("anidamiento excesivo en {campo}: {niveles} niveles")]
    AnidamientoExcesivo {
        /// Donde.
        campo: &'static str,
        /// Cuantos niveles se vieron.
        niveles: usize,
    },

    /// Texto que decia ser de una codificacion y no lo era.
    #[error("codificacion invalida en {0}")]
    CodificacionInvalida(&'static str),

    /// La cabecera no corresponde al protocolo que se creia.
    ///
    /// Es informativo, no un fallo: significa «esto no es lo que pensaba», y el
    /// motor prueba con otro disector.
    #[error("no es {0}")]
    NoEsEsteProtocolo(&'static str),
}

/// Resultado de una diseccion.
pub type Resultado<T> = Result<T, ErrorDiseccion>;
