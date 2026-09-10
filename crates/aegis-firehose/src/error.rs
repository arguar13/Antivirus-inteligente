//! Errores del firehose.

/// Lo que puede salir mal al entregar auditoria.
#[derive(Debug, thiserror::Error)]
pub enum ErrorFirehose {
    /// Fallo de entrada/salida sobre el diario.
    #[error("E/S en el diario ({op}): {source}")]
    Diario {
        /// Operacion que fallaba.
        op: &'static str,
        /// Causa del sistema.
        #[source]
        source: std::io::Error,
    },

    /// El diario esta lleno y la politica es rechazar.
    ///
    /// NO es un fallo del producto: es la politica funcionando. Ver
    /// [`crate::PoliticaLleno`].
    #[error("el diario alcanzo su presupuesto de {presupuesto} bytes con {ocupado} ocupados")]
    DiarioLleno {
        /// Presupuesto configurado.
        presupuesto: u64,
        /// Bytes realmente ocupados.
        ocupado: u64,
    },

    /// Un registro supera el tamano maximo admitido.
    #[error("el registro mide {tamano} bytes y el maximo es {maximo}")]
    RegistroDesmesurado {
        /// Tamano del registro rechazado.
        tamano: usize,
        /// Maximo admitido.
        maximo: usize,
    },

    /// El diario en disco esta corrupto mas alla de la cola.
    ///
    /// Se distingue de una escritura a medias —que se trunca y se sigue— porque
    /// una corrupcion en MEDIO del diario significa que hay registros de
    /// auditoria perdidos, y eso hay que decirlo, no arreglarlo en silencio.
    #[error("el segmento {segmento} esta corrupto en el desplazamiento {desplazamiento}")]
    DiarioCorrupto {
        /// Segmento afectado.
        segmento: u64,
        /// Desplazamiento del primer byte ilegible.
        desplazamiento: u64,
    },

    /// Configuracion invalida.
    #[error("configuracion: {0}")]
    Config(String),
}

/// Resultado del firehose.
pub type Resultado<T> = std::result::Result<T, ErrorFirehose>;
