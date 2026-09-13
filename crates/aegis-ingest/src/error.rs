//! Errores de la ingesta.
//!
//! Las variantes estan separadas por QUIEN tiene que hacer algo, no por donde se
//! produjo el fallo. Un analizador que devuelve «error» a secas obliga a quien
//! llama a decidir con una cadena de texto, y lo que acaba pasando es que todo se
//! trata igual: se reintenta lo que no se puede reintentar y se descarta lo que
//! habia que conservar.

use std::fmt;

/// Resultado de la ingesta.
pub type Resultado<T> = std::result::Result<T, ErrorIngesta>;

/// Lo que puede salir mal al ingerir.
#[derive(Debug, thiserror::Error)]
pub enum ErrorIngesta {
    /// El registro no se pudo analizar.
    ///
    /// **No es un fallo del sistema, es un dato**: un registro malformado en una
    /// entrada abierta a la red es lo normal, no la excepcion. Se cuenta y se
    /// sigue; abortar la lectura del flujo entero le daria a cualquiera la forma
    /// mas barata de cegar la ingesta: mandar una linea rota.
    #[error("registro ilegible en {origen}: {motivo}")]
    Malformado {
        /// Que analizador lo rechazo.
        origen: &'static str,
        /// Por que.
        motivo: String,
    },

    /// El registro excede un tope.
    ///
    /// Separado de [`ErrorIngesta::Malformado`] a proposito: un registro
    /// demasiado grande puede ser perfectamente valido y estar diciendo que los
    /// topes se quedaron cortos. Confundirlo con basura esconderia esa senal.
    #[error("{que} de {tamano} bytes supera el tope de {tope}")]
    Excedido {
        /// Que parte se paso.
        que: &'static str,
        /// Cuanto medía.
        tamano: usize,
        /// Cuanto se admite.
        tope: usize,
    },

    /// La cola esta llena y la politica es rechazar.
    ///
    /// Es contrapresion, no un fallo: quien produce tiene que reducir el ritmo.
    #[error("cola llena: {ocupado} de {capacidad} bytes")]
    Saturada {
        /// Bytes ocupados.
        ocupado: usize,
        /// Bytes de capacidad.
        capacidad: usize,
    },

    /// Fallo de entrada/salida.
    #[error("{contexto}: {fuente}")]
    Es {
        /// Que se estaba haciendo.
        contexto: String,
        /// El error del sistema.
        #[source]
        fuente: std::io::Error,
    },

    /// Fallo del diario durable.
    #[error("diario: {0}")]
    Diario(String),

    /// Configuracion imposible.
    #[error("configuracion: {0}")]
    Config(String),
}

impl ErrorIngesta {
    /// Construye un error de entrada/salida con contexto.
    pub fn es(contexto: impl fmt::Display, fuente: std::io::Error) -> ErrorIngesta {
        ErrorIngesta::Es {
            contexto: contexto.to_string(),
            fuente,
        }
    }

    /// Si el error describe el registro y no el sistema.
    ///
    /// Lo usa el bucle de lectura para decidir si sigue: un registro malo se
    /// cuenta y se salta; un disco que falla, no.
    #[must_use]
    pub fn es_del_registro(&self) -> bool {
        matches!(
            self,
            ErrorIngesta::Malformado { .. } | ErrorIngesta::Excedido { .. }
        )
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn un_registro_roto_no_para_el_flujo_pero_un_disco_roto_si() {
        // La distincion es la que impide que una sola linea preparada ciegue la
        // ingesta entera de una maquina.
        let roto = ErrorIngesta::Malformado {
            origen: "syslog",
            motivo: "sin prioridad".into(),
        };
        assert!(roto.es_del_registro());

        let disco = ErrorIngesta::es(
            "leyendo /var/log/x",
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        );
        assert!(!disco.es_del_registro());
    }

    #[test]
    fn el_exceso_se_distingue_de_la_basura() {
        // Un registro demasiado grande puede estar diciendo que los topes se
        // quedaron cortos; tratarlo como basura esconderia esa senal.
        let e = ErrorIngesta::Excedido {
            que: "mensaje",
            tamano: 100_000,
            tope: 16_384,
        };
        assert!(e.es_del_registro());
        assert!(e.to_string().contains("16384"));
    }
}
