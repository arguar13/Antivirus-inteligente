//! Aislamiento multi-inquilino (FASE 110).
//!
//! La API de hoy trata el inquilino como un filtro opcional de consulta: los
//! agentes, las alertas, las cazas y la cuarentena son globales. En una consola
//! multi-inquilino eso es una fuga entre clientes esperando a ocurrir. Aqui el
//! inquilino va ligado a la SESION, no a un parametro que el cliente elige, y un
//! recurso de otro inquilino no se ve —ni por error de una consulta, ni por un id
//! adivinado—. El filtrado es una funcion pura sobre la etiqueta de inquilino de
//! cada recurso.

use crate::rbac::Rol;

/// La sesion de un operador: quien es, de que inquilino, y con que rol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sesion {
    /// Usuario.
    pub usuario: String,
    /// Inquilino al que pertenece. Todo lo que ve se acota a este.
    pub inquilino: String,
    /// Rol, para la autorizacion (ver [`crate::rbac`]).
    pub rol: Rol,
}

impl Sesion {
    /// Si esta sesion puede ver un recurso etiquetado con `inquilino_recurso`.
    ///
    /// Solo si es el suyo. No hay «inquilino comodin» para operadores: un
    /// administrador de la plataforma que necesite ver varios inquilinos entra con
    /// una sesion por inquilino, y eso queda en el rastro de cada uno.
    #[must_use]
    pub fn puede_ver(&self, inquilino_recurso: &str) -> bool {
        self.inquilino == inquilino_recurso
    }
}

/// Algo que pertenece a un inquilino.
pub trait DeInquilino {
    /// El inquilino dueno del recurso.
    fn inquilino(&self) -> &str;
}

/// Filtra recursos al inquilino de la sesion: lo de otros inquilinos NO sale.
///
/// Es la operacion que toda lista de la consola pasa antes de responder. Se hace
/// aqui, en un solo sitio, para que ninguna vista nueva se olvide de filtrar —el
/// olvido es justo la fuga—.
pub fn filtrar<'a, T: DeInquilino>(sesion: &Sesion, recursos: &'a [T]) -> Vec<&'a T> {
    recursos
        .iter()
        .filter(|r| sesion.puede_ver(r.inquilino()))
        .collect()
}

#[cfg(test)]
mod pruebas {
    use super::*;

    struct Recurso {
        inquilino: String,
        _id: u32,
    }
    impl DeInquilino for Recurso {
        fn inquilino(&self) -> &str {
            &self.inquilino
        }
    }

    fn sesion(inq: &str) -> Sesion {
        Sesion {
            usuario: "ana".into(),
            inquilino: inq.into(),
            rol: Rol::Analista,
        }
    }

    #[test]
    fn una_sesion_no_ve_recursos_de_otro_inquilino() {
        let s = sesion("cliente-a");
        assert!(s.puede_ver("cliente-a"));
        assert!(!s.puede_ver("cliente-b"), "no se ve el inquilino ajeno");
    }

    #[test]
    fn el_filtro_deja_fuera_lo_de_otros_inquilinos() {
        let recursos = vec![
            Recurso {
                inquilino: "cliente-a".into(),
                _id: 1,
            },
            Recurso {
                inquilino: "cliente-b".into(),
                _id: 2,
            },
            Recurso {
                inquilino: "cliente-a".into(),
                _id: 3,
            },
        ];
        let vistos = filtrar(&sesion("cliente-a"), &recursos);
        assert_eq!(vistos.len(), 2, "solo los dos de cliente-a");
        assert!(vistos.iter().all(|r| r.inquilino == "cliente-a"));
    }

    #[test]
    fn un_id_de_otro_inquilino_no_se_cuela() {
        // Aunque el cliente adivine el id 2 (de cliente-b), su sesion no lo ve.
        let recursos = vec![Recurso {
            inquilino: "cliente-b".into(),
            _id: 2,
        }];
        assert!(filtrar(&sesion("cliente-a"), &recursos).is_empty());
    }
}
