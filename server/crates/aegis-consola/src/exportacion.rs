//! El estrangulamiento de exportacion de la consola (FASE 110, invariante 8).
//!
//! Una consola que permite descargar lo que la politica retiene es una fuga con
//! interfaz bonita. Por eso TODO lo que la consola exporta o ensena hacia fuera
//! pasa por el MISMO juez de difusion de la FASE 78 (`aegis-share::Difusor`) que
//! gobierna TAXII, la federacion y el enjambre. No se reimplementa el criterio: se
//! usa el unico que hay, para que no haya un segundo camino de salida con reglas
//! distintas —que es justo lo que la invariante 8 existe para impedir—.

use aegis_share::{Destino, Difusor, Marcado, Retenido};

/// El resultado de intentar exportar algo desde la consola.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exportacion {
    /// Puede salir por ese destino.
    Permitida,
    /// El juez de difusion lo retiene, con su motivo.
    Retenida {
        /// Por que no sale.
        motivo: String,
    },
}

impl Exportacion {
    /// Si la exportacion sale.
    #[must_use]
    pub fn sale(&self) -> bool {
        matches!(self, Exportacion::Permitida)
    }
}

/// Frase legible de por que algo se retuvo.
fn motivo(r: &Retenido) -> String {
    match r {
        Retenido::NoDistribuible => {
            "TLP:RED: no se distribuye por ningun canal, ni siquiera exportando a fichero".into()
        }
        Retenido::Revocado => "el objeto esta revocado: no sale".into(),
        otro => format!("retenido por el juez de difusion: {otro:?}"),
    }
}

/// Exporta algo desde la consola, pasando por el juez de difusion de la FASE 78.
///
/// `marcado` es el TLP/PAP del objeto, `revocado` si esta revocado, y `destino` el
/// destino declarado. Es el UNICO camino por el que la consola saca algo: no hay
/// un `exportar_sin_juez`.
#[must_use]
pub fn exportar(marcado: Marcado, revocado: bool, destino: &Destino) -> Exportacion {
    match Difusor::juzgar_marcado(marcado, revocado, destino) {
        Ok(()) => Exportacion::Permitida,
        Err(r) => Exportacion::Retenida { motivo: motivo(&r) },
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;
    use aegis_share::{Canal, Pap, Tlp};

    fn destino_exportacion(tope: Tlp) -> Destino {
        Destino {
            nombre: "descarga-analista".into(),
            canal: Canal::Exportacion,
            tope_tlp: tope,
            es_propia_organizacion: true,
        }
    }

    #[test]
    fn lo_no_distribuible_no_sale_ni_exportando() {
        // TLP:RED no sale por ningun camino, ni una descarga a fichero.
        let rojo = Marcado::nuevo(Tlp::Red, Pap::Red);
        let e = exportar(rojo, false, &destino_exportacion(Tlp::Red));
        assert!(!e.sale());
        assert!(matches!(e, Exportacion::Retenida { .. }));
    }

    #[test]
    fn lo_compartible_sale_por_el_mismo_juez() {
        // TLP:GREEN a un destino que lo admite: sale.
        let verde = Marcado::nuevo(Tlp::Green, Pap::Green);
        let e = exportar(verde, false, &destino_exportacion(Tlp::Amber));
        assert!(e.sale(), "{e:?}");
    }

    #[test]
    fn lo_revocado_no_sale() {
        let verde = Marcado::nuevo(Tlp::Green, Pap::Green);
        assert!(!exportar(verde, true, &destino_exportacion(Tlp::Amber)).sale());
    }

    #[test]
    fn no_hay_segundo_camino_que_supere_el_tope_del_destino() {
        // AMBER a un destino cuyo tope es GREEN: retenido, como en cualquier otro
        // canal. La consola no es una excepcion.
        let ambar = Marcado::nuevo(Tlp::Amber, Pap::Amber);
        assert!(!exportar(ambar, false, &destino_exportacion(Tlp::Green)).sale());
    }
}
