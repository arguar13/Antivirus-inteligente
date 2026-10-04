//! La puerta de publicacion: lo unico que produce bytes firmables.
//!
//! # La puerta esta en el tipo
//!
//! Firmar necesita un [`Firmable`], y un [`Firmable`] solo sale de
//! [`preparar`] (sus campos son privados a este modulo). [`preparar`] no
//! devuelve nada si alguna regla rompe su motor, si la epoca no avanza, si la
//! escalera no se sostiene contra el historial o si alguien quiere imponer sin
//! numeros. No hay «preparar y luego ya miro el informe»: dejar construir el
//! paquete y confiar en que alguien mire antes de firmar es dejar la puerta
//! abierta con un cartel al lado (la misma leccion que `corpus::preparar`).
//!
//! # Promocion y reversion, de una llamada cada una
//!
//! - [`promover`]: el MISMO contenido de una publicacion, al anillo siguiente,
//!   con el peldaño que acredita como le fue.
//! - [`revertir`]: vuelve a publicar, con epoca NUEVA, el contenido que tenia la
//!   flota antes del ultimo cambio. Volver atras es avanzar la epoca: la epoca
//!   monotona no se toca nunca hacia abajo, ni para arreglar un error.

use crate::anillo::{Anillo, Peldano};
use crate::paquete::{Entrada, Manifiesto, Sellado, CTX_CONTENIDO};
use crate::validar::{Informe, Medir, Validadores};
use crate::{ClaveFirmaHibrida, ErrorCanal};

/// Lo que se quiere publicar: el canal y sus reglas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Borrador {
    /// Canal.
    pub canal: String,
    /// Reglas.
    pub entradas: Vec<Entrada>,
}

/// A donde y cuando.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destino {
    /// Epoca nueva (mayor que cualquiera publicada en el canal).
    pub epoca: u64,
    /// Marca de tiempo informativa.
    pub generado_ns: u64,
    /// Anillo.
    pub anillo: Anillo,
    /// Escalera que acredita el anillo.
    pub escalera: Vec<Peldano>,
    /// Epoca a la que revierte, o 0.
    pub revierte_a: u64,
}

/// Un paquete que ha pasado la puerta y se puede firmar.
#[derive(Debug, Clone)]
pub struct Firmable {
    manifiesto: Manifiesto,
    cuerpo: Vec<u8>,
    informes: Vec<Informe>,
}

impl Firmable {
    /// Los bytes que hay que firmar, bajo [`CTX_CONTENIDO`].
    #[must_use]
    pub fn cuerpo(&self) -> &[u8] {
        &self.cuerpo
    }

    /// El manifiesto.
    #[must_use]
    pub fn manifiesto(&self) -> &Manifiesto {
        &self.manifiesto
    }

    /// Lo que la puerta supo de cada regla (cota y tiempo medido).
    #[must_use]
    pub fn informes(&self) -> &[Informe] {
        &self.informes
    }

    /// Sella con una firma hecha fuera (en el firmador, que guarda la clave).
    #[must_use]
    pub fn sellar(&self, firma: Vec<u8>) -> Vec<u8> {
        Sellado {
            cuerpo: self.cuerpo.clone(),
            firma,
        }
        .a_bytes()
    }

    /// Firma con la clave hibrida y sella.
    ///
    /// # Errores
    /// [`ErrorCanal::Estructura`] si la primitiva de firma falla.
    pub fn firmar(&self, clave: &ClaveFirmaHibrida) -> Result<Vec<u8>, ErrorCanal> {
        let f = clave
            .firmar(&self.cuerpo, CTX_CONTENIDO)
            .map_err(|e| ErrorCanal::Estructura(format!("no se pudo firmar: {e}")))?;
        Ok(self.sellar(f.a_bytes()))
    }
}

/// Una publicacion ya hecha.
#[derive(Debug, Clone)]
pub struct Publicado {
    /// Su manifiesto.
    pub manifiesto: Manifiesto,
    /// Huella de su contenido.
    pub sha_contenido: [u8; 32],
}

/// Lo publicado en un canal, en orden de epoca. Lo guarda el plano de control.
#[derive(Debug, Clone, Default)]
pub struct Historial {
    publicados: Vec<Publicado>,
}

impl Historial {
    /// Vacio.
    #[must_use]
    pub fn nuevo() -> Historial {
        Historial::default()
    }

    /// La epoca mas alta publicada (0 si ninguna).
    #[must_use]
    pub fn ultima_epoca(&self) -> u64 {
        self.publicados.last().map_or(0, |p| p.manifiesto.epoca)
    }

    /// Lo publicado en una epoca.
    #[must_use]
    pub fn en(&self, epoca: u64) -> Option<&Publicado> {
        self.publicados.iter().find(|p| p.manifiesto.epoca == epoca)
    }

    /// Todo lo publicado.
    #[must_use]
    pub fn publicados(&self) -> &[Publicado] {
        &self.publicados
    }

    /// Registra una publicacion, una vez firmada y distribuida.
    ///
    /// # Errores
    /// [`ErrorCanal::Retroceso`] si su epoca no supera la ultima registrada.
    pub fn registrar(&mut self, f: &Firmable) -> Result<(), ErrorCanal> {
        let ultima = self.ultima_epoca();
        if f.manifiesto.epoca <= ultima {
            return Err(ErrorCanal::Retroceso {
                ofrecida: f.manifiesto.epoca,
                vista: ultima,
            });
        }
        self.publicados.push(Publicado {
            sha_contenido: f.manifiesto.sha_contenido(),
            manifiesto: f.manifiesto.clone(),
        });
        Ok(())
    }
}

/// La puerta. Unica forma de obtener un [`Firmable`].
///
/// Comprueba, en orden: la epoca contra el historial, la estructura (limites,
/// anillo, escalera, imponer con numeros), la escalera y la reversion contra lo
/// que de verdad se publico, y que ninguna regla rompe su motor, midiendo el
/// tiempo.
///
/// # Errores
/// El primer [`ErrorCanal`] que se encuentre; si son reglas rotas, todas.
pub fn preparar(
    borrador: Borrador,
    destino: Destino,
    historial: &Historial,
    validadores: &Validadores,
) -> Result<Firmable, ErrorCanal> {
    let manifiesto = Manifiesto {
        canal: borrador.canal,
        epoca: destino.epoca,
        generado_ns: destino.generado_ns,
        anillo: destino.anillo,
        escalera: destino.escalera,
        revierte_a: destino.revierte_a,
        entradas: borrador.entradas,
    };
    let ultima = historial.ultima_epoca();
    if manifiesto.epoca <= ultima {
        return Err(ErrorCanal::Retroceso {
            ofrecida: manifiesto.epoca,
            vista: ultima,
        });
    }
    manifiesto
        .comprobar_estructura()
        .map_err(ErrorCanal::Estructura)?;

    let sha = manifiesto.sha_contenido();
    for p in &manifiesto.escalera {
        let publicado = historial.en(p.epoca).ok_or_else(|| {
            ErrorCanal::Escalera(format!(
                "el peldaño cita la epoca {}, que no se publico",
                p.epoca
            ))
        })?;
        if publicado.manifiesto.canal != manifiesto.canal
            || publicado.manifiesto.anillo.orden() != p.orden
            || publicado.sha_contenido != sha
        {
            return Err(ErrorCanal::Escalera(format!(
                "el peldaño de la epoca {} no es este contenido en ese anillo",
                p.epoca
            )));
        }
    }
    if manifiesto.revierte_a != 0 {
        let destino = historial.en(manifiesto.revierte_a).ok_or_else(|| {
            ErrorCanal::Escalera(format!(
                "revierte a la epoca {}, que no se publico",
                manifiesto.revierte_a
            ))
        })?;
        if destino.sha_contenido != sha {
            return Err(ErrorCanal::Escalera(
                "la reversion no lleva el contenido de la epoca a la que dice volver".into(),
            ));
        }
        if destino.manifiesto.anillo.orden() < manifiesto.anillo.orden() {
            return Err(ErrorCanal::Escalera(
                "se revierte a un contenido que nunca llego a un anillo tan ancho".into(),
            ));
        }
    }

    let informes = validadores
        .validar(&manifiesto, Medir::Tiempo)
        .map_err(ErrorCanal::Roto)?;
    let cuerpo = manifiesto.a_bytes();
    Ok(Firmable {
        manifiesto,
        cuerpo,
        informes,
    })
}

/// Promueve el contenido de la epoca `desde` al anillo `anillo`.
///
/// `sanos` y `fallos` son lo que informaron los equipos del anillo de `desde`.
/// El peldaño se añade a la escalera que ya traia.
///
/// # Errores
/// Los de [`preparar`], mas [`ErrorCanal::Escalera`] si `desde` no existe.
pub fn promover(
    historial: &Historial,
    desde: u64,
    salud: (u64, u64),
    anillo: Anillo,
    epoca: u64,
    generado_ns: u64,
    validadores: &Validadores,
) -> Result<Firmable, ErrorCanal> {
    let origen = historial
        .en(desde)
        .ok_or_else(|| ErrorCanal::Escalera(format!("no hay publicacion en la epoca {desde}")))?;
    let m = &origen.manifiesto;
    let mut escalera = m.escalera.clone();
    escalera.push(Peldano {
        orden: m.anillo.orden(),
        epoca: desde,
        sanos: salud.0,
        fallos: salud.1,
    });
    preparar(
        Borrador {
            canal: m.canal.clone(),
            entradas: m.entradas.clone(),
        },
        Destino {
            epoca,
            generado_ns,
            anillo,
            escalera,
            revierte_a: 0,
        },
        historial,
        validadores,
    )
}

/// El rollback de la flota en una llamada.
///
/// Busca la publicacion mas reciente que llego a la flota con un contenido
/// DISTINTO del de la ultima publicacion (sea del anillo que sea) y la vuelve a
/// publicar para toda la flota con una epoca nueva. Pasa por la puerta como
/// cualquier otra: si aquel contenido ya no funciona con el motor de hoy, no
/// se publica, y lo que toca es apagar las reglas con [`crate::ajustes`].
///
/// # Errores
/// [`ErrorCanal::SinAnterior`] si no hay a donde volver; los de [`preparar`].
pub fn revertir(
    historial: &Historial,
    epoca: u64,
    generado_ns: u64,
    validadores: &Validadores,
) -> Result<Firmable, ErrorCanal> {
    let ultimo = historial.publicados.last().ok_or(ErrorCanal::SinAnterior)?;
    let destino = historial
        .publicados
        .iter()
        .rev()
        .find(|p| p.manifiesto.anillo == Anillo::Flota && p.sha_contenido != ultimo.sha_contenido)
        .ok_or(ErrorCanal::SinAnterior)?;
    preparar(
        Borrador {
            canal: destino.manifiesto.canal.clone(),
            entradas: destino.manifiesto.entradas.clone(),
        },
        Destino {
            epoca,
            generado_ns,
            anillo: Anillo::Flota,
            escalera: Vec::new(),
            revierte_a: destino.manifiesto.epoca,
        },
        historial,
        validadores,
    )
}
